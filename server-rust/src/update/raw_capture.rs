//! Raw-update capture: seals the restore archive into a capsule on the data
//! partition, the only one a raw write leaves in place. Nothing here
//! authorizes a partition write; the writer and the early restore check again.

use super::{
    raw_transport::TransferContext,
    restore_accounts::SignedAccounts,
    restore_archive::{self, CapturedArchive, RestoreArchiveError},
    restore_capsule::{
        CapsuleError, RestoreSecret, open_capsule, prepare_capsule,
        ticket::{Binding, BootId, RestoreTicket, TicketError},
    },
    restore_effective::RootContext,
    restore_identity::{self, IdentityCheckedRestore, RestoreIdentityError},
    restore_job::{self, Check, JobError, PinnedSshHelper, SshPreflightJob},
    restore_native::AccountFiles,
    restore_preflight::{PrepareRootError, PreparedSshRoot, prepare_sshd_root},
};
use crate::config::Config;
use rand_core::{OsRng, RngCore};
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, fsync, openat, renameat_with, unlinkat};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File},
    io::{self, Seek, Write},
    net::IpAddr,
    os::unix::fs::DirBuilderExt,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const TEMPORARY_PREFIX: &str = ".capsule-";
const SUFFIX: &str = ".capsule";

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error(transparent)]
    Capsule(#[from] CapsuleError),
    #[error("restore capsule I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("secure entropy is unavailable")]
    Entropy,
    #[error(transparent)]
    Archive(#[from] RestoreArchiveError),
    #[error(transparent)]
    Identity(#[from] RestoreIdentityError),
    #[error(transparent)]
    Ticket(#[from] TicketError),
    #[error(transparent)]
    Image(#[from] JobError),
    #[error("the sealed restore capsule changed before it was checked")]
    Changed,
    #[error("raw update capture was cancelled")]
    Cancelled,
    #[error(transparent)]
    Preflight(#[from] PrepareRootError),
    #[error("the SSH probe context is invalid")]
    Context,
    #[error("the image does not carry its early restore")]
    NotRestorable,
}
type Result<T> = std::result::Result<T, CaptureError>;

/// The sealed capsule's name and digest, and the key that opens it.
// No Debug/Clone: the secret moves on into exactly one ticket.
pub struct SealedCapsule {
    secret: RestoreSecret,
    sha256: [u8; 32],
    name: String,
}

impl SealedCapsule {
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn into_secret(self) -> RestoreSecret {
        self.secret
    }
}

/// What capture needs from the authenticated target image. Production reads
/// both through the pinned sandbox; host tests stub them.
pub trait TargetImage {
    /// The image's account tables, merged into the captured accounts.
    fn signed_accounts(&mut self, cancel: &AtomicBool) -> Result<SignedAccounts>;
    /// Checks the restored SSH identity against the image's sshd.
    fn check_ssh(
        &mut self,
        restore: &mut IdentityCheckedRestore,
        cancel: &AtomicBool,
    ) -> Result<()>;
}

/// The production target image. The pinned sandbox reads the authenticated
/// read-only image descriptors; nothing from the image runs outside it.
pub struct SandboxImage<'a> {
    pub helper: &'a PinnedSshHelper,
    pub images: &'a [File; 2],
    pub transfer: &'a TransferContext,
    /// Empty private directory; the child mounts the image in its namespace.
    pub mountpoint: &'a Path,
    /// Private directory on the root filesystem for the prepared sshd roots.
    pub ssh_roots: &'a Path,
    pub hostname: &'a str,
}

impl TargetImage for SandboxImage<'_> {
    fn signed_accounts(&mut self, cancel: &AtomicBool) -> Result<SignedAccounts> {
        Ok(restore_job::export_signed_accounts(
            self.helper,
            self.images,
            self.transfer,
            self.mountpoint,
            cancel,
        )?)
    }

    /// The image's sshd must accept the restored configuration, report an
    /// effective policy for a root connection, and prove possession of every
    /// restored host key. No particular policy value is required.
    fn check_ssh(
        &mut self,
        restore: &mut IdentityCheckedRestore,
        cancel: &AtomicBool,
    ) -> Result<()> {
        let checks = [
            Check::Syntax,
            Check::Effective(probe_context(self.hostname)?),
            Check::HostKeys,
        ];
        let Self {
            helper,
            images,
            transfer,
            mountpoint,
            ..
        } = *self;
        run_ssh_checks(restore, self.ssh_roots, checks, |identity, check| {
            SshPreflightJob {
                helper,
                identity,
                images: [images[0].try_clone()?, images[1].try_clone()?],
                transfer: transfer.clone(),
                image_mountpoint: mountpoint.to_path_buf(),
                check,
            }
            .run(cancel)?;
            Ok(())
        })
    }
}

/// One fresh, empty private sshd root per check, removed after its job. A
/// root that does not empty (unknown recovery entries) stays for inspection.
fn run_ssh_checks(
    restore: &mut IdentityCheckedRestore,
    ssh_roots: &Path,
    checks: impl IntoIterator<Item = Check>,
    mut run: impl FnMut(PreparedSshRoot, Check) -> Result<()>,
) -> Result<()> {
    for (index, check) in checks.into_iter().enumerate() {
        let root = ssh_roots.join(format!("check-{index}"));
        DirBuilder::new().mode(0o700).create(&root)?;
        let result = prepare_sshd_root(restore, &root)
            .map_err(CaptureError::from)
            .and_then(|identity| run(identity, check));
        if let Err(error) = &result {
            let stage = ["syntax", "effective", "hostkeys"][index];
            tracing::warn!(stage, error = %error, "SSH preflight check failed");
        }
        let removed = fs::remove_dir(&root);
        result?;
        removed?;
    }
    Ok(())
}

/// A root connection from a documentation address: the default Match branch,
/// independent of the device's networks.
fn probe_context(hostname: &str) -> Result<RootContext> {
    RootContext::new(
        hostname,
        IpAddr::from([192, 0, 2, 10]),
        IpAddr::from([192, 0, 2, 1]),
        22,
        None,
    )
    .map_err(|_| CaptureError::Context)
}

/// Inputs from the authenticated metadata and the live system. The caller holds
/// the update owner and the writer drain, has refused a pending credential or
/// Pico pair journal, and pins `capsule_directory` on the data partition.
pub struct CaptureRequest<'a> {
    pub source_root: &'a Path,
    pub private_staging: &'a Path,
    pub capsule_directory: &'a File,
    pub config: &'a Config,
    pub working_dir: &'a Path,
    pub config_path: &'a Path,
    pub target_version: &'a str,
    pub target: &'a str,
    pub boot_image_sha256: [u8; 32],
    pub rootfs_image_sha256: [u8; 32],
    pub source_boot: BootId,
    pub device_id: [u8; 32],
}

/// A prepared ticket and the capsule it opens. Publishing the ticket and
/// writing the images stay with the caller.
pub struct Captured {
    ticket: RestoreTicket,
    capsule_name: String,
}

impl Captured {
    pub fn capsule_name(&self) -> &str {
        &self.capsule_name
    }
    pub fn into_ticket(self) -> RestoreTicket {
        self.ticket
    }
}

/// Captures the live state, seals it, reopens the sealed capsule as the early
/// restore will and checks it against the image, then binds a prepared ticket
/// to the capsule, both images, this boot and this device. Any failure after
/// sealing removes the capsule; no partition is touched here.
pub fn capture(
    request: &CaptureRequest<'_>,
    image: &mut impl TargetImage,
    cancel: &AtomicBool,
) -> Result<Captured> {
    cancelled(cancel)?;
    let signed = image.signed_accounts(cancel)?;
    // Without its helper a written image would never restore, and the next
    // update would then retire the only capsule of this device's identity.
    if !signed.facts().restorable {
        return Err(CaptureError::NotRestorable);
    }
    cancelled(cancel)?;
    let mut archive = restore_identity::capture_effective(
        request.source_root,
        request.private_staging,
        request.config,
        request.working_dir,
        request.config_path,
        &signed.as_files(),
    )?;
    let sealed = seal_capsule(
        &mut archive,
        request.target_version,
        request.capsule_directory,
    )?;
    drop(archive);
    let checked = verify_sealed(
        &sealed,
        request.capsule_directory,
        request.private_staging,
        &signed.as_files(),
    )
    .and_then(|mut restore| {
        cancelled(cancel)?;
        image.check_ssh(&mut restore, cancel)
    })
    .and_then(|()| cancelled(cancel));
    let capsule_name = sealed.name().to_string();
    let prepared = checked.and_then(|()| {
        let binding = Binding {
            source_boot: request.source_boot,
            device_id: request.device_id,
            capsule_sha256: *sealed.sha256(),
            boot_image_sha256: request.boot_image_sha256,
            rootfs_image_sha256: request.rootfs_image_sha256,
            // The version early boot observes, not the minimum to install.
            target_app_version: signed.facts().app_version.clone(),
            target: request.target.to_string(),
        };
        Ok(RestoreTicket::prepared(sealed.into_secret(), binding)?)
    });
    match prepared {
        Ok(ticket) => Ok(Captured {
            ticket,
            capsule_name,
        }),
        Err(error) => {
            let _ = unlinkat(request.capsule_directory, &capsule_name, AtFlags::empty())
                .and_then(|()| fsync(request.capsule_directory));
            Err(error)
        }
    }
}

/// Reopens the published capsule, requires the digest the ticket will carry,
/// decrypts it and validates the archive and its accounts, as restore will.
fn verify_sealed(
    sealed: &SealedCapsule,
    directory: &File,
    private_staging: &Path,
    signed: &AccountFiles<'_>,
) -> Result<IdentityCheckedRestore> {
    let mut file = File::from(
        openat(
            directory,
            sealed.name(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    );
    let mut hash = Sha256::new();
    io::copy(&mut file, &mut hash)?;
    if <[u8; 32]>::from(hash.finalize()) != sealed.sha256 {
        return Err(CaptureError::Changed);
    }
    file.rewind()?;
    let payload = open_capsule(&sealed.secret, &mut file, private_staging)?;
    let validated = restore_archive::validate(payload)?;
    Ok(restore_identity::check_identity(validated, signed)?)
}

fn cancelled(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::SeqCst) {
        Err(CaptureError::Cancelled)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailBefore {
    Sync,
    Rename,
    DirectorySync,
}
#[cfg(test)]
thread_local! {
    static FAIL_AT: std::cell::Cell<Option<FailBefore>> = const { std::cell::Cell::new(None) };
}

/// Encrypts `archive` into `directory` as `<transaction>.capsule`: an exclusive
/// 0600 temporary, fsync, a rename that never replaces, then a directory
/// fsync. On any error no secret is returned and neither the temporary nor a
/// published capsule is left, as far as the directory allows removal.
/// `directory` must be the pinned private capsule directory.
pub fn seal_capsule(
    archive: &mut CapturedArchive,
    target_version: &str,
    directory: &File,
) -> Result<SealedCapsule> {
    let mut suffix = [0; 8];
    OsRng
        .try_fill_bytes(&mut suffix)
        .map_err(|_| CaptureError::Entropy)?;
    let temporary = format!("{TEMPORARY_PREFIX}{}.tmp", hex(&suffix));
    let file = File::from(
        openat(
            directory,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io::Error::from)?,
    );
    let sealed = write_and_publish(archive, target_version, directory, &temporary, file);
    if sealed.is_err() {
        // Gone after a successful rename; otherwise never left behind.
        let _ = unlinkat(directory, &temporary, AtFlags::empty());
    }
    sealed
}

fn write_and_publish(
    archive: &mut CapturedArchive,
    target_version: &str,
    directory: &File,
    temporary: &str,
    mut file: File,
) -> Result<SealedCapsule> {
    archive.rewind()?;
    let size = archive.size();
    let mut output = HashingWriter {
        inner: &mut file,
        hash: Sha256::new(),
    };
    let secret = prepare_capsule(target_version, size, archive, &mut output)?;
    let sha256 = output.hash.finalize().into();
    fail(FailBefore::Sync)?;
    file.sync_all()?;
    drop(file);
    let name = format!("{}{SUFFIX}", hex(&secret.transaction_id()));
    fail(FailBefore::Rename)?;
    renameat_with(
        directory,
        temporary,
        directory,
        &name,
        RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)?;
    if let Err(error) =
        fail(FailBefore::DirectorySync).and_then(|()| fsync(directory).map_err(io::Error::from))
    {
        // The secret never leaves this function, so nothing could open it.
        let _ = unlinkat(directory, &name, AtFlags::empty());
        return Err(error.into());
    }
    Ok(SealedCapsule {
        secret,
        sha256,
        name,
    })
}

fn fail(step: FailBefore) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_AT.with(|fail| fail.get()) == Some(step) {
        return Err(io::Error::other("injected capsule fault"));
    }
    #[cfg(not(test))]
    let _ = step;
    Ok(())
}

struct HashingWriter<'a> {
    inner: &'a mut File,
    hash: Sha256,
}
impl Write for HashingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(bytes)?;
        self.hash.update(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "raw_capture_tests.rs"]
mod tests;
