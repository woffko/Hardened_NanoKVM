use super::{
    restore_archive::{self, RestoreAction, RestoreArchiveError},
    restore_capsule::ticket::{
        self, BootId, BootObservation, Phase, RestoreTicket, Store, TicketError,
    },
    restore_identity::{self, IdentityCheckedRestore, RestoreIdentityError},
    restore_native::AccountFiles,
};
use serde::Deserialize;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path},
};

pub const REQUIRED_PATH: &str = "etc/kvm/raw-restore-required";
pub const REQUIRED_BYTES: &[u8] = b"nanokvm-raw-restore-required-v1\n";
pub const CAPSULE_DIR: &str = "/data/.nanokvm-restore";
pub const STAGING_DIR: &str = "/etc/kvm/.raw-restore";
pub const BLOCK_MARKER: &str = "/run/nanokvm-restore-blocked";
const MAX_ACCOUNT: u64 = 1024 * 1024;
const MAX_VERSION: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Ticket(#[from] TicketError),
    #[error(transparent)]
    Archive(#[from] RestoreArchiveError),
    #[error(transparent)]
    Identity(#[from] RestoreIdentityError),
    #[error("raw restore I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("raw restore-required marker is missing or invalid")]
    InvalidMarker,
    #[error("raw image has no prepared restore ticket")]
    MissingTicket,
    #[error("raw restore ticket was abandoned")]
    Abandoned,
    #[error("raw restore target path is unsafe")]
    UnsafePath,
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    NotRequired,
    Applied,
    AlreadyCommitted,
}

#[derive(Debug, Deserialize)]
struct VersionFile {
    version: String,
    target: String,
}

pub struct Observation {
    pub boot_id: BootId,
    pub device_id: [u8; 32],
    pub system_version: String,
    pub app_version: String,
    pub target: String,
}

impl Observation {
    fn boot(&self) -> BootObservation<'_> {
        BootObservation {
            boot_id: self.boot_id,
            device_id: self.device_id,
            system_version: &self.system_version,
            app_version: &self.app_version,
            target: &self.target,
        }
    }
}

pub fn run_early() -> Result<Outcome> {
    let result = (|| -> Result<Outcome> {
        let mut store = Store::open_boot()?;
        let root = Path::new("/");
        let observed = observe(root)?;
        run_observed(
            root,
            &mut store,
            Path::new(CAPSULE_DIR),
            Path::new(STAGING_DIR),
            Path::new(BLOCK_MARKER),
            &observed,
        )
    })();
    if result.is_err() {
        let _ = write_marker(Path::new(BLOCK_MARKER));
    }
    result
}

pub fn run_observed(
    root: &Path,
    store: &mut Store,
    capsule_dir: &Path,
    staging: &Path,
    marker: &Path,
    observed: &Observation,
) -> Result<Outcome> {
    let result = (|| -> Result<Outcome> {
        if !required(root)? {
            return Ok(Outcome::NotRequired);
        }
        run_required(root, store, capsule_dir, staging, observed)
    })();
    match &result {
        Ok(_) => {
            let _ = fs::remove_file(marker);
        }
        Err(_) => {
            let _ = write_marker(marker);
        }
    }
    result
}

fn run_required(
    root: &Path,
    store: &mut Store,
    capsule_dir: &Path,
    staging: &Path,
    observed: &Observation,
) -> Result<Outcome> {
    let mut ticket = store.load()?.ok_or(Error::MissingTicket)?;
    match ticket.phase() {
        Phase::Committed => {
            remove_capsule(capsule_dir, &ticket)?;
            return Ok(Outcome::AlreadyCommitted);
        }
        Phase::Abandoned => return Err(Error::Abandoned),
        Phase::Prepared | Phase::Applying | Phase::Restored => {}
    }
    let boot = observed.boot();
    if matches!(ticket.phase(), Phase::Prepared | Phase::Applying) {
        store.begin_apply(&mut ticket, &boot)?;
    }
    let identity = open_archive(root, store, &ticket, capsule_dir, staging, &boot)?;
    apply(root, identity)?;
    if ticket.phase() == Phase::Applying {
        store.mark_restored(&mut ticket, &boot)?;
    }
    store.commit(&mut ticket, &boot)?;
    remove_capsule(capsule_dir, &ticket)?;
    Ok(Outcome::Applied)
}

fn required(root: &Path) -> Result<bool> {
    let path = root.join(REQUIRED_PATH);
    match fs::read(&path) {
        Ok(bytes) if bytes == REQUIRED_BYTES => {
            let metadata = fs::metadata(&path)?;
            if !metadata.is_file()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o644
            {
                return Err(Error::InvalidMarker);
            }
            Ok(true)
        }
        Ok(_) => Err(Error::InvalidMarker),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn write_marker(marker: &Path) -> Result<()> {
    fs::write(marker, b"raw restore blocked\n")?;
    fs::set_permissions(marker, fs::Permissions::from_mode(0o600))?;
    if let Some(parent) = marker.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn open_archive(
    root: &Path,
    store: &mut Store,
    ticket: &RestoreTicket,
    capsule_dir: &Path,
    staging: &Path,
    observed: &BootObservation<'_>,
) -> Result<IdentityCheckedRestore> {
    let capsule = capsule_path(capsule_dir, ticket);
    let mut file = File::open(capsule)?;
    let payload = store.decrypt(ticket, observed, &mut file, staging)?;
    let archive = restore_archive::validate(payload)?;
    let passwd = read_bounded(&root.join("etc/passwd"), MAX_ACCOUNT)?;
    let group = read_bounded(&root.join("etc/group"), MAX_ACCOUNT)?;
    let shadow = read_bounded(&root.join("etc/shadow"), MAX_ACCOUNT)?;
    let gshadow = read_optional(&root.join("etc/gshadow"), MAX_ACCOUNT)?;
    let accounts = AccountFiles {
        passwd: &passwd,
        group: &group,
        shadow: &shadow,
        gshadow: gshadow.as_deref(),
    };
    restore_identity::check_identity(archive, &accounts).map_err(Into::into)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(Error::Io(io::Error::other(
            "account table is not a bounded file",
        )));
    }
    Ok(fs::read(path)?)
}

fn read_optional(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    match read_bounded(path, limit) {
        Ok(value) => Ok(Some(value)),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn apply(root: &Path, mut identity: IdentityCheckedRestore) -> Result<()> {
    for index in 0..identity.members().len() {
        let (path, action, mode) = {
            let member = &identity.members()[index];
            (member.path.clone(), member.action, member.mode)
        };
        match action {
            RestoreAction::Write => {
                write_member(root, &path, mode, &mut identity, index)?;
            }
            RestoreAction::Absent => remove_member(root, &path)?,
        }
    }
    File::open(root)?.sync_all()?;
    Ok(())
}

fn write_member(
    root: &Path,
    path: &str,
    mode: u32,
    identity: &mut IdentityCheckedRestore,
    index: usize,
) -> Result<()> {
    let target = safe_target(root, path)?;
    let parent = target.parent().ok_or(Error::UnsafePath)?;
    if !parent.is_dir() {
        return Err(Error::UnsafePath);
    }
    let temporary = parent.join(format!(".nanokvm-restore-{}-{index}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    #[cfg(target_os = "linux")]
    options.custom_flags(nix::libc::O_NOFOLLOW);
    let mut file = options.open(&temporary)?;
    let result = (|| -> Result<()> {
        identity.copy_file(index, &mut file)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        fs::rename(&temporary, &target)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_member(root: &Path, path: &str) -> Result<()> {
    let target = safe_target(root, path)?;
    match fs::symlink_metadata(&target) {
        Ok(metadata) if metadata.file_type().is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(&target)?;
            if let Some(parent) = target.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
        Ok(_) => Err(Error::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn safe_target(root: &Path, relative: &str) -> Result<std::path::PathBuf> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::UnsafePath);
    }
    Ok(root.join(path))
}

fn capsule_path(directory: &Path, ticket: &RestoreTicket) -> std::path::PathBuf {
    directory.join(format!(
        "{:032x}.capsule",
        u128::from_be_bytes(ticket.transaction_id())
    ))
}

fn remove_capsule(directory: &Path, ticket: &RestoreTicket) -> Result<()> {
    match fs::remove_file(capsule_path(directory, ticket)) {
        Ok(()) => {
            File::open(directory)?.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn observe(root: &Path) -> Result<Observation> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot_id = BootId::parse(boot.trim()).map_err(|_| Error::InvalidMarker)?;
    let device_id = ticket::device_id().map_err(|_| Error::InvalidMarker)?;
    let version: VersionFile = serde_json::from_slice(&read_bounded(
        &root.join("etc/kvm/system-version.json"),
        MAX_VERSION,
    )?)
    .map_err(|_| Error::InvalidMarker)?;
    let app_version = fs::read_to_string(root.join("kvmapp/version"))?;
    let app_version = app_version.trim().to_string();
    if app_version.is_empty() {
        return Err(Error::InvalidMarker);
    }
    Ok(Observation {
        boot_id,
        device_id,
        system_version: version.version,
        app_version,
        target: version.target,
    })
}

#[cfg(test)]
#[path = "raw_restore_tests.rs"]
mod tests;
