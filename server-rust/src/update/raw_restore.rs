use super::{
    restore_archive::{self, RestoreAction, RestoreArchiveError},
    restore_capsule::ticket::{
        self, BootId, BootObservation, Phase, RestoreTicket, Store, TicketError,
    },
    restore_identity::{self, IdentityCheckedRestore, RestoreIdentityError},
    restore_native::AccountFiles,
};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, mkdirat, renameat, statat, unlinkat};
use serde::Deserialize;
use std::{
    fs::{self, File},
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
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
    #[error("raw restore target {path} failed: {source}")]
    Target { path: String, source: Box<Error> },
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
    let boot = observed.boot();
    match ticket.phase() {
        Phase::Committed => {
            // Only this system's own restore ends the requirement: a fresh
            // image never inherits the receipt of an earlier one.
            ticket.belongs_to(&boot)?;
            finish(root, capsule_dir, &ticket);
            return Ok(Outcome::AlreadyCommitted);
        }
        Phase::Abandoned => return Err(Error::Abandoned),
        Phase::Prepared | Phase::Applying | Phase::Restored => {}
    }
    if matches!(ticket.phase(), Phase::Prepared | Phase::Applying) {
        store.begin_apply(&mut ticket, &boot)?;
    }
    let identity = open_archive(root, store, &ticket, capsule_dir, staging, &boot)?;
    apply(root, identity)?;
    if ticket.phase() == Phase::Applying {
        store.mark_restored(&mut ticket, &boot)?;
    }
    store.commit(&mut ticket, &boot)?;
    finish(root, capsule_dir, &ticket);
    Ok(Outcome::Applied)
}

/// The commit is the restore's last durable fact. What follows is cleanup, and
/// a failure here must not keep the owner out: the ticket has lost its key, so
/// a leftover capsule is inert, and a requirement that stays is retired by the
/// next boot.
fn finish(root: &Path, capsule_dir: &Path, ticket: &RestoreTicket) {
    if let Err(error) = remove_capsule(capsule_dir, ticket) {
        eprintln!("raw early restore: capsule not removed: {error}");
    }
    if let Err(error) = retire_required(root) {
        eprintln!("raw early restore: requirement not retired: {error}");
    }
}

/// Ends the requirement on a restored rootfs. From here on its boots no longer
/// read the boot ticket, which later update attempts replace and which sits on
/// a FAT partition, so neither can keep this system off the network.
pub fn retire_required(root: &Path) -> io::Result<()> {
    let path = root.join(REQUIRED_PATH);
    match fs::remove_file(&path) {
        Ok(()) => File::open(root.join("etc/kvm"))?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
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
    // Validate every parent before replacing identity files. Fresh images do
    // not contain optional settings/workspace directories. Create only parents
    // of authenticated writes, privately, without following symlinks.
    for member in identity.members() {
        parent_directory(root, &member.path, member.action == RestoreAction::Write).map_err(
            |source| Error::Target {
                path: member.path.clone(),
                source: Box::new(source),
            },
        )?;
    }
    for index in 0..identity.members().len() {
        let (path, action, mode) = {
            let member = &identity.members()[index];
            (member.path.clone(), member.action, member.mode)
        };
        let result = match action {
            RestoreAction::Write => write_member(root, &path, mode, &mut identity, index),
            RestoreAction::Absent => remove_member(root, &path),
        };
        result.map_err(|source| Error::Target {
            path,
            source: Box::new(source),
        })?;
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
    let (parent, name) = parent_directory(root, path, true)?.ok_or(Error::UnsafePath)?;
    let temporary = format!(".nanokvm-restore-{}-{index}", std::process::id());
    // A power cut can leave this name behind, and early boot PIDs repeat.
    match unlinkat(&parent, &temporary, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(io::Error::from(error).into()),
    }
    let mut file: File = rustix::fs::openat(
        &parent,
        &temporary,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(io::Error::from)?
    .into();
    let result = (|| -> Result<()> {
        identity.copy_file(index, &mut file)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        renameat(&parent, &temporary, &parent, name).map_err(io::Error::from)?;
        parent.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = unlinkat(&parent, &temporary, AtFlags::empty());
    }
    result
}

fn remove_member(root: &Path, path: &str) -> Result<()> {
    let Some((parent, name)) = parent_directory(root, path, false)? else {
        return Ok(());
    };
    match statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata)
            if matches!(
                FileType::from_raw_mode(metadata.st_mode),
                FileType::RegularFile | FileType::Symlink
            ) =>
        {
            unlinkat(&parent, name, AtFlags::empty()).map_err(io::Error::from)?;
            parent.sync_all()?;
            Ok(())
        }
        Ok(_) => Err(Error::UnsafePath),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(io::Error::from(error).into()),
    }
}

fn parent_directory<'a>(
    root: &Path,
    relative: &'a str,
    create: bool,
) -> Result<Option<(File, &'a str)>> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Error::UnsafePath);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(Error::UnsafePath)?;
    let mut directory = super::restore_fs::open_root(root, false)?;
    for (index, component) in path
        .parent()
        .ok_or(Error::UnsafePath)?
        .components()
        .enumerate()
    {
        let Component::Normal(part) = component else {
            return Err(Error::UnsafePath);
        };
        let part = part.to_str().ok_or(Error::UnsafePath)?;
        if index == 0 && part == "boot" {
            // The one admitted cross-mount parent is the protected boot store.
            directory = super::restore_fs::open_boot(&directory)?;
            continue;
        }
        match super::restore_fs::open_beneath(&directory, part, OFlags::RDONLY | OFlags::DIRECTORY)
        {
            Ok(child) => directory = child,
            Err(error) if error.kind() == io::ErrorKind::NotFound && !create => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match mkdirat(&directory, part, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                    Ok(()) => directory.sync_all()?,
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(error) => return Err(io::Error::from(error).into()),
                }
                directory = super::restore_fs::open_beneath(
                    &directory,
                    part,
                    OFlags::RDONLY | OFlags::DIRECTORY,
                )?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(Some((directory, name)))
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
