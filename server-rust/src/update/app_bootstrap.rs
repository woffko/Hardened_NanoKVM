//! Compile-bound app recovery and fixed-rootfs bootstrap publication. Early
//! consumer gate scripts are compile-bound below; the slot producer remains open.

use super::{app_slot, operation_lock::ProcessLock, restore_binding, restore_fs};
use rand_core::{OsRng, RngCore};
use rustix::fs::{Mode, OFlags, RenameFlags, fchmod, mkdirat, openat, renameat_with};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

const EXECUTABLE: &str = "nanokvm-app-recovery";

// Trusted backend source bytes, never a runtime /kvmapp or manifest fallback.
// S95 must not overwrite these independent gates from a rolled-back bundle.
pub const BOOT_SCRIPTS: &[(&str, &[u8])] = &[
    (
        "S02apprecover",
        include_bytes!("../../../kvmapp/system/init.d/S02apprecover"),
    ),
    (
        "S30eth",
        include_bytes!("../../../kvmapp/system/init.d/S30eth"),
    ),
    (
        "S30wifi",
        include_bytes!("../../../kvmapp/system/init.d/S30wifi"),
    ),
    (
        "S95nanokvm",
        include_bytes!("../../../kvmapp/system/init.d/S95nanokvm"),
    ),
];

/// Only a trusted backend build supplies these immutable bytes. No runtime
/// pathname, manifest, environment variable or bundled helper is a fallback.
/// This checks framing/ELF/build consistency, not a release RSA signature.
pub fn embedded_recovery() -> io::Result<&'static [u8]> {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/app-recovery.binding"));
    let binding = restore_binding::validate_app_recovery(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid embedded app recovery"))?;
    Ok(binding.image)
}

/// Establish independent support for a historical app-only bridge. This is not
/// itself an early boot invocation, slot authorization, health acknowledgement or permission
/// to perform the legacy two-rename swap. Never replace a different helper.
pub fn ensure_installed() -> io::Result<()> {
    let image = embedded_recovery()?;
    let _admission = ProcessLock::acquire().map_err(io::Error::other)?;
    let absent_transaction = no_transaction()?;
    let root = restore_fs::open_root(Path::new("/"), true)?;
    let _boot_parent = boot_parent_at(&root, 0)?;
    let parent = fixed_parent(absent_transaction)?;
    ensure_at(&parent, image, 0, absent_transaction)
}

/// The caller already owns app/system update admission. Read-only prerequisite
/// for the still-legacy app API, never a claim that its swap is crash-safe.
/// Any journal (including terminal), corrupt state or missing helper refuses
/// another legacy mutation; the future producer must own journal retirement.
pub fn check_before_legacy_install() -> io::Result<()> {
    let image = embedded_recovery()?;
    if !no_transaction()? {
        return Err(invalid());
    }
    let parent = fixed_parent(false)?;
    let _file = existing(&parent, EXECUTABLE, image, 0)?.ok_or_else(invalid)?;
    parent.sync_all()?;
    let root = restore_fs::open_root(Path::new("/"), true)?;
    check_boot_scripts_at(&root, 0)?;
    Ok(())
}

fn check_boot_scripts_at(root: &File, uid: u32) -> io::Result<()> {
    let parent = boot_parent_at(root, uid)?;
    for (name, bytes) in BOOT_SCRIPTS {
        let file = existing(&parent, name, bytes, uid)?.ok_or_else(invalid)?;
        file.sync_all()?;
    }
    parent.sync_all()
}

fn boot_parent_at(root: &File, uid: u32) -> io::Result<File> {
    let device = root.metadata()?.dev();
    protected_directory(root, uid, device)?;
    let etc = restore_fs::open_beneath(root, "etc", OFlags::RDONLY | OFlags::DIRECTORY)?;
    protected_directory(&etc, uid, device)?;
    let parent = restore_fs::open_beneath(&etc, "init.d", OFlags::RDONLY | OFlags::DIRECTORY)?;
    protected_directory(&parent, uid, device)?;
    Ok(parent)
}

fn no_transaction() -> io::Result<bool> {
    app_slot::status()
        .map(|status| status == app_slot::Status::NoTransaction)
        .map_err(io::Error::other)
}

fn fixed_parent(create: bool) -> io::Result<File> {
    if !nix::unistd::geteuid().is_root() {
        return Err(invalid());
    }
    let root = restore_fs::open_root(Path::new("/"), true)?;
    parent_at(&root, 0, create)
}

fn parent_at(root: &File, uid: u32, create: bool) -> io::Result<File> {
    let device = root.metadata()?.dev();
    protected_directory(root, uid, device)?;
    let usr = restore_fs::open_beneath(root, "usr", OFlags::RDONLY | OFlags::DIRECTORY)?;
    protected_directory(&usr, uid, device)?;
    let mut created = false;
    let parent = match restore_fs::open_beneath(&usr, "libexec", OFlags::RDONLY | OFlags::DIRECTORY)
    {
        Ok(parent) => parent,
        Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
            match mkdirat(&usr, "libexec", Mode::from_raw_mode(0o755)) {
                Ok(()) => created = true,
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            let parent =
                restore_fs::open_beneath(&usr, "libexec", OFlags::RDONLY | OFlags::DIRECTORY)?;
            // Only this invocation's newly created directory may have its mode
            // established; an existing object is never chmod-repaired.
            if created {
                protected_directory(&parent, uid, device)?;
                fchmod(&parent, Mode::from_raw_mode(0o755))?;
            }
            parent
        }
        Err(error) => return Err(error),
    };
    protected_directory(&parent, uid, device)?;
    // Also finish a prior invocation's rename/mkdir durability barrier.
    parent.sync_all()?;
    usr.sync_all()?;
    Ok(parent)
}

fn protected_directory(directory: &File, uid: u32, device: u64) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.dev() != device
        || metadata.mode() & 0o7022 != 0
    {
        return Err(invalid());
    }
    Ok(())
}

fn checked_file(file: &File, uid: u32, device: u64, size: usize) -> io::Result<std::fs::Metadata> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.dev() != device
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o755
        || metadata.len() != size as u64
    {
        return Err(invalid());
    }
    Ok(metadata)
}

fn existing(parent: &File, name: &str, image: &[u8], uid: u32) -> io::Result<Option<File>> {
    let device = parent.metadata()?.dev();
    protected_directory(parent, uid, device)?;
    // Inspect the object before any data open. O_PATH cannot block on a FIFO
    // or trigger a device read; openat2 still rejects all aliases/mounts.
    let identity = match restore_fs::open_beneath(parent, name, OFlags::PATH) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let identity = checked_file(&identity, uid, device, image.len())?;
    let mut file = restore_fs::open_beneath(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let before = checked_file(&file, uid, device, image.len())?;
    if before.ino() != identity.ino() {
        return Err(invalid());
    }
    let mut buffer = [0; 16 * 1024];
    for expected in image.chunks(buffer.len()) {
        file.read_exact(&mut buffer[..expected.len()])?;
        if buffer[..expected.len()] != *expected {
            return Err(invalid());
        }
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(invalid());
    }
    let after = checked_file(&file, uid, device, image.len())?;
    let named = restore_fs::open_beneath(parent, name, OFlags::PATH)?;
    let named = checked_file(&named, uid, device, image.len())?;
    if after.ino() != identity.ino() || named.ino() != identity.ino() {
        return Err(invalid());
    }
    Ok(Some(file))
}

fn ensure_at(parent: &File, image: &[u8], uid: u32, install: bool) -> io::Result<()> {
    if image.is_empty() || image.len() as u64 > restore_binding::MAX_HELPER {
        return Err(invalid());
    }
    if let Some(file) = existing(parent, EXECUTABLE, image, uid)? {
        file.sync_all()?;
        parent.sync_all()?;
        return Ok(());
    }
    if !install {
        return Err(invalid());
    }
    let mut nonce = [0; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| io::Error::other("app bootstrap entropy unavailable"))?;
    let name = format!(
        ".nanokvm-app-recovery-next-{:032x}",
        u128::from_be_bytes(nonce)
    );
    let mut file: File = openat(
        parent,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?
    .into();
    // Fresh exclusive FD only. Existing files are never written/chmod-repaired.
    fchmod(&file, Mode::from_raw_mode(0o600))?;
    file.write_all(image)?;
    #[cfg(test)]
    checkpoint("written");
    fchmod(&file, Mode::from_raw_mode(0o755))?;
    file.sync_all()?;
    #[cfg(test)]
    checkpoint("synced");
    publish(parent, &name, image, uid)
}

fn publish(parent: &File, name: &str, image: &[u8], uid: u32) -> io::Result<()> {
    match renameat_with(parent, name, parent, EXECUTABLE, RenameFlags::NOREPLACE) {
        Ok(()) => {}
        // Another publisher must have installed the exact same safe image.
        // Retain this temporary; do not overwrite or delete the winner.
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    #[cfg(test)]
    checkpoint("renamed");
    parent.sync_all()?;
    #[cfg(test)]
    checkpoint("published");
    let _file = existing(parent, EXECUTABLE, image, uid)?.ok_or_else(invalid)?;
    Ok(())
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unsafe or mismatched independent app recovery",
    )
}

#[cfg(test)]
fn checkpoint(position: &str) {
    if std::env::var("NANOKVM_APP_BOOTSTRAP_TEST_STOP").as_deref() == Ok(position) {
        println!("app-bootstrap-checkpoint-ready");
        io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
}

#[cfg(test)]
#[path = "app_bootstrap_tests.rs"]
mod tests;
