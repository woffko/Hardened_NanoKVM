//! Compile-bound app recovery and fixed-rootfs bootstrap publication. Early
//! consumer gate scripts are compile-bound below; the slot producer remains open.

use super::{app_slot, operation_lock::ProcessLock, restore_binding, restore_fs};
use rand_core::{OsRng, RngCore};
use rustix::fs::{Mode, OFlags, RenameFlags, fchmod, mkdirat, openat, renameat_with};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

const EXECUTABLE: &str = "nanokvm-app-recovery";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HelperVersion {
    size: usize,
    sha256: [u8; 32],
}

// Directed, compile-bound compatibility, not a runtime manifest or a version
// string supplied by the installed executable. This exact v1 development helper
// is retained in the 89aa736 evidence. RC12 itself has no independent helper.
// New entries require exact-byte review and journal/rollback compatibility review.
const V1_PREDECESSORS: &[HelperVersion] = &[HelperVersion {
    size: 373_048,
    sha256: [
        0x90, 0x95, 0x52, 0x2c, 0xaf, 0x08, 0xd9, 0xf0, 0xa0, 0xbf, 0x2f, 0x70, 0x91, 0x7b, 0x9c,
        0xe7, 0x33, 0x93, 0x0d, 0x9c, 0xed, 0xb8, 0x5f, 0x50, 0x24, 0x9b, 0x74, 0x5c, 0xc2, 0xb5,
        0x35, 0xe8,
    ],
}];

// Trusted backend source bytes, never a runtime /kvmapp or manifest fallback.
// S95 must not overwrite these independent gates from a rolled-back bundle.
// Both views reference the SAME generated frames; there is no second payload.
pub const BOOT_SCRIPT_FRAMES: [&[u8]; 4] = [
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/boot-script-S02apprecover.binding"
    )),
    include_bytes!(concat!(env!("OUT_DIR"), "/boot-script-S30eth.binding")),
    include_bytes!(concat!(env!("OUT_DIR"), "/boot-script-S30wifi.binding")),
    include_bytes!(concat!(env!("OUT_DIR"), "/boot-script-S95nanokvm.binding")),
];

// Build.rs has already validated the frame and its minimum length. Stripping
// this constant prefix preserves the existing exact startup payload API.
const fn boot_script_payload(frame: &[u8]) -> &[u8] {
    frame.split_at(super::boot_script_binding::HEADER).1
}

pub const BOOT_SCRIPTS: &[(&str, &[u8])] = &[
    ("S02apprecover", boot_script_payload(BOOT_SCRIPT_FRAMES[0])),
    ("S30eth", boot_script_payload(BOOT_SCRIPT_FRAMES[1])),
    ("S30wifi", boot_script_payload(BOOT_SCRIPT_FRAMES[2])),
    ("S95nanokvm", boot_script_payload(BOOT_SCRIPT_FRAMES[3])),
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
/// to perform the legacy two-rename swap. Only explicitly pinned v1 predecessors
/// may be replaced; unknown helpers and nonterminal journals refuse migration.
pub fn ensure_installed() -> io::Result<()> {
    let image = embedded_recovery()?;
    let admission = ProcessLock::acquire().map_err(io::Error::other)?;
    ensure_with_admission(image, &admission)
}

// Only callers with compile-bound image bytes and the same live update lease
// may compose app/native bootstrap without an inter-family admission gap.
pub(super) fn ensure_with_admission(image: &[u8], admission: &ProcessLock) -> io::Result<()> {
    let status = app_slot::status().map_err(io::Error::other)?;
    let root = restore_fs::open_root(Path::new("/"), true)?;
    let _boot_parent = boot_parent_at(&root, 0)?;
    let parent = fixed_parent(status == app_slot::Status::NoTransaction)?;
    ensure_at(&parent, image, 0, status, V1_PREDECESSORS, admission)
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
    super::native_bootstrap::check_installed()?;
    Ok(())
}

/// Read-only trial prerequisite under a retained parent-owned installation.
/// Unlike legacy admission this must not inspect/acquire the busy app store.
pub fn check_trial_support(_startup: &super::app_trial::Startup) -> io::Result<()> {
    let image = embedded_recovery()?;
    let parent = fixed_parent(false)?;
    let _file = existing(&parent, EXECUTABLE, image, 0)?.ok_or_else(invalid)?;
    let root = restore_fs::open_root(Path::new("/"), true)?;
    check_boot_scripts_at(&root, 0)?;
    super::native_bootstrap::check_installed()
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

pub(super) fn parent_at(root: &File, uid: u32, create: bool) -> io::Result<File> {
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

fn open_existing(
    parent: &File,
    name: &str,
    size: usize,
    uid: u32,
) -> io::Result<Option<(File, u64)>> {
    let device = parent.metadata()?.dev();
    protected_directory(parent, uid, device)?;
    // Inspect the object before any data open. O_PATH cannot block on a FIFO
    // or trigger a device read; openat2 still rejects all aliases/mounts.
    let identity = match restore_fs::open_beneath(parent, name, OFlags::PATH) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let identity = checked_file(&identity, uid, device, size)?;
    let file = restore_fs::open_beneath(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let before = checked_file(&file, uid, device, size)?;
    if before.ino() != identity.ino() {
        return Err(invalid());
    }
    Ok(Some((file, identity.ino())))
}

fn finish_existing(
    parent: &File,
    name: &str,
    file: &File,
    size: usize,
    uid: u32,
    inode: u64,
) -> io::Result<()> {
    let device = parent.metadata()?.dev();
    protected_directory(parent, uid, device)?;
    let after = checked_file(file, uid, device, size)?;
    let named = restore_fs::open_beneath(parent, name, OFlags::PATH)?;
    let named = checked_file(&named, uid, device, size)?;
    if after.ino() != inode || named.ino() != inode {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn existing(
    parent: &File,
    name: &str,
    image: &[u8],
    uid: u32,
) -> io::Result<Option<File>> {
    let Some((mut file, inode)) = open_existing(parent, name, image.len(), uid)? else {
        return Ok(None);
    };
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
    finish_existing(parent, name, &file, image.len(), uid, inode)?;
    Ok(Some(file))
}

fn predecessor(
    parent: &File,
    name: &str,
    uid: u32,
    versions: &[HelperVersion],
) -> io::Result<File> {
    // Unknown sizes are refused before opening for data. The O_PATH inspection
    // cannot block on a FIFO or read a device, and aliases are rejected.
    let identity = restore_fs::open_beneath(parent, name, OFlags::PATH)?;
    let size = identity.metadata()?.len();
    let version = versions
        .iter()
        .find(|version| {
            version.size != 0
                && version.size as u64 <= restore_binding::MAX_HELPER
                && version.size as u64 == size
        })
        .ok_or_else(invalid)?;
    let Some((mut file, inode)) = open_existing(parent, name, version.size, uid)? else {
        return Err(invalid());
    };
    let mut hash = Sha256::new();
    let mut remaining = version.size;
    let mut buffer = [0; 16 * 1024];
    while remaining != 0 {
        let length = remaining.min(buffer.len());
        file.read_exact(&mut buffer[..length])?;
        hash.update(&buffer[..length]);
        remaining -= length;
    }
    if file.read(&mut buffer[..1])? != 0 {
        return Err(invalid());
    }
    let digest: [u8; 32] = hash.finalize().into();
    if !versions
        .iter()
        .any(|version| version.size as u64 == size && version.sha256 == digest)
    {
        return Err(invalid());
    }
    finish_existing(parent, name, &file, version.size, uid, inode)?;
    Ok(file)
}

fn ensure_at(
    parent: &File,
    image: &[u8],
    uid: u32,
    status: app_slot::Status,
    predecessors: &[HelperVersion],
    _admission: &ProcessLock,
) -> io::Result<()> {
    if image.is_empty() || image.len() as u64 > restore_binding::MAX_HELPER {
        return Err(invalid());
    }
    match existing(parent, EXECUTABLE, image, uid) {
        Ok(Some(file)) => {
            file.sync_all()?;
            parent.sync_all()?;
            return Ok(());
        }
        Ok(None) if status == app_slot::Status::NoTransaction => {}
        Ok(None) => return Err(invalid()),
        Err(error)
            if error.kind() == io::ErrorKind::InvalidData
                && matches!(
                    status,
                    app_slot::Status::NoTransaction
                        | app_slot::Status::Transaction(
                            app_slot::Phase::Committed | app_slot::Phase::RolledBack
                        )
                ) =>
        {
            return migrate_at(parent, image, uid, predecessors);
        }
        Err(error) => return Err(error),
    }
    let name = stage_helper(parent, image)?;
    publish(parent, &name, image, uid)
}

fn stage_helper(parent: &File, image: &[u8]) -> io::Result<String> {
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
    Ok(name)
}

fn migrate_at(
    parent: &File,
    image: &[u8],
    uid: u32,
    predecessors: &[HelperVersion],
) -> io::Result<()> {
    let previous = predecessor(parent, EXECUTABLE, uid, predecessors)?;
    previous.sync_all()?;
    let inode = previous.metadata()?.ino();
    let name = stage_helper(parent, image)?;
    // The caller holds update admission throughout status inspection, staging
    // and publication. Recheck the protected canonical name before exchange;
    // unrelated privileged writers must use the same admission protocol.
    let named = predecessor(parent, EXECUTABLE, uid, predecessors)?;
    if named.metadata()?.ino() != inode {
        return Err(invalid());
    }
    renameat_with(
        parent,
        name.as_str(),
        parent,
        EXECUTABLE,
        RenameFlags::EXCHANGE,
    )?;
    #[cfg(test)]
    checkpoint("exchanged");
    #[cfg(test)]
    if std::env::var("NANOKVM_APP_BOOTSTRAP_TEST_ERROR").as_deref() == Ok("exchange-sync") {
        return Err(io::Error::other("injected exchange directory sync error"));
    }
    parent.sync_all()?;
    #[cfg(test)]
    checkpoint("exchange-published");
    // Exchange retains the exact previous inode at the exclusive random name.
    // It is evidence only, never a fallback executable or a journal authority.
    let retained = predecessor(parent, &name, uid, predecessors)?;
    if retained.metadata()?.ino() != inode {
        return Err(invalid());
    }
    let current = existing(parent, EXECUTABLE, image, uid)?.ok_or_else(invalid)?;
    current.sync_all()?;
    Ok(())
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
        if std::env::var_os("NANOKVM_APP_BOOTSTRAP_TEST_RESUME").is_some() {
            let mut byte = [0];
            io::stdin().read_exact(&mut byte).unwrap();
            assert_eq!(byte, [1]);
            return;
        }
        loop {
            std::thread::park();
        }
    }
}

#[cfg(test)]
#[path = "app_bootstrap_tests.rs"]
mod tests;

#[cfg(all(test, feature = "app-bootstrap-bound-test-fixture"))]
#[path = "app_bootstrap_root_tests.rs"]
pub(super) mod root_tests;
