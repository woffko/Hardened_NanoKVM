//! Fixed-root, compile-bound native program bootstrap before boot publication.
//! This establishes files only, never ownership of an existing native process.

use super::{app_bootstrap, app_slot, operation_lock::ProcessLock, restore_binding, restore_fs};
use crate::native_owner::embedded;
use rand_core::{OsRng, RngCore};
use rustix::fs::{Mode, OFlags, RenameFlags, fchmod, openat, renameat_with};
use std::{
    fs::File,
    io::{self, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

type Images<'a> = [&'a [u8]; 4];

/// Retain until all compile-bound consumer scripts have been published. This
/// lease does not stop native processes or authorize an app-slot transaction.
pub struct BootSupport {
    _admission: ProcessLock,
}

pub fn prepare_boot_support() -> io::Result<BootSupport> {
    let app = app_bootstrap::embedded_recovery()?;
    let native = embedded_images()?;
    let admission = ProcessLock::acquire().map_err(io::Error::other)?;
    app_bootstrap::ensure_with_admission(app, &admission)?;
    ensure_locked(native, &admission)?;
    Ok(BootSupport {
        _admission: admission,
    })
}

fn embedded_images() -> io::Result<Images<'static>> {
    let [owner, broker, client, recovery] = restore_binding::NATIVE_RUNTIMES.map(embedded::image);
    // Decode the complete family before any filesystem mutation.
    Ok([owner?, broker?, client?, recovery?])
}

/// Install absent fixed native executables under update admission. An existing
/// member must already have exactly these bytes and safe metadata. Unknown or
/// older executables are never overwritten/adopted, even at a terminal journal.
/// Directed executable upgrade requires a future retained-owner migration.
pub fn ensure_installed() -> io::Result<()> {
    let images = embedded_images()?;
    let admission = ProcessLock::acquire().map_err(io::Error::other)?;
    ensure_locked(images, &admission)
}

fn ensure_locked(images: Images<'_>, admission: &ProcessLock) -> io::Result<()> {
    let status = app_slot::status().map_err(io::Error::other)?;
    let root = fixed_root()?;
    let parent = app_bootstrap::parent_at(&root, 0, status == app_slot::Status::NoTransaction)?;
    ensure_at(&parent, images, 0, 0, status, admission)
}

/// Caller already holds update admission. No mkdir, executable replacement,
/// process adoption or recovery permission is supplied by this prerequisite.
pub fn check_installed() -> io::Result<()> {
    let images = embedded_images()?;
    let root = fixed_root()?;
    let parent = app_bootstrap::parent_at(&root, 0, false)?;
    for (runtime, image) in restore_binding::NATIVE_RUNTIMES.into_iter().zip(images) {
        let file = existing(&parent, runtime.filename(), image, 0, 0)?.ok_or_else(invalid)?;
        file.sync_all()?;
    }
    parent.sync_all()
}

fn fixed_root() -> io::Result<File> {
    if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    restore_fs::open_root(Path::new("/"), true)
}

fn existing(
    parent: &File,
    name: &str,
    image: &[u8],
    uid: u32,
    gid: u32,
) -> io::Result<Option<File>> {
    let file = app_bootstrap::existing(parent, name, image, uid)?;
    if let Some(file) = &file
        && file.metadata()?.gid() != gid
    {
        return Err(invalid());
    }
    Ok(file)
}

fn ensure_at(
    parent: &File,
    images: Images<'_>,
    uid: u32,
    gid: u32,
    status: app_slot::Status,
    _admission: &ProcessLock,
) -> io::Result<()> {
    let mut missing = [false; 4];
    // Validate every existing member before creating any new member. A foreign
    // late role cannot leave the earlier names newly authorized by this call.
    for (index, (runtime, image)) in restore_binding::NATIVE_RUNTIMES
        .into_iter()
        .zip(images)
        .enumerate()
    {
        if image.is_empty() || image.len() as u64 > restore_binding::MAX_NATIVE_HELPER {
            return Err(invalid());
        }
        match existing(parent, runtime.filename(), image, uid, gid)? {
            Some(file) => file.sync_all()?,
            None if status == app_slot::Status::NoTransaction => missing[index] = true,
            None => return Err(invalid()),
        }
    }
    let mut staged: [Option<String>; 4] = std::array::from_fn(|_| None);
    for (index, runtime) in restore_binding::NATIVE_RUNTIMES.into_iter().enumerate() {
        if missing[index] {
            staged[index] = Some(stage(parent, runtime.filename(), images[index])?);
            #[cfg(test)]
            checkpoint(&format!("staged-{index}"));
        }
    }
    // A crash may leave an exact subset and exclusive staged evidence. Retry
    // validates that subset, then finishes missing names. No boot scripts are
    // authorized until the entire family has passed its final check.
    for (index, runtime) in restore_binding::NATIVE_RUNTIMES.into_iter().enumerate() {
        if let Some(name) = &staged[index] {
            match renameat_with(
                parent,
                name.as_str(),
                parent,
                runtime.filename(),
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            parent.sync_all()?;
            #[cfg(test)]
            checkpoint(&format!("published-{index}"));
        }
    }
    for (runtime, image) in restore_binding::NATIVE_RUNTIMES.into_iter().zip(images) {
        let file = existing(parent, runtime.filename(), image, uid, gid)?.ok_or_else(invalid)?;
        file.sync_all()?;
    }
    parent.sync_all()?;
    #[cfg(test)]
    checkpoint("verified");
    Ok(())
}

fn stage(parent: &File, executable: &str, image: &[u8]) -> io::Result<String> {
    let mut nonce = [0; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| io::Error::other("native bootstrap entropy unavailable"))?;
    let name = format!(".{executable}-next-{:032x}", u128::from_be_bytes(nonce));
    let mut file: File = openat(
        parent,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?
    .into();
    fchmod(&file, Mode::from_raw_mode(0o600))?;
    file.write_all(image)?;
    fchmod(&file, Mode::from_raw_mode(0o755))?;
    file.sync_all()?;
    Ok(name)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unsafe or mismatched independent native runtime",
    )
}

#[cfg(test)]
fn checkpoint(position: &str) {
    if std::env::var("NANOKVM_NATIVE_BOOTSTRAP_TEST_STOP").as_deref() == Ok(position) {
        println!("native-bootstrap-checkpoint-ready");
        io::stdout().flush().unwrap();
        if std::env::var_os("NANOKVM_NATIVE_BOOTSTRAP_TEST_RESUME").is_some() {
            use std::io::Read;
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
#[path = "native_bootstrap_tests.rs"]
mod tests;

#[cfg(all(test, feature = "app-bootstrap-bound-test-fixture"))]
#[path = "native_bootstrap_root_tests.rs"]
mod root_tests;
