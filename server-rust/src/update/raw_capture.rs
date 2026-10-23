//! Raw-update capture: seals the restore archive into a capsule on the data
//! partition, the only one a raw write leaves in place. Nothing here
//! authorizes a partition write; the writer and the early restore check again.

use super::{
    restore_archive::CapturedArchive,
    restore_capsule::{CapsuleError, RestoreSecret, prepare_capsule},
};
use rand_core::{OsRng, RngCore};
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags, fsync, openat, renameat_with, unlinkat};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Seek, Write},
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
