//! Anonymous, kernel-readonly snapshots of PUBLIC release bytes. Expected
//! digests must come from already authenticated metadata, never p3 JSON. This
//! module does not verify signatures, protect against malicious local root, or
//! make a raw-exported/maliciously mounted backing filesystem trustworthy.

use super::{restore_fs, staged_archive::StageDirectory};
use rustix::fs::{OFlags, PROC_SUPER_MAGIC, fcntl_getfl, fstatfs, openat};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};

const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SnapshotError {
    #[error("public update snapshot exceeds its byte budget or has an incorrect length")]
    Length,
    #[error("public update snapshot does not match authenticated digests")]
    Digest,
    #[error("public update snapshot is not an anonymous readonly regular file")]
    Storage,
    #[error("public update snapshot I/O failed")]
    Io(#[from] io::Error),
}

pub(crate) struct PublicSnapshot {
    file: File,
}

impl PublicSnapshot {
    pub fn capture(
        directory: &StageDirectory,
        source: &mut impl Read,
        size: u64,
        sha256: &[u8; 32],
        sha512: &[u8; 64],
    ) -> Result<Self, SnapshotError> {
        Self::capture_hashed(
            directory,
            source,
            size,
            ReleaseDigests {
                hash256: Sha256::new(),
                hash512: Sha512::new(),
                sha256,
                sha512,
            },
        )
    }

    /// Raw-image SHA-256 must come from the manifest inside an authenticated
    /// archive, not from a second, mutable p3 JSON file. This does not itself
    /// establish that provenance or a target-device authorization.
    pub fn capture_sha256(
        directory: &StageDirectory,
        source: &mut impl Read,
        size: u64,
        sha256: &[u8; 32],
    ) -> Result<Self, SnapshotError> {
        Self::capture_hashed(
            directory,
            source,
            size,
            ImageDigest {
                hash: Sha256::new(),
                expected: sha256,
            },
        )
    }

    fn capture_hashed(
        directory: &StageDirectory,
        source: &mut impl Read,
        size: u64,
        mut hashes: impl SnapshotDigests,
    ) -> Result<Self, SnapshotError> {
        if size == 0 || size > MAX_BYTES {
            return Err(SnapshotError::Length);
        }
        let mut output = directory.create_public_spool()?;
        let mut remaining = size;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining != 0 {
            let limit = remaining.min(buffer.len() as u64) as usize;
            let count = source.read(&mut buffer[..limit])?;
            if count == 0 {
                return Err(SnapshotError::Length);
            }
            output.write_all(&buffer[..count])?;
            hashes.update(&buffer[..count]);
            remaining -= count as u64;
        }
        if source.read(&mut [0; 1])? != 0 {
            return Err(SnapshotError::Length);
        }
        if !hashes.matches() {
            return Err(SnapshotError::Digest);
        }
        output.sync_all()?;
        let file = reopen_readonly(&output, size)?;
        // try_clone/dup would preserve O_RDWR. Only this independently opened
        // O_RDONLY description survives; capture never lends a writable alias.
        drop(output);
        Ok(Self { file })
    }
}

// Statically selected outside the copy loop: image snapshots do not calculate
// an unused SHA-512 over multi-GB expanded image data.
trait SnapshotDigests {
    fn update(&mut self, bytes: &[u8]);
    fn matches(self) -> bool;
}

struct ImageDigest<'a> {
    hash: Sha256,
    expected: &'a [u8; 32],
}

impl SnapshotDigests for ImageDigest<'_> {
    fn update(&mut self, bytes: &[u8]) {
        self.hash.update(bytes);
    }

    fn matches(self) -> bool {
        let actual: [u8; 32] = self.hash.finalize().into();
        actual == *self.expected
    }
}

struct ReleaseDigests<'a> {
    hash256: Sha256,
    hash512: Sha512,
    sha256: &'a [u8; 32],
    sha512: &'a [u8; 64],
}

impl SnapshotDigests for ReleaseDigests<'_> {
    fn update(&mut self, bytes: &[u8]) {
        self.hash256.update(bytes);
        self.hash512.update(bytes);
    }

    fn matches(self) -> bool {
        let actual256: [u8; 32] = self.hash256.finalize().into();
        let actual512: [u8; 64] = self.hash512.finalize().into();
        actual256 == *self.sha256 && actual512 == *self.sha512
    }
}

impl Read for PublicSnapshot {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

impl Seek for PublicSnapshot {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

fn reopen_readonly(source: &File, size: u64) -> Result<File, SnapshotError> {
    let expected = source.metadata()?;
    if !expected.is_file()
        || expected.nlink() != 0
        || expected.len() != size
        || expected.uid() != nix::unistd::geteuid().as_raw()
        || expected.mode() & 0o7022 != 0
    {
        return Err(SnapshotError::Storage);
    }
    // Deliberate parent-side proc-fd reopen of our OWN unnamed file, not a
    // configurable source path or a host-proc mount inside the native sandbox.
    // Verify actual procfs before allowing its magic-link semantics.
    let procfs = restore_fs::open_root(Path::new("/proc"), false)?;
    if fstatfs(&procfs).map_err(io::Error::from)?.f_type != PROC_SUPER_MAGIC {
        return Err(SnapshotError::Storage);
    }
    let path = format!("self/fd/{}", source.as_raw_fd());
    let file: File = openat(
        &procfs,
        path.as_str(),
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?
    .into();
    let actual = file.metadata()?;
    if actual.dev() != expected.dev()
        || actual.ino() != expected.ino()
        || actual.len() != size
        || actual.nlink() != 0
        || fcntl_getfl(&file).map_err(io::Error::from)? & OFlags::ACCMODE != OFlags::RDONLY
    {
        return Err(SnapshotError::Storage);
    }
    Ok(file)
}

#[cfg(test)]
#[path = "staged_snapshot_tests.rs"]
mod tests;
