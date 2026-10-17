//! Private rootfs receipt for exact update metadata/signature bytes. A receipt
//! is NOT authentication: every install must verify it against current policy.

use super::restore_fs;
use rand_core::{OsRng, RngCore};
use rustix::fs::{
    AtFlags, FlockOperation, Mode, OFlags, ResolveFlags, flock, mkdirat, openat2, renameat,
    unlinkat,
};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

pub(crate) const MAX_METADATA: usize = 64 * 1024;
pub(crate) const MAX_SIGNATURE: usize = 16 * 1024;
const MAGIC: &[u8; 8] = b"NKSM0001";
const HEADER: usize = 16;
const DIRECTORY: &str = "update-trust";
const RECORD: &str = "system-metadata.v1";

#[derive(Debug, thiserror::Error)]
pub(crate) enum MetadataError {
    #[error("update metadata receipt requires a private rootfs directory")]
    Unsafe,
    #[error("update metadata receipt is invalid or exceeds its budget")]
    Invalid,
    #[error("update metadata receipt is busy")]
    Busy,
    #[error("update metadata receipt I/O failed")]
    Io(#[from] io::Error),
}
type Result<T> = std::result::Result<T, MetadataError>;

// Exact bytes, not a re-serialized SystemLatest. No verification proof is
// attached until the API validates shape/signature with the active key policy.
pub(crate) struct MetadataReceipt {
    pub metadata: Vec<u8>,
    pub signature: Vec<u8>,
}

pub(crate) struct MetadataStore {
    directory: File,
    uid: u32,
    device: u64,
    #[cfg(test)]
    fail_at: Option<PublicationStep>,
}
#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum PublicationStep {
    Written,
    FileSynced,
    Renamed,
    DirectorySynced,
}
impl Drop for MetadataStore {
    fn drop(&mut self) {
        // A pre-exec sibling may inherit the same open file description.
        let _ = flock(&self.directory, FlockOperation::Unlock);
    }
}
impl MetadataStore {
    pub fn open() -> Result<Self> {
        if !nix::unistd::geteuid().is_root() {
            return Err(MetadataError::Unsafe);
        }
        let parent = restore_fs::open_root(Path::new("/etc/kvm"), true)?;
        Self::from_parent(parent, 0)
    }

    fn from_parent(parent: File, uid: u32) -> Result<Self> {
        let metadata = parent.metadata()?;
        if metadata.uid() != uid || metadata.mode() & 0o7022 != 0 {
            return Err(MetadataError::Unsafe);
        }
        let device = metadata.dev();
        match mkdirat(&parent, DIRECTORY, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => parent.sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
        let directory =
            restore_fs::open_beneath(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != uid || metadata.dev() != device || metadata.mode() & 0o7077 != 0 {
            return Err(MetadataError::Unsafe);
        }
        flock(&directory, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                MetadataError::Busy
            } else {
                MetadataError::Io(error.into())
            }
        })?;
        Ok(Self {
            directory,
            uid,
            device,
            #[cfg(test)]
            fail_at: None,
        })
    }

    pub fn read(&self) -> Result<Option<MetadataReceipt>> {
        // Inspect without opening a FIFO/device for I/O. The rootfs path is
        // private, but malformed persistent objects must fail without blocking.
        let pinned = match restore_fs::open_beneath(&self.directory, RECORD, OFlags::PATH) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = pinned.metadata()?;
        self.check_file(&metadata)?;
        if metadata.len() < HEADER as u64
            || metadata.len() > (HEADER + MAX_METADATA + MAX_SIGNATURE) as u64
        {
            return Err(MetadataError::Invalid);
        }
        let mut file =
            restore_fs::open_beneath(&self.directory, RECORD, OFlags::RDONLY | OFlags::NONBLOCK)?;
        let actual = file.metadata()?;
        self.check_file(&actual)?;
        if actual.dev() != metadata.dev()
            || actual.ino() != metadata.ino()
            || actual.len() != metadata.len()
        {
            return Err(MetadataError::Unsafe);
        }
        let mut header = [0_u8; HEADER];
        file.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(MetadataError::Invalid);
        }
        let metadata_len = u32::from_be_bytes(
            header[8..12]
                .try_into()
                .map_err(|_| MetadataError::Invalid)?,
        ) as usize;
        let signature_len = u32::from_be_bytes(
            header[12..16]
                .try_into()
                .map_err(|_| MetadataError::Invalid)?,
        ) as usize;
        check_lengths(metadata_len, signature_len)?;
        if metadata.len() != (HEADER + metadata_len + signature_len) as u64 {
            return Err(MetadataError::Invalid);
        }
        let mut receipt = MetadataReceipt {
            metadata: vec![0; metadata_len],
            signature: vec![0; signature_len],
        };
        file.read_exact(&mut receipt.metadata)?;
        file.read_exact(&mut receipt.signature)?;
        if file.read(&mut [0_u8; 1])? != 0 {
            return Err(MetadataError::Invalid);
        }
        Ok(Some(receipt))
    }

    pub fn replace(&self, metadata: &[u8], signature: &[u8]) -> Result<()> {
        check_lengths(metadata.len(), signature.len())?;
        // Do not replace a pre-existing unsafe object, nor silently discard a
        // corrupt canonical receipt that may be needed for operator recovery.
        let _ = self.read()?;
        let mut nonce = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| MetadataError::Invalid)?;
        let temporary = format!(".system-metadata-{:032x}.next", u128::from_be_bytes(nonce));
        let mut file: File = openat2(
            &self.directory,
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map_err(io::Error::from)?
        .into();
        let result = (|| -> Result<()> {
            self.check_file(&file.metadata()?)?;
            file.write_all(MAGIC)?;
            file.write_all(&(metadata.len() as u32).to_be_bytes())?;
            file.write_all(&(signature.len() as u32).to_be_bytes())?;
            file.write_all(metadata)?;
            file.write_all(signature)?;
            #[cfg(test)]
            self.inject(PublicationStep::Written)?;
            file.sync_all()?;
            #[cfg(test)]
            self.inject(PublicationStep::FileSynced)?;
            renameat(&self.directory, &temporary, &self.directory, RECORD)
                .map_err(io::Error::from)?;
            #[cfg(test)]
            self.inject(PublicationStep::Renamed)?;
            self.directory.sync_all()?;
            #[cfg(test)]
            self.inject(PublicationStep::DirectorySynced)?;
            Ok(())
        })();
        // Only this operation's exact random private temporary member. A
        // post-rename error leaves the durable canonical receipt for re-read.
        if result.is_err() {
            let _ = unlinkat(&self.directory, &temporary, AtFlags::empty());
        }
        result
    }

    fn check_file(&self, metadata: &fs::Metadata) -> Result<()> {
        if !metadata.is_file()
            || metadata.uid() != self.uid
            || metadata.dev() != self.device
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(MetadataError::Unsafe);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(parent: &Path) -> Result<Self> {
        Self::from_parent(
            restore_fs::open_root(parent, true)?,
            nix::unistd::geteuid().as_raw(),
        )
    }
    #[cfg(test)]
    fn inject(&self, step: PublicationStep) -> Result<()> {
        if self.fail_at == Some(step) {
            return Err(io::Error::other("synthetic publication failure").into());
        }
        Ok(())
    }
}

fn check_lengths(metadata: usize, signature: usize) -> Result<()> {
    if metadata == 0 || metadata > MAX_METADATA || signature > MAX_SIGNATURE {
        return Err(MetadataError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
#[path = "staged_metadata_tests.rs"]
mod tests;
