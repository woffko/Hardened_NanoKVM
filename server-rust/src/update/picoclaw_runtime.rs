//! The managed Pico runtime executable for the broker's Remove job: checked
//! identity and exact removal of one fixed rootfs file. No path is caller
//! selected, nothing else is deleted, and a link, directory or foreign file
//! refuses.
use super::restore_fs;
use crate::{AppError, Result};
use rustix::fs::{AtFlags, OFlags, unlinkat};
use std::{fs::File, os::unix::fs::MetadataExt, path::Path};

const DIRECTORY: &str = "/usr/bin";
const NAME: &str = "picoclaw";

/// The identity of one present managed file. Any change refuses its removal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Asset {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Asset {
    pub(crate) const BYTES: usize = 56;

    pub(crate) fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }

    pub(crate) fn encode(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        for (index, value) in [self.device, self.inode, self.size].into_iter().enumerate() {
            bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (index, value) in [
            self.modified.0,
            self.modified.1,
            self.changed.0,
            self.changed.1,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = 24 + index * 8;
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    pub(crate) fn decode(bytes: &[u8; Self::BYTES]) -> Self {
        let word = |index: usize| {
            let mut value = [0; 8];
            value.copy_from_slice(&bytes[index * 8..index * 8 + 8]);
            value
        };
        Self {
            device: u64::from_le_bytes(word(0)),
            inode: u64::from_le_bytes(word(1)),
            size: u64::from_le_bytes(word(2)),
            modified: (i64::from_le_bytes(word(3)), i64::from_le_bytes(word(4))),
            changed: (i64::from_le_bytes(word(5)), i64::from_le_bytes(word(6))),
        }
    }
}

fn invalid() -> AppError {
    AppError::Config("invalid or unsafe picoclaw runtime executable".into())
}

// Without its directory the executable cannot exist either.
fn parent() -> Result<Option<File>> {
    let directory = match restore_fs::open_root(Path::new(DIRECTORY), true) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7022 != 0 {
        return Err(invalid());
    }
    Ok(Some(directory))
}

fn observe_at(parent: &File) -> Result<Option<Asset>> {
    let pinned = match restore_fs::open_beneath(parent, NAME, OFlags::PATH) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = pinned.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || metadata.dev() != parent.metadata()?.dev()
    {
        return Err(invalid());
    }
    Ok(Some(Asset::of(&metadata)))
}

/// Read-only: the managed executable's identity, or its absence.
pub(crate) fn observe() -> Result<Option<Asset>> {
    match parent()? {
        Some(parent) => observe_at(&parent),
        None => Ok(None),
    }
}

/// Remove exactly the planned executable, durably. Absence is a completed
/// removal; any other file refuses and is kept.
pub(crate) fn remove(planned: Asset) -> Result<()> {
    let Some(parent) = parent()? else {
        return Ok(());
    };
    match observe_at(&parent)? {
        None => {}
        Some(actual) if actual == planned => {
            unlinkat(&parent, NAME, AtFlags::empty()).map_err(std::io::Error::from)?;
        }
        Some(_) => {
            return Err(AppError::Conflict(
                "picoclaw runtime executable changed".into(),
            ));
        }
    }
    parent.sync_all()?;
    Ok(())
}
