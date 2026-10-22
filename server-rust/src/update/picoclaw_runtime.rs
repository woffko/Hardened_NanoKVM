//! The managed Pico runtime executable for the broker's Install and Remove
//! jobs: checked identity, a streamed digest, exact atomic installation from
//! the installer's staged file and exact removal of one fixed rootfs file. No
//! path is caller selected, and a link, directory or foreign file refuses.
use super::restore_fs;
use crate::{AppError, Result};
use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, fchmod, openat2, renameat_with, unlinkat,
};
use sha2::{Digest, Sha512};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

const DIRECTORY: &str = "/usr/bin";
const NAME: &str = "picoclaw";
/// The installer extracts the executable here; it is not a rootfs runtime.
const STAGED: &str = "/root/.picoclaw-cache";
pub(crate) const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

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
    open_directory(DIRECTORY)
}

fn open_directory(path: &str) -> Result<Option<File>> {
    let directory = match restore_fs::open_root(Path::new(path), true) {
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
        || metadata.len() > MAX_EXECUTABLE_BYTES
    {
        return Err(invalid());
    }
    Ok(Some(Asset::of(&metadata)))
}

// The checked file of exactly this identity, opened for reading.
fn open_exact(parent: &File, asset: Asset) -> Result<File> {
    let file = restore_fs::open_beneath(parent, NAME, OFlags::RDONLY | OFlags::NONBLOCK)?;
    if Asset::of(&file.metadata()?) != asset {
        return Err(AppError::Conflict(
            "picoclaw runtime executable changed".into(),
        ));
    }
    Ok(file)
}

// SHA-512 of exactly `size` bytes from the start of `file`.
fn sha512(file: &mut File, size: u64) -> Result<[u8; 64]> {
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha512::new();
    if std::io::copy(&mut file.take(size + 1), &mut hash)? != size {
        return Err(invalid());
    }
    Ok(hash.finalize().into())
}

fn digest_at(parent: &File) -> Result<Option<(Asset, [u8; 64])>> {
    let Some(asset) = observe_at(parent)? else {
        return Ok(None);
    };
    let mut file = open_exact(parent, asset)?;
    let digest = sha512(&mut file, asset.size)?;
    if Asset::of(&file.metadata()?) != asset {
        return Err(invalid());
    }
    Ok(Some((asset, digest)))
}

/// The installed executable's identity and SHA-512, or its absence.
pub(crate) fn installed() -> Result<Option<(Asset, [u8; 64])>> {
    match parent()? {
        Some(parent) => digest_at(&parent),
        None => Ok(None),
    }
}

/// The installer's staged executable: identity and SHA-512, or its absence.
pub(crate) fn staged() -> Result<Option<(Asset, [u8; 64])>> {
    match open_directory(STAGED)? {
        Some(directory) => digest_at(&directory),
        None => Ok(None),
    }
}

/// Install exactly the planned staged executable over exactly the planned
/// prior one (or none), atomically and durably. The copy is hashed again
/// while it is written; any difference refuses and leaves the prior file.
pub(crate) fn install(staged: Asset, digest: [u8; 64], prior: Option<Asset>) -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand_core::{OsRng, RngCore};
    let parent = parent()?.ok_or_else(invalid)?;
    let source = open_directory(STAGED)?.ok_or_else(invalid)?;
    if observe_at(&parent)? != prior {
        return Err(AppError::Conflict(
            "picoclaw runtime executable changed".into(),
        ));
    }
    let mut input = open_exact(&source, staged)?;
    let mut entropy = [0_u8; 12];
    OsRng
        .try_fill_bytes(&mut entropy)
        .map_err(|_| AppError::Internal("runtime temporary-name entropy unavailable".into()))?;
    let name = format!(".picoclaw-{}.tmp", URL_SAFE_NO_PAD.encode(entropy));
    let mut output: File = openat2(
        &parent,
        name.as_str(),
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o700),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(std::io::Error::from)?
    .into();
    let written = (|| -> Result<()> {
        let mut hash = Sha512::new();
        let mut buffer = vec![0; 64 * 1024];
        let mut left = staged.size;
        while left > 0 {
            let count = input.read(&mut buffer[..left.min(64 * 1024) as usize])?;
            if count == 0 {
                return Err(invalid());
            }
            hash.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
            left -= count as u64;
        }
        let copied: [u8; 64] = hash.finalize().into();
        if copied != digest || input.read(&mut [0])? != 0 {
            return Err(AppError::Conflict(
                "picoclaw staged executable changed".into(),
            ));
        }
        output.sync_all()?;
        fchmod(&output, Mode::from_raw_mode(0o755)).map_err(std::io::Error::from)?;
        output.sync_all()?;
        if observe_at(&parent)? != prior {
            return Err(AppError::Conflict(
                "picoclaw runtime executable changed".into(),
            ));
        }
        renameat_with(
            &parent,
            name.as_str(),
            &parent,
            NAME,
            if prior.is_none() {
                RenameFlags::NOREPLACE
            } else {
                RenameFlags::empty()
            },
        )
        .map_err(std::io::Error::from)?;
        Ok(())
    })();
    if let Err(error) = written {
        // Only our own unrenamed temporary is ever removed.
        if restore_fs::open_beneath(&parent, name.as_str(), OFlags::PATH)
            .and_then(|file| file.metadata())
            .is_ok_and(|named| {
                output
                    .metadata()
                    .is_ok_and(|ours| (named.dev(), named.ino()) == (ours.dev(), ours.ino()))
            })
        {
            let _ = unlinkat(&parent, name.as_str(), AtFlags::empty());
        }
        return Err(error);
    }
    parent.sync_all()?;
    match digest_at(&parent)? {
        Some((_, installed)) if installed == digest => Ok(()),
        _ => Err(invalid()),
    }
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
