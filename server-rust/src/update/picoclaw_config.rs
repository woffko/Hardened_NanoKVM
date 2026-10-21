//! Checked rootfs I/O for the two credential-bearing PicoClaw config files.
use super::{restore_fs, state_writers::ConfigPermit};
use crate::{AppError, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use rustix::fs::{
    AtFlags, Mode, OFlags, RenameFlags, ResolveFlags, mkdirat, openat2, renameat, renameat_with,
    unlinkat,
};
use std::{
    fs::{File, Metadata},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};
use zeroize::Zeroizing;

pub(crate) const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const CONFIG: &str = "config.json";
const SECURITY: &str = ".security.yml";

fn invalid() -> AppError {
    AppError::Config("invalid or unsafe picoclaw configuration storage".into())
}

#[derive(PartialEq, Eq)]
struct Revision {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl From<&Metadata> for Revision {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            bytes: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

struct Directory {
    file: File,
    device: u64,
}
impl Directory {
    fn check(&self) -> Result<()> {
        let metadata = self.file.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.dev() != self.device
            || metadata.mode() & 0o7022 != 0
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn open(path: &Path, create: bool) -> Result<Self> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let file = File::open("/")?;
        let device = file.metadata()?.dev();
        let mut directory = Self { file, device };
        directory.check()?;
        for component in absolute.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => {
                    let name = name.to_str().ok_or_else(invalid)?;
                    let mut created = false;
                    let opened = restore_fs::open_beneath(
                        &directory.file,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY,
                    );
                    directory.file = match opened {
                        Ok(file) => file,
                        Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                            match mkdirat(&directory.file, name, Mode::from_raw_mode(0o700)) {
                                Ok(()) => {
                                    created = true;
                                    directory.file.sync_all()?;
                                }
                                Err(rustix::io::Errno::EXIST) => {}
                                Err(error) => return Err(std::io::Error::from(error).into()),
                            }
                            restore_fs::open_beneath(
                                &directory.file,
                                name,
                                OFlags::RDONLY | OFlags::DIRECTORY,
                            )?
                        }
                        Err(error) => return Err(error.into()),
                    };
                    directory.check()?;
                    if created {
                        directory.file.sync_all()?;
                    }
                }
                _ => return Err(invalid()),
            }
        }
        Ok(directory)
    }

    fn inspect(&self, name: &str) -> Result<Option<Revision>> {
        self.check()?;
        let pinned = match restore_fs::open_beneath(&self.file, name, OFlags::PATH) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = pinned.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.dev() != self.device
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() > MAX_FILE_BYTES as u64
        {
            return Err(invalid());
        }
        Ok(Some(Revision::from(&metadata)))
    }

    fn read(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let Some(before) = self.inspect(name)? else {
            return Ok(None);
        };
        let mut file =
            restore_fs::open_beneath(&self.file, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
        if Revision::from(&file.metadata()?) != before {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(before.bytes as usize + 1));
        (&mut file)
            .take(MAX_FILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != before.bytes || Revision::from(&file.metadata()?) != before {
            return Err(invalid());
        }
        Ok(Some(bytes))
    }

    fn temporary(&self) -> Result<Temporary<'_>> {
        for _ in 0..8 {
            let mut entropy = [0_u8; 16];
            OsRng.try_fill_bytes(&mut entropy).map_err(|_| {
                AppError::Internal("configuration temporary-name entropy unavailable".into())
            })?;
            let name = format!(".picoclaw-config-{}.tmp", URL_SAFE_NO_PAD.encode(entropy));
            let file: File = match openat2(
                &self.file,
                name.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
                ResolveFlags::BENEATH
                    | ResolveFlags::NO_SYMLINKS
                    | ResolveFlags::NO_MAGICLINKS
                    | ResolveFlags::NO_XDEV,
            ) {
                Ok(file) => file.into(),
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(std::io::Error::from(error).into()),
            };
            let temporary = Temporary {
                parent: self,
                name,
                file,
                linked: true,
            };
            rustix::fs::fchmod(&temporary.file, Mode::from_raw_mode(0o600))
                .map_err(std::io::Error::from)?;
            self.inspect(&temporary.name)?.ok_or_else(invalid)?;
            return Ok(temporary);
        }
        Err(AppError::Conflict(
            "configuration temporary-name collision".into(),
        ))
    }
}

struct Temporary<'a> {
    parent: &'a Directory,
    name: String,
    file: File,
    linked: bool,
}
impl Drop for Temporary<'_> {
    fn drop(&mut self) {
        // Never remove an unrelated inode, even on a failed publication.
        if self.linked
            && let Ok(Some(named)) = self.parent.inspect(&self.name)
            && self
                .file
                .metadata()
                .is_ok_and(|actual| named.device == actual.dev() && named.inode == actual.ino())
        {
            let _ = unlinkat(&self.parent.file, self.name.as_str(), AtFlags::empty());
        }
    }
}

fn destination(path: &Path) -> Result<(Directory, &str)> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid)?;
    if name != CONFIG && name != SECURITY {
        return Err(invalid());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok((Directory::open(parent, false)?, name))
}

pub(crate) struct RawDocuments {
    pub config: Zeroizing<Vec<u8>>,
    pub security: Option<Zeroizing<Vec<u8>>>,
}

pub(crate) fn read_pair(path: &Path) -> Result<RawDocuments> {
    if path.file_name().and_then(|name| name.to_str()) != Some(CONFIG) {
        return Err(invalid());
    }
    let (directory, _) = destination(path)?;
    let config = directory
        .read(CONFIG)?
        .ok_or_else(|| AppError::Config("picoclaw config is missing".into()))?;
    let security = directory.read(SECURITY)?;
    Ok(RawDocuments { config, security })
}

/// Config-owned first-run setup only; this is not external-writer quiescence.
pub(crate) fn needs_onboard(_permit: &ConfigPermit, path: &Path) -> Result<bool> {
    if path.file_name().and_then(|name| name.to_str()) != Some(CONFIG) {
        return Err(invalid());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(Directory::open(parent, true)?.inspect(CONFIG)?.is_none())
}

pub(crate) fn replace(_permit: &ConfigPermit, path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(invalid());
    }
    let (directory, name) = destination(path)?;
    let before = directory.inspect(name)?;
    let mut temporary = directory.temporary()?;
    temporary.file.write_all(bytes)?;
    temporary.file.sync_all()?;
    if directory.inspect(name)? != before {
        return Err(AppError::Conflict(
            "picoclaw configuration changed during publication".into(),
        ));
    }
    if before.is_none() {
        renameat_with(
            &directory.file,
            temporary.name.as_str(),
            &directory.file,
            name,
            RenameFlags::NOREPLACE,
        )
    } else {
        renameat(
            &directory.file,
            temporary.name.as_str(),
            &directory.file,
            name,
        )
    }
    .map_err(std::io::Error::from)?;
    temporary.linked = false;
    // Failure here is ambiguous durability, not a claim that old bytes remain.
    directory.file.sync_all()?;
    Ok(())
}
