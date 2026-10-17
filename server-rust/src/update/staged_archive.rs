//! Descriptor-owned system archive downloads on the data filesystem. These
//! handles are not signature proofs, and do not make payload staging immutable.

use super::restore_fs;
use rand_core::{OsRng, RngCore};
use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags, mkdirat, openat2, renameat, unlinkat};
use std::{
    fs::File,
    io::{self, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

pub(crate) struct StageDirectory {
    directory: File,
}

impl StageDirectory {
    pub fn prepare(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() || path == Path::new("/") {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Mount transitions are admitted only while resolving the configured
        // stage root (normally /data/p3). Every member below it uses NO_XDEV.
        let mut directory = File::open("/")?;
        for component in path.components() {
            let name = match component {
                Component::RootDir => continue,
                Component::Normal(name) => name,
                _ => return Err(io::ErrorKind::InvalidInput.into()),
            };
            match mkdirat(&directory, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) => directory.sync_all()?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            directory = openat2(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                RESOLVE,
            )?
            .into();
        }
        Self::checked(directory)
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        if path == Path::new("/") {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Self::checked(restore_fs::open_root(path, false)?)
    }

    fn checked(directory: File) -> io::Result<Self> {
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o7022 != 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Self { directory })
    }

    pub fn create_download(&self) -> io::Result<StagedDownload> {
        let directory = self.directory.try_clone()?;
        let mut nonce = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| io::ErrorKind::Other)?;
        let name = format!(".system-archive-{:032x}.part", u128::from_be_bytes(nonce));
        let file: File = openat2(
            &self.directory,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            RESOLVE | ResolveFlags::NO_XDEV,
        )?
        .into();
        Ok(StagedDownload {
            directory,
            temporary: Some(name),
            file,
        })
    }

    pub fn open_archive(&self, name: &str) -> io::Result<File> {
        check_name(name)?;
        // O_PATH inspects FIFO/device objects without invoking their I/O.
        let pinned = restore_fs::open_beneath(&self.directory, name, OFlags::PATH)?;
        let expected = pinned.metadata()?;
        check_archive(&expected, self.directory.metadata()?.dev())?;
        let file =
            restore_fs::open_beneath(&self.directory, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
        let actual = file.metadata()?;
        check_archive(&actual, expected.dev())?;
        if actual.ino() != expected.ino() || actual.len() != expected.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(file)
    }

    pub fn replace_generated(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        check_name(name)?;
        let mut generated = self.create_download()?;
        generated.file_mut().write_all(bytes)?;
        generated.publish(name)
    }

    pub fn remove_generated(&self, name: &str) -> io::Result<()> {
        check_name(name)?;
        match unlinkat(&self.directory, name, AtFlags::empty()) {
            Ok(()) => self.directory.sync_all(),
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub(crate) struct StagedDownload {
    directory: File,
    temporary: Option<String>,
    file: File,
}

impl StagedDownload {
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn writer(&self) -> io::Result<File> {
        self.file.try_clone()
    }

    // Call only after exact signed-size and digest checks on file_mut(). The
    // destination entry may be replaced, but is never opened for writing.
    pub fn publish(&mut self, name: &str) -> io::Result<()> {
        check_name(name)?;
        let temporary = self.temporary.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
        self.file.sync_all()?;
        renameat(&self.directory, temporary, &self.directory, name)?;
        self.temporary = None;
        self.directory.sync_all()
    }
}

impl Drop for StagedDownload {
    fn drop(&mut self) {
        // Never recursively clean staging or remove a canonical archive. Only
        // the exact random name owned by this unsuccessful download is removed.
        if let Some(name) = &self.temporary {
            let _ = unlinkat(&self.directory, name, AtFlags::empty());
        }
    }
}

fn check_archive(metadata: &std::fs::Metadata, device: u64) -> io::Result<()> {
    if !metadata.is_file()
        || metadata.dev() != device
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

fn check_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "staged_archive_tests.rs"]
mod tests;
