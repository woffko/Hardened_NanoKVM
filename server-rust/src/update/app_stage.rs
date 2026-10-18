//! Private rootfs application staging. Online digests must come from verified
//! metadata; manual imports intentionally have no built-in signature proof.
//! This is not the durable app-slot journal or protection from malicious root.

use super::{restore_fs, staged_snapshot::reopen_readonly};
use rand_core::{OsRng, RngCore};
use rustix::fs::{Mode, OFlags, ResolveFlags, mkdirat, openat2};
use sha2::{Digest, Sha512};
use std::{
    fs::{self, File},
    io::{self, Read, Seek, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(crate) const MAX_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const DIRECTORY: &str = "application-update";

pub(crate) struct AppStage {
    parent: File,
    directory: File,
    name: String,
    path: PathBuf,
    cleanup: bool,
}

impl AppStage {
    pub fn prepare() -> io::Result<Self> {
        if !nix::unistd::geteuid().is_root() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        for path in ["/", "/etc"] {
            check_directory(&restore_fs::open_root(Path::new(path), true)?, false)?;
        }
        let parent = restore_fs::open_root(Path::new("/etc/kvm"), true)?;
        Self::at_parent(parent, Path::new("/etc/kvm"))
    }

    fn at_parent(parent: File, path: &Path) -> io::Result<Self> {
        check_directory(&parent, false)?;
        match mkdirat(&parent, DIRECTORY, Mode::from_raw_mode(0o700)) {
            Ok(()) => parent.sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
        let root =
            restore_fs::open_beneath(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
        check_directory(&root, true)?;
        if root.metadata()?.dev() != parent.metadata()?.dev() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut nonce = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| io::Error::other("app staging entropy unavailable"))?;
        let name = format!("stage-{:032x}", u128::from_be_bytes(nonce));
        // No reuse, repair, scan or deletion of prior operations after a crash.
        mkdirat(&root, name.as_str(), Mode::from_raw_mode(0o700))?;
        root.sync_all()?;
        let directory = restore_fs::open_beneath(&root, &name, OFlags::RDONLY | OFlags::DIRECTORY)?;
        check_directory(&directory, true)?;
        Ok(Self {
            parent: root,
            directory,
            path: path.join(DIRECTORY).join(&name),
            name,
            cleanup: true,
        })
    }

    pub fn create_archive(&self) -> io::Result<AppDownload> {
        let file: File = openat2(
            &self.directory,
            ".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )?
        .into();
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 0
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.dev() != self.directory.metadata()?.dev()
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(AppDownload { file, written: 0 })
    }

    pub fn extraction_path(&self) -> io::Result<PathBuf> {
        self.check_binding()?;
        Ok(self.path.join("extract"))
    }

    /// Once live slot mutation may have started, an ordinary error must not
    /// erase the validated candidate. This flag is not a durable journal.
    pub fn preserve_recovery(&mut self) {
        self.cleanup = false;
    }

    /// Consume only after the install path succeeded, while work admission is
    /// still retained. Re-enables best-effort cleanup of this owned subtree.
    pub fn discard_after_success(mut self) {
        self.cleanup = true;
    }

    fn check_binding(&self) -> io::Result<()> {
        let named =
            restore_fs::open_beneath(&self.parent, &self.name, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let actual = named.metadata()?;
        let expected = self.directory.metadata()?;
        check_directory(&named, true)?;
        if actual.ino() != expected.ino() || actual.dev() != expected.dev() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // Extraction still uses protected pathnames. Reject replacement of any
        // ancestor; the fixed production parent is not writable through USB.
        let named = restore_fs::open_root(&self.path, false)?.metadata()?;
        if named.ino() != expected.ino() || named.dev() != expected.dev() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fixture(path: &Path) -> io::Result<Self> {
        Self::at_parent(File::open(path)?, path)
    }
}

impl Drop for AppStage {
    fn drop(&mut self) {
        // Only this operation's fresh private subtree. Never follow a replaced
        // binding, remove old staging, or touch the app slot/backup/recovery.
        if self.cleanup && self.check_binding().is_ok() {
            let _ = fs::remove_dir_all(&self.path);
            let _ = self.parent.sync_all();
        }
    }
}

pub(crate) struct AppDownload {
    file: File,
    written: u64,
}

impl AppDownload {
    pub fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let length = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|length| *length <= MAX_ARCHIVE_BYTES)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.file.write_all(bytes)?;
        self.written = length;
        Ok(())
    }

    /// The caller must authenticate the metadata. No writable alias or archive
    /// pathname is exposed, so hashing and extraction share the same inode.
    pub fn finish_online(mut self, size: u64, sha512: &[u8; 64]) -> io::Result<AppArchive> {
        if size != self.written {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.file.rewind()?;
        let mut hash = Sha512::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = self.file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        let actual: [u8; 64] = hash.finalize().into();
        if actual != *sha512 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.freeze()
    }

    /// Explicit administrative offline import, NOT an unsigned online fallback.
    pub fn finish_manual_import(self) -> io::Result<AppArchive> {
        self.freeze()
    }

    fn freeze(self) -> io::Result<AppArchive> {
        if self.written == 0 || self.file.metadata()?.len() != self.written {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.file.sync_all()?;
        let file = reopen_readonly(&self.file, self.written).map_err(io::Error::other)?;
        // Independently opened O_RDONLY description; the sole writable file is
        // closed before the opaque archive leaves this function.
        drop(self);
        Ok(AppArchive { file })
    }
}

pub(crate) struct AppArchive {
    file: File,
}

impl Read for AppArchive {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file.read(bytes)
    }
}

fn check_directory(directory: &File, private: bool) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7022 != 0
        || (private && metadata.mode() & 0o7777 != 0o700)
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "app_stage_tests.rs"]
mod tests;
