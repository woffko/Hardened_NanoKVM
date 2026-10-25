//! Fixed readonly imports from an exact image. The production entry is only
//! RootfsView::bind_ssh_runtime; no public source-path/root-fd constructor.

use super::{RootfsError, restore_fs};
use nix::mount::{MsFlags, mount};
use rustix::fs::{Dir, Mode, OFlags, ResolveFlags, StatVfsMountFlags, fstatvfs, mkdirat, openat2};
use std::{
    fs::File,
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

// Whole fixed signed runtime directories preserve loader/library/provider and
// internal symlink semantics; never guess a DT_NEEDED closure from host ldd.
const DIRECTORIES: [(&str, bool, bool); 7] = [
    ("usr", true, true),
    ("lib", true, true),
    ("bin", true, true),
    ("sbin", false, true),
    ("lib64", false, true),
    ("etc/ssl", false, false),
    ("var/empty", false, false),
];
const LOADER_CONFIGS: [&str; 2] = ["etc/ld-musl-riscv64.path", "etc/ld-musl-riscv64xthead.path"];

pub(super) fn bind_runtime(source: &File, prepared: &File) -> Result<(), RootfsError> {
    let root = source.metadata()?;
    if !root.is_dir() || root.uid() != 0 || root.mode() & 0o7022 != 0 {
        return Err(RootfsError::Layout);
    }
    for (path, required, executable) in DIRECTORIES {
        let image = open_source(source, path, true)?;
        match image {
            Some(image) => bind_one(prepared, path, image, true, executable)?,
            None if required => return Err(RootfsError::Layout),
            None => {
                check_absent_or_empty(prepared, path, true)?;
            }
        }
    }
    for path in LOADER_CONFIGS {
        match open_source(source, path, false)? {
            Some(image) => {
                if image.metadata()?.len() > 4096 {
                    return Err(RootfsError::Layout);
                }
                bind_one(prepared, path, image, false, false)?;
            }
            None => {
                // Never admit a private/old loader-path override.
                if check_absent_or_empty(prepared, path, false)? {
                    return Err(RootfsError::Layout);
                }
            }
        }
    }
    // Fixed command must resolve to a safe executable in this exact image.
    let executable = open_source(source, "usr/sbin/sshd", false)?
        .ok_or(RootfsError::Layout)?
        .metadata()?;
    if executable.mode() & 0o100 == 0 {
        return Err(RootfsError::Layout);
    }
    Ok(())
}

fn open_source(root: &File, path: &str, directory: bool) -> Result<Option<File>, RootfsError> {
    let flags = OFlags::RDONLY
        | OFlags::NONBLOCK
        | OFlags::CLOEXEC
        | if directory {
            OFlags::DIRECTORY
        } else {
            OFlags::empty()
        };
    let file: File = match openat2(
        root,
        path,
        flags,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    ) {
        Ok(file) => file.into(),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(RootfsError::Layout),
    };
    let metadata = file.metadata()?;
    if metadata.uid() != 0
        || metadata.mode() & 0o7022 != 0
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(RootfsError::Layout);
    }
    Ok(Some(file))
}

fn check_absent_or_empty(root: &File, path: &str, directory: bool) -> Result<bool, RootfsError> {
    let file = match restore_fs::open_beneath(root, path, OFlags::RDONLY | OFlags::NONBLOCK) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(RootfsError::Layout),
    };
    let metadata = file.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o7022 != 0 {
        return Err(RootfsError::Layout);
    }
    if directory {
        if !metadata.is_dir() {
            return Err(RootfsError::Layout);
        }
        for entry in Dir::read_from(&file).map_err(io::Error::from)? {
            let entry = entry.map_err(io::Error::from)?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                return Err(RootfsError::Layout);
            }
        }
    } else if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() != 0 {
        return Err(RootfsError::Layout);
    }
    Ok(true)
}

fn bind_one(
    prepared: &File,
    path: &str,
    source: File,
    directory: bool,
    executable: bool,
) -> Result<(), RootfsError> {
    if !check_absent_or_empty(prepared, path, directory)? {
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        let parent = if parent.is_empty() {
            prepared.try_clone()?
        } else {
            // Only fixed one-level etc/var parents; no uploaded path or symlink.
            match restore_fs::open_beneath(prepared, parent, OFlags::RDONLY | OFlags::DIRECTORY) {
                Ok(parent) => parent,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    mkdirat(prepared, parent, Mode::RWXU).map_err(io::Error::from)?;
                    restore_fs::open_beneath(prepared, parent, OFlags::RDONLY | OFlags::DIRECTORY)?
                }
                Err(_) => return Err(RootfsError::Layout),
            }
        };
        if directory {
            mkdirat(&parent, name, Mode::RWXU).map_err(io::Error::from)?;
        } else {
            let _placeholder = openat2(
                &parent,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )
            .map_err(io::Error::from)?;
        }
    }
    let target = restore_fs::open_beneath(prepared, path, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let source_path = format!("/proc/self/fd/{}", source.as_raw_fd());
    let target_path = format!("/proc/self/fd/{}", target.as_raw_fd());
    mount(
        Some(source_path.as_str()),
        target_path.as_str(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|_| RootfsError::Mount)?;
    // Old target fd still pins the covered writable mount. Reopen across ONLY
    // this fixed import point in the current namespace, then remount that clone.
    let bound: File = openat2(
        prepared,
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(io::Error::from)?
    .into();
    let expected = source.metadata()?;
    let actual = bound.metadata()?;
    if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
        return Err(RootfsError::Mount);
    }
    let target_path = format!("/proc/self/fd/{}", bound.as_raw_fd());
    let flags = MsFlags::MS_BIND
        | MsFlags::MS_REMOUNT
        | MsFlags::MS_RDONLY
        | MsFlags::MS_NODEV
        | MsFlags::MS_NOSUID
        | if executable {
            MsFlags::empty()
        } else {
            MsFlags::MS_NOEXEC
        };
    mount(
        None::<&str>,
        target_path.as_str(),
        None::<&str>,
        flags,
        None::<&str>,
    )
    .map_err(|_| RootfsError::Mount)?;
    let flags = fstatvfs(&bound).map_err(io::Error::from)?.f_flag;
    if !flags
        .contains(StatVfsMountFlags::RDONLY | StatVfsMountFlags::NODEV | StatVfsMountFlags::NOSUID)
        || flags.contains(StatVfsMountFlags::NOEXEC) == executable
    {
        return Err(RootfsError::Mount);
    }
    Ok(())
}
