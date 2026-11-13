//! Descriptor-relative Linux restore I/O. There is no path-based fallback.

use std::{
    fs::File,
    io,
    path::{Component, Path},
};

use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Pin an absolute directory without following any symlink component. Only
/// the source root may cross mounts; private plaintext staging must stay on /.
pub(super) fn open_root(path: &Path, same_rootfs: bool) -> io::Result<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let root = File::open("/")?;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    let relative = if relative.as_os_str().is_empty() {
        Path::new(".")
    } else {
        relative
    };
    Ok(openat2(
        &root,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        if same_rootfs {
            RESOLVE | ResolveFlags::NO_XDEV
        } else {
            RESOLVE
        },
    )?
    .into())
}

pub(super) fn open_beneath(root: &File, path: &str, flags: OFlags) -> io::Result<File> {
    Ok(openat2(
        root,
        path,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE | ResolveFlags::NO_XDEV,
    )?
    .into())
}

/// /boot is the only explicitly admitted mount below the source root. Once
/// pinned, all its members are opened with open_beneath, including NO_XDEV.
pub(super) fn open_boot(root: &File) -> io::Result<File> {
    Ok(openat2(
        root,
        "boot",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE,
    )?
    .into())
}
