//! Fixed-root internal capability storage. Verification never provisions a key.
use super::{restore_fs, state_writers::ConfigPermit};
use crate::{AppError, Result};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use rustix::fs::{AtFlags, Mode, OFlags, PROC_SUPER_MAGIC, ResolveFlags, fstatfs, linkat, openat2};
use std::{
    fs::File,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};
use zeroize::Zeroizing;

const NAME: &str = ".picoclaw_internal_token";
const MAX_FILE_BYTES: u64 = 1024;
const MAX_TOKEN_BYTES: usize = 256;

fn invalid() -> AppError {
    AppError::Config("invalid picoclaw internal credential store".into())
}

pub(crate) fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().all(|byte| byte.is_ascii_graphic())
}

fn parent_at(parent: &File, uid: u32, device: u64) -> Result<()> {
    let metadata = parent.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != uid
        || metadata.dev() != device
        || metadata.mode() & 0o7022 != 0
    {
        return Err(invalid());
    }
    Ok(())
}

fn fixed_parent() -> Result<File> {
    let root = restore_fs::open_root(Path::new("/"), true)?;
    let device = root.metadata()?.dev();
    parent_at(&root, 0, device)?;
    parent_at(&restore_fs::open_root(Path::new("/etc"), true)?, 0, device)?;
    let parent = restore_fs::open_root(Path::new("/etc/kvm"), true)?;
    parent_at(&parent, 0, device)?;
    Ok(parent)
}

fn read_at(parent: &File, uid: u32) -> Result<Option<(String, File)>> {
    let device = parent.metadata()?.dev();
    parent_at(parent, uid, device)?;
    let pinned = match restore_fs::open_beneath(parent, NAME, OFlags::PATH) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = pinned.metadata()?;
    if !metadata.is_file()
        || metadata.dev() != device
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || !(1..=MAX_FILE_BYTES).contains(&metadata.len())
    {
        return Err(invalid());
    }
    let mut file = restore_fs::open_beneath(parent, NAME, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let identity =
        |m: &std::fs::Metadata| (m.dev(), m.ino(), m.uid(), m.mode(), m.nlink(), m.len());
    if identity(&file.metadata()?) != identity(&metadata) {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_FILE_BYTES as usize + 1));
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || identity(&file.metadata()?) != identity(&metadata) {
        return Err(invalid());
    }
    let token = std::str::from_utf8(&bytes).map_err(|_| invalid())?.trim();
    if !valid_token(token) {
        return Err(invalid());
    }
    Ok(Some((token.to_string(), file)))
}

pub(crate) fn read() -> Result<String> {
    read_at(&fixed_parent()?, 0)?
        .map(|(token, _)| token)
        .ok_or_else(invalid)
}

/// Read-only snapshot for job classification: no sync, provisioning or repair.
/// Absence is explicit and an unsafe store refuses, as for `read`.
pub(crate) fn observe() -> Result<Option<Zeroizing<String>>> {
    Ok(read_at(&fixed_parent()?, 0)?.map(|(token, _)| Zeroizing::new(token)))
}

/// One new internal credential value; nothing is stored by this call.
pub(crate) fn new_value() -> Result<Zeroizing<String>> {
    let mut entropy = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(entropy.as_mut())
        .map_err(|_| AppError::Internal("internal credential entropy unavailable".into()))?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(entropy.as_ref())))
}

fn ensure_at(parent: &File, uid: u32) -> Result<String> {
    let device = parent.metadata()?.dev();
    parent_at(parent, uid, device)?;
    if let Some((token, file)) = read_at(parent, uid)? {
        file.sync_all()?;
        parent.sync_all()?;
        return Ok(token);
    }
    let token = new_value()?;
    let mut file: File = openat2(
        parent,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )
    .map_err(std::io::Error::from)?
    .into();
    rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600)).map_err(std::io::Error::from)?;
    file.write_all(token.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    let procfs = restore_fs::open_root(Path::new("/proc"), false)?;
    if fstatfs(&procfs).map_err(std::io::Error::from)?.f_type != PROC_SUPER_MAGIC {
        return Err(invalid());
    }
    let source = format!("self/fd/{}", file.as_raw_fd());
    match linkat(
        &procfs,
        source.as_str(),
        parent,
        NAME,
        AtFlags::SYMLINK_FOLLOW,
    ) {
        Ok(()) => {
            let (actual, named) = read_at(parent, uid)?.ok_or_else(invalid)?;
            if named.metadata()?.ino() != file.metadata()?.ino() || actual != *token {
                return Err(invalid());
            }
            parent.sync_all()?;
            Ok(actual)
        }
        Err(rustix::io::Errno::EXIST) => {
            // Another creator won. Never replace its key or return ours.
            let (winner, named) = read_at(parent, uid)?.ok_or_else(invalid)?;
            named.sync_all()?;
            parent.sync_all()?;
            Ok(winner)
        }
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}

pub(crate) fn ensure(_permit: &ConfigPermit) -> Result<String> {
    ensure_at(&fixed_parent()?, 0)
}

#[cfg(test)]
#[path = "picoclaw_token_tests.rs"]
mod tests;
