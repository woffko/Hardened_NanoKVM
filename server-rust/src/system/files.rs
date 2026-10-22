use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rand_core::{OsRng, RngCore};

use crate::{AppError, Result};

/// Replace `path` with `content` and `mode`. The bytes go to a temporary file
/// beside it whose name no other writer uses, created exclusively without
/// following links and fsynced. A rename publishes it, then the directory is
/// fsynced. A reader sees the old file or the new one, never a mix.
pub(crate) fn write_atomic(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let parent = parent(path)?;
    fs::create_dir_all(parent)?;
    let temp = unique_temp(path)?;
    let written = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temp)?;
        file.set_permissions(Permissions::from_mode(mode))?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

/// Point the symlink `link` at `target` through a uniquely named temporary link.
pub(crate) fn replace_symlink(target: &Path, link: &Path) -> Result<()> {
    let parent = parent(link)?;
    let temp = unique_temp(link)?;
    std::os::unix::fs::symlink(target, &temp)?;
    if let Err(error) = fs::rename(&temp, link) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn parent(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| AppError::Internal("path has no parent".to_string()))
}

/// `.<name>.<pid>.<counter>.<random>.tmp`. The counter separates this process's
/// writers, the pid other processes, and the random part a stale file left by
/// an earlier boot under the same pid.
fn unique_temp(path: &Path) -> Result<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppError::Internal("path has invalid filename".to_string()))?;
    let mut random = [0_u8; 8];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| AppError::Internal("the random source is unavailable".to_string()))?;
    Ok(path.with_file_name(format!(
        ".{name}.{}.{}.{:016x}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        u64::from_le_bytes(random)
    )))
}

pub fn clean_relative_path(input: &Path) -> Result<PathBuf> {
    if input.is_absolute() {
        return Err(AppError::BadRequest(
            "absolute paths are not allowed".to_string(),
        ));
    }

    let mut out = PathBuf::new();
    for component in input.components() {
        match component {
            std::path::Component::Normal(part) => out.push(part),
            std::path::Component::CurDir => {}
            _ => {
                return Err(AppError::BadRequest(
                    "path traversal is not allowed".to_string(),
                ));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(AppError::BadRequest(
            "empty path is not allowed".to_string(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "files_tests.rs"]
mod tests;
