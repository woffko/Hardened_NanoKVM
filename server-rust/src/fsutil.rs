//! Shared helpers for writing small sensitive files safely.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};

use crate::{AppError, Result};

/// Write `data` to `path` atomically with mode 0600.
///
/// Writes to a uniquely named temporary file in the same directory, fsyncs it,
/// then renames over the destination, so a reader never observes a partial
/// file and a crash mid-write cannot leave the original truncated. Refuses to
/// traverse symlinks or special files on the way to the destination.
pub fn write_0600_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(AppError::Config("empty file path".to_string()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Config("file path has no parent".to_string()))?;
    ensure_no_symlink_components(parent)?;
    fs::create_dir_all(parent)?;
    ensure_no_symlink_components(path)?;

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AppError::Config("file path has invalid file name".to_string()))?;
    let tmp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        random_tmp_suffix()
    ));

    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp_path)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp_path, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        if let Ok(parent_dir) = fs::File::open(parent) {
            let _ = parent_dir.sync_all();
        }
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_result
}

fn ensure_no_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) => current.push(component.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(AppError::Config(
                    "file path cannot contain parent directory components".to_string(),
                ));
            }
            Component::Normal(value) => current.push(value),
        }

        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(AppError::Config(format!(
                    "refusing to write through symlink: {}",
                    current.display()
                )));
            }
            Ok(metadata) if metadata.file_type().is_fifo() || metadata.file_type().is_socket() => {
                return Err(AppError::Config(format!(
                    "refusing to write through special file: {}",
                    current.display()
                )));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn random_tmp_suffix() -> String {
    let mut bytes = [0_u8; 8];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn writes_with_owner_only_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = root.join("secret");

        write_0600_atomic(&path, b"payload").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"payload");
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn replaces_existing_content_and_leaves_no_temporaries() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = root.join("secret");

        write_0600_atomic(&path, b"first").unwrap();
        write_0600_atomic(&path, b"second").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"second");
        let leftovers: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name != "secret")
            .collect();
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    #[test]
    fn refuses_to_follow_a_symlinked_destination() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"original").unwrap();
        symlink(&target, &link).unwrap();

        assert!(write_0600_atomic(&link, b"payload").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }
}
