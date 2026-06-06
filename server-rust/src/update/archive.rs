use std::{
    fs::{self, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

use crate::{AppError, Result, system::files::clean_relative_path};

pub fn safe_join(root: &Path, member_name: &Path) -> Result<PathBuf> {
    let relative = clean_relative_path(member_name)?;
    let joined = root.join(relative);
    if !joined.starts_with(root) {
        return Err(AppError::BadRequest(
            "archive member escapes extraction root".to_string(),
        ));
    }
    Ok(joined)
}

pub fn extract_tar_gz_safe(src: &Path, dest: &Path) -> Result<PathBuf> {
    fs::create_dir_all(dest)?;
    let file = fs::File::open(src)?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);
    let mut first_top_level = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let target = safe_join(dest, &path)?;

        if first_top_level.is_none() {
            if let Some(first) = path.components().next() {
                first_top_level = Some(dest.join(first.as_os_str()));
            }
        }

        match entry.header().entry_type() {
            EntryType::Directory => fs::create_dir_all(&target)?,
            EntryType::Regular => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                reject_symlink_parent(dest, &target)?;
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .open(&target)?;
                io::copy(&mut entry, &mut out)?;
                out.sync_all()?;
            }
            _ => {
                return Err(AppError::BadRequest(
                    "unsupported archive entry type".to_string(),
                ));
            }
        }
    }

    first_top_level.ok_or_else(|| AppError::BadRequest("empty archive".to_string()))
}

fn reject_symlink_parent(root: &Path, target: &Path) -> Result<()> {
    let mut current = target.parent();
    while let Some(path) = current {
        if path == root {
            return Ok(());
        }
        if fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(AppError::BadRequest(
                "archive target crosses symlink parent".to_string(),
            ));
        }
        current = path.parent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal_members() {
        let root = Path::new("/tmp/root");
        assert!(safe_join(root, Path::new("../etc/passwd")).is_err());
        assert!(safe_join(root, Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn accepts_normal_relative_members() {
        let root = Path::new("/tmp/root");
        assert_eq!(
            safe_join(root, Path::new("latest/bin/server")).unwrap(),
            Path::new("/tmp/root/latest/bin/server")
        );
    }
}
