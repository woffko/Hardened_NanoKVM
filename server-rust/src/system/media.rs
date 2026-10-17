use std::{
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use super::command::{AllowedCommand, run_allowed};
use crate::{AppError, Result};

pub const MEDIA_ROOT: &str = "/data/media";
const PRIVATE_MOUNT_OPTIONS: &str = "nosuid,nodev,noexec,uid=0,gid=0,fmask=0177,dmask=0077";

pub async fn secure_device_mounts() -> Result<()> {
    for (mountpoint, source, kind) in [
        ("/boot", "/dev/mmcblk0p1", "vfat"),
        ("/data", "/dev/mmcblk0p3", "exfat"),
    ] {
        let mounts = fs::read_to_string("/proc/mounts")?;
        if !has_expected_mount(&mounts, mountpoint, source, kind, false) {
            return Err(AppError::Config(format!(
                "expected mounted {kind} {source} on {mountpoint}; refusing storage migration"
            )));
        }
        if has_expected_mount(&mounts, mountpoint, source, kind, true) {
            continue;
        }
        // These vendor FAT/exFAT drivers do not apply new uid/masks during
        // remount. A normal (never lazy/forced) unmount is necessary. This runs
        // only after the legacy USB LUN is closed and before API writers start.
        // Busy mounts fail closed rather than discarding any open user's data.
        checked_directory(Path::new(mountpoint))?;
        fs::File::open(mountpoint)?.sync_all()?;
        let unmount = run_allowed(
            AllowedCommand::Umount,
            [mountpoint],
            Duration::from_secs(10),
        )
        .await?;
        if unmount.status != 0 {
            return Err(AppError::Conflict(format!(
                "{mountpoint} is busy; safe storage migration requires a reboot"
            )));
        }
        let output = run_allowed(
            AllowedCommand::Mount,
            ["-t", kind, "-o", PRIVATE_MOUNT_OPTIONS, source, mountpoint],
            Duration::from_secs(10),
        )
        .await?;
        if output.status != 0 {
            return Err(AppError::Internal(format!(
                "failed to restrict {mountpoint} mount; management startup refused"
            )));
        }
        let mounts = fs::read_to_string("/proc/mounts")?;
        if !has_expected_mount(&mounts, mountpoint, source, kind, true) {
            return Err(AppError::Config(format!(
                "private mount options not effective on {mountpoint}"
            )));
        }
    }
    Ok(())
}

fn has_expected_mount(mounts: &str, target: &str, source: &str, kind: &str, private: bool) -> bool {
    let mut entries = mounts
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| fields.len() >= 4 && fields[1] == target);
    let Some(fields) = entries.next() else {
        return false;
    };
    // Do not accept an underlying mount's options when another mount shadows it.
    entries.next().is_none()
        && fields[0] == source
        && fields[2] == kind
        && (!private
            || [
                    "rw",
                    "nosuid",
                    "nodev",
                    "noexec",
                    "fmask=0177",
                    "dmask=0077",
                ]
                .iter()
                .all(|required| fields[3].split(',').any(|value| value == *required))
                // Vendor FAT/exFAT omit uid=0/gid=0 from show_options.
                && fields[3].split(',').all(|value| {
                    (!value.starts_with("uid=") || value == "uid=0")
                        && (!value.starts_with("gid=") || value == "gid=0")
                }))
}

pub fn is_image(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("iso") || ext.eq_ignore_ascii_case("img"))
}

// Used for both existing files and upload destinations. Reject symlinks in
// *every* component, including aliases that resolve back inside the same root.
pub fn checked_directory(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(AppError::BadRequest(
            "media directory must be absolute".to_string(),
        ));
    }
    let mut current = PathBuf::new();
    for part in path.components() {
        match part {
            Component::RootDir | Component::Normal(_) => current.push(part),
            _ => return Err(AppError::BadRequest("invalid media directory".to_string())),
        }
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AppError::BadRequest(
                "media directory contains an alias or non-directory".to_string(),
            ));
        }
    }
    Ok(current)
}

pub fn checked_media_root(root: &Path) -> Result<PathBuf> {
    let root = checked_directory(root)?;
    reject_media_mount_aliases(&root, &fs::read_to_string("/proc/self/mountinfo")?)?;
    Ok(root)
}

fn reject_media_mount_aliases(root: &Path, mountinfo: &str) -> Result<()> {
    for line in mountinfo.lines() {
        let Some(target) = line.split_whitespace().nth(4) else {
            return Err(AppError::Internal("invalid mount inventory".to_string()));
        };
        // A media tree is a directory in /data, never a separate mount. This
        // also rejects same-filesystem bind mounts that st_dev cannot detect.
        // Escaped spaces remain within the same path component; the fixed
        // /data/media boundary itself contains no escapable characters.
        if Path::new(target).starts_with(root) {
            return Err(AppError::BadRequest(
                "mount aliases inside media storage are not allowed".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn check_file(path: &Path, root: &Path) -> Result<()> {
    let root = checked_directory(root)?;
    let parent = path
        .parent()
        .ok_or_else(|| AppError::BadRequest("invalid media path".to_string()))?;
    let parent = checked_directory(parent)?;
    let metadata = fs::symlink_metadata(path)?;
    if !parent.starts_with(&root)
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.dev() != fs::metadata(root)?.dev()
    {
        return Err(AppError::BadRequest(
            "image must be a private regular file inside media storage".to_string(),
        ));
    }
    Ok(())
}

pub fn ensure_not_loop_backed(image: &Path, block_root: &Path) -> Result<()> {
    for entry in fs::read_dir(block_root)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("loop") {
            continue;
        }
        let backing = match fs::read_to_string(entry.path().join("loop/backing_file")) {
            Ok(value) => value,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        // This vendor kernel emits a literal pathname plus one newline.
        if Path::new(backing.strip_suffix('\n').unwrap_or(&backing)) == image {
            return Err(AppError::Conflict("image is in use by a local loop device; detach it before USB export, migration or replacement".to_string()));
        }
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct Migration {
    pub moved: usize,
    pub collisions: usize,
}

// Only top-level user image files are eligible. Never walk/import legacy
// cache, preserve, backup or other service directories. Collisions retain both
// originals; repeated boots therefore cannot overwrite an existing image.
pub fn prepare_and_migrate(data: &Path, root: &Path) -> Result<Migration> {
    checked_directory(data)?;
    if root.parent() != Some(data) {
        return Err(AppError::BadRequest(
            "media root must be a direct data child".to_string(),
        ));
    }
    match fs::create_dir(root) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err.into()),
    }
    checked_media_root(root)?;
    if fs::metadata(root)?.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    if fs::metadata(root)?.dev() != fs::metadata(data)?.dev() {
        return Err(AppError::BadRequest(
            "media root is on a different filesystem".to_string(),
        ));
    }
    let mut result = Migration::default();
    for entry in fs::read_dir(data)? {
        let entry = entry?;
        let source = entry.path();
        if !entry.file_type()?.is_file() || !is_image(&source) {
            continue;
        }
        check_file(&source, data)?;
        ensure_not_loop_backed(&source, Path::new("/sys/block"))?;
        let dest = root.join(entry.file_name());
        match fs::symlink_metadata(&dest) {
            Ok(_) => {
                result.collisions += 1;
                continue;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        fs::rename(source, dest)?;
        result.moved += 1;
    }
    // exFAT mount masks, not chmod, supply the effective on-device permissions.
    fs::File::open(root)?.sync_all()?;
    fs::File::open(data)?.sync_all()?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    #[test]
    fn effective_mount_check_requires_identity_and_all_restrictions() {
        let options = "rw,nosuid,nodev,noexec,uid=0,gid=0,fmask=0177,dmask=0077";
        let mounts = format!("/dev/mmcblk0p3 /data exfat {options} 0 0\n");
        assert!(has_expected_mount(
            &mounts,
            "/data",
            "/dev/mmcblk0p3",
            "exfat",
            true
        ));
        for option in [
            "rw",
            "nosuid",
            "nodev",
            "noexec",
            "fmask=0177",
            "dmask=0077",
        ] {
            let incomplete = mounts.replace(option, "");
            assert!(
                !has_expected_mount(&incomplete, "/data", "/dev/mmcblk0p3", "exfat", true),
                "{option}"
            );
        }
        let default_owner = mounts.replace(",uid=0,gid=0", "");
        assert!(has_expected_mount(
            &default_owner,
            "/data",
            "/dev/mmcblk0p3",
            "exfat",
            true
        ));
        assert!(!has_expected_mount(
            &mounts.replace("uid=0", "uid=1000"),
            "/data",
            "/dev/mmcblk0p3",
            "exfat",
            true
        ));
        assert!(!has_expected_mount(
            &mounts.replace("gid=0", "gid=1000"),
            "/data",
            "/dev/mmcblk0p3",
            "exfat",
            true
        ));
        assert!(!has_expected_mount(
            &mounts,
            "/data",
            "/dev/mmcblk0p2",
            "exfat",
            true
        ));
        assert!(!has_expected_mount(
            &mounts,
            "/data",
            "/dev/mmcblk0p3",
            "ext4",
            true
        ));
        assert!(!has_expected_mount(
            &format!("{mounts}{mounts}"),
            "/data",
            "/dev/mmcblk0p3",
            "exfat",
            true
        ));
    }

    #[test]
    fn media_mount_aliases_cannot_expose_private_same_filesystem_trees() {
        let root = Path::new(MEDIA_ROOT);
        let normal = "30 1 179:3 / /data rw - exfat /dev/mmcblk0p3 rw\n";
        assert!(reject_media_mount_aliases(root, normal).is_ok());
        for alias in [
            "/data/media",
            "/data/media/alias",
            "/data/media/nested\\040name",
        ] {
            let info = format!(
                "{normal}31 30 179:3 /.hardened-kvmcache {alias} rw - exfat /dev/mmcblk0p3 rw\n"
            );
            assert!(reject_media_mount_aliases(root, &info).is_err());
        }
        assert!(reject_media_mount_aliases(root, "malformed").is_err());
    }

    #[test]
    fn migration_preserves_collisions_and_ignores_private_trees() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("media");
        fs::create_dir(&root).unwrap();
        fs::write(dir.path().join("installer.iso"), b"user media").unwrap();
        fs::write(dir.path().join("same.img"), b"old").unwrap();
        fs::write(root.join("same.img"), b"new").unwrap();
        let private = dir.path().join(".hardened-kvmcache");
        fs::create_dir(&private).unwrap();
        fs::write(private.join("rootfs.img"), b"private").unwrap();
        let report = prepare_and_migrate(dir.path(), &root).unwrap();
        assert_eq!((report.moved, report.collisions), (1, 1));
        assert_eq!(fs::read(root.join("installer.iso")).unwrap(), b"user media");
        assert_eq!(fs::read(dir.path().join("same.img")).unwrap(), b"old");
        assert_eq!(fs::read(root.join("same.img")).unwrap(), b"new");
        assert!(private.join("rootfs.img").exists());
        assert!(!root.join("rootfs.img").exists());
        let again = prepare_and_migrate(dir.path(), &root).unwrap();
        assert_eq!((again.moved, again.collisions), (0, 1));
    }

    #[test]
    fn rejects_media_root_and_parent_symlinks() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        symlink(&real, dir.path().join("media")).unwrap();
        assert!(prepare_and_migrate(dir.path(), &dir.path().join("media")).is_err());
        assert!(checked_directory(&dir.path().join("media")).is_err());
    }

    #[test]
    fn rejects_hardlink_aliases() {
        let dir = tempdir().unwrap();
        let image = dir.path().join("image.img");
        fs::write(&image, b"image").unwrap();
        fs::hard_link(&image, dir.path().join("alias.img")).unwrap();
        assert!(check_file(&image, dir.path()).is_err());
    }
}
