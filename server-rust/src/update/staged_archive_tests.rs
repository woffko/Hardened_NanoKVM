use super::*;
use std::{
    fs,
    io::{Read, Seek, Write},
    os::unix::fs::{PermissionsExt, symlink},
};
use tempfile::tempdir;

#[test]
fn download_is_private_unpublished_and_failure_cleans_only_its_own_name() {
    let root = tempdir().unwrap();
    let path = root.path().join("cache/system");
    let stage = StageDirectory::prepare(&path).unwrap();
    fs::write(path.join("old.tar.gz"), b"keep archive").unwrap();
    fs::create_dir(path.join("preserve")).unwrap();
    fs::write(path.join("preserve/state"), b"keep state").unwrap();
    let mut download = stage.create_download().unwrap();
    assert_eq!(download.file.metadata().unwrap().mode() & 0o7777, 0o600);
    download.file_mut().write_all(b"partial download").unwrap();
    assert_eq!(fs::read_dir(&path).unwrap().count(), 3);
    drop(download);
    assert_eq!(fs::read_dir(&path).unwrap().count(), 2);
    assert_eq!(fs::read(path.join("old.tar.gz")).unwrap(), b"keep archive");
    assert_eq!(
        fs::read(path.join("preserve/state")).unwrap(),
        b"keep state"
    );
}

#[test]
fn publishing_replaces_name_not_symlink_or_hardlink_target_contents() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let sentinel = outside.path().join("sentinel");
    fs::write(&sentinel, b"outside unchanged").unwrap();
    let path = root.path().join("system");
    let stage = StageDirectory::prepare(&path).unwrap();
    for hardlink in [false, true] {
        let canonical = path.join("update.tar.gz");
        if hardlink {
            fs::hard_link(&sentinel, &canonical).unwrap();
        } else {
            symlink(&sentinel, &canonical).unwrap();
        }
        assert!(stage.open_archive("update.tar.gz").is_err());
        let mut download = stage.create_download().unwrap();
        download
            .file_mut()
            .write_all(b"new verified bytes")
            .unwrap();
        download.publish("update.tar.gz").unwrap();
        drop(download);
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside unchanged");
        assert_eq!(fs::read(&canonical).unwrap(), b"new verified bytes");
        assert!(
            !fs::symlink_metadata(&canonical)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&canonical).unwrap();
    }
}

#[test]
fn pinned_parent_and_archive_survive_name_replacement_without_escape() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let path = root.path().join("system");
    let moved = root.path().join("old-system");
    let stage = StageDirectory::prepare(&path).unwrap();
    let mut download = stage.create_download().unwrap();
    download.file_mut().write_all(b"pinned bytes").unwrap();
    fs::rename(&path, &moved).unwrap();
    symlink(outside.path(), &path).unwrap();
    download.publish("update.tar.gz").unwrap();
    download.file_mut().rewind().unwrap();
    let mut bytes = Vec::new();
    download.file_mut().read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"pinned bytes");
    assert_eq!(fs::read(moved.join("update.tar.gz")).unwrap(), bytes);
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    assert!(StageDirectory::prepare(&path).is_err());
    assert!(StageDirectory::open(&path).is_err());

    let mut archive = stage.open_archive("update.tar.gz").unwrap();
    fs::rename(moved.join("update.tar.gz"), moved.join("saved")).unwrap();
    fs::write(moved.join("update.tar.gz"), b"replacement").unwrap();
    bytes.clear();
    archive.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"pinned bytes");
}

#[test]
fn rejects_unsafe_stage_names_archive_modes_and_nonregular_objects() {
    let root = tempdir().unwrap();
    assert!(StageDirectory::prepare(Path::new("/")).is_err());
    assert!(StageDirectory::open(Path::new("/")).is_err());
    assert!(StageDirectory::prepare(Path::new("relative")).is_err());
    let stage = StageDirectory::prepare(&root.path().join("system")).unwrap();
    for name in ["", ".", "..", "../escape", "/escape", "sub/file"] {
        assert!(stage.open_archive(name).is_err());
        let mut download = stage.create_download().unwrap();
        assert!(download.publish(name).is_err());
    }
    fs::create_dir(root.path().join("system/directory")).unwrap();
    assert!(stage.open_archive("directory").is_err());
    nix::unistd::mkfifo(
        &root.path().join("system/fifo"),
        nix::sys::stat::Mode::S_IRUSR,
    )
    .unwrap();
    assert!(stage.open_archive("fifo").is_err());
    fs::write(root.path().join("system/shared"), b"untrusted").unwrap();
    fs::set_permissions(
        root.path().join("system/shared"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(stage.open_archive("shared").is_err());
    fs::set_permissions(
        root.path().join("system"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(StageDirectory::open(&root.path().join("system")).is_err());
}
