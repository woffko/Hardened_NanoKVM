use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

fn fixture() -> (tempfile::TempDir, File, u32) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let parent = File::open(root.path()).unwrap();
    (root, parent, nix::unistd::geteuid().as_raw())
}

fn put(root: &Path, bytes: &[u8]) {
    fs::write(root.join(NAME), bytes).unwrap();
    fs::set_permissions(root.join(NAME), fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn readonly_missing_lookup_does_not_provision_and_creation_is_private_and_stable() {
    let (root, parent, uid) = fixture();
    assert!(read_at(&parent, uid).unwrap().is_none());
    assert!(!root.path().join(NAME).exists());
    let token = ensure_at(&parent, uid).unwrap();
    assert!(valid_token(&token));
    assert_eq!(token.len(), 43);
    let before = root.path().join(NAME).metadata().unwrap();
    assert_eq!(before.mode() & 0o7777, 0o600);
    assert_eq!(before.nlink(), 1);
    let loaded = read_at(&parent, uid).unwrap().unwrap().0;
    assert!(loaded == token);
    assert!(ensure_at(&parent, uid).unwrap() == token);
    assert_eq!(
        root.path().join(NAME).metadata().unwrap().ino(),
        before.ino()
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    fs::remove_file(root.path().join(NAME)).unwrap();
    assert!(read_at(&parent, uid).unwrap().is_none());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn malformed_existing_values_are_not_adopted_or_replaced() {
    for bytes in [
        b"".as_slice(),
        b" \r\n\t",
        b"synthetic fixture with spaces",
        b"synthetic\nfixture",
        b"synthetic\rfixture",
        b"synthetic\0fixture",
        &[0xff],
    ] {
        let (root, parent, uid) = fixture();
        put(root.path(), bytes);
        let inode = root.path().join(NAME).metadata().unwrap().ino();
        assert!(read_at(&parent, uid).is_err());
        assert!(ensure_at(&parent, uid).is_err());
        assert_eq!(fs::read(root.path().join(NAME)).unwrap(), bytes);
        assert_eq!(root.path().join(NAME).metadata().unwrap().ino(), inode);
    }
}

#[test]
fn existing_visible_ascii_formats_and_outer_whitespace_remain_compatible() {
    for bytes in [
        b"synthetic-url_safe-token_1\n".as_slice(),
        b"synthetic+base64/token==\r\n",
        b"  synthetic-legacy-fixture  \n",
    ] {
        let (root, parent, uid) = fixture();
        put(root.path(), bytes);
        let before = fs::read(root.path().join(NAME)).unwrap();
        let token = read_at(&parent, uid).unwrap().unwrap().0;
        assert!(valid_token(&token));
        assert!(ensure_at(&parent, uid).unwrap() == token);
        assert_eq!(fs::read(root.path().join(NAME)).unwrap(), before);
    }
}

#[test]
fn token_and_file_size_limits_reject_without_repair() {
    for size in [MAX_TOKEN_BYTES + 1, MAX_FILE_BYTES as usize + 1] {
        let (root, parent, uid) = fixture();
        put(root.path(), &vec![b'x'; size]);
        assert!(read_at(&parent, uid).is_err());
        assert!(ensure_at(&parent, uid).is_err());
        assert_eq!(
            root.path().join(NAME).metadata().unwrap().len(),
            size as u64
        );
    }
}

#[test]
fn unsafe_modes_links_directories_and_special_files_refuse_without_mutation() {
    for kind in 0..6 {
        let (root, parent, uid) = fixture();
        let outside = tempfile::tempdir().unwrap();
        let sentinel = outside.path().join("sentinel");
        fs::write(&sentinel, b"synthetic-sentinel-unchanged").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
        let path = root.path().join(NAME);
        match kind {
            0 | 1 => {
                put(root.path(), b"synthetic-token\n");
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(if kind == 0 { 0o644 } else { 0o400 }),
                )
                .unwrap();
            }
            2 => std::os::unix::fs::symlink(&sentinel, &path).unwrap(),
            3 => fs::hard_link(&sentinel, &path).unwrap(),
            4 => fs::create_dir(&path).unwrap(),
            _ => rustix::fs::mknodat(
                &parent,
                NAME,
                rustix::fs::FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap(),
        }
        let before = path.symlink_metadata().unwrap();
        assert!(read_at(&parent, uid).is_err());
        assert!(ensure_at(&parent, uid).is_err());
        let after = path.symlink_metadata().unwrap();
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.mode(), after.mode());
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"synthetic-sentinel-unchanged"
        );
    }
}

#[test]
fn writable_or_foreign_parent_is_not_a_provisioning_location() {
    let (root, parent, uid) = fixture();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(ensure_at(&parent, uid).is_err());
    assert!(!root.path().join(NAME).exists());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(ensure_at(&parent, uid.wrapping_add(1)).is_err());
    assert!(!root.path().join(NAME).exists());
}

#[test]
fn concurrent_creators_adopt_one_durable_key_without_replacing_it() {
    let (root, parent, uid) = fixture();
    let tokens = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(4);
        for _ in 0..4 {
            handles.push(scope.spawn(|| ensure_at(&parent, uid).unwrap()));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    let winner = read_at(&parent, uid).unwrap().unwrap().0;
    assert!(tokens.iter().all(|token| token == &winner));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}
