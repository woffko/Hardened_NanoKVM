use super::*;
use crate::update::{restore_archive, restore_capsule::open_capsule};
use std::{
    fs,
    io::{Cursor, Read},
    os::unix::fs::PermissionsExt,
    path::Path,
};
use tempfile::{TempDir, tempdir};

const VERSION: &str = "0.3.0-raw.13";

fn private() -> TempDir {
    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn the_capsule_is_published_whole_under_its_transaction_and_opens_with_its_secret() {
    let (source, staging, capsules) = (tempdir().unwrap(), private(), private());
    let mut archive = restore_archive::fixture_archive(source.path(), staging.path());
    let mut plaintext = Vec::new();
    archive.rewind().unwrap();
    archive.read_to_end(&mut plaintext).unwrap();
    let directory = File::open(capsules.path()).unwrap();

    let sealed = seal_capsule(&mut archive, VERSION, &directory).unwrap();

    assert_eq!(names(capsules.path()), [sealed.name().to_string()]);
    let path = capsules.path().join(sealed.name());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let encrypted = fs::read(&path).unwrap();
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&encrypted)),
        *sealed.sha256()
    );
    let name = sealed.name().to_string();
    let secret = sealed.into_secret();
    assert_eq!(name, format!("{}{SUFFIX}", hex(&secret.transaction_id())));
    let mut payload = open_capsule(&secret, &mut Cursor::new(encrypted), staging.path()).unwrap();
    let mut opened = Vec::new();
    payload.read_to_end(&mut opened).unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn every_seal_has_a_fresh_transaction_and_never_replaces_a_capsule() {
    let (source, staging, capsules) = (tempdir().unwrap(), private(), private());
    let mut archive = restore_archive::fixture_archive(source.path(), staging.path());
    let directory = File::open(capsules.path()).unwrap();
    let first = seal_capsule(&mut archive, VERSION, &directory).unwrap();
    let second = seal_capsule(&mut archive, VERSION, &directory).unwrap();
    assert_ne!(first.name(), second.name());
    assert_ne!(first.sha256(), second.sha256());
    assert_eq!(names(capsules.path()).len(), 2);
}

#[test]
fn an_interrupted_seal_leaves_neither_a_temporary_nor_a_capsule() {
    let (source, staging, capsules) = (tempdir().unwrap(), private(), private());
    let mut archive = restore_archive::fixture_archive(source.path(), staging.path());
    let directory = File::open(capsules.path()).unwrap();
    for step in [
        FailBefore::Sync,
        FailBefore::Rename,
        FailBefore::DirectorySync,
    ] {
        FAIL_AT.with(|fail| fail.set(Some(step)));
        let result = seal_capsule(&mut archive, VERSION, &directory);
        FAIL_AT.with(|fail| fail.set(None));
        assert!(matches!(result, Err(CaptureError::Io(_))));
        assert!(
            names(capsules.path()).is_empty(),
            "left after an injected fault"
        );
    }
    fs::set_permissions(capsules.path(), fs::Permissions::from_mode(0o500)).unwrap();
    assert!(seal_capsule(&mut archive, VERSION, &directory).is_err());
    fs::set_permissions(capsules.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(names(capsules.path()).is_empty());
}
