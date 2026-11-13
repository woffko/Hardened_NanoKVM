use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::tempdir;

#[test]
fn receipt_roundtrip_preserves_exact_bytes_and_private_modes() {
    let parent = tempdir().unwrap();
    let store = MetadataStore::for_test(parent.path()).unwrap();
    assert!(store.read().unwrap().is_none());
    let metadata = b"{ \"version\": \"synthetic\" }\n";
    let signature = b"synthetic detached binary\0signature";
    store.replace(metadata, signature).unwrap();
    let receipt = store.read().unwrap().unwrap();
    assert_eq!(receipt.metadata, metadata);
    assert_eq!(receipt.signature, signature);
    assert_eq!(
        fs::metadata(parent.path().join(DIRECTORY)).unwrap().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        fs::metadata(parent.path().join(DIRECTORY).join(RECORD))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    store
        .replace(b"second exact generation\n", b"second signature")
        .unwrap();
    assert_eq!(
        store.read().unwrap().unwrap().metadata,
        b"second exact generation\n"
    );
    assert_eq!(
        fs::read_dir(parent.path().join(DIRECTORY)).unwrap().count(),
        1
    );
    drop(store);
    assert_eq!(
        MetadataStore::for_test(parent.path())
            .unwrap()
            .read()
            .unwrap()
            .unwrap()
            .signature,
        b"second signature"
    );
}

#[test]
fn unsigned_receipt_is_structural_only_and_does_not_claim_authentication() {
    let parent = tempdir().unwrap();
    let store = MetadataStore::for_test(parent.path()).unwrap();
    store.replace(b"explicit lab metadata", b"").unwrap();
    let receipt = store.read().unwrap().unwrap();
    assert_eq!(receipt.metadata, b"explicit lab metadata");
    assert!(receipt.signature.is_empty());
}

#[test]
fn bounds_and_corrupt_canonical_receipt_preserve_existing_evidence() {
    let parent = tempdir().unwrap();
    let store = MetadataStore::for_test(parent.path()).unwrap();
    assert!(store.replace(b"", b"signature").is_err());
    assert!(
        store
            .replace(&vec![0; MAX_METADATA + 1], b"signature")
            .is_err()
    );
    assert!(
        store
            .replace(b"metadata", &vec![0; MAX_SIGNATURE + 1])
            .is_err()
    );
    store.replace(b"metadata", b"signature").unwrap();
    let canonical = parent.path().join(DIRECTORY).join(RECORD);
    let valid = fs::read(&canonical).unwrap();
    for corrupt in [
        valid[..valid.len() - 1].to_vec(),
        [valid.as_slice(), b"extra"].concat(),
        vec![0; HEADER],
        vec![0; MAX_METADATA + MAX_SIGNATURE + HEADER + 1],
    ] {
        fs::write(&canonical, &corrupt).unwrap();
        assert!(store.read().is_err());
        assert!(
            store
                .replace(b"replacement", b"replacement signature")
                .is_err()
        );
        assert_eq!(fs::read(&canonical).unwrap(), corrupt);
        assert_eq!(
            fs::read_dir(parent.path().join(DIRECTORY)).unwrap().count(),
            1
        );
    }
}

#[test]
fn symlinks_hardlinks_and_shared_objects_are_never_imported_or_replaced() {
    let parent = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(
        outside.path().join("sentinel"),
        b"synthetic unchanged outside",
    )
    .unwrap();
    symlink(outside.path(), parent.path().join(DIRECTORY)).unwrap();
    assert!(MetadataStore::for_test(parent.path()).is_err());
    fs::remove_file(parent.path().join(DIRECTORY)).unwrap();
    let store = MetadataStore::for_test(parent.path()).unwrap();
    let canonical = parent.path().join(DIRECTORY).join(RECORD);
    symlink(outside.path().join("sentinel"), &canonical).unwrap();
    assert!(store.read().is_err());
    assert!(store.replace(b"metadata", b"signature").is_err());
    fs::remove_file(&canonical).unwrap();
    store.replace(b"metadata", b"signature").unwrap();
    fs::hard_link(&canonical, outside.path().join("alias")).unwrap();
    assert!(store.read().is_err());
    assert!(
        store
            .replace(b"replacement", b"replacement signature")
            .is_err()
    );
    fs::remove_file(outside.path().join("alias")).unwrap();
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.read().is_err());
    assert!(
        store
            .replace(b"replacement", b"replacement signature")
            .is_err()
    );
    assert_eq!(
        fs::read(outside.path().join("sentinel")).unwrap(),
        b"synthetic unchanged outside"
    );
    drop(store);
    fs::set_permissions(
        parent.path().join(DIRECTORY),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(MetadataStore::for_test(parent.path()).is_err());
}

#[test]
fn lock_lifetime_belongs_to_store_not_incidental_fd_alias() {
    let parent = tempdir().unwrap();
    let store = MetadataStore::for_test(parent.path()).unwrap();
    let alias = store.directory.try_clone().unwrap();
    assert!(matches!(
        MetadataStore::for_test(parent.path()),
        Err(MetadataError::Busy)
    ));
    drop(store);
    let successor = MetadataStore::for_test(parent.path()).unwrap();
    drop(alias);
    assert!(matches!(
        MetadataStore::for_test(parent.path()),
        Err(MetadataError::Busy)
    ));
    drop(successor);
    assert!(MetadataStore::for_test(parent.path()).is_ok());
}

#[test]
fn non_regular_records_are_rejected_without_opening_them_for_io() {
    let parent = tempdir().unwrap();
    let store = MetadataStore::for_test(parent.path()).unwrap();
    let canonical = parent.path().join(DIRECTORY).join(RECORD);
    nix::unistd::mkfifo(
        &canonical,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(matches!(store.read(), Err(MetadataError::Unsafe)));
    assert!(store.replace(b"metadata", b"signature").is_err());
    fs::remove_file(&canonical).unwrap();
    fs::create_dir(&canonical).unwrap();
    assert!(matches!(store.read(), Err(MetadataError::Unsafe)));
    assert!(store.replace(b"metadata", b"signature").is_err());
}

#[test]
fn publication_faults_leave_a_complete_old_or_new_receipt_and_no_partial_canonical() {
    for step in [
        PublicationStep::Written,
        PublicationStep::FileSynced,
        PublicationStep::Renamed,
        PublicationStep::DirectorySynced,
    ] {
        for existing in [false, true] {
            let parent = tempdir().unwrap();
            let mut store = MetadataStore::for_test(parent.path()).unwrap();
            if existing {
                store
                    .replace(b"old exact metadata", b"old signature")
                    .unwrap();
            }
            store.fail_at = Some(step);
            assert!(
                store
                    .replace(b"new exact metadata", b"new signature")
                    .is_err()
            );
            drop(store);
            let reopened = MetadataStore::for_test(parent.path()).unwrap();
            let receipt = reopened.read().unwrap();
            match step {
                PublicationStep::Written | PublicationStep::FileSynced => {
                    if existing {
                        let receipt = receipt.unwrap();
                        assert_eq!(receipt.metadata, b"old exact metadata");
                        assert_eq!(receipt.signature, b"old signature");
                    } else {
                        assert!(receipt.is_none());
                    }
                }
                PublicationStep::Renamed | PublicationStep::DirectorySynced => {
                    let receipt = receipt.unwrap();
                    assert_eq!(receipt.metadata, b"new exact metadata");
                    assert_eq!(receipt.signature, b"new signature");
                }
            }
            assert_eq!(
                fs::read_dir(parent.path().join(DIRECTORY)).unwrap().count(),
                usize::from(
                    existing
                        || matches!(
                            step,
                            PublicationStep::Renamed | PublicationStep::DirectorySynced
                        )
                )
            );
        }
    }
}
