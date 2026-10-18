use super::*;
use rustix::fs::{OFlags, fcntl_getfl};
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn online_archive_is_unnamed_kernel_readonly_and_exactly_digest_bound() {
    let root = tempfile::tempdir().unwrap();
    let stage = AppStage::fixture(root.path()).unwrap();
    let mut download = stage.create_archive().unwrap();
    let bytes = b"public app archive fixture";
    download.append(bytes).unwrap();
    assert_eq!(fs::read_dir(&stage.path).unwrap().count(), 0);
    let mut archive = download
        .finish_online(bytes.len() as u64, &Sha512::digest(bytes).into())
        .unwrap();
    assert_eq!(archive.file.metadata().unwrap().nlink(), 0);
    assert_eq!(
        fcntl_getfl(&archive.file).unwrap() & OFlags::ACCMODE,
        OFlags::RDONLY
    );
    assert!(
        archive
            .file
            .try_clone()
            .unwrap()
            .write_all(b"tamper")
            .is_err()
    );
    assert!(archive.file.set_len(0).is_err());
    let mut actual = Vec::new();
    archive.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
    let path = stage.path.clone();
    drop(stage);
    assert!(!path.exists());
}

#[test]
fn online_rejects_wrong_length_digest_and_empty_input() {
    let root = tempfile::tempdir().unwrap();
    let stage = AppStage::fixture(root.path()).unwrap();
    for (size, digest) in [
        (2, Sha512::digest(b"abc").into()),
        (3, [0; 64]),
        (4, [0; 64]),
    ] {
        let mut download = stage.create_archive().unwrap();
        download.append(b"abc").unwrap();
        assert!(download.finish_online(size, &digest).is_err());
    }
    assert!(
        stage
            .create_archive()
            .unwrap()
            .finish_online(0, &Sha512::digest(b"").into())
            .is_err()
    );
    assert_eq!(fs::read_dir(&stage.path).unwrap().count(), 0);
}

#[test]
fn manual_import_is_explicit_and_readonly_without_a_signature_claim() {
    let root = tempfile::tempdir().unwrap();
    let stage = AppStage::fixture(root.path()).unwrap();
    let mut download = stage.create_archive().unwrap();
    download.append(b"administrative import").unwrap();
    let mut archive = download.finish_manual_import().unwrap();
    let mut actual = Vec::new();
    archive.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, b"administrative import");
    assert!(
        archive
            .file
            .try_clone()
            .unwrap()
            .write_all(b"tamper")
            .is_err()
    );
    assert!(
        stage
            .create_archive()
            .unwrap()
            .finish_manual_import()
            .is_err()
    );
}

#[test]
fn append_budget_is_checked_before_write_and_sealing_checks_inode_length() {
    let root = tempfile::tempdir().unwrap();
    let stage = AppStage::fixture(root.path()).unwrap();
    let mut download = stage.create_archive().unwrap();
    download.written = MAX_ARCHIVE_BYTES - 1;
    assert!(download.append(b"xx").is_err());
    assert_eq!(download.file.metadata().unwrap().len(), 0);
    assert!(download.finish_manual_import().is_err());
}

#[test]
fn staging_never_reuses_or_removes_prior_crash_evidence() {
    let root = tempfile::tempdir().unwrap();
    let first = AppStage::fixture(root.path()).unwrap();
    let first_path = root.path().join(DIRECTORY).join("prior-crash-evidence");
    fs::rename(&first.path, &first_path).unwrap();
    fs::write(first_path.join("recovery-evidence"), b"keep").unwrap();
    // A mismatched binding is left as evidence, never recursively reclaimed.
    drop(first);
    let second = AppStage::fixture(root.path()).unwrap();
    assert_ne!(first_path, second.path);
    fs::create_dir(second.path.join("extract")).unwrap();
    fs::write(second.path.join("extract/partial"), b"owned").unwrap();
    let second_path = second.path.clone();
    drop(second);
    assert!(!second_path.exists());
    assert_eq!(
        fs::read(first_path.join("recovery-evidence")).unwrap(),
        b"keep"
    );
}

#[test]
fn slot_failure_retains_validated_candidate_and_only_success_consumes_its_stage() {
    let root = tempfile::tempdir().unwrap();
    let mut failed = AppStage::fixture(root.path()).unwrap();
    let failed_path = failed.path.clone();
    fs::create_dir(failed_path.join("extract")).unwrap();
    fs::write(
        failed_path.join("extract/candidate"),
        b"preserve for recovery",
    )
    .unwrap();
    failed.preserve_recovery();
    drop(failed);
    assert_eq!(
        fs::read(failed_path.join("extract/candidate")).unwrap(),
        b"preserve for recovery"
    );
    let mut succeeded = AppStage::fixture(root.path()).unwrap();
    let success_path = succeeded.path.clone();
    succeeded.preserve_recovery();
    succeeded.discard_after_success();
    assert!(!success_path.exists());
    assert_eq!(
        fs::read(failed_path.join("extract/candidate")).unwrap(),
        b"preserve for recovery"
    );
}

#[test]
fn unsafe_stage_root_and_parent_are_rejected_without_repair() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    symlink(elsewhere.path(), root.path().join(DIRECTORY)).unwrap();
    assert!(AppStage::fixture(root.path()).is_err());
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
    fs::remove_file(root.path().join(DIRECTORY)).unwrap();
    fs::create_dir(root.path().join(DIRECTORY)).unwrap();
    fs::set_permissions(
        root.path().join(DIRECTORY),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(AppStage::fixture(root.path()).is_err());
    fs::remove_dir(root.path().join(DIRECTORY)).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(AppStage::fixture(root.path()).is_err());
    assert!(!root.path().join(DIRECTORY).exists());
}

#[test]
fn replaced_stage_name_is_not_followed_for_extraction_or_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let stage = AppStage::fixture(root.path()).unwrap();
    let saved = root.path().join(DIRECTORY).join("saved");
    fs::rename(&stage.path, &saved).unwrap();
    fs::write(elsewhere.path().join("keep"), b"foreign").unwrap();
    symlink(elsewhere.path(), &stage.path).unwrap();
    assert!(stage.extraction_path().is_err());
    drop(stage);
    assert_eq!(fs::read(elsewhere.path().join("keep")).unwrap(), b"foreign");
    assert!(saved.exists());
}
