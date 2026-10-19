use super::*;
use rustix::fs::{OFlags, fcntl_getfl};
use std::os::unix::fs::{PermissionsExt, symlink};

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn private_capacity_child_fixture() {
    let Ok(root) = std::env::var("NANOKVM_SPACE_FIXTURE_ROOT") else {
        return;
    };
    let case = std::env::var("NANOKVM_SPACE_FIXTURE_CASE").unwrap();
    let options = match case.as_str() {
        "bytes" => "mode=0700,size=8388608,nr_inodes=4096",
        "inodes" => "mode=0700,size=67108864,nr_inodes=64",
        _ => "mode=0700,size=67108864,nr_inodes=4096",
    };
    let mut flags = nix::mount::MsFlags::MS_NODEV
        | nix::mount::MsFlags::MS_NOSUID
        | nix::mount::MsFlags::MS_NOEXEC;
    if case == "readonly" {
        flags |= nix::mount::MsFlags::MS_RDONLY;
    }
    nix::mount::mount(
        Some("tmpfs"),
        Path::new(&root),
        Some("tmpfs"),
        flags,
        Some(options),
    )
    .unwrap();
    if case == "ample" {
        let stage = AppStage::fixture(Path::new(&root)).unwrap();
        let mut download = stage.create_archive().unwrap();
        download.append(&compressed_fixture()).unwrap();
        let archive = download.finish_manual_import().unwrap();
        let extracted = stage.extract(archive).unwrap();
        assert_eq!(fs::read(extracted.join("payload")).unwrap(), b"data");
        drop(stage);
    } else {
        let error = match AppStage::fixture(Path::new(&root)) {
            Ok(_) => panic!("insufficient/readonly fixture admitted"),
            Err(error) => error,
        };
        assert_eq!(
            error.raw_os_error(),
            Some(if case == "readonly" { 30 } else { 28 })
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }
    println!("private-capacity-fixture-ran");
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn kernel_private_capacity_limits_refuse_without_using_host_disk_or_old_evidence() {
    for case in ["bytes", "inodes", "readonly", "ample"] {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("volume")).unwrap();
        let evidence = root.path().join("outside-recovery-evidence");
        fs::write(&evidence, b"preserve outside volume").unwrap();
        let output = std::process::Command::new("/usr/bin/unshare")
            .args(["--user", "--map-root-user", "--mount", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_stage::tests::private_capacity_child_fixture",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_SPACE_FIXTURE_ROOT", root.path().join("volume"))
            .env("NANOKVM_SPACE_FIXTURE_CASE", case)
            .output()
            .unwrap();
        assert!(output.status.success(), "{case}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("private-capacity-fixture-ran"));
        assert_eq!(fs::read(evidence).unwrap(), b"preserve outside volume");
        assert_eq!(fs::read_dir(root.path().join("volume")).unwrap().count(), 0);
    }
}

fn compressed_fixture() -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append_data(&mut header, "kvmapp/payload", b"data".as_slice())
        .unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&builder.into_inner().unwrap()).unwrap();
    gzip.finish().unwrap()
}

#[test]
fn refused_growth_writes_nothing_and_does_not_reclaim_old_evidence() {
    let root = tempfile::tempdir().unwrap();
    let evidence = root.path().join("old-recovery-evidence");
    fs::write(&evidence, b"preserve").unwrap();
    let stage = AppStage::fixture(root.path()).unwrap();
    let mut download = stage.create_archive().unwrap();
    let capacity = Capacity::fixture(4096, super::super::app_space::RECOVERY_BYTES, 128);
    assert_eq!(
        download
            .append_with_capacity(b"new bytes", capacity)
            .unwrap_err()
            .raw_os_error(),
        Some(28)
    );
    assert_eq!(
        (download.written, download.file.metadata().unwrap().len()),
        (0, 0)
    );
    assert_eq!(fs::read(evidence).unwrap(), b"preserve");
}

#[test]
fn extraction_rechecks_free_space_and_inode_budget_before_creating_output() {
    for fault in ["bytes", "inodes", "unit", "initial", "stat-error"] {
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("old-live");
        fs::write(&live, b"keep old app").unwrap();
        let stage = AppStage::fixture(root.path()).unwrap();
        let mut download = stage.create_archive().unwrap();
        download.append(&compressed_fixture()).unwrap();
        let archive = download.finish_manual_import().unwrap();
        let mut calls = 0;
        let result = stage.extract_with_capacity(archive, |_| {
            calls += 1;
            let ample = Capacity::fixture(4096, 1024 * 1024 * 1024, 10000);
            if calls == 1 && fault != "initial" {
                return Ok(ample);
            }
            match fault {
                "inodes" => Ok(Capacity::fixture(4096, 1024 * 1024 * 1024, 128)),
                "unit" => Ok(Capacity::fixture(8192, 1024 * 1024 * 1024, 10000)),
                "stat-error" => Err(io::Error::other("fixture capacity probe failed")),
                _ => Ok(Capacity::fixture(4096, 0, 10000)),
            }
        });
        assert!(result.is_err(), "{fault}");
        assert_eq!(calls, if fault == "initial" { 1 } else { 2 });
        assert!(!stage.extraction_path().unwrap().exists());
        assert_eq!(fs::read(live).unwrap(), b"keep old app");
    }
}

#[test]
fn checked_extraction_rewinds_the_same_archive_and_preserves_format_checks() {
    let root = tempfile::tempdir().unwrap();
    let stage = AppStage::fixture(root.path()).unwrap();
    let bytes = compressed_fixture();
    let mut download = stage.create_archive().unwrap();
    download.append(&bytes).unwrap();
    let mut archive = download.finish_manual_import().unwrap();
    archive.read_exact(&mut [0; 7]).unwrap();
    let extracted = stage.extract(archive).unwrap();
    assert_eq!(fs::read(extracted.join("payload")).unwrap(), b"data");
    let other = AppStage::fixture(root.path()).unwrap();
    let mut corrupt = bytes;
    let length = corrupt.len();
    corrupt[length - 8] ^= 1;
    let mut download = other.create_archive().unwrap();
    download.append(&corrupt).unwrap();
    let archive = download.finish_manual_import().unwrap();
    assert!(other.extract(archive).is_err());
    assert!(!other.extraction_path().unwrap().exists());
}

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
fn candidate_fingerprint_covers_whole_readonly_inode_and_rewinds_for_extraction() {
    let root = tempfile::tempdir().unwrap();
    let stage = AppStage::fixture(root.path()).unwrap();
    let bytes = b"whole exact app archive, not just the unread suffix";
    let mut download = stage.create_archive().unwrap();
    download.append(bytes).unwrap();
    let mut archive = download.finish_manual_import().unwrap();
    archive.read_exact(&mut [0; 7]).unwrap();
    for _ in 0..2 {
        assert_eq!(
            archive.fingerprint().unwrap(),
            (bytes.len() as u64, Sha512::digest(bytes).into())
        );
        let mut actual = Vec::new();
        archive.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, bytes);
    }
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
