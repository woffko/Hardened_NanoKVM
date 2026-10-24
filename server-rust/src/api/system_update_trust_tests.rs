use super::*;
use std::io::Write;
use std::process::Command;
use tempfile::{TempDir, tempdir};

struct SigningFixture {
    _directory: TempDir,
    private: PathBuf,
    public: PathBuf,
    config: Config,
}
impl SigningFixture {
    fn new() -> Self {
        let directory = tempdir().unwrap();
        let private = directory.path().join("synthetic-only.pem");
        let public = directory.path().join("synthetic-only.pub.pem");
        let result = Command::new("/usr/bin/openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&private)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "synthetic test key generation failed"
        );
        let result = Command::new("/usr/bin/openssl")
            .args(["pkey", "-in"])
            .arg(&private)
            .args(["-pubout", "-out"])
            .arg(&public)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "synthetic public key extraction failed"
        );
        fs::set_permissions(&public, fs::Permissions::from_mode(0o644)).unwrap();
        let mut config = Config::default();
        config.paths.system_update_public_key = public.clone();
        Self {
            _directory: directory,
            private,
            public,
            config,
        }
    }
    fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        let metadata = self._directory.path().join("synthetic-metadata.json");
        let signature = self._directory.path().join("synthetic-metadata.sig");
        fs::write(&metadata, bytes).unwrap();
        let result = Command::new("/usr/bin/openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(&self.private)
            .arg("-out")
            .arg(&signature)
            .arg(&metadata)
            .output()
            .unwrap();
        assert!(result.status.success(), "synthetic test signing failed");
        fs::read(signature).unwrap()
    }
    fn policy(&self, value: &str) {
        let policy = self._directory.path().join("update-key-policy");
        fs::write(&policy, value).unwrap();
        fs::set_permissions(policy, fs::Permissions::from_mode(0o644)).unwrap();
    }
}

fn exact_metadata() -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(&tests::valid_latest()).unwrap();
    bytes.push(b'\n');
    bytes
}

#[tokio::test]
async fn install_receipt_requires_exact_signature_and_current_key_policy() {
    let fixture = SigningFixture::new();
    fixture.policy("hardened-system-test\n");
    let bytes = exact_metadata();
    let signature = fixture.sign(&bytes);
    let parent = tempdir().unwrap();
    let store = MetadataStore::for_test(parent.path()).unwrap();
    store.replace(&bytes, &signature).unwrap();
    let verified = authenticate_stored_system_metadata(
        required_system_metadata_receipt(&store).unwrap(),
        &fixture.config,
    )
    .await
    .unwrap();
    assert_eq!(verified.metadata, bytes);
    assert_eq!(verified.signature, signature);
    assert_eq!(verified.latest, tests::valid_latest());

    // Re-serializing the same parsed fields changes bytes and must not verify.
    let mut whitespace = bytes.clone();
    whitespace.push(b'\n');
    assert!(
        authenticate_stored_system_metadata(
            MetadataReceipt {
                metadata: whitespace,
                signature: signature.clone()
            },
            &fixture.config
        )
        .await
        .is_err()
    );
    let mut forged = tests::valid_latest();
    forged.sha256 = "b".repeat(64);
    assert!(
        authenticate_stored_system_metadata(
            MetadataReceipt {
                metadata: serde_json::to_vec(&forged).unwrap(),
                signature: signature.clone()
            },
            &fixture.config
        )
        .await
        .is_err()
    );
    for bad_signature in [Vec::new(), vec![0; 256], vec![0; MAX_SIGNATURE + 1]] {
        assert!(
            authenticate_stored_system_metadata(
                MetadataReceipt {
                    metadata: bytes.clone(),
                    signature: bad_signature
                },
                &fixture.config
            )
            .await
            .is_err()
        );
    }

    // Persisted bytes do not freeze a permission that policy has since revoked.
    fixture.policy("hardened-system-prod-2026q3\n");
    assert!(
        authenticate_stored_system_metadata(
            required_system_metadata_receipt(&store).unwrap(),
            &fixture.config
        )
        .await
        .is_err()
    );
    fixture.policy("hardened-system-test\n");
    let other = SigningFixture::new();
    fs::copy(&other.public, &fixture.public).unwrap();
    assert!(
        authenticate_stored_system_metadata(
            required_system_metadata_receipt(&store).unwrap(),
            &fixture.config
        )
        .await
        .is_err()
    );
    assert_eq!(store.read().unwrap().unwrap().metadata, bytes);
    assert_eq!(store.read().unwrap().unwrap().signature, signature);
}

#[tokio::test]
async fn explicit_unsigned_lab_policy_is_rechecked_not_inferred_from_cache() {
    let mut latest = tests::valid_latest();
    latest.signature_algorithm = SYSTEM_UPDATE_UNSIGNED_ALGORITHM.to_string();
    latest.signature_key_id = SYSTEM_UPDATE_UNSIGNED_ALGORITHM.to_string();
    let metadata = serde_json::to_vec(&latest).unwrap();
    let mut config = Config::default();
    assert!(
        authenticate_stored_system_metadata(
            MetadataReceipt {
                metadata: metadata.clone(),
                signature: Vec::new()
            },
            &config
        )
        .await
        .is_err()
    );
    config.security.allow_unsigned_updates = true;
    assert!(
        authenticate_stored_system_metadata(
            MetadataReceipt {
                metadata: metadata.clone(),
                signature: Vec::new()
            },
            &config
        )
        .await
        .is_ok()
    );
    assert!(
        authenticate_stored_system_metadata(
            MetadataReceipt {
                metadata: metadata.clone(),
                signature: b"not a signed receipt".to_vec()
            },
            &config
        )
        .await
        .is_err()
    );
    config.security.allow_unsigned_updates = false;
    assert!(
        authenticate_stored_system_metadata(
            MetadataReceipt {
                metadata,
                signature: Vec::new()
            },
            &config
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn forged_stage_cannot_replace_authenticated_latest_before_payload_access() {
    let fixture = SigningFixture::new();
    let metadata = exact_metadata();
    let signature = fixture.sign(&metadata);
    let verified = authenticate_stored_system_metadata(
        MetadataReceipt {
            metadata,
            signature,
        },
        &fixture.config,
    )
    .await
    .unwrap();
    let stage = tempdir().unwrap();
    let mut forged = tests::valid_latest();
    forged.sha256 = "b".repeat(64);
    let record = SystemStageRecord {
        staged_at: 0,
        latest: forged,
        manifest: tests::valid_manifest(SystemManifestFile {
            payload: "system-version.json".to_string(),
            install: SYSTEM_VERSION_FILE.to_string(),
            size: 1,
            sha256: "a".repeat(64),
        }),
    };
    write_stage_record(stage.path(), &record).unwrap();
    let before = fs::read(stage.path().join(SYSTEM_STAGE_RECORD)).unwrap();
    let error = install_staged_update(stage.path(), &fixture.config, verified, None).unwrap_err();
    assert!(
        matches!(error, AppError::BadRequest(ref message) if message.starts_with("staged system update differs from authenticated metadata"))
    );
    assert_eq!(
        fs::read(stage.path().join(SYSTEM_STAGE_RECORD)).unwrap(),
        before
    );
    assert_eq!(fs::read_dir(stage.path()).unwrap().count(), 1);
}

#[test]
fn legacy_cache_is_not_imported_as_protected_metadata() {
    let parent = tempdir().unwrap();
    let store = MetadataStore::for_test(parent.path()).unwrap();
    fs::write(parent.path().join(SYSTEM_STAGE_RECORD), exact_metadata()).unwrap();
    let error = required_system_metadata_receipt(&store).err().unwrap();
    assert!(
        matches!(error, AppError::BadRequest(ref message) if message.contains("Download and Verify again"))
    );
    assert!(store.read().unwrap().is_none());
}

#[tokio::test]
async fn archive_stream_is_exactly_bounded_and_never_opens_the_canonical_name() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let sentinel = outside.path().join("sentinel");
    fs::write(&sentinel, b"outside unchanged").unwrap();
    let stage = StageDirectory::prepare(&root.path().join("system")).unwrap();
    let canonical = root.path().join("system/update.tar.gz");
    std::os::unix::fs::symlink(&sentinel, &canonical).unwrap();
    let mut downloaded = stage.create_download().unwrap();
    let mut command = tokio::process::Command::new("/usr/bin/printf");
    command.args(["%s", "synthetic archive"]);
    receive_system_archive(&mut command, 17, &downloaded, Duration::from_secs(5))
        .await
        .unwrap();
    downloaded.file_mut().rewind().unwrap();
    let mut content = Vec::new();
    downloaded.file_mut().read_to_end(&mut content).unwrap();
    assert_eq!(content, b"synthetic archive");
    assert_eq!(fs::read(&sentinel).unwrap(), b"outside unchanged");
    assert!(
        fs::symlink_metadata(&canonical)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    drop(downloaded);
    assert_eq!(fs::read_dir(root.path().join("system")).unwrap().count(), 1);

    for (bytes, size, expected_ok) in [
        (b"exact".as_slice(), 5, true),
        (b"short".as_slice(), 6, false),
        (b"oversized".as_slice(), 8, false),
        (b"".as_slice(), 1, false),
    ] {
        let mut source = bytes;
        let mut destination = Vec::new();
        assert_eq!(
            copy_system_archive(&mut source, &mut destination, size)
                .await
                .is_ok(),
            expected_ok
        );
        assert!(destination.len() as u64 <= size);
        if expected_ok {
            assert_eq!(destination, bytes);
        }
    }
}

#[tokio::test]
async fn failed_or_cancelled_archive_transfer_does_not_publish_or_delete_recovery_data() {
    let root = tempdir().unwrap();
    let stage = StageDirectory::prepare(&root.path().join("system")).unwrap();
    let keep = root.path().join("system/keep");
    fs::write(&keep, b"recovery data").unwrap();
    for oversized in [false, true] {
        let downloaded = stage.create_download().unwrap();
        let mut command = tokio::process::Command::new(if oversized {
            "/usr/bin/printf"
        } else {
            "/usr/bin/false"
        });
        if oversized {
            command.args(["%s", "too many bytes"]);
        }
        assert!(
            receive_system_archive(&mut command, 1, &downloaded, Duration::from_secs(5))
                .await
                .is_err()
        );
        drop(downloaded);
        assert_eq!(fs::read_dir(root.path().join("system")).unwrap().count(), 1);
    }
    let downloaded = stage.create_download().unwrap();
    let mut command = tokio::process::Command::new("/usr/bin/sleep");
    command.arg("10");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            receive_system_archive(&mut command, 1, &downloaded, Duration::from_secs(5))
        )
        .await
        .is_err()
    );
    drop(downloaded);
    assert_eq!(fs::read(&keep).unwrap(), b"recovery data");
    assert_eq!(fs::read_dir(root.path().join("system")).unwrap().count(), 1);
}

#[test]
fn archive_child_fixture() {
    let Ok(mode) = std::env::var("NANOKVM_ARCHIVE_TEST_MODE") else {
        return;
    };
    let pid_path = std::env::var_os("NANOKVM_ARCHIVE_TEST_PID").unwrap();
    fs::write(pid_path, std::process::id().to_string()).unwrap();
    match mode.as_str() {
        "hang" => std::thread::sleep(Duration::from_secs(30)),
        "fail" => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(b"synthetic bytes before failed exit")
                .unwrap();
            stdout.flush().unwrap();
            std::process::exit(7);
        }
        _ => panic!("invalid synthetic archive child fixture"),
    }
}

fn archive_child(mode: &str, pid_path: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .env_clear()
        .env("NANOKVM_ARCHIVE_TEST_MODE", mode)
        .env("NANOKVM_ARCHIVE_TEST_PID", pid_path)
        .args([
            "--exact",
            "api::system_update::trust_tests::archive_child_fixture",
            "--nocapture",
        ]);
    command
}

fn archive_child_reaped(pid_path: &Path) -> bool {
    let pid = fs::read_to_string(pid_path).unwrap();
    !Path::new("/proc").join(pid).exists()
}

#[tokio::test]
async fn archive_child_nonzero_exit_deadline_and_cancellation_are_reaped() {
    let root = tempdir().unwrap();
    let stage_path = root.path().join("system");
    let stage = StageDirectory::prepare(&stage_path).unwrap();
    let pid_path = root.path().join("child-pid");
    // Measure the deterministic synthetic test-harness stdout; even an exact
    // completed byte stream is unusable when the direct child exits nonzero.
    let control = archive_child("fail", &pid_path).output().await.unwrap();
    assert_eq!(control.status.code(), Some(7));
    assert!(!control.stdout.is_empty());
    let downloaded = stage.create_download().unwrap();
    let error = receive_system_archive(
        &mut archive_child("fail", &pid_path),
        control.stdout.len() as u64,
        &downloaded,
        Duration::from_secs(3),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, AppError::BadRequest(ref message) if message == "download system update archive failed")
    );
    assert!(archive_child_reaped(&pid_path));
    drop(downloaded);

    let downloaded = stage.create_download().unwrap();
    let error = receive_system_archive(
        &mut archive_child("hang", &pid_path),
        1024,
        &downloaded,
        Duration::from_millis(500),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, AppError::Internal(ref message) if message == "system archive download timed out")
    );
    assert!(archive_child_reaped(&pid_path));
    drop(downloaded);

    fs::remove_file(&pid_path).unwrap();
    let downloaded = stage.create_download().unwrap();
    let mut command = archive_child("hang", &pid_path);
    let operation = tokio::spawn(async move {
        receive_system_archive(&mut command, 1024, &downloaded, Duration::from_secs(10)).await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !pid_path.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    operation.abort();
    assert!(operation.await.unwrap_err().is_cancelled());
    tokio::time::timeout(Duration::from_secs(3), async {
        while !archive_child_reaped(&pid_path) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fs::read_dir(&stage_path).unwrap().count(), 0);
}

fn synthetic_system_bundle() -> (SystemLatest, SystemManifest, Vec<u8>) {
    let payload = b"synthetic system version";
    let manifest = tests::valid_manifest(SystemManifestFile {
        payload: "rootfs/etc/kvm/system-version.json".into(),
        install: SYSTEM_VERSION_FILE.into(),
        size: payload.len() as u64,
        sha256: format!("{:x}", Sha256::digest(payload)),
    });
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (path, bytes) in [
        ("manifest.json", serde_json::to_vec(&manifest).unwrap()),
        (
            "payload/rootfs/etc/kvm/system-version.json",
            payload.to_vec(),
        ),
    ] {
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes.as_slice())
            .unwrap();
    }
    let bytes = builder.into_inner().unwrap().finish().unwrap();
    let mut latest = tests::valid_latest();
    latest.size = bytes.len() as u64;
    latest.sha256 = format!("{:x}", Sha256::digest(&bytes));
    latest.sha512 = STANDARD.encode(Sha512::digest(&bytes));
    (latest, manifest, bytes)
}

#[test]
fn cache_reuse_requires_archive_digest_not_just_same_size_and_valid_extraction() {
    let root = tempdir().unwrap();
    let stage_path = root.path().join("system");
    let stage = StageDirectory::prepare(&stage_path).unwrap();
    let (latest, manifest, mut bytes) = synthetic_system_bundle();
    let mut downloaded = stage.create_download().unwrap();
    downloaded.file_mut().write_all(&bytes).unwrap();
    verify_system_archive(downloaded.file_mut(), &latest).unwrap();
    downloaded.publish(&latest.name).unwrap();
    let mut snapshot = freeze_system_archive(downloaded.file_mut(), &stage_path, &latest).unwrap();
    let extracted = extract_and_verify_system_bundle(&mut snapshot, &stage_path, &latest).unwrap();
    let (extracted, raw_images) = extracted;
    assert!(raw_images.is_none());
    assert_eq!(extracted, manifest);
    write_stage_record(
        &stage_path,
        &SystemStageRecord {
            staged_at: 0,
            latest: latest.clone(),
            manifest,
        },
    )
    .unwrap();
    assert!(
        read_cached_staged_update(&stage_path, &latest)
            .unwrap()
            .is_some()
    );
    bytes[0] ^= 1;
    fs::write(stage_path.join(&latest.name), &bytes).unwrap();
    assert_eq!(
        fs::metadata(stage_path.join(&latest.name)).unwrap().len(),
        latest.size
    );
    assert!(
        read_cached_staged_update(&stage_path, &latest)
            .unwrap()
            .is_none()
    );
    assert_eq!(fs::read(stage_path.join(&latest.name)).unwrap(), bytes);
}

#[test]
fn system_extraction_uses_frozen_archive_despite_source_inode_and_name_tampering() {
    let root = tempdir().unwrap();
    let stage_path = root.path().join("system");
    let stage = StageDirectory::prepare(&stage_path).unwrap();
    let (latest, manifest, bytes) = synthetic_system_bundle();
    let source_path = stage_path.join(&latest.name);
    fs::write(&source_path, &bytes).unwrap();
    let mut source = stage.open_archive(&latest.name).unwrap();
    let mut snapshot = freeze_system_archive(&mut source, &stage_path, &latest).unwrap();
    let tamper = vec![b'x'; bytes.len()];
    fs::write(&source_path, &tamper).unwrap();
    // The original inode and the original name are both no longer valid input.
    fs::rename(&source_path, stage_path.join("old-source")).unwrap();
    fs::write(&source_path, &tamper).unwrap();
    let actual = extract_and_verify_system_bundle(&mut snapshot, &stage_path, &latest).unwrap();
    let (actual, raw_images) = actual;
    assert!(raw_images.is_none());
    assert_eq!(actual, manifest);
    assert!(freeze_system_archive(&mut source, &stage_path, &latest).is_err());
    assert_eq!(fs::read(stage_path.join("old-source")).unwrap(), tamper);
    assert_eq!(fs::read(&source_path).unwrap(), tamper);
}

#[test]
fn frozen_system_archive_checks_both_signed_digests_without_touching_legacy_staging() {
    let root = tempdir().unwrap();
    let stage_path = root.path().join("system");
    let stage = StageDirectory::prepare(&stage_path).unwrap();
    let (latest, _, bytes) = synthetic_system_bundle();
    fs::write(stage_path.join(&latest.name), &bytes).unwrap();
    fs::write(stage_path.join("preserve"), b"retained recovery").unwrap();
    for change in 0..4 {
        let mut forged = latest.clone();
        match change {
            0 => forged.sha256 = "b".repeat(64),
            1 => forged.sha512 = STANDARD.encode([2_u8; 64]),
            2 => forged.size += 1,
            _ => forged.sha512 = "invalid".into(),
        }
        let mut source = stage.open_archive(&latest.name).unwrap();
        assert!(freeze_system_archive(&mut source, &stage_path, &forged).is_err());
        assert_eq!(fs::read_dir(&stage_path).unwrap().count(), 2);
        assert_eq!(
            fs::read(stage_path.join("preserve")).unwrap(),
            b"retained recovery"
        );
    }
}

#[test]
fn preparing_stage_preserves_backups_preserve_and_unknown_recovery_material() {
    let parent = tempdir().unwrap();
    let stage = parent.path().join("system-update");
    for file in [
        "backups/previous/state",
        "preserve/identity",
        "unknown-user-file",
        "old-archive.tar.gz",
    ] {
        let path = stage.join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"synthetic retained recovery material").unwrap();
    }
    prepare_stage_dir(&stage).unwrap();
    prepare_stage_dir(&stage).unwrap();
    for file in [
        "backups/previous/state",
        "preserve/identity",
        "unknown-user-file",
        "old-archive.tar.gz",
    ] {
        assert_eq!(
            fs::read(stage.join(file)).unwrap(),
            b"synthetic retained recovery material"
        );
    }
    fs::write(stage.join(SYSTEM_STAGE_RECORD), b"malformed legacy JSON").unwrap();
    assert!(
        read_cached_staged_update(&stage, &tests::valid_latest())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fs::read(stage.join(SYSTEM_STAGE_RECORD)).unwrap(),
        b"malformed legacy JSON"
    );
}

#[test]
fn retained_progress_and_stage_symlinks_never_become_write_targets() {
    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let stage = root.path().join("system");
    prepare_stage_dir(&stage).unwrap();
    let sentinel = outside.path().join("sentinel");
    fs::write(&sentinel, b"outside unchanged").unwrap();
    for name in [SYSTEM_STAGE_RECORD, SYSTEM_PROGRESS_RECORD] {
        std::os::unix::fs::symlink(&sentinel, stage.join(name)).unwrap();
    }
    write_update_progress(
        &stage,
        SystemUpdateProgress::new("download", "downloading", None, None),
    )
    .unwrap();
    let record = SystemStageRecord {
        staged_at: 0,
        latest: tests::valid_latest(),
        manifest: tests::valid_manifest(SystemManifestFile {
            payload: "boot/boot.sd".into(),
            install: "/boot/boot.sd".into(),
            size: 1,
            sha256: "a".repeat(64),
        }),
    };
    write_stage_record(&stage, &record).unwrap();
    assert_eq!(fs::read(&sentinel).unwrap(), b"outside unchanged");
    assert!(read_update_progress(&stage).unwrap().is_some());
    assert!(read_stage_record(&stage).unwrap().is_some());
    fs::remove_file(stage.join(SYSTEM_PROGRESS_RECORD)).unwrap();
    std::os::unix::fs::symlink(&sentinel, stage.join(SYSTEM_PROGRESS_RECORD)).unwrap();
    remove_update_progress(&stage).unwrap();
    assert!(fs::symlink_metadata(stage.join(SYSTEM_PROGRESS_RECORD)).is_err());
    assert_eq!(fs::read(&sentinel).unwrap(), b"outside unchanged");
}

#[test]
fn any_pending_object_blocks_relaunch_without_deleting_evidence() {
    let parent = tempdir().unwrap();
    let pending = parent.path().join("pending");
    assert!(reject_pending_system_paths(&[&pending]).is_ok());
    fs::write(
        &pending,
        b"even malformed pending state is not permission to retry",
    )
    .unwrap();
    assert!(matches!(
        reject_pending_system_paths(&[&pending]),
        Err(AppError::Conflict(_))
    ));
    assert!(pending.is_file());
    fs::remove_file(&pending).unwrap();
    std::os::unix::fs::symlink(parent.path().join("absent"), &pending).unwrap();
    assert!(matches!(
        reject_pending_system_paths(&[&pending]),
        Err(AppError::Conflict(_))
    ));
    assert!(
        fs::symlink_metadata(&pending)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn legacy_raw_marker_is_diagnostic_only_and_never_a_pending_fallback() {
    let parent = tempdir().unwrap();
    let pending = parent.path().join("root-pending");
    let legacy = parent.path().join("legacy-p3-marker");
    let (record, error) = read_pending_status(&pending, &legacy);
    assert!(record.is_none() && error.is_none());
    let forged = br#"{"pending":{"version":"0.3.0-raw.12","target":"sg2002-licheervnano-sd","backupId":"raw-forged","installedAt":1,"requiresReboot":true,"fileCount":2}}"#;
    for bytes in [forged.as_slice(), b"invalid json", b""] {
        fs::write(&legacy, bytes).unwrap();
        let (record, error) = read_pending_status(&pending, &legacy);
        assert!(record.is_none(), "p3 marker became pending authority");
        assert!(error.is_some(), "legacy evidence was silently hidden");
        assert!(read_pending_update(&pending).unwrap().is_none());
        assert_eq!(fs::read(&legacy).unwrap(), bytes);
    }
    fs::remove_file(&legacy).unwrap();
    fs::create_dir(&legacy).unwrap();
    assert!(read_pending_status(&pending, &legacy).1.is_some());
    fs::remove_dir(&legacy).unwrap();
    std::os::unix::fs::symlink(parent.path().join("absent"), &legacy).unwrap();
    assert!(read_pending_status(&pending, &legacy).1.is_some());
    assert!(fs::symlink_metadata(&legacy).unwrap().is_symlink());
    fs::remove_file(&legacy).unwrap();
    nix::unistd::mkfifo(&legacy, nix::sys::stat::Mode::S_IRUSR).unwrap();
    assert!(read_pending_status(&pending, &legacy).1.is_some());
    assert!(fs::symlink_metadata(&legacy).is_ok());
}

#[test]
fn root_pending_status_keeps_root_record_and_exposes_read_errors() {
    let parent = tempdir().unwrap();
    let pending = parent.path().join("root-pending");
    let legacy = parent.path().join("legacy-p3-marker");
    let expected = SystemPendingUpdate {
        version: "0.3.0-file.1".into(),
        target: "sg2002-licheervnano-sd".into(),
        backup_id: "trusted-file-backup".into(),
        installed_at: 42,
        requires_reboot: true,
        file_count: 1,
        install_boot_id: None,
    };
    let bytes = serde_json::to_vec(&expected).unwrap();
    fs::write(&pending, &bytes).unwrap();
    let (record, error) = read_pending_status(&pending, &legacy);
    assert!(error.is_none());
    assert_eq!(record.unwrap().backup_id, expected.backup_id);
    fs::write(&legacy, b"legacy evidence, never parsed").unwrap();
    let (record, error) = read_pending_status(&pending, &legacy);
    assert_eq!(record.unwrap().backup_id, expected.backup_id);
    assert!(error.is_some());
    assert_eq!(fs::read(&pending).unwrap(), bytes);
    fs::write(&pending, b"corrupt root pending").unwrap();
    let (record, error) = read_pending_status(&pending, &legacy);
    assert!(record.is_none());
    assert!(error.unwrap().contains("invalid pending system update"));
    assert_eq!(fs::read(&pending).unwrap(), b"corrupt root pending");
    assert_eq!(fs::read(&legacy).unwrap(), b"legacy evidence, never parsed");
}

#[test]
fn pending_reader_refuses_symlinks_special_files_and_oversized_records() {
    let parent = tempdir().unwrap();
    let pending = parent.path().join("root-pending");
    let victim = parent.path().join("unchanged-target");
    fs::write(&victim, b"unrelated bytes").unwrap();
    std::os::unix::fs::symlink(&victim, &pending).unwrap();
    assert!(read_pending_update(&pending).is_err());
    assert_eq!(fs::read(&victim).unwrap(), b"unrelated bytes");
    fs::remove_file(&pending).unwrap();
    std::os::unix::fs::symlink(parent.path().join("absent"), &pending).unwrap();
    assert!(read_pending_update(&pending).is_err());
    fs::remove_file(&pending).unwrap();
    fs::create_dir(&pending).unwrap();
    assert!(read_pending_update(&pending).is_err());
    fs::remove_dir(&pending).unwrap();
    nix::unistd::mkfifo(&pending, nix::sys::stat::Mode::S_IRUSR).unwrap();
    assert!(read_pending_update(&pending).is_err());
    fs::remove_file(&pending).unwrap();
    let oversized = vec![b' '; MAX_PENDING_UPDATE_BYTES as usize + 1];
    fs::write(&pending, &oversized).unwrap();
    assert!(read_pending_update(&pending).is_err());
    assert_eq!(fs::read(&pending).unwrap(), oversized);
}
