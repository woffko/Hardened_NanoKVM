use super::*;
use rustix::fs::{OFlags, fcntl_getfl};
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::Command,
};

const LIMIT: Duration = Duration::from_secs(5);

struct SignedFixture {
    root: tempfile::TempDir,
    key: PathBuf,
    metadata: Vec<u8>,
    signature: Vec<u8>,
}

impl SignedFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("synthetic-only.pem");
        let key = root.path().join("synthetic-only.pub.pem");
        let source = root.path().join("synthetic-metadata");
        let signature = root.path().join("synthetic-signature");
        let metadata = b"exact synthetic PUBLIC metadata\n".to_vec();
        fs::write(&source, &metadata).unwrap();
        for args in [
            vec![
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                private.to_str().unwrap(),
            ],
            vec![
                "pkey",
                "-in",
                private.to_str().unwrap(),
                "-pubout",
                "-out",
                key.to_str().unwrap(),
            ],
            vec![
                "dgst",
                "-sha256",
                "-sign",
                private.to_str().unwrap(),
                "-out",
                signature.to_str().unwrap(),
                source.to_str().unwrap(),
            ],
        ] {
            assert!(
                Command::new("/usr/bin/openssl")
                    .args(args)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        }
        let signature = fs::read(signature).unwrap();
        fs::write(
            root.path().join(UPDATE_KEY_POLICY_FILE),
            format!("{LEGACY_UPDATE_KEY_ID}\n"),
        )
        .unwrap();
        Self {
            root,
            key,
            metadata,
            signature,
        }
    }

    fn capture(&self) -> SignatureInputs {
        SignatureInputs::capture(
            &self.metadata,
            &self.signature,
            &self.key,
            LEGACY_UPDATE_KEY_ID,
        )
        .unwrap()
    }
}

#[tokio::test]
async fn actual_openssl_reads_only_anonymous_readonly_inputs_after_source_replacement() {
    let mut fixture = SignedFixture::new();
    let entries = || fs::read_dir(fixture.root.path()).unwrap().count();
    let before = entries();
    let inputs = fixture.capture();
    assert_eq!(entries(), before); // No named temporary inputs.
    for file in [&inputs.key, &inputs.metadata, &inputs.signature] {
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.nlink(), 0);
        assert_eq!(fcntl_getfl(file).unwrap() & OFlags::ACCMODE, OFlags::RDONLY);
        let mut readonly = file;
        assert!(readonly.write_all(b"cannot write").is_err());
    }
    let replacement = fixture.root.path().join("replacement");
    fs::write(&replacement, b"not a key").unwrap();
    fs::rename(replacement, &fixture.key).unwrap();
    fixture.metadata.fill(b'x');
    fixture.signature.fill(0);
    // All three original inputs remain exact after the caller/source changes.
    inputs.verify(LIMIT).await.unwrap();
    assert!(
        verify_metadata_signature(
            &fixture.metadata,
            &fixture.signature,
            &fixture.key,
            LEGACY_UPDATE_KEY_ID,
            LIMIT
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn signature_failures_and_input_budgets_cannot_bypass_capture() {
    let fixture = SignedFixture::new();
    let mut forged = fixture.signature.clone();
    forged[0] ^= 1;
    assert!(
        verify_metadata_signature(
            &fixture.metadata,
            &forged,
            &fixture.key,
            LEGACY_UPDATE_KEY_ID,
            LIMIT
        )
        .await
        .is_err()
    );
    for (metadata, signature) in [
        (Vec::new(), fixture.signature.clone()),
        (vec![b'x'; MAX_METADATA + 1], fixture.signature.clone()),
        (fixture.metadata.clone(), Vec::new()),
        (fixture.metadata.clone(), vec![0; MAX_SIGNATURE + 1]),
    ] {
        assert!(
            verify_metadata_signature(
                &metadata,
                &signature,
                &fixture.key,
                LEGACY_UPDATE_KEY_ID,
                LIMIT
            )
            .await
            .is_err()
        );
    }
    for id in ["", "../key", "bad/key", ".hidden", "unknown"] {
        assert!(
            verify_metadata_signature(
                &fixture.metadata,
                &fixture.signature,
                &fixture.key,
                id,
                LIMIT
            )
            .await
            .is_err()
        );
    }
}

#[test]
fn key_and_policy_capture_refuses_unsafe_aliases_types_modes_and_bounds() {
    for name in ["key", "policy"] {
        for fault in [
            "symlink",
            "hardlink",
            "fifo",
            "directory",
            "writable",
            "empty",
            "oversized",
        ] {
            let root = tempfile::tempdir().unwrap();
            let key = root.path().join("key.pub.pem");
            let policy = root.path().join(UPDATE_KEY_POLICY_FILE);
            fs::write(&key, b"synthetic public key").unwrap();
            fs::write(&policy, b"hardened-system-dev\n").unwrap();
            let target = if name == "key" { &key } else { &policy };
            match fault {
                "symlink" => {
                    fs::remove_file(target).unwrap();
                    symlink(root.path().join("missing"), target).unwrap();
                }
                "hardlink" => fs::hard_link(target, root.path().join("alias")).unwrap(),
                "fifo" => {
                    fs::remove_file(target).unwrap();
                    rustix::fs::mknodat(
                        rustix::fs::CWD,
                        target,
                        rustix::fs::FileType::Fifo,
                        Mode::RUSR | Mode::WUSR,
                        0,
                    )
                    .unwrap();
                }
                "directory" => {
                    fs::remove_file(target).unwrap();
                    fs::create_dir(target).unwrap();
                }
                "writable" => {
                    fs::set_permissions(target, fs::Permissions::from_mode(0o666)).unwrap()
                }
                "empty" => fs::write(target, b"").unwrap(),
                "oversized" => {
                    let maximum = if name == "key" {
                        MAX_UPDATE_PUBLIC_KEY_BYTES
                    } else {
                        MAX_UPDATE_KEY_POLICY_BYTES
                    };
                    fs::File::options()
                        .write(true)
                        .open(target)
                        .unwrap()
                        .set_len(maximum + 1)
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                SignatureInputs::capture(b"metadata", b"signature", &key, LEGACY_UPDATE_KEY_ID)
                    .is_err(),
                "accepted {name}/{fault}"
            );
        }
    }
}

#[test]
fn protected_root_and_keyring_refuse_parent_aliases_writable_and_mount_paths() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("trust");
    fs::create_dir(&directory).unwrap();
    let key = directory.join("key.pub.pem");
    fs::write(&key, b"key").unwrap();
    // With a policy that allows both IDs, only the paths can be the reason.
    let policy = format!("{LEGACY_UPDATE_KEY_ID}\nproduction\n");
    fs::write(directory.join(UPDATE_KEY_POLICY_FILE), &policy).unwrap();
    SignatureInputs::capture(b"m", b"s", &key, LEGACY_UPDATE_KEY_ID).unwrap();
    let alias = root.path().join("alias");
    symlink(&directory, &alias).unwrap();
    assert!(
        SignatureInputs::capture(b"m", b"s", &alias.join("key.pub.pem"), LEGACY_UPDATE_KEY_ID)
            .is_err()
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(SignatureInputs::capture(b"m", b"s", &key, LEGACY_UPDATE_KEY_ID).is_err());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    // A nonsticky writable intermediate component is also rejected.
    let child = directory.join("child");
    fs::create_dir(&child).unwrap();
    fs::write(child.join("key"), b"key").unwrap();
    fs::write(child.join(UPDATE_KEY_POLICY_FILE), &policy).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        SignatureInputs::capture(b"m", b"s", &child.join("key"), LEGACY_UPDATE_KEY_ID).is_err()
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
    symlink(&child, directory.join(UPDATE_KEYRING_DIR)).unwrap();
    assert!(SignatureInputs::capture(b"m", b"s", &key, "production").is_err());
    assert!(open_trust_root(Path::new("relative")).is_err());
    assert!(open_trust_root(Path::new("/proc")).is_err());
    assert!(open_trust_root(&directory.join("../trust")).is_err());
}

#[test]
fn pinned_source_replacement_and_inplace_change_are_detected_before_read() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let source = root.path().join("key");
    fs::write(&source, b"original").unwrap();
    let pinned = PinnedTrustFile::open(&directory, "key", 64)
        .unwrap()
        .unwrap();
    let replacement = root.path().join("new");
    fs::write(&replacement, b"original").unwrap();
    fs::rename(replacement, &source).unwrap();
    assert!(pinned.read(&directory, "key").is_err());
    let pinned = PinnedTrustFile::open(&directory, "key", 64)
        .unwrap()
        .unwrap();
    fs::write(&source, b"modified").unwrap(); // Same length, not just a size check.
    File::open(&source)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH)
        .unwrap();
    assert!(pinned.read(&directory, "key").is_err());
}

#[test]
fn a_missing_policy_allows_no_key_and_a_policy_allows_only_what_it_lists() {
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("legacy.pem");
    fs::write(&key, b"legacy").unwrap();
    fs::create_dir(root.path().join(UPDATE_KEYRING_DIR)).unwrap();
    fs::write(
        root.path()
            .join(UPDATE_KEYRING_DIR)
            .join("hardened-system-prod-2026q3.pub.pem"),
        b"production",
    )
    .unwrap();
    // Without a policy nothing verifies: not the retired IDs, whose key file
    // is still installed, and not the production ID either.
    for id in [
        LEGACY_UPDATE_KEY_ID,
        LEGACY_TEST_UPDATE_KEY_ID,
        "hardened-system-prod-2026q3",
    ] {
        match SignatureInputs::capture(b"m", b"s", &key, id) {
            Err(AppError::Config(message)) => assert!(message.contains("policy is missing")),
            _ => panic!("{id} was not refused for the missing policy"),
        }
    }
    // The bridge policy of the key transition allowed the retired IDs.
    fs::write(
        root.path().join(UPDATE_KEY_POLICY_FILE),
        format!("{LEGACY_UPDATE_KEY_ID}\n{LEGACY_TEST_UPDATE_KEY_ID}\n"),
    )
    .unwrap();
    for id in [LEGACY_UPDATE_KEY_ID, LEGACY_TEST_UPDATE_KEY_ID] {
        SignatureInputs::capture(b"m", b"s", &key, id).unwrap();
    }
    // The policy since the retirement lists the production ID alone.
    fs::write(
        root.path().join(UPDATE_KEY_POLICY_FILE),
        b"hardened-system-prod-2026q3\n",
    )
    .unwrap();
    SignatureInputs::capture(b"m", b"s", &key, "hardened-system-prod-2026q3").unwrap();
    for id in [LEGACY_UPDATE_KEY_ID, LEGACY_TEST_UPDATE_KEY_ID] {
        match SignatureInputs::capture(b"m", b"s", &key, id) {
            Err(AppError::BadRequest(message)) => assert!(message.contains("not allowed")),
            _ => panic!("{id} passed the production-only policy"),
        }
    }
}

#[tokio::test]
async fn cancelled_command_keeps_exact_input_descriptors_until_direct_child_reap() {
    use nix::{errno::Errno, sys::wait::waitpid, unistd::Pid};
    use tokio::{sync::oneshot, time};
    struct Released(Option<oneshot::Sender<()>>);
    impl Drop for Released {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
    let fixture = SignedFixture::new();
    let inputs = fixture.capture();
    let pid_path = fixture.root.path().join("fixture-child-pid");
    let arguments = vec![
        "-c".to_owned(),
        "cat -- \"$1\" \"$2\" \"$3\" >/dev/null || exit 1; printf '%s' \"$$\" >\"$4\"; exec sleep 30".to_owned(),
        "fixture".to_owned(),
        proc_path(&inputs.key),
        proc_path(&inputs.metadata),
        proc_path(&inputs.signature),
        pid_path.to_str().unwrap().to_owned(),
    ];
    let (released, mut release) = oneshot::channel();
    let request = tokio::spawn(async move {
        // Explicit test command only; production verify() always maps OpenSsl.
        // Tuple order drops all input files BEFORE sending the cleanup receipt.
        run_allowed_owned(
            AllowedCommand::CustomForTest("/bin/sh".into()),
            arguments,
            LIMIT,
            (inputs, Released(Some(released))),
        )
        .await
    });
    let pid = time::timeout(LIMIT, async {
        loop {
            if let Ok(text) = fs::read_to_string(&pid_path)
                && let Ok(pid) = text.parse::<i32>()
            {
                break pid;
            }
            time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await;
    let released_early = !matches!(release.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    // Do not panic with a live fixture merely because its PID marker failed.
    // Cancel/join the outer task and give its owner a cleanup turn first. The
    // command itself also has a finite independent deadline.
    request.abort();
    let request = request.await;
    let cleaned_up = released_early || matches!(time::timeout(LIMIT, release).await, Ok(Ok(())));
    assert!(cleaned_up, "fixture command cleanup did not finish");
    assert!(!released_early, "inputs released before cancellation");
    let pid = pid.unwrap();
    assert!(request.unwrap_err().is_cancelled());
    assert_eq!(waitpid(Pid::from_raw(pid), None), Err(Errno::ECHILD));
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}
