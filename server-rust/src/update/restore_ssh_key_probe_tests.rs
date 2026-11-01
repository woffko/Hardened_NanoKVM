use super::*;
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    process::Command as StdCommand,
};
use tempfile::{TempDir, tempdir};

fn generate(kind: &str, bits: Option<&str>) -> (TempDir, File, Zeroizing<Vec<u8>>) {
    let directory = tempdir().unwrap();
    let path = directory.path().join("synthetic-key");
    let mut command = StdCommand::new("/usr/bin/ssh-keygen");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .args([
            "-q",
            "-t",
            kind,
            "-N",
            "",
            "-C",
            "synthetic test fixture",
            "-f",
        ])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(bits) = bits {
        command.args(["-b", bits]);
    }
    assert!(command.status().unwrap().success());
    let bytes = Zeroizing::new(fs::read(&path).unwrap());
    let public_path = directory.path().join("synthetic-key.pub");
    let public = Zeroizing::new(fs::read(&public_path).unwrap());
    fs::remove_file(path).unwrap();
    fs::remove_file(public_path).unwrap();
    let mut private = create_private_spool(directory.path()).unwrap();
    private.write_all(&bytes).unwrap();
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    (directory, private, public)
}

#[tokio::test]
async fn native_rsa_ecdsa_and_ed25519_keys_prove_possession_with_or_without_public_companion() {
    for (kind, bits, algorithm) in [
        ("rsa", Some("2048"), Algorithm::Rsa),
        ("ecdsa", Some("256"), Algorithm::Ecdsa),
        ("ed25519", None, Algorithm::Ed25519),
    ] {
        let (directory, private, public) = generate(kind, bits);
        check_pair(&private, Some(&public), algorithm, directory.path())
            .await
            .unwrap();
        check_pair(&private, None, algorithm, directory.path())
            .await
            .unwrap();
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}

#[tokio::test]
async fn mismatched_companion_wrong_algorithm_and_malformed_private_fail_redacted() {
    let (directory, private, _) = generate("ed25519", None);
    let (_, _, other_public) = generate("ed25519", None);
    assert!(matches!(
        check_pair(
            &private,
            Some(&other_public),
            Algorithm::Ed25519,
            directory.path()
        )
        .await,
        Err(SshRestoreError::InvalidKey)
    ));
    assert!(matches!(
        check_pair(&private, None, Algorithm::Rsa, directory.path()).await,
        Err(SshRestoreError::InvalidKey)
    ));
    let mut invalid = create_private_spool(directory.path()).unwrap();
    invalid.write_all(b"synthetic-secret-marker\n").unwrap();
    let error = check_pair(&invalid, None, Algorithm::Ed25519, directory.path())
        .await
        .err()
        .unwrap();
    assert!(!format!("{error:?} {error}").contains("synthetic-secret-marker"));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

fn string_range(bytes: &[u8], at: &mut usize) -> std::ops::Range<usize> {
    let length = u32::from_be_bytes(bytes[*at..*at + 4].try_into().unwrap()) as usize;
    *at += 4;
    let range = *at..*at + length;
    assert!(range.end <= bytes.len());
    *at = range.end;
    range
}

#[tokio::test]
async fn ed25519_stored_public_fields_can_pass_y_but_not_a_signature_challenge() {
    let (directory, mut private, public) = generate("ed25519", None);
    let mut pem = Zeroizing::new(Vec::new());
    private.seek(SeekFrom::Start(0)).unwrap();
    private.read_to_end(&mut pem).unwrap();
    let mut encoded = Zeroizing::new(Vec::with_capacity(pem.len()));
    for line in pem.split(|b| *b == b'\n') {
        if !line.starts_with(b"-----") {
            encoded.extend_from_slice(line);
        }
    }
    let mut blob = Zeroizing::new(STANDARD.decode(&*encoded).unwrap());
    let mut at = b"openssh-key-v1\0".len();
    for _ in 0..3 {
        string_range(&blob, &mut at);
    }
    assert_eq!(&blob[at..at + 4], &1_u32.to_be_bytes());
    at += 4;
    string_range(&blob, &mut at); // envelope public key remains unchanged
    let block = string_range(&blob, &mut at);
    at = block.start + 8; // equal checkints remain unchanged
    let kind = string_range(&blob, &mut at);
    assert_eq!(&blob[kind], b"ssh-ed25519");
    string_range(&blob, &mut at); // separate public field remains unchanged
    let secret = string_range(&blob, &mut at);
    assert_eq!(secret.len(), 64);
    blob[secret.start] ^= 1; // only change the seed, not either stored public field
    let encoded = Zeroizing::new(STANDARD.encode(&*blob));
    let mut changed = create_private_spool(directory.path()).unwrap();
    writeln!(
        changed,
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----",
        *encoded
    )
    .unwrap();
    let path = format!("/proc/{}/fd/{}", std::process::id(), changed.as_raw_fd());
    let output = keygen(&["-y", "-P", "", "-f", &path], &[]).await.unwrap();
    assert!(
        parse_public(&output, Algorithm::Ed25519).unwrap().blob
            == parse_public(&public, Algorithm::Ed25519).unwrap().blob
    );
    assert!(matches!(
        check_pair(
            &changed,
            Some(&public),
            Algorithm::Ed25519,
            directory.path()
        )
        .await,
        Err(SshRestoreError::InvalidKey)
    ));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn public_identity_parser_is_bounded_and_rejects_type_confusion_without_echoing_bytes() {
    for bytes in [
        &b""[..],
        &b"ssh-ed25519 invalid-base64 synthetic-marker"[..],
        &b"sk-ssh-ed25519@openssh.com AAAA"[..],
        &b"ssh-ed25519 AAAA\0"[..],
    ] {
        assert!(parse_public(bytes, Algorithm::Ed25519).is_err());
    }
    assert!(parse_public(&vec![b'x'; MAX_PUBLIC + 1], Algorithm::Ed25519).is_err());
    let blob = [0, 0, 0, 7, b's', b's', b'h', b'-', b'r', b's', b'a'];
    let wrong_type = format!("ssh-ed25519 {}", STANDARD.encode(blob));
    assert!(parse_public(wrong_type.as_bytes(), Algorithm::Ed25519).is_err());
}

#[test]
fn process_fixture() {
    let Ok(mode) = std::env::var("NANOKVM_KEY_PROBE_TEST_MODE") else {
        return;
    };
    let path = std::env::var_os("NANOKVM_KEY_PROBE_TEST_PID").unwrap();
    fs::write(path, std::process::id().to_string()).unwrap();
    match mode.as_str() {
        "flood" => {
            let mut output = std::io::stdout().lock();
            let _ = output.write_all(&vec![b'x'; MAX_PUBLIC * 4]);
        }
        "hang" => std::thread::sleep(Duration::from_secs(30)),
        _ => panic!("invalid synthetic process fixture"),
    }
}

fn fixture_command(mode: &str, pid_file: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env_clear()
        .env("NANOKVM_KEY_PROBE_TEST_MODE", mode)
        .env("NANOKVM_KEY_PROBE_TEST_PID", pid_file)
        .args([
            "--exact",
            "update::restore_ssh::key_probe::tests::process_fixture",
            "--nocapture",
        ]);
    command
}

fn assert_reaped(pid_file: &Path) {
    let pid = fs::read_to_string(pid_file).unwrap();
    assert!(
        !Path::new("/proc").join(pid).exists(),
        "probe child was not reaped"
    );
}

#[tokio::test]
async fn output_overflow_and_deadline_kill_and_reap_the_only_child() {
    let directory = tempdir().unwrap();
    for (mode, expected_timeout) in [("flood", false), ("hang", true)] {
        let pid_file = directory.path().join(mode);
        let error = run_child(
            fixture_command(mode, &pid_file),
            &[],
            Duration::from_millis(500),
        )
        .await
        .err()
        .unwrap();
        assert!(if expected_timeout {
            matches!(error, SshRestoreError::ProbeTimeout)
        } else {
            matches!(error, SshRestoreError::Limit)
        });
        assert_reaped(&pid_file);
    }
}

#[tokio::test]
async fn cancellation_does_not_detach_a_probe_reader_or_leave_the_child_running() {
    let directory = tempdir().unwrap();
    let pid_file = directory.path().join("cancel");
    let command = fixture_command("hang", &pid_file);
    let task = tokio::spawn(async move { run_child(command, &[], Duration::from_secs(5)).await });
    timeout(Duration::from_secs(3), async {
        while !pid_file.exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    timeout(Duration::from_secs(3), async {
        let pid = fs::read_to_string(&pid_file).unwrap();
        while Path::new("/proc").join(&pid).exists() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_reaped(&pid_file);
}

#[test]
fn only_the_type_name_openssh_gave_up_counts_as_retired() {
    use crate::update::restore_key::retired_public;
    let old = b"# comment\n\nssh-mldsa44-ed25519@openssh.com AAAA root@old\n";
    assert!(retired_public(old, Algorithm::Mldsa44Ed25519));
    for other in [Algorithm::Rsa, Algorithm::Ecdsa, Algorithm::Ed25519] {
        assert!(!retired_public(old, other));
    }
    for public in [
        &b"ssh-mldsa44-ed25519 AAAA root@new\n"[..],
        b"ssh-mldsa44-ed25519@openssh.community AAAA\n",
        b"# ssh-mldsa44-ed25519@openssh.com AAAA\n",
        b"",
    ] {
        assert!(!retired_public(public, Algorithm::Mldsa44Ed25519));
    }
}
