use super::*;
use std::{
    cell::Cell,
    io::Cursor,
    os::unix::fs::{PermissionsExt, symlink},
};
use tempfile::tempdir;

fn seal(bytes: &[u8]) -> (RestoreSecret, Vec<u8>) {
    let mut ciphertext = Vec::new();
    let secret = prepare_capsule(
        "0.3.0-raw.13",
        bytes.len() as u64,
        &mut Cursor::new(bytes),
        &mut ciphertext,
    )
    .unwrap();
    (secret, ciphertext)
}

fn rejects_without_plaintext(secret: &RestoreSecret, bytes: &[u8]) {
    let root = tempdir().unwrap();
    assert!(open_capsule(secret, &mut Cursor::new(bytes), root.path()).is_err());
    assert_eq!(
        fs::read_dir(root.path()).unwrap().count(),
        0,
        "failed authentication retained a plaintext spool"
    );
}

#[test]
fn round_trip_handles_partial_and_exact_chunk_boundaries() {
    for length in [
        1,
        CHUNK_BYTES - 1,
        CHUNK_BYTES,
        CHUNK_BYTES + 1,
        CHUNK_BYTES * 2,
        CHUNK_BYTES * 3 + 17,
    ] {
        let bytes: Vec<_> = (0..length).map(|value| (value % 251) as u8).collect();
        let (secret, ciphertext) = seal(&bytes);
        let expected_size = HEADER_BYTES + length + length.div_ceil(CHUNK_BYTES) * TAG_BYTES;
        assert_eq!(ciphertext.len(), expected_size);
        let root = tempdir().unwrap();
        let mut verified =
            open_capsule(&secret, &mut Cursor::new(&ciphertext), root.path()).unwrap();
        let mut plaintext = Vec::new();
        verified.read_to_end(&mut plaintext).unwrap();
        assert_eq!(plaintext, bytes);
        verified.rewind().unwrap();
        assert_eq!(verified.read(&mut [0; 1]).unwrap(), 1);
        drop(verified);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn every_header_byte_is_bound_to_the_trusted_context_and_authentication() {
    let (secret, ciphertext) = seal(b"synthetic account configuration");
    for offset in 0..HEADER_BYTES {
        let mut corrupt = ciphertext.clone();
        corrupt[offset] ^= 1;
        rejects_without_plaintext(&secret, &corrupt);
    }
}

#[test]
fn corrupted_ciphertext_and_late_tags_never_return_partial_state() {
    let (secret, ciphertext) = seal(&vec![42; CHUNK_BYTES * 3 + 11]);
    for offset in [
        HEADER_BYTES,
        HEADER_BYTES + CHUNK_BYTES,
        HEADER_BYTES + (CHUNK_BYTES + TAG_BYTES) * 2,
        ciphertext.len() - 1,
    ] {
        let mut corrupt = ciphertext.clone();
        corrupt[offset] ^= 1;
        rejects_without_plaintext(&secret, &corrupt);
    }
}

#[test]
fn reordered_duplicate_and_missing_chunks_are_rejected() {
    let (secret, ciphertext) = seal(&vec![13; CHUNK_BYTES * 3]);
    let frame = CHUNK_BYTES + TAG_BYTES;
    let mut reordered = ciphertext.clone();
    reordered[HEADER_BYTES..HEADER_BYTES + frame]
        .copy_from_slice(&ciphertext[HEADER_BYTES + frame..HEADER_BYTES + frame * 2]);
    reordered[HEADER_BYTES + frame..HEADER_BYTES + frame * 2]
        .copy_from_slice(&ciphertext[HEADER_BYTES..HEADER_BYTES + frame]);
    rejects_without_plaintext(&secret, &reordered);
    let mut duplicated = ciphertext.clone();
    duplicated[HEADER_BYTES + frame..HEADER_BYTES + frame * 2]
        .copy_from_slice(&ciphertext[HEADER_BYTES..HEADER_BYTES + frame]);
    rejects_without_plaintext(&secret, &duplicated);
    let mut missing = ciphertext.clone();
    missing.drain(HEADER_BYTES..HEADER_BYTES + frame);
    rejects_without_plaintext(&secret, &missing);
}

#[test]
fn truncation_and_extra_data_are_rejected() {
    let (secret, ciphertext) = seal(&vec![7; CHUNK_BYTES + 20]);
    for length in [
        0,
        1,
        HEADER_BYTES - 1,
        HEADER_BYTES,
        HEADER_BYTES + CHUNK_BYTES + TAG_BYTES,
        ciphertext.len() - TAG_BYTES,
        ciphertext.len() - 1,
    ] {
        rejects_without_plaintext(&secret, &ciphertext[..length]);
    }
    let mut appended = ciphertext.clone();
    appended.push(0);
    rejects_without_plaintext(&secret, &appended);
    appended.extend_from_slice(&ciphertext);
    rejects_without_plaintext(&secret, &appended);
}

#[test]
fn wrong_key_is_rejected_without_exposing_it_in_errors() {
    let (mut secret, ciphertext) = seal(b"synthetic account state");
    secret.key[0] ^= 1;
    let root = tempdir().unwrap();
    let error = open_capsule(&secret, &mut Cursor::new(&ciphertext), root.path())
        .err()
        .unwrap();
    assert!(matches!(error, CapsuleError::Authentication));
    assert_eq!(error.to_string(), "restore capsule authentication failed");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn foreign_transaction_version_and_length_are_rejected() {
    let (mut secret, ciphertext) = seal(b"synthetic persistent state");
    secret.transaction_id[0] ^= 1;
    rejects_without_plaintext(&secret, &ciphertext);
    secret.transaction_id[0] ^= 1;
    secret.target_version = "0.3.0-raw.14".to_string();
    rejects_without_plaintext(&secret, &ciphertext);
    secret.target_version = "0.3.0-raw.13".to_string();
    secret.plaintext_len += 1;
    rejects_without_plaintext(&secret, &ciphertext);
}

#[test]
fn independently_prepared_capsules_have_distinct_transaction_and_nonce() {
    let bytes = b"same synthetic configuration";
    let (a, ciphertext_a) = seal(bytes);
    let (b, ciphertext_b) = seal(bytes);
    assert_ne!(a.transaction_id, b.transaction_id);
    assert_ne!(
        &ciphertext_a[HEADER_BYTES - NONCE_BYTES..HEADER_BYTES],
        &ciphertext_b[HEADER_BYTES - NONCE_BYTES..HEADER_BYTES]
    );
    assert_ne!(ciphertext_a, ciphertext_b);
    let mut splice = ciphertext_a.clone();
    splice[HEADER_BYTES..].copy_from_slice(&ciphertext_b[HEADER_BYTES..]);
    rejects_without_plaintext(&a, &splice);
}

#[test]
fn invalid_context_is_rejected_before_writing_any_output() {
    for (version, length) in [
        ("", 1),
        ("bad\nversion", 1),
        ("../other", 1),
        ("version", 0),
        ("version", MAX_PLAINTEXT_BYTES + 1),
        ("version", u64::MAX),
    ] {
        let mut out = Vec::new();
        assert!(matches!(
            prepare_capsule(version, length, &mut Cursor::new(b"state"), &mut out),
            Err(CapsuleError::InvalidContext)
        ));
        assert!(out.is_empty());
    }
    let mut out = Vec::new();
    assert!(
        prepare_capsule(
            &"v".repeat(VERSION_BYTES + 1),
            1,
            &mut Cursor::new(b"x"),
            &mut out
        )
        .is_err()
    );
    assert!(out.is_empty());
}

#[test]
fn input_length_mismatch_cannot_publish_a_restore_secret() {
    for length in [2, 4] {
        let mut out = Vec::new();
        assert!(
            prepare_capsule("0.3.0-raw.13", length, &mut Cursor::new(b"abc"), &mut out).is_err()
        );
    }
}

#[test]
fn private_spool_is_owner_only_and_removed_on_drop() {
    let (secret, ciphertext) = seal(b"synthetic identity state");
    let root = tempdir().unwrap();
    let verified = open_capsule(&secret, &mut Cursor::new(&ciphertext), root.path()).unwrap();
    let metadata = verified.file.metadata().unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
    assert_eq!(metadata.nlink(), 0);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    drop(verified);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn shared_or_symlinked_staging_is_rejected_without_touching_existing_files() {
    let (secret, ciphertext) = seal(b"synthetic state");
    let parent = tempdir().unwrap();
    let root = parent.path().join("private");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(root.join("sentinel"), b"preserve unrelated data").unwrap();
    assert!(matches!(
        open_capsule(&secret, &mut Cursor::new(&ciphertext), &root),
        Err(CapsuleError::InvalidStaging)
    ));
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = parent.path().join("alias");
    symlink(&root, &alias).unwrap();
    assert!(matches!(
        open_capsule(&secret, &mut Cursor::new(&ciphertext), &alias),
        Err(CapsuleError::InvalidStaging)
    ));
    assert_eq!(
        fs::read(root.join("sentinel")).unwrap(),
        b"preserve unrelated data"
    );
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
}

struct LimitedReader<'a> {
    data: Cursor<&'a [u8]>,
    maximum: &'a Cell<usize>,
}

impl Read for LimitedReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.maximum.set(self.maximum.get().max(bytes.len()));
        assert!(bytes.len() <= CHUNK_BYTES + TAG_BYTES);
        self.data.read(bytes)
    }
}

#[test]
fn multi_megabyte_state_uses_only_bounded_read_buffers() {
    let bytes = vec![29; 2 * 1024 * 1024 + 5];
    let maximum = Cell::new(0);
    let mut source = LimitedReader {
        data: Cursor::new(&bytes),
        maximum: &maximum,
    };
    let mut ciphertext = Vec::new();
    let secret = prepare_capsule(
        "0.3.0-raw.13",
        bytes.len() as u64,
        &mut source,
        &mut ciphertext,
    )
    .unwrap();
    assert_eq!(maximum.get(), CHUNK_BYTES);
    maximum.set(0);
    let mut source = LimitedReader {
        data: Cursor::new(&ciphertext),
        maximum: &maximum,
    };
    let root = tempdir().unwrap();
    let mut verified = open_capsule(&secret, &mut source, root.path()).unwrap();
    assert_eq!(maximum.get(), CHUNK_BYTES + TAG_BYTES);
    let mut output = Vec::new();
    verified.read_to_end(&mut output).unwrap();
    assert_eq!(output, bytes);
}

#[test]
fn encryption_does_not_leave_configuration_plaintext_in_capsule() {
    let fixture = b"SyntheticSecretConfigSentinel=not-a-real-credential-123456789";
    let (_secret, ciphertext) = seal(fixture);
    assert!(
        !ciphertext
            .windows(fixture.len())
            .any(|window| window == fixture)
    );
}

#[test]
fn frames_match_standard_be32_counter_and_final_flag_nonces() {
    use chacha20poly1305::{
        Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    let bytes = vec![53; CHUNK_BYTES + 9];
    let (secret, ciphertext) = seal(&bytes);
    let header = &ciphertext[..HEADER_BYTES];
    let cipher = ChaCha20Poly1305::new((&*secret.key).into());
    let mut nonce = [0; 12];
    nonce[..NONCE_BYTES].copy_from_slice(&header[HEADER_BYTES - NONCE_BYTES..]);
    let first = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &bytes[..CHUNK_BYTES],
                aad: header,
            },
        )
        .unwrap();
    assert_eq!(
        &ciphertext[HEADER_BYTES..HEADER_BYTES + CHUNK_BYTES + TAG_BYTES],
        first
    );
    nonce[7..11].copy_from_slice(&1_u32.to_be_bytes());
    nonce[11] = 1;
    let last = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &bytes[CHUNK_BYTES..],
                aad: header,
            },
        )
        .unwrap();
    assert_eq!(&ciphertext[HEADER_BYTES + CHUNK_BYTES + TAG_BYTES..], last);
}

#[test]
fn huge_untrusted_header_length_is_rejected_before_reading_body() {
    let (secret, mut ciphertext) = seal(b"state");
    ciphertext[24..32].copy_from_slice(&u64::MAX.to_be_bytes());
    let mut reader = Cursor::new(&ciphertext);
    let root = tempdir().unwrap();
    assert!(matches!(
        open_capsule(&secret, &mut reader, root.path()),
        Err(CapsuleError::HeaderMismatch)
    ));
    assert_eq!(reader.position(), HEADER_BYTES as u64);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("synthetic write failure"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn write_error_cannot_return_a_restore_secret() {
    assert!(matches!(
        prepare_capsule(
            "0.3.0-raw.13",
            3,
            &mut Cursor::new(b"abc"),
            &mut FailingWriter
        ),
        Err(CapsuleError::Io(_))
    ));
}

struct FlushFailWriter(Vec<u8>);

impl Write for FlushFailWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("synthetic flush failure"))
    }
}

#[test]
fn flush_error_cannot_return_a_restore_secret() {
    let mut output = FlushFailWriter(Vec::new());
    assert!(matches!(
        prepare_capsule("0.3.0-raw.13", 3, &mut Cursor::new(b"abc"), &mut output),
        Err(CapsuleError::Io(_))
    ));
    assert!(!output.0.is_empty());
}

struct ErrorReader<'a> {
    source: Cursor<&'a [u8]>,
    fail_at: usize,
}

impl Read for ErrorReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let position = self.source.position() as usize;
        if position >= self.fail_at {
            return Err(io::Error::other("synthetic input I/O failure"));
        }
        let len = bytes.len().min(self.fail_at - position);
        self.source.read(&mut bytes[..len])
    }
}

#[test]
fn input_io_errors_never_return_partial_plaintext() {
    let (secret, ciphertext) = seal(&vec![7; CHUNK_BYTES * 2 + 3]);
    for fail_at in [
        10,
        HEADER_BYTES,
        HEADER_BYTES + CHUNK_BYTES + TAG_BYTES,
        ciphertext.len(),
    ] {
        let root = tempdir().unwrap();
        let mut reader = ErrorReader {
            source: Cursor::new(&ciphertext),
            fail_at,
        };
        assert!(matches!(
            open_capsule(&secret, &mut reader, root.path()),
            Err(CapsuleError::Io(_))
        ));
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn crash_fixture_child() {
    let Some(root) = std::env::var_os("NANOKVM_CAPSULE_CRASH_FIXTURE_ROOT") else {
        return;
    };
    let (secret, ciphertext) = seal(b"synthetic state held only by an unlinked descriptor");
    let payload = open_capsule(&secret, &mut Cursor::new(ciphertext), Path::new(&root)).unwrap();
    println!("CAPSULE_FIXTURE_READY");
    io::stdout().flush().unwrap();
    // Parent normally kills this process immediately. Keep a finite safety
    // timeout for a failed parent, and retain descriptor ownership until then.
    std::thread::sleep(std::time::Duration::from_secs(20));
    drop(payload);
}

#[test]
fn process_termination_cannot_leave_named_plaintext_spools() {
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
        sync::mpsc,
        thread,
        time::Duration,
    };
    let root = tempdir().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::restore_capsule::tests::crash_fixture_child",
            "--nocapture",
        ])
        .env("NANOKVM_CAPSULE_CRASH_FIXTURE_ROOT", root.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        while stdout.read_line(&mut line).unwrap_or(0) > 0 {
            if line.trim() == "CAPSULE_FIXTURE_READY" {
                let _ = tx.send(());
                break;
            }
            line.clear();
        }
    });
    let ready = rx.recv_timeout(Duration::from_secs(5));
    let _ = child.kill();
    child.wait().unwrap();
    reader.join().unwrap();
    assert!(
        ready.is_ok(),
        "child did not reach the owned-spool checkpoint"
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}
