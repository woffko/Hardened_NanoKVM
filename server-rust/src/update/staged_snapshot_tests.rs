use super::*;
use std::{fs, io::Cursor};
use tempfile::tempdir;

fn capture(stage: &StageDirectory, bytes: &[u8]) -> PublicSnapshot {
    PublicSnapshot::capture(
        stage,
        &mut Cursor::new(bytes),
        bytes.len() as u64,
        &Sha256::digest(bytes).into(),
        &Sha512::digest(bytes).into(),
    )
    .unwrap()
}

#[test]
fn snapshot_has_no_name_and_is_kernel_readonly_not_merely_a_read_api() {
    let root = tempdir().unwrap();
    let stage = StageDirectory::prepare(&root.path().join("system")).unwrap();
    let data = b"public signed archive bytes";
    let mut snapshot = capture(&stage, data);
    assert_eq!(fs::read_dir(root.path().join("system")).unwrap().count(), 0);
    let metadata = snapshot.file.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.nlink(), 0);
    assert_eq!(metadata.len(), data.len() as u64);
    assert_eq!(
        fcntl_getfl(&snapshot.file).unwrap() & OFlags::ACCMODE,
        OFlags::RDONLY
    );
    let mut alias = snapshot.file.try_clone().unwrap();
    assert_eq!(
        alias.write_all(b"tamper").unwrap_err().raw_os_error(),
        Some(nix::libc::EBADF)
    );
    assert!(alias.set_len(0).is_err());
    let mut bytes = Vec::new();
    snapshot.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, data);
    snapshot.rewind().unwrap();
    bytes.clear();
    snapshot.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, data);
}

#[test]
fn changing_source_inode_contents_or_name_after_capture_cannot_change_snapshot() {
    let root = tempdir().unwrap();
    let stage_path = root.path().join("system");
    let stage = StageDirectory::prepare(&stage_path).unwrap();
    let path = stage_path.join("source.tar.gz");
    let bytes = b"original authenticated public bytes";
    fs::write(&path, bytes).unwrap();
    let mut source = File::open(&path).unwrap();
    let mut snapshot = PublicSnapshot::capture(
        &stage,
        &mut source,
        bytes.len() as u64,
        &Sha256::digest(bytes).into(),
        &Sha512::digest(bytes).into(),
    )
    .unwrap();
    fs::write(&path, b"same inode now maliciously overwritten").unwrap();
    fs::rename(&path, stage_path.join("replaced-source")).unwrap();
    fs::write(&path, b"another named replacement").unwrap();
    let mut actual = Vec::new();
    snapshot.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, bytes);
    assert_eq!(fs::read_dir(&stage_path).unwrap().count(), 2);
}

#[test]
fn both_digests_exact_length_and_budget_are_required_before_any_snapshot_is_returned() {
    let root = tempdir().unwrap();
    let stage_path = root.path().join("system");
    let stage = StageDirectory::prepare(&stage_path).unwrap();
    let bytes = b"public bytes";
    let valid256: [u8; 32] = Sha256::digest(bytes).into();
    let valid512: [u8; 64] = Sha512::digest(bytes).into();
    for (size, hash256, hash512, length_error) in [
        (0, valid256, valid512, true),
        (MAX_BYTES + 1, valid256, valid512, true),
        (bytes.len() as u64 - 1, valid256, valid512, true),
        (bytes.len() as u64 + 1, valid256, valid512, true),
        (bytes.len() as u64, [0; 32], valid512, false),
        (bytes.len() as u64, valid256, [0; 64], false),
    ] {
        let error =
            PublicSnapshot::capture(&stage, &mut Cursor::new(bytes), size, &hash256, &hash512)
                .err()
                .unwrap();
        assert!(if length_error {
            matches!(error, SnapshotError::Length)
        } else {
            matches!(error, SnapshotError::Digest)
        });
        assert_eq!(fs::read_dir(&stage_path).unwrap().count(), 0);
    }
}

#[test]
fn public_snapshot_stream_handles_boundaries_with_a_fixed_read_buffer() {
    struct ShortReader<'a> {
        bytes: &'a [u8],
        largest_request: usize,
    }
    impl Read for ShortReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.largest_request = self.largest_request.max(out.len());
            let count = out.len().min(self.bytes.len()).min(977);
            out[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }
    let root = tempdir().unwrap();
    let stage = StageDirectory::prepare(&root.path().join("system")).unwrap();
    for size in [1, 65535, 65536, 65537, 3 * 1024 * 1024 + 17] {
        let data: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
        let mut source = ShortReader {
            bytes: &data,
            largest_request: 0,
        };
        let mut snapshot = PublicSnapshot::capture(
            &stage,
            &mut source,
            size as u64,
            &Sha256::digest(&data).into(),
            &Sha512::digest(&data).into(),
        )
        .unwrap();
        assert!(source.largest_request <= 64 * 1024);
        let mut actual = Vec::new();
        snapshot.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, data);
    }
}

#[test]
fn interrupted_source_copy_never_leaves_a_named_partial_or_usable_snapshot() {
    struct FailAfter {
        remaining: usize,
    }
    impl Read for FailAfter {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::other("synthetic I/O failure"));
            }
            let count = self.remaining.min(out.len());
            out[..count].fill(b'x');
            self.remaining -= count;
            Ok(count)
        }
    }
    let root = tempdir().unwrap();
    let stage_path = root.path().join("system");
    let stage = StageDirectory::prepare(&stage_path).unwrap();
    fs::write(stage_path.join("keep"), b"recovery evidence").unwrap();
    for remaining in [0, 1, 65537] {
        let error = PublicSnapshot::capture(
            &stage,
            &mut FailAfter { remaining },
            128 * 1024,
            &[0; 32],
            &[0; 64],
        )
        .err()
        .unwrap();
        assert!(matches!(error, SnapshotError::Io(_)));
        assert_eq!(fs::read_dir(&stage_path).unwrap().count(), 1);
        assert_eq!(
            fs::read(stage_path.join("keep")).unwrap(),
            b"recovery evidence"
        );
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn snapshot_enospc_child_fixture() {
    let Some(path) = std::env::var_os("NANOKVM_SNAPSHOT_ENOSPC_FIXTURE") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    use nix::mount::{MsFlags, mount};
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .unwrap();
    mount(
        None::<&str>,
        &path,
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("size=4096,mode=0700"),
    )
    .unwrap();
    let stage = StageDirectory::open(&path).unwrap();
    let bytes = vec![b'x'; 128 * 1024];
    let error = PublicSnapshot::capture(
        &stage,
        &mut Cursor::new(&bytes),
        bytes.len() as u64,
        &Sha256::digest(&bytes).into(),
        &Sha512::digest(&bytes).into(),
    )
    .err()
    .unwrap();
    assert!(
        matches!(error, SnapshotError::Io(ref error) if error.raw_os_error() == Some(nix::libc::ENOSPC))
    );
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn actual_private_namespace_enospc_returns_no_snapshot_or_named_partial() {
    // Only a disposable user+mount namespace gets mount capability. This is
    // real host ENOSPC on a 4-KiB tmpfs, not actual exFAT/vendor-kernel evidence.
    let root = tempdir().unwrap();
    let path = root.path().join("disposable-mount");
    fs::create_dir(&path).unwrap();
    let output = std::process::Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::staged_snapshot::tests::snapshot_enospc_child_fixture",
            "--nocapture",
        ])
        .env_clear()
        .env("NANOKVM_SNAPSHOT_ENOSPC_FIXTURE", &path)
        .output()
        .unwrap();
    assert!(output.status.success(), "disposable ENOSPC fixture failed");
    // No mount or partial data remains in the parent's namespace.
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
}
