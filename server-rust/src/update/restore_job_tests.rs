use super::*;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::MetadataExt, sync::Arc};

const POLICY: &str = "permitrootlogin yes\npasswordauthentication yes\npubkeyauthentication yes\nkbdinteractiveauthentication no\npermitemptypasswords no\nauthenticationmethods any\nmaxauthtries 6\nlogingracetime 120\nmaxsessions 10\nmaxstartups 10:30:100\n";

fn command(program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args).env_clear().stdin(Stdio::null());
    command
}

fn check_reaped(
    mut command: Command,
    cancel: &AtomicBool,
    deadline: Duration,
    effective: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(command);
    let pid = nix::unistd::Pid::from_raw(child.id() as i32);
    let result = collect(
        OwnedChild(child),
        cancel,
        Instant::now(),
        deadline,
        if effective {
            restore_effective::MAX_OUTPUT
        } else {
            0
        },
    );
    assert_eq!(
        nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
        Err(nix::errno::Errno::ECHILD)
    );
    result
}

#[test]
fn native_zero_and_eof_are_required_and_private_policy_parses() {
    let cancel = AtomicBool::new(false);
    let raw = check_reaped(
        command("/usr/bin/printf", &["%s", POLICY]),
        &cancel,
        Duration::from_secs(5),
        true,
    )
    .unwrap();
    let context =
        RootContext::parse("user=root,host=fixture,addr=192.0.2.1,laddr=192.0.2.2,lport=22")
            .unwrap();
    let policy = restore_effective::read_policy(&mut &raw[..], &context).unwrap();
    assert!(policy.summary().password_authentication);
    assert!(
        check_reaped(
            command("/usr/bin/true", &[]),
            &cancel,
            Duration::from_secs(5),
            false
        )
        .unwrap()
        .is_empty()
    );
    assert!(matches!(
        check_reaped(
            command("/usr/bin/false", &[]),
            &cancel,
            Duration::from_secs(5),
            true
        ),
        Err(JobError::Native)
    ));
    assert!(matches!(
        check_reaped(
            command("/usr/bin/printf", &["%s", POLICY]),
            &cancel,
            Duration::from_secs(5),
            false
        ),
        Err(JobError::Native)
    ));
    let empty = check_reaped(
        command("/usr/bin/true", &[]),
        &cancel,
        Duration::from_secs(5),
        true,
    )
    .unwrap();
    assert!(restore_effective::read_policy(&mut &empty[..], &context).is_err());
}

#[test]
fn timeout_cancellation_and_overflow_kill_and_reap_without_private_error_bytes() {
    let cancel = AtomicBool::new(false);
    let started = Instant::now();
    assert!(matches!(
        check_reaped(
            command("/usr/bin/sleep", &["60"]),
            &cancel,
            Duration::from_millis(80),
            true
        ),
        Err(JobError::Timeout)
    ));
    assert!(started.elapsed() < Duration::from_secs(5));
    let cancel = Arc::new(AtomicBool::new(false));
    let writer = Arc::clone(&cancel);
    let thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(80));
        writer.store(true, Ordering::SeqCst);
    });
    let result = check_reaped(
        command("/usr/bin/sleep", &["60"]),
        &cancel,
        Duration::from_secs(5),
        true,
    );
    thread.join().unwrap();
    assert!(matches!(result, Err(JobError::Cancelled)));
    let cancel = AtomicBool::new(false);
    let error = check_reaped(
        command("/usr/bin/head", &["-c", "65537", "/dev/zero"]),
        &cancel,
        Duration::from_secs(5),
        true,
    )
    .err()
    .unwrap();
    assert!(matches!(error, JobError::Native));
    assert!(!format!("{error:?} {error}").contains(POLICY));
    // Exactly the byte budget is accepted by transport (parser still rejects
    // nonsense); the next byte is not silently truncated to a valid result.
    assert_eq!(
        check_reaped(
            command("/usr/bin/head", &["-c", "65536", "/dev/zero"]),
            &cancel,
            Duration::from_secs(5),
            true
        )
        .unwrap()
        .len(),
        65536
    );
}

#[test]
fn pinned_proc_fd_exec_survives_source_replacement_and_parent_close() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    fs::copy("/usr/bin/true", &source).unwrap();
    let helper = PinnedSshHelper::host_fixture(&source, temporary.path());
    let metadata = helper.file.metadata().unwrap();
    assert_eq!(metadata.nlink(), 0);
    assert_eq!(metadata.mode() & 0o7777, 0o500);
    fs::write(&source, b"synthetic source replacement, not executable").unwrap();
    let mut command = helper.command().unwrap();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(command);
    drop(helper); // source inode and our fd can disappear after successful exec
    assert!(child.wait().unwrap().success());
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);
}

fn elf() -> Vec<u8> {
    let mut bytes = vec![0; 120];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&243_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes
}

#[test]
fn embedded_runtime_has_no_mutable_path_fallback() {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/ssh-runtime.binding"));
    let temporary = tempfile::tempdir().unwrap();
    if bytes.is_empty() {
        assert!(matches!(
            PinnedSshHelper::check_embedded(),
            Err(JobError::Helper)
        ));
        assert!(matches!(
            PinnedSshHelper::embedded(temporary.path()),
            Err(JobError::Helper)
        ));
    } else {
        let binding = crate::update::restore_binding::validate(bytes).unwrap();
        PinnedSshHelper::check_embedded().unwrap();
        let mut pinned = PinnedSshHelper::embedded(temporary.path()).unwrap();
        let mut copied = Vec::new();
        pinned.file.read_to_end(&mut copied).unwrap();
        assert_eq!(copied, binding.image);
        assert_eq!(pinned.file.metadata().unwrap().nlink(), 0);
    }
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
}

#[test]
fn helper_capture_enforces_exact_trusted_digest_size_static_rv64_and_readonly() {
    let temporary = tempfile::tempdir().unwrap();
    let valid = elf();
    let digest: [u8; 32] = Sha256::digest(&valid).into();
    let pinned = PinnedSshHelper::capture(
        &mut &valid[..],
        valid.len() as u64,
        &digest,
        temporary.path(),
    )
    .unwrap();
    assert_eq!(pinned.file.metadata().unwrap().nlink(), 0);
    assert_eq!(
        fcntl_getfl(&pinned.file).unwrap() & OFlags::ACCMODE,
        OFlags::RDONLY
    );
    assert!(
        rustix::io::fcntl_getfd(&pinned.file)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
    assert!(std::os::fd::AsRawFd::as_raw_fd(&pinned.file) > 2);
    let mut trailing = valid.clone();
    trailing.push(0x42);
    assert!(matches!(
        PinnedSshHelper::capture(
            &mut &trailing[..],
            valid.len() as u64,
            &digest,
            temporary.path()
        ),
        Err(JobError::Helper)
    ));
    for (offset, byte) in [
        (0, 0),
        (4, 1),
        (5, 2),
        (16, 3),
        (18, 62),
        (20, 2),
        (32, 255),
        (52, 63),
        (54, 55),
        (56, 0),
        (56, 129),
        (64, 2),
        (64, 3),
        (64, 4),
    ] {
        let mut invalid = valid.clone();
        invalid[offset] = byte;
        let hash = Sha256::digest(&invalid).into();
        assert!(
            matches!(
                PinnedSshHelper::capture(
                    &mut &invalid[..],
                    invalid.len() as u64,
                    &hash,
                    temporary.path()
                ),
                Err(JobError::Helper)
            ),
            "offset={offset}"
        );
    }
    assert!(
        PinnedSshHelper::capture(
            &mut &valid[..],
            valid.len() as u64,
            &[0; 32],
            temporary.path()
        )
        .is_err()
    );
    for size in [0, 63, 119, 121, 32 * 1024 * 1024 + 1] {
        assert!(
            PinnedSshHelper::capture(&mut &valid[..], size, &digest, temporary.path()).is_err()
        );
    }
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
}

#[test]
#[ignore = "requires the separately built retained static RV64 helper"]
fn actual_static_rv64_build_passes_immutable_capture_not_host_execution() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/restore-runtime/riscv64gc-unknown-linux-musl/release/nanokvm-ssh-sandbox");
    let bytes = fs::read(path).unwrap();
    let hash = Sha256::digest(&bytes).into();
    let temporary = tempfile::tempdir().unwrap();
    // Self-computed hash is fixture input, NOT authenticated release authority.
    let pinned =
        PinnedSshHelper::capture(&mut &bytes[..], bytes.len() as u64, &hash, temporary.path())
            .unwrap();
    assert_eq!(pinned.file.metadata().unwrap().nlink(), 0);
    assert_eq!(
        fcntl_getfl(&pinned.file).unwrap() & OFlags::ACCMODE,
        OFlags::RDONLY
    );
    assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 0);
}

#[test]
fn public_transfer_arguments_are_fixed_and_bounded() {
    let context = TransferContext::new([42; 16], "0.3.0-raw.fixture", [1025, 65537]).unwrap();
    let mut command = Command::new("never-executed");
    context.append_helper_arguments(&mut command);
    assert_eq!(
        command.get_args().collect::<Vec<_>>(),
        [
            "--transaction",
            "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
            "--version",
            "0.3.0-raw.fixture",
            "--boot-size",
            "1025",
            "--rootfs-size",
            "65537"
        ]
    );
}

#[test]
fn successful_exit_without_output_eof_is_not_accepted() {
    let (reader, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap();
    let mut command = command("/usr/bin/true", &[]);
    let mut child = command
        .stdout(Stdio::from(writer.try_clone().unwrap()))
        .spawn()
        .unwrap();
    drop(command);
    let pid = nix::unistd::Pid::from_raw(child.id() as i32);
    child.stdout = Some(std::process::ChildStdout::from(reader));
    let result = collect(
        OwnedChild(child),
        &AtomicBool::new(false),
        Instant::now(),
        Duration::from_millis(80),
        restore_effective::MAX_OUTPUT,
    );
    drop(writer); // deliberate extra writer: EOF never arrived during collection
    assert!(matches!(result, Err(JobError::Timeout)));
    assert_eq!(
        nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
        Err(nix::errno::Errno::ECHILD)
    );
}
