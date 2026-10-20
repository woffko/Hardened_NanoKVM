//! Disposable fixed-root process-death composition, not target power-loss proof.
use super::tests::{Fixture, Position};
use super::*;
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

const NATIVE: &str = "/etc/kvm/native-runtime-owner/state";
const INTENT: &str = "/etc/kvm/application-slot/recovery";

fn command(root: &Path, mode: &str) -> Command {
    let mut child = Command::new("/usr/bin/unshare");
    child
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::app_slot::recovery_tests::recovery_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_RECOVERY_ROOT", root)
        .env("NANOKVM_RECOVERY_MODE", mode);
    child
}

#[test]
fn recovery_child_fixture() {
    let Ok(root) = std::env::var("NANOKVM_RECOVERY_ROOT") else {
        return;
    };
    let mode = std::env::var("NANOKVM_RECOVERY_MODE").unwrap();
    let started = Instant::now();
    let trace = |phase: &str| {
        eprintln!(
            "recovery-child {:.6}s: {phase}",
            started.elapsed().as_secs_f64()
        );
    };
    trace("fixture-start");
    let proc = Path::new(&root).join("proc");
    fs::create_dir_all(&proc).unwrap();
    trace("proc-parent-ready");
    nix::mount::mount(
        Some("/proc"),
        proc.as_path(),
        None::<&str>,
        nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    trace("proc-bound");
    nix::unistd::chroot(Path::new(&root)).unwrap();
    std::env::set_current_dir("/").unwrap();
    trace("root-entered");
    if mode == "run" {
        trace("native-enrollment-begin");
        crate::native_owner::broker::app_recovery_closed_fixture(&File::open("/etc/kvm").unwrap());
        trace("native-enrollment-complete");
        drop(ProcessLock::acquire().unwrap());
        trace("update-admission-probed");
        drop(
            super::super::state_writers::StateWriters::default()
                .try_drain()
                .unwrap(),
        );
        trace("writer-admission-probed");
        // Process-local umask only, after fixture directory enrollment.
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o777));
        trace("recover-begin");
        recover().unwrap();
        trace("recover-returned-without-selected-stop");
        panic!("requested recovery checkpoint was not reached");
    }
    let before = fs::read(NATIVE).unwrap();
    let pending = fs::read(INTENT).unwrap();
    let current = fs::read("/etc/kvm/application-slot/current/state").ok();
    if before[44] == 4 {
        assert!(matches!(recover(), Err(SlotError::Busy)));
        assert!(matches!(boot_gate(), Err(SlotError::Busy)));
        assert_eq!(fs::read(NATIVE).unwrap(), before);
        assert_eq!(fs::read(INTENT).unwrap(), pending);
        assert_eq!(
            fs::read("/etc/kvm/application-slot/current/state").ok(),
            current
        );
        // This is a synthetic prior-epoch record, NOT a hardware reboot test.
        // The reader still obtains its current identity from real procfs.
        let mut prior = before;
        let other = if &prior[8..44] == b"12345678-1234-1234-1234-123456789abc" {
            b"87654321-4321-4321-4321-cba987654321"
        } else {
            b"12345678-1234-1234-1234-123456789abc"
        };
        prior[8..44].copy_from_slice(other);
        let hash = Sha256::digest(&prior[..48]);
        prior[48..].copy_from_slice(&hash);
        fs::write(NATIVE, prior).unwrap();
        File::open(NATIVE).unwrap().sync_all().unwrap();
    } else {
        assert_eq!(before[44], 2);
    }
    let expected = if mode == "committed" {
        Phase::Committed
    } else {
        Phase::RolledBack
    };
    assert_eq!(recover().unwrap(), Status::Transaction(expected));
    assert_eq!(status().unwrap(), Status::NoTransaction);
    assert!(!Path::new(INTENT).exists());
    let job = job_status([2; 16]).unwrap().unwrap();
    assert!(job.archived);
    assert_eq!(job.phase, expected);
    let native = fs::read(NATIVE).unwrap();
    let boot = fs::read("/proc/sys/kernel/random/boot_id").unwrap();
    assert_eq!(&native[8..44], &boot[..36]);
    assert_eq!(native[44], 2);
    assert_eq!(fs::metadata(NATIVE).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(boot_gate().unwrap(), Status::NoTransaction);
    drop(ProcessLock::acquire().unwrap());
    drop(
        super::super::state_writers::StateWriters::default()
            .try_drain()
            .unwrap(),
    );
    println!("fixed-root-recovery-completed");
}

#[test]
fn killed_recovery_resumes_exact_transaction_before_or_after_archival() {
    for committed in [false, true] {
        for point in [
            "recovery-intent-durable",
            "recovery-native-fenced",
            "recovery-slot-terminal",
            "retire-history-ready",
            "retire-terminal-synced",
            "retire-current-renamed",
            "retire-history-synced",
            "retire-parent-synced",
            "recovery-app-archived",
            "recovery-native-closed",
        ] {
            let fixture = Fixture::new(
                if committed {
                    Phase::Committed
                } else {
                    Phase::Published
                },
                Position::Published,
            );
            fs::create_dir_all(fixture.root.path().join("etc/kvm")).unwrap();
            fs::rename(
                fixture.root.path().join(DIRECTORY),
                fixture.root.path().join("etc/kvm/application-slot"),
            )
            .unwrap();
            let started = Instant::now();
            let mut child = command(fixture.root.path(), "run")
                .env("NANOKVM_APP_SLOT_TEST_STOP", point)
                .env("NANOKVM_APP_SLOT_TEST_TRACE", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();
            let errors = std::thread::spawn(move || {
                let mut kept = Vec::with_capacity(65536);
                let mut dropped = 0_usize;
                let mut last_read = None;
                let mut buffer = [0; 2048];
                loop {
                    let count = stderr.read(&mut buffer).unwrap();
                    if count == 0 {
                        break;
                    }
                    last_read = Some(started.elapsed());
                    let save = count.min(65536 - kept.len());
                    kept.extend_from_slice(&buffer[..save]);
                    dropped = dropped.saturating_add(count - save);
                }
                (kept, dropped, last_read)
            });
            let (send, receive) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                let mut last = None;
                for line in BufReader::new(stdout).lines() {
                    let line = line.unwrap();
                    let ready = line.contains("slot-checkpoint-ready");
                    last = Some(line.chars().take(512).collect::<String>());
                    if ready {
                        let _ = send.send(());
                        break;
                    }
                }
                last
            });
            let checkpoint = receive.recv_timeout(Duration::from_secs(15));
            let reached = checkpoint.is_ok();
            let wchan =
                (!reached).then(|| fs::read_to_string(format!("/proc/{}/wchan", child.id())));
            let process_state = (!reached).then(|| {
                fs::read_to_string(format!("/proc/{}/status", child.id())).map(|status| {
                    status
                        .lines()
                        .find(|line| line.starts_with("State:"))
                        .map(str::to_owned)
                })
            });
            let killed = child.kill();
            let output = child.wait_with_output().unwrap();
            let last_stdout = reader.join().unwrap();
            let (stderr, dropped, last_read) = errors.join().unwrap();
            assert!(
                reached,
                "{committed}/{point}: elapsed={:?}, checkpoint={checkpoint:?}, kill={killed:?}, \
                 last_stdout={last_stdout:?}, stderr_dropped={dropped}, stderr_last_at={last_read:?}, \
                 wchan={wchan:?}, process_state={process_state:?}, output={output:?}, stderr={}",
                started.elapsed(),
                String::from_utf8_lossy(&stderr)
            );
            assert_eq!(output.status.signal(), Some(9));
            let output = command(
                fixture.root.path(),
                if committed { "committed" } else { "rollback" },
            )
            .output()
            .unwrap();
            assert!(output.status.success(), "{committed}/{point}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("fixed-root-recovery-completed")
            );
            assert_eq!(
                fs::read(fixture.root.path().join("kvmapp/identity")).unwrap(),
                if committed { b"new" } else { b"old" }
            );
        }
    }
}
