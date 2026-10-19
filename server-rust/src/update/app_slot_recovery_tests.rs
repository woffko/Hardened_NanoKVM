//! Disposable fixed-root process-death composition, not target power-loss proof.
use super::tests::{Fixture, Position};
use super::*;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::process::ExitStatusExt,
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
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
    let proc = Path::new(&root).join("proc");
    fs::create_dir_all(&proc).unwrap();
    nix::mount::mount(
        Some("/proc"),
        proc.as_path(),
        None::<&str>,
        nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    nix::unistd::chroot(Path::new(&root)).unwrap();
    std::env::set_current_dir("/").unwrap();
    if mode == "run" {
        crate::native_owner::broker::app_recovery_closed_fixture(&File::open("/etc/kvm").unwrap());
        drop(ProcessLock::acquire().unwrap());
        drop(
            super::super::state_writers::StateWriters::default()
                .try_drain()
                .unwrap(),
        );
        // Process-local umask only, after fixture directory enrollment.
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o777));
        recover().unwrap();
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
            let mut child = command(fixture.root.path(), "run")
                .env("NANOKVM_APP_SLOT_TEST_STOP", point)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (send, receive) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    if line.unwrap().contains("slot-checkpoint-ready") {
                        let _ = send.send(());
                        break;
                    }
                }
            });
            let reached = receive.recv_timeout(Duration::from_secs(15)).is_ok();
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            reader.join().unwrap();
            assert!(reached, "{committed}/{point}: {output:?}");
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
