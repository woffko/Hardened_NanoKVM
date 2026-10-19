use super::*;
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const BOOT: &str = "12345678-1234-1234-1234-123456789abc";

fn acquire(root: &Path) -> Result<Broker, JournalError> {
    Ok(Broker {
        group: Group::default(),
        enrollment: boot::Permit::fixture(&File::open(root).unwrap()),
        update_parent: Some(File::open(root).unwrap()),
        journal: journal::Store::fixture(
            &File::open(root).unwrap(),
            nix::unistd::geteuid().as_raw(),
            BOOT,
        )?,
    })
}
fn start(broker: &mut Broker, root: &Path, mode: &str) -> Result<(), StartFailure> {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "native_owner::broker::tests::scope_probe",
            "--nocapture",
        ])
        .env_clear()
        .env("NANOKVM_NATIVE_BROKER_FIXTURE", root)
        .env("NANOKVM_NATIVE_BROKER_MODE", mode)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    broker.start_owned(Role::Hwmon, command)
}
fn until(mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn ready(broker: &mut Broker) {
    until(|| broker.poll()[1] == Some(Status::Running));
}
fn state(root: &Path) -> Vec<u8> {
    fs::read(root.join("native-runtime-owner/state")).unwrap()
}
fn collision(root: &Path) {
    let path = root.join("native-runtime-owner/.state.next");
    fs::write(&path, b"synthetic publication collision").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn boot_enrollment_is_retained_across_native_maintenance_resume_and_final_drain() {
    use rustix::fs::{FlockOperation, flock};
    let root = tempfile::tempdir().unwrap();
    let mut broker = acquire(root.path()).unwrap();
    let contender = File::open(root.path().join("native-runtime-boot")).unwrap();
    let blocked = || {
        assert_eq!(
            flock(&contender, FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        )
    };
    blocked();
    start(&mut broker, root.path(), "normal").unwrap();
    ready(&mut broker);
    let mut drain = broker.begin_maintenance();
    until(|| matches!(drain.poll(), Ok(DrainStatus::Drained)));
    blocked();
    let Resume::Running(broker) = drain.resume() else {
        panic!("proven drain must resume");
    };
    blocked();
    let mut drain = broker.begin_drain();
    until(|| matches!(drain.poll(), Ok(DrainStatus::Drained)));
    blocked();
    drop(drain);
    flock(&contender, FlockOperation::NonBlockingLockExclusive).unwrap();
    flock(&contender, FlockOperation::Unlock).unwrap();
}

#[test]
fn scope_probe() {
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_BROKER_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    assert_eq!(
        state(root)[44],
        1,
        "native work began before durable Active intent"
    );
    fs::write(root.join("owner.pid"), std::process::id().to_string()).unwrap();
    let mut control = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
    control
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    control.write_all(b"R").unwrap();
    let mut byte = [0];
    let _ = control.read(&mut byte);
    if std::env::var("NANOKVM_NATIVE_BROKER_MODE").unwrap() == "normal" {
        control.write_all(b"D\0").unwrap();
    }
}

#[test]
fn intent_precedes_launch_and_closed_receipt_precedes_explicit_resume() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = acquire(root.path()).unwrap();
    assert!(!broker.journal_is_from_previous_boot());
    start(&mut broker, root.path(), "normal").unwrap();
    ready(&mut broker);
    assert_eq!(state(root.path())[44], 1);
    assert!(matches!(acquire(root.path()), Err(JournalError::Busy)));
    let mut drain = broker.begin_drain();
    until(|| matches!(drain.poll(), Ok(DrainStatus::Drained)));
    assert_eq!(state(root.path())[44], 2);
    let Resume::Running(mut broker) = drain.resume() else {
        panic!("closed broker did not resume");
    };
    start(&mut broker, root.path(), "normal").unwrap();
    ready(&mut broker);
    assert_eq!(state(root.path())[44], 1);
    let mut drain = broker.begin_drain();
    until(|| matches!(drain.poll(), Ok(DrainStatus::Drained)));
    drop(drain);
    assert!(acquire(root.path()).is_ok());
}

#[test]
fn journal_failure_before_start_never_launches_native_work() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = acquire(root.path()).unwrap();
    collision(root.path());
    assert!(matches!(
        start(&mut broker, root.path(), "normal"),
        Err(StartFailure::Journal(JournalError::Ambiguous))
    ));
    assert!(!root.path().join("owner.pid").exists());
    assert!(!root.path().join("native-runtime-owner/state").exists());
    assert!(matches!(broker.begin_drain().resume(), Resume::Retained(_)));
}

#[test]
fn missing_receipt_keeps_durable_active_even_after_direct_owner_reap() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = acquire(root.path()).unwrap();
    start(&mut broker, root.path(), "missing").unwrap();
    ready(&mut broker);
    let mut drain = broker.begin_drain();
    until(|| matches!(drain.poll(), Ok(DrainStatus::Uncertain)));
    until(|| {
        let _ = drain.poll();
        drain.group.all_owner_processes_reaped()
    });
    assert_eq!(state(root.path())[44], 1);
    assert!(matches!(drain.resume(), Resume::Retained(_)));
    assert!(matches!(
        acquire(root.path()),
        Err(JournalError::Unresolved)
    ));
}

#[test]
fn failed_closed_publication_retains_owner_and_never_resumes() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = acquire(root.path()).unwrap();
    start(&mut broker, root.path(), "normal").unwrap();
    ready(&mut broker);
    collision(root.path());
    let mut drain = broker.begin_drain();
    until(|| matches!(drain.poll(), Err(JournalError::Ambiguous)));
    assert!(drain.group.all_owner_processes_reaped());
    assert_eq!(state(root.path())[44], 1);
    assert!(matches!(drain.resume(), Resume::Retained(_)));
    assert!(matches!(acquire(root.path()), Err(JournalError::Ambiguous)));
}

#[test]
fn controller_drop_and_eventual_owner_exit_do_not_clean_the_journal() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = acquire(root.path()).unwrap();
    start(&mut broker, root.path(), "normal").unwrap();
    ready(&mut broker);
    let raw: i32 = fs::read_to_string(root.path().join("owner.pid"))
        .unwrap()
        .parse()
        .unwrap();
    let pid = rustix::process::Pid::from_raw(raw).unwrap();
    // This is our still-unreaped fixture child, not an arbitrary PID nomination.
    let _pin = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
    drop(broker);
    until(|| {
        rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
            .unwrap()
            .is_some()
    });
    assert_eq!(state(root.path())[44], 1);
    assert!(matches!(
        acquire(root.path()),
        Err(JournalError::Unresolved)
    ));
}

#[test]
fn failed_spawn_retains_active_until_an_explicit_empty_drain_is_published() {
    for close in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut broker = acquire(root.path()).unwrap();
        let command = Command::new(root.path().join("missing-native-owner"));
        assert!(matches!(
            broker.start_owned(Role::Hwmon, command),
            Err(StartFailure::Scope(StartError::Spawn(_)))
        ));
        assert_eq!(state(root.path())[44], 1);
        if close {
            let mut drain = broker.begin_drain();
            assert!(matches!(drain.poll(), Ok(DrainStatus::Drained)));
            assert_eq!(state(root.path())[44], 2);
            drop(drain);
            assert!(acquire(root.path()).is_ok());
        } else {
            drop(broker);
            assert!(matches!(
                acquire(root.path()),
                Err(JournalError::Unresolved)
            ));
        }
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn protected_journal_and_real_subreaper_tree_share_one_retained_lifetime() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = acquire(root.path()).unwrap();
    // cargo test --all-targets builds this fixture for the integration tests.
    // Resolve beside the current test artifact, respecting CARGO_TARGET_DIR.
    let test = std::env::current_exe().unwrap();
    let fixture = test
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("nanokvm-native-owner-fixture");
    let mut command = Command::new(fixture);
    command
        .args(["scope", "tree"])
        .arg(root.path())
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    broker.start_owned(Role::KvmSystem, command).unwrap();
    until(|| broker.poll()[0] == Some(Status::Running));
    let mut raw = None;
    until(|| {
        raw = fs::read_to_string(root.path().join("leaf.pid"))
            .ok()
            .and_then(|text| text.parse::<i32>().ok());
        raw.is_some()
    });
    let raw = raw.unwrap();
    struct Leaf(std::os::fd::OwnedFd);
    impl Drop for Leaf {
        fn drop(&mut self) {
            let _ = rustix::process::pidfd_send_signal(&self.0, rustix::process::Signal::KILL);
        }
    }
    let leaf = Leaf(
        rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(raw).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap(),
    );
    let mut drain = broker.begin_drain();
    assert!(matches!(drain.poll(), Ok(DrainStatus::Pending)));
    assert_eq!(state(root.path())[44], 1);
    until(|| matches!(drain.poll(), Ok(DrainStatus::Drained)));
    let mut fds = [rustix::event::PollFd::new(
        &leaf.0,
        rustix::event::PollFlags::IN,
    )];
    assert_eq!(
        rustix::event::poll(
            &mut fds,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0
            })
        )
        .unwrap(),
        1
    );
    assert_eq!(state(root.path())[44], 2);
    drop(drain);
    assert!(acquire(root.path()).is_ok());
}
