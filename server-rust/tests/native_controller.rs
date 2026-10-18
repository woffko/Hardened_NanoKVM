#![cfg(feature = "sandbox-test-fixture")]

#[path = "../src/native_owner/controller.rs"]
mod controller;

use controller::{Drain, DrainStatus, Group, Role, StartError, Status};
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const LIMIT: Duration = Duration::from_secs(8);

fn command(kind: &str, mode: &str, root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nanokvm-native-owner-fixture"));
    command
        .args([kind, mode])
        .arg(root)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn until(mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(start.elapsed() < LIMIT, "controller fixture deadline");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn ready(group: &mut Group) {
    until(|| {
        group
            .poll()
            .iter()
            .flatten()
            .all(|s| matches!(s, Status::Running | Status::Closed(_)))
    });
}

fn drain(mut drain: Drain) -> Drain {
    until(|| drain.poll() == DrainStatus::Drained);
    drain
}

struct Pin(std::os::fd::OwnedFd);

impl Pin {
    fn read(root: &Path, name: &str) -> Self {
        let mut pid = None;
        until(|| {
            pid = fs::read_to_string(root.join(name))
                .ok()
                .and_then(|s| s.parse().ok())
                .and_then(rustix::process::Pid::from_raw);
            pid.is_some()
        });
        Self(
            rustix::process::pidfd_open(pid.unwrap(), rustix::process::PidfdFlags::empty())
                .unwrap(),
        )
    }

    fn exited(&self) -> bool {
        let mut fds = [rustix::event::PollFd::new(
            &self.0,
            rustix::event::PollFlags::IN,
        )];
        rustix::event::poll(
            &mut fds,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .unwrap()
            == 1
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        // Only pinned synthetic descendants, never a numeric PID/name lookup.
        let _ = rustix::process::pidfd_send_signal(&self.0, rustix::process::Signal::KILL);
    }
}

#[test]
fn sibling_trees_stop_together_and_cannot_restart_until_both_join() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut group = Group::default();
    group
        .start_command(Role::KvmSystem, command("scope", "tree", a.path()))
        .unwrap();
    group
        .start_command(Role::Hwmon, command("scope", "tree", b.path()))
        .unwrap();
    ready(&mut group);
    let leaf_a = Pin::read(a.path(), "leaf.pid");
    let leaf_b = Pin::read(b.path(), "leaf.pid");
    assert!(matches!(
        group.start_command(Role::Hwmon, command("scope", "hold", b.path())),
        Err(StartError::AlreadyOwned)
    ));
    let started = Instant::now();
    let paused = group.begin_drain();
    let mut paused = match paused.try_resume() {
        Ok(_) => panic!("admission reopened before closure"),
        Err(paused) => paused,
    };
    until(|| paused.poll() == DrainStatus::Drained);
    assert!(started.elapsed() >= Duration::from_millis(1800));
    assert!(leaf_a.exited() && leaf_b.exited());
    // Explicit resume returns the only launch capability, not an automatic respawn.
    let mut group = paused.try_resume().ok().unwrap();
    group
        .start_command(Role::Hwmon, command("scope", "hold", b.path()))
        .unwrap();
    ready(&mut group);
    drop(drain(group.begin_drain()));
}

#[test]
fn caller_deadline_retains_drain_and_owner_can_finish_later() {
    let root = tempfile::tempdir().unwrap();
    let mut group = Group::default();
    group
        .start_command(Role::KvmSystem, command("scope", "tree", root.path()))
        .unwrap();
    ready(&mut group);
    let leaf = Pin::read(root.path(), "leaf.pid");
    let mut paused = group.begin_drain();
    assert_eq!(paused.poll(), DrainStatus::Pending);
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(paused.poll(), DrainStatus::Pending);
    assert!(!leaf.exited());
    drop(drain(paused));
    assert!(leaf.exited());
}

#[test]
fn dropped_controller_requests_eof_cleanup_but_does_not_respawn() {
    let root = tempfile::tempdir().unwrap();
    let mut group = Group::default();
    group
        .start_command(Role::KvmSystem, command("scope", "tree", root.path()))
        .unwrap();
    ready(&mut group);
    let leaf = Pin::read(root.path(), "leaf.pid");
    let owner = Pin::read(root.path(), "owner.pid");
    drop(group.begin_drain());
    until(|| leaf.exited());
    until(|| owner.exited());
    // This test intentionally discarded the controller Child. Reap its pinned
    // direct fixture owner explicitly; this is not a native-tree closure proof.
    let raw = fs::read_to_string(root.path().join("owner.pid")).unwrap();
    let pid = rustix::process::Pid::from_raw(raw.parse().unwrap()).unwrap();
    rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty()).unwrap();
}

#[test]
fn receipt_without_owner_exit_is_not_drained() {
    let root = tempfile::tempdir().unwrap();
    let mut group = Group::default();
    group
        .start_command(
            Role::KvmSystem,
            command("wire", "receipt-before-exit", root.path()),
        )
        .unwrap();
    ready(&mut group);
    // Stub has sent D1, but is still alive, waiting for Stop.
    for _ in 0..3 {
        assert!(!matches!(group.poll()[0], Some(Status::Closed(_))));
    }
    drop(drain(group.begin_drain()));
}

#[test]
fn malformed_missing_truncated_duplicate_and_mismatched_receipts_stay_uncertain() {
    for mode in [
        "missing",
        "malformed",
        "truncated",
        "duplicate",
        "wrong-exit",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut group = Group::default();
        group
            .start_command(Role::KvmSystem, command("wire", mode, root.path()))
            .unwrap();
        until(|| group.poll()[0] == Some(Status::Uncertain));
        assert!(matches!(
            group.start_command(Role::Hwmon, command("scope", "hold", root.path())),
            Err(StartError::UncertainOwnership)
        ));
        let mut paused = group.begin_drain();
        assert_eq!(paused.poll(), DrainStatus::Uncertain);
        until(|| {
            paused.poll();
            paused.all_owner_processes_reaped()
        });
        assert!(paused.try_resume().is_err());
    }
}

#[test]
fn killed_owner_without_receipt_closes_sibling_admission_and_stops_sibling() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut group = Group::default();
    // A wire stub intentionally has no children: killing a real subreaper can
    // orphan native work, which this controller must never pretend to recover.
    group
        .start_command(Role::KvmSystem, command("wire", "killed", a.path()))
        .unwrap();
    group
        .start_command(Role::Hwmon, command("scope", "hold", b.path()))
        .unwrap();
    ready(&mut group);
    let owner = Pin::read(a.path(), "owner.pid");
    let sibling = Pin::read(b.path(), "leader.pid");
    rustix::process::pidfd_send_signal(&owner.0, rustix::process::Signal::KILL).unwrap();
    until(|| group.poll()[0] == Some(Status::Uncertain));
    until(|| {
        group.poll();
        sibling.exited()
    });
    let mut paused = group.begin_drain();
    assert_eq!(paused.poll(), DrainStatus::Uncertain);
    until(|| {
        paused.poll();
        paused.all_owner_processes_reaped()
    });
    assert!(paused.try_resume().is_err());
}

#[test]
fn spawn_failure_does_not_claim_a_scope_or_prevent_later_start() {
    let root = tempfile::tempdir().unwrap();
    let mut group = Group::default();
    match group.start_command(Role::KvmSystem, Command::new(root.path().join("absent"))) {
        Err(StartError::Spawn(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        _ => panic!("spawn error was hidden"),
    }
    group
        .start_command(Role::KvmSystem, command("scope", "hold", root.path()))
        .unwrap();
    ready(&mut group);
    drop(drain(group.begin_drain()));
}

#[test]
fn immediate_drain_can_close_before_the_owner_announces_readiness() {
    let root = tempfile::tempdir().unwrap();
    let mut group = Group::default();
    group
        .start_command(Role::KvmSystem, command("scope", "hold", root.path()))
        .unwrap();
    // Covers both legal schedules: Stop observed before child spawn (D0 only),
    // or R followed by Stop/D0. Neither is treated as a missing-ready failure.
    drop(drain(group.begin_drain()));
}

#[test]
fn production_start_has_no_arbitrary_command_selector() {
    // The fixed role entry remains compiled and type checked; never run it on
    // the host. All runtime fixtures above use the private parent-only seam.
    let _start: fn(&mut Group, Role) -> Result<(), StartError> = Group::start;
}
