#![cfg(feature = "sandbox-test-fixture")]

#[path = "../src/update/app_trial_wire.rs"]
pub mod app_trial_wire;

#[path = "../src/native_owner/controller.rs"]
mod controller;
#[path = "../src/native_owner/picoclaw_home.rs"]
pub mod picoclaw_home;

use controller::{Drain, DrainStatus, Group, Resume, Role, StartError, Status};
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
        Resume::Running(_) => panic!("admission reopened before closure"),
        Resume::Retained(paused) => paused,
    };
    until(|| paused.poll() == DrainStatus::Drained);
    assert!(started.elapsed() >= Duration::from_millis(1800));
    assert!(leaf_a.exited() && leaf_b.exited());
    // Explicit resume returns the only launch capability, not an automatic respawn.
    let Resume::Running(mut group) = paused.try_resume() else {
        panic!("drained group retained")
    };
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
fn backend_controller_drop_cannot_bypass_guarded_eof_with_implicit_stop() {
    let root = tempfile::tempdir().unwrap();
    let update = fs::File::create(root.path().join("update-lock")).unwrap();
    rustix::fs::flock(
        &update,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
    let mut group = Group::default();
    group
        .start_command(Role::Backend, command("scope-guarded", "tree", root.path()))
        .unwrap();
    ready(&mut group);
    let owner = Pin::read(root.path(), "owner.pid");
    let leader = Pin::read(root.path(), "leader.pid");
    let leaf = Pin::read(root.path(), "leaf.pid");
    drop(group);
    until(|| root.path().join("orphan-attempt").exists());
    assert!(!root.path().join("orphan-acquired").exists());
    assert!(!leader.exited() && !leaf.exited() && !owner.exited());
    drop(update);
    until(|| owner.exited());
    assert!(leader.exited() && leaf.exited());
    let raw = fs::read_to_string(root.path().join("owner.pid")).unwrap();
    rustix::process::waitpid(
        rustix::process::Pid::from_raw(raw.parse().unwrap()),
        rustix::process::WaitOptions::empty(),
    )
    .unwrap();
}

#[test]
fn backend_protocol_failure_closes_control_without_unauthorized_stop_byte() {
    let root = tempfile::tempdir().unwrap();
    let mut group = Group::default();
    group
        .start_command(
            Role::Backend,
            command("wire", "malformed-record", root.path()),
        )
        .unwrap();
    until(|| group.poll()[2] == Some(Status::Uncertain));
    until(|| root.path().join("received-control").exists());
    assert!(
        fs::read(root.path().join("received-control"))
            .unwrap()
            .is_empty()
    );
    let mut retained = group.begin_drain();
    until(|| {
        retained.poll();
        retained.all_owner_processes_reaped()
    });
    assert_eq!(retained.poll(), DrainStatus::Uncertain);
}

#[test]
fn native_maintenance_retains_backend_then_full_drain_stops_it() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut group = Group::default();
    group
        .start_command(Role::KvmSystem, command("scope", "hold", a.path()))
        .unwrap();
    group
        .start_command(Role::Backend, command("scope", "hold", b.path()))
        .unwrap();
    ready(&mut group);
    let backend = Pin::read(b.path(), "leader.pid");
    let mut paused = drain(group.begin_native_drain());
    assert_eq!(paused.backend_status(), Some(Status::Running));
    assert!(!backend.exited());
    let Resume::Running(mut group) = paused.try_resume() else {
        panic!("drained group retained")
    };
    group.stop_backend();
    drop(drain(group.begin_drain()));
    assert!(backend.exited());
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
        assert!(matches!(paused.try_resume(), Resume::Retained(_)));
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
    assert!(matches!(paused.try_resume(), Resume::Retained(_)));
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
    let trial = controller::backend_trial_command(&picoclaw_home::Home::default());
    assert_eq!(trial.get_program(), "/usr/libexec/nanokvm-native-owner");
    assert_eq!(
        trial.get_args().collect::<Vec<_>>(),
        ["--scope", "backend-trial"]
    );
    // The fixed role entry remains compiled and type checked; never run it on
    // the host. All runtime fixtures above use the private parent-only seam.
    let _start: fn(&mut Group, Role) -> Result<(), StartError> = Group::start;
}

#[test]
fn actual_trial_owner_waits_for_bound_ready_and_acknowledges_only_matching_commit() {
    use controller::trial_wire as wire;
    let root = tempfile::tempdir().unwrap();
    let update = fs::File::create(root.path().join("update-lock")).unwrap();
    rustix::fs::flock(
        &update,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
    let mut group = Group::default();
    let transaction = [0x31; 16];
    group
        .start_trial(
            command("scope-trial", "trial-delayed", root.path()),
            transaction,
        )
        .unwrap();
    until(|| fs::read(root.path().join("trial-begin")).is_ok_and(|b| b.len() == wire::BYTES));
    assert_eq!(
        wire::parse(
            &fs::read(root.path().join("trial-begin"))
                .unwrap()
                .try_into()
                .unwrap(),
            wire::Event::Begin
        )
        .unwrap(),
        transaction
    );
    assert_eq!(group.poll()[2], Some(Status::Starting));
    assert!(group.commit_trial(transaction).is_err());
    assert!(!root.path().join("trial-committed").exists());
    fs::write(root.path().join("release-ready"), b"ready").unwrap();
    until(|| group.poll()[2] == Some(Status::Running));
    assert!(group.commit_trial([8; 16]).is_err());
    assert!(!root.path().join("trial-committed").exists());
    until(|| group.commit_trial(transaction).unwrap());
    until(|| fs::read(root.path().join("trial-committed")).is_ok_and(|b| b.len() == wire::BYTES));
    assert_eq!(
        wire::parse(
            &fs::read(root.path().join("trial-committed"))
                .unwrap()
                .try_into()
                .unwrap(),
            wire::Event::Commit
        )
        .unwrap(),
        transaction
    );
    // Repeated observation does not send a duplicate Commit.
    assert!(group.commit_trial(transaction).unwrap());
    let _joined = drain(group.begin_drain());
    assert!(!root.path().join("orphan-acquired").exists());
}

#[test]
fn bad_ready_and_pre_ready_leader_death_require_explicit_join_under_held_update_lock() {
    for mode in [
        "trial-wrong",
        "trial-truncated",
        "trial-eof",
        "trial-orphan",
    ] {
        let root = tempfile::tempdir().unwrap();
        let update = fs::File::create(root.path().join("update-lock")).unwrap();
        rustix::fs::flock(
            &update,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
        let mut group = Group::default();
        let mut cmd = command("scope-trial", mode, root.path());
        cmd.stderr(Stdio::inherit());
        group.start_trial(cmd, [0x31; 16]).unwrap();
        until(|| {
            let status = group.poll()[2];
            assert!(
                !matches!(status, Some(Status::Uncertain | Status::Closed(_))),
                "{mode}: {status:?}"
            );
            status == Some(Status::TrialFailed)
        });
        assert!(group.commit_trial([0x31; 16]).is_err());
        assert!(!root.path().join("trial-committed").exists());
        let mut joined = group.begin_drain();
        until(|| joined.poll() == DrainStatus::Drained);
        assert!(joined.all_owner_processes_reaped());
        assert!(!root.path().join("orphan-acquired").exists());
    }
}
