use super::*;
use crate::{
    native_owner::controller::{DrainStatus, Group, Role, Status as ScopeStatus},
    update::app_slot::{
        Phase,
        issuer_tests::{accepted_fixture, assert_admission_released, assert_excluded as excluded},
    },
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn broker(root: &Path) -> Broker {
    Broker {
        group: Group::default(),
        enrollment: super::super::boot::Permit::fixture(&File::open(root).unwrap()),
        update_parent: Some(File::open(root).unwrap()),
        journal: journal::Store::fixture(
            &File::open(root).unwrap(),
            nix::unistd::geteuid().as_raw(),
            "12345678-1234-1234-1234-123456789abc",
        )
        .unwrap(),
    }
}

#[track_caller]
fn until(mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "app native closure deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn native_phase(root: &Path) -> u8 {
    fs::read(root.join("native-runtime-owner/state")).unwrap()[44]
}

fn released<T>(release: Release<T>) -> Broker {
    match release {
        Release::Released(broker) => *broker,
        Release::Retained(_) => panic!("terminal retirement failed"),
    }
}

fn start_roles(broker: &mut Broker, root: &Path, missing: bool) {
    for (role, name) in [
        (Role::KvmSystem, "kvm"),
        (Role::Hwmon, "hwmon"),
        (Role::Backend, "backend"),
        (Role::Picoclaw, "picoclaw"),
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "native_owner::broker::app_install::tests::scope_probe",
                "--nocapture",
            ])
            .env_clear()
            .env("NANOKVM_APP_NATIVE_ROOT", root)
            .env("NANOKVM_APP_NATIVE_ROLE", name)
            .env(
                "NANOKVM_APP_NATIVE_RECEIPT",
                if missing && role == Role::Hwmon {
                    "missing"
                } else {
                    "complete"
                },
            )
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if role == Role::Backend {
            let admission = broker.runtime_permit().unwrap();
            broker.start_backend(command, &admission).unwrap();
        } else if role == Role::Picoclaw {
            let admission = broker.runtime_permit().unwrap();
            // This scope fixture has no credential files. Root pair provenance
            // is tested separately; use an explicit synthetic generation while
            // retaining the same Update/Config launch admission as production.
            broker
                .start_picoclaw(
                    command,
                    &admission,
                    crate::update::picoclaw_config::Generation::fixture([0x31; 32]),
                )
                .unwrap();
        } else {
            broker.start_owned(role, command).unwrap();
        }
    }
    until(|| broker.group.poll() == [Some(ScopeStatus::Running); 4]);
}

#[test]
fn running_probes_survive_normal_idle_until_admitted_shutdown() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    start_roles(&mut broker, root.path(), false);
    // A native service must remain Running while an update is prepared, not
    // expire from the fixture's former 15-second pre-Stop read timeout.
    std::thread::sleep(Duration::from_secs(16));
    assert_eq!(broker.group.poll(), [Some(ScopeStatus::Running); 4]);
    let admission = broker.runtime_permit().unwrap();
    let super::super::Shutdown::Draining(mut drain) = broker.shutdown(admission) else {
        panic!("idle runtime shutdown refused")
    };
    until(|| drain.poll().unwrap() == DrainStatus::Drained);
    assert!(drain.group.all_owner_processes_reaped());
}

#[test]
fn running_probe_controller_eof_exits_without_a_stop_or_closure_receipt() {
    use std::{net::Shutdown, os::fd::OwnedFd, process::Child};

    // This direct child is a protocol-only probe with no descendants. Failure
    // cleanup is not a receipt and never supplies native recovery authority.
    struct Probe {
        child: Child,
        reaped: bool,
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    broker.journal.begin().unwrap();
    let (mut control, peer) = UnixStream::pair().unwrap();
    control
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let mut probe = Probe {
        child: Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_owner::broker::app_install::tests::scope_probe",
                "--nocapture",
            ])
            .env_clear()
            .env("NANOKVM_APP_NATIVE_ROOT", root.path())
            .env("NANOKVM_APP_NATIVE_ROLE", "backend")
            .env("NANOKVM_APP_NATIVE_RECEIPT", "complete")
            .stdin(Stdio::from(OwnedFd::from(peer)))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
        reaped: false,
    };
    let mut ready = [0];
    control.read_exact(&mut ready).unwrap();
    assert_eq!(ready, *b"R");
    control.shutdown(Shutdown::Write).unwrap();
    let mut exit = None;
    until(|| {
        exit = probe.child.try_wait().unwrap();
        exit.is_some()
    });
    probe.reaped = true;
    assert!(exit.unwrap().success());
    assert_eq!(
        control.read(&mut ready).unwrap(),
        0,
        "EOF is not a D receipt"
    );
    assert!(root.path().join("backend-controller-lost").exists());
    assert!(!root.path().join("backend-stopping").exists());
    assert_eq!(native_phase(root.path()), 1, "EOF cannot close the journal");
}

#[test]
fn scope_probe() {
    let Some(root) = std::env::var_os("NANOKVM_APP_NATIVE_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let role = std::env::var("NANOKVM_APP_NATIVE_ROLE").unwrap();
    assert_eq!(native_phase(root), 1);
    let mut control = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
    control
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    control.write_all(b"R").unwrap();
    let mut stop = [0];
    // The controller has not admitted Stop while its candidate is prepared.
    // A read timeout is idle Running, not service death. Keep the per-read
    // bound; the parent's unchanged 8-second deadline governs admitted drain.
    loop {
        match control.read(&mut stop) {
            Ok(0) => {
                // This protocol-only probe has no descendants. EOF ends it,
                // but supplies neither D nor durable native closure evidence.
                fs::write(root.join(format!("{role}-controller-lost")), b"lost").unwrap();
                return;
            }
            Ok(_) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(error) => panic!("native probe control failed: {error}"),
        }
    }
    assert_eq!(stop, *b"S");
    assert_eq!(
        native_phase(root),
        4,
        "Stop preceded durable update-admitted intent"
    );
    fs::write(root.join(format!("{role}-stopping")), b"stopping").unwrap();
    if role == "backend" {
        until(|| !root.join("hold-backend").exists());
    }
    if std::env::var("NANOKVM_APP_NATIVE_RECEIPT").unwrap() == "complete" {
        control.write_all(b"D\0").unwrap();
    }
}

fn trial_command(root: &Path, mode: &str) -> Command {
    let role = "backend";
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "native_owner::broker::app_install::tests::trial_scope_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_APP_NATIVE_ROOT", root)
        .env("NANOKVM_APP_NATIVE_ROLE", role)
        .env("NANOKVM_APP_TRIAL_MODE", mode)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
}

#[test]
fn trial_scope_probe() {
    use crate::update::app_trial::wire;
    let Some(root) = std::env::var_os("NANOKVM_APP_NATIVE_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let role = std::env::var("NANOKVM_APP_NATIVE_ROLE").unwrap();
    let mode = std::env::var("NANOKVM_APP_TRIAL_MODE").unwrap();
    let mut control = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
    control
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    assert_eq!(
        native_phase(root),
        4,
        "native admission reopened before trial"
    );
    assert_eq!(
        fs::read(root.join("application-slot/current/state")).unwrap()[8],
        Phase::Published as u8
    );
    let mut transaction = [0; 16];
    if role == "backend" {
        let mut begin = [0; wire::BYTES];
        control.read_exact(&mut begin).unwrap();
        transaction = wire::parse(&begin, wire::Event::Begin).unwrap();
        assert_eq!(
            transaction,
            fs::read(root.join("application-slot/current/state")).unwrap()[16..32]
        );
        fs::write(root.join("trial-owner-started"), b"started").unwrap();
        if mode == "resume-failure" {
            fs::write(root.join("trial-owner-pid"), std::process::id().to_string()).unwrap();
        }
        until(|| !root.join("hold-trial-ready").exists());
    }
    let failed = role == "backend" && mode == "failed-ready";
    control.write_all(if failed { b"F" } else { b"R" }).unwrap();
    let mut first = [0];
    if mode == "resume-failure" {
        // This child is only a protocol probe with no descendants. The test
        // deliberately loses its controller after checking retained authority;
        // EOF is cleanup here, never a native closure receipt.
        assert_eq!(
            control.read_exact(&mut first).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        fs::write(root.join("trial-controller-lost"), b"lost without commit").unwrap();
        return;
    }
    control.read_exact(&mut first).unwrap();
    if role == "backend" && first != *b"S" {
        assert!(!failed);
        let mut commit = [0; wire::BYTES];
        commit[0] = first[0];
        control.read_exact(&mut commit[1..]).unwrap();
        assert_eq!(
            wire::parse(&commit, wire::Event::Commit).unwrap(),
            transaction
        );
        assert_eq!(
            fs::read(root.join("application-slot/current/state")).unwrap()[8],
            Phase::Committed as u8
        );
        assert_eq!(
            native_phase(root),
            1,
            "backend serving precedes durable native resume"
        );
        fs::write(root.join("trial-authorized"), b"authorized").unwrap();
        if mode != "no-ack" {
            control.write_all(b"K").unwrap();
        }
        control.read_exact(&mut first).unwrap();
    }
    assert_eq!(first, *b"S");
    assert_eq!(
        native_phase(root),
        4,
        "Stop preceded durable stopping fence"
    );
    if mode == "missing-receipt" && role == "backend" {
        return;
    }
    control
        .write_all(if failed { b"D\x03" } else { b"D\0" })
        .unwrap();
    if failed {
        std::process::exit(72);
    }
}

fn stage_support(session: &mut Session) {
    let mut prepared = session.prepare_support().unwrap();
    prepared.check().unwrap();
    prepared.exchange().unwrap();
}

async fn published(root: &Path, running: bool) -> Session {
    let mut broker = broker(root);
    if running {
        start_roles(&mut broker, root, false);
    }
    let install = accepted_fixture(root).await;
    crate::update::app_slot::support::populate_retained_fixture(&install);
    let Start::Draining(mut session) = broker.begin_app_install(install) else {
        panic!("drain refused")
    };
    until(|| matches!(session.poll(), Ok(DrainStatus::Drained)));
    stage_support(&mut session);
    // Trial is impossible in Prepared, despite the exact accepted lease.
    let BeginTrial::Retained(retained) = session.start_trial_command(trial_command(root, "valid"))
    else {
        panic!("trial before publication")
    };
    session = retained;
    assert_eq!(
        session.publish().unwrap(),
        Status::Transaction(Phase::Published)
    );
    session
}

fn support_live(root: &Path) -> [(u64, u64, Vec<u8>); 9] {
    [
        "usr/libexec/nanokvm-app-recovery",
        "usr/libexec/nanokvm-native-owner",
        "usr/libexec/nanokvm-native-broker",
        "usr/libexec/nanokvm-native-ctl",
        "usr/libexec/nanokvm-native-recovery",
        "etc/init.d/S02apprecover",
        "etc/init.d/S30eth",
        "etc/init.d/S30wifi",
        "etc/init.d/S95nanokvm",
    ]
    .map(|name| {
        let path = root.join(name);
        let metadata = path.metadata().unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o755);
        (metadata.dev(), metadata.ino(), fs::read(path).unwrap())
    })
}

fn support_evidence(root: &Path) -> Vec<(std::ffi::OsString, u64, Vec<u8>)> {
    let mut entries = Vec::with_capacity(11);
    for entry in fs::read_dir(root.join("etc/kvm/application-support")).unwrap() {
        let entry = entry.unwrap();
        entries.push((
            entry.file_name(),
            entry.metadata().unwrap().ino(),
            fs::read(entry.path()).unwrap(),
        ));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

fn release_support_terminal<T>(root: &Path, owner: T, release: impl Fn(T) -> Release<T>) -> Broker {
    assert_eq!(support_evidence(root).len(), 10);
    let foreign = root.join("etc/kvm/application-support/foreign");
    fs::write(&foreign, b"unknown terminal evidence must be retained").unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
    let evidence = support_evidence(root);
    let live = support_live(root);
    let state = fs::read(root.join("application-slot/current/state")).unwrap();
    let Release::Retained(owner) = release(owner) else {
        panic!("unknown support evidence released terminal ownership")
    };
    excluded(root);
    assert_eq!(support_evidence(root), evidence);
    assert_eq!(support_live(root), live);
    assert_eq!(
        fs::read(root.join("application-slot/current/state")).unwrap(),
        state
    );
    assert!(!root.join("application-slot/history").exists());
    // Remove only this test's known foreign file, never unknown runtime data.
    fs::remove_file(foreign).unwrap();
    released(release(owner))
}

#[tokio::test]
async fn real_drained_session_composes_support_exchange_trial_and_terminal_settlement() {
    for mode in [
        "valid",
        "failed-ready",
        "prepared-abort",
        "no-ack",
        "missing-receipt",
    ] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut broker = broker(root);
        start_roles(&mut broker, root, false);
        let install = crate::update::app_slot::support::accepted_fixture(root).await;
        let transaction = install.transaction();
        let old = support_live(root);
        fs::write(root.join("hold-backend"), b"hold").unwrap();
        let Start::Draining(mut session) = broker.begin_app_install(install) else {
            panic!("support install drain refused")
        };
        until(|| root.join("backend-stopping").exists());
        assert!(matches!(session.prepare_support(), Err(SlotError::Busy)));
        assert!(!root.join("etc/kvm/application-support").exists());
        assert_eq!(support_live(root), old);
        excluded(root);
        fs::remove_file(root.join("hold-backend")).unwrap();
        until(|| session.poll().unwrap() == DrainStatus::Drained);
        assert_eq!(native_phase(root), 4);
        let mut prepared = session.prepare_support().unwrap();
        prepared.check().unwrap();
        assert_eq!(support_live(root), old);
        assert_eq!(support_evidence(root).len(), 10);
        excluded(root);
        prepared.exchange().unwrap();
        prepared.check_exchanged().unwrap();
        let new = support_live(root);
        for (old, new) in old.iter().zip(&new) {
            assert_eq!(old.0, new.0);
            assert_ne!(old.1, new.1);
            assert_ne!(old.2, new.2);
        }
        excluded(root);
        drop(prepared);
        let broker = if mode == "prepared-abort" {
            let Rollback::Restored(restored) = session.rollback() else {
                panic!("drained support preparation could not abort")
            };
            assert_eq!(support_live(root), old);
            release_support_terminal(root, restored, RolledBack::release)
        } else {
            let foreign = root.join("etc/kvm/application-support/foreign");
            fs::write(&foreign, b"unknown before app publication").unwrap();
            fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
            let evidence = support_evidence(root);
            assert!(matches!(session.publish(), Err(SlotError::Invalid)));
            assert_eq!(support_evidence(root), evidence);
            assert_eq!(support_live(root), new);
            assert_eq!(
                fs::read(root.join("kvmapp/identity")).unwrap(),
                b"old unchanged"
            );
            excluded(root);
            fs::remove_file(foreign).unwrap();
            assert_eq!(
                session.publish().unwrap(),
                Status::Transaction(Phase::Published)
            );
            fs::write(root.join("hold-trial-ready"), b"hold").unwrap();
            let BeginTrial::Started(mut trial) =
                session.start_trial_command(trial_command(root, mode))
            else {
                panic!("support-backed trial refused")
            };
            until(|| root.join("trial-owner-started").exists());
            assert_eq!(trial.poll(), TrialStatus::Starting);
            assert_eq!(support_live(root), new);
            excluded(root);
            fs::remove_file(root.join("hold-trial-ready")).unwrap();
            if matches!(mode, "no-ack" | "missing-receipt") {
                until(|| trial.poll() == TrialStatus::Ready);
                let trial = if mode == "no-ack" {
                    let CommitTrial::Pending(trial) = trial.commit() else {
                        panic!("missing support-backed commit ack was not retained")
                    };
                    until(|| root.join("trial-authorized").exists());
                    trial
                } else {
                    trial
                };
                let StopTrial::Draining(mut session) = trial.stop() else {
                    panic!("support-backed uncertain trial could not stop")
                };
                until(|| {
                    if mode == "no-ack" {
                        session.poll().unwrap() == DrainStatus::Drained
                    } else {
                        session.poll().unwrap() == DrainStatus::Uncertain
                            && session.group.all_owner_processes_reaped()
                    }
                });
                let evidence = support_evidence(root);
                let state = fs::read(root.join("application-slot/current/state")).unwrap();
                assert_eq!(
                    state[8],
                    if mode == "no-ack" {
                        Phase::Committed as u8
                    } else {
                        Phase::Published as u8
                    }
                );
                let Rollback::Retained(session) = session.rollback() else {
                    panic!("committed or unclosed support-backed runtime rolled back")
                };
                assert_eq!(support_live(root), new);
                assert_eq!(support_evidence(root), evidence);
                assert_eq!(
                    fs::read(root.join("application-slot/current/state")).unwrap(),
                    state
                );
                assert!(!root.join("application-slot/history").exists());
                assert_eq!(native_phase(root), 4);
                excluded(root);
                // All known probe processes are reaped. Losing this fixture's
                // owner does not turn durable Stopping into a closure proof.
                drop(session);
                assert_eq!(native_phase(root), 4);
                continue;
            }
            if mode == "valid" {
                until(|| trial.poll() == TrialStatus::Ready);
                let mut current = Some(trial);
                let mut committed = None;
                until(|| {
                    match current.take().unwrap().commit() {
                        CommitTrial::Pending(next) => current = Some(next),
                        CommitTrial::Committed(done) => committed = Some(done),
                        CommitTrial::Retained(_) => panic!("support-backed commit failed"),
                    }
                    committed.is_some()
                });
                assert_eq!(support_live(root), new);
                release_support_terminal(root, committed.unwrap(), Committed::release)
            } else {
                until(|| trial.poll() == TrialStatus::Failed);
                let CommitTrial::Retained(trial) = trial.commit() else {
                    panic!("failed support-backed trial committed")
                };
                let StopTrial::Draining(mut session) = trial.stop() else {
                    panic!("failed support-backed trial could not stop")
                };
                until(|| session.poll().unwrap() == DrainStatus::Drained);
                assert_eq!(support_live(root), new);
                let Rollback::Restored(restored) = session.rollback() else {
                    panic!("joined support-backed trial could not rollback")
                };
                assert_eq!(support_live(root), old);
                release_support_terminal(root, restored, RolledBack::release)
            }
        };
        assert!(support_evidence(root).is_empty());
        let status = crate::update::app_slot::job_status_fixture(root, transaction)
            .unwrap()
            .unwrap();
        assert!(status.archived);
        assert_eq!(
            status.phase,
            if mode == "valid" {
                Phase::Committed
            } else {
                Phase::RolledBack
            }
        );
        assert_eq!(support_live(root), if mode == "valid" { new } else { old });
        if mode != "valid" {
            assert_eq!(
                fs::read(root.join("kvmapp/identity")).unwrap(),
                b"old unchanged"
            );
        }
        assert_admission_released(root);
        assert_eq!(native_phase(root), 1);
        let admission = broker.runtime_permit().unwrap();
        let super::super::Shutdown::Draining(mut drain) = broker.shutdown(admission) else {
            panic!("post-support terminal shutdown refused")
        };
        until(|| drain.poll().unwrap() == DrainStatus::Drained);
    }
}

#[tokio::test]
async fn published_trial_retains_freeze_and_commits_durably_before_backend_authorization() {
    let root = tempfile::tempdir().unwrap();
    let session = published(root.path(), true).await;
    fs::write(root.path().join("hold-trial-ready"), b"hold").unwrap();
    let BeginTrial::Started(mut trial) =
        session.start_trial_command(trial_command(root.path(), "valid"))
    else {
        panic!("trial refused")
    };
    until(|| root.path().join("trial-owner-started").exists());
    assert_eq!(trial.poll(), TrialStatus::Starting);
    assert_eq!(
        trial.group.poll()[..2],
        [Some(ScopeStatus::Closed(
            crate::native_owner::controller::Completion::Stopped
        )); 2],
        "previously running native writers must stay closed throughout trial"
    );
    assert_eq!(
        trial.group.poll()[3],
        Some(ScopeStatus::Closed(
            crate::native_owner::controller::Completion::Stopped
        )),
        "optional Pico writer must stay closed throughout trial"
    );
    let CommitTrial::Pending(retained) = trial.commit() else {
        panic!("unready trial committed")
    };
    trial = retained;
    excluded(root.path());
    assert_eq!(
        fs::read(root.path().join("application-slot/current/state")).unwrap()[8],
        Phase::Published as u8
    );
    fs::remove_file(root.path().join("hold-trial-ready")).unwrap();
    until(|| trial.poll() == TrialStatus::Ready);
    let mut current = Some(trial);
    let mut committed = None;
    until(|| {
        match current.take().unwrap().commit() {
            CommitTrial::Pending(next) => current = Some(next),
            CommitTrial::Committed(done) => committed = Some(done),
            CommitTrial::Retained(_) => panic!("ready trial commit failed"),
        }
        committed.is_some()
    });
    excluded(root.path());
    assert_eq!(
        fs::read(root.path().join("application-slot/current/state")).unwrap()[8],
        Phase::Committed as u8
    );
    assert!(
        root.path().join("application-slot/current/old").exists(),
        "commit must not erase rollback evidence"
    );
    let committed = committed.unwrap();
    let transaction = committed.install.transaction();
    let collision = root
        .path()
        .join("application-slot/history")
        .join(format!("{:032x}", u128::from_be_bytes(transaction)));
    fs::create_dir_all(&collision).unwrap();
    fs::set_permissions(
        collision.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&collision, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(collision.join("foreign"), b"retain").unwrap();
    let Release::Retained(committed) = committed.release() else {
        panic!("foreign archive was overwritten")
    };
    excluded(root.path());
    assert_eq!(fs::read(collision.join("foreign")).unwrap(), b"retain");
    fs::remove_file(collision.join("foreign")).unwrap();
    fs::remove_dir(&collision).unwrap();
    let mut broker = released(committed.release());
    assert!(
        crate::update::app_slot::job_status_fixture(root.path(), transaction)
            .unwrap()
            .unwrap()
            .archived
    );
    assert_admission_released(root.path());
    // Native writers resume only in the ordinary post-freeze broker path.
    for (role, name) in [
        (Role::KvmSystem, "kvm"),
        (Role::Hwmon, "hwmon"),
        (Role::Picoclaw, "picoclaw"),
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "native_owner::broker::app_install::tests::scope_probe",
                "--nocapture",
            ])
            .env_clear()
            .env("NANOKVM_APP_NATIVE_ROOT", root.path())
            .env("NANOKVM_APP_NATIVE_ROLE", name)
            .env("NANOKVM_APP_NATIVE_RECEIPT", "complete")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if role == Role::Picoclaw {
            let admission = broker.runtime_permit().unwrap();
            broker
                .start_picoclaw(
                    command,
                    &admission,
                    crate::update::picoclaw_config::Generation::fixture([0x31; 32]),
                )
                .unwrap();
        } else {
            broker.start_owned(role, command).unwrap();
        }
    }
    until(|| broker.group.poll() == [Some(ScopeStatus::Running); 4]);
    let admission = broker.runtime_permit().unwrap();
    let super::super::Shutdown::Draining(mut drain) = broker.shutdown(admission) else {
        panic!("shutdown refused")
    };
    until(|| drain.poll().unwrap() == DrainStatus::Drained);
}

#[tokio::test]
async fn failed_trial_must_stop_and_join_before_old_slot_rollback() {
    let root = tempfile::tempdir().unwrap();
    let session = published(root.path(), false).await;
    let BeginTrial::Started(mut trial) =
        session.start_trial_command(trial_command(root.path(), "failed-ready"))
    else {
        panic!("trial refused")
    };
    until(|| trial.poll() == TrialStatus::Failed);
    excluded(root.path());
    let CommitTrial::Retained(trial) = trial.commit() else {
        panic!("failed trial committed")
    };
    let StopTrial::Draining(mut session) = trial.stop() else {
        panic!("stop refused")
    };
    until(|| session.poll().unwrap() == DrainStatus::Drained);
    let Rollback::Restored(restored) = session.rollback() else {
        panic!("closed trial cannot rollback")
    };
    excluded(root.path());
    assert_eq!(
        fs::read(root.path().join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
    let collision = root.path().join("application-slot/history").join(format!(
        "{:032x}",
        u128::from_be_bytes(restored.transaction())
    ));
    fs::create_dir_all(&collision).unwrap();
    fs::set_permissions(
        collision.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&collision, fs::Permissions::from_mode(0o700)).unwrap();
    let Release::Retained(restored) = restored.release() else {
        panic!("foreign archive was overwritten")
    };
    excluded(root.path());
    fs::remove_dir(collision).unwrap();
    drop(released(restored.release()));
}

#[tokio::test]
async fn lost_commit_ack_never_reverts_a_canonically_committed_slot() {
    let root = tempfile::tempdir().unwrap();
    let session = published(root.path(), false).await;
    let BeginTrial::Started(mut trial) =
        session.start_trial_command(trial_command(root.path(), "no-ack"))
    else {
        panic!("trial refused")
    };
    until(|| trial.poll() == TrialStatus::Ready);
    let CommitTrial::Pending(trial) = trial.commit() else {
        panic!("no-ack did not retain")
    };
    until(|| root.path().join("trial-authorized").exists());
    excluded(root.path());
    let StopTrial::Draining(mut session) = trial.stop() else {
        panic!("stop refused")
    };
    until(|| session.poll().unwrap() == DrainStatus::Drained);
    let Rollback::Retained(session) = session.rollback() else {
        panic!("committed app rolled back")
    };
    excluded(root.path());
    assert_eq!(
        fs::read(root.path().join("application-slot/current/state")).unwrap()[8],
        Phase::Committed as u8
    );
    assert_eq!(
        fs::read(root.path().join("kvmapp/version")).unwrap(),
        b"2.0.43\n"
    );
    assert_eq!(native_phase(root.path()), 4);
    drop(session);
}

#[tokio::test]
async fn native_resume_failure_after_durable_app_commit_retains_without_backend_authorization() {
    let root = tempfile::tempdir().unwrap();
    let session = published(root.path(), false).await;
    let BeginTrial::Started(mut trial) =
        session.start_trial_command(trial_command(root.path(), "resume-failure"))
    else {
        panic!("trial refused")
    };
    until(|| trial.poll() == TrialStatus::Ready);
    let next = root.path().join("native-runtime-owner/.state.next");
    fs::write(&next, b"retain collision").unwrap();
    fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
    let CommitTrial::Retained(trial) = trial.commit() else {
        panic!("failed native resume authorized backend")
    };
    assert_eq!(
        fs::read(root.path().join("application-slot/current/state")).unwrap()[8],
        Phase::Committed as u8
    );
    assert_eq!(native_phase(root.path()), 4);
    assert_eq!(fs::read(&next).unwrap(), b"retain collision");
    assert!(!root.path().join("trial-authorized").exists());
    assert!(trial.journal.ready().is_err());
    excluded(root.path());
    let CommitTrial::Retained(trial) = trial.commit() else {
        panic!("ambiguous native journal retried commit")
    };
    let StopTrial::Retained(trial) = trial.stop() else {
        panic!("ambiguous native journal authorized Stop/rollback")
    };
    assert!(!root.path().join("trial-authorized").exists());
    assert_eq!(
        fs::read(root.path().join("kvmapp/version")).unwrap(),
        b"2.0.43\n"
    );
    excluded(root.path());

    // Lose and reap ONLY this known childless protocol fixture. Keep journal
    // and install admission alive; no production closure/rollback is minted.
    let pid = fs::read_to_string(root.path().join("trial-owner-pid"))
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let TrialSession {
        group,
        journal,
        install,
        ..
    } = trial;
    drop(group);
    until(|| {
        matches!(
            nix::sys::wait::waitpid(
                nix::unistd::Pid::from_raw(pid),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG)
            )
            .unwrap(),
            nix::sys::wait::WaitStatus::Exited(_, 0)
        )
    });
    assert!(root.path().join("trial-controller-lost").exists());
    assert!(journal.ready().is_err());
    excluded(root.path());
    assert_eq!(native_phase(root.path()), 4);
    assert_eq!(fs::read(&next).unwrap(), b"retain collision");
    drop((journal, install));
}

#[tokio::test]
async fn trial_owner_exit_without_receipt_never_authorizes_old_slot_rollback() {
    let root = tempfile::tempdir().unwrap();
    let session = published(root.path(), false).await;
    let BeginTrial::Started(mut trial) =
        session.start_trial_command(trial_command(root.path(), "missing-receipt"))
    else {
        panic!("trial refused")
    };
    until(|| trial.poll() == TrialStatus::Ready);
    let StopTrial::Draining(mut session) = trial.stop() else {
        panic!("stop refused")
    };
    until(|| {
        matches!(session.poll(), Ok(DrainStatus::Uncertain))
            && session.group.all_owner_processes_reaped()
    });
    let Rollback::Retained(session) = session.rollback() else {
        panic!("exit without closure receipt permitted rollback")
    };
    excluded(root.path());
    assert_eq!(native_phase(root.path()), 4);
    assert_eq!(
        fs::read(root.path().join("kvmapp/version")).unwrap(),
        b"2.0.43\n"
    );
    assert!(root.path().join("application-slot/current/old").exists());
    drop(session);
}

#[tokio::test]
async fn all_three_scopes_must_join_before_publication_and_rollback_releases_no_early_lock() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    start_roles(&mut broker, root.path(), false);
    let install = accepted_fixture(root.path()).await;
    crate::update::app_slot::support::populate_retained_fixture(&install);
    let id = install.transaction();
    fs::create_dir(root.path().join("kvmapp/kvm")).unwrap();
    for (name, value) in [
        ("ap.ssid", "synthetic AP"),
        ("ap.pass", "synthetic-only-pass"),
        ("type", "h264"),
        ("fps", "30"),
        ("qlty", "80"),
        ("gop", "30"),
        ("res", "1920x1080"),
    ] {
        fs::write(root.path().join("kvmapp/kvm").join(name), value).unwrap();
    }
    let old_inode = root.path().join("kvmapp").metadata().unwrap().ino();
    fs::write(root.path().join("hold-backend"), b"hold").unwrap();
    let Start::Draining(mut session) = broker.begin_app_install(install) else {
        panic!("admitted app drain refused");
    };
    assert_eq!(session.transaction(), id);
    until(|| root.path().join("backend-stopping").exists());
    assert_eq!(native_phase(root.path()), 4);
    assert!(matches!(session.publish(), Err(SlotError::Busy)));
    assert_eq!(
        root.path().join("kvmapp").metadata().unwrap().ino(),
        old_inode
    );
    excluded(root.path());
    fs::remove_file(root.path().join("hold-backend")).unwrap();
    until(|| matches!(session.poll(), Ok(DrainStatus::Drained)));
    assert_eq!(
        native_phase(root.path()),
        4,
        "drained is not Closed during app work"
    );
    stage_support(&mut session);
    assert_eq!(
        session.publish().unwrap(),
        Status::Transaction(Phase::Published)
    );
    assert_eq!(
        fs::read(root.path().join("kvmapp/version")).unwrap(),
        b"2.0.43\n"
    );
    assert_ne!(
        root.path().join("kvmapp").metadata().unwrap().ino(),
        old_inode
    );
    for name in ["ap.ssid", "ap.pass", "type", "fps", "qlty", "gop", "res"] {
        let path = root.path().join("kvmapp/kvm").join(name);
        assert_eq!(
            fs::read(&path).unwrap(),
            fs::read(
                root.path()
                    .join("application-slot/current/old/kvm")
                    .join(name)
            )
            .unwrap()
        );
        assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o600);
    }
    assert!(matches!(session.publish(), Err(SlotError::Invalid)));
    excluded(root.path());
    let Rollback::Restored(restored) = session.rollback() else {
        panic!("known closed runtime/old slot must recover");
    };
    assert_eq!(restored.transaction(), id);
    excluded(root.path());
    let mut broker = released(restored.release());
    assert_eq!(
        root.path().join("kvmapp").metadata().unwrap().ino(),
        old_inode
    );
    assert_eq!(
        fs::read(root.path().join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
    assert_eq!(native_phase(root.path()), 1);
    assert_admission_released(root.path());
    assert_eq!(
        broker.group.poll(),
        [Some(ScopeStatus::Closed(
            crate::native_owner::controller::Completion::Stopped
        )); 4]
    );
}

#[tokio::test]
async fn missing_native_receipt_never_grants_publication_or_rollback_resume() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    start_roles(&mut broker, root.path(), true);
    let install = accepted_fixture(root.path()).await;
    let old = root.path().join("kvmapp").metadata().unwrap().ino();
    let Start::Draining(mut session) = broker.begin_app_install(install) else {
        panic!("app drain refused");
    };
    until(|| matches!(session.poll(), Ok(DrainStatus::Uncertain)));
    until(|| {
        let _ = session.poll();
        session.group.all_owner_processes_reaped()
    });
    assert!(matches!(session.publish(), Err(SlotError::Busy)));
    let Rollback::Retained(session) = session.rollback() else {
        panic!("uncertain runtime resumed");
    };
    assert_eq!(root.path().join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(native_phase(root.path()), 4);
    excluded(root.path());
    drop(session);
    assert!(matches!(
        journal::Store::fixture(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw(),
            "12345678-1234-1234-1234-123456789abc"
        ),
        Err(JournalError::Unresolved)
    ));
}

#[tokio::test]
async fn stop_publication_failure_retains_the_install_and_never_starts_drain() {
    let root = tempfile::tempdir().unwrap();
    let broker = broker(root.path());
    let install = accepted_fixture(root.path()).await;
    let path = root.path().join("native-runtime-owner/.state.next");
    fs::write(&path, b"retain collision").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let Start::Retained { broker, install } = broker.begin_app_install(install) else {
        panic!("uncertain publication authorized Stop");
    };
    assert_eq!(fs::read(&path).unwrap(), b"retain collision");
    assert!(broker.journal.ready().is_err());
    assert!(!root.path().join("native-runtime-owner/state").exists());
    excluded(root.path());
    assert_ne!(install.transaction(), [0; 16]);
    assert_eq!(
        fs::read(root.path().join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
}
