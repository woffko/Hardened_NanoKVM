//! Durable commit I/O and live trial supervision remain separate authorities.
use super::*;
use std::sync::mpsc;

fn excluded(root: &Path) {
    for name in ["application-slot", "native-runtime-owner"] {
        let directory = std::fs::File::open(root.join(name)).unwrap();
        assert_eq!(
            rustix::fs::flock(
                &directory,
                rustix::fs::FlockOperation::NonBlockingLockExclusive
            ),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
    }
    assert_excluded(root);
}

fn gate(
    position: u8,
    entered: mpsc::Sender<()>,
    resume: mpsc::Receiver<()>,
) -> app_install::InstallIoFixture {
    match position {
        0 => app_install::InstallIoFixture::Block { entered, resume },
        1 => app_install::InstallIoFixture::BlockCommitJournal { entered, resume },
        _ => app_install::InstallIoFixture::BlockAfterIo { entered, resume },
    }
}

fn child(root: &Path) -> i32 {
    fs::read_to_string(root.join("trial-owner-started"))
        .unwrap()
        .parse()
        .unwrap()
}

fn reap_abandoned_fixture(root: &Path, pid: i32) {
    // Only this known childless probe permits controller loss without a native
    // receipt. Reaping it is cleanup, never commit/rollback/closure authority.
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
    assert!(root.join("trial-controller-lost").exists());
}

#[tokio::test]
async fn held_commit_at_both_durable_boundaries_serves_control_without_ack_or_rollback() {
    for position in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_commit = Some(gate(position, entered, resumed));
        let (old, transaction) = accept(&mut engine, root).await;
        until(|| {
            engine.tick();
            entering.try_recv().is_ok()
        });
        assert!(matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::Committing(_)
        ));
        let record = fs::read(root.join("application-slot/current/state")).unwrap();
        let native = fs::read(root.join("native-runtime-owner/state")).unwrap();
        assert_eq!(
            record[8],
            if position == 0 {
                app_slot::Phase::Published
            } else {
                app_slot::Phase::Committed
            } as u8
        );
        assert_eq!(native[44], if position == 2 { 1 } else { 4 });
        assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
        engine.disconnected(1);
        engine.disconnected(2);
        for _ in 0..3 {
            for (operation, code) in [
                (Operation::Observe, Code::Ok),
                (Operation::CancelAppInstall, Code::Busy),
                (Operation::RetryAppRetirement, Code::Busy),
                (Operation::EnsureKvm, Code::Busy),
                (Operation::EnsureHwmon, Code::Busy),
                (Operation::EnsureBackend, Code::Busy),
                (Operation::RestartBackend, Code::Busy),
                (Operation::RestartBackendSafe, Code::Busy),
                (Operation::Pause, Code::Busy),
                (Operation::Resume, Code::Busy),
                (Operation::Shutdown, Code::Busy),
                (Operation::BackendRunning, Code::Unavailable),
            ] {
                let start = Instant::now();
                let reply = engine.request(3, operation);
                assert!(
                    start.elapsed() < Duration::from_millis(250),
                    "{operation:?}"
                );
                assert_eq!(reply.code, code, "{operation:?}");
                assert_eq!(reply.mode, Mode::Installing);
                assert_eq!(
                    fs::read(root.join("application-slot/current/state")).unwrap(),
                    record
                );
                assert_eq!(
                    fs::read(root.join("native-runtime-owner/state")).unwrap(),
                    native
                );
                assert!(!root.join("trial-authorized").exists());
                assert!(!root.join("trial-stopping").exists());
                assert!(!root.join("application-slot/history").exists());
                excluded(root);
            }
        }
        resume.send(()).unwrap();
        until(|| {
            engine.tick();
            engine.install.is_none() && engine.mode == Mode::Running
        });
        let status = app_slot::job_status_fixture(root, transaction)
            .unwrap()
            .unwrap();
        assert_eq!(status.phase, app_slot::Phase::Committed);
        assert!(status.archived);
        assert!(root.join("trial-authorized").exists());
        assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
        shutdown(&mut engine);
    }
}

#[tokio::test]
async fn commit_spawn_panic_and_real_journal_error_never_retry_ack_or_rollback_after_repair() {
    for failure in 0..5 {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        fs::write(
            root.join("trial-allow-controller-loss"),
            b"known fixture cleanup",
        )
        .unwrap();
        let mut engine = engine(root);
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_commit = Some(match failure {
            0 => app_install::InstallIoFixture::SpawnFailure,
            1 => app_install::InstallIoFixture::Panic,
            2 => app_install::InstallIoFixture::PanicAfterCommitRecord,
            3 => app_install::InstallIoFixture::PanicAfterIo,
            _ => gate(1, entered, resumed),
        });
        let (old, transaction) = accept(&mut engine, root).await;
        let collision = root.join("native-runtime-owner/.state.next");
        if failure == 4 {
            until(|| {
                engine.tick();
                entering.try_recv().is_ok()
            });
            assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
            fs::write(&collision, b"known commit journal collision").unwrap();
            resume.send(()).unwrap();
        }
        until(|| {
            engine.tick();
            engine.mode == Mode::Uncertain
        });
        let pid = child(root);
        assert!(matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::Committing(_)
        ));
        let record = fs::read(root.join("application-slot/current/state")).unwrap();
        let native = fs::read(root.join("native-runtime-owner/state")).unwrap();
        assert_eq!(
            record[8],
            if failure < 2 {
                app_slot::Phase::Published
            } else {
                app_slot::Phase::Committed
            } as u8
        );
        assert_eq!(native[44], if failure == 3 { 1 } else { 4 });
        if failure == 4 {
            fs::remove_file(collision).unwrap();
        }
        for _ in 0..3 {
            engine.disconnected(1);
            assert_eq!(engine.request(2, Operation::Observe).mode, Mode::Uncertain);
            assert_eq!(
                engine.request(2, Operation::CancelAppInstall).code,
                Code::Uncertain
            );
            assert_eq!(
                engine.request(2, Operation::RetryAppRetirement).code,
                Code::Uncertain
            );
            assert_eq!(
                fs::read(root.join("application-slot/current/state")).unwrap(),
                record
            );
            assert_eq!(
                fs::read(root.join("native-runtime-owner/state")).unwrap(),
                native
            );
            assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
            assert!(!root.join("trial-authorized").exists());
            assert!(!root.join("trial-stopping").exists());
            assert!(!root.join("application-slot/history").exists());
            excluded(root);
        }
        drop(engine);
        reap_abandoned_fixture(root, pid);
    }
}

#[tokio::test]
async fn trial_owner_loss_during_commit_cannot_be_cleared_by_successful_filesystem_work() {
    for position in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_commit = Some(gate(position, entered, resumed));
        let (_, transaction) = accept(&mut engine, root).await;
        until(|| {
            engine.tick();
            entering.try_recv().is_ok()
        });
        let pid = child(root);
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();
        until(|| {
            engine.tick();
            engine.mode == Mode::Uncertain && !Path::new("/proc").join(pid.to_string()).exists()
        });
        excluded(root);
        resume.send(()).unwrap();
        until(|| {
            engine.tick();
            matches!(&engine.install.as_ref().unwrap().owner, InstallOwner::Committing(owner) if owner.fixture_io_settled())
        });
        assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
        assert_eq!(
            fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
            1
        );
        for _ in 0..3 {
            assert_eq!(engine.request(2, Operation::Observe).mode, Mode::Uncertain);
            assert_eq!(
                engine.request(2, Operation::CancelAppInstall).code,
                Code::Uncertain
            );
            assert_eq!(
                engine.request(2, Operation::RetryAppRetirement).code,
                Code::Uncertain
            );
            excluded(root);
            assert!(!root.join("trial-authorized").exists());
            assert!(!root.join("trial-stopping").exists());
            assert!(!root.join("application-slot/history").exists());
        }
    }
}

#[tokio::test]
async fn owner_loss_in_the_joined_commit_to_ack_gap_never_sends_stop_or_attempts_rollback() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    let (entered, entering) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    engine.fixture_commit = Some(gate(2, entered, resumed));
    let (_, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        entering.try_recv().is_ok()
    });
    let pid = child(root);
    resume.send(()).unwrap();
    until(|| {
        engine.tick();
        matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::Trial(_)
        )
    });
    assert!(engine.install.as_ref().unwrap().stage == InstallStage::CommitPending);
    assert!(!root.join("trial-authorized").exists());
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    // Observe actual exit before allowing another broker tick to send an ack.
    // Do not steal the controller's wait/reap or call that exit a closure receipt.
    until(|| match fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status
            .lines()
            .any(|line| line.starts_with("State:") && line.contains("Z (zombie)")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => panic!("fixture process observation: {error}"),
    });
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    assert!(engine.install.as_ref().unwrap().stage == InstallStage::Failed);
    assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
    assert_eq!(
        fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    assert!(!root.join("trial-authorized").exists());
    assert!(!root.join("trial-stopping").exists());
    assert_eq!(
        engine.request(2, Operation::CancelAppInstall).code,
        Code::Uncertain
    );
    excluded(root);
}

#[tokio::test]
async fn commit_teardown_joins_both_writes_before_releasing_native_and_update_leases() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(
        root.join("trial-allow-controller-loss"),
        b"known fixture cleanup",
    )
    .unwrap();
    let mut engine = engine(root);
    let (entered, entering) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    engine.fixture_commit = Some(gate(1, entered, resumed));
    let (_, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        entering.try_recv().is_ok()
    });
    let pid = child(root);
    std::thread::scope(|scope| {
        let root = root.to_path_buf();
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            excluded(&root);
            assert_eq!(
                fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
                4
            );
            resume.send(()).unwrap();
        });
        drop(engine);
    });
    reap_abandoned_fixture(root, pid);
    assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
    assert_eq!(
        fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    assert!(!root.join("trial-authorized").exists());
    assert!(!root.join("application-slot/history").exists());
    crate::update::app_slot::issuer_tests::assert_admission_released(root);
}
