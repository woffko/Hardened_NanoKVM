use super::app_install::InstallIoFixture as RetirementFixture;
use super::*;
use std::sync::mpsc;

fn assert_store_excluded(root: &Path) {
    let directory = std::fs::File::open(root.join("application-slot")).unwrap();
    assert_eq!(
        rustix::fs::flock(
            &directory,
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        ),
        Err(rustix::io::Errno::WOULDBLOCK)
    );
    assert_excluded(root);
}

#[tokio::test]
async fn blocked_terminal_io_keeps_commit_and_rollback_control_responsive_and_excluded() {
    for rollback in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        // Declare senders after engine: on assertion failure channel EOF also
        // unblocks the fixture worker before Engine's joining teardown.
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_retirement = Some(RetirementFixture::Block {
            entered,
            resume: resumed,
        });
        if rollback {
            fs::write(root.join("trial-ready-fail"), b"fail").unwrap();
        }
        let (old, transaction) = accept(&mut engine, root).await;
        until(|| {
            engine.tick();
            entering.try_recv().is_ok()
        });
        assert_eq!(engine.mode, Mode::Installing);
        assert_eq!(
            phase(root, transaction),
            if rollback {
                app_slot::Phase::RolledBack
            } else {
                app_slot::Phase::Committed
            } as u8
        );
        assert_eq!(
            root.join("kvmapp").metadata().unwrap().ino() == old,
            rollback
        );
        assert_store_excluded(root);
        let Some(install) = engine.install.as_mut() else {
            panic!("retained installation absent");
        };
        let (InstallOwner::Committed(owner) | InstallOwner::RolledBack(owner)) = &mut install.owner
        else {
            panic!("blocked retirement owner absent");
        };
        let diagnostic = owner.fixture_diagnostics();
        assert!(
            diagnostic.contains("state=running, finished=Some(false)"),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains("tid=Some(") && diagnostic.contains("comm=\"app-retirement"),
            "{diagnostic}"
        );
        assert!(diagnostic.len() < 17 * 1024);
        assert_store_excluded(root);
        engine.disconnected(1);
        engine.disconnected(2);
        for _ in 0..3 {
            for (op, expected) in [
                (Operation::Observe, Code::Ok),
                (Operation::EnsureKvm, Code::Busy),
                (Operation::EnsureHwmon, Code::Busy),
                (Operation::EnsureBackend, Code::Busy),
                (Operation::RestartBackend, Code::Busy),
                (Operation::RestartBackendSafe, Code::Busy),
                (Operation::Shutdown, Code::Busy),
                (Operation::Pause, Code::Busy),
                (Operation::Resume, Code::Busy),
                (Operation::RetryAppRetirement, Code::Busy),
                (Operation::CancelAppInstall, Code::Uncertain),
            ] {
                let started = Instant::now();
                let reply = engine.request(3, op);
                assert!(started.elapsed() < Duration::from_millis(250), "{op:?}");
                assert_eq!(reply.code, expected, "{op:?}");
                assert_eq!(reply.mode, Mode::Installing);
                assert!(engine.install.is_some());
                assert_store_excluded(root);
            }
        }
        assert!(!root.join("kvm").exists());
        assert!(!root.join("hwmon").exists());
        assert!(!root.join("application-slot/history").exists());
        resume.send(()).unwrap();
        until(|| {
            engine.tick();
            engine.install.is_none() && engine.mode == Mode::Running
        });
        assert!(
            app_slot::job_status_fixture(root, transaction)
                .unwrap()
                .unwrap()
                .archived
        );
        shutdown(&mut engine);
    }
}

#[tokio::test]
async fn worker_spawn_failure_and_panic_retain_terminal_authority_until_explicit_retry() {
    for rollback in [false, true] {
        for panic in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let root = root.path();
            let mut engine = engine(root);
            engine.fixture_retirement = Some(if panic {
                RetirementFixture::Panic
            } else {
                RetirementFixture::SpawnFailure
            });
            if rollback {
                fs::write(root.join("trial-ready-fail"), b"fail").unwrap();
            }
            let (_, transaction) = accept(&mut engine, root).await;
            let started = Instant::now();
            loop {
                let before = install_state(&engine);
                let tick_started = Instant::now();
                engine.tick();
                if engine.mode == Mode::Uncertain {
                    break;
                }
                assert!(
                    started.elapsed() < FIXTURE_WAIT,
                    "awaiting injected retirement fault: rollback={rollback}, panic={panic}, before={before:?}, after={:?}, mode={:?}, tick={:?}, elapsed={:?}",
                    install_state(&engine),
                    engine.mode,
                    tick_started.elapsed(),
                    started.elapsed()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let state = fs::read(root.join("application-slot/current/state")).unwrap();
            let support = support::evidence(root);
            for _ in 0..3 {
                engine.disconnected(1);
                engine.tick();
                assert_eq!(engine.request(2, Operation::Observe).mode, Mode::Uncertain);
                assert_store_excluded(root);
                assert_eq!(
                    fs::read(root.join("application-slot/current/state")).unwrap(),
                    state
                );
                assert_eq!(support::evidence(root), support);
                assert!(!root.join("application-slot/history").exists());
            }
            let reply = engine.request(2, Operation::RetryAppRetirement);
            assert_eq!(reply.code, Code::Ok);
            assert_eq!(reply.mode, Mode::Installing);
            assert_store_excluded(root);
            until(|| {
                engine.tick();
                engine.install.is_none() && engine.mode == Mode::Running
            });
            assert!(
                app_slot::job_status_fixture(root, transaction)
                    .unwrap()
                    .unwrap()
                    .archived
            );
            shutdown(&mut engine);
        }
    }
}

#[tokio::test]
async fn panic_after_successful_filesystem_retirement_still_requires_explicit_retry() {
    for rollback in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        engine.fixture_retirement = Some(RetirementFixture::PanicAfterIo);
        if rollback {
            fs::write(root.join("trial-ready-fail"), b"fail").unwrap();
        }
        let (_, transaction) = accept(&mut engine, root).await;
        until(|| {
            engine.tick();
            engine.mode == Mode::Uncertain
        });
        let archived = app_slot::job_status_fixture(root, transaction)
            .unwrap()
            .unwrap();
        assert!(archived.archived);
        for _ in 0..3 {
            engine.tick();
            assert_store_excluded(root);
            assert_eq!(engine.mode, Mode::Uncertain);
            assert_eq!(
                app_slot::job_status_fixture(root, transaction)
                    .unwrap()
                    .unwrap(),
                archived
            );
        }
        let reply = engine.request(2, Operation::RetryAppRetirement);
        assert_eq!(reply.code, Code::Ok);
        assert_eq!(reply.mode, Mode::Installing);
        assert_store_excluded(root);
        until(|| {
            engine.tick();
            engine.install.is_none() && engine.mode == Mode::Running
        });
        assert_eq!(
            app_slot::job_status_fixture(root, transaction)
                .unwrap()
                .unwrap(),
            archived
        );
        shutdown(&mut engine);
    }
}

#[tokio::test]
async fn owner_loss_during_blocked_retirement_cannot_release_even_after_successful_io() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    let (entered, entering) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    engine.fixture_retirement = Some(RetirementFixture::Block {
        entered,
        resume: resumed,
    });
    let (_, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        entering.try_recv().is_ok()
    });
    let pid: i32 = fs::read_to_string(root.join("trial-owner-started"))
        .unwrap()
        .parse()
        .unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
            && engine.backend_status == Some(Status::Uncertain)
            && !Path::new("/proc").join(pid.to_string()).exists()
    });
    assert_store_excluded(root);
    resume.send(()).unwrap();
    until(|| {
        engine.tick();
        app_slot::job_status_fixture(root, transaction)
            .is_ok_and(|status| status.is_some_and(|status| status.archived))
    });
    for _ in 0..3 {
        assert_eq!(
            engine.request(2, Operation::RetryAppRetirement).code,
            Code::Uncertain
        );
        assert_eq!(engine.mode, Mode::Uncertain);
        assert!(engine.install.is_some());
        assert_store_excluded(root);
        assert!(!root.join("kvm").exists());
        assert!(!root.join("hwmon").exists());
    }
    drop(engine);
}

#[tokio::test]
async fn daemon_teardown_joins_retirement_without_detaching_or_releasing_admission_early() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    let (entered, entering) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    engine.fixture_retirement = Some(RetirementFixture::Block {
        entered,
        resume: resumed,
    });
    fs::write(root.join("trial-ready-fail"), b"fail").unwrap();
    let (_, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        entering.try_recv().is_ok()
    });
    std::thread::scope(|scope| {
        let root = root.to_path_buf();
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            assert_store_excluded(&root);
            resume.send(()).unwrap();
        });
        drop(engine);
    });
    assert!(
        app_slot::job_status_fixture(root, transaction)
            .unwrap()
            .unwrap()
            .archived
    );
    crate::update::app_slot::issuer_tests::assert_admission_released(root);
}
