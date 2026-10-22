//! Fixed rollback I/O is distinct from closure, resume and terminal retirement.
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
        1 => app_install::InstallIoFixture::BlockRollbackJournal { entered, resume },
        _ => app_install::InstallIoFixture::BlockAfterIo { entered, resume },
    }
}

fn failed_trial(root: &Path) {
    fs::write(root.join("trial-ready-fail"), b"fail before commit").unwrap();
}

#[tokio::test]
async fn held_rollback_at_both_durable_boundaries_keeps_control_and_all_exclusions() {
    for position in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        // On assertion unwind, sender EOF unblocks work before joining Engine.
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_rollback = Some(gate(position, entered, resumed));
        failed_trial(root);
        let (old, transaction) = accept(&mut engine, root).await;
        let original_support = support::live(root);
        until(|| {
            engine.tick();
            entering.try_recv().is_ok()
        });
        assert!(matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::RollingBack(_)
        ));
        let record = fs::read(root.join("application-slot/current/state")).unwrap();
        let native = fs::read(root.join("native-runtime-owner/state")).unwrap();
        let held_support = support::live(root);
        assert_eq!(
            record[8],
            if position == 0 {
                app_slot::Phase::Published
            } else {
                app_slot::Phase::RolledBack
            } as u8
        );
        assert_eq!(native[44], if position == 2 { 1 } else { 4 });
        assert_eq!(
            root.join("kvmapp").metadata().unwrap().ino() == old,
            position != 0
        );
        assert!(root.join("trial-stopping").exists());
        engine.disconnected(1);
        engine.disconnected(2);
        for _ in 0..3 {
            for (operation, code) in [
                (Operation::Observe, Code::Ok),
                (Operation::CancelAppInstall, Code::Uncertain),
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
                assert_eq!(support::live(root), held_support);
                assert!(!root.join("trial-authorized").exists());
                assert!(!root.join("application-slot/history").exists());
                assert!(!root.join("kvm").exists());
                assert!(!root.join("hwmon").exists());
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
        assert_eq!(status.phase, app_slot::Phase::RolledBack);
        assert!(status.archived);
        assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(support::live(root), original_support);
        assert!(support::evidence(root).is_empty());
        assert!(!root.join("trial-authorized").exists());
        shutdown(&mut engine);
    }
}

#[tokio::test]
async fn rollback_spawn_panic_and_real_errors_retain_authority_without_retry_after_repair() {
    for failure in 0..6 {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_rollback = Some(match failure {
            0 => app_install::InstallIoFixture::SpawnFailure,
            1 => app_install::InstallIoFixture::Panic,
            2 => app_install::InstallIoFixture::PanicAfterRollbackRecord,
            3 => app_install::InstallIoFixture::PanicAfterIo,
            4 => gate(1, entered, resumed),
            _ => gate(0, entered, resumed),
        });
        failed_trial(root);
        let (old, transaction) = accept(&mut engine, root).await;
        let collision = if failure == 5 {
            root.join("application-slot/current/new")
        } else {
            root.join("native-runtime-owner/.state.next")
        };
        if failure >= 4 {
            until(|| {
                engine.tick();
                entering.try_recv().is_ok()
            });
            if failure == 5 {
                fs::create_dir(&collision).unwrap();
            } else {
                fs::write(&collision, b"known rollback journal collision").unwrap();
            }
            resume.send(()).unwrap();
        }
        until(|| {
            engine.tick();
            engine.mode == Mode::Uncertain
        });
        assert!(matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::RollingBack(_)
        ));
        let record = fs::read(root.join("application-slot/current/state")).unwrap();
        let native = fs::read(root.join("native-runtime-owner/state")).unwrap();
        let held_support = support::live(root);
        let rolled_back = matches!(failure, 2..=4);
        assert_eq!(
            record[8],
            if rolled_back {
                app_slot::Phase::RolledBack
            } else {
                app_slot::Phase::Published
            } as u8
        );
        assert_eq!(native[44], if failure == 3 { 1 } else { 4 });
        assert_eq!(
            root.join("kvmapp").metadata().unwrap().ino() == old,
            rolled_back
        );
        if failure == 4 {
            fs::remove_file(collision).unwrap();
        } else if failure == 5 {
            fs::remove_dir(collision).unwrap();
        }
        for _ in 0..3 {
            engine.disconnected(1);
            for operation in [
                Operation::Observe,
                Operation::CancelAppInstall,
                Operation::RetryAppRetirement,
            ] {
                let start = Instant::now();
                let reply = engine.request(2, operation);
                assert!(start.elapsed() < Duration::from_millis(250));
                assert_eq!(reply.code, Code::Uncertain);
                assert_eq!(reply.mode, Mode::Uncertain);
            }
            assert_eq!(phase(root, transaction), record[8]);
            assert_eq!(
                fs::read(root.join("application-slot/current/state")).unwrap(),
                record
            );
            assert_eq!(
                fs::read(root.join("native-runtime-owner/state")).unwrap(),
                native
            );
            assert_eq!(support::live(root), held_support);
            assert!(!root.join("trial-authorized").exists());
            assert!(!root.join("application-slot/history").exists());
            assert!(!root.join("kvm").exists());
            assert!(!root.join("hwmon").exists());
            excluded(root);
        }
    }
}

#[tokio::test]
async fn cancellation_starts_only_one_joined_rollback_without_trial_or_early_success() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    let (entered, entering) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    engine.fixture_hold_published = true;
    engine.fixture_rollback = Some(gate(1, entered, resumed));
    let (old, transaction) = accept(&mut engine, root).await;
    let original_support = support::live(root);
    until(|| {
        engine.tick();
        engine.install.as_ref().unwrap().stage == InstallStage::Published
    });
    let started = Instant::now();
    let reply = engine.request(1, Operation::CancelAppInstall);
    assert!(started.elapsed() < Duration::from_millis(250));
    assert_eq!(reply.code, Code::Ok);
    assert_eq!(reply.mode, Mode::Installing);
    until(|| {
        engine.tick();
        entering.try_recv().is_ok()
    });
    engine.disconnected(1);
    assert_eq!(
        engine.request(2, Operation::CancelAppInstall).code,
        Code::Uncertain
    );
    assert_eq!(engine.mode, Mode::Installing);
    assert_eq!(phase(root, transaction), app_slot::Phase::RolledBack as u8);
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert!(!root.join("trial-owner-started").exists());
    assert!(!root.join("application-slot/history").exists());
    excluded(root);
    resume.send(()).unwrap();
    until(|| {
        engine.tick();
        engine.install.is_none() && engine.mode == Mode::Running
    });
    assert_eq!(support::live(root), original_support);
    assert!(
        app_slot::job_status_fixture(root, transaction)
            .unwrap()
            .unwrap()
            .archived
    );
    shutdown(&mut engine);
}

#[tokio::test]
async fn lost_native_receipt_never_admits_rollback_work_or_releases_its_owner() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    engine.fixture_rollback = Some(app_install::InstallIoFixture::Panic);
    failed_trial(root);
    fs::write(root.join("trial-missing-receipt"), b"omit closure").unwrap();
    let (old, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    assert!(matches!(
        engine.install.as_ref().unwrap().owner,
        InstallOwner::Draining(_)
    ));
    let record = fs::read(root.join("application-slot/current/state")).unwrap();
    for _ in 0..3 {
        assert_eq!(
            engine.request(2, Operation::CancelAppInstall).code,
            Code::Uncertain
        );
        assert!(engine.fixture_rollback.is_some());
        assert_eq!(phase(root, transaction), app_slot::Phase::Published as u8);
        assert_eq!(
            fs::read(root.join("application-slot/current/state")).unwrap(),
            record
        );
        assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(
            fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
            4
        );
        assert!(!root.join("application-slot/history").exists());
        excluded(root);
    }
}

#[tokio::test]
async fn forfeited_main_thread_authority_cannot_be_restored_by_late_successful_io() {
    for position in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_rollback = Some(gate(position, entered, resumed));
        failed_trial(root);
        let (old, transaction) = accept(&mut engine, root).await;
        until(|| {
            engine.tick();
            entering.try_recv().is_ok()
        });
        let InstallOwner::RollingBack(owner) = &mut engine.install.as_mut().unwrap().owner else {
            panic!("rollback worker not retained");
        };
        owner.fixture_forfeit_closed_proof();
        assert_eq!(engine.request(2, Operation::Observe).mode, Mode::Uncertain);
        excluded(root);
        resume.send(()).unwrap();
        until(|| {
            engine.tick();
            matches!(&engine.install.as_ref().unwrap().owner, InstallOwner::RollingBack(owner) if owner.fixture_io_settled())
        });
        assert_eq!(phase(root, transaction), app_slot::Phase::RolledBack as u8);
        assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(
            fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
            1
        );
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
            assert!(!root.join("application-slot/history").exists());
            assert!(!root.join("kvm").exists());
            assert!(!root.join("hwmon").exists());
            excluded(root);
        }
    }
}

#[tokio::test]
async fn rollback_teardown_joins_both_writes_before_releasing_singleton_and_admission() {
    for position in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_rollback = Some(gate(position, entered, resumed));
        failed_trial(root);
        let (old, transaction) = accept(&mut engine, root).await;
        until(|| {
            engine.tick();
            entering.try_recv().is_ok()
        });
        std::thread::scope(|scope| {
            let root = root.to_path_buf();
            scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                excluded(&root);
                assert_eq!(
                    fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
                    if position == 2 { 1 } else { 4 }
                );
                resume.send(()).unwrap();
            });
            drop(engine);
        });
        assert_eq!(phase(root, transaction), app_slot::Phase::RolledBack as u8);
        assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(
            fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
            1
        );
        assert!(!root.join("trial-authorized").exists());
        assert!(!root.join("application-slot/history").exists());
        crate::update::app_slot::issuer_tests::assert_admission_released(root);
    }
}
