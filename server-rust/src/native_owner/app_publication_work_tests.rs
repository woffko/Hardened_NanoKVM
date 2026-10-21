//! Fixed publication work under the retained native drain, not device gates.
use super::*;
use std::sync::mpsc;

fn excluded(root: &Path) {
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
async fn held_publication_before_and_after_io_serves_control_and_queues_one_joined_rollback() {
    for after_io in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        // Gate owners drop before the joining Engine on assertion unwind.
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_publication = Some(if after_io {
            app_install::InstallIoFixture::BlockAfterIo {
                entered,
                resume: resumed,
            }
        } else {
            app_install::InstallIoFixture::Block {
                entered,
                resume: resumed,
            }
        });
        let (old, transaction) = accept(&mut engine, root).await;
        let original_support = support::live(root);
        until(|| {
            engine.tick();
            entering.try_recv().is_ok()
        });
        assert!(engine.install.as_ref().unwrap().stage == InstallStage::Publishing);
        let held_support = support::live(root);
        let held_evidence = support::evidence(root);
        assert_eq!(held_evidence.len(), 10);
        assert_ne!(held_support, original_support);
        let held_phase = if after_io {
            app_slot::Phase::Published
        } else {
            app_slot::Phase::Prepared
        };
        let held_inode = root.join("kvmapp").metadata().unwrap().ino();
        assert_eq!(held_inode == old, !after_io);
        engine.disconnected(1);
        engine.disconnected(2);
        for _ in 0..3 {
            for (operation, code) in [
                (Operation::Observe, Code::Ok),
                (Operation::EnsureKvm, Code::Busy),
                (Operation::EnsureHwmon, Code::Busy),
                (Operation::EnsureBackend, Code::Busy),
                (Operation::RestartBackend, Code::Busy),
                (Operation::RestartBackendSafe, Code::Busy),
                (Operation::Pause, Code::Busy),
                (Operation::Resume, Code::Busy),
                (Operation::Shutdown, Code::Busy),
                (Operation::RetryAppRetirement, Code::Busy),
                (Operation::CancelAppInstall, Code::Ok),
            ] {
                let start = Instant::now();
                let reply = engine.request(3, operation);
                assert!(
                    start.elapsed() < Duration::from_millis(250),
                    "{operation:?}"
                );
                assert_eq!(reply.code, code, "{operation:?}");
                assert_eq!(reply.mode, Mode::Installing);
                assert_eq!(phase(root, transaction), held_phase as u8);
                assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), held_inode);
                assert_eq!(support::live(root), held_support);
                assert_eq!(support::evidence(root), held_evidence);
                assert!(!root.join("trial-owner-started").exists());
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
        assert_eq!(status.phase, app_slot::Phase::RolledBack);
        assert!(status.archived);
        assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(support::live(root), original_support);
        assert!(support::evidence(root).is_empty());
        assert!(!root.join("trial-owner-started").exists());
        shutdown(&mut engine);
    }
}

#[tokio::test]
async fn publication_spawn_and_unwind_failure_never_replay_or_start_trial_and_retain_cancel() {
    for failure in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        engine.fixture_publication = Some(match failure {
            0 => app_install::InstallIoFixture::SpawnFailure,
            1 => app_install::InstallIoFixture::Panic,
            _ => app_install::InstallIoFixture::PanicAfterIo,
        });
        let (old, transaction) = accept(&mut engine, root).await;
        let original_support = support::live(root);
        until(|| {
            engine.tick();
            engine.mode == Mode::Uncertain
        });
        assert!(matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::Draining(_)
        ));
        let held_support = support::live(root);
        let held_evidence = support::evidence(root);
        let held_phase = if failure == 2 {
            app_slot::Phase::Published
        } else {
            app_slot::Phase::Prepared
        };
        let held_inode = root.join("kvmapp").metadata().unwrap().ino();
        assert_eq!(held_inode == old, failure != 2);
        for _ in 0..3 {
            engine.disconnected(1);
            assert_eq!(engine.request(2, Operation::Observe).mode, Mode::Uncertain);
            assert_eq!(
                engine.request(2, Operation::RetryAppRetirement).code,
                Code::Uncertain
            );
            assert_eq!(phase(root, transaction), held_phase as u8);
            assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), held_inode);
            assert_eq!(support::live(root), held_support);
            assert_eq!(support::evidence(root), held_evidence);
            assert!(!root.join("trial-owner-started").exists());
            excluded(root);
        }
        assert_eq!(
            engine.request(2, Operation::CancelAppInstall).code,
            Code::Ok
        );
        until(|| {
            engine.tick();
            engine.install.is_none() && engine.mode == Mode::Running
        });
        assert_eq!(phase(root, transaction), app_slot::Phase::RolledBack as u8);
        assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(support::live(root), original_support);
        assert!(support::evidence(root).is_empty());
        assert!(!root.join("trial-owner-started").exists());
        shutdown(&mut engine);
    }
}

#[tokio::test]
async fn queued_publication_cancel_cannot_clear_native_uncertainty_even_after_successful_io() {
    for after_io in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_publication = Some(if after_io {
            app_install::InstallIoFixture::BlockAfterIo {
                entered,
                resume: resumed,
            }
        } else {
            app_install::InstallIoFixture::Block {
                entered,
                resume: resumed,
            }
        });
        let (old, transaction) = accept(&mut engine, root).await;
        until(|| {
            engine.tick();
            entering.try_recv().is_ok()
        });
        assert_eq!(
            engine.request(2, Operation::CancelAppInstall).code,
            Code::Ok
        );
        let native = fs::read(root.join("native-runtime-owner/state")).unwrap();
        let foreign = root.join("native-runtime-owner/.state.next");
        fs::write(&foreign, b"known publication fixture collision").unwrap();
        let InstallOwner::PreparingInstall { owner, .. } =
            &mut engine.install.as_mut().unwrap().owner
        else {
            panic!("publication worker not retained");
        };
        owner.fixture_failed_stopping_publication();
        assert_eq!(engine.request(2, Operation::Observe).mode, Mode::Uncertain);
        excluded(root);
        fs::remove_file(foreign).unwrap();
        resume.send(()).unwrap();
        until(|| {
            engine.tick();
            matches!(
                engine.install.as_ref().unwrap().owner,
                InstallOwner::Draining(_)
            )
        });
        // Inspect the first joined result, before a later tick hides a race.
        assert_eq!(engine.mode, Mode::Uncertain);
        assert!(engine.install.as_ref().unwrap().stage == InstallStage::Failed);
        assert_eq!(engine.backend_status, Some(Status::Uncertain));
        assert_eq!(phase(root, transaction), app_slot::Phase::Published as u8);
        assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
        let held_support = support::live(root);
        let held_evidence = support::evidence(root);
        for _ in 0..3 {
            assert_eq!(
                engine.request(2, Operation::CancelAppInstall).code,
                Code::Uncertain
            );
            assert_eq!(
                engine.request(2, Operation::RetryAppRetirement).code,
                Code::Uncertain
            );
            assert_eq!(support::live(root), held_support);
            assert_eq!(support::evidence(root), held_evidence);
            assert_eq!(
                fs::read(root.join("native-runtime-owner/state")).unwrap(),
                native
            );
            assert!(!root.join("trial-owner-started").exists());
            assert!(!root.join("application-slot/history").exists());
            excluded(root);
        }
    }
}

#[tokio::test]
async fn publication_teardown_joins_before_admission_release_and_never_claims_closed_or_trial() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    let (entered, entering) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    engine.fixture_publication = Some(app_install::InstallIoFixture::Block {
        entered,
        resume: resumed,
    });
    let (old, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        entering.try_recv().is_ok()
    });
    let native = fs::read(root.join("native-runtime-owner/state")).unwrap();
    std::thread::scope(|scope| {
        let root = root.to_path_buf();
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            excluded(&root);
            assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
            resume.send(()).unwrap();
        });
        drop(engine);
    });
    let status = app_slot::job_status_fixture(root, transaction)
        .unwrap()
        .unwrap();
    assert_eq!(status.phase, app_slot::Phase::Published);
    assert!(!status.archived);
    assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(
        fs::read(root.join("native-runtime-owner/state")).unwrap(),
        native
    );
    assert_eq!(native[44], 4);
    assert!(!root.join("trial-owner-started").exists());
    crate::update::app_slot::issuer_tests::assert_admission_released(root);
}
