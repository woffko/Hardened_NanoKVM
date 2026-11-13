//! Engine orchestration fixtures, not vendor runtime/device acceptance.
use super::*;
use crate::update::support_abi;
use sha2::{Digest, Sha256};
use std::sync::mpsc;

fn store_excluded(root: &Path) {
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

const LIVE: [&str; 9] = [
    "usr/libexec/nanokvm-app-recovery",
    "usr/libexec/nanokvm-native-owner",
    "usr/libexec/nanokvm-native-broker",
    "usr/libexec/nanokvm-native-ctl",
    "usr/libexec/nanokvm-native-recovery",
    "etc/init.d/S02apprecover",
    "etc/init.d/S30eth",
    "etc/init.d/S30wifi",
    "etc/init.d/S95nanokvm",
];

pub(super) fn live(root: &Path) -> [(u64, Vec<u8>); 9] {
    LIVE.map(|name| {
        let path = root.join(name);
        let metadata = path.metadata().unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o755);
        (metadata.ino(), fs::read(path).unwrap())
    })
}

pub(super) fn evidence(root: &Path) -> Vec<(std::ffi::OsString, u64, Vec<u8>)> {
    let path = root.join("etc/kvm/application-support");
    let mut entries = Vec::with_capacity(11);
    match fs::read_dir(path) {
        Ok(directory) => {
            for entry in directory {
                let entry = entry.unwrap();
                entries.push((
                    entry.file_name(),
                    entry.metadata().unwrap().ino(),
                    fs::read(entry.path()).unwrap(),
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => panic!("support evidence: {error}"),
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

fn preparing(engine: &mut Engine) {
    until(|| {
        if engine
            .install
            .as_ref()
            .is_some_and(|install| install.stage == InstallStage::PreparingSupport)
        {
            return true;
        }
        engine.tick();
        false
    });
}

fn refused(engine: &mut Engine, root: &Path, transaction: [u8; 16], old: u64) {
    let before = live(root);
    let state = fs::read(root.join("application-slot/current/state")).unwrap();
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    assert!(matches!(
        engine.install.as_ref().unwrap().owner,
        InstallOwner::Draining(_)
    ));
    assert!(engine.install.as_ref().unwrap().stage == InstallStage::Failed);
    let support = evidence(root);
    for _ in 0..3 {
        engine.tick();
        assert_eq!(engine.mode, Mode::Uncertain);
        assert_eq!(live(root), before);
        assert_eq!(evidence(root), support);
        assert_eq!(
            fs::read(root.join("application-slot/current/state")).unwrap(),
            state
        );
        assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(phase(root, transaction), app_slot::Phase::Prepared as u8);
        assert_excluded(root);
        assert!(!root.join("trial-owner-started").exists());
        assert!(!root.join("application-slot/history").exists());
    }
}

/// A verdict before staging: nothing changed, and the previous runtime resumes
/// instead of the device staying uncertain until a reboot.
fn resumed(engine: &mut Engine, root: &Path, transaction: [u8; 16], old: u64) {
    let before = live(root);
    until(|| {
        engine.tick();
        engine.install.is_none() && engine.mode == Mode::Running
    });
    assert_eq!(live(root), before);
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(phase(root, transaction), app_slot::Phase::RolledBack as u8);
    assert!(!root.join("application-slot/current").exists());
    assert!(!root.join("trial-owner-started").exists());
}

#[tokio::test]
async fn executing_epoch_one_stages_the_support_family_and_can_roll_back() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    let (old, transaction) = accept(&mut engine, root).await;
    let before = live(root);
    preparing(&mut engine);
    assert_eq!(support_abi::CURRENT.support_transition, 1);
    until(|| {
        engine.tick();
        engine
            .install
            .as_ref()
            .is_some_and(|install| install.stage == InstallStage::SupportReady)
    });
    assert_ne!(engine.mode, Mode::Uncertain);
    assert_eq!(evidence(root).len(), 10);
    assert_ne!(live(root), before);
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert!(!root.join("trial-owner-started").exists());
    assert_eq!(
        engine.request(1, Operation::CancelAppInstall).code,
        Code::Ok
    );
    until(|| {
        engine.tick();
        engine.install.is_none() && engine.mode == Mode::Running
    });
    assert_eq!(phase(root, transaction), app_slot::Phase::RolledBack as u8);
    assert_eq!(live(root), before);
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    shutdown(&mut engine);
}

#[tokio::test]
async fn absent_or_matching_unknown_source_contracts_never_select_the_executing_broker() {
    for unknown in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        let (old, transaction) = accept(&mut engine, root).await;
        preparing(&mut engine);
        for path in ["kvmapp", "application-slot/current/new"] {
            let backend = root.join(path).join("server/NanoKVM-Server");
            let mut bytes = fs::read(&backend).unwrap();
            let start = bytes.len() - support_abi::BYTES;
            assert_eq!(&bytes[start..start + 8], support_abi::MAGIC);
            if unknown {
                // BOTH app roots agree, but not with the retained executing
                // broker. Rehash the valid descriptor, not a malformed literal.
                bytes[start + 16..start + 20].copy_from_slice(&2_u32.to_le_bytes());
                let mut hash = Sha256::new();
                hash.update(b"NanoKVM support ABI descriptor v1\0");
                hash.update(&bytes[start..start + 96]);
                bytes[start + 96..].copy_from_slice(&hash.finalize());
                assert!(support_abi::checksummed(&bytes[start..]));
            } else {
                bytes.truncate(start);
            }
            fs::write(backend, bytes).unwrap();
        }
        resumed(&mut engine, root, transaction, old);
        assert!(!root.join("etc/kvm/application-support").exists());
    }
}

#[tokio::test]
async fn every_unknown_live_member_refuses_without_exchange_or_automatic_retry() {
    for name in LIVE {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        let (old, transaction) = accept(&mut engine, root).await;
        preparing(&mut engine);
        let path = root.join(name);
        fs::write(&path, b"unknown live support must not be replaced").unwrap();
        resumed(&mut engine, root, transaction, old);
        assert!(evidence(root).is_empty());
        assert_eq!(
            fs::read(path).unwrap(),
            b"unknown live support must not be replaced"
        );
    }
}

#[tokio::test]
async fn support_exchange_waits_for_all_three_scopes_and_can_abort_before_app_publication() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    start_all(&mut engine);
    fs::write(root.join("backend-stop-hold"), b"hold").unwrap();
    let (old, transaction) = accept(&mut engine, root).await;
    let predecessor = live(root);
    until(|| {
        engine.tick();
        root.join("backend-stopping").exists()
    });
    for _ in 0..3 {
        engine.tick();
        assert!(engine.install.as_ref().unwrap().stage == InstallStage::Draining);
        assert_eq!(live(root), predecessor);
        assert!(!root.join("etc/kvm/application-support").exists());
        assert_eq!(phase(root, transaction), app_slot::Phase::Prepared as u8);
        assert_excluded(root);
    }
    fs::remove_file(root.join("backend-stop-hold")).unwrap();
    preparing(&mut engine);
    assert!(!root.join("etc/kvm/application-support").exists());
    until(|| {
        engine.tick();
        engine.install.as_ref().unwrap().stage == InstallStage::SupportReady
    });
    let successor = live(root);
    for (before, after) in predecessor.iter().zip(&successor) {
        assert_ne!(before.0, after.0);
        assert_ne!(before.1, after.1);
    }
    assert_eq!(evidence(root).len(), 10);
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(phase(root, transaction), app_slot::Phase::Prepared as u8);
    assert_excluded(root);
    assert!(!root.join("trial-owner-started").exists());
    // Call the same owned cancel handler directly to target this precise
    // inter-tick boundary; request() normally ticks before handling its op.
    assert_eq!(engine.cancel_install(), Code::Ok);
    until(|| {
        engine.tick();
        engine.install.is_none() && engine.mode == Mode::Running
    });
    assert_eq!(live(root), predecessor);
    assert!(evidence(root).is_empty());
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(phase(root, transaction), app_slot::Phase::RolledBack as u8);
    assert!(!root.join("trial-owner-started").exists());
    shutdown(&mut engine);
}

#[tokio::test]
async fn unknown_support_after_exchange_blocks_app_publication_and_retains_exact_evidence() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    let (old, transaction) = accept(&mut engine, root).await;
    preparing(&mut engine);
    until(|| {
        engine.tick();
        engine.install.as_ref().unwrap().stage == InstallStage::SupportReady
    });
    let foreign = root.join("etc/kvm/application-support/foreign");
    fs::write(&foreign, b"retain unknown support evidence").unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o600)).unwrap();
    let support = evidence(root);
    refused(&mut engine, root, transaction, old);
    assert_eq!(evidence(root), support);
    assert_eq!(
        fs::read(foreign).unwrap(),
        b"retain unknown support evidence"
    );
}

#[tokio::test]
async fn blocked_support_before_and_after_io_keeps_control_responsive_and_queues_cancel_until_join()
{
    for after_io in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        let (entered, entering) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        engine.fixture_support = Some(if after_io {
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
        let predecessor = live(root);
        until(|| {
            engine.tick();
            entering.try_recv().is_ok()
        });
        assert!(matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::PreparingInstall { .. }
        ));
        let held_live = live(root);
        let held_evidence = evidence(root);
        assert_eq!(held_evidence.len(), if after_io { 10 } else { 0 });
        assert_eq!(held_live == predecessor, !after_io);
        engine.disconnected(1);
        engine.disconnected(2);
        for _ in 0..3 {
            for (operation, expected) in [
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
                assert_eq!(reply.code, expected, "{operation:?}");
                assert_eq!(reply.mode, Mode::Installing);
                assert_eq!(live(root), held_live);
                assert_eq!(evidence(root), held_evidence);
                assert_eq!(phase(root, transaction), app_slot::Phase::Prepared as u8);
                assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
                assert!(!root.join("trial-owner-started").exists());
                store_excluded(root);
            }
        }
        resume.send(()).unwrap();
        until(|| {
            engine.tick();
            engine.install.is_none() && engine.mode == Mode::Running
        });
        assert_eq!(phase(root, transaction), app_slot::Phase::RolledBack as u8);
        assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(live(root), predecessor);
        assert!(evidence(root).is_empty());
        assert!(!root.join("trial-owner-started").exists());
        shutdown(&mut engine);
    }
}

#[tokio::test]
async fn support_spawn_and_unwind_failure_preserve_owner_without_implicit_replay_or_publication() {
    for failure in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let mut engine = engine(root);
        engine.fixture_support = Some(match failure {
            0 => app_install::InstallIoFixture::SpawnFailure,
            1 => app_install::InstallIoFixture::Panic,
            _ => app_install::InstallIoFixture::PanicAfterIo,
        });
        let (old, transaction) = accept(&mut engine, root).await;
        let predecessor = live(root);
        until(|| {
            engine.tick();
            engine.mode == Mode::Uncertain
        });
        assert!(matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::Draining(_)
        ));
        let held_live = live(root);
        let held_evidence = evidence(root);
        assert_eq!(held_evidence.len(), if failure == 2 { 10 } else { 0 });
        for _ in 0..3 {
            engine.disconnected(1);
            engine.tick();
            assert_eq!(
                engine.request(2, Operation::RetryAppRetirement).code,
                Code::Uncertain
            );
            assert_eq!(engine.mode, Mode::Uncertain);
            assert_eq!(live(root), held_live);
            assert_eq!(evidence(root), held_evidence);
            assert_eq!(phase(root, transaction), app_slot::Phase::Prepared as u8);
            assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
            assert!(!root.join("trial-owner-started").exists());
            store_excluded(root);
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
        assert_eq!(live(root), predecessor);
        assert!(evidence(root).is_empty());
        assert!(!root.join("trial-owner-started").exists());
        shutdown(&mut engine);
    }
}

#[tokio::test]
async fn support_success_cannot_clear_native_journal_uncertainty_seen_during_worker_io() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    let (entered, entering) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    engine.fixture_support = Some(app_install::InstallIoFixture::Block {
        entered,
        resume: resumed,
    });
    let (old, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        entering.try_recv().is_ok()
    });
    let native_state = fs::read(root.join("native-runtime-owner/state")).unwrap();
    let cancellation = engine.request(2, Operation::CancelAppInstall);
    assert_eq!(cancellation.code, Code::Ok);
    assert_eq!(cancellation.mode, Mode::Installing);
    let foreign = root.join("native-runtime-owner/.state.next");
    fs::write(&foreign, b"known fixture journal collision").unwrap();
    let InstallOwner::PreparingInstall { owner, .. } = &mut engine.install.as_mut().unwrap().owner
    else {
        panic!("support worker was not retained");
    };
    owner.fixture_failed_stopping_publication();
    assert_eq!(engine.request(2, Operation::Observe).mode, Mode::Uncertain);
    store_excluded(root);
    fs::remove_file(foreign).unwrap();
    resume.send(()).unwrap();
    until(|| {
        engine.tick();
        matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::Draining(_)
        )
    });
    // Check the VERY FIRST result after join, before another request/tick could
    // conceal a transient Installing/Rollback state after native uncertainty.
    assert_eq!(engine.mode, Mode::Uncertain);
    assert!(engine.install.as_ref().unwrap().stage == InstallStage::Failed);
    assert_eq!(engine.backend_status, Some(Status::Uncertain));
    assert_eq!(evidence(root).len(), 10);
    for _ in 0..3 {
        assert_eq!(
            engine.request(2, Operation::CancelAppInstall).code,
            Code::Uncertain
        );
        assert_eq!(
            engine.request(2, Operation::RetryAppRetirement).code,
            Code::Uncertain
        );
        store_excluded(root);
        assert_eq!(phase(root, transaction), app_slot::Phase::Prepared as u8);
        assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(
            fs::read(root.join("native-runtime-owner/state")).unwrap(),
            native_state
        );
        assert!(!root.join("trial-owner-started").exists());
    }
    drop(engine);
}

#[tokio::test]
async fn support_teardown_joins_worker_keeps_admission_and_never_publishes_app_or_closed_native_state()
 {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    let (entered, entering) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    engine.fixture_support = Some(app_install::InstallIoFixture::Block {
        entered,
        resume: resumed,
    });
    let (old, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        entering.try_recv().is_ok()
    });
    let native_state = fs::read(root.join("native-runtime-owner/state")).unwrap();
    std::thread::scope(|scope| {
        let root = root.to_path_buf();
        scope.spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            store_excluded(&root);
            resume.send(()).unwrap();
        });
        drop(engine);
    });
    assert_eq!(phase(root, transaction), app_slot::Phase::Prepared as u8);
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(evidence(root).len(), 10);
    assert_eq!(
        fs::read(root.join("native-runtime-owner/state")).unwrap(),
        native_state
    );
    assert_eq!(native_state[44], 4);
    assert!(!root.join("trial-owner-started").exists());
    crate::update::app_slot::issuer_tests::assert_admission_released(root);
}
