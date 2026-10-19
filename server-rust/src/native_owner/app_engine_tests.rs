use super::*;
use crate::update::app_slot::issuer_tests::{assert_excluded, prepared_fixture, received_fixture};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn start_all(engine: &mut Engine) {
    for operation in [
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::EnsureBackend,
    ] {
        assert_eq!(engine.request(1, operation).code, Code::Ok);
    }
    until(|| {
        engine.tick();
        engine.roles == [2; 2] && engine.backend_status == Some(Status::Running)
    });
}

async fn accept(engine: &mut Engine, root: &Path) -> (u64, [u8; 16]) {
    let (owner, prepared) = prepared_fixture(root).await;
    let transaction = prepared.transaction();
    let old = root.join("kvmapp").metadata().unwrap().ino();
    let admission = received_fixture(root, prepared);
    assert_eq!(engine.accept_install(admission), Code::Ok);
    drop(owner);
    (old, transaction)
}

fn phase(root: &Path) -> u8 {
    fs::read(root.join("application-slot/current/state")).unwrap()[8]
}

fn shutdown(engine: &mut Engine) {
    assert_eq!(engine.request(1, Operation::Shutdown).code, Code::Ok);
    until(|| {
        engine.tick();
        engine.mode == Mode::Stopped
    });
}

#[tokio::test]
async fn engine_drives_trial_commit_and_post_freeze_supervision_without_early_success() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("trial-ready-hold"), b"hold").unwrap();
    fs::write(root.join("trial-ack-hold"), b"hold").unwrap();
    let mut engine = engine(root);
    start_all(&mut engine);
    let native = [
        fs::read(root.join("kvm")).unwrap(),
        fs::read(root.join("hwmon")).unwrap(),
    ];
    let (old, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        root.join("trial-owner-started").exists()
    });
    assert_eq!(engine.mode, Mode::Installing);
    assert_eq!(engine.roles, [4; 2]);
    assert!(matches!(
        engine.install.as_ref().unwrap().owner,
        InstallOwner::Trial(_)
    ));
    assert_eq!(phase(root), app_slot::Phase::Published as u8);
    assert_excluded(root);
    for op in [
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::EnsureBackend,
        Operation::Shutdown,
    ] {
        assert_eq!(engine.request(2, op).code, Code::Busy);
    }
    assert_eq!(
        engine.request(2, Operation::BackendRunning).code,
        Code::Unavailable
    );
    fs::remove_file(root.join("trial-ready-hold")).unwrap();
    until(|| {
        engine.tick();
        fs::read(root.join("trial-authorized"))
            .is_ok_and(|bytes| bytes.len() == crate::app_trial_wire::BYTES)
    });
    assert_eq!(phase(root), app_slot::Phase::Committed as u8);
    assert_eq!(engine.mode, Mode::Installing);
    assert!(engine.install.as_ref().unwrap().stage == InstallStage::CommitPending);
    assert_eq!(
        engine.request(2, Operation::BackendRunning).code,
        Code::Unavailable
    );
    assert_eq!(
        engine.request(2, Operation::CancelAppInstall).code,
        Code::Busy
    );
    assert!(!root.join("trial-stopping").exists());
    assert_excluded(root);
    assert_eq!(fs::read(root.join("kvm")).unwrap(), native[0]);
    assert_eq!(fs::read(root.join("hwmon")).unwrap(), native[1]);
    let commit: [u8; crate::app_trial_wire::BYTES] = fs::read(root.join("trial-authorized"))
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        crate::app_trial_wire::parse(&commit, crate::app_trial_wire::Event::Commit).unwrap(),
        transaction
    );
    fs::remove_file(root.join("trial-ack-hold")).unwrap();
    until(|| {
        engine.tick();
        engine.install.is_none()
            && engine.mode == Mode::Running
            && engine.roles == [2; 2]
            && engine.backend_status == Some(Status::Running)
    });
    assert_eq!(engine.request(2, Operation::BackendRunning).code, Code::Ok);
    assert_ne!(fs::read(root.join("kvm")).unwrap(), native[0]);
    assert_ne!(fs::read(root.join("hwmon")).unwrap(), native[1]);
    assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(
        engine.request(2, Operation::CancelAppInstall).code,
        Code::Busy
    );
    assert_eq!(phase(root), app_slot::Phase::Committed as u8);
    drop(
        crate::update::operation_lock::ProcessLock::from_parent(
            &File::open(root).unwrap(),
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap(),
    );
    shutdown(&mut engine);
}

#[tokio::test]
async fn failed_trial_is_joined_before_automatic_uncommitted_rollback_and_old_restart() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("trial-ready-fail"), b"fail").unwrap();
    fs::write(root.join("trial-stop-hold"), b"hold").unwrap();
    let mut engine = engine(root);
    start_all(&mut engine);
    let (old, _) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        root.join("trial-stopping").exists()
    });
    for _ in 0..3 {
        engine.tick();
        assert_eq!(engine.mode, Mode::Installing);
        assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_excluded(root);
    }
    assert_eq!(phase(root), app_slot::Phase::Published as u8);
    assert!(!root.join("trial-authorized").exists());
    fs::remove_file(root.join("trial-stop-hold")).unwrap();
    until(|| {
        engine.tick();
        engine.install.is_none()
            && engine.mode == Mode::Running
            && engine.roles == [2; 2]
            && engine.backend_status == Some(Status::Running)
    });
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(
        fs::read(root.join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
    assert_eq!(phase(root), app_slot::Phase::RolledBack as u8);
    assert_eq!(engine.request(2, Operation::BackendRunning).code, Code::Ok);
    shutdown(&mut engine);
}

#[tokio::test]
async fn cancelled_trial_without_closure_receipt_never_rolls_back_or_releases_admission() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("trial-ready-hold"), b"hold").unwrap();
    fs::write(root.join("trial-missing-receipt"), b"missing").unwrap();
    let mut engine = engine(root);
    start_all(&mut engine);
    let (old, _) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        root.join("trial-owner-started").exists()
    });
    let pid = fs::read_to_string(root.join("trial-owner-started")).unwrap();
    let pid: u32 = pid.parse().unwrap();
    let cancelled = engine.request(2, Operation::CancelAppInstall);
    assert_eq!(cancelled.code, Code::Ok);
    assert_eq!(cancelled.mode, Mode::Installing);
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain && !Path::new("/proc").join(pid.to_string()).exists()
    });
    assert!(engine.install.as_ref().unwrap().stage == InstallStage::Failed);
    assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(phase(root), app_slot::Phase::Published as u8);
    assert!(!root.join("trial-authorized").exists());
    assert_excluded(root);
    assert_eq!(
        engine.request(2, Operation::CancelAppInstall).code,
        Code::Uncertain
    );
    // The existing lifecycle protocol reports uncertainty over every nominal
    // Busy result while ownership is unresolved; it does not grant shutdown.
    assert_eq!(engine.request(2, Operation::Shutdown).code, Code::Uncertain);
    assert_excluded(root);
}

#[tokio::test]
async fn commit_publication_failure_retains_engine_owner_and_never_retries_or_reverts_committed_app()
 {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("trial-ready-hold"), b"hold").unwrap();
    fs::write(root.join("trial-allow-controller-loss"), b"fixture cleanup").unwrap();
    let mut engine = engine(root);
    let (old, _) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        root.join("trial-owner-started").exists()
    });
    let pid: i32 = fs::read_to_string(root.join("trial-owner-started"))
        .unwrap()
        .parse()
        .unwrap();
    let next = root.join("native-runtime-owner/.state.next");
    fs::write(&next, b"retain collision").unwrap();
    fs::set_permissions(&next, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(root.join("trial-ready-hold")).unwrap();
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    assert!(matches!(
        engine.install.as_ref().unwrap().owner,
        InstallOwner::Trial(_)
    ));
    assert!(engine.install.as_ref().unwrap().stage == InstallStage::Failed);
    assert_eq!(phase(root), app_slot::Phase::Committed as u8);
    assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(fs::read(&next).unwrap(), b"retain collision");
    assert_eq!(
        fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
        4
    );
    for _ in 0..3 {
        engine.tick();
        assert_eq!(engine.mode, Mode::Uncertain);
        assert_eq!(
            engine.request(2, Operation::CancelAppInstall).code,
            Code::Uncertain
        );
        assert_excluded(root);
        assert!(!root.join("trial-authorized").exists());
        assert!(!root.join("trial-stopping").exists());
    }
    // Deliberately forfeit this childless fixture's controller after all
    // retention assertions; then reap the exact exec child, without claiming
    // native closure or rollback authority from its death.
    drop(engine);
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
    assert_eq!(phase(root), app_slot::Phase::Committed as u8);
    assert_eq!(fs::read(&next).unwrap(), b"retain collision");
}
