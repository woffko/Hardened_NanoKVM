use super::*;
use crate::update::app_slot::issuer_tests::{assert_excluded, prepared_fixture, received_fixture};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[path = "app_engine_support_tests.rs"]
mod support;

#[path = "app_retirement_tests.rs"]
mod retirement;

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

fn phase(root: &Path, transaction: [u8; 16]) -> u8 {
    app_slot::job_status_fixture(root, transaction)
        .unwrap()
        .unwrap()
        .phase as u8
}

fn shutdown(engine: &mut Engine) {
    // A transferred lease's last CLOEXEC alias can remain in another parallel
    // fixture's fork-before-exec window. A confirmed Busy/Running reply means
    // Shutdown was not admitted, not unknown completion. Do not force unlock,
    // accept uncertainty or retry an already admitted shutdown.
    until(|| {
        let reply = engine.request(1, Operation::Shutdown);
        if reply.code == Code::Busy {
            assert_eq!(reply.mode, Mode::Running);
            assert!(engine.install.is_none());
            return false;
        }
        assert_eq!(reply.code, Code::Ok);
        true
    });
    until(|| {
        engine.tick();
        engine.mode == Mode::Stopped
    });
}

fn install_state(engine: &Engine) -> Option<(&'static str, &'static str)> {
    engine.install.as_ref().map(|install| {
        let stage = match install.stage {
            InstallStage::Draining => "draining",
            InstallStage::PreparingSupport => "preparing-support",
            InstallStage::SupportReady => "support-ready",
            InstallStage::Published => "published",
            InstallStage::Trial => "trial",
            InstallStage::CommitPending => "commit-pending",
            InstallStage::Rollback => "rollback",
            InstallStage::Retiring => "retiring",
            InstallStage::Failed => "failed",
        };
        let owner = match &install.owner {
            InstallOwner::Draining(_) => "draining",
            InstallOwner::PreparingSupport { .. } => "preparing-support",
            InstallOwner::Trial(_) => "trial",
            InstallOwner::Committed(_) => "committed",
            InstallOwner::RolledBack(_) => "rolled-back",
            InstallOwner::Refused { .. } => "refused",
        };
        (stage, owner)
    })
}

fn normal_install_until(engine: &mut Engine, root: &Path, transaction: [u8; 16], sequence: usize) {
    let started = Instant::now();
    loop {
        let before = install_state(engine);
        let tick_started = Instant::now();
        engine.tick();
        let tick_duration = tick_started.elapsed();
        let after = install_state(engine);
        if before != after || tick_duration >= Duration::from_millis(100) {
            eprintln!(
                "payload-prelude-tick: sequence={sequence}, before={before:?}, after={after:?}, mode={:?}, roles={:?}, backend={:?}, tick_duration={tick_duration:?}, elapsed={:?}",
                engine.mode,
                engine.roles,
                engine.backend_status,
                started.elapsed()
            );
        }
        if engine.install.is_none()
            && engine.mode == Mode::Running
            && engine.roles == [2; 2]
            && engine.backend_status == Some(Status::Running)
        {
            return;
        }
        if started.elapsed() >= FIXTURE_WAIT {
            let receipt = app_slot::job_status_fixture(root, transaction)
                .ok()
                .flatten()
                .map(|status| (status.phase as u8, status.archived));
            panic!(
                "payload-prune prelude timeout BEFORE fault injection: sequence={sequence}, transaction={transaction:02x?}, stage={after:?}, mode={:?}, roles={:?}, backend={:?}, receipt={receipt:?}, tick_duration={tick_duration:?}, elapsed={:?}",
                engine.mode,
                engine.roles,
                engine.backend_status,
                started.elapsed()
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn retry_with_unrepaired_fault(engine: &mut Engine, root: &Path) {
    let reply = engine.request(2, Operation::RetryAppRetirement);
    assert_eq!(reply.code, Code::Ok);
    assert_eq!(reply.mode, Mode::Installing);
    assert_excluded(root);
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    assert_excluded(root);
    assert!(engine.install.is_some());
}

#[test]
fn busy_shutdown_is_not_admitted_and_can_be_reissued_after_exact_lock_release() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = engine(root.path());
    let parent = std::fs::File::open(root.path()).unwrap();
    let held = crate::update::operation_lock::ProcessLock::from_parent(
        &parent,
        nix::unistd::geteuid().as_raw(),
    )
    .unwrap();
    let reply = engine.request(1, Operation::Shutdown);
    assert_eq!(reply.code, Code::Busy);
    assert_eq!(reply.mode, Mode::Running);
    assert!(!root.path().join("native-runtime-owner/state").exists());
    drop(held);
    shutdown(&mut engine);
    assert_eq!(engine.mode, Mode::Stopped);
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        2
    );
}

#[tokio::test]
async fn engine_drives_trial_commit_and_post_freeze_supervision_without_early_success() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("trial-ready-hold"), b"hold").unwrap();
    fs::write(root.join("trial-ack-hold"), b"hold").unwrap();
    let mut engine = engine(root);
    start_all(&mut engine);
    assert_eq!(
        engine.request(2, Operation::RetryAppRetirement).code,
        Code::Busy
    );
    let native = [
        fs::read(root.join("kvm")).unwrap(),
        fs::read(root.join("hwmon")).unwrap(),
    ];
    let (old, transaction) = accept(&mut engine, root).await;
    let predecessor_support = support::live(root);
    until(|| {
        engine.tick();
        root.join("trial-owner-started").exists()
    });
    assert_eq!(engine.mode, Mode::Installing);
    assert_eq!(engine.roles, [4; 2]);
    let successor_support = support::live(root);
    for (old, new) in predecessor_support.iter().zip(&successor_support) {
        assert_ne!(old.0, new.0);
        assert_ne!(old.1, new.1);
    }
    assert_eq!(support::evidence(root).len(), 10);
    assert!(matches!(
        engine.install.as_ref().unwrap().owner,
        InstallOwner::Trial(_)
    ));
    assert_eq!(phase(root, transaction), app_slot::Phase::Published as u8);
    assert_eq!(
        engine.request(2, Operation::RetryAppRetirement).code,
        Code::Busy
    );
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
    assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
    assert_eq!(support::live(root), successor_support);
    assert_eq!(support::evidence(root).len(), 10);
    assert_eq!(engine.mode, Mode::Installing);
    assert!(engine.install.as_ref().unwrap().stage == InstallStage::CommitPending);
    assert_eq!(
        engine.request(2, Operation::RetryAppRetirement).code,
        Code::Busy
    );
    assert_excluded(root);
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
    assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
    assert!(
        app_slot::job_status_fixture(root, transaction)
            .unwrap()
            .unwrap()
            .archived
    );
    assert!(!root.join("application-slot/current").exists());
    assert_eq!(support::live(root), successor_support);
    assert!(support::evidence(root).is_empty());
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
async fn successive_installs_keep_independent_durable_jobs_order_and_inactive_slots() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    engine.fixture_trace_starts = true;
    start_all(&mut engine);
    let mut previous = None;
    let mut baseline = None;
    for sequence in 1_u64..=3 {
        let (old, transaction) = accept(&mut engine, root).await;
        let baseline = *baseline.get_or_insert(old);
        let started = Instant::now();
        loop {
            let before = install_state(&engine);
            let before_mode = engine.mode;
            let before_roles = engine.roles;
            let tick_started = Instant::now();
            engine.tick();
            let tick_duration = tick_started.elapsed();
            let after = install_state(&engine);
            if before != after || tick_duration >= Duration::from_millis(100) {
                eprintln!(
                    "successive-install-tick: sequence={sequence}, before={before:?}/{before_mode:?}/{before_roles:?}, after={after:?}/{:?}/{:?}, backend={:?}, tick_duration={tick_duration:?}, elapsed={:?}",
                    engine.mode,
                    engine.roles,
                    engine.backend_status,
                    started.elapsed()
                );
            }
            if engine.install.is_none()
                && engine.mode == Mode::Running
                && engine.roles == [2; 2]
                && engine.backend_status == Some(Status::Running)
            {
                break;
            }
            if started.elapsed() >= FIXTURE_WAIT {
                let install = after;
                let receipt = app_slot::job_status_fixture(root, transaction)
                    .ok()
                    .flatten()
                    .map(|status| (status.phase as u8, status.archived));
                // Successive trials reuse marker paths: bind evidence to THIS
                // transaction, never the mere existence of a previous marker.
                let authorized = fs::read(root.join("trial-authorized"))
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .and_then(|bytes| {
                        crate::app_trial_wire::parse(&bytes, crate::app_trial_wire::Event::Commit)
                            .ok()
                    })
                    == Some(transaction);
                panic!(
                    "successive install timeout: sequence={sequence}, transaction={transaction:02x?}, mode={:?}, install={install:?}, roles={:?}, backend={:?}, receipt={receipt:?}, current_authorized={authorized}, tick_duration={tick_duration:?}, elapsed={:?}",
                    engine.mode,
                    engine.roles,
                    engine.backend_status,
                    started.elapsed()
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let status = app_slot::job_status_fixture(root, transaction)
            .unwrap()
            .unwrap();
        assert_eq!(status.phase, app_slot::Phase::Committed);
        assert!(status.archived);
        let archived = root
            .join("application-slot/history")
            .join(format!("{:032x}", u128::from_be_bytes(transaction)));
        assert_eq!(archived.join("old").metadata().unwrap().ino(), old);
        // Inspect the actual fixed on-disk v1 receipt, not a test-provided
        // retention decision. Baseline remains pinned across later commits.
        let head = fs::read(root.join("application-slot/history-head")).unwrap();
        assert_eq!(head.len(), 256);
        assert_eq!(&head[..8], b"NKAPPH01");
        assert_eq!(
            u64::from_le_bytes(head[8..16].try_into().unwrap()),
            sequence
        );
        assert_eq!(&head[16..32], &transaction);
        assert_eq!(
            u64::from_le_bytes(head[72..80].try_into().unwrap()),
            baseline
        );
        assert_eq!(u64::from_le_bytes(head[88..96].try_into().unwrap()), old);
        assert_eq!(fs::read(archived.join("order")).unwrap(), head);
        assert!(!root.join("application-slot/current").exists());
        if let Some(prior) = previous {
            assert_ne!(prior, transaction);
            let earlier = app_slot::job_status_fixture(root, prior).unwrap().unwrap();
            assert!(earlier.archived);
            assert_eq!(earlier.phase, app_slot::Phase::Committed);
            assert_eq!(earlier.inactive_payload_retained, sequence == 2);
        }
        previous = Some(transaction);
    }
    shutdown(&mut engine);
}

#[tokio::test]
async fn payload_prune_failure_retains_full_terminal_owner_until_explicit_root_retry() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let mut engine = engine(root);
    start_all(&mut engine);
    let mut transactions = Vec::new();
    for sequence in 1..=2 {
        let (_, transaction) = accept(&mut engine, root).await;
        normal_install_until(&mut engine, root, transaction, sequence);
        transactions.push(transaction);
    }
    let victim = root
        .join("application-slot/history")
        .join(format!("{:032x}", u128::from_be_bytes(transactions[1])));
    let collision = victim.join("payload-expired");
    // Admission now validates all history before issuing the candidate. Inject
    // this retirement fault only after that distinct boundary has succeeded.
    fs::remove_file(root.join("trial-owner-started")).unwrap();
    fs::write(root.join("trial-ready-hold"), b"hold for retirement fault").unwrap();
    let (_, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        root.join("trial-owner-started").exists()
    });
    fs::write(&collision, b"foreign expiry evidence").unwrap();
    fs::remove_file(root.join("trial-ready-hold")).unwrap();
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    assert!(matches!(
        engine.install.as_ref().unwrap().owner,
        InstallOwner::Committed(_)
    ));
    for _ in 0..3 {
        engine.tick();
        assert_excluded(root);
        assert_eq!(engine.mode, Mode::Uncertain);
        assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
        assert!(victim.join("old").exists());
        assert_eq!(fs::read(&collision).unwrap(), b"foreign expiry evidence");
        assert_eq!(
            engine.request(2, Operation::EnsureKvm).code,
            Code::Uncertain
        );
    }
    retry_with_unrepaired_fault(&mut engine, root);
    fs::remove_file(&collision).unwrap();
    engine.tick();
    assert_excluded(root);
    assert!(engine.install.is_some());
    assert_eq!(
        engine.request(2, Operation::RetryAppRetirement).code,
        Code::Ok
    );
    until(|| {
        engine.tick();
        engine.install.is_none()
            && engine.mode == Mode::Running
            && engine.roles == [2; 2]
            && engine.backend_status == Some(Status::Running)
    });
    let status = app_slot::job_status_fixture(root, transactions[1])
        .unwrap()
        .unwrap();
    assert!(status.archived && !status.inactive_payload_retained);
    assert!(
        app_slot::job_status_fixture(root, transactions[0])
            .unwrap()
            .unwrap()
            .inactive_payload_retained
    );
    assert!(!victim.join("old").exists());
    assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
    shutdown(&mut engine);
}

#[tokio::test]
async fn rollback_retirement_collision_retains_engine_exclusions_and_never_restarts_old_runtime() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("trial-ready-fail"), b"fail").unwrap();
    fs::write(root.join("trial-stop-hold"), b"hold").unwrap();
    let mut engine = engine(root);
    let (old, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        root.join("trial-stopping").exists()
    });
    let collision = root
        .join("application-slot/history")
        .join(format!("{:032x}", u128::from_be_bytes(transaction)));
    fs::create_dir_all(&collision).unwrap();
    fs::set_permissions(
        collision.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&collision, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(collision.join("foreign"), b"retain foreign archive").unwrap();
    fs::remove_file(root.join("trial-stop-hold")).unwrap();
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    assert!(matches!(
        engine.install.as_ref().unwrap().owner,
        InstallOwner::RolledBack(_)
    ));
    assert_eq!(
        fs::read(root.join("application-slot/current/state")).unwrap()[8],
        app_slot::Phase::RolledBack as u8
    );
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    for _ in 0..3 {
        engine.tick();
        assert_eq!(engine.mode, Mode::Uncertain);
        assert_excluded(root);
        assert_eq!(
            engine.request(2, Operation::EnsureBackend).code,
            Code::Uncertain
        );
        assert_eq!(
            engine.request(2, Operation::CancelAppInstall).code,
            Code::Uncertain
        );
        assert_eq!(
            fs::read(collision.join("foreign")).unwrap(),
            b"retain foreign archive"
        );
        assert!(!root.join("backend").exists());
    }
    retry_with_unrepaired_fault(&mut engine, root);
    assert_excluded(root);
    fs::remove_file(collision.join("foreign")).unwrap();
    fs::remove_dir(&collision).unwrap();
    // Repairing the known fixture collision does not implicitly retry/release.
    for _ in 0..3 {
        engine.tick();
        assert_excluded(root);
    }
    let reply = engine.request(2, Operation::RetryAppRetirement);
    assert_eq!(reply.code, Code::Ok);
    assert_eq!(reply.mode, Mode::Installing);
    assert_excluded(root);
    until(|| {
        engine.tick();
        engine.install.is_none() && engine.mode == Mode::Running
    });
    let snapshot = app_slot::job_status_fixture(root, transaction)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.phase, app_slot::Phase::RolledBack);
    assert!(snapshot.archived);
    assert_eq!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(
        engine.request(2, Operation::RetryAppRetirement).code,
        Code::Busy
    );
    shutdown(&mut engine);
}

#[test]
fn receipt_gc_failure_retains_engine_ownership_until_explicit_root_retry() {
    let root = tempfile::tempdir().unwrap();
    let fault = root.path().join("receipt-fault-once");
    fs::write(&fault, b"one exact receipt quarantine failure").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_owner::broker::ipc::tests::install_engine::receipt_gc_engine_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_RECEIPT_ENGINE_ROOT", root.path())
        .env("NANOKVM_APP_SLOT_TEST_FAIL", "receipt-quarantined")
        .env("NANOKVM_RECEIPT_TEST_FAIL_ONCE", &fault)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("receipt-engine-retained-and-retried")
    );
    assert!(!fault.exists());
}

#[tokio::test]
async fn receipt_gc_engine_child() {
    let Ok(root) = std::env::var("NANOKVM_RECEIPT_ENGINE_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let mut engine = engine(root);
    engine.fixture_trace_starts = true;
    start_all(&mut engine);
    let mut transactions = Vec::with_capacity(34);
    for sequence in 1..=34 {
        let (_, transaction) = accept(&mut engine, root).await;
        transactions.push(transaction);
        if sequence < 34 {
            receipt_engine_until(&mut engine, sequence, "retired/running", |engine| {
                engine.install.is_none()
                    && engine.mode == Mode::Running
                    && engine.roles == [2; 2]
                    && engine.backend_status == Some(Status::Running)
            });
        } else {
            receipt_engine_until(&mut engine, sequence, "retained uncertainty", |engine| {
                engine.mode == Mode::Uncertain
            });
        }
    }
    let transaction = transactions[33];
    let current = root.join("application-slot/current");
    assert!(current.join("receipt-manifest").exists());
    assert!(
        root.join("application-slot/history/.receipts-pruning")
            .exists()
    );
    assert!(!root.join("receipt-fault-once").exists());
    for _ in 0..3 {
        engine.tick();
        assert!(matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::Committed(_)
        ));
        assert_excluded(root);
        assert_eq!(engine.mode, Mode::Uncertain);
        assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
        assert!(matches!(
            app_slot::job_status_fixture(root, transactions[1]),
            Err(app_slot::SlotError::Busy)
        ));
        assert_eq!(
            engine.request(2, Operation::EnsureKvm).code,
            Code::Uncertain
        );
        assert!(current.join("receipt-manifest").exists());
    }
    assert_eq!(
        engine.request(2, Operation::RetryAppRetirement).code,
        Code::Ok
    );
    receipt_engine_until(
        &mut engine,
        34,
        "explicit retry retired/running",
        |engine| {
            engine.install.is_none()
                && engine.mode == Mode::Running
                && engine.roles == [2; 2]
                && engine.backend_status == Some(Status::Running)
        },
    );
    assert!(
        app_slot::job_status_fixture(root, transactions[1])
            .unwrap()
            .is_none()
    );
    assert!(
        app_slot::job_status_fixture(root, transactions[0])
            .unwrap()
            .unwrap()
            .inactive_payload_retained
    );
    let latest = app_slot::job_status_fixture(root, transaction)
        .unwrap()
        .unwrap();
    assert!(latest.archived && latest.inactive_payload_retained);
    assert_eq!(latest.phase, app_slot::Phase::Committed);
    assert!(!current.exists());
    shutdown(&mut engine);
    println!("receipt-engine-retained-and-retried");
}

fn receipt_engine_until(
    engine: &mut Engine,
    sequence: u64,
    expected: &str,
    mut ready: impl FnMut(&Engine) -> bool,
) {
    // This34-install durability fixture competes with real fsync/SIGKILL
    // matrices in the full suite. Its observation budget is not a production
    // protocol deadline. Keep every exact state assertion and diagnose a stall
    // with its sequence/stage, rather than a context-free6s harness panic.
    let start = Instant::now();
    loop {
        let was_installing = engine.install.is_some();
        let tick_started = Instant::now();
        engine.tick();
        let tick_duration = tick_started.elapsed();
        if ready(engine) {
            return;
        }
        let stage = engine.install.as_ref().map(|install| match install.stage {
            InstallStage::Draining => "draining",
            InstallStage::PreparingSupport => "preparing-support",
            InstallStage::SupportReady => "support-ready",
            InstallStage::Published => "published",
            InstallStage::Trial => "trial",
            InstallStage::CommitPending => "commit-pending",
            InstallStage::Rollback => "rollback",
            InstallStage::Retiring => "retiring",
            InstallStage::Failed => "failed",
        });
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "sequence={sequence}, expected={expected}, mode={:?}, stage={stage:?}, roles={:?}, backend={:?}, was_installing={was_installing}, tick_duration={tick_duration:?}, wanted={:?}, retry_remaining={:?}",
            engine.mode,
            engine.roles,
            engine.backend_status,
            engine.wanted,
            engine
                .retry
                .map(|retry| retry.saturating_duration_since(Instant::now()))
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[tokio::test]
async fn committed_retirement_collision_keeps_terminal_owner_without_retry_revert_or_native_restart()
 {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("trial-ack-hold"), b"hold").unwrap();
    fs::write(root.join("trial-allow-controller-loss"), b"fixture cleanup").unwrap();
    let mut engine = engine(root);
    let (old, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        root.join("trial-authorized").exists()
    });
    let collision = root
        .join("application-slot/history")
        .join(format!("{:032x}", u128::from_be_bytes(transaction)));
    fs::create_dir_all(&collision).unwrap();
    fs::set_permissions(
        collision.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&collision, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(collision.join("foreign"), b"retain foreign archive").unwrap();
    fs::remove_file(root.join("trial-ack-hold")).unwrap();
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    assert!(matches!(
        engine.install.as_ref().unwrap().owner,
        InstallOwner::Committed(_)
    ));
    for _ in 0..3 {
        engine.tick();
        assert_eq!(engine.mode, Mode::Uncertain);
        assert_excluded(root);
        assert_eq!(
            engine.request(2, Operation::EnsureKvm).code,
            Code::Uncertain
        );
        assert_eq!(
            engine.request(2, Operation::BackendRunning).code,
            Code::Uncertain
        );
        assert_eq!(
            engine.request(2, Operation::CancelAppInstall).code,
            Code::Uncertain
        );
        assert_eq!(
            fs::read(root.join("application-slot/current/state")).unwrap()[8],
            app_slot::Phase::Committed as u8
        );
        assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(
            fs::read(collision.join("foreign")).unwrap(),
            b"retain foreign archive"
        );
        assert!(!root.join("trial-stopping").exists());
        assert!(!root.join("kvm").exists());
        assert!(!root.join("hwmon").exists());
    }
    retry_with_unrepaired_fault(&mut engine, root);
    assert_excluded(root);
    fs::remove_file(collision.join("foreign")).unwrap();
    fs::remove_dir(&collision).unwrap();
    for _ in 0..3 {
        engine.tick();
        assert_excluded(root);
    }
    let reply = engine.request(2, Operation::RetryAppRetirement);
    assert_eq!(reply.code, Code::Ok);
    assert_eq!(reply.mode, Mode::Installing);
    assert_excluded(root);
    until(|| {
        engine.tick();
        engine.install.is_none()
            && engine.mode == Mode::Running
            && engine.backend_status == Some(Status::Running)
    });
    let snapshot = app_slot::job_status_fixture(root, transaction)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.phase, app_slot::Phase::Committed);
    assert!(snapshot.archived);
    assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
    assert!(!root.join("trial-stopping").exists());
    assert_eq!(
        engine.request(2, Operation::RetryAppRetirement).code,
        Code::Busy
    );
    shutdown(&mut engine);
    assert!(!root.join("trial-controller-lost").exists());
}

#[tokio::test]
async fn terminal_retry_cannot_clear_later_owner_loss_even_after_the_archive_collision_is_removed()
{
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("trial-ack-hold"), b"hold").unwrap();
    let mut engine = engine(root);
    let (_, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        root.join("trial-authorized").exists()
    });
    let pid: i32 = fs::read_to_string(root.join("trial-owner-started"))
        .unwrap()
        .parse()
        .unwrap();
    let collision = root
        .join("application-slot/history")
        .join(format!("{:032x}", u128::from_be_bytes(transaction)));
    fs::create_dir_all(&collision).unwrap();
    fs::set_permissions(
        collision.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&collision, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(root.join("trial-ack-hold")).unwrap();
    until(|| {
        engine.tick();
        matches!(
            engine.install.as_ref().map(|i| &i.owner),
            Some(InstallOwner::Committed(_))
        )
    });
    // Exact childless fixture owner, not an arbitrary PID or target process.
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();
    until(|| {
        engine.tick();
        engine.backend_status == Some(Status::Uncertain)
            && !Path::new("/proc").join(pid.to_string()).exists()
    });
    fs::remove_dir(&collision).unwrap();
    for _ in 0..3 {
        assert_eq!(
            engine.request(2, Operation::RetryAppRetirement).code,
            Code::Uncertain
        );
        assert_excluded(root);
        assert!(matches!(
            engine.install.as_ref().unwrap().owner,
            InstallOwner::Committed(_)
        ));
        assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
        assert!(!collision.exists());
        assert!(root.join("application-slot/current").exists());
    }
    // The group reaped the exact probe but did not receive a closure receipt.
    // No owner destruction, PID disappearance or retry grants closure.
    drop(engine);
}

#[tokio::test]
async fn failed_trial_is_joined_before_automatic_uncommitted_rollback_and_old_restart() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("trial-ready-fail"), b"fail").unwrap();
    fs::write(root.join("trial-stop-hold"), b"hold").unwrap();
    let mut engine = engine(root);
    start_all(&mut engine);
    let (old, transaction) = accept(&mut engine, root).await;
    let predecessor_support = support::live(root);
    until(|| {
        engine.tick();
        root.join("trial-stopping").exists()
    });
    let successor_support = support::live(root);
    assert_ne!(successor_support, predecessor_support);
    for _ in 0..3 {
        engine.tick();
        assert_eq!(engine.mode, Mode::Installing);
        assert_ne!(root.join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(support::live(root), successor_support);
        assert_eq!(support::evidence(root).len(), 10);
        assert_excluded(root);
    }
    assert_eq!(phase(root, transaction), app_slot::Phase::Published as u8);
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
    assert_eq!(phase(root, transaction), app_slot::Phase::RolledBack as u8);
    assert!(
        app_slot::job_status_fixture(root, transaction)
            .unwrap()
            .unwrap()
            .archived
    );
    assert!(!root.join("application-slot/current").exists());
    assert_eq!(support::live(root), predecessor_support);
    assert!(support::evidence(root).is_empty());
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
    let (old, transaction) = accept(&mut engine, root).await;
    until(|| {
        engine.tick();
        root.join("trial-owner-started").exists()
    });
    let successor_support = support::live(root);
    let support_evidence = support::evidence(root);
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
    assert_eq!(phase(root, transaction), app_slot::Phase::Published as u8);
    assert!(!root.join("trial-authorized").exists());
    assert_eq!(support::live(root), successor_support);
    assert_eq!(support::evidence(root), support_evidence);
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
    let (old, transaction) = accept(&mut engine, root).await;
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
    assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
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
        assert_eq!(
            engine.request(2, Operation::RetryAppRetirement).code,
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
    assert_eq!(phase(root, transaction), app_slot::Phase::Committed as u8);
    assert_eq!(fs::read(&next).unwrap(), b"retain collision");
}
