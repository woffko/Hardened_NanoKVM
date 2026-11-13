//! Filesystem/lifecycle-gate components. Private empty-group fixture tokens are
//! NOT proof of real process drain, trial health, power-cut or target acceptance.
use super::tests::{assert_old, fixture, run_probe, support};
use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn assert_new(root: &Path, plan: &Plan) {
    for (index, entry) in plan.entries.iter().enumerate() {
        let path = root
            .join(if index < 5 {
                "usr/libexec"
            } else {
                "etc/init.d"
            })
            .join(live_name(index));
        assert_eq!(path.metadata().unwrap().ino(), entry.new.identity.inode);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(fs::read(path).unwrap())),
            entry.new.sha256
        );
    }
}

fn live_inodes(root: &Path) -> [u64; COUNT] {
    std::array::from_fn(|index| {
        root.join(if index < 5 {
            "usr/libexec"
        } else {
            "etc/init.d"
        })
        .join(live_name(index))
        .metadata()
        .unwrap()
        .ino()
    })
}

#[tokio::test]
async fn exchange_and_restore_are_exact_idempotent_pairs_under_the_same_retained_guard() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    let closed = ClosedRuntime::fixture(install.transaction());
    let source = Sources::open(&install, &closed).unwrap();
    let before = install._store.record().unwrap().encode().unwrap();
    let mut prepared = stage(&mut install, closed, source).unwrap();
    prepared.exchange().unwrap();
    prepared.check_exchanged().unwrap();
    assert_new(root.path(), &prepared.plan);
    let live = live_inodes(root.path());
    prepared.exchange().unwrap();
    assert_eq!(live_inodes(root.path()), live);
    super::super::issuer_tests::assert_excluded(root.path());
    assert_eq!(
        prepared.install._store.record().unwrap().encode().unwrap(),
        before
    );
    prepared.restore_predecessor().unwrap();
    prepared.check().unwrap();
    assert_old(root.path(), &prepared.plan);
    prepared.restore_predecessor().unwrap();
    assert_old(root.path(), &prepared.plan);
    for _ in 0..2 {
        assert_eq!(
            prepared.install.rollback(&prepared.closed).unwrap(),
            super::super::Status::Transaction(AppPhase::RolledBack)
        );
        assert_old(root.path(), &prepared.plan);
    }
    assert!(require_clear(&prepared.install._store.rootfs, prepared.install._store.uid).is_err());
}

#[tokio::test]
async fn partial_staging_abort_retains_old_files_and_pending_evidence_after_terminal_app_record() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    let closed = ClosedRuntime::fixture(install.transaction());
    let sources = Sources::open(&install, &closed).unwrap();
    let prepared = stage(&mut install, closed, sources).unwrap();
    // Explicit filesystem-state fixture: the actual killed preparation
    // prefixes are covered separately. This does not mint native closure.
    let mut staging = prepared.plan.clone();
    staging.phase = SupportPhase::Staging;
    fs::write(
        support(root.path()).join(PLAN),
        staging
            .encode(
                prepared.install._store.uid,
                prepared.install._store.rootfs.metadata().unwrap().gid(),
            )
            .unwrap(),
    )
    .unwrap();
    for name in &NAMES[4..] {
        fs::remove_file(support(root.path()).join(name)).unwrap();
    }
    let before = inventory(&prepared.directories.support).unwrap();
    for _ in 0..2 {
        assert_eq!(
            prepared.install.rollback(&prepared.closed).unwrap(),
            super::super::Status::Transaction(AppPhase::RolledBack)
        );
        assert_old(root.path(), &staging);
        assert_eq!(inventory(&prepared.directories.support).unwrap(), before);
        assert!(
            load_plan(&prepared.directories, &prepared.install._store, PLAN).unwrap() == staging
        );
        assert!(
            require_clear(&prepared.install._store.rootfs, prepared.install._store.uid).is_err()
        );
        super::super::issuer_tests::assert_excluded(root.path());
    }
}

#[tokio::test]
async fn retained_closed_rollback_finishes_only_its_exact_pending_ready_publication() {
    for foreign in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut install = fixture(root.path()).await;
        let closed = ClosedRuntime::fixture(install.transaction());
        let sources = Sources::open(&install, &closed).unwrap();
        let prepared = stage(&mut install, closed, sources).unwrap();
        let mut staging = prepared.plan.clone();
        staging.phase = SupportPhase::Staging;
        let uid = prepared.install._store.uid;
        let gid = prepared.install._store.rootfs.metadata().unwrap().gid();
        fs::write(
            support(root.path()).join(PLAN),
            staging.encode(uid, gid).unwrap(),
        )
        .unwrap();
        fs::write(
            support(root.path()).join(NEXT),
            prepared.plan.encode(uid, gid).unwrap(),
        )
        .unwrap();
        fs::set_permissions(
            support(root.path()).join(NEXT),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        if foreign {
            // Retained accepted context must fail BEFORE promoting even a
            // checksum-valid same-canonical PLAN+NEXT edge.
            prepared.install.record.version = "555.0.0".into();
            assert!(prepared.install.rollback(&prepared.closed).is_err());
            assert!(
                load_plan(&prepared.directories, &prepared.install._store, PLAN).unwrap()
                    == staging
            );
            assert!(support(root.path()).join(NEXT).is_file());
        } else {
            assert_eq!(
                prepared.install.rollback(&prepared.closed).unwrap(),
                super::super::Status::Transaction(AppPhase::RolledBack)
            );
            assert!(
                load_plan(&prepared.directories, &prepared.install._store, PLAN).unwrap()
                    == prepared.plan
            );
            assert!(!support(root.path()).join(NEXT).exists());
            assert_old(root.path(), &prepared.plan);
        }
    }
}

#[tokio::test]
async fn app_publish_trial_and_rollback_observe_complete_support_before_slot_or_runtime_changes() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    let closed = ClosedRuntime::fixture(install.transaction());
    let sources = Sources::open(&install, &closed).unwrap();
    let mut prepared = stage(&mut install, closed, sources).unwrap();
    let before = prepared.install._store.record().unwrap().encode().unwrap();
    assert!(prepared.install.publish(&prepared.closed).is_err());
    assert_eq!(
        prepared.install._store.record().unwrap().encode().unwrap(),
        before
    );
    prepared.exchange().unwrap();
    assert_eq!(
        prepared.install.publish(&prepared.closed).unwrap(),
        super::super::Status::Transaction(AppPhase::Published)
    );
    prepared.install.check_trial(&prepared.closed).unwrap();
    prepared.restore_predecessor().unwrap();
    assert!(prepared.install.check_trial(&prepared.closed).is_err());
    // Re-exchange with the private low-level engine to exercise the actual
    // AcceptedInstall rollback hook from Published; no trial process is alive.
    reconcile_pairs(
        &prepared.install._store,
        &prepared.directories,
        &prepared.plan,
        Direction::New,
    )
    .unwrap();
    assert_eq!(
        prepared.install.rollback(&prepared.closed).unwrap(),
        super::super::Status::Transaction(AppPhase::RolledBack)
    );
    assert_old(root.path(), &prepared.plan);
    assert!(require_clear(&prepared.install._store.rootfs, prepared.install._store.uid).is_err());
    assert!(support(root.path()).join(PLAN).is_file());
    super::super::issuer_tests::assert_excluded(root.path());
}

#[tokio::test]
async fn canonical_committed_app_never_selects_old_support_even_after_unknown_ack() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    let closed = ClosedRuntime::fixture(install.transaction());
    let sources = Sources::open(&install, &closed).unwrap();
    let mut prepared = stage(&mut install, closed, sources).unwrap();
    prepared.exchange().unwrap();
    prepared.install.publish(&prepared.closed).unwrap();
    // Canonical commit-state fixture only, NOT a minted TrialReady/health proof.
    let mut record = prepared.install._store.record().unwrap();
    record.phase = AppPhase::Committed;
    prepared.install._store.publish(&record).unwrap();
    prepared.install.record = record;
    let before = live_inodes(root.path());
    assert!(prepared.restore_predecessor().is_err());
    assert!(prepared.install.rollback(&prepared.closed).is_err());
    assert!(
        reconcile_pairs(
            &prepared.install._store,
            &prepared.directories,
            &prepared.plan,
            Direction::Old
        )
        .is_err()
    );
    assert_eq!(live_inodes(root.path()), before);
    reconcile_pairs(
        &prepared.install._store,
        &prepared.directories,
        &prepared.plan,
        Direction::New,
    )
    .unwrap();
    assert_new(root.path(), &prepared.plan);
}

#[tokio::test]
async fn nonprefix_mixture_is_reconciled_but_any_unknown_late_pair_refuses_before_first_swap() {
    for damaged in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut install = fixture(root.path()).await;
        let closed = ClosedRuntime::fixture(install.transaction());
        let sources = Sources::open(&install, &closed).unwrap();
        let mut prepared = stage(&mut install, closed, sources).unwrap();
        if damaged {
            fs::write(support(root.path()).join(NAMES[8]), b"unknown late pair").unwrap();
            let before = live_inodes(root.path());
            assert!(prepared.exchange().is_err());
            assert_eq!(live_inodes(root.path()), before);
        } else {
            for index in [0, 2, 4, 6, 8] {
                renameat_with(
                    prepared.directories.live(index),
                    live_name(index),
                    &prepared.directories.support,
                    NAMES[index],
                    RenameFlags::EXCHANGE,
                )
                .unwrap();
            }
            prepared.exchange().unwrap();
            assert_new(root.path(), &prepared.plan);
            prepared.restore_predecessor().unwrap();
            assert_old(root.path(), &prepared.plan);
        }
    }
}

#[tokio::test]
async fn empty_namespace_is_harmless_but_missing_plan_never_hides_staged_or_torn_evidence() {
    let root = tempfile::tempdir().unwrap();
    let mut install = fixture(root.path()).await;
    require_clear(&install._store.rootfs, install._store.uid).unwrap();
    let closed = ClosedRuntime::fixture(install.transaction());
    let sources = Sources::open(&install, &closed).unwrap();
    let prepared = stage(&mut install, closed, sources).unwrap();
    fs::remove_file(support(root.path()).join(PLAN)).unwrap();
    assert!(require_clear(&prepared.install._store.rootfs, prepared.install._store.uid).is_err());
    assert!(prepared.install.check_trial(&prepared.closed).is_err());
    assert!(before_publish(prepared.install, &prepared.closed).is_err());
    assert!(before_rollback(prepared.install, &prepared.closed).is_err());
    assert_eq!(fs::read_dir(support(root.path())).unwrap().count(), COUNT);
}

#[test]
fn every_exchange_parent_sync_and_restore_prefix_reopens_exact_pairs_after_process_death_or_io_error()
 {
    for action in ["new", "old"] {
        for fault in [false, true] {
            for index in 0..COUNT {
                for step in ["renamed", "live-synced", "stage-synced"] {
                    let point = format!("{action}-{step}-{index}");
                    let root = tempfile::tempdir().unwrap();
                    run_probe(
                        root.path(),
                        if fault {
                            "NANOKVM_SUPPORT_FAULT"
                        } else {
                            "NANOKVM_SUPPORT_STOP"
                        },
                        &point,
                        !fault,
                        action,
                    );
                    let uid = nix::unistd::geteuid().as_raw();
                    let store = Store::at_root(
                        File::open(root.path()).unwrap(),
                        File::open(root.path().join("application-slot")).unwrap(),
                        uid,
                        true,
                    )
                    .unwrap()
                    .unwrap();
                    let directories = Directories::existing(&store).unwrap().unwrap();
                    let plan = load_plan(&directories, &store, PLAN).unwrap();
                    assert!(plan.phase == SupportPhase::Ready);
                    let record = bound_record(&store, &plan).unwrap();
                    assert_eq!(record.phase, AppPhase::Prepared);
                    plan.check_layout(
                        record.phase,
                        &inspect_layout(&directories, &store, &plan).unwrap(),
                    )
                    .unwrap();
                    // Filesystem component restart only. Real runtime recovery
                    // must retain FencedAppRecovery/update/writer ownership.
                    reconcile_pairs(&store, &directories, &plan, Direction::New).unwrap();
                    assert_new(root.path(), &plan);
                    let before = live_inodes(root.path());
                    reconcile_pairs(&store, &directories, &plan, Direction::New).unwrap();
                    assert_eq!(live_inodes(root.path()), before);
                    reconcile_pairs(&store, &directories, &plan, Direction::Old).unwrap();
                    reconcile_pairs(&store, &directories, &plan, Direction::Old).unwrap();
                    assert_old(root.path(), &plan);
                    assert!(require_clear(&store.rootfs, store.uid).is_err());
                }
            }
        }
    }
}
