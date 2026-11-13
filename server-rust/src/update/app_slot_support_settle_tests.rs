//! Filesystem settlement fixtures, not native closure, trial health or power-cut
//! acceptance. Production entry requires the SAME terminal lifetime capability.
use super::*;
use crate::update::app_slot::support::tests::{
    assert_old, fixture, run_probe, support, terminal_fixture,
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

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

fn write_plan(directories: &Directories, store: &Store, name: &str, plan: &Plan) {
    let path = format!("/proc/self/fd/{}/{name}", directories.support.as_raw_fd());
    fs::write(
        &path,
        plan.encode(store.uid, store.rootfs.metadata().unwrap().gid())
            .unwrap(),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn terminal_cleanup_removes_only_inactive_exact_members_and_plan_last_without_retiring_app() {
    for new in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut install = fixture(root.path()).await;
        let closed = ClosedRuntime::fixture(install.transaction());
        let sources = Sources::open(&install, &closed).unwrap();
        let mut prepared = stage(&mut install, closed, sources).unwrap();
        terminal_fixture(&mut prepared, new);
        let record = prepared.install._store.record().unwrap().encode().unwrap();
        let live = live_inodes(root.path());
        run(&prepared.install._store).unwrap();
        require_clear(&prepared.install._store.rootfs, prepared.install._store.uid).unwrap();
        run(&prepared.install._store).unwrap();
        assert_eq!(live_inodes(root.path()), live);
        assert_eq!(
            prepared.install._store.record().unwrap().encode().unwrap(),
            record
        );
        assert_eq!(inventory(&prepared.directories.support).unwrap(), 0);
        assert!(root.path().join("application-slot/current/state").is_file());
        assert!(!root.path().join("application-slot/history").exists());
        super::super::super::issuer_tests::assert_excluded(root.path());
    }
}

#[tokio::test]
async fn staging_abort_settles_only_known_missing_successors_and_never_a_committed_app() {
    for new in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut install = fixture(root.path()).await;
        let closed = ClosedRuntime::fixture(install.transaction());
        let sources = Sources::open(&install, &closed).unwrap();
        let mut prepared = stage(&mut install, closed, sources).unwrap();
        terminal_fixture(&mut prepared, new);
        let mut staging = prepared.plan.clone();
        staging.phase = SupportPhase::Staging;
        write_plan(
            &prepared.directories,
            &prepared.install._store,
            PLAN,
            &staging,
        );
        if !new {
            for name in &NAMES[3..] {
                fs::remove_file(support(root.path()).join(name)).unwrap();
            }
            run(&prepared.install._store).unwrap();
            assert_old(root.path(), &prepared.plan);
            assert_eq!(inventory(&prepared.directories.support).unwrap(), 0);
        } else {
            let before = inventory(&prepared.directories.support).unwrap();
            let live = live_inodes(root.path());
            assert!(run(&prepared.install._store).is_err());
            assert_eq!(inventory(&prepared.directories.support).unwrap(), before);
            assert_eq!(live_inodes(root.path()), live);
        }
    }
}

#[tokio::test]
async fn unknown_late_member_or_bad_next_never_allows_any_cleanup_or_live_exchange() {
    for kind in 0..7 {
        let root = tempfile::tempdir().unwrap();
        let mut install = fixture(root.path()).await;
        let closed = ClosedRuntime::fixture(install.transaction());
        let sources = Sources::open(&install, &closed).unwrap();
        let mut prepared = stage(&mut install, closed, sources).unwrap();
        terminal_fixture(&mut prepared, true);
        match kind {
            0 => {
                fs::write(
                    support(root.path()).join(NAMES[8]),
                    b"unknown inactive bytes",
                )
                .unwrap();
            }
            1 => {
                fs::remove_file(support(root.path()).join(NAMES[8])).unwrap();
            }
            2 => {
                fs::write(support(root.path()).join("foreign"), b"retain foreign").unwrap();
            }
            3 => {
                let next = prepared.plan.clone();
                write_plan(&prepared.directories, &prepared.install._store, NEXT, &next);
            }
            4 => {
                let mut next = prepared.plan.clone();
                next.phase = SupportPhase::CleanupNew;
                next.app.version = "777.0.0".into();
                write_plan(&prepared.directories, &prepared.install._store, NEXT, &next);
            }
            5 => {
                fs::write(support(root.path()).join(NEXT), b"torn").unwrap();
            }
            _ => {
                let mut next = prepared.plan.clone();
                next.phase = SupportPhase::CleanupOld;
                write_plan(&prepared.directories, &prepared.install._store, NEXT, &next);
            }
        }
        let live = live_inodes(root.path());
        let mut names: Vec<_> = fs::read_dir(support(root.path()))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        names.sort();
        assert!(run(&prepared.install._store).is_err());
        let mut after: Vec<_> = fs::read_dir(support(root.path()))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        after.sort();
        assert_eq!(after, names);
        assert_eq!(live_inodes(root.path()), live);
        assert!(
            load_plan(&prepared.directories, &prepared.install._store, PLAN).unwrap()
                == prepared.plan
        );
    }
}

#[test]
fn every_terminal_cleanup_and_pending_plan_rename_prefix_reopens_without_repeating_live_mutation() {
    for new in [false, true] {
        let action = if new { "cleanup-new" } else { "cleanup-old" };
        let mut points = Vec::with_capacity(27);
        for step in [
            "file-synced",
            "linked",
            "link-synced",
            "renamed",
            "rename-synced",
        ] {
            points.push((action, format!("{action}-plan-{step}")));
        }
        for index in 0..COUNT {
            for step in ["unlinked", "synced"] {
                points.push((action, format!("cleanup-member-{step}-{index}")));
            }
        }
        points.push((action, "cleanup-plan-unlinked".into()));
        points.push((action, "cleanup-empty-synced".into()));
        let next = if new {
            "cleanup-next-new"
        } else {
            "cleanup-next-old"
        };
        for step in ["renamed", "synced"] {
            points.push((next, format!("settlement-next-{step}")));
        }
        assert_eq!(points.len(), 27);
        for fault in [false, true] {
            for (action, point) in &points {
                let root = tempfile::tempdir().unwrap();
                run_probe(
                    root.path(),
                    if fault {
                        "NANOKVM_SUPPORT_FAULT"
                    } else {
                        "NANOKVM_SUPPORT_STOP"
                    },
                    point,
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
                let live = live_inodes(root.path());
                let before = store.record().unwrap().encode().unwrap();
                assert_eq!(
                    store.record().unwrap().phase,
                    if new {
                        AppPhase::Committed
                    } else {
                        AppPhase::RolledBack
                    }
                );
                run(&store).unwrap();
                run(&store).unwrap();
                require_clear(&store.rootfs, uid).unwrap();
                assert_eq!(live_inodes(root.path()), live);
                assert_eq!(store.record().unwrap().encode().unwrap(), before);
                assert_eq!(fs::read_dir(support(root.path())).unwrap().count(), 0);
                assert!(!root.path().join("application-slot/history").exists());
            }
        }
    }
}
