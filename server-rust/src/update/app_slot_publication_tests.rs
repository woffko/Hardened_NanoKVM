use super::*;
use crate::native_owner::broker::app_install::ClosedRuntime;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

fn current(root: &Path) -> PathBuf {
    root.join(DIRECTORY).join(CURRENT)
}

#[tokio::test]
async fn another_transactions_native_closure_never_authorizes_publication_or_rollback() {
    let root = tempfile::tempdir().unwrap();
    let mut install = issuer_tests::accepted_fixture(root.path()).await;
    let before = fs::read(current(root.path()).join(STATE)).unwrap();
    let mut other = install.transaction();
    other[0] ^= 0xff;
    let closed = ClosedRuntime::fixture(other);
    assert!(matches!(install.publish(&closed), Err(SlotError::Invalid)));
    assert!(matches!(install.rollback(&closed), Err(SlotError::Invalid)));
    assert_eq!(fs::read(current(root.path()).join(STATE)).unwrap(), before);
    assert_eq!(
        fs::read(root.path().join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
}

#[tokio::test]
async fn unsafe_old_mutable_state_never_changes_the_live_slot_or_canonical_phase() {
    for kind in 0..5 {
        let root = tempfile::tempdir().unwrap();
        let mut install = issuer_tests::accepted_fixture(root.path()).await;
        let directory = root.path().join("kvmapp/kvm");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("ap.pass");
        match kind {
            0 => {
                fs::write(directory.join("real"), b"synthetic secret").unwrap();
                symlink("real", &path).unwrap();
            }
            1 => {
                fs::write(&path, b"synthetic secret").unwrap();
                fs::hard_link(&path, directory.join("alias")).unwrap();
            }
            2 => {
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &path,
                    FileType::Fifo,
                    Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap();
            }
            3 => {
                fs::write(&path, vec![0; APP_STATE_BYTES as usize + 1]).unwrap();
            }
            _ => {
                fs::write(&path, b"synthetic secret").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
            }
        }
        let before = fs::read(current(root.path()).join(STATE)).unwrap();
        let old = root.path().join("kvmapp").metadata().unwrap().ino();
        let closed = ClosedRuntime::fixture(install.transaction());
        assert!(install.publish(&closed).is_err());
        assert_eq!(root.path().join("kvmapp").metadata().unwrap().ino(), old);
        assert_eq!(fs::read(current(root.path()).join(STATE)).unwrap(), before);
        assert_eq!(
            install.rollback(&closed).unwrap(),
            Status::Transaction(Phase::RolledBack)
        );
    }
}

#[tokio::test]
async fn absence_is_preserved_without_importing_arbitrary_old_code_or_defaults() {
    let root = tempfile::tempdir().unwrap();
    let mut install = issuer_tests::accepted_fixture(root.path()).await;
    fs::create_dir(root.path().join("kvmapp/kvm")).unwrap();
    fs::write(
        root.path().join("kvmapp/kvm/untrusted-script"),
        b"never copy old code",
    )
    .unwrap();
    let target = current(root.path()).join("new/kvm");
    fs::create_dir(&target).unwrap();
    for name in APP_STATE {
        fs::write(
            target.join(name),
            b"factory default must not replace absence",
        )
        .unwrap();
    }
    fs::write(target.join("packaged-data"), b"keep new package data").unwrap();
    let closed = ClosedRuntime::fixture(install.transaction());
    assert_eq!(
        install.publish(&closed).unwrap(),
        Status::Transaction(Phase::Published)
    );
    for name in APP_STATE {
        assert!(!root.path().join("kvmapp/kvm").join(name).exists());
    }
    assert!(!root.path().join("kvmapp/kvm/untrusted-script").exists());
    assert_eq!(
        fs::read(root.path().join("kvmapp/kvm/packaged-data")).unwrap(),
        b"keep new package data"
    );
    assert_eq!(
        install.rollback(&closed).unwrap(),
        Status::Transaction(Phase::RolledBack)
    );
    assert_eq!(
        fs::read(root.path().join("kvmapp/kvm/untrusted-script")).unwrap(),
        b"never copy old code"
    );
}

#[test]
fn app_data_overlay_is_exactly_the_existing_restore_allowlist_subset() {
    use std::collections::BTreeSet;
    let expected: BTreeSet<_> = super::super::restore_policy::FIXED
        .iter()
        .filter_map(|path| path.strip_prefix("kvmapp/kvm/"))
        .collect();
    assert_eq!(APP_STATE.into_iter().collect::<BTreeSet<_>>(), expected);
}

#[test]
fn publication_crash_child() {
    let Some(root) = std::env::var_os("NANOKVM_APP_PUBLICATION_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let mut install = runtime.block_on(issuer_tests::accepted_fixture(&root));
    fs::create_dir(root.join("kvmapp/kvm")).unwrap();
    for name in APP_STATE {
        fs::write(
            root.join("kvmapp/kvm").join(name),
            b"synthetic bounded state",
        )
        .unwrap();
    }
    // Filesystem crash component only: real three-scope native closure is
    // independently exercised by broker::app_install tests.
    install
        .publish(&ClosedRuntime::fixture(install.transaction()))
        .unwrap();
    panic!("parent must kill the child at the selected publication checkpoint");
}

#[test]
fn every_data_journal_and_slot_rename_crash_boundary_recovers_the_recorded_old_app() {
    let mut stops = Vec::new();
    for name in APP_STATE {
        stops.push(format!("app-state-{name}"));
    }
    for phase in ["publishing", "published"] {
        for step in [
            "record-written",
            "record-synced",
            "record-renamed",
            "record-published",
        ] {
            stops.push(format!("{phase}:{step}"));
        }
    }
    stops.extend(
        [
            "publish-old-parked",
            "publish-old-parked-synced",
            "publish-new-live",
            "publish-new-live-synced",
        ]
        .map(String::from),
    );
    for stop in stops {
        let root = tempfile::tempdir().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_slot::publication_tests::publication_crash_child",
                "--nocapture",
            ])
            .env("NANOKVM_APP_PUBLICATION_ROOT", root.path())
            .env("NANOKVM_APP_SLOT_TEST_STOP", &stop)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.unwrap().trim_end().ends_with("slot-checkpoint-ready") {
                    tx.send(()).unwrap();
                    break;
                }
            }
        });
        let ready = rx.recv_timeout(Duration::from_secs(15));
        child.kill().unwrap();
        let output = child.wait_with_output().unwrap();
        reader.join().unwrap();
        assert!(
            ready.is_ok(),
            "checkpoint {stop}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _admission = ProcessLock::from_parent(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap();
        let store = Store::at_root(
            File::open(root.path()).unwrap(),
            File::open(root.path().join(DIRECTORY)).unwrap(),
            nix::unistd::geteuid().as_raw(),
            true,
        )
        .unwrap()
        .unwrap();
        let old = store.record().unwrap().old;
        assert_eq!(
            store.recover().unwrap(),
            Status::Transaction(Phase::RolledBack)
        );
        assert_eq!(
            root.path().join("kvmapp").metadata().unwrap().ino(),
            old.inode
        );
        assert_eq!(
            fs::read(root.path().join("kvmapp/identity")).unwrap(),
            b"old unchanged"
        );
        for name in APP_STATE {
            assert_eq!(
                fs::read(root.path().join("kvmapp/kvm").join(name)).unwrap(),
                b"synthetic bounded state"
            );
        }
        assert_eq!(
            store.recover().unwrap(),
            Status::Transaction(Phase::RolledBack)
        );
    }
}
