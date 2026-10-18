use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
const OTHER: &str = "87654321-4321-4321-4321-cba987654321";
const STEPS: [Step; 6] = [
    Step::BeforeCreate,
    Step::Created,
    Step::Written,
    Step::FileSynced,
    Step::Renamed,
    Step::DirectorySynced,
];

fn acquire(root: &Path, boot: &str) -> Result<Store, Error> {
    Store::fixture(
        &File::open(root).unwrap(),
        nix::unistd::geteuid().as_raw(),
        boot,
    )
}
fn private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn kernel_boot_epoch_is_stable_bounded_and_uses_the_ticket_parser() {
    assert!(Epoch::current().unwrap() == Epoch::current().unwrap());
    assert!(
        Epoch::parse(BOOT.as_bytes()).unwrap()
            == Epoch::parse(BOOT.to_uppercase().as_bytes()).unwrap()
    );
    for bytes in [
        b"".as_slice(),
        b"00000000-0000-0000-0000-000000000000",
        b"12345678-1234-1234-1234-123456789abg",
        b"12345678-1234-1234-1234-123456789abc\n",
    ] {
        assert!(Epoch::parse(bytes).is_err());
    }
}

#[test]
fn singleton_active_intent_survives_drop_but_clean_receipt_allows_reopen() {
    let root = tempfile::tempdir().unwrap();
    let mut store = acquire(root.path(), BOOT).unwrap();
    let inode = store.directory.metadata().unwrap().ino();
    assert!(matches!(acquire(root.path(), BOOT), Err(Error::Busy)));
    store.begin().unwrap();
    drop(store);
    assert!(matches!(acquire(root.path(), BOOT), Err(Error::Unresolved)));
    // A different actual boot proves only old process lifetimes ended.
    let mut store = acquire(root.path(), OTHER).unwrap();
    assert!(store.previous_boot());
    assert_eq!(store.directory.metadata().unwrap().ino(), inode);
    store.begin().unwrap();
    store.close().unwrap();
    drop(store);
    assert!(!acquire(root.path(), OTHER).unwrap().previous_boot());
}

#[test]
fn publication_failures_poison_the_live_store_and_preserve_evidence() {
    for step in STEPS {
        let root = tempfile::tempdir().unwrap();
        let mut store = acquire(root.path(), BOOT).unwrap();
        store.fail_at = Some(step);
        assert!(matches!(store.begin(), Err(Error::Ambiguous)));
        assert!(matches!(store.begin(), Err(Error::Ambiguous)));
        assert!(matches!(store.close(), Err(Error::Ambiguous)));
        drop(store);
        let next = acquire(root.path(), BOOT);
        match step {
            Step::BeforeCreate => assert!(next.is_ok()), // No launch permission was returned.
            Step::Created | Step::Written | Step::FileSynced => {
                assert!(matches!(next, Err(Error::Ambiguous)))
            }
            Step::Renamed | Step::DirectorySynced => {
                assert!(matches!(next, Err(Error::Unresolved)))
            }
        }
    }
}

#[test]
fn close_failure_never_clears_the_live_stores_uncertainty() {
    for step in STEPS {
        let root = tempfile::tempdir().unwrap();
        let mut store = acquire(root.path(), BOOT).unwrap();
        store.begin().unwrap();
        store.fail_at = Some(step);
        assert!(matches!(store.close(), Err(Error::Ambiguous)));
        assert!(matches!(store.begin(), Err(Error::Ambiguous)));
        drop(store);
        match step {
            Step::BeforeCreate => {
                assert!(matches!(acquire(root.path(), BOOT), Err(Error::Unresolved)))
            }
            Step::Created | Step::Written | Step::FileSynced => {
                assert!(matches!(acquire(root.path(), BOOT), Err(Error::Ambiguous)))
            }
            Step::Renamed | Step::DirectorySynced => assert!(acquire(root.path(), BOOT).is_ok()),
        }
    }
}

#[test]
fn canonical_closed_with_valid_looking_temporary_is_ambiguous_in_any_boot() {
    let root = tempfile::tempdir().unwrap();
    let mut store = acquire(root.path(), BOOT).unwrap();
    store.begin().unwrap();
    store.close().unwrap();
    let state = root.path().join(DIRECTORY).join(STATE);
    let next = root.path().join(DIRECTORY).join(NEXT);
    let closed = fs::read(&state).unwrap();
    drop(store);
    private(&next, &closed);
    for boot in [BOOT, OTHER] {
        assert!(matches!(acquire(root.path(), boot), Err(Error::Ambiguous)));
        assert_eq!(fs::read(&state).unwrap(), closed);
        assert_eq!(fs::read(&next).unwrap(), closed);
    }
}

#[test]
fn corruption_unknown_fields_truncation_and_trailing_data_are_not_repaired() {
    let root = tempfile::tempdir().unwrap();
    let mut store = acquire(root.path(), BOOT).unwrap();
    store.begin().unwrap();
    let state = root.path().join(DIRECTORY).join(STATE);
    let valid = fs::read(&state).unwrap();
    drop(store);
    for offset in [0, 8, 44, 45, HASH, BYTES - 1] {
        let mut bad = valid.clone();
        bad[offset] ^= 0xff;
        if offset == 44 || offset == 45 {
            let hash = Sha256::digest(&bad[..HASH]);
            bad[HASH..].copy_from_slice(&hash);
        }
        private(&state, &bad);
        assert!(matches!(acquire(root.path(), OTHER), Err(Error::Invalid)));
        assert_eq!(fs::read(&state).unwrap(), bad);
    }
    for length in [0, 1, BYTES - 1, BYTES + 1, 4096] {
        private(&state, &vec![0; length]);
        assert!(matches!(acquire(root.path(), OTHER), Err(Error::Invalid)));
        assert_eq!(fs::metadata(&state).unwrap().len(), length as u64);
    }
}

#[test]
fn unsafe_paths_modes_hardlinks_and_owners_are_rejected_without_cleanup() {
    let root = tempfile::tempdir().unwrap();
    let parent = File::open(root.path()).unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    assert!(matches!(
        Store::fixture(&parent, uid.wrapping_add(1), BOOT),
        Err(Error::Unsafe)
    ));
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(acquire(root.path(), BOOT), Err(Error::Unsafe)));
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let directory = root.path().join(DIRECTORY);
    symlink("/", &directory).unwrap();
    assert!(acquire(root.path(), BOOT).is_err());
    assert!(fs::symlink_metadata(&directory).unwrap().is_symlink());
    fs::remove_file(&directory).unwrap();
    drop(acquire(root.path(), BOOT).unwrap());
    let state = directory.join(STATE);
    symlink("/dev/null", &state).unwrap();
    assert!(acquire(root.path(), BOOT).is_err());
    assert!(fs::symlink_metadata(&state).unwrap().is_symlink());
    fs::remove_file(&state).unwrap();
    private(&state, &[0; BYTES]);
    fs::hard_link(&state, root.path().join("alias")).unwrap();
    assert!(matches!(acquire(root.path(), BOOT), Err(Error::Unsafe)));
    fs::remove_file(root.path().join("alias")).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(acquire(root.path(), BOOT), Err(Error::Unsafe)));
    fs::remove_file(&state).unwrap();
    nix::unistd::mkfifo(
        &state,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(matches!(acquire(root.path(), BOOT), Err(Error::Unsafe)));
}

// Unit-only subprocess controls. No environment selector exists in production.
#[test]
fn crash_probe() {
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_JOURNAL_FIXTURE") else {
        return;
    };
    let index: usize = std::env::var("NANOKVM_NATIVE_JOURNAL_STEP")
        .unwrap()
        .parse()
        .unwrap();
    let root = Path::new(&root);
    let mut store = acquire(root, BOOT).unwrap();
    store.pause_at = Some((STEPS[index], root.join("ready")));
    store.begin().unwrap();
}

struct Probe(std::process::Child);
impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn actual_process_death_releases_lease_without_forging_closure_at_each_write_boundary() {
    for (index, step) in STEPS.iter().enumerate() {
        let root = tempfile::tempdir().unwrap();
        let mut child = Probe(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "native_owner::broker::journal::tests::crash_probe",
                    "--nocapture",
                ])
                .env_clear()
                .env("NANOKVM_NATIVE_JOURNAL_FIXTURE", root.path())
                .env("NANOKVM_NATIVE_JOURNAL_STEP", index.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let started = Instant::now();
        while !root.path().join("ready").exists() {
            assert!(started.elapsed() < Duration::from_secs(5));
            assert!(child.0.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(acquire(root.path(), BOOT), Err(Error::Busy)));
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        match step {
            Step::BeforeCreate => assert!(acquire(root.path(), BOOT).is_ok()),
            Step::Created | Step::Written | Step::FileSynced => {
                assert!(matches!(acquire(root.path(), BOOT), Err(Error::Ambiguous)))
            }
            Step::Renamed | Step::DirectorySynced => {
                assert!(matches!(acquire(root.path(), BOOT), Err(Error::Unresolved)))
            }
        }
    }
}
