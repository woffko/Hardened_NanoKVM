use super::*;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};

const IMAGE: &[u8] = b"synthetic compile-bound helper bytes, never executed";
const PREVIOUS: &[u8] = b"synthetic pinned previous helper bytes, also never executed";

fn previous_version() -> HelperVersion {
    HelperVersion {
        size: PREVIOUS.len(),
        sha256: Sha256::digest(PREVIOUS).into(),
    }
}

#[test]
fn consumer_gate_scripts_must_be_exact_protected_independent_files() {
    for fault in 0..6 {
        let root = tempdir().unwrap();
        let parent = root.path().join("etc/init.d");
        fs::create_dir_all(&parent).unwrap();
        for (name, bytes) in BOOT_SCRIPTS {
            fs::write(parent.join(name), bytes).unwrap();
            fs::set_permissions(parent.join(name), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let uid = nix::unistd::geteuid().as_raw();
        assert!(check_boot_scripts_at(&File::open(root.path()).unwrap(), uid).is_ok());
        let victim = parent.join("S02apprecover");
        match fault {
            0 => fs::remove_file(&victim).unwrap(),
            1 => fs::write(&victim, b"foreign gate bytes").unwrap(),
            2 => fs::set_permissions(&victim, fs::Permissions::from_mode(0o777)).unwrap(),
            3 => {
                fs::rename(&victim, parent.join("other")).unwrap();
                std::os::unix::fs::symlink("other", &victim).unwrap();
            }
            4 => fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap(),
            _ => fs::hard_link(&victim, parent.join("alias")).unwrap(),
        }
        assert!(
            check_boot_scripts_at(&File::open(root.path()).unwrap(), uid).is_err(),
            "fault {fault}"
        );
    }
}

struct Fixture(TempDir);
impl Fixture {
    fn new() -> Self {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join("usr")).unwrap();
        Self(root)
    }

    fn parent(&self, create: bool) -> io::Result<File> {
        parent_at(
            &File::open(self.0.path())?,
            nix::unistd::geteuid().as_raw(),
            create,
        )
    }

    fn canonical(&self) -> std::path::PathBuf {
        self.0.path().join("usr/libexec").join(EXECUTABLE)
    }

    fn install(&self, allowed: bool) -> io::Result<()> {
        let admission = self.admission()?;
        ensure_at(
            &self.parent(true)?,
            IMAGE,
            nix::unistd::geteuid().as_raw(),
            if allowed {
                app_slot::Status::NoTransaction
            } else {
                app_slot::Status::Transaction(app_slot::Phase::Prepared)
            },
            &[],
            &admission,
        )
    }

    fn admission(&self) -> io::Result<ProcessLock> {
        let parent = self.0.path().join("etc/kvm");
        fs::create_dir_all(&parent)?;
        ProcessLock::from_parent(&File::open(parent)?, nix::unistd::geteuid().as_raw())
            .map_err(io::Error::other)
    }

    fn previous(&self) {
        self.parent(true).unwrap();
        fs::write(self.canonical(), PREVIOUS).unwrap();
        fs::set_permissions(self.canonical(), fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn migrate(&self, status: app_slot::Status) -> io::Result<()> {
        let admission = self.admission()?;
        ensure_at(
            &self.parent(false)?,
            IMAGE,
            nix::unistd::geteuid().as_raw(),
            status,
            &[previous_version()],
            &admission,
        )
    }
}

#[test]
fn embedded_recovery_has_no_path_fallback() {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/app-recovery.binding"));
    if bytes.is_empty() {
        assert!(embedded_recovery().is_err());
    } else {
        let expected = restore_binding::validate_app_recovery(bytes).unwrap();
        assert_eq!(embedded_recovery().unwrap(), expected.image);
        assert!(restore_binding::validate(bytes).is_err());
    }
}

#[test]
fn independent_publication_is_exact_idempotent_and_preserves_its_inode() {
    let fixture = Fixture::new();
    fixture.install(true).unwrap();
    let first = fixture.canonical().metadata().unwrap();
    assert_eq!(first.mode() & 0o7777, 0o755);
    assert_eq!(first.nlink(), 1);
    assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
    fixture.install(true).unwrap();
    fixture.install(false).unwrap();
    assert_eq!(fixture.canonical().metadata().unwrap().ino(), first.ino());
    assert_eq!(
        fs::read_dir(fixture.canonical().parent().unwrap())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn pending_transaction_can_only_verify_an_existing_exact_helper() {
    let fixture = Fixture::new();
    let parent = fixture.parent(true).unwrap();
    assert!(fixture.install(false).is_err());
    assert_eq!(
        fs::read_dir(fixture.canonical().parent().unwrap())
            .unwrap()
            .count(),
        0
    );
    fixture.install(true).unwrap();
    let before = fixture.canonical().metadata().unwrap();
    assert!(
        ensure_at(
            &parent,
            b"different helper",
            nix::unistd::geteuid().as_raw(),
            app_slot::Status::Transaction(app_slot::Phase::Prepared),
            &[],
            &fixture.admission().unwrap(),
        )
        .is_err()
    );
    assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
    assert_eq!(fixture.canonical().metadata().unwrap().ino(), before.ino());
}

#[test]
fn only_pinned_predecessors_migrate_in_untracked_or_valid_terminal_states() {
    for status in [
        app_slot::Status::NoTransaction,
        app_slot::Status::Transaction(app_slot::Phase::Committed),
        app_slot::Status::Transaction(app_slot::Phase::RolledBack),
    ] {
        let fixture = Fixture::new();
        fixture.previous();
        let old_inode = fixture.canonical().metadata().unwrap().ino();
        fixture.migrate(status).unwrap();
        assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
        assert_ne!(fixture.canonical().metadata().unwrap().ino(), old_inode);
        let entries = fs::read_dir(fixture.canonical().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2);
        let retained = entries
            .iter()
            .find(|path| **path != fixture.canonical())
            .unwrap();
        assert_eq!(fs::read(retained).unwrap(), PREVIOUS);
        assert_eq!(retained.metadata().unwrap().ino(), old_inode);
        assert_eq!(retained.metadata().unwrap().mode() & 0o7777, 0o755);
        fixture.migrate(status).unwrap();
        assert_eq!(fs::read_dir(retained.parent().unwrap()).unwrap().count(), 2);
    }
}

#[test]
fn nonterminal_states_never_replace_even_a_pinned_predecessor() {
    for phase in [
        app_slot::Phase::Prepared,
        app_slot::Phase::Publishing,
        app_slot::Phase::Published,
        app_slot::Phase::RollingBack,
    ] {
        let fixture = Fixture::new();
        fixture.previous();
        let inode = fixture.canonical().metadata().unwrap().ino();
        assert!(
            fixture
                .migrate(app_slot::Status::Transaction(phase))
                .is_err()
        );
        assert_eq!(fs::read(fixture.canonical()).unwrap(), PREVIOUS);
        assert_eq!(fixture.canonical().metadata().unwrap().ino(), inode);
        assert_eq!(
            fs::read_dir(fixture.canonical().parent().unwrap())
                .unwrap()
                .count(),
            1
        );
        // Exact-current verification remains read-only even while recovery is
        // pending; this does not declare the app healthy or authorize launch.
        fs::write(fixture.canonical(), IMAGE).unwrap();
        fixture
            .migrate(app_slot::Status::Transaction(phase))
            .unwrap();
        assert_eq!(fixture.canonical().metadata().unwrap().ino(), inode);
    }
}

#[test]
fn terminal_journals_do_not_authorize_installing_missing_support() {
    for phase in [app_slot::Phase::Committed, app_slot::Phase::RolledBack] {
        let fixture = Fixture::new();
        fixture.parent(true).unwrap();
        assert!(
            fixture
                .migrate(app_slot::Status::Transaction(phase))
                .is_err()
        );
        assert_eq!(
            fs::read_dir(fixture.canonical().parent().unwrap())
                .unwrap()
                .count(),
            0
        );
    }
}

#[test]
fn unknown_or_unsafe_predecessors_are_refused_before_staging() {
    for fault in 0..8 {
        let fixture = Fixture::new();
        fixture.previous();
        let path = fixture.canonical();
        match fault {
            0 => fs::write(&path, b"unknown different-size helper").unwrap(),
            1 => {
                let mut corrupt = PREVIOUS.to_vec();
                corrupt[0] ^= 1;
                fs::write(&path, corrupt).unwrap();
            }
            2 => fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap(),
            3 => fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap(),
            4 => fs::hard_link(&path, path.with_file_name("alias")).unwrap(),
            5 => {
                fs::rename(&path, path.with_file_name("other")).unwrap();
                std::os::unix::fs::symlink("other", &path).unwrap();
            }
            6 => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            _ => {
                fs::remove_file(&path).unwrap();
                rustix::fs::mknodat(
                    fixture.parent(false).unwrap(),
                    EXECUTABLE,
                    rustix::fs::FileType::Fifo,
                    Mode::from_raw_mode(0o755),
                    0,
                )
                .unwrap();
            }
        }
        let before = fs::symlink_metadata(&path).unwrap();
        let count = fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert!(
            fixture.migrate(app_slot::Status::NoTransaction).is_err(),
            "fault {fault}"
        );
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (before.ino(), before.mode(), before.len(), before.nlink()),
            (after.ino(), after.mode(), after.len(), after.nlink())
        );
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), count);
    }
}

#[test]
fn a_predecessor_needs_both_the_pinned_size_and_digest() {
    for fault in 0..4 {
        let fixture = Fixture::new();
        fixture.previous();
        let mut version = previous_version();
        match fault {
            0 => version.size += 1,
            1 => version.sha256[0] ^= 1,
            2 => version.size = 0,
            _ => version.size = restore_binding::MAX_HELPER as usize + 1,
        }
        assert!(
            ensure_at(
                &fixture.parent(false).unwrap(),
                IMAGE,
                nix::unistd::geteuid().as_raw(),
                app_slot::Status::NoTransaction,
                &[version],
                &fixture.admission().unwrap(),
            )
            .is_err()
        );
        assert_eq!(fs::read(fixture.canonical()).unwrap(), PREVIOUS);
        assert_eq!(
            fs::read_dir(fixture.canonical().parent().unwrap())
                .unwrap()
                .count(),
            1
        );
    }
}

#[test]
fn no_replace_publication_preserves_an_exact_or_conflicting_race_winner() {
    for same in [true, false] {
        let fixture = Fixture::new();
        let parent = fixture.parent(true).unwrap();
        fixture.install(true).unwrap();
        if !same {
            fs::write(fixture.canonical(), b"foreign winner").unwrap();
        }
        let winner = fixture.canonical().metadata().unwrap();
        let temporary = fixture.canonical().with_file_name(".race-loser");
        fs::write(&temporary, IMAGE).unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            publish(
                &parent,
                ".race-loser",
                IMAGE,
                nix::unistd::geteuid().as_raw()
            )
            .is_ok(),
            same
        );
        assert_eq!(fixture.canonical().metadata().unwrap().ino(), winner.ino());
        assert_eq!(
            fs::read(fixture.canonical()).unwrap(),
            if same { IMAGE } else { b"foreign winner" }
        );
        assert_eq!(fs::read(temporary).unwrap(), IMAGE);
    }
}

#[test]
fn unsafe_or_mismatched_existing_objects_are_never_overwritten_or_repaired() {
    for kind in 0..8 {
        let fixture = Fixture::new();
        let parent = fixture.parent(true).unwrap();
        let path = fixture.canonical();
        match kind {
            0 => fs::create_dir(&path).unwrap(),
            1 => {
                let real = path.with_file_name("other");
                fs::write(&real, IMAGE).unwrap();
                std::os::unix::fs::symlink(&real, &path).unwrap();
            }
            2 => {
                rustix::fs::mknodat(
                    &parent,
                    EXECUTABLE,
                    rustix::fs::FileType::Fifo,
                    Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap();
            }
            _ => {
                fixture.install(true).unwrap();
                match kind {
                    3 => fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap(),
                    4 => fs::hard_link(&path, path.with_file_name("alias")).unwrap(),
                    5 => fs::write(&path, b"corrupt helper").unwrap(),
                    6 => {
                        let mut corrupt = IMAGE.to_vec();
                        corrupt[0] ^= 1;
                        fs::write(&path, corrupt).unwrap();
                    }
                    _ => fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap(),
                }
            }
        }
        let before = fs::symlink_metadata(&path).unwrap();
        assert!(fixture.install(true).is_err(), "kind {kind}");
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (before.ino(), before.mode(), before.len(), before.nlink()),
            (after.ino(), after.mode(), after.len(), after.nlink()),
            "kind {kind}"
        );
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            if kind == 1 || kind == 4 { 2 } else { 1 }
        );
    }
}

#[test]
fn unsafe_parent_and_foreign_identity_are_rejected_without_repairs() {
    for component in ["usr", "usr/libexec"] {
        let fixture = Fixture::new();
        fixture.parent(true).unwrap();
        let path = fixture.0.path().join(component);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(fixture.parent(true).is_err());
        assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o777);
        assert!(!fixture.canonical().exists());
    }
    let fixture = Fixture::new();
    fixture.install(true).unwrap();
    let parent = fixture.parent(false).unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    assert!(existing(&parent, EXECUTABLE, IMAGE, uid.wrapping_add(1)).is_err());
    assert!(
        checked_file(
            &File::open(fixture.canonical()).unwrap(),
            uid,
            parent.metadata().unwrap().dev().wrapping_add(1),
            IMAGE.len()
        )
        .is_err()
    );
    assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
}

#[test]
fn parent_aliases_missing_read_only_parent_and_torn_temporaries_are_not_authority() {
    let fixture = Fixture::new();
    assert!(fixture.parent(false).is_err());
    assert!(!fixture.0.path().join("usr/libexec").exists());
    let other = tempdir().unwrap();
    std::os::unix::fs::symlink(other.path(), fixture.0.path().join("usr/libexec")).unwrap();
    assert!(fixture.parent(true).is_err());
    assert_eq!(fs::read_dir(other.path()).unwrap().count(), 0);

    let fixture = Fixture::new();
    fixture.parent(true).unwrap();
    for (name, bytes) in [
        (".nanokvm-app-recovery-next-good", IMAGE),
        (".nanokvm-app-recovery-next-torn", b"torn".as_slice()),
    ] {
        fs::write(fixture.canonical().with_file_name(name), bytes).unwrap();
    }
    assert!(fixture.install(false).is_err());
    fixture.install(true).unwrap();
    assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
    assert_eq!(
        fs::read(
            fixture
                .canonical()
                .with_file_name(".nanokvm-app-recovery-next-torn")
        )
        .unwrap(),
        b"torn"
    );
    assert_eq!(
        fs::read_dir(fixture.canonical().parent().unwrap())
            .unwrap()
            .count(),
        3
    );
}

#[test]
#[ignore = "parent-controlled bootstrap crash/umask fixture; no standalone operation"]
fn child_publication_probe() {
    let Ok(root) = std::env::var("NANOKVM_APP_BOOTSTRAP_TEST_ROOT") else {
        return;
    };
    if std::env::var("NANOKVM_APP_BOOTSTRAP_TEST_UMASK").as_deref() == Ok("0777") {
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o777));
    }
    let root = File::open(root).unwrap();
    let admission_parent =
        restore_fs::open_beneath(&root, "etc/kvm", OFlags::RDONLY | OFlags::DIRECTORY).unwrap();
    let admission =
        ProcessLock::from_parent(&admission_parent, nix::unistd::geteuid().as_raw()).unwrap();
    let parent = parent_at(&root, nix::unistd::geteuid().as_raw(), false).unwrap();
    let migrating = std::env::var_os("NANOKVM_APP_BOOTSTRAP_TEST_MIGRATE").is_some();
    let versions = [previous_version()];
    ensure_at(
        &parent,
        IMAGE,
        nix::unistd::geteuid().as_raw(),
        app_slot::Status::NoTransaction,
        if migrating { &versions } else { &[] },
        &admission,
    )
    .unwrap();
    assert!(
        std::env::var_os("NANOKVM_APP_BOOTSTRAP_TEST_STOP").is_none(),
        "checkpoint not reached"
    );
}

fn child(fixture: &Fixture) -> Command {
    // The child acquires the real cooperative admission, not a fabricated token.
    drop(fixture.admission().unwrap());
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "update::app_bootstrap::tests::child_publication_probe",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_APP_BOOTSTRAP_TEST_ROOT", fixture.0.path())
        .stdin(Stdio::null());
    command
}

#[test]
fn restrictive_child_umask_does_not_publish_a_broken_helper_mode() {
    let fixture = Fixture::new();
    fixture.parent(true).unwrap();
    let result = child(&fixture)
        .env("NANOKVM_APP_BOOTSTRAP_TEST_UMASK", "0777")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fixture.canonical().metadata().unwrap().mode() & 0o7777,
        0o755
    );
    fixture.install(false).unwrap();
}

#[test]
fn actual_process_kill_at_every_file_publication_boundary_keeps_canonical_complete() {
    for point in ["written", "synced", "renamed", "published"] {
        let fixture = Fixture::new();
        fixture.parent(true).unwrap();
        let mut child = child(&fixture)
            .env("NANOKVM_APP_BOOTSTRAP_TEST_STOP", point)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut reached = false;
        while let Ok(line) =
            receive.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            if line.contains("app-bootstrap-checkpoint-ready") {
                reached = true;
                break;
            }
        }
        let _ = child.kill();
        let status = child.wait().unwrap();
        reader.join().unwrap();
        assert!(reached, "{point}");
        assert_eq!(status.signal(), Some(9));
        if let Ok(bytes) = fs::read(fixture.canonical()) {
            assert_eq!(bytes, IMAGE, "{point}")
        }
        fixture.install(true).unwrap();
        fixture.install(false).unwrap();
        assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
    }
}

fn migration_child_at_checkpoint(
    fixture: &Fixture,
    point: &str,
) -> (std::process::Child, std::thread::JoinHandle<()>) {
    let mut process = child(fixture)
        .env("NANOKVM_APP_BOOTSTRAP_TEST_MIGRATE", "1")
        .env("NANOKVM_APP_BOOTSTRAP_TEST_RESUME", "1")
        .env("NANOKVM_APP_BOOTSTRAP_TEST_STOP", point)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = process.stdout.take().unwrap();
    let (send, receive) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while let Ok(line) = receive.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        if line.contains("app-bootstrap-checkpoint-ready") {
            assert!(
                fixture.admission().is_err(),
                "child must retain update admission at {point}"
            );
            return (process, reader);
        }
    }
    let _ = process.kill();
    let _ = process.wait();
    reader.join().unwrap();
    panic!("migration checkpoint not reached: {point}");
}

#[test]
fn killed_migration_never_exposes_a_missing_or_partial_canonical_helper() {
    for point in ["written", "synced", "exchanged", "exchange-published"] {
        let fixture = Fixture::new();
        fixture.previous();
        let old_inode = fixture.canonical().metadata().unwrap().ino();
        let (mut process, reader) = migration_child_at_checkpoint(&fixture, point);
        process.kill().unwrap();
        assert_eq!(process.wait().unwrap().signal(), Some(9));
        reader.join().unwrap();
        let canonical = fs::read(fixture.canonical()).unwrap();
        assert_eq!(
            canonical,
            if point.starts_with("exchange") {
                IMAGE
            } else {
                PREVIOUS
            }
        );
        assert_eq!(
            fixture.canonical().metadata().unwrap().mode() & 0o7777,
            0o755
        );
        fixture.migrate(app_slot::Status::NoTransaction).unwrap();
        assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
        let retained = fs::read_dir(fixture.canonical().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.metadata().unwrap().ino() == old_inode)
            .unwrap();
        assert_eq!(fs::read(retained).unwrap(), PREVIOUS);
        fixture.migrate(app_slot::Status::NoTransaction).unwrap();
    }
}

#[test]
fn canonical_replacement_before_exchange_is_refused_and_evidence_retained() {
    for same_bytes in [true, false] {
        let fixture = Fixture::new();
        fixture.previous();
        let (mut process, reader) = migration_child_at_checkpoint(&fixture, "synced");
        let parked = fixture.canonical().with_file_name("external-old");
        fs::rename(fixture.canonical(), &parked).unwrap();
        let replacement = if same_bytes {
            PREVIOUS
        } else {
            b"unknown external replacement"
        };
        fs::write(fixture.canonical(), replacement).unwrap();
        fs::set_permissions(fixture.canonical(), fs::Permissions::from_mode(0o755)).unwrap();
        let winner = fixture.canonical().metadata().unwrap().ino();
        process.stdin.take().unwrap().write_all(&[1]).unwrap();
        assert!(!process.wait().unwrap().success());
        reader.join().unwrap();
        assert_eq!(fs::read(fixture.canonical()).unwrap(), replacement);
        assert_eq!(fixture.canonical().metadata().unwrap().ino(), winner);
        assert_eq!(fs::read(parked).unwrap(), PREVIOUS);
        let candidates = fs::read_dir(fixture.canonical().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".nanokvm-app-recovery-next-")
            })
            .collect::<Vec<_>>();
        assert_eq!(candidates.len(), 1);
        assert_eq!(fs::read(&candidates[0]).unwrap(), IMAGE);
    }
}

#[test]
fn directory_sync_error_after_exchange_is_not_reported_as_rollback() {
    let fixture = Fixture::new();
    fixture.previous();
    let inode = fixture.canonical().metadata().unwrap().ino();
    let result = child(&fixture)
        .env("NANOKVM_APP_BOOTSTRAP_TEST_MIGRATE", "1")
        .env("NANOKVM_APP_BOOTSTRAP_TEST_ERROR", "exchange-sync")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
    let retained = fs::read_dir(fixture.canonical().parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.metadata().unwrap().ino() == inode)
        .unwrap();
    assert_eq!(fs::read(retained).unwrap(), PREVIOUS);
    // Re-inspection sees exact new canonical bytes and completes the durability
    // barrier. It does not replay exchange or execute retained old evidence.
    let count = fs::read_dir(fixture.canonical().parent().unwrap())
        .unwrap()
        .count();
    fixture.migrate(app_slot::Status::NoTransaction).unwrap();
    assert_eq!(
        fs::read_dir(fixture.canonical().parent().unwrap())
            .unwrap()
            .count(),
        count
    );
}

#[test]
fn cooperating_update_owner_prevents_migration_before_any_publication() {
    let fixture = Fixture::new();
    fixture.previous();
    let admission = fixture.admission().unwrap();
    assert!(fixture.migrate(app_slot::Status::NoTransaction).is_err());
    assert_eq!(fs::read(fixture.canonical()).unwrap(), PREVIOUS);
    assert_eq!(
        fs::read_dir(fixture.canonical().parent().unwrap())
            .unwrap()
            .count(),
        1
    );
    drop(admission);
    fixture.migrate(app_slot::Status::NoTransaction).unwrap();
}

#[test]
#[ignore = "retained exact RV64 predecessor evidence; never executes that file"]
fn production_predecessor_pin_matches_the_retained_actual_helper() {
    let fixture = Fixture::new();
    fixture.parent(true).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("build/audit/remediation-2026-10-17/host/helper-migration/predecessor-v1");
    fs::copy(source, fixture.canonical()).unwrap();
    fs::set_permissions(fixture.canonical(), fs::Permissions::from_mode(0o755)).unwrap();
    let parent = fixture.parent(false).unwrap();
    let file = predecessor(
        &parent,
        EXECUTABLE,
        nix::unistd::geteuid().as_raw(),
        V1_PREDECESSORS,
    )
    .unwrap();
    assert_eq!(file.metadata().unwrap().len(), 373_048);
    let inode = file.metadata().unwrap().ino();
    // Actual old RV64 bytes enter the production migration primitive. The new
    // test bytes are deliberately not an ELF, and neither object is executed.
    ensure_at(
        &parent,
        IMAGE,
        nix::unistd::geteuid().as_raw(),
        app_slot::Status::NoTransaction,
        V1_PREDECESSORS,
        &fixture.admission().unwrap(),
    )
    .unwrap();
    assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
    assert!(
        fs::read_dir(fixture.canonical().parent().unwrap())
            .unwrap()
            .any(|entry| entry.unwrap().metadata().unwrap().ino() == inode)
    );
}
