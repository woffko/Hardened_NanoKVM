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
        ensure_at(
            &self.parent(true)?,
            IMAGE,
            nix::unistd::geteuid().as_raw(),
            allowed,
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
    assert!(ensure_at(&parent, IMAGE, nix::unistd::geteuid().as_raw(), false).is_err());
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
            false
        )
        .is_err()
    );
    assert_eq!(fs::read(fixture.canonical()).unwrap(), IMAGE);
    assert_eq!(fixture.canonical().metadata().unwrap().ino(), before.ino());
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
    assert!(existing(&parent, IMAGE, uid.wrapping_add(1)).is_err());
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
    let parent = fixture.parent(true).unwrap();
    for (name, bytes) in [
        (".nanokvm-app-recovery-next-good", IMAGE),
        (".nanokvm-app-recovery-next-torn", b"torn".as_slice()),
    ] {
        fs::write(fixture.canonical().with_file_name(name), bytes).unwrap();
    }
    assert!(ensure_at(&parent, IMAGE, nix::unistd::geteuid().as_raw(), false).is_err());
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
    let parent = parent_at(
        &File::open(root).unwrap(),
        nix::unistd::geteuid().as_raw(),
        false,
    )
    .unwrap();
    ensure_at(&parent, IMAGE, nix::unistd::geteuid().as_raw(), true).unwrap();
    assert!(
        std::env::var_os("NANOKVM_APP_BOOTSTRAP_TEST_STOP").is_none(),
        "checkpoint not reached"
    );
}

fn child(fixture: &Fixture) -> Command {
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
