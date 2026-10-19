use super::super::tests::{Fixture, Position};
use super::*;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

const POINTS: [&str; 13] = [
    "retire-history-ready",
    "retire-terminal-synced",
    "history-order-file-synced",
    "history-order-linked",
    "history-order-published",
    "history-head-file-synced",
    "history-head-linked",
    "history-head-next-synced",
    "history-head-renamed",
    "history-head-published",
    "retire-current-renamed",
    "retire-history-synced",
    "retire-parent-synced",
];

fn fixture(phase: Phase) -> Fixture {
    Fixture::new(
        phase,
        if phase == Phase::Committed {
            Position::Published
        } else {
            Position::Prepared
        },
    )
}

fn retirement_fixture(phase: Phase, subsequent: bool) -> Fixture {
    if !subsequent {
        return fixture(phase);
    }
    let mut fixture = fixture(Phase::Committed);
    fixture
        .store(true)
        .unwrap()
        .retire(&fixture.record)
        .unwrap();
    fs::write(fixture.root.path().join("kvmapp/identity"), b"old").unwrap();
    fixture.advance(phase, 7);
    fixture
}

fn archive(fixture: &Fixture) -> PathBuf {
    fixture
        .root
        .path()
        .join(DIRECTORY)
        .join(HISTORY)
        .join(format!(
            "{:032x}",
            u128::from_be_bytes(fixture.record.transaction)
        ))
}

fn assert_archived(fixture: &Fixture) {
    let status = job_status_fixture(fixture.root.path(), fixture.record.transaction)
        .unwrap()
        .unwrap();
    assert!(status.archived);
    assert_eq!(status.phase, fixture.record.phase);
    assert_eq!(status.version, fixture.record.version);
    assert!(!fixture.current().exists());
    assert_eq!(
        fs::read(archive(fixture).join(STATE)).unwrap(),
        fixture.record.encode().unwrap()
    );
    let (live, inactive, inactive_name) = if fixture.record.phase == Phase::Committed {
        (b"new".as_slice(), b"old".as_slice(), "old")
    } else {
        (b"old".as_slice(), b"new".as_slice(), "new")
    };
    assert_eq!(
        fs::read(fixture.root.path().join("kvmapp/identity")).unwrap(),
        live
    );
    assert_eq!(
        fs::read(archive(fixture).join(inactive_name).join("identity")).unwrap(),
        inactive
    );
}

#[test]
fn terminal_archive_preserves_both_slots_and_job_is_readable_under_exclusive_ownership() {
    for phase in [Phase::Committed, Phase::RolledBack] {
        let fixture = fixture(phase);
        let store = fixture.store(true).unwrap();
        assert!(matches!(fixture.store(false), Err(SlotError::Busy)));
        let status = job_status_fixture(fixture.root.path(), fixture.record.transaction)
            .unwrap()
            .unwrap();
        assert!(!status.archived);
        assert_eq!(status.phase, phase);
        fs::write(
            fixture.current().join(".state-next-evidence"),
            b"retain evidence",
        )
        .unwrap();
        assert!(store.retire(&fixture.record).unwrap().archived);
        assert_archived(&fixture);
        assert_eq!(
            fs::read(archive(&fixture).join(".state-next-evidence")).unwrap(),
            b"retain evidence"
        );
        assert!(
            store.retire(&fixture.record).unwrap().archived,
            "exact pinned retry is idempotent"
        );
        assert!(matches!(fixture.store(true), Err(SlotError::Busy)));
        drop(store);
        assert!(
            Store::at_root(
                File::open(fixture.root.path()).unwrap(),
                File::open(fixture.root.path().join(DIRECTORY)).unwrap(),
                nix::unistd::geteuid().as_raw(),
                true
            )
            .unwrap()
            .is_none()
        );
        assert!(
            job_status_fixture(fixture.root.path(), [7; 16])
                .unwrap()
                .is_none()
        );
        assert!(job_status_fixture(fixture.root.path(), [0; 16]).is_err());
    }
}

#[test]
fn nonterminal_or_changed_canonical_context_cannot_be_retired() {
    for phase in [
        Phase::Prepared,
        Phase::Publishing,
        Phase::Published,
        Phase::RollingBack,
    ] {
        let fixture = fixture(phase);
        let before = fs::read(fixture.current().join(STATE)).unwrap();
        assert!(
            fixture
                .store(true)
                .unwrap()
                .retire(&fixture.record)
                .is_err()
        );
        assert_eq!(fs::read(fixture.current().join(STATE)).unwrap(), before);
        assert!(!archive(&fixture).exists());
    }
    let fixture = fixture(Phase::Committed);
    let mut changed = Record::decode(&fixture.record.encode().unwrap()).unwrap();
    changed.metadata_sha256[0] ^= 1;
    assert!(fixture.store(true).unwrap().retire(&changed).is_err());
    assert!(!archive(&fixture).exists());
    assert_eq!(
        fs::read(fixture.current().join(STATE)).unwrap(),
        fixture.record.encode().unwrap()
    );
}

#[test]
fn foreign_archive_destination_and_replaced_current_are_never_overwritten_or_deleted() {
    for replaced in [false, true] {
        let fixture = fixture(Phase::Committed);
        let store = fixture.store(true).unwrap();
        let evidence = if replaced {
            let saved = fixture.root.path().join(DIRECTORY).join("saved-current");
            fs::rename(fixture.current(), &saved).unwrap();
            fs::create_dir(fixture.current()).unwrap();
            fs::set_permissions(fixture.current(), fs::Permissions::from_mode(0o700)).unwrap();
            fixture.current().join("foreign")
        } else {
            fs::create_dir_all(archive(&fixture)).unwrap();
            fs::set_permissions(
                archive(&fixture).parent().unwrap(),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            fs::set_permissions(archive(&fixture), fs::Permissions::from_mode(0o700)).unwrap();
            archive(&fixture).join("foreign")
        };
        fs::write(&evidence, b"foreign bytes").unwrap();
        assert!(store.retire(&fixture.record).is_err());
        assert_eq!(fs::read(evidence).unwrap(), b"foreign bytes");
        assert_eq!(
            store.record().unwrap().encode().unwrap(),
            fixture.record.encode().unwrap()
        );
        assert!(matches!(fixture.store(true), Err(SlotError::Busy)));
    }
}

#[test]
fn unsafe_history_entries_and_record_types_are_rejected_without_following_them() {
    for kind in 0..4 {
        let fixture = fixture(Phase::Committed);
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("sentinel"), b"outside unchanged").unwrap();
        let history = archive(&fixture).parent().unwrap().to_path_buf();
        match kind {
            0 => std::os::unix::fs::symlink(outside.path(), &history).unwrap(),
            1 => fs::write(&history, b"foreign file").unwrap(),
            _ => {
                fs::create_dir(&history).unwrap();
                fs::set_permissions(
                    &history,
                    fs::Permissions::from_mode(if kind == 2 { 0o755 } else { 0o700 }),
                )
                .unwrap();
                if kind == 3 {
                    std::os::unix::fs::symlink(outside.path(), archive(&fixture)).unwrap();
                }
            }
        }
        assert!(
            fixture
                .store(true)
                .unwrap()
                .retire(&fixture.record)
                .is_err()
        );
        assert!(job_status_fixture(fixture.root.path(), fixture.record.transaction).is_err());
        assert_eq!(
            fs::read(outside.path().join("sentinel")).unwrap(),
            b"outside unchanged"
        );
        assert_eq!(
            fs::read(fixture.current().join(STATE)).unwrap(),
            fixture.record.encode().unwrap()
        );
    }
    for kind in 0..5 {
        let fixture = fixture(Phase::Committed);
        let path = fixture.current().join(STATE);
        match kind {
            0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            1 => fs::hard_link(&path, fixture.current().join("alias")).unwrap(),
            2 => {
                fs::rename(&path, fixture.current().join("saved-state")).unwrap();
                std::os::unix::fs::symlink("saved-state", &path).unwrap();
            }
            3 => fs::write(&path, [0; RECORD_BYTES + 1]).unwrap(),
            _ => {
                fs::remove_file(&path).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &path,
                    FileType::Fifo,
                    Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap();
            }
        }
        assert!(job_status_fixture(fixture.root.path(), fixture.record.transaction).is_err());
        assert!(
            fixture
                .store(true)
                .unwrap()
                .retire(&fixture.record)
                .is_err()
        );
        assert!(!archive(&fixture).exists());
    }
}

#[test]
fn archived_job_rejects_wrong_transaction_and_nonterminal_phase_without_repair() {
    for nonterminal in [false, true] {
        let mut fixture = fixture(Phase::Committed);
        let path = archive(&fixture);
        fs::create_dir(path.parent().unwrap()).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(fixture.current(), &path).unwrap();
        let requested = fixture.record.transaction;
        if nonterminal {
            fixture.record.phase = Phase::Published;
        } else {
            fixture.record.transaction = [6; 16];
        }
        let bytes = fixture.record.encode().unwrap();
        fs::write(path.join(STATE), bytes).unwrap();
        assert!(job_status_fixture(fixture.root.path(), requested).is_err());
        assert_eq!(fs::read(path.join(STATE)).unwrap(), bytes);
    }
}

fn command(fixture: &Fixture) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "update::app_slot::terminal::tests::terminal_child_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_APP_SLOT_TERMINAL_ROOT", fixture.root.path());
    command
}

#[test]
fn terminal_child_probe() {
    let Ok(root) = std::env::var("NANOKVM_APP_SLOT_TERMINAL_ROOT") else {
        return;
    };
    let store = Store::at_root(
        File::open(&root).unwrap(),
        File::open(Path::new(&root).join(DIRECTORY)).unwrap(),
        nix::unistd::geteuid().as_raw(),
        true,
    )
    .unwrap()
    .unwrap();
    let record = store.record().unwrap();
    if std::env::var_os("NANOKVM_APP_SLOT_TEST_UMASK").is_some() {
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o777));
    }
    if std::env::var_os("NANOKVM_APP_SLOT_TEST_FAIL").is_some() {
        assert!(store.retire(&record).is_err());
        assert!(matches!(
            Store::at_root(
                File::open(&root).unwrap(),
                File::open(Path::new(&root).join(DIRECTORY)).unwrap(),
                nix::unistd::geteuid().as_raw(),
                true
            ),
            Err(SlotError::Busy)
        ));
        assert_eq!(
            store.record().unwrap().encode().unwrap(),
            record.encode().unwrap()
        );
        println!("retirement-failure-retained");
    } else {
        store.retire(&record).unwrap();
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn fresh_history_has_exact_private_mode_independent_of_root_child_umask() {
    let fixture = fixture(Phase::Committed);
    let output = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::app_slot::terminal::tests::terminal_child_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_APP_SLOT_TERMINAL_ROOT", fixture.root.path())
        .env("NANOKVM_APP_SLOT_TEST_UMASK", "0777")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_archived(&fixture);
    assert_eq!(
        archive(&fixture)
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .mode()
            & 0o7777,
        0o700
    );
}

// File-layer retry only. The test retains the exact current descriptor across
// child loss; this is not a production fresh-boot/runtime closure capability.
fn finish_pinned(fixture: &Fixture, current: File) {
    let directory = File::open(fixture.root.path().join(DIRECTORY)).unwrap();
    flock(&directory, FlockOperation::NonBlockingLockExclusive).unwrap();
    let store = Store {
        rootfs: File::open(fixture.root.path()).unwrap(),
        _lock: StoreLock(directory),
        current,
        uid: nix::unistd::geteuid().as_raw(),
        device: fixture.root.path().metadata().unwrap().dev(),
    };
    store.retire(&fixture.record).unwrap();
    assert_archived(fixture);
}

#[test]
fn every_retirement_io_failure_retains_canonical_evidence_and_allows_exact_pinned_retry() {
    for (phase, subsequent) in [
        (Phase::Committed, false),
        (Phase::RolledBack, false),
        (Phase::Committed, true),
        (Phase::RolledBack, true),
    ] {
        for point in POINTS {
            let fixture = retirement_fixture(phase, subsequent);
            let current = File::open(fixture.current()).unwrap();
            let output = command(&fixture)
                .env("NANOKVM_APP_SLOT_TEST_FAIL", point)
                .output()
                .unwrap();
            assert!(output.status.success(), "{point}: {output:?}");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("retirement-failure-retained")
            );
            finish_pinned(&fixture, current);
        }
    }
}

#[test]
fn real_sigkill_at_each_retirement_boundary_never_loses_receipt_or_inactive_slot() {
    for (phase, subsequent) in [
        (Phase::Committed, false),
        (Phase::RolledBack, false),
        (Phase::Committed, true),
        (Phase::RolledBack, true),
    ] {
        for point in POINTS {
            let fixture = retirement_fixture(phase, subsequent);
            let current = File::open(fixture.current()).unwrap();
            let mut child = command(&fixture)
                .env("NANOKVM_APP_SLOT_TEST_STOP", point)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdout = child.stdout.take().unwrap();
            let (send, receive) = mpsc::sync_channel(1);
            let reader = std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    if line.unwrap().contains("slot-checkpoint-ready") {
                        let _ = send.send(());
                        break;
                    }
                }
            });
            let reached = receive.recv_timeout(Duration::from_secs(10)).is_ok();
            let _ = child.kill();
            let result = child.wait().unwrap();
            reader.join().unwrap();
            assert!(reached, "checkpoint {point} not reached");
            assert_eq!(result.signal(), Some(9));
            let snapshot = job_status_fixture(fixture.root.path(), fixture.record.transaction)
                .unwrap()
                .unwrap();
            assert_eq!(snapshot.phase, phase);
            finish_pinned(&fixture, current);
        }
    }
}
