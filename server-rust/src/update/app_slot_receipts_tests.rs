use super::*;
use crate::update::app_slot::{
    history::tests::{archive as retire_fixture, fixture},
    job_status_fixture,
    tests::Fixture,
};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

fn advance(fixture: &mut Fixture, phase: Phase, sequence: u64) {
    fixture.advance(phase, 7);
    fixture.record.transaction = u128::from(sequence).to_be_bytes();
    fixture.write_record();
}

fn initial() -> Fixture {
    let mut fixture = fixture(Phase::Committed);
    fixture.record.transaction = 1_u128.to_be_bytes();
    fixture.write_record();
    fixture
}

fn pending() -> Fixture {
    let mut fixture = initial();
    retire_fixture(&fixture);
    for sequence in 2..=33 {
        advance(&mut fixture, Phase::Committed, sequence);
        retire_fixture(&fixture);
    }
    advance(&mut fixture, Phase::Committed, 34);
    fixture
}

fn root(fixture: &Fixture) -> std::path::PathBuf {
    fixture.root.path().join(DIRECTORY)
}

fn assert_finished(fixture: &Fixture) {
    let store = fixture.store(true).unwrap();
    let head = load(&store._lock.0, HEAD, store.device, store.uid)
        .unwrap()
        .unwrap()
        .order;
    assert!(head.sequence == 34 && head.transaction == 34_u128.to_be_bytes());
    let anchor = anchor_at(&store._lock.0, ANCHOR, store.device, store.uid)
        .unwrap()
        .unwrap()
        .0;
    assert!(anchor.owner == head && anchor.floor.sequence == 3);
    assert_eq!(anchor.pins.len(), 1);
    assert_eq!(anchor.pins[0].sequence, 1);
    assert!(chain(&store, Some(&head)).unwrap().len() <= KEEP as usize + 2);
    assert!(
        job_status_fixture(fixture.root.path(), 2_u128.to_be_bytes())
            .unwrap()
            .is_none()
    );
    assert!(
        job_status_fixture(fixture.root.path(), 1_u128.to_be_bytes())
            .unwrap()
            .unwrap()
            .inactive_payload_retained
    );
    for path in [JOURNAL, PROGRESS, PROGRESS_NEXT] {
        assert!(!fixture.current().join(path).exists());
    }
    assert!(!root(fixture).join("history").join(GARBAGE).exists());
    assert!(!root(fixture).join(ANCHOR_NEXT).exists());
}

fn assert_diagnostic_during_retirement(fixture: &Fixture) {
    let victim = job_status_fixture(fixture.root.path(), 2_u128.to_be_bytes());
    if fixture.current().join(JOURNAL).exists() {
        assert!(matches!(victim, Err(SlotError::Busy)));
    } else {
        let status = victim.unwrap();
        assert_eq!(
            status.is_some(),
            root(fixture)
                .join("history")
                .join(name(2_u128.to_be_bytes()))
                .exists()
        );
    }
    let baseline = job_status_fixture(fixture.root.path(), 1_u128.to_be_bytes())
        .unwrap()
        .unwrap();
    assert!(baseline.archived && baseline.inactive_payload_retained);
    let current = job_status_fixture(fixture.root.path(), 34_u128.to_be_bytes())
        .unwrap()
        .unwrap();
    assert!(!current.archived && current.phase == Phase::Committed);
}

#[test]
fn more_than_256_terminal_operations_keep_a_bounded_window_and_real_source_pin() {
    let mut fixture = initial();
    let baseline = fixture.record.old;
    let mut head = retire_fixture(&fixture);
    for sequence in 2..=270 {
        advance(
            &mut fixture,
            if sequence % 3 == 0 {
                Phase::RolledBack
            } else {
                Phase::Committed
            },
            sequence,
        );
        head = retire_fixture(&fixture);
        assert_eq!(head.sequence, sequence);
        assert_eq!(head.baseline, baseline);
        let count = fs::read_dir(root(&fixture).join("history"))
            .unwrap()
            .count();
        assert!(
            count <= KEEP as usize + 2,
            "sequence={sequence}, count={count}"
        );
    }
    assert_eq!(head.transaction, 270_u128.to_be_bytes());
    assert!(
        job_status_fixture(fixture.root.path(), 2_u128.to_be_bytes())
            .unwrap()
            .is_none()
    );
    assert!(
        job_status_fixture(fixture.root.path(), 1_u128.to_be_bytes())
            .unwrap()
            .unwrap()
            .inactive_payload_retained
    );
}

#[test]
fn old_fallback_survives_many_rollbacks_and_expires_only_after_a_new_commit() {
    let mut fixture = initial();
    retire_fixture(&fixture);
    advance(&mut fixture, Phase::Committed, 2);
    let fallback = retire_fixture(&fixture).fallback;
    for sequence in 3..=75 {
        advance(&mut fixture, Phase::RolledBack, sequence);
        assert_eq!(retire_fixture(&fixture).fallback, fallback);
    }
    let status = job_status_fixture(fixture.root.path(), 2_u128.to_be_bytes())
        .unwrap()
        .unwrap();
    assert!(status.inactive_payload_retained);
    assert_eq!(
        fs::read_dir(root(&fixture).join("history"))
            .unwrap()
            .count(),
        KEEP as usize + 2
    );
    advance(&mut fixture, Phase::Committed, 76);
    let head = retire_fixture(&fixture);
    assert_ne!(head.fallback, fallback);
    assert!(
        job_status_fixture(fixture.root.path(), 2_u128.to_be_bytes())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fs::read_dir(root(&fixture).join("history"))
            .unwrap()
            .count(),
        KEEP as usize + 1
    );
}

#[test]
fn source_can_remain_live_through_initial_rollbacks_without_an_archived_pin() {
    let mut fixture = fixture(Phase::RolledBack);
    fixture.record.transaction = 1_u128.to_be_bytes();
    fixture.write_record();
    let baseline = fixture.record.old;
    retire_fixture(&fixture);
    for sequence in 2..=70 {
        advance(&mut fixture, Phase::RolledBack, sequence);
        let head = retire_fixture(&fixture);
        assert!(head.live == baseline && head.fallback == baseline && head.baseline == baseline);
    }
    let parent = File::open(root(&fixture)).unwrap();
    let anchor = anchor_at(
        &parent,
        ANCHOR,
        fixture.record.old.device,
        nix::unistd::geteuid().as_raw(),
    )
    .unwrap()
    .unwrap()
    .0;
    assert!(anchor.pins.is_empty());
    assert_eq!(
        fs::read_dir(root(&fixture).join("history"))
            .unwrap()
            .count(),
        KEEP as usize
    );
    advance(&mut fixture, Phase::Committed, 71);
    retire_fixture(&fixture);
    for sequence in 72..=110 {
        advance(&mut fixture, Phase::RolledBack, sequence);
        retire_fixture(&fixture);
    }
    assert!(
        job_status_fixture(fixture.root.path(), 1_u128.to_be_bytes())
            .unwrap()
            .is_none()
    );
    let pinned = job_status_fixture(fixture.root.path(), 71_u128.to_be_bytes())
        .unwrap()
        .unwrap();
    assert!(pinned.archived && pinned.inactive_payload_retained);
}

#[test]
fn another_candidate_requires_valid_history_namespace_and_actual_baseline() {
    let fixture = initial();
    retire_fixture(&fixture);
    let parent = root(&fixture);
    let history = parent.join("history");
    let source = history.join(name(1_u128.to_be_bytes())).join("old");
    let outside = tempfile::tempdir().unwrap();
    let directory = File::open(&parent).unwrap();
    let rootfs = File::open(fixture.root.path()).unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    let device = rootfs.metadata().unwrap().dev();
    let head = fs::read(parent.join(HEAD)).unwrap();
    for case in 0..3 {
        match case {
            0 => fs::create_dir(history.join("foreign-archive")).unwrap(),
            1 => fs::write(parent.join(ANCHOR_NEXT), b"foreign pending anchor").unwrap(),
            _ => fs::rename(&source, outside.path().join("saved-baseline")).unwrap(),
        }
        assert!(
            super::super::super::require_preparation(&directory, &rootfs, device, uid).is_err()
        );
        assert_eq!(fs::read(parent.join(HEAD)).unwrap(), head);
        assert!(!parent.join(CURRENT).exists());
        match case {
            0 => fs::remove_dir(history.join("foreign-archive")).unwrap(),
            1 => fs::remove_file(parent.join(ANCHOR_NEXT)).unwrap(),
            _ => fs::rename(outside.path().join("saved-baseline"), &source).unwrap(),
        }
    }
    super::super::super::require_preparation(&directory, &rootfs, device, uid).unwrap();
}

fn command(fixture: &Fixture) -> Command {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        "update::app_slot::history::prune::receipts::tests::receipt_child",
        "--nocapture",
        "--test-threads=1",
    ])
    .env_clear()
    .env("NANOKVM_RECEIPT_ROOT", fixture.root.path());
    cmd
}

#[test]
fn receipt_child() {
    let Ok(root) = std::env::var("NANOKVM_RECEIPT_ROOT") else {
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
    let result = super::super::super::register(&store, &store.record().unwrap());
    if std::env::var_os("NANOKVM_APP_SLOT_TEST_FAIL").is_some() {
        assert!(result.is_err());
        println!("receipt-failure-retained");
    } else {
        result.unwrap();
    }
}

fn kill_at(fixture: &Fixture, point: &str) {
    let mut child = command(fixture)
        .env("NANOKVM_APP_SLOT_TEST_STOP", point)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, recv) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line.unwrap().contains("slot-checkpoint-ready") {
                let _ = send.send(());
                break;
            }
        }
    });
    let reached = recv.recv_timeout(Duration::from_secs(30)).is_ok();
    let _ = child.kill();
    let status = child.wait().unwrap();
    reader.join().unwrap();
    assert!(reached, "{point}");
    assert_eq!(status.signal(), Some(9));
}

fn points() -> Vec<String> {
    let mut points: Vec<_> = [
        "prune-receipt-manifest-file-synced",
        "prune-receipt-manifest-linked",
        "receipt-manifest-published",
        "prune-receipt-cursor-file-synced",
        "prune-receipt-cursor-linked",
        "receipt-cursor-renamed",
        "receipt-cursor-synced",
        "receipt-quarantined",
        "receipt-directory-unlinked",
        "prune-receipt-anchor-file-synced",
        "prune-receipt-anchor-linked",
        "receipt-anchor-renamed",
        "receipt-anchor-synced",
        "receipt-cursor-unlinked",
        "receipt-cursor-removed",
        "receipt-manifest-unlinked",
        "receipt-manifest-removed",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for step in 0..5 {
        for phase in ["pending", "synced", "advanced"] {
            points.push(format!("receipt-step-{step}-{phase}"));
        }
        if (1..4).contains(&step) {
            points.push(format!("receipt-step-{step}-unlinked"));
        }
    }
    points
}

#[test]
fn every_receipt_io_boundary_keeps_exact_retry_and_source_fallback_payloads() {
    for point in points() {
        let fixture = pending();
        let output = command(&fixture)
            .env("NANOKVM_APP_SLOT_TEST_FAIL", &point)
            .output()
            .unwrap();
        assert!(output.status.success(), "{point}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("receipt-failure-retained"));
        assert_diagnostic_during_retirement(&fixture);
        let store = fixture.store(true).unwrap();
        super::super::super::register(&store, &fixture.record).unwrap();
        drop(store);
        assert_finished(&fixture);
    }
}

#[test]
fn real_sigkill_at_each_receipt_boundary_resumes_only_the_durable_exact_plan() {
    for point in points() {
        let fixture = pending();
        kill_at(&fixture, &point);
        assert_diagnostic_during_retirement(&fixture);
        let store = fixture.store(true).unwrap();
        super::super::super::register(&store, &fixture.record).unwrap();
        drop(store);
        assert_finished(&fixture);
    }
}

#[test]
fn corrupt_anchor_or_plan_never_authorizes_deletion() {
    let fixture = pending();
    kill_at(&fixture, "receipt-manifest-published");
    let store = fixture.store(true).unwrap();
    let anchor = fs::read(root(&fixture).join(ANCHOR)).unwrap();
    for index in 0..anchor.len() {
        let mut corrupt = anchor.clone();
        corrupt[index] ^= 1;
        assert!(
            Anchor::decode(&corrupt, store.device).is_err(),
            "anchor{index}"
        );
    }
    let journal = fs::read(fixture.current().join(JOURNAL)).unwrap();
    for index in 0..journal.len() {
        let mut corrupt = journal.clone();
        corrupt[index] ^= 1;
        assert!(
            Journal::decode(&corrupt, store.device).is_err(),
            "journal{index}"
        );
    }
    assert!(matches!(
        job_status_fixture(fixture.root.path(), 2_u128.to_be_bytes()),
        Err(SlotError::Busy)
    ));
    assert!(
        root(&fixture)
            .join("history")
            .join(name(2_u128.to_be_bytes()))
            .join(STATE)
            .exists()
    );
}

#[test]
fn missing_progress_substituted_member_or_extra_evidence_refuse_without_repair() {
    for case in 0..3 {
        let fixture = pending();
        kill_at(&fixture, "receipt-step-1-pending");
        let quarantine = root(&fixture).join("history").join(GARBAGE);
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("sentinel"), b"preserve outside").unwrap();
        match case {
            0 => fs::remove_file(fixture.current().join(PROGRESS)).unwrap(),
            1 => {
                let state = fs::read(quarantine.join(STATE)).unwrap();
                fs::rename(quarantine.join(STATE), outside.path().join("saved-state")).unwrap();
                fs::write(quarantine.join(STATE), state).unwrap();
            }
            _ => std::os::unix::fs::symlink(outside.path(), quarantine.join("foreign")).unwrap(),
        }
        let journal = fs::read(fixture.current().join(JOURNAL)).unwrap();
        let store = fixture.store(true).unwrap();
        assert!(super::super::super::register(&store, &fixture.record).is_err());
        assert_eq!(fs::read(fixture.current().join(JOURNAL)).unwrap(), journal);
        assert!(quarantine.join(EXPIRED).exists());
        assert_eq!(
            fs::read(outside.path().join("sentinel")).unwrap(),
            b"preserve outside"
        );
    }
}

#[test]
fn pending_plan_rejects_foreign_namespace_anchor_and_corrupt_nonvictim_before_deletion() {
    let fixture = pending();
    kill_at(&fixture, "receipt-manifest-published");
    let outside = tempfile::tempdir().unwrap();
    let parent = root(&fixture);
    let history = parent.join("history");
    let victim = history.join(name(2_u128.to_be_bytes()));
    let marker = fs::read(victim.join(EXPIRED)).unwrap();
    let plan = fs::read(fixture.current().join(JOURNAL)).unwrap();
    let kept_marker = history.join(name(20_u128.to_be_bytes())).join(EXPIRED);
    let kept = fs::read(&kept_marker).unwrap();
    for case in 0..6 {
        match case {
            0 => fs::create_dir(history.join("unknown-history")).unwrap(),
            1 => {
                fs::write(parent.join(ANCHOR_NEXT), b"foreign anchor").unwrap();
                fs::set_permissions(
                    parent.join(ANCHOR_NEXT),
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            2 => {
                let mut bad = kept.clone();
                bad[159] ^= 1;
                fs::write(&kept_marker, bad).unwrap();
            }
            3 => {
                fs::create_dir(history.join(GARBAGE)).unwrap();
                fs::set_permissions(
                    history.join(GARBAGE),
                    std::fs::Permissions::from_mode(0o700),
                )
                .unwrap();
            }
            4 => fs::rename(parent.join(HEAD), outside.path().join("saved-head")).unwrap(),
            _ => fs::rename(parent.join(ANCHOR), outside.path().join("saved-anchor")).unwrap(),
        }
        let store = fixture.store(true).unwrap();
        assert!(
            super::super::super::register(&store, &fixture.record).is_err(),
            "case={case}"
        );
        drop(store);
        assert_eq!(fs::read(victim.join(EXPIRED)).unwrap(), marker);
        assert_eq!(fs::read(fixture.current().join(JOURNAL)).unwrap(), plan);
        match case {
            0 => fs::remove_dir(history.join("unknown-history")).unwrap(),
            1 => fs::remove_file(parent.join(ANCHOR_NEXT)).unwrap(),
            2 => fs::write(&kept_marker, &kept).unwrap(),
            3 => fs::remove_dir(history.join(GARBAGE)).unwrap(),
            4 => fs::rename(outside.path().join("saved-head"), parent.join(HEAD)).unwrap(),
            _ => fs::rename(outside.path().join("saved-anchor"), parent.join(ANCHOR)).unwrap(),
        }
    }
    let store = fixture.store(true).unwrap();
    super::super::super::register(&store, &fixture.record).unwrap();
    drop(store);
    assert_finished(&fixture);
}
