use super::*;
use crate::update::app_slot::tests::{Fixture, Position};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

fn name(transaction: [u8; 16]) -> String {
    format!("{:032x}", u128::from_be_bytes(transaction))
}

pub(super) fn fixture(phase: Phase) -> Fixture {
    Fixture::new(
        phase,
        if phase == Phase::Committed {
            Position::Published
        } else {
            Position::Prepared
        },
    )
}

fn parent(fixture: &Fixture) -> PathBuf {
    fixture.root.path().join(DIRECTORY)
}

// File-layer composition only; actual native retirement is covered by the
// terminal crash matrix and independent Engine tests, not inferred here.
pub(super) fn archive(fixture: &Fixture) -> Order {
    let store = fixture.store(true).unwrap();
    register(&store, &fixture.record).unwrap();
    let history = parent(fixture).join("history");
    if !history.exists() {
        fs::create_dir(&history).unwrap();
        fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::rename(
        fixture.current(),
        history.join(name(fixture.record.transaction)),
    )
    .unwrap();
    File::open(&history).unwrap().sync_all().unwrap();
    store._lock.0.sync_all().unwrap();
    let head = load(&store._lock.0, HEAD, store.device, store.uid)
        .unwrap()
        .unwrap();
    require_preparation(&store._lock.0, &store.rootfs, store.device, store.uid).unwrap();
    head.order
}

#[test]
fn mixed_terminal_chain_keeps_source_baseline_and_previous_committed_fallback() {
    let mut fixture = fixture(Phase::Committed);
    fixture.record.transaction = [9; 16];
    fixture.write_record();
    let baseline = fixture.record.old;
    let mut head = archive(&fixture);
    assert_eq!(head.sequence, 1);
    assert!(head.baseline == baseline && head.fallback == baseline);
    let mut retained = vec![fixture.record.clone()];
    for (phase, transaction) in [
        (Phase::RolledBack, 2),
        (Phase::Committed, 8),
        (Phase::RolledBack, 1),
        (Phase::Committed, 7),
    ] {
        fixture.advance(phase, transaction);
        let expected_fallback = if phase == Phase::Committed {
            fixture.record.old
        } else {
            head.fallback
        };
        let next = archive(&fixture);
        assert_eq!(next.sequence, head.sequence + 1);
        assert_eq!(next.previous, head.transaction);
        assert_eq!(next.predecessor, digest(&head.encode().unwrap()));
        assert!(next.baseline == baseline && next.fallback == expected_fallback);
        assert!(
            next.live
                == if phase == Phase::Committed {
                    fixture.record.new
                } else {
                    fixture.record.old
                }
        );
        retained.push(fixture.record.clone());
        head = next;
    }
    for record in retained {
        let directory = parent(&fixture)
            .join("history")
            .join(name(record.transaction));
        let inactive = directory.join(if record.phase == Phase::Committed {
            "old"
        } else {
            "new"
        });
        assert_eq!(
            fs::read(directory.join(STATE)).unwrap(),
            record.encode().unwrap()
        );
        assert_eq!(fs::read(directory.join(ORDER)).unwrap().len(), BYTES);
        let expected = if record.phase == Phase::Committed {
            record.old
        } else {
            record.new
        };
        let retained = archived_payload(
            &File::open(&directory).unwrap(),
            &record,
            expected.device,
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap();
        if retained {
            assert_eq!(inactive.metadata().unwrap().ino(), expected.inode);
        } else {
            assert!(!inactive.exists());
            assert!(directory.join("payload-expired").exists());
        }
        if [head.baseline, head.fallback, head.live].contains(&expected) {
            assert!(retained);
        }
    }
}

#[test]
fn order_codec_bounds_checksum_padding_identity_and_sequence_overflow() {
    let fixture = fixture(Phase::Committed);
    let store = fixture.store(true).unwrap();
    let order = Order::next(&store, &fixture.record, None).unwrap();
    let bytes = order.encode().unwrap();
    assert_eq!(
        Order::decode(&bytes, store.device)
            .unwrap()
            .encode()
            .unwrap(),
        bytes
    );
    for index in 0..BYTES {
        let mut corrupt = bytes;
        corrupt[index] ^= 1;
        assert!(Order::decode(&corrupt, store.device).is_err(), "{index}");
    }
    for offset in [8, 16, 32, 176] {
        let mut corrupt = bytes;
        if offset == 8 || offset == 16 {
            corrupt[offset..offset + if offset == 8 { 8 } else { 16 }].fill(0);
        } else {
            corrupt[offset] ^= 1;
        }
        let hash = digest(&corrupt[..PREFIX]);
        corrupt[PREFIX..].copy_from_slice(&hash);
        assert!(Order::decode(&corrupt, store.device).is_err());
    }
    assert!(Order::decode(&bytes[..BYTES - 1], store.device).is_err());
    assert!(Order::decode(&bytes, store.device ^ 1).is_err());
    let mut previous = order;
    previous.sequence = u64::MAX;
    previous.transaction = [8; 16];
    previous.live = fixture.record.old;
    assert!(Order::next(&store, &fixture.record, Some(&previous)).is_err());
}

#[test]
fn missing_order_or_mismatched_terminal_context_is_not_repaired_from_head() {
    for missing in [false, true] {
        let mut fixture = fixture(Phase::Committed);
        let store = fixture.store(true).unwrap();
        register(&store, &fixture.record).unwrap();
        let head = fs::read(parent(&fixture).join(HEAD)).unwrap();
        let order = fixture.current().join(ORDER);
        if missing {
            fs::remove_file(&order).unwrap();
        } else {
            fixture.record.archive_sha512[0] ^= 1;
            fixture.write_record();
        }
        assert!(register(&store, &fixture.record).is_err());
        assert_eq!(fs::read(parent(&fixture).join(HEAD)).unwrap(), head);
        assert_eq!(order.exists(), !missing);
    }
}

#[test]
fn unknown_pre_policy_history_and_replaced_live_refuse_without_adoption() {
    let fixture = fixture(Phase::Committed);
    let history = parent(&fixture).join("history");
    fs::create_dir(&history).unwrap();
    fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(history.join("foreign"), b"preserve unknown evidence").unwrap();
    let store = fixture.store(true).unwrap();
    assert!(register(&store, &fixture.record).is_err());
    assert!(!parent(&fixture).join(HEAD).exists());
    assert!(!fixture.current().join(ORDER).exists());
    assert_eq!(
        fs::read(history.join("foreign")).unwrap(),
        b"preserve unknown evidence"
    );
    drop(store);
    fs::remove_file(history.join("foreign")).unwrap();
    archive(&fixture);
    let live = fixture.root.path().join("kvmapp");
    fs::rename(&live, fixture.root.path().join("saved-live")).unwrap();
    fs::create_dir(&live).unwrap();
    let root = File::open(fixture.root.path()).unwrap();
    let parent = File::open(parent(&fixture)).unwrap();
    assert!(
        require_preparation(
            &parent,
            &root,
            root.metadata().unwrap().dev(),
            nix::unistd::geteuid().as_raw()
        )
        .is_err()
    );
    assert!(fixture.root.path().join("saved-live/identity").exists());
}

#[test]
fn complete_pending_head_resumes_only_for_exact_next_terminal_transaction() {
    for foreign in [false, true] {
        let mut fixture = fixture(Phase::Committed);
        let previous = archive(&fixture);
        fixture.advance(Phase::RolledBack, 7);
        let store = fixture.store(true).unwrap();
        let mut next = Order::next(&store, &fixture.record, Some(&previous)).unwrap();
        if foreign {
            next.transaction = [6; 16];
        }
        link_complete(&store._lock.0, NEXT, &next, "head").unwrap();
        let pending = fs::read(parent(&fixture).join(NEXT)).unwrap();
        assert!(
            require_preparation(&store._lock.0, &store.rootfs, store.device, store.uid).is_err()
        );
        if foreign {
            assert!(register(&store, &fixture.record).is_err());
            assert_eq!(fs::read(parent(&fixture).join(NEXT)).unwrap(), pending);
            assert_eq!(
                fs::read(parent(&fixture).join(HEAD)).unwrap(),
                previous.encode().unwrap()
            );
        } else {
            register(&store, &fixture.record).unwrap();
            assert!(!parent(&fixture).join(NEXT).exists());
            assert_eq!(
                fs::read(parent(&fixture).join(HEAD)).unwrap(),
                next.encode().unwrap()
            );
        }
    }
}

#[test]
fn unsafe_head_names_are_never_followed_repaired_or_used_for_ordering() {
    for kind in 0..6 {
        let fixture = fixture(Phase::Committed);
        let path = parent(&fixture).join(HEAD);
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("sentinel");
        fs::write(&target, b"keep outside bytes").unwrap();
        match kind {
            0 => std::os::unix::fs::symlink(&target, &path).unwrap(),
            1 => fs::create_dir(&path).unwrap(),
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
            _ => {
                let store = fixture.store(true).unwrap();
                register(&store, &fixture.record).unwrap();
                if kind == 3 {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                } else if kind == 4 {
                    fs::hard_link(&path, parent(&fixture).join("foreign-head-link")).unwrap();
                } else {
                    fs::write(&path, [0; BYTES + 1]).unwrap();
                }
            }
        }
        let store = fixture.store(true).unwrap();
        assert!(register(&store, &fixture.record).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep outside bytes");
    }
}

#[test]
fn substituted_archive_or_missing_order_cannot_continue_the_chain() {
    for substitute in [false, true] {
        let mut fixture = fixture(Phase::Committed);
        let previous = archive(&fixture);
        let archived = parent(&fixture)
            .join("history")
            .join(name(previous.transaction));
        let saved = parent(&fixture).join("saved-archive-evidence");
        if substitute {
            fs::rename(&archived, &saved).unwrap();
            fs::create_dir(&archived).unwrap();
            fs::set_permissions(&archived, fs::Permissions::from_mode(0o700)).unwrap();
            for file in [STATE, ORDER] {
                fs::copy(saved.join(file), archived.join(file)).unwrap();
            }
        } else {
            fs::rename(
                archived.join(ORDER),
                parent(&fixture).join("saved-order-evidence"),
            )
            .unwrap();
        }
        let root = File::open(fixture.root.path()).unwrap();
        let directory = File::open(parent(&fixture)).unwrap();
        let device = root.metadata().unwrap().dev();
        let uid = nix::unistd::geteuid().as_raw();
        assert!(require_preparation(&directory, &root, device, uid).is_err());
        let before = fs::read(parent(&fixture).join(HEAD)).unwrap();
        fixture.advance(Phase::RolledBack, 7);
        let store = fixture.store(true).unwrap();
        assert!(register(&store, &fixture.record).is_err());
        assert!(!fixture.current().join(ORDER).exists());
        assert_eq!(fs::read(parent(&fixture).join(HEAD)).unwrap(), before);
        assert!(if substitute {
            saved.exists()
        } else {
            parent(&fixture).join("saved-order-evidence").exists()
        });
    }
}
