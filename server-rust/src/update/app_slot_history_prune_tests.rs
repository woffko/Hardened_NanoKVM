use super::super::tests::{archive, fixture};
use super::*;
use crate::update::app_slot::{job_status_fixture, tests::Fixture};
use std::{
    fs,
    io::{BufRead, BufReader, Seek},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

fn prunable() -> Fixture {
    let mut fixture = fixture(Phase::Committed);
    archive(&fixture);
    let extra = fixture.root.path().join("kvmapp/extra/sub");
    fs::create_dir_all(&extra).unwrap();
    fs::write(extra.join("data"), b"inactive payload data").unwrap();
    fixture.advance(Phase::Committed, 7);
    archive(&fixture);
    fixture.advance(Phase::Committed, 9);
    fixture
}

fn victim(fixture: &Fixture) -> PathBuf {
    fixture
        .root
        .path()
        .join(DIRECTORY)
        .join("history")
        .join(format!("{:032x}", u128::from_be_bytes([7; 16])))
}

fn assert_pruned(fixture: &Fixture) {
    let victim = victim(fixture);
    assert!(!victim.join("old").exists());
    assert!(!victim.join(QUARANTINE).exists());
    assert_eq!(fs::read(victim.join(EXPIRED)).unwrap().len(), 160);
    assert!(victim.join(STATE).exists() && victim.join(ORDER).exists());
    let status = job_status_fixture(fixture.root.path(), [7; 16])
        .unwrap()
        .unwrap();
    assert_eq!(status.phase, Phase::Committed);
    assert!(status.archived && !status.inactive_payload_retained);
    let baseline = fixture
        .root
        .path()
        .join(DIRECTORY)
        .join("history")
        .join(format!("{:032x}", u128::from_be_bytes([2; 16])))
        .join("old");
    assert_eq!(fs::read(baseline.join("identity")).unwrap(), b"old");
    assert_eq!(
        fixture.current().join("old").metadata().unwrap().ino(),
        fixture.record.old.inode
    );
    assert_eq!(
        fixture.root.path().join("kvmapp").metadata().unwrap().ino(),
        fixture.record.new.inode
    );
    for name in [MANIFEST, CURSOR, CURSOR_NEXT] {
        assert!(!fixture.current().join(name).exists());
    }
}

#[test]
fn removes_only_expired_inactive_tree_and_preserves_receipts_pins_and_live() {
    let fixture = prunable();
    let state = fs::read(victim(&fixture).join(STATE)).unwrap();
    let order = fs::read(victim(&fixture).join(ORDER)).unwrap();
    let store = fixture.store(true).unwrap();
    register(&store, &fixture.record).unwrap();
    assert_pruned(&fixture);
    assert_eq!(fs::read(victim(&fixture).join(STATE)).unwrap(), state);
    assert_eq!(fs::read(victim(&fixture).join(ORDER)).unwrap(), order);
    register(&store, &fixture.record).unwrap();
    assert_pruned(&fixture);
}

#[test]
fn unknown_nested_links_special_files_and_metadata_refuse_without_deletion() {
    for kind in 0..5 {
        let fixture = prunable();
        let outside = tempfile::tempdir().unwrap();
        let sentinel = outside.path().join("sentinel");
        fs::write(&sentinel, b"outside unchanged").unwrap();
        let path = victim(&fixture).join("old/foreign");
        match kind {
            0 => std::os::unix::fs::symlink(&sentinel, &path).unwrap(),
            1 => fs::hard_link(&sentinel, &path).unwrap(),
            2 => rustix::fs::mknodat(
                rustix::fs::CWD,
                &path,
                FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap(),
            3 => {
                fs::write(&path, b"unsafe writable").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
            }
            _ => {
                let file = File::create(&path).unwrap();
                file.set_len(256 * 1024 * 1024 + 64 * 1024 + 1).unwrap();
            }
        }
        let store = fixture.store(true).unwrap();
        assert!(register(&store, &fixture.record).is_err());
        assert!(victim(&fixture).join("old/identity").exists());
        assert!(!fixture.current().join(MANIFEST).exists());
        assert_eq!(fs::read(sentinel).unwrap(), b"outside unchanged");
    }
}

#[test]
fn manifest_roundtrip_detects_every_corrupt_byte_and_noncanonical_path() {
    let fixture = prunable();
    let store = fixture.store(true).unwrap();
    let head = load(&store._lock.0, HEAD, store.device, store.uid)
        .unwrap()
        .unwrap();
    let owner = Order::next(&store, &fixture.record, Some(&head.order)).unwrap();
    let archives = chain(&store, Some(&head.order)).unwrap();
    let victim = &archives[0];
    let payload = open_optional(&victim.directory, "old").unwrap().unwrap();
    let nodes = tree::collect(&payload, victim.order.directory, store.device, store.uid).unwrap();
    let mut manifest = Manifest::new(owner, victim.order.clone(), nodes).unwrap();
    let mut bytes = Vec::new();
    manifest.encode(&mut bytes).unwrap();
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    file.rewind().unwrap();
    assert_eq!(
        Manifest::read(&mut file, store.device).unwrap().hash,
        manifest.hash
    );
    for index in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[index] ^= 1;
        file.set_len(0).unwrap();
        file.rewind().unwrap();
        file.write_all(&corrupt).unwrap();
        file.rewind().unwrap();
        assert!(Manifest::read(&mut file, store.device).is_err(), "{index}");
    }
    manifest.nodes[0].path = PathBuf::from("../outside");
    assert!(manifest.encode(&mut io::sink()).is_err());
}

fn command(fixture: &Fixture) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "update::app_slot::history::prune::tests::prune_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_PRUNE_ROOT", fixture.root.path());
    command
}

#[test]
fn prune_child() {
    let Ok(root) = std::env::var("NANOKVM_PRUNE_ROOT") else {
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
    if let Ok(source) = std::env::var("NANOKVM_PRUNE_BIND_SOURCE") {
        let target = Path::new(&root)
            .join(DIRECTORY)
            .join("history")
            .join(format!("{:032x}", u128::from_be_bytes([7; 16])))
            .join("old/extra");
        nix::mount::mount(
            Some(Path::new(&source)),
            &target,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .unwrap();
        let error = register(&store, &record).unwrap_err();
        assert!(matches!(error,SlotError::Io(error) if error.raw_os_error()==Some(18)));
        println!("prune-bind-refused");
        return;
    }
    if std::env::var_os("NANOKVM_APP_SLOT_TEST_FAIL").is_some() {
        assert!(register(&store, &record).is_err());
        println!("prune-failure-retained");
    } else {
        register(&store, &record).unwrap();
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
    let status = child.wait().unwrap();
    reader.join().unwrap();
    assert!(reached, "{point}");
    assert_eq!(status.signal(), Some(9));
}

fn points() -> Vec<String> {
    let mut points = vec![
        "prune-manifest-file-synced",
        "prune-manifest-linked",
        "prune-manifest-published",
        "prune-cursor-file-synced",
        "prune-cursor-linked",
        "prune-cursor-renamed",
        "prune-cursor-published",
        "prune-payload-quarantined",
        "prune-quarantine-synced",
        "prune-quarantine-boundary-synced",
        "prune-node-pinned",
        "prune-node-unlinked",
        "prune-node-parent-synced",
        "prune-expired-file-synced",
        "prune-expired-linked",
        "prune-expiry-published",
        "prune-cursor-removed",
        "prune-manifest-removed",
        "prune-cursor-unlinked",
        "prune-manifest-unlinked",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for index in 0..5 {
        for suffix in ["pending", "synced", "advanced"] {
            points.push(format!("prune-delete-{index}-{suffix}"));
        }
    }
    points
}

#[test]
fn every_prune_io_boundary_retains_context_and_exact_retry_finishes() {
    for point in points() {
        let fixture = prunable();
        let output = command(&fixture)
            .env("NANOKVM_APP_SLOT_TEST_FAIL", &point)
            .output()
            .unwrap();
        assert!(output.status.success(), "{point}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("prune-failure-retained"));
        let store = fixture.store(true).unwrap();
        register(&store, &fixture.record).unwrap();
        assert_pruned(&fixture);
    }
}

#[test]
fn real_sigkill_at_each_prune_boundary_resumes_only_exact_manifest_and_next_unlink() {
    for point in points() {
        let fixture = prunable();
        kill_at(&fixture, &point);
        let store = fixture.store(true).unwrap();
        register(&store, &fixture.record).unwrap();
        assert_pruned(&fixture);
    }
}

#[test]
fn killed_prune_rejects_substituted_descendant_and_preserves_both_objects() {
    let fixture = prunable();
    kill_at(&fixture, "prune-delete-0-pending");
    let path = victim(&fixture).join(QUARANTINE).join("extra/sub/data");
    let saved = fixture.root.path().join("saved-prune-descendant");
    fs::rename(&path, &saved).unwrap();
    fs::write(&path, b"foreign replacement").unwrap();
    let manifest = fs::read(fixture.current().join(MANIFEST)).unwrap();
    let store = fixture.store(true).unwrap();
    assert!(register(&store, &fixture.record).is_err());
    assert_eq!(fs::read(&saved).unwrap(), b"inactive payload data");
    assert_eq!(fs::read(path).unwrap(), b"foreign replacement");
    assert_eq!(
        fs::read(fixture.current().join(MANIFEST)).unwrap(),
        manifest
    );
}

#[test]
fn unknown_archives_or_missing_pins_refuse_before_prune_side_effects() {
    for kind in 0..3 {
        let fixture = prunable();
        let root = fixture.root.path().join(DIRECTORY).join("history");
        let evidence = if kind == 0 {
            let path = root.join("untracked");
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path.join("evidence")
        } else if kind == 1 {
            victim(&fixture).join("unknown-evidence")
        } else {
            let baseline = root
                .join(format!("{:032x}", u128::from_be_bytes([2; 16])))
                .join("old");
            let saved = fixture.root.path().join("saved-baseline-evidence");
            fs::rename(baseline, &saved).unwrap();
            saved.join("evidence")
        };
        fs::write(&evidence, b"preserve evidence").unwrap();
        let store = fixture.store(true).unwrap();
        assert!(register(&store, &fixture.record).is_err());
        assert!(victim(&fixture).join("old/extra/sub/data").exists());
        assert!(!fixture.current().join(MANIFEST).exists());
        assert_eq!(fs::read(evidence).unwrap(), b"preserve evidence");
    }
}

#[test]
fn missing_or_foreign_progress_and_manifest_never_adopt_partial_deletion() {
    for kind in 0..4 {
        let fixture = prunable();
        kill_at(&fixture, "prune-delete-0-synced");
        let store = fixture.store(true).unwrap();
        let (mut manifest, _) = pending(&store).unwrap().unwrap();
        if kind == 0 {
            fs::remove_file(fixture.current().join(CURSOR)).unwrap();
        } else if kind == 1 {
            manifest.hash[0] ^= 1;
            fs::write(
                fixture.current().join(CURSOR),
                Cursor {
                    index: 0,
                    pending: true,
                }
                .encode(&manifest)
                .unwrap(),
            )
            .unwrap();
        } else if kind == 2 {
            fs::write(
                fixture.current().join(CURSOR),
                Cursor {
                    index: manifest.nodes.len(),
                    pending: false,
                }
                .encode(&manifest)
                .unwrap(),
            )
            .unwrap();
        } else {
            manifest.owner.transaction = [6; 16];
            let mut encoded = Vec::new();
            manifest.encode(&mut encoded).unwrap();
            fs::write(fixture.current().join(MANIFEST), encoded).unwrap();
        }
        let before = fs::read(fixture.current().join(MANIFEST)).unwrap();
        assert!(register(&store, &fixture.record).is_err());
        assert_eq!(fs::read(fixture.current().join(MANIFEST)).unwrap(), before);
        assert_eq!(fixture.current().join(CURSOR).exists(), kind != 0);
        assert!(victim(&fixture).join(QUARANTINE).join("identity").exists());
        assert!(!victim(&fixture).join(EXPIRED).exists());
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn actual_bind_mount_inside_inactive_payload_is_refused_without_crossing_mount() {
    let fixture = prunable();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("sentinel"), b"outside preserved").unwrap();
    let output = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::app_slot::history::prune::tests::prune_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_PRUNE_ROOT", fixture.root.path())
        .env("NANOKVM_PRUNE_BIND_SOURCE", outside.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("prune-bind-refused"));
    assert_eq!(
        fs::read(outside.path().join("sentinel")).unwrap(),
        b"outside preserved"
    );
    assert!(victim(&fixture).join("old/extra/sub/data").exists());
    assert!(!fixture.current().join(MANIFEST).exists());
}

#[test]
fn empty_directories_and_non_utf8_names_are_deleted_only_as_manifest_members() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let fixture = prunable();
    let payload = victim(&fixture).join("old");
    fs::create_dir(payload.join("empty")).unwrap();
    fs::write(
        payload.join(OsString::from_vec(vec![0xff, b'-', b'x'])),
        b"bounded binary filename",
    )
    .unwrap();
    let store = fixture.store(true).unwrap();
    register(&store, &fixture.record).unwrap();
    assert_pruned(&fixture);
}

#[test]
fn expired_inode_numbers_neither_clear_current_pins_nor_supply_missing_ones() {
    let fixture = prunable();
    let store = fixture.store(true).unwrap();
    let previous = load(&store._lock.0, HEAD, store.device, store.uid)
        .unwrap()
        .unwrap();
    let order = Order::next(&store, &fixture.record, Some(&previous.order)).unwrap();
    // Abstract identity-lifetime case, not a claim of forced kernel inode reuse.
    let mut pins = Pins::new(&order, &fixture.record);
    pins.observe(fixture.record.new, false);
    pins.observe(order.baseline, false);
    assert!(pins.require_all().is_err());
    let mut pins = Pins::new(&order, &fixture.record);
    pins.observe(fixture.record.new, false);
    pins.observe(order.baseline, true);
    pins.require_all().unwrap();
}
