use super::*;
use crate::update::state_writers::StateWriters;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    process::{Command, Stdio},
    time::Duration,
};

fn put_anchor(root: &Path, anchor: Anchor) {
    let path = root.join(ANCHOR);
    fs::write(&path, anchor.encode()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn enroll(root: &Path) -> Result<ConfigPermit> {
    let parent = File::open(root)?;
    let update = ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap();
    StateWriters::for_test_parent(parent).configuration_for_bootstrap(&update)
}

#[test]
fn factory_enrollment_is_explicit_random_bound_and_idempotent() {
    let root = tempfile::tempdir().unwrap();
    // Ordinary legacy/bootstrap reads never manufacture factory authority.
    drop(enroll(root.path()).unwrap());
    assert!(!root.path().join(ANCHOR).exists());
    assert!(!root.path().join(DIRECTORY).exists());
    put_anchor(root.path(), Anchor::Factory);
    let parent = File::open(root.path()).unwrap();
    let writers = StateWriters::for_test_parent(parent.try_clone().unwrap());
    assert!(writers.configuration().is_err());
    assert!(writers.try_drain().is_err());
    drop(enroll(root.path()).unwrap());
    let (Anchor::Ready(epoch), anchor_revision) =
        read_anchor(&parent, nix::unistd::geteuid().as_raw())
            .unwrap()
            .unwrap()
    else {
        panic!("enrollment did not become ready");
    };
    assert_ne!(epoch, [0; 16]);
    let path = root.path().join(DIRECTORY).join(STATE);
    let state_revision = Revision::from(&fs::metadata(&path).unwrap());
    let bytes = fs::read(&path).unwrap();
    let state = Snapshot::decode(&bytes).unwrap();
    assert_eq!(state.epoch, epoch);
    assert_eq!(state.sequence, 0);
    assert!(state.active.is_none() && state.receipts.iter().all(Option::is_none));
    drop(enroll(root.path()).unwrap());
    drop(writers.configuration().unwrap());
    assert!(
        read_anchor(&parent, nix::unistd::geteuid().as_raw()).unwrap()
            == Some((Anchor::Ready(epoch), anchor_revision))
    );
    assert!(Revision::from(&fs::metadata(&path).unwrap()) == state_revision);
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn bootstrap_lease_drops_its_lock_even_if_a_pre_exec_alias_survives() {
    let root = tempfile::tempdir().unwrap();
    put_anchor(root.path(), Anchor::Factory);
    drop(enroll(root.path()).unwrap());
    let parent = File::open(root.path()).unwrap();
    let directory =
        restore_fs::open_beneath(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY).unwrap();
    let lease = BootstrapLease::exclusive(directory).unwrap();
    // try_clone models the shared open description held by a fork child before
    // exec. No unsafe fork or timing/concurrency change is needed for this proof.
    let alias = lease.directory.try_clone().unwrap();
    assert!(check_parent(&parent, nix::unistd::geteuid().as_raw()).is_err());
    drop(lease);
    assert!(alias.metadata().unwrap().is_dir());
    check_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap();
}

#[test]
fn ready_anchor_never_recreates_lost_or_foreign_store() {
    for fault in ["missing", "epoch", "active", "next", "mode", "anchor-loss"] {
        let root = tempfile::tempdir().unwrap();
        put_anchor(root.path(), Anchor::Factory);
        drop(enroll(root.path()).unwrap());
        let path = root.path().join(DIRECTORY).join(STATE);
        match fault {
            "missing" => fs::remove_file(&path).unwrap(),
            "epoch" | "active" => {
                let mut state = Snapshot::decode(&fs::read(&path).unwrap()).unwrap();
                if fault == "epoch" {
                    state.epoch[0] ^= 1;
                } else {
                    state.sequence = 1;
                    state.active = Some(super::super::tests::record(1, Phase::Accepted));
                }
                fs::write(&path, state.encode().unwrap().as_slice()).unwrap();
            }
            "next" => fs::write(root.path().join(NEXT), b"unknown enrollment evidence").unwrap(),
            "mode" => {
                fs::set_permissions(root.path().join(ANCHOR), fs::Permissions::from_mode(0o644))
                    .unwrap()
            }
            "anchor-loss" => {
                fs::remove_file(root.path().join(ANCHOR)).unwrap();
                assert!(enroll(root.path()).is_err());
                assert!(
                    StateWriters::for_test_parent(File::open(root.path()).unwrap())
                        .configuration()
                        .is_err()
                );
                assert!(!root.path().join(ANCHOR).exists());
                continue;
            }
            _ => unreachable!(),
        }
        let before = fs::read(root.path().join(ANCHOR)).unwrap();
        assert!(enroll(root.path()).is_err(), "{fault}");
        let writers = StateWriters::for_test_parent(File::open(root.path()).unwrap());
        assert!(writers.configuration().is_err(), "{fault}");
        assert!(writers.try_drain().is_err(), "{fault}");
        assert_eq!(fs::read(root.path().join(ANCHOR)).unwrap(), before);
    }
    let root = tempfile::tempdir().unwrap();
    put_anchor(root.path(), Anchor::Ready([7; 16]));
    assert!(enroll(root.path()).is_err());
    assert!(!root.path().join(DIRECTORY).exists());
}

#[test]
fn factory_and_pending_refuse_unknown_store_members_without_cleanup() {
    for anchor in [Anchor::Factory, Anchor::Pending([7; 16])] {
        for member in [STATE, "active", "payload", ".state.next"] {
            let root = tempfile::tempdir().unwrap();
            put_anchor(root.path(), anchor);
            let directory = root.path().join(DIRECTORY);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(directory.join(member), b"unknown bytes").unwrap();
            fs::set_permissions(directory.join(member), fs::Permissions::from_mode(0o600)).unwrap();
            assert!(enroll(root.path()).is_err());
            assert_eq!(fs::read(directory.join(member)).unwrap(), b"unknown bytes");
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
            assert_eq!(fs::read(root.path().join(ANCHOR)).unwrap(), anchor.encode());
        }
    }
}

#[test]
fn malformed_anchor_types_fields_domains_and_links_refuse_without_initialization() {
    for fault in [
        "phase",
        "zero-pending",
        "zero-ready",
        "domain",
        "epoch",
        "reserved",
        "hash",
        "size",
        "symlink",
        "hardlink",
        "fifo",
        "directory",
    ] {
        let root = tempfile::tempdir().unwrap();
        put_anchor(root.path(), Anchor::Factory);
        let path = root.path().join(ANCHOR);
        match fault {
            "symlink" => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink("missing", &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, root.path().join("alias")).unwrap(),
            "fifo" => {
                fs::remove_file(&path).unwrap();
                rustix::fs::mknodat(
                    File::open(root.path()).unwrap(),
                    ANCHOR,
                    rustix::fs::FileType::Fifo,
                    Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap();
            }
            "directory" => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            _ => {
                let mut bytes = Anchor::Factory.encode().to_vec();
                match fault {
                    "phase" => bytes[8] = 9,
                    "zero-pending" => bytes[8] = 2,
                    "zero-ready" => bytes[8] = 3,
                    "domain" => {
                        let hash = digest(&bytes[..64]);
                        bytes[64..].copy_from_slice(&hash);
                    }
                    "epoch" => bytes[16] = 1,
                    "reserved" => bytes[32] = 1,
                    "hash" => bytes[64] ^= 1,
                    "size" => bytes.push(0),
                    _ => unreachable!(),
                }
                if matches!(
                    fault,
                    "phase" | "epoch" | "reserved" | "zero-pending" | "zero-ready"
                ) {
                    let hash = anchor_digest(&bytes[..64]);
                    bytes[64..].copy_from_slice(&hash);
                }
                fs::write(&path, bytes).unwrap();
            }
        }
        assert!(enroll(root.path()).is_err(), "{fault}");
        assert!(!root.path().join(DIRECTORY).exists());
    }
}

#[test]
fn actual_sigkill_preserves_enrollment_epoch_or_unknown_publication_fence() {
    for point in [
        "pending-staged",
        "pending-published",
        "state-written",
        "state-durable",
        "ready-staged",
        "ready-published",
    ] {
        let root = tempfile::tempdir().unwrap();
        put_anchor(root.path(), Anchor::Factory);
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::picoclaw_config::jobs::bootstrap::tests::enrollment_child",
                "--nocapture",
            ])
            .env_clear()
            .env("NANOKVM_PICO_ENROLL_ROOT", root.path())
            .env("NANOKVM_PICO_ENROLL_POINT", point)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut child = super::super::tests::OwnedChild(Some(child));
        let stdout = child.0.as_mut().unwrap().stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.unwrap().contains("pico-enrollment-checkpoint-ready") {
                    let _ = send.send(());
                    break;
                }
            }
        });
        // Reap/join on every observation path, including failed checkpoint.
        let reached = receive.recv_timeout(Duration::from_secs(30));
        let _ = child.0.as_mut().unwrap().kill();
        let status = child.0.as_mut().unwrap().wait().unwrap();
        child.0 = None;
        reader.join().unwrap();
        reached.unwrap();
        assert_eq!(status.signal(), Some(9));
        let parent = File::open(root.path()).unwrap();
        let before = read_anchor(&parent, nix::unistd::geteuid().as_raw())
            .unwrap()
            .unwrap()
            .0;
        if point.ends_with("staged") {
            assert!(root.path().join(NEXT).is_file());
            assert!(enroll(root.path()).is_err());
            assert!(
                read_anchor(&parent, nix::unistd::geteuid().as_raw())
                    .unwrap()
                    .unwrap()
                    .0
                    == before
            );
        } else {
            assert!(!root.path().join(NEXT).exists());
            drop(enroll(root.path()).unwrap());
            let after = read_anchor(&parent, nix::unistd::geteuid().as_raw())
                .unwrap()
                .unwrap()
                .0;
            match (before, after) {
                (Anchor::Pending(a) | Anchor::Ready(a), Anchor::Ready(b)) => assert_eq!(a, b),
                _ => panic!("enrollment changed identity after process death"),
            }
        }
    }
}

#[test]
fn enrollment_child() {
    let Some(root) = std::env::var_os("NANOKVM_PICO_ENROLL_ROOT") else {
        return;
    };
    drop(enroll(Path::new(&root)).unwrap());
    panic!("fixture failed to stop at enrollment checkpoint");
}

#[test]
fn fixed_early_boot_enrolls_factory_before_native_ready_and_never_resets_lost_state() {
    let root = tempfile::tempdir().unwrap();
    for name in ["etc/kvm", "etc/init.d", "proc", "kvmapp"] {
        fs::create_dir_all(root.path().join(name)).unwrap();
    }
    let child = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::picoclaw_config::jobs::bootstrap::tests::fixed_early_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_PICO_FACTORY_ROOT", root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = super::super::tests::OwnedChild(Some(child));
    let start = std::time::Instant::now();
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "early Pico factory fixture watchdog"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("fixed-early-pico-enrollment-checked")
    );
}

#[test]
fn fixed_early_child() {
    let Some(root) = std::env::var_os("NANOKVM_PICO_FACTORY_ROOT") else {
        return;
    };
    // Exercise the real validated kernel epoch, not a regular-file UUID.
    nix::mount::mount(
        Some("/proc"),
        Path::new(&root).join("proc").as_path(),
        None::<&str>,
        nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    nix::unistd::chroot(Path::new(&root)).unwrap();
    std::env::set_current_dir("/").unwrap();
    for (name, bytes) in crate::update::app_bootstrap::BOOT_SCRIPTS {
        let path = Path::new("/etc/init.d").join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let native = Path::new("/etc/kvm/native-runtime-boot");
    fs::create_dir(native).unwrap();
    fs::set_permissions(native, fs::Permissions::from_mode(0o700)).unwrap();
    let mut boot = [0; 112];
    boot[..8].copy_from_slice(b"NKBOOT02");
    boot[44] = 1;
    let hash = Sha256::digest(&boot[..80]);
    boot[80..].copy_from_slice(&hash);
    fs::write(native.join("state"), boot).unwrap();
    fs::set_permissions(native.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
    put_anchor(Path::new("/etc/kvm"), Anchor::Factory);
    assert!(StateWriters::default().configuration().is_err());
    assert!(crate::native_owner::broker::boot::require_ready().is_err());
    crate::native_owner::broker::boot::activate_early().unwrap();
    drop(crate::native_owner::broker::boot::require_ready().unwrap());
    drop(StateWriters::default().configuration().unwrap());
    let parent = File::open("/etc/kvm").unwrap();
    let before = fs::read(Path::new("/etc/kvm").join(ANCHOR)).unwrap();
    assert!(matches!(
        read_anchor(&parent, 0).unwrap(),
        Some((Anchor::Ready(_), _))
    ));
    fs::remove_file(Path::new("/etc/kvm").join(DIRECTORY).join(STATE)).unwrap();
    assert!(crate::native_owner::broker::boot::activate_early().is_err());
    assert!(StateWriters::default().configuration().is_err());
    assert_eq!(
        fs::read(Path::new("/etc/kvm").join(ANCHOR)).unwrap(),
        before
    );
    assert!(!Path::new("/etc/kvm").join(DIRECTORY).join(STATE).exists());
    println!("fixed-early-pico-enrollment-checked");
}
