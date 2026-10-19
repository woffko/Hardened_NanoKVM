use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
const OTHER: &str = "87654321-4321-4321-4321-cba987654321";
const STEPS: [Step; 11] = [
    Step::FenceCreated,
    Step::EpochSynced,
    Step::MemberQuarantined(0),
    Step::MemberQuarantined(1),
    Step::MemberQuarantined(2),
    Step::MemberQuarantined(3),
    Step::EvidenceSynced,
    Step::ClosureFileSynced,
    Step::ClosureLinked,
    Step::ClosureSynced,
    Step::FenceArchived,
];

fn recovery(root: &Path, boot: &str) -> Result<Recovery, Error> {
    Ok(Recovery {
        store: Store::lease(
            &File::open(root).unwrap(),
            nix::unistd::geteuid().as_raw(),
            Epoch::parse(boot.as_bytes())?,
            true,
        )?,
        fail_at: None,
        pause_at: None,
        create_at: None,
    })
}

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

fn seed(root: &Path) {
    drop(recovery(root, BOOT).unwrap());
    for name in MEMBERS {
        private(
            &root.join(super::super::DIRECTORY).join(name),
            name.as_bytes(),
        );
    }
}

fn preserved(root: &Path) {
    let directory = root.join(super::super::DIRECTORY);
    let evidence = directory.join(format!("recovered-{BOOT}/evidence"));
    for name in MEMBERS {
        assert_eq!(fs::read(evidence.join(name)).unwrap(), name.as_bytes());
    }
    assert!(!directory.join(RECOVERY).exists());
    let store = acquire(root, OTHER).unwrap();
    assert!(matches!(store.read().unwrap(), Some((_, Phase::Closed))));
    assert_eq!(fs::read(directory.join(STATE)).unwrap().len(), BYTES);
}

#[test]
fn same_boot_never_recovers_and_different_boot_preserves_all_exact_members() {
    let root = tempfile::tempdir().unwrap();
    seed(root.path());
    let r = recovery(root.path(), BOOT).unwrap();
    let directory = root.path().join(super::super::DIRECTORY);
    let inode = fs::metadata(&directory).unwrap().ino();
    let state_inode = fs::metadata(directory.join(STATE)).unwrap().ino();
    assert_eq!(r.prepare().unwrap(), Status::AwaitingReboot);
    assert_eq!(r.prepare().unwrap(), Status::AwaitingReboot);
    assert!(matches!(r.complete(), Err(Error::Reboot)));
    assert_eq!(fs::read(directory.join(STATE)).unwrap(), STATE.as_bytes());
    assert!(matches!(recovery(root.path(), OTHER), Err(Error::Busy)));
    drop(r);
    for boot in [BOOT, OTHER] {
        assert!(matches!(acquire(root.path(), boot), Err(Error::Recovery)));
    }
    let r = recovery(root.path(), OTHER).unwrap();
    assert_eq!(r.inspect().unwrap(), Status::ReadyAfterReboot);
    r.complete().unwrap();
    drop(r);
    preserved(root.path());
    assert_eq!(fs::metadata(&directory).unwrap().ino(), inode);
    assert_eq!(
        fs::metadata(directory.join(format!("recovered-{BOOT}/evidence/state")))
            .unwrap()
            .ino(),
        state_inode
    );
}

#[test]
fn a_live_native_owner_lease_cannot_be_bypassed_for_recovery() {
    let root = tempfile::tempdir().unwrap();
    let mut active = acquire(root.path(), BOOT).unwrap();
    active.begin().unwrap();
    assert!(matches!(recovery(root.path(), BOOT), Err(Error::Busy)));
    assert!(
        !root
            .path()
            .join(super::super::DIRECTORY)
            .join(RECOVERY)
            .exists()
    );
    drop(active);
    assert!(matches!(acquire(root.path(), BOOT), Err(Error::Unresolved)));
    let r = recovery(root.path(), BOOT).unwrap();
    assert_eq!(r.prepare().unwrap(), Status::AwaitingReboot);
    assert!(matches!(r.complete(), Err(Error::Reboot)));
}

#[test]
fn read_only_lease_does_not_create_missing_journal_storage() {
    let root = tempfile::tempdir().unwrap();
    assert!(matches!(
        Store::lease(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw(),
            Epoch::parse(BOOT.as_bytes()).unwrap(),
            false
        ),
        Err(Error::Absent)
    ));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn any_fence_object_blocks_normal_admission_without_following_links() {
    for link in [false, true] {
        let root = tempfile::tempdir().unwrap();
        drop(recovery(root.path(), BOOT).unwrap());
        let fence = root.path().join(super::super::DIRECTORY).join(RECOVERY);
        let outside = root.path().join("outside");
        private(&outside, b"do not change");
        if link {
            symlink(&outside, &fence).unwrap();
        } else {
            private(&fence, b"foreign fence");
        }
        assert!(matches!(acquire(root.path(), OTHER), Err(Error::Recovery)));
        let r = recovery(root.path(), OTHER).unwrap();
        assert!(r.inspect().is_err());
        assert!(r.prepare().is_err());
        assert!(r.complete().is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"do not change");
    }
}

#[test]
fn another_boot_after_interrupted_closed_publication_can_finish_the_same_fence() {
    const THIRD: &str = "abcdefab-cdef-abcd-efab-cdefabcdefab";
    let root = tempfile::tempdir().unwrap();
    seed(root.path());
    let r = recovery(root.path(), BOOT).unwrap();
    r.prepare().unwrap();
    drop(r);
    let mut r = recovery(root.path(), OTHER).unwrap();
    r.fail_at = Some(Step::ClosureSynced);
    assert!(r.complete().is_err());
    drop(r);
    assert!(matches!(acquire(root.path(), THIRD), Err(Error::Recovery)));
    let r = recovery(root.path(), THIRD).unwrap();
    assert_eq!(r.inspect().unwrap(), Status::ReadyAfterReboot);
    r.complete().unwrap();
    drop(r);
    preserved(root.path());
}

#[test]
fn missing_members_are_recorded_and_quarantine_does_not_follow_original_symlinks() {
    let root = tempfile::tempdir().unwrap();
    drop(recovery(root.path(), BOOT).unwrap());
    let directory = root.path().join(super::super::DIRECTORY);
    let outside = root.path().join("outside");
    private(&outside, b"untouched fixture");
    symlink(&outside, directory.join(STATE)).unwrap();
    let r = recovery(root.path(), BOOT).unwrap();
    r.prepare().unwrap();
    drop(r);
    let r = recovery(root.path(), OTHER).unwrap();
    r.complete().unwrap();
    drop(r);
    let evidence = directory.join(format!("recovered-{BOOT}/evidence"));
    assert!(
        fs::symlink_metadata(evidence.join(STATE))
            .unwrap()
            .is_symlink()
    );
    assert_eq!(fs::read(&outside).unwrap(), b"untouched fixture");
    for name in [&ABSENT[1], &ABSENT[2], &ABSENT[3]] {
        assert_eq!(fs::metadata(evidence.join(name)).unwrap().len(), 0);
    }
    assert!(acquire(root.path(), OTHER).is_ok());
}

#[test]
fn preparation_errors_keep_a_fence_and_completion_errors_are_restartable() {
    for (index, step) in STEPS.into_iter().enumerate() {
        let root = tempfile::tempdir().unwrap();
        seed(root.path());
        let mut r = recovery(root.path(), BOOT).unwrap();
        if index < 2 {
            r.fail_at = Some(step);
            assert!(matches!(r.prepare(), Err(Error::Io)));
            drop(r);
            assert!(matches!(acquire(root.path(), OTHER), Err(Error::Recovery)));
            let r = recovery(root.path(), BOOT).unwrap();
            assert_eq!(r.prepare().unwrap(), Status::AwaitingReboot);
        } else {
            r.prepare().unwrap();
            drop(r);
            let mut r = recovery(root.path(), OTHER).unwrap();
            r.fail_at = Some(step);
            assert!(matches!(r.complete(), Err(Error::Io)));
        }
        let r = recovery(root.path(), OTHER).unwrap();
        if r.inspect().unwrap() != Status::NoFence {
            r.complete().unwrap();
        }
        drop(r);
        preserved(root.path());
    }
}

#[test]
fn malformed_fences_are_preserved_and_never_grant_admission() {
    for kind in 0..7 {
        let root = tempfile::tempdir().unwrap();
        let r = recovery(root.path(), BOOT).unwrap();
        r.prepare().unwrap();
        drop(r);
        let directory = root.path().join(super::super::DIRECTORY);
        let fence = directory.join(RECOVERY);
        let epoch = fence.join(boot_name(Epoch::parse(BOOT.as_bytes()).unwrap()).unwrap());
        match kind {
            0 => private(&fence.join("unknown"), b"keep"),
            1 => private(&epoch, b"not empty"),
            2 => {
                fs::remove_file(&epoch).unwrap();
                symlink("/dev/null", &epoch).unwrap();
            }
            3 => private(
                &fence.join(boot_name(Epoch::parse(OTHER.as_bytes()).unwrap()).unwrap()),
                b"",
            ),
            4 => fs::set_permissions(&fence, fs::Permissions::from_mode(0o755)).unwrap(),
            5 => {
                symlink(root.path(), fence.join(EVIDENCE)).unwrap();
            }
            _ => private(&fence.join(QUARANTINED), b""),
        }
        let r = recovery(root.path(), OTHER).unwrap();
        assert!(r.inspect().is_err(), "kind={kind}");
        assert!(r.prepare().is_err(), "kind={kind}");
        assert!(r.complete().is_err(), "kind={kind}");
        drop(r);
        assert!(matches!(acquire(root.path(), OTHER), Err(Error::Recovery)));
        assert!(fs::symlink_metadata(fence).is_ok());
    }
}

#[test]
fn valid_looking_epoch_name_corruption_cannot_fake_a_different_boot() {
    let root = tempfile::tempdir().unwrap();
    let r = recovery(root.path(), BOOT).unwrap();
    r.prepare().unwrap();
    drop(r);
    let directory = root.path().join(super::super::DIRECTORY);
    let fence = directory.join(RECOVERY);
    let original = boot_name(Epoch::parse(BOOT.as_bytes()).unwrap()).unwrap();
    let mut damaged = original.clone().into_bytes();
    damaged[5] = b'2'; // Still a valid nonzero UUID, but not its bound checksum.
    let damaged = String::from_utf8(damaged).unwrap();
    fs::rename(fence.join(&original), fence.join(&damaged)).unwrap();
    let r = recovery(root.path(), BOOT).unwrap();
    assert!(matches!(r.inspect(), Err(Error::Invalid)));
    assert!(matches!(r.prepare(), Err(Error::Invalid)));
    assert!(matches!(r.complete(), Err(Error::Invalid)));
    drop(r);
    assert!(matches!(acquire(root.path(), BOOT), Err(Error::Recovery)));
    assert!(fence.join(damaged).exists());
}

#[test]
fn duplicate_evidence_and_foreign_archive_destination_are_not_overwritten() {
    for duplicate in [false, true] {
        let root = tempfile::tempdir().unwrap();
        seed(root.path());
        let r = recovery(root.path(), BOOT).unwrap();
        r.prepare().unwrap();
        drop(r);
        let directory = root.path().join(super::super::DIRECTORY);
        let mut r = recovery(root.path(), OTHER).unwrap();
        if duplicate {
            r.fail_at = Some(Step::MemberQuarantined(0));
            assert!(r.complete().is_err());
            private(&directory.join("recovery/evidence/absent-state"), b"");
        } else {
            fs::create_dir(directory.join(format!("recovered-{BOOT}"))).unwrap();
            private(
                &directory.join(format!("recovered-{BOOT}/keep")),
                b"keep archive",
            );
        }
        r.fail_at = None;
        assert!(r.complete().is_err());
        drop(r);
        assert!(directory.join(RECOVERY).exists());
        if duplicate {
            assert_eq!(
                fs::read(directory.join("recovery/evidence/state")).unwrap(),
                STATE.as_bytes()
            );
        } else {
            assert_eq!(
                fs::read(directory.join(format!("recovered-{BOOT}/keep"))).unwrap(),
                b"keep archive"
            );
        }
    }
}

#[test]
fn recreated_runtime_members_during_closed_publication_keep_the_fence() {
    for name in [NEXT, MEMBERS[2], MEMBERS[3]] {
        let root = tempfile::tempdir().unwrap();
        seed(root.path());
        let r = recovery(root.path(), BOOT).unwrap();
        r.prepare().unwrap();
        drop(r);
        let mut r = recovery(root.path(), OTHER).unwrap();
        r.create_at = Some((Step::ClosureFileSynced, name));
        assert!(matches!(r.complete(), Err(Error::Ambiguous)));
        drop(r);
        assert!(matches!(acquire(root.path(), OTHER), Err(Error::Recovery)));
        let directory = root.path().join(super::super::DIRECTORY);
        assert!(directory.join(name).exists());
        assert_eq!(
            fs::read(directory.join("recovery/evidence/state")).unwrap(),
            STATE.as_bytes()
        );
    }
}

struct Probe(Child);
impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn crash_probe() {
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_RECOVERY_FIXTURE") else {
        return;
    };
    let index: usize = std::env::var("NANOKVM_NATIVE_RECOVERY_STEP")
        .unwrap()
        .parse()
        .unwrap();
    let mut r = recovery(Path::new(&root), if index < 2 { BOOT } else { OTHER }).unwrap();
    r.pause_at = Some((STEPS[index], Path::new(&root).join("ready")));
    if index < 2 {
        r.prepare().unwrap();
    } else {
        r.complete().unwrap();
    }
    panic!("fixture did not pause");
}

#[test]
fn actual_process_death_at_every_recovery_boundary_preserves_evidence_and_fencing() {
    for index in 0..STEPS.len() {
        let root = tempfile::tempdir().unwrap();
        seed(root.path());
        if index >= 2 {
            let r = recovery(root.path(), BOOT).unwrap();
            r.prepare().unwrap();
        }
        let mut child = Probe(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "native_owner::broker::journal::recovery::tests::crash_probe",
                    "--nocapture",
                ])
                .env_clear()
                .env("NANOKVM_NATIVE_RECOVERY_FIXTURE", root.path())
                .env("NANOKVM_NATIVE_RECOVERY_STEP", index.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let start = Instant::now();
        while fs::read(root.path().join("ready")).ok().as_deref() != Some(b"fixture") {
            assert!(start.elapsed() < Duration::from_secs(6), "step={index}");
            assert!(child.0.try_wait().unwrap().is_none(), "step={index}");
            std::thread::sleep(Duration::from_millis(5));
        }
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        drop(child);
        if index < 2 {
            let r = recovery(root.path(), BOOT).unwrap();
            r.prepare().unwrap();
        }
        let r = recovery(root.path(), OTHER).unwrap();
        if r.inspect().unwrap() != Status::NoFence {
            r.complete().unwrap();
        }
        drop(r);
        preserved(root.path());
    }
}
