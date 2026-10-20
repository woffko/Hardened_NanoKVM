use super::*;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};

#[test]
fn candidate_modes_grant_only_runtime_execution_and_do_not_touch_old_live_data() {
    let fixture = tempdir().unwrap();
    let candidate = fixture.path().join("candidate");
    fs::create_dir(&candidate).unwrap();
    let old = fixture.path().join("old-live");
    fs::write(&old, b"unchanged old data").unwrap();
    fs::set_permissions(&old, fs::Permissions::from_mode(0o640)).unwrap();
    let cases = [
        ("server/NanoKVM-Server", 0o755),
        ("backends/NanoKVM-Server.rust", 0o755),
        ("backends/NanoKVM-Server.go", 0o755),
        ("kvm_system/kvm_system", 0o755),
        ("hwmon/nanokvm-hwmon", 0o755),
        ("system/network/udhcpc6.script", 0o755),
        ("system/bin/nanokvm-owned-command", 0o755),
        ("system/init.d/S95nanokvm", 0o755),
        (
            "picoclaw/skills/kvm-control/scripts/nanokvm-bridge.sh",
            0o755,
        ),
        ("system/bin/nested/unexpected", 0o600),
        ("system/keys/update-policy.json", 0o600),
        ("server/dl_lib/libkvm.so", 0o600),
        ("server/web/index.html", 0o600),
        ("system/ko/usb_f_mass_storage.ko", 0o600),
        ("picoclaw/AGENT.md", 0o600),
        ("version", 0o600),
    ];
    for (name, _) in cases {
        let path = candidate.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"synthetic signed candidate content").unwrap();
        // Do not trust incoming executable bits, including on data files.
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let directory = File::open(&candidate).unwrap();
    let mut members = 0;
    let mut bytes = 0;
    sync_candidate(
        &directory,
        directory.metadata().unwrap().dev(),
        nix::unistd::geteuid().as_raw(),
        Path::new(""),
        0,
        &mut members,
        &mut bytes,
    )
    .unwrap();
    for (name, mode) in cases {
        assert_eq!(
            fs::metadata(candidate.join(name)).unwrap().mode() & 0o7777,
            mode,
            "{name}"
        );
    }
    for name in ["", "server", "server/web", "system", "system/init.d"] {
        assert_eq!(
            fs::metadata(candidate.join(name)).unwrap().mode() & 0o7777,
            0o755
        );
    }
    assert_eq!(fs::read(&old).unwrap(), b"unchanged old data");
    assert_eq!(fs::metadata(old).unwrap().mode() & 0o7777, 0o640);
}

#[derive(Clone, Copy)]
pub(super) enum Position {
    Prepared,
    Parked,
    Published,
}

pub(super) struct Fixture {
    pub(super) root: TempDir,
    pub(super) record: Record,
}
impl Fixture {
    pub(super) fn new(phase: Phase, position: Position) -> Self {
        let root = tempdir().unwrap();
        let slot = root.path().join(DIRECTORY);
        fs::create_dir(&slot).unwrap();
        fs::set_permissions(&slot, fs::Permissions::from_mode(0o700)).unwrap();
        let current = slot.join(CURRENT);
        fs::create_dir(&current).unwrap();
        fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).unwrap();
        let old = root.path().join("kvmapp");
        let new = current.join("new");
        fs::create_dir(&old).unwrap();
        fs::create_dir(&new).unwrap();
        fs::write(old.join("identity"), b"old").unwrap();
        fs::write(new.join("identity"), b"new").unwrap();
        let device = root.path().metadata().unwrap().dev();
        let uid = nix::unistd::geteuid().as_raw();
        let record = Record {
            phase,
            import: Import::Signed,
            transaction: [2; 16],
            old: Identity::of(&File::open(&old).unwrap(), device, uid).unwrap(),
            new: Identity::of(&File::open(&new).unwrap(), device, uid).unwrap(),
            archive_sha512: [3; 64],
            metadata_sha256: [4; 32],
            signature_sha256: [5; 32],
            version: "2.0.43".into(),
        };
        if matches!(position, Position::Parked | Position::Published) {
            fs::rename(&old, current.join("old")).unwrap();
        }
        if matches!(position, Position::Published) {
            fs::rename(new, &old).unwrap();
        }
        let fixture = Self { root, record };
        fixture.write_record();
        File::open(fixture.root.path()).unwrap().sync_all().unwrap();
        File::open(fixture.current()).unwrap().sync_all().unwrap();
        fixture
    }

    pub(super) fn current(&self) -> PathBuf {
        self.root.path().join(DIRECTORY).join(CURRENT)
    }

    pub(super) fn write_record(&self) {
        let path = self.current().join(STATE);
        fs::write(&path, self.record.encode().unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        File::open(path).unwrap().sync_all().unwrap();
    }

    pub(super) fn advance(&mut self, phase: Phase, transaction: u8) {
        fs::create_dir(self.current()).unwrap();
        fs::set_permissions(self.current(), fs::Permissions::from_mode(0o700)).unwrap();
        let live = self.root.path().join("kvmapp");
        let new = self.current().join("new");
        fs::create_dir(&new).unwrap();
        fs::write(new.join("identity"), b"new").unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        let device = self.root.path().metadata().unwrap().dev();
        self.record.old = Identity::of(&File::open(&live).unwrap(), device, uid).unwrap();
        self.record.new = Identity::of(&File::open(&new).unwrap(), device, uid).unwrap();
        self.record.phase = phase;
        self.record.transaction = [transaction; 16];
        if phase == Phase::Committed {
            fs::rename(&live, self.current().join("old")).unwrap();
            fs::rename(new, live).unwrap();
        }
        self.write_record();
    }

    pub(super) fn store(&self, recover: bool) -> Result<Store> {
        Store::at_root(
            File::open(self.root.path()).unwrap(),
            File::open(self.root.path().join(DIRECTORY)).unwrap(),
            nix::unistd::geteuid().as_raw(),
            recover,
        )
        .map(|value| value.unwrap())
    }

    fn assert_old_restored(&self) {
        assert_eq!(
            fs::read(self.root.path().join("kvmapp/identity")).unwrap(),
            b"old"
        );
        assert_eq!(
            fs::read(self.current().join("new/identity")).unwrap(),
            b"new"
        );
        assert!(!self.current().join("old").exists());
        let record = self.store(false).unwrap().record().unwrap();
        assert_eq!(record.phase, Phase::RolledBack);
        assert_eq!(record.transaction, self.record.transaction);
        assert_eq!(record.archive_sha512, self.record.archive_sha512);
        assert_eq!(record.metadata_sha256, self.record.metadata_sha256);
        assert_eq!(record.signature_sha256, self.record.signature_sha256);
    }
}

#[test]
fn fixed_record_roundtrip_and_every_corrupted_byte_is_rejected() {
    let fixture = Fixture::new(Phase::Prepared, Position::Prepared);
    let original = fixture.record.encode().unwrap();
    let decoded = Record::decode(&original).unwrap();
    assert_eq!(decoded.encode().unwrap(), original);
    for index in 0..RECORD_BYTES {
        let mut changed = original;
        changed[index] ^= 0x80;
        assert!(Record::decode(&changed).is_err(), "index {index}");
    }
    for length in [0, 8, RECORD_BYTES - 1, RECORD_BYTES + 1] {
        assert!(Record::decode(&vec![0; length]).is_err());
    }
}

#[test]
fn checksum_cannot_make_invalid_context_or_reserved_fields_valid() {
    let fixture = Fixture::new(Phase::Prepared, Position::Prepared);
    let original = fixture.record.encode().unwrap();
    for (index, value) in [(8, 0), (8, 7), (9, 0), (9, 4), (10, 1), (400, 1)] {
        let mut bytes = original;
        bytes[index] = value;
        let digest = record_hash(&bytes[..HASH_OFFSET]);
        bytes[HASH_OFFSET..].copy_from_slice(&digest);
        assert!(Record::decode(&bytes).is_err());
    }
    for range in [16..32, 40..48, 56..64, 64..128, 128..160, 160..192] {
        let mut bytes = original;
        bytes[range].fill(0);
        let digest = record_hash(&bytes[..HASH_OFFSET]);
        bytes[HASH_OFFSET..].copy_from_slice(&digest);
        assert!(Record::decode(&bytes).is_err());
    }
    for version in ["", "x.y.z", "2.0", "2.0.43.1", "2.0.-1", "2.0.43\n"] {
        let mut record = Record::decode(&original).unwrap();
        record.version = version.into();
        assert!(record.encode().is_err());
    }
    let mut record = Record::decode(&original).unwrap();
    record.new = record.old;
    assert!(record.encode().is_err());
    record.new.inode += 1;
    record.new.device ^= 1;
    assert!(record.encode().is_err());
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn boot_gate_child_fixture() {
    let Ok(root) = std::env::var("NANOKVM_APP_GATE_FIXTURE_ROOT") else {
        return;
    };
    let case = std::env::var("NANOKVM_APP_GATE_FIXTURE_CASE").unwrap();
    assert!(nix::unistd::geteuid().is_root());
    // Only this fresh disposable mount namespace/root. Real procfs supplies
    // kernel boot identity; no target hardware or production override is used.
    fs::create_dir(Path::new(&root).join("proc")).unwrap();
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
    if let Some(route) = case.strip_prefix("support-") {
        support_boot_gate(route);
        println!("app-boot-gate-fixture-ran");
        return;
    }
    if !matches!(case.as_str(), "none" | "corrupt" | "missing-native") {
        crate::native_owner::broker::app_recovery_closed_fixture(&File::open("/etc/kvm").unwrap());
    }
    let admission = ProcessLock::acquire().unwrap();
    if case == "corrupt" {
        assert!(boot_gate().is_err());
        assert_eq!(
            fs::read("/etc/kvm/application-slot/current/state").unwrap(),
            b"corrupt fixture"
        );
    } else if case == "none" {
        assert_eq!(boot_gate().unwrap(), Status::NoTransaction);
    } else if case == "committed" {
        assert_eq!(boot_gate().unwrap(), Status::Transaction(Phase::Committed));
    } else if case == "rolled-back" {
        assert_eq!(boot_gate().unwrap(), Status::Transaction(Phase::RolledBack));
    } else if case == "missing-native" {
        let before = fs::read("/etc/kvm/application-slot/current/state").unwrap();
        drop(admission);
        assert!(matches!(recover(), Err(SlotError::Busy)));
        assert!(matches!(boot_gate(), Err(SlotError::Busy)));
        assert_eq!(
            fs::read("/etc/kvm/application-slot/current/state").unwrap(),
            before
        );
        assert!(!Path::new("/etc/kvm/application-slot/history").exists());
    } else {
        // A still-owning installer cannot be rolled back by a boot consumer.
        let before = status().unwrap();
        assert!(matches!(boot_gate(), Err(SlotError::Busy)));
        assert_eq!(status().unwrap(), before);
        drop(admission);
        assert_eq!(boot_gate().unwrap(), Status::Transaction(Phase::RolledBack));
        let job = job_status([2; 16]).unwrap().unwrap();
        assert!(job.archived);
        assert_eq!(job.phase, Phase::RolledBack);
        let _admission = ProcessLock::acquire().unwrap();
        assert_eq!(boot_gate().unwrap(), Status::NoTransaction);
    }
    println!("app-boot-gate-fixture-ran");
}

#[cfg(feature = "sandbox-test-fixture")]
fn support_boot_gate(route: &str) {
    let support = Path::new("/etc/kvm/application-support");
    let mut evidence = Vec::with_capacity(1);
    for entry in fs::read_dir(support).unwrap() {
        let path = entry.unwrap().path();
        let metadata = path.metadata().unwrap();
        evidence.push((path.clone(), metadata.ino(), fs::read(path).unwrap()));
    }
    assert!(evidence.len() <= 1);
    let pending = !evidence.is_empty();
    let current = Path::new("/etc/kvm/application-slot/current/state");
    let before = fs::read(current).ok();
    if !matches!(route, "none" | "absent") {
        crate::native_owner::broker::app_recovery_closed_fixture(&File::open("/etc/kvm").unwrap());
    }
    let admission = ProcessLock::acquire().unwrap();
    let native = if route == "native" {
        Some(crate::native_owner::broker::ReadyAppRecovery::acquire().unwrap())
    } else {
        None
    };
    let writers = if route == "writer" {
        Some(
            super::super::state_writers::StateWriters::default()
                .try_drain()
                .unwrap(),
        )
    } else {
        None
    };
    if route != "update" {
        drop(admission);
    }
    if route == "absent" {
        assert!(matches!(
            crate::native_owner::broker::ReadyAppRecovery::acquire(),
            Err(crate::native_owner::broker::JournalError::Absent)
        ));
    }
    let result = boot_gate();
    if pending {
        let malformed_plan =
            route == "retire" && evidence[0].0.file_name() == Some(std::ffi::OsStr::new("plan"));
        if malformed_plan {
            // Full fenced recovery now inspects PLAN metadata before archival;
            // this deliberately truncated file fails the strict size guard.
            assert!(
                matches!(result, Err(SlotError::Unsafe)),
                "{route}: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(SlotError::Invalid)),
                "{route}: {result:?}"
            );
        }
        assert_eq!(fs::read(current).ok(), before);
        assert!(!Path::new("/etc/kvm/application-slot/history").exists());
    } else if route == "none" {
        assert_eq!(result.unwrap(), Status::NoTransaction);
    } else {
        let record = Record::decode(before.as_ref().unwrap()).unwrap();
        assert_eq!(result.unwrap(), Status::Transaction(record.phase));
        if route == "retire" {
            assert_eq!(boot_gate().unwrap(), Status::NoTransaction);
        }
    }
    if route == "none" {
        let result = recover();
        if pending {
            assert!(matches!(result, Err(SlotError::Invalid)));
        } else {
            assert_eq!(result.unwrap(), Status::NoTransaction);
        }
    }
    for (path, inode, bytes) in evidence {
        assert_eq!(path.metadata().unwrap().ino(), inode);
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    assert_eq!(fs::read_dir(support).unwrap().count(), usize::from(pending));
    drop((native, writers));
}

#[cfg(feature = "sandbox-test-fixture")]
fn run_boot_gate_fixture(fixture: &Fixture, case: &str) {
    let output = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::app_slot::tests::boot_gate_child_fixture",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_APP_GATE_FIXTURE_ROOT", fixture.root.path())
        .env("NANOKVM_APP_GATE_FIXTURE_CASE", case)
        .output()
        .unwrap();
    assert!(output.status.success(), "{case}: {output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("running 1 test")
            && text.contains("1 passed; 0 failed")
            && text.contains("app-boot-gate-fixture-ran"),
        "{case}: {text}"
    );
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn actual_fixed_root_boot_gate_respects_restart_admission_and_recovers_interrupted_slots() {
    for (case, phase, position) in [
        ("none", Phase::Prepared, Position::Prepared),
        ("committed", Phase::Committed, Position::Published),
        ("rolled-back", Phase::RolledBack, Position::Prepared),
        ("prepared", Phase::Prepared, Position::Prepared),
        ("parked", Phase::Publishing, Position::Parked),
        ("published", Phase::Published, Position::Published),
        ("corrupt", Phase::Prepared, Position::Prepared),
        ("missing-native", Phase::Published, Position::Published),
    ] {
        let fixture = Fixture::new(phase, position);
        fs::create_dir_all(fixture.root.path().join("etc/kvm")).unwrap();
        let directory = fixture.root.path().join("etc/kvm/application-slot");
        fs::rename(fixture.root.path().join(DIRECTORY), &directory).unwrap();
        if case == "none" {
            fs::remove_dir_all(&directory).unwrap();
        }
        if case == "corrupt" {
            fs::write(directory.join("current/state"), b"corrupt fixture").unwrap();
        }
        run_boot_gate_fixture(&fixture, case);
        assert_eq!(
            fs::read(fixture.root.path().join("kvmapp/identity")).unwrap(),
            if matches!(case, "committed" | "missing-native") {
                b"new"
            } else {
                b"old"
            }
        );
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn actual_boot_shortcuts_and_terminal_retirement_never_bypass_pending_support_evidence() {
    for route in ["none", "update", "native", "absent", "writer", "retire"] {
        for phase in [Phase::Committed, Phase::RolledBack] {
            for member in [
                None,
                Some("plan"),
                Some("plan-next"),
                Some("member-8"),
                Some("foreign"),
            ] {
                let fixture = Fixture::new(
                    phase,
                    if phase == Phase::Committed {
                        Position::Published
                    } else {
                        Position::Prepared
                    },
                );
                let parent = fixture.root.path().join("etc/kvm");
                fs::create_dir_all(&parent).unwrap();
                // Full fenced recovery pins these protected live parents
                // before examining deliberately malformed support evidence.
                fs::create_dir_all(fixture.root.path().join("usr/libexec")).unwrap();
                fs::create_dir_all(fixture.root.path().join("etc/init.d")).unwrap();
                let directory = parent.join("application-slot");
                fs::rename(fixture.root.path().join(DIRECTORY), &directory).unwrap();
                if route == "none" {
                    fs::remove_dir_all(directory).unwrap();
                }
                let support = parent.join("application-support");
                fs::create_dir(&support).unwrap();
                fs::set_permissions(&support, fs::Permissions::from_mode(0o700)).unwrap();
                if let Some(member) = member {
                    let path = support.join(member);
                    fs::write(&path, b"retained torn support evidence").unwrap();
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
                }
                run_boot_gate_fixture(&fixture, &format!("support-{route}"));
                assert_eq!(
                    fs::read(fixture.root.path().join("kvmapp/identity")).unwrap(),
                    if phase == Phase::Committed {
                        b"new"
                    } else {
                        b"old"
                    }
                );
            }
        }
    }
}

#[test]
fn manual_and_explicit_lab_receipts_remain_distinct_from_signed_context() {
    let fixture = Fixture::new(Phase::Prepared, Position::Prepared);
    let mut record = Record::decode(&fixture.record.encode().unwrap()).unwrap();
    record.import = Import::Manual;
    assert!(record.encode().is_err());
    record.metadata_sha256.fill(0);
    record.signature_sha256.fill(0);
    assert!(Record::decode(&record.encode().unwrap()).is_ok());
    record.import = Import::UnsignedLab;
    assert!(record.encode().is_err());
    record.metadata_sha256.fill(4);
    assert!(Record::decode(&record.encode().unwrap()).is_ok());
    record.signature_sha256.fill(5);
    assert!(record.encode().is_err());
}

#[test]
fn every_supported_uncommitted_layout_restores_the_same_old_inode() {
    for phase in [
        Phase::Prepared,
        Phase::Publishing,
        Phase::Published,
        Phase::RollingBack,
    ] {
        for position in [Position::Prepared, Position::Parked, Position::Published] {
            let fixture = Fixture::new(phase, position);
            let old_inode = fixture.record.old;
            assert_eq!(
                fixture.store(true).unwrap().recover().unwrap(),
                Status::Transaction(Phase::RolledBack)
            );
            let actual = fixture.root.path().join("kvmapp").metadata().unwrap();
            assert_eq!(
                (actual.dev(), actual.ino()),
                (old_inode.device, old_inode.inode)
            );
            fixture.assert_old_restored();
            assert_eq!(
                fixture.store(true).unwrap().recover().unwrap(),
                Status::Transaction(Phase::RolledBack)
            );
            fixture.assert_old_restored();
        }
    }
}

#[test]
fn committed_is_publication_only_and_is_not_replayed_or_claimed_healthy() {
    let fixture = Fixture::new(Phase::Committed, Position::Published);
    assert_eq!(
        fixture.store(true).unwrap().recover().unwrap(),
        Status::Transaction(Phase::Committed)
    );
    assert_eq!(
        fs::read(fixture.root.path().join("kvmapp/identity")).unwrap(),
        b"new"
    );
    assert_eq!(
        fs::read(fixture.current().join("old/identity")).unwrap(),
        b"old"
    );
    for (phase, position) in [
        (Phase::Committed, Position::Prepared),
        (Phase::RolledBack, Position::Published),
    ] {
        let fixture = Fixture::new(phase, position);
        let before = fs::read(fixture.current().join(STATE)).unwrap();
        assert!(fixture.store(true).unwrap().recover().is_err());
        assert_eq!(fs::read(fixture.current().join(STATE)).unwrap(), before);
    }
}

#[test]
fn foreign_missing_duplicate_and_symlinked_slots_never_authorize_recovery() {
    for kind in 0..5 {
        let fixture = Fixture::new(Phase::Publishing, Position::Parked);
        let before = fs::read(fixture.current().join(STATE)).unwrap();
        match kind {
            0 => {
                fs::create_dir(fixture.root.path().join("kvmapp")).unwrap();
            }
            1 => {
                fs::remove_dir_all(fixture.current().join("old")).unwrap();
            }
            2 => {
                fs::rename(
                    fixture.current().join("new"),
                    fixture.current().join("unrecognized"),
                )
                .unwrap();
            }
            3 => {
                std::os::unix::fs::symlink(
                    fixture.current().join("old"),
                    fixture.root.path().join("kvmapp"),
                )
                .unwrap();
            }
            _ => {
                fs::rename(
                    fixture.current().join("old"),
                    fixture.current().join("saved-old"),
                )
                .unwrap();
                fs::create_dir(fixture.current().join("old")).unwrap();
            }
        }
        assert!(fixture.store(true).unwrap().recover().is_err());
        assert_eq!(fs::read(fixture.current().join(STATE)).unwrap(), before);
    }
}

#[test]
fn corrupt_canonical_record_never_falls_back_to_valid_temporary_or_legacy_marker() {
    let fixture = Fixture::new(Phase::Published, Position::Published);
    let valid = fs::read(fixture.current().join(STATE)).unwrap();
    fs::write(fixture.current().join(".state-next-synthetic"), &valid).unwrap();
    fs::write(
        fixture
            .root
            .path()
            .join("hardened-system-raw-update-pending.json"),
        &valid,
    )
    .unwrap();
    let mut corrupt = valid.clone();
    corrupt[100] ^= 1;
    fs::write(fixture.current().join(STATE), &corrupt).unwrap();
    assert!(fixture.store(true).unwrap().recover().is_err());
    assert_eq!(
        fs::read(fixture.root.path().join("kvmapp/identity")).unwrap(),
        b"new"
    );
    assert_eq!(fs::read(fixture.current().join(STATE)).unwrap(), corrupt);
    assert_eq!(
        fs::read(fixture.current().join(".state-next-synthetic")).unwrap(),
        valid
    );
}

#[test]
fn torn_unpublished_temporaries_are_preserved_but_never_selected_as_authority() {
    let fixture = Fixture::new(Phase::Published, Position::Published);
    for (name, bytes) in [
        (".state-next-short", b"broken".as_slice()),
        (".state-next-full", &fixture.record.encode().unwrap()),
    ] {
        fs::write(fixture.current().join(name), bytes).unwrap();
    }
    fixture.store(true).unwrap().recover().unwrap();
    fixture.assert_old_restored();
    assert_eq!(
        fs::read(fixture.current().join(".state-next-short")).unwrap(),
        b"broken"
    );
    assert!(fixture.current().join(".state-next-full").is_file());
}

#[test]
fn unsafe_record_types_permissions_links_and_wrong_device_are_rejected_before_mutation() {
    for kind in 0..6 {
        let fixture = Fixture::new(Phase::Published, Position::Published);
        let path = fixture.current().join(STATE);
        match kind {
            0 => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            1 => fs::hard_link(&path, fixture.current().join("alias")).unwrap(),
            2 => {
                fs::rename(&path, fixture.current().join("real-state")).unwrap();
                std::os::unix::fs::symlink("real-state", &path).unwrap();
            }
            3 => {
                fs::write(&path, [0; RECORD_BYTES + 1]).unwrap();
            }
            4 => {
                fs::remove_file(&path).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &path,
                    rustix::fs::FileType::Fifo,
                    Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap();
            }
            _ => {
                let mut record = Record::decode(&fixture.record.encode().unwrap()).unwrap();
                record.old.device ^= 1;
                record.new.device = record.old.device;
                fs::write(&path, record.encode().unwrap()).unwrap();
            }
        }
        assert!(fixture.store(true).unwrap().recover().is_err());
        assert_eq!(
            fs::read(fixture.root.path().join("kvmapp/identity")).unwrap(),
            b"new"
        );
        assert_eq!(
            fs::read(fixture.current().join("old/identity")).unwrap(),
            b"old"
        );
    }
}

#[test]
fn fixed_store_inode_lock_has_no_unlink_or_repair_fallback() {
    let fixture = Fixture::new(Phase::Prepared, Position::Prepared);
    let before = fixture
        .root
        .path()
        .join(DIRECTORY)
        .metadata()
        .unwrap()
        .ino();
    let first = fixture.store(true).unwrap();
    assert!(matches!(fixture.store(false), Err(SlotError::Busy)));
    assert!(matches!(fixture.store(true), Err(SlotError::Busy)));
    drop(first);
    let first = fixture.store(false).unwrap();
    let second = fixture.store(false).unwrap();
    assert!(matches!(fixture.store(true), Err(SlotError::Busy)));
    drop((first, second));
    assert!(fixture.store(true).is_ok());
    assert_eq!(
        fixture
            .root
            .path()
            .join(DIRECTORY)
            .metadata()
            .unwrap()
            .ino(),
        before
    );
    fs::set_permissions(
        fixture.root.path().join(DIRECTORY),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(matches!(fixture.store(true), Err(SlotError::Unsafe)));
}

#[test]
fn completed_owner_unlocks_even_while_an_inherited_description_is_still_open() {
    let fixture = Fixture::new(Phase::Prepared, Position::Prepared);
    let first = fixture.store(true).unwrap();
    let inherited = first._lock.0.try_clone().unwrap();
    assert!(matches!(fixture.store(true), Err(SlotError::Busy)));
    drop(first);
    assert!(fixture.store(true).is_ok());
    drop(inherited);
}

#[test]
fn missing_transaction_is_not_created_and_orphan_preparation_is_not_consumed() {
    let fixture = Fixture::new(Phase::Prepared, Position::Prepared);
    fs::rename(
        fixture.current(),
        fixture
            .root
            .path()
            .join(DIRECTORY)
            .join("pending-synthetic"),
    )
    .unwrap();
    let opened = Store::at_root(
        File::open(fixture.root.path()).unwrap(),
        File::open(fixture.root.path().join(DIRECTORY)).unwrap(),
        nix::unistd::geteuid().as_raw(),
        false,
    )
    .unwrap();
    assert!(opened.is_none());
    assert!(!fixture.current().exists());
    assert!(
        fixture
            .root
            .path()
            .join(DIRECTORY)
            .join("pending-synthetic/state")
            .is_file()
    );
}

#[test]
#[ignore = "parent-controlled process-kill fixture; no standalone operation"]
fn child_recovery_probe() {
    let Ok(root) = std::env::var("NANOKVM_APP_SLOT_TEST_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    if std::env::var("NANOKVM_APP_SLOT_TEST_UMASK").as_deref() == Ok("0777") {
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o777));
    }
    let store = Store::at_root(
        File::open(root).unwrap(),
        File::open(root.join(DIRECTORY)).unwrap(),
        nix::unistd::geteuid().as_raw(),
        true,
    )
    .unwrap()
    .unwrap();
    store.recover().unwrap();
    assert!(
        std::env::var_os("NANOKVM_APP_SLOT_TEST_STOP").is_none(),
        "requested checkpoint was not reached"
    );
}

#[test]
fn restrictive_child_umask_cannot_publish_an_unreadable_canonical_record() {
    let fixture = Fixture::new(Phase::Published, Position::Published);
    let result = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::app_slot::tests::child_recovery_probe",
            "--ignored",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_APP_SLOT_TEST_ROOT", fixture.root.path())
        .env("NANOKVM_APP_SLOT_TEST_UMASK", "0777")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(
        fixture.current().join(STATE).metadata().unwrap().mode() & 0o7777,
        0o600,
        "the recovery publisher inherited an unsafe record mode from umask"
    );
    fixture.assert_old_restored();
}

#[test]
fn real_sigkill_at_every_recovery_publication_and_rename_boundary_is_recoverable() {
    for point in [
        "rolling-back:record-written",
        "rolling-back:record-synced",
        "rolling-back:record-renamed",
        "rolling-back:record-published",
        "candidate-parked",
        "candidate-parked-synced",
        "old-restored",
        "old-restored-synced",
        "rolled-back:record-written",
        "rolled-back:record-synced",
        "rolled-back:record-renamed",
        "rolled-back:record-published",
    ] {
        let fixture = Fixture::new(Phase::Published, Position::Published);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_slot::tests::child_recovery_probe",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_APP_SLOT_TEST_ROOT", fixture.root.path())
            .env("NANOKVM_APP_SLOT_TEST_STOP", point)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let output = child.stdout.take().unwrap();
        let (send, receive) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else {
                    break;
                };
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
            if line.contains("slot-checkpoint-ready") {
                reached = true;
                break;
            }
        }
        let _ = child.kill();
        let result = child.wait().unwrap();
        reader.join().unwrap();
        assert!(reached, "checkpoint {point} was not reached");
        assert_eq!(result.signal(), Some(9), "checkpoint {point}");
        fixture.store(true).unwrap().recover().unwrap();
        fixture.assert_old_restored();
        fixture.store(true).unwrap().recover().unwrap();
        fixture.assert_old_restored();
    }
}
