//! Real fixed-root entry, decoded state and update lock in a private chroot.
use super::*;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Duration,
};
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
}
impl Fixture {
    fn new() -> Self {
        embedded_images()
            .expect("run test-native-bootstrap-root.sh with all four actual static bindings");
        let root = tempfile::tempdir().unwrap();
        for parent in [
            "usr/libexec",
            "etc/kvm/update-operation",
            "etc/init.d",
            "kvmapp",
            "proc",
        ] {
            fs::create_dir_all(root.path().join(parent)).unwrap();
        }
        fs::set_permissions(
            root.path().join("etc/kvm/update-operation"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        for (name, bytes) in app_bootstrap::BOOT_SCRIPTS {
            let path = root.path().join("etc/init.d").join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self { root }
    }
    fn path(&self, index: usize) -> std::path::PathBuf {
        self.root
            .path()
            .join("usr/libexec")
            .join(restore_binding::NATIVE_RUNTIMES[index].filename())
    }
    fn seed_factory(&self) -> std::path::PathBuf {
        let parent = self.root.path().join("etc/kvm/native-runtime-boot");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let mut bytes = [0; 112];
        bytes[..8].copy_from_slice(b"NKBOOT02");
        bytes[44] = 1;
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&bytes[..80]);
        bytes[80..].copy_from_slice(&hash);
        fs::write(parent.join("state"), bytes).unwrap();
        fs::set_permissions(parent.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
        // Full-image factory input is separate from native process enrollment.
        let mut pico = [0; 96];
        pico[..8].copy_from_slice(b"NKPENR01");
        pico[8] = 1;
        let mut hash = Sha256::new();
        hash.update(b"NanoKVM Pico enrollment v1\0");
        hash.update(&pico[..64]);
        pico[64..].copy_from_slice(&hash.finalize());
        let anchor = self.root.path().join("etc/kvm/picoclaw-enrollment");
        fs::write(&anchor, pico).unwrap();
        fs::set_permissions(anchor, fs::Permissions::from_mode(0o600)).unwrap();
        parent
    }
    fn command(&self, expected: &str) -> Command {
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--user", "--map-root-user", "--mount", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::native_bootstrap::root_tests::fixed_root_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_NATIVE_ROOT_FIXTURE", self.root.path())
            .env("NANOKVM_NATIVE_ROOT_EXPECTED", expected);
        command
    }
    fn run(&self, expected: &str) {
        let mut command = self.command(expected);
        // A hang check, not a speed check: a child takes about a second, and other
        // work on the machine has stretched it past 20 s (ledger 2026-10-31).
        let output = super::super::app_bootstrap::root_tests::run_probe(
            &mut command,
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(output.status.success(), "{expected}: {output:?}");
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .contains("native-fixed-root-fixture-ran")
        );
    }
}

struct Paused {
    child: Child,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Paused {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}

fn paused(fixture: &Fixture, point: &str) -> Paused {
    let (expected, variable, marker) = if point.starts_with("optional-") {
        (
            "chain",
            "NANOKVM_APP_BOOTSTRAP_TEST_STOP",
            "app-bootstrap-checkpoint-ready",
        )
    } else {
        (
            if point == "boot-ready" {
                "hold-ready"
            } else {
                "success"
            },
            "NANOKVM_NATIVE_BOOTSTRAP_TEST_STOP",
            "native-bootstrap-checkpoint-ready",
        )
    };
    let mut child = fixture
        .command(expected)
        .env(variable, point)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line.unwrap().contains(marker) {
                let _ = send.send(());
                return;
            }
        }
    });
    let child = Paused {
        child,
        reader: Some(reader),
    };
    receive
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| panic!("checkpoint not reached: {point}"));
    child
}

#[test]
fn fixed_root_child() {
    let Ok(root) = std::env::var("NANOKVM_NATIVE_ROOT_FIXTURE") else {
        return;
    };
    let expected = std::env::var("NANOKVM_NATIVE_ROOT_EXPECTED").unwrap();
    // The boot fence must use real procfs, not a fixture UUID in a regular file.
    // This private mount namespace disappears with the child process.
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
    let result = match expected.as_str() {
        "update-fence" => {
            check_production_update_fence();
            Ok(())
        }
        "activate" | "activate-failure" => {
            crate::native_owner::broker::boot::activate_early().map_err(io::Error::other)
        }
        "ready" | "ready-failure" => crate::native_owner::broker::boot::require_ready()
            .map(drop)
            .map_err(io::Error::other),
        "chain" | "hold-ready" | "chain-failure" => prepare_boot_support().and_then(|support| {
            let writers = super::super::state_writers::StateWriters::default();
            assert!(writers.configuration().is_err());
            if expected == "hold-ready" {
                checkpoint("boot-ready");
            }
            let checked = app_bootstrap::check_before_legacy_install();
            drop(support);
            assert!(writers.configuration().is_ok());
            checked
        }),
        "configuration-busy" => {
            let writers = super::super::state_writers::StateWriters::default();
            let config = writers.configuration().unwrap();
            assert!(prepare_boot_support().is_err());
            assert!(fs::read_dir("/usr/libexec").unwrap().next().is_none());
            assert!(!Path::new("/etc/kvm/native-runtime-boot/state").exists());
            assert!(ProcessLock::acquire().is_ok());
            drop(config);
            drop(prepare_boot_support().unwrap());
            assert!(writers.configuration().is_ok());
            Ok(())
        }
        "configuration-observer-busy" => {
            assert!(
                super::super::state_writers::StateWriters::default()
                    .configuration()
                    .is_err()
            );
            Ok(())
        }
        "publication-authority" => {
            check_boot_publication_authority();
            Ok(())
        }
        "publication-shared-refusal" => {
            let permit = crate::native_owner::broker::boot::require_ready().unwrap();
            assert!(permit.check_armed_publication().is_err());
            Ok(())
        }
        "legacy-refusal" => app_bootstrap::check_before_legacy_install(),
        _ => ensure_installed(),
    };
    match expected.as_str() {
        "success" | "chain" | "hold-ready" => {
            result.unwrap();
            check_installed().unwrap();
        }
        "activate"
        | "ready"
        | "update-fence"
        | "configuration-busy"
        | "configuration-observer-busy"
        | "publication-authority"
        | "publication-shared-refusal" => result.unwrap(),
        "activate-failure" | "ready-failure" => assert!(result.is_err()),
        "failure" | "legacy-refusal" | "chain-failure" => {
            assert!(result.is_err());
            assert!(
                super::super::state_writers::StateWriters::default()
                    .configuration()
                    .is_ok()
            );
        }
        "busy" => {
            let error = result.unwrap_err();
            assert!(matches!(
                error.get_ref().and_then(
                    |error| error.downcast_ref::<super::super::operation_lock::LockError>()
                ),
                Some(super::super::operation_lock::LockError::Busy)
            ));
        }
        _ => panic!("invalid native fixture case"),
    }
    println!("native-fixed-root-fixture-ran");
}

fn check_boot_publication_authority() {
    use sha2::{Digest, Sha256};
    let support = prepare_boot_support().unwrap();
    let path = Path::new("/etc/kvm/native-runtime-boot/state");
    let armed = fs::read(path).unwrap();
    assert_eq!(armed[44], 2);
    assert!(support._boot.check_armed_publication().is_ok());
    for case in ["factory", "prior-armed", "ready", "corrupt"] {
        let mut bytes = armed.clone();
        match case {
            "factory" => {
                bytes[8..44].fill(0);
                bytes[44] = 1;
            }
            "prior-armed" => {
                let prior = b"00000000-0000-4000-8000-000000000001";
                assert_ne!(&bytes[8..44], prior);
                bytes[8..44].copy_from_slice(prior);
            }
            "ready" => {
                bytes[44] = 3;
                bytes[48..80].fill(0x21);
            }
            "corrupt" => bytes[0] ^= 1,
            _ => unreachable!(),
        }
        let digest = Sha256::digest(&bytes[..80]);
        bytes[80..].copy_from_slice(&digest);
        fs::write(path, &bytes).unwrap();
        assert!(support._boot.check_armed_publication().is_err(), "{case}");
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    fs::write(path, &armed).unwrap();
    assert!(support._boot.check_armed_publication().is_ok());
}

fn check_production_update_fence() {
    use crate::update::operation::{Kind, UpdateCoordinator};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;
    // No test-parent escape: exercise the real fixed-root coordinator path
    // after chroot with actual procfs and kernel boot identity.
    let coordinator = Arc::new(UpdateCoordinator::default());
    drop(coordinator.acquire(Kind::SystemInstall).unwrap());
    let directory = Path::new("/etc/kvm/native-runtime-owner");
    fs::create_dir(directory).unwrap();
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    let boot = fs::read("/proc/sys/kernel/random/boot_id").unwrap();
    let mut bytes = [0; 80];
    bytes[..8].copy_from_slice(b"NKBROK01");
    bytes[8..44].copy_from_slice(&boot[..36]);
    for phase in [1, 2, 3, 4] {
        bytes[44] = phase;
        let hash = Sha256::digest(&bytes[..48]);
        bytes[48..].copy_from_slice(&hash);
        fs::write(directory.join("state"), bytes).unwrap();
        fs::set_permissions(directory.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
        for kind in [
            Kind::ApplicationOnline,
            Kind::ApplicationOffline,
            Kind::SystemDownload,
            Kind::SystemInstall,
            Kind::SystemRollback,
            Kind::SystemConfirm,
        ] {
            let result = coordinator.acquire(kind);
            assert_eq!(result.is_ok(), phase != 4, "phase={phase}, kind={kind:?}");
            drop(result);
            // A denied admission must release the kernel guard, not leak it.
            drop(ProcessLock::acquire().unwrap());
        }
        if phase != 2 {
            let app = Path::new("/etc/kvm/application-slot/current/state");
            let before = fs::read(app).unwrap();
            assert!(matches!(
                crate::update::app_slot::recover(),
                Err(crate::update::app_slot::SlotError::Busy)
            ));
            assert_eq!(fs::read(app).unwrap(), before);
        }
    }
    // UpdateEX is available after installer loss; it is not closure proof for
    // the independently owned trial runtime in this same kernel boot.
    let app = Path::new("/etc/kvm/application-slot/current");
    let before = fs::read(app.join("state")).unwrap();
    let live = fs::metadata("/kvmapp").unwrap().ino();
    let old = fs::metadata(app.join("old")).unwrap().ino();
    for direct in [true, false] {
        let result = if direct {
            crate::update::app_slot::recover()
        } else {
            crate::update::app_slot::boot_gate()
        };
        assert!(matches!(
            result,
            Err(crate::update::app_slot::SlotError::Busy)
        ));
        assert_eq!(fs::read(app.join("state")).unwrap(), before);
        assert_eq!(fs::metadata("/kvmapp").unwrap().ino(), live);
        assert_eq!(fs::metadata(app.join("old")).unwrap().ino(), old);
        assert!(!app.join("new").exists());
        assert_eq!(fs::read(directory.join("state")).unwrap(), bytes);
        drop(ProcessLock::acquire().unwrap());
    }
    fs::write(directory.join(".state.next"), b"foreign evidence").unwrap();
    assert!(coordinator.acquire(Kind::ApplicationOffline).is_err());
    assert_eq!(
        fs::read(directory.join(".state.next")).unwrap(),
        b"foreign evidence"
    );
    drop(ProcessLock::acquire().unwrap());
    assert!(matches!(
        crate::update::app_slot::recover(),
        Err(crate::update::app_slot::SlotError::Busy)
    ));
    assert_eq!(fs::read(app.join("state")).unwrap(), before);
    // A synthetic prior epoch may run guarded rollback and exact archival.
    // This does not assert runtime health or simulate an actual power cut.
    fs::remove_file(directory.join(".state.next")).unwrap();
    let previous = b"00000000-0000-4000-8000-000000000001";
    assert_ne!(&bytes[8..44], previous);
    bytes[8..44].copy_from_slice(previous);
    let hash = Sha256::digest(&bytes[..48]);
    bytes[48..].copy_from_slice(&hash);
    fs::write(directory.join("state"), bytes).unwrap();
    assert_eq!(
        crate::update::app_slot::recover().unwrap(),
        crate::update::app_slot::Status::Transaction(crate::update::app_slot::Phase::RolledBack)
    );
    assert_eq!(fs::metadata("/kvmapp").unwrap().ino(), old);
    let native = fs::read(directory.join("state")).unwrap();
    assert_eq!(&native[8..44], &boot[..36]);
    assert_eq!(native[44], 2);
    assert_eq!(
        crate::update::app_slot::status().unwrap(),
        crate::update::app_slot::Status::NoTransaction
    );
    let transaction: [u8; 16] = before[16..32].try_into().unwrap();
    let snapshot = crate::update::app_slot::job_status(transaction)
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.phase, crate::update::app_slot::Phase::RolledBack);
    assert!(snapshot.archived);
    // Even with no current and an otherwise valid history record, a torn
    // recovery intent cannot become NoTransaction/bootstrap permission.
    let next = Path::new("/etc/kvm/application-slot/.recovery.next");
    let history = Path::new("/etc/kvm/application-slot/history")
        .join(format!("{:032x}", u128::from_be_bytes(transaction)))
        .join("state");
    let archived = fs::read(&history).unwrap();
    let native_before = fs::read(directory.join("state")).unwrap();
    fs::write(next, b"torn recovery receipt").unwrap();
    fs::set_permissions(next, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(crate::update::app_slot::status().is_err());
    assert!(crate::update::app_slot::boot_gate().is_err());
    assert!(crate::update::app_slot::recover().is_err());
    assert!(ensure_installed().is_err());
    assert!(app_bootstrap::ensure_installed().is_err());
    assert!(fs::read_dir("/usr/libexec").unwrap().next().is_none());
    assert_eq!(fs::read(next).unwrap(), b"torn recovery receipt");
    assert_eq!(fs::read(history).unwrap(), archived);
    assert_eq!(fs::read(directory.join("state")).unwrap(), native_before);
}

#[test]
fn production_update_admission_checks_durable_backend_stop_after_exclusive_lock() {
    let fixture = Fixture::new();
    crate::update::app_slot::issuer_tests::fixed_root_recovery_fixture(fixture.root.path());
    fixture.run("update-fence");
}

#[test]
fn fixed_root_live_transition_only_arms_and_cannot_activate_in_same_boot() {
    let fixture = Fixture::new();
    fixture.run("chain");
    let state = fixture
        .root
        .path()
        .join("etc/kvm/native-runtime-boot/state");
    let bytes = fs::read(&state).unwrap();
    assert_eq!(&bytes[..8], b"NKBOOT02");
    assert_eq!(bytes[44], 2);
    fixture.run("ready-failure");
    fixture.run("activate-failure");
    assert_eq!(fs::read(&state).unwrap(), bytes);
}

#[test]
fn fixed_root_factory_activates_only_with_exact_consumer_scripts() {
    for fault in [false, true] {
        let fixture = Fixture::new();
        let parent = fixture.seed_factory();
        if fault {
            fs::write(
                fixture.root.path().join("etc/init.d/S30wifi"),
                b"legacy script",
            )
            .unwrap();
        }
        fixture.run(if fault {
            "activate-failure"
        } else {
            "activate"
        });
        fixture.run(if fault { "ready-failure" } else { "ready" });
        if !fault {
            let before = parent.join("state").metadata().unwrap().ino();
            // Actual S02 core -> backend BootSupport on the same kernel epoch.
            fixture.run("chain");
            fixture.run("ready");
            assert_eq!(parent.join("state").metadata().unwrap().ino(), before);
        }
        assert_eq!(
            fs::read(parent.join("state")).unwrap()[44],
            if fault { 1 } else { 3 }
        );
    }
}

#[test]
fn boot_support_retains_configuration_and_refuses_contention_before_publication() {
    Fixture::new().run("configuration-busy");
}

#[test]
fn optional_publication_requires_exclusive_current_boot_armed_authority() {
    Fixture::new().run("publication-authority");
    let fixture = Fixture::new();
    let parent = fixture.seed_factory();
    fixture.run("activate");
    let before = fs::read(parent.join("state")).unwrap();
    fixture.run("publication-shared-refusal");
    assert_eq!(fs::read(parent.join("state")).unwrap(), before);
    fixture.run("ready");
}

#[test]
fn optional_bootstrap_preserves_absence_and_only_migrates_the_exact_rc12_source() {
    let legacy = include_bytes!("../../tests/fixtures/rc12-S96picoclaw.sh");
    use sha2::{Digest, Sha256};
    assert_eq!(legacy.len(), 3316);
    assert_eq!(
        format!("{:x}", Sha256::digest(legacy)),
        "499258cb3d84aad2ddf179b7d5f6e3e82abb7db889f3db22b8ae3a9f0ae88272"
    );
    for case in [
        "absent",
        "current",
        "legacy",
        "custom",
        "mode",
        "symlink",
        "hardlink",
        "fifo",
        "directory",
    ] {
        let fixture = Fixture::new();
        let path = fixture.root.path().join("etc/init.d/S96picoclaw");
        if case != "absent" {
            fs::write(
                &path,
                if case == "current" {
                    app_bootstrap::PICO_BOOT_SCRIPT
                } else {
                    legacy
                },
            )
            .unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            match case {
                "custom" => fs::write(&path, b"custom optional service; preserve me").unwrap(),
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    std::os::unix::fs::symlink("S95nanokvm", &path).unwrap();
                }
                "hardlink" => fs::hard_link(&path, path.with_file_name("pico-alias")).unwrap(),
                "fifo" => {
                    fs::remove_file(&path).unwrap();
                    nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
                }
                "directory" => {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                _ => {}
            }
        }
        let before = fs::symlink_metadata(&path).ok().map(|m| m.ino());
        let allowed = matches!(case, "absent" | "current" | "legacy");
        fixture.run(if allowed { "chain" } else { "chain-failure" });
        let evidence: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".S96picoclaw-next-")
            })
            .collect();
        if case == "absent" {
            assert!(!path.exists());
            assert!(evidence.is_empty());
            continue;
        }
        if !allowed {
            assert_eq!(path.symlink_metadata().unwrap().ino(), before.unwrap());
            assert!(evidence.is_empty());
            match case {
                "custom" => assert_eq!(
                    fs::read(&path).unwrap(),
                    b"custom optional service; preserve me"
                ),
                "mode" => {
                    assert_eq!(fs::read(&path).unwrap(), legacy);
                    assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o644);
                }
                "symlink" => assert_eq!(fs::read_link(&path).unwrap(), Path::new("S95nanokvm")),
                "hardlink" => {
                    assert_eq!(fs::read(&path).unwrap(), legacy);
                    assert_eq!(path.metadata().unwrap().nlink(), 2);
                }
                "fifo" => assert!(std::os::unix::fs::FileTypeExt::is_fifo(
                    &path.symlink_metadata().unwrap().file_type()
                )),
                "directory" => assert!(path.is_dir()),
                _ => unreachable!(),
            }
            continue;
        }
        assert_eq!(fs::read(&path).unwrap(), app_bootstrap::PICO_BOOT_SCRIPT);
        if case == "legacy" {
            assert_ne!(path.metadata().unwrap().ino(), before.unwrap());
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].metadata().unwrap().ino(), before.unwrap());
            assert_eq!(fs::read(&evidence[0]).unwrap(), legacy);
        } else {
            assert_eq!(path.metadata().unwrap().ino(), before.unwrap());
            assert!(evidence.is_empty());
        }
        let inode = path.metadata().unwrap().ino();
        fixture.run("chain");
        assert_eq!(path.metadata().unwrap().ino(), inode);
        fixture.run("activate-failure");
        fixture.run("ready-failure");
    }
}

#[test]
fn optional_publication_process_death_keeps_old_evidence_and_never_grants_ready() {
    let legacy = include_bytes!("../../tests/fixtures/rc12-S96picoclaw.sh");
    for point in [
        "optional-written",
        "optional-synced",
        "optional-exchanged",
        "optional-published",
        "optional-verified",
    ] {
        let fixture = Fixture::new();
        let path = fixture.root.path().join("etc/init.d/S96picoclaw");
        fs::write(&path, legacy).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let legacy_inode = path.metadata().unwrap().ino();
        let mut child = paused(&fixture, point);
        fixture.run("busy");
        fixture.run("configuration-observer-busy");
        fixture.run("ready-failure");
        child.child.kill().unwrap();
        assert_eq!(child.child.wait().unwrap().signal(), Some(9));
        drop(child);
        let exchanged = matches!(
            point,
            "optional-exchanged" | "optional-published" | "optional-verified"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            if exchanged {
                app_bootstrap::PICO_BOOT_SCRIPT
            } else {
                legacy
            },
            "{point}"
        );
        let evidence: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".S96picoclaw-next-")
            })
            .map(|path| {
                let metadata = path.metadata().unwrap();
                let bytes = fs::read(&path).unwrap();
                (path, metadata.ino(), metadata.mode() & 0o7777, bytes)
            })
            .collect();
        assert_eq!(evidence.len(), 1, "{point}");
        if exchanged {
            assert_eq!(evidence[0].1, legacy_inode);
            assert_eq!(evidence[0].3, legacy);
        }
        let state = fixture
            .root
            .path()
            .join("etc/kvm/native-runtime-boot/state");
        let armed = fs::read(&state).unwrap();
        assert_eq!(armed[44], 2);
        assert_eq!(&armed[45..80], &[0; 35]);
        fixture.run("activate-failure");
        fixture.run("ready-failure");
        fixture.run("chain");
        fixture.run("chain");
        assert_eq!(fs::read(&path).unwrap(), app_bootstrap::PICO_BOOT_SCRIPT);
        assert_eq!(fs::read(&state).unwrap(), armed);
        for (path, inode, mode, bytes) in evidence {
            let metadata = path.metadata().unwrap();
            assert_eq!(metadata.ino(), inode, "{point}");
            assert_eq!(metadata.mode() & 0o7777, mode, "{point}");
            assert_eq!(fs::read(path).unwrap(), bytes, "{point}");
        }
        fixture.run("activate-failure");
        fixture.run("ready-failure");
    }
}

#[test]
fn fixed_root_optional_script_change_never_inherits_same_boot_ready() {
    let source = include_bytes!("../../../kvmapp/system/init.d/S96picoclaw");
    for change in ["add", "remove", "replace", "symlink", "hardlink"] {
        let fixture = Fixture::new();
        let parent = fixture.seed_factory();
        let script = fixture.root.path().join("etc/init.d/S96picoclaw");
        if change != "add" {
            fs::write(&script, source).unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fixture.run("activate");
        fixture.run("ready");
        let before = fs::read(parent.join("state")).unwrap();
        assert_eq!(before[45], u8::from(change != "add"));
        assert_ne!(&before[48..80], &[0; 32]);
        match change {
            "add" => {
                fs::write(&script, source).unwrap();
                fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            }
            "remove" => fs::remove_file(&script).unwrap(),
            "replace" => fs::write(&script, b"legacy independent gateway launcher").unwrap(),
            "symlink" => {
                fs::remove_file(&script).unwrap();
                std::os::unix::fs::symlink("S95nanokvm", &script).unwrap();
            }
            "hardlink" => fs::hard_link(&script, script.with_file_name("alias")).unwrap(),
            _ => unreachable!(),
        }
        fixture.run("ready-failure");
        fixture.run("activate-failure");
        assert_eq!(fs::read(parent.join("state")).unwrap(), before);
        if matches!(change, "add" | "remove") {
            fixture.run("chain");
            let armed = fs::read(parent.join("state")).unwrap();
            assert_eq!(armed[44], 2);
            assert_eq!(&armed[45..80], &[0; 35]);
            fixture.run("activate-failure");
            fixture.run("ready-failure");
        } else {
            fixture.run("chain-failure");
            assert_eq!(fs::read(parent.join("state")).unwrap(), before);
        }
    }
}

#[test]
fn actual_fixed_root_installs_exact_family_and_preserves_every_existing_inode() {
    let fixture = Fixture::new();
    fixture.run("success");
    let images = embedded_images().unwrap();
    let inodes =
        std::array::from_fn::<_, 4, _>(|index| fixture.path(index).metadata().unwrap().ino());
    fixture.run("success");
    for index in 0..4 {
        assert_eq!(fs::read(fixture.path(index)).unwrap(), images[index]);
        assert_eq!(fixture.path(index).metadata().unwrap().ino(), inodes[index]);
        assert_eq!(
            fixture.path(index).metadata().unwrap().mode() & 0o7777,
            0o755
        );
    }
}

#[test]
fn actual_app_bootstrap_and_legacy_prerequisite_require_the_complete_native_family() {
    let fixture = Fixture::new();
    fixture.run("chain");
    let helper = fixture.root.path().join("usr/libexec/nanokvm-app-recovery");
    let before = helper.metadata().unwrap().ino();
    fs::remove_file(fixture.path(3)).unwrap();
    fixture.run("legacy-refusal");
    assert!(!fixture.path(3).exists());
    assert_eq!(helper.metadata().unwrap().ino(), before);
}

#[test]
fn actual_fixed_root_rejects_foreign_late_role_before_installing_other_names() {
    let fixture = Fixture::new();
    fs::write(fixture.path(3), b"unrecognized existing recovery helper").unwrap();
    fs::set_permissions(fixture.path(3), fs::Permissions::from_mode(0o755)).unwrap();
    let inode = fixture.path(3).metadata().unwrap().ino();
    fixture.run("failure");
    assert_eq!(
        fs::read(fixture.path(3)).unwrap(),
        b"unrecognized existing recovery helper"
    );
    assert_eq!(fixture.path(3).metadata().unwrap().ino(), inode);
    assert_eq!(
        fs::read_dir(fixture.path(0).parent().unwrap())
            .unwrap()
            .count(),
        1
    );
}

#[test]
fn actual_fixed_root_refuses_a_competing_update_lease() {
    let fixture = Fixture::new();
    let parent = File::open(fixture.root.path().join("etc/kvm")).unwrap();
    let admission = ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap();
    fixture.run("busy");
    assert_eq!(
        fs::read_dir(fixture.path(0).parent().unwrap())
            .unwrap()
            .count(),
        0
    );
    drop(admission);
    fixture.run("success");
}

#[test]
fn corrupt_decoded_journal_prevents_any_native_publication() {
    let fixture = Fixture::new();
    let current = fixture.root.path().join("etc/kvm/application-slot/current");
    fs::create_dir_all(&current).unwrap();
    fs::set_permissions(current.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(current.join("state"), b"corrupt native bootstrap fixture").unwrap();
    fs::set_permissions(current.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
    fixture.run("failure");
    assert_eq!(
        fs::read(current.join("state")).unwrap(),
        b"corrupt native bootstrap fixture"
    );
    assert_eq!(
        fs::read_dir(fixture.path(0).parent().unwrap())
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn process_death_at_every_family_boundary_keeps_admission_and_resumes_exactly() {
    for point in [
        "staged-0",
        "staged-1",
        "staged-2",
        "staged-3",
        "published-0",
        "published-1",
        "published-2",
        "published-3",
        "verified",
        "boot-ready",
    ] {
        let fixture = Fixture::new();
        let mut child = paused(&fixture, point);
        fixture.run("busy");
        child.child.kill().unwrap();
        assert_eq!(child.child.wait().unwrap().signal(), Some(9));
        drop(child);
        let old = std::array::from_fn::<_, 4, _>(|index| {
            fixture
                .path(index)
                .metadata()
                .ok()
                .map(|metadata| metadata.ino())
        });
        fixture.run("success");
        fixture.run("success");
        let images = embedded_images().unwrap();
        for index in 0..4 {
            assert_eq!(
                fs::read(fixture.path(index)).unwrap(),
                images[index],
                "{point}"
            );
            if let Some(inode) = old[index] {
                assert_eq!(
                    fixture.path(index).metadata().unwrap().ino(),
                    inode,
                    "{point}"
                );
            }
        }
    }
}
