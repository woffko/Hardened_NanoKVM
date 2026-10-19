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
        let output = super::super::app_bootstrap::root_tests::run_probe(
            &mut command,
            Duration::from_secs(20),
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
    let mut child = fixture
        .command(if point == "boot-ready" {
            "hold-ready"
        } else {
            "success"
        })
        .env("NANOKVM_NATIVE_BOOTSTRAP_TEST_STOP", point)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (send, receive) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line.unwrap().contains("native-bootstrap-checkpoint-ready") {
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
        "chain" | "hold-ready" => prepare_boot_support().and_then(|support| {
            if expected == "hold-ready" {
                checkpoint("boot-ready");
            }
            let checked = app_bootstrap::check_before_legacy_install();
            drop(support);
            checked
        }),
        "legacy-refusal" => app_bootstrap::check_before_legacy_install(),
        _ => ensure_installed(),
    };
    match expected.as_str() {
        "success" | "chain" | "hold-ready" => {
            result.unwrap();
            check_installed().unwrap();
        }
        "activate" | "ready" | "update-fence" => result.unwrap(),
        "activate-failure" | "ready-failure" => assert!(result.is_err()),
        "failure" | "legacy-refusal" => assert!(result.is_err()),
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
    }
    fs::write(directory.join(".state.next"), b"foreign evidence").unwrap();
    assert!(coordinator.acquire(Kind::ApplicationOffline).is_err());
    assert_eq!(
        fs::read(directory.join(".state.next")).unwrap(),
        b"foreign evidence"
    );
    drop(ProcessLock::acquire().unwrap());
}

#[test]
fn production_update_admission_checks_durable_backend_stop_after_exclusive_lock() {
    Fixture::new().run("update-fence");
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
    assert_eq!(&bytes[..8], b"NKBOOT01");
    assert_eq!(bytes[44], 2);
    fixture.run("ready-failure");
    fixture.run("activate-failure");
    assert_eq!(fs::read(&state).unwrap(), bytes);
}

#[test]
fn fixed_root_factory_activates_only_with_exact_consumer_scripts() {
    for fault in [false, true] {
        let fixture = Fixture::new();
        let parent = fixture.root.path().join("etc/kvm/native-runtime-boot");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let mut bytes = [0; 80];
        bytes[..8].copy_from_slice(b"NKBOOT01");
        bytes[44] = 1;
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(&bytes[..48]);
        bytes[48..].copy_from_slice(&hash);
        fs::write(parent.join("state"), bytes).unwrap();
        fs::set_permissions(parent.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
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
