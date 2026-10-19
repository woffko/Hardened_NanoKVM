use super::*;
use crate::{
    native_owner::controller::{DrainStatus, Group, Role, Status as ScopeStatus},
    update::{
        app_slot::{
            Phase,
            issuer_tests::{accepted_fixture, assert_excluded as excluded},
        },
        operation_lock::ProcessLock,
    },
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::UnixStream,
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn broker(root: &Path) -> Broker {
    Broker {
        group: Group::default(),
        enrollment: super::super::boot::Permit::fixture(&File::open(root).unwrap()),
        update_parent: Some(File::open(root).unwrap()),
        journal: journal::Store::fixture(
            &File::open(root).unwrap(),
            nix::unistd::geteuid().as_raw(),
            "12345678-1234-1234-1234-123456789abc",
        )
        .unwrap(),
    }
}

fn until(mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "app native closure deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn native_phase(root: &Path) -> u8 {
    fs::read(root.join("native-runtime-owner/state")).unwrap()[44]
}

fn start_roles(broker: &mut Broker, root: &Path, missing: bool) {
    for (role, name) in [
        (Role::KvmSystem, "kvm"),
        (Role::Hwmon, "hwmon"),
        (Role::Backend, "backend"),
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "native_owner::broker::app_install::tests::scope_probe",
                "--nocapture",
            ])
            .env_clear()
            .env("NANOKVM_APP_NATIVE_ROOT", root)
            .env("NANOKVM_APP_NATIVE_ROLE", name)
            .env(
                "NANOKVM_APP_NATIVE_RECEIPT",
                if missing && role == Role::Hwmon {
                    "missing"
                } else {
                    "complete"
                },
            )
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if role == Role::Backend {
            let admission = broker.runtime_permit().unwrap();
            broker.start_backend(command, &admission).unwrap();
        } else {
            broker.start_owned(role, command).unwrap();
        }
    }
    until(|| broker.group.poll() == [Some(ScopeStatus::Running); 3]);
}

#[test]
fn scope_probe() {
    let Some(root) = std::env::var_os("NANOKVM_APP_NATIVE_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let role = std::env::var("NANOKVM_APP_NATIVE_ROLE").unwrap();
    assert_eq!(native_phase(root), 1);
    let mut control = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
    control
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    control.write_all(b"R").unwrap();
    let mut stop = [0];
    control.read_exact(&mut stop).unwrap();
    assert_eq!(stop, *b"S");
    assert_eq!(
        native_phase(root),
        4,
        "Stop preceded durable update-admitted intent"
    );
    fs::write(root.join(format!("{role}-stopping")), b"stopping").unwrap();
    if role == "backend" {
        until(|| !root.join("hold-backend").exists());
    }
    if std::env::var("NANOKVM_APP_NATIVE_RECEIPT").unwrap() == "complete" {
        control.write_all(b"D\0").unwrap();
    }
}

#[tokio::test]
async fn all_three_scopes_must_join_before_publication_and_rollback_releases_no_early_lock() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    start_roles(&mut broker, root.path(), false);
    let install = accepted_fixture(root.path()).await;
    let id = install.transaction();
    fs::create_dir(root.path().join("kvmapp/kvm")).unwrap();
    for (name, value) in [
        ("ap.ssid", "synthetic AP"),
        ("ap.pass", "synthetic-only-pass"),
        ("type", "h264"),
        ("fps", "30"),
        ("qlty", "80"),
        ("gop", "30"),
        ("res", "1920x1080"),
    ] {
        fs::write(root.path().join("kvmapp/kvm").join(name), value).unwrap();
    }
    let old_inode = root.path().join("kvmapp").metadata().unwrap().ino();
    fs::write(root.path().join("hold-backend"), b"hold").unwrap();
    let Start::Draining(mut session) = broker.begin_app_install(install) else {
        panic!("admitted app drain refused");
    };
    assert_eq!(session.transaction(), id);
    until(|| root.path().join("backend-stopping").exists());
    assert_eq!(native_phase(root.path()), 4);
    assert!(matches!(session.publish(), Err(SlotError::Busy)));
    assert_eq!(
        root.path().join("kvmapp").metadata().unwrap().ino(),
        old_inode
    );
    excluded(root.path());
    fs::remove_file(root.path().join("hold-backend")).unwrap();
    until(|| matches!(session.poll(), Ok(DrainStatus::Drained)));
    assert_eq!(
        native_phase(root.path()),
        4,
        "drained is not Closed during app work"
    );
    assert_eq!(
        session.publish().unwrap(),
        Status::Transaction(Phase::Published)
    );
    assert_eq!(
        fs::read(root.path().join("kvmapp/version")).unwrap(),
        b"2.0.43\n"
    );
    assert_ne!(
        root.path().join("kvmapp").metadata().unwrap().ino(),
        old_inode
    );
    for name in ["ap.ssid", "ap.pass", "type", "fps", "qlty", "gop", "res"] {
        let path = root.path().join("kvmapp/kvm").join(name);
        assert_eq!(
            fs::read(&path).unwrap(),
            fs::read(
                root.path()
                    .join("application-slot/current/old/kvm")
                    .join(name)
            )
            .unwrap()
        );
        assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o600);
    }
    assert!(matches!(session.publish(), Err(SlotError::Invalid)));
    excluded(root.path());
    let Rollback::Restored(restored) = session.rollback() else {
        panic!("known closed runtime/old slot must recover");
    };
    assert_eq!(restored.transaction(), id);
    excluded(root.path());
    let mut broker = restored.release();
    assert_eq!(
        root.path().join("kvmapp").metadata().unwrap().ino(),
        old_inode
    );
    assert_eq!(
        fs::read(root.path().join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
    assert_eq!(native_phase(root.path()), 1);
    let parent = File::open(root.path()).unwrap();
    until(|| ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).is_ok());
    assert_eq!(
        broker.group.poll(),
        [Some(ScopeStatus::Closed(
            crate::native_owner::controller::Completion::Stopped
        )); 3]
    );
}

#[tokio::test]
async fn missing_native_receipt_never_grants_publication_or_rollback_resume() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    start_roles(&mut broker, root.path(), true);
    let install = accepted_fixture(root.path()).await;
    let old = root.path().join("kvmapp").metadata().unwrap().ino();
    let Start::Draining(mut session) = broker.begin_app_install(install) else {
        panic!("app drain refused");
    };
    until(|| matches!(session.poll(), Ok(DrainStatus::Uncertain)));
    until(|| {
        let _ = session.poll();
        session.group.all_owner_processes_reaped()
    });
    assert!(matches!(session.publish(), Err(SlotError::Busy)));
    let Rollback::Retained(session) = session.rollback() else {
        panic!("uncertain runtime resumed");
    };
    assert_eq!(root.path().join("kvmapp").metadata().unwrap().ino(), old);
    assert_eq!(native_phase(root.path()), 4);
    excluded(root.path());
    drop(session);
    assert!(matches!(
        journal::Store::fixture(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw(),
            "12345678-1234-1234-1234-123456789abc"
        ),
        Err(JournalError::Unresolved)
    ));
}

#[tokio::test]
async fn stop_publication_failure_retains_the_install_and_never_starts_drain() {
    let root = tempfile::tempdir().unwrap();
    let broker = broker(root.path());
    let install = accepted_fixture(root.path()).await;
    let path = root.path().join("native-runtime-owner/.state.next");
    fs::write(&path, b"retain collision").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let Start::Retained { broker, install } = broker.begin_app_install(install) else {
        panic!("uncertain publication authorized Stop");
    };
    assert_eq!(fs::read(&path).unwrap(), b"retain collision");
    assert!(broker.journal.ready().is_err());
    assert!(!root.path().join("native-runtime-owner/state").exists());
    excluded(root.path());
    assert_ne!(install.transaction(), [0; 16]);
    assert_eq!(
        fs::read(root.path().join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
}
