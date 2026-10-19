use super::*;
use crate::update::app_slot::issuer_tests::{assert_excluded, prepared_fixture};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::Child,
};

struct ChildOwner(Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child(root: &Path, name: &str) -> ChildOwner {
    ChildOwner(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("native_owner::broker::ipc::tests::delivery::{name}"),
                "--nocapture",
            ])
            .env_clear()
            .env("NANOKVM_DELIVERY_FIXTURE", root)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

#[test]
fn broker_child() {
    let Some(root) = std::env::var_os("NANOKVM_DELIVERY_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    let mut server = Server::new(broker(root), nix::unistd::geteuid().as_raw()).unwrap();
    server.engine.fixture = Some(root.to_path_buf());
    fs::write(root.join("broker-ready"), b"ready").unwrap();
    server.run().unwrap();
}

#[test]
fn frontend_child() {
    let Some(root) = std::env::var_os("NANOKVM_DELIVERY_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let (owner, prepared) = runtime.block_on(prepared_fixture(root));
    let directory = File::open(root.join("native-runtime-owner")).unwrap();
    let socket =
        journal::socket::connect_install(&directory, nix::unistd::geteuid().as_raw()).unwrap();
    let sender =
        app_install_lease::Sender::fixture(socket, nix::unistd::geteuid().as_raw()).unwrap();
    sender.send(prepared.into_handoff()).unwrap();
    fs::write(root.join("offer-sent"), b"queued only").unwrap();
    // The parent kills this actual frontend while its original UpdateOwner is
    // still live. Queued rights, not orderly destructors, must retain admission.
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    drop(owner);
    panic!("frontend should have been killed");
}

#[test]
fn independent_daemon_accepts_queued_install_after_actual_frontend_death_and_can_rollback() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path();
    fs::write(path.join("hold-install-offer"), b"hold").unwrap();
    let mut daemon = child(path, "broker_child");
    until(|| path.join("broker-ready").exists());
    let mut control = connect(path);
    for op in [
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::EnsureBackend,
    ] {
        assert_eq!(exchange(&mut control, op).code, Code::Ok);
    }
    until(|| exchange(&mut control, Operation::Observe).roles == [2; 2]);
    until(|| exchange(&mut control, Operation::BackendRunning).code == Code::Ok);
    let mut frontend = child(path, "frontend_child");
    until(|| path.join("offer-sent").exists());
    let old_inode = path.join("kvmapp").metadata().unwrap().ino();
    frontend.0.kill().unwrap();
    let status = frontend.0.wait().unwrap();
    assert!(!status.success());
    assert_excluded(path);
    assert_eq!(
        exchange(&mut control, Operation::Observe).mode,
        Mode::Running
    );
    fs::remove_file(path.join("hold-install-offer")).unwrap();
    observed(&mut control, Mode::Installing);
    until(|| {
        fs::read(path.join("application-slot/current/state")).unwrap()[8]
            == app_slot::Phase::Published as u8
    });
    assert_ne!(path.join("kvmapp").metadata().unwrap().ino(), old_inode);
    assert_eq!(fs::read(path.join("kvmapp/version")).unwrap(), b"2.0.43\n");
    assert_eq!(
        fs::read(path.join("native-runtime-owner/state")).unwrap()[44],
        4
    );
    assert_excluded(path);
    // Neither the disappeared sender nor a fresh lifecycle connection owns the
    // install. Ordinary restarts/shutdown cannot release/reacquire its leases.
    drop(control);
    control = connect(path);
    for op in [
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::EnsureBackend,
        Operation::RestartBackend,
        Operation::Pause,
        Operation::Resume,
        Operation::Shutdown,
    ] {
        assert_eq!(exchange(&mut control, op).code, Code::Busy);
    }
    assert_excluded(path);
    assert_eq!(
        exchange(&mut control, Operation::CancelAppInstall).code,
        Code::Ok
    );
    assert_eq!(path.join("kvmapp").metadata().unwrap().ino(), old_inode);
    assert_eq!(
        fs::read(path.join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
    until(|| exchange(&mut control, Operation::BackendRunning).code == Code::Ok);
    let reply = exchange(&mut control, Operation::Shutdown);
    assert_eq!(reply.code, Code::Ok);
    if reply.mode != Mode::Stopped {
        observed(&mut control, Mode::Stopped);
    }
    until(|| daemon.0.try_wait().unwrap().is_some());
    assert!(daemon.0.wait().unwrap().success());
    for name in ["control.sock", "app-install.sock"] {
        assert!(!path.join("native-runtime-owner").join(name).exists());
    }
}

#[test]
fn install_endpoint_is_private_independent_and_does_not_delete_foreign_replacements() {
    let root = tempfile::tempdir().unwrap();
    let broker = broker(root.path());
    let control = broker.journal.endpoint().unwrap();
    let endpoint = broker.journal.install_endpoint().unwrap();
    let directory = root.path().join("native-runtime-owner");
    let path = directory.join("app-install.sock");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(
        rustix::net::sockopt::socket_type(&endpoint.listener).unwrap(),
        rustix::net::SocketType::SEQPACKET
    );
    assert_eq!(
        rustix::net::sockopt::socket_type(&control.listener).unwrap(),
        rustix::net::SocketType::STREAM
    );
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"foreign replacement").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    drop(endpoint);
    assert_eq!(fs::read(&path).unwrap(), b"foreign replacement");
    assert!(broker.journal.install_endpoint().is_err());
    assert!(directory.join("control.sock").exists());
}

#[test]
fn stalled_or_malformed_install_offer_does_not_block_lifecycle_or_stop_backend() {
    let root = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    let mut server = Server::new(broker(root.path()), uid).unwrap();
    server.engine.fixture = Some(root.path().to_path_buf());
    server.idle = Duration::from_millis(200);
    let directory = File::open(root.path().join("native-runtime-owner")).unwrap();
    let mut pending = Vec::new();
    for _ in 0..INSTALL_OFFERS {
        pending.push(journal::socket::connect_install(&directory, uid).unwrap());
    }
    // Queue the malformed frame BEFORE the server can expire this connection.
    // Backend process startup under a loaded full suite may exceed the fixture's
    // 200ms idle deadline; that expiry is correct, not a failed malformed offer.
    rustix::net::send(
        &pending[0],
        b"not a lease offer",
        rustix::net::SendFlags::NOSIGNAL,
    )
    .unwrap();
    serve_prepared(server, || {
        let mut control = connect(root.path());
        assert_eq!(
            exchange(&mut control, Operation::EnsureBackend).code,
            Code::Ok
        );
        until(|| exchange(&mut control, Operation::BackendRunning).code == Code::Ok);
        for _ in 0..4 {
            assert_eq!(
                exchange(&mut control, Operation::Observe).mode,
                Mode::Running
            );
        }
        assert_eq!(
            exchange(&mut control, Operation::BackendRunning).code,
            Code::Ok
        );
        assert!(!root.path().join("application-slot").exists());
        let reply = exchange(&mut control, Operation::Shutdown);
        if reply.mode != Mode::Stopped {
            observed(&mut control, Mode::Stopped);
        }
    });
}

#[test]
fn expired_offer_slots_are_closed_and_reusable_for_a_valid_install() {
    let root = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    serve(root.path(), uid, || {
        let directory = File::open(root.path().join("native-runtime-owner")).unwrap();
        let mut stalled = Vec::new();
        for _ in 0..INSTALL_OFFERS {
            stalled.push(journal::socket::connect_install(&directory, uid).unwrap());
        }
        // Observe actual EOF, not an assumed elapsed sleep. The fixture uses
        // the same idle field as production, with a shorter local deadline.
        for socket in &stalled {
            until(|| {
                matches!(
                    rustix::net::recv(socket, &mut [0u8; 1], rustix::net::RecvFlags::DONTWAIT),
                    Ok((0, _))
                )
            });
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let (owner, prepared) = runtime.block_on(prepared_fixture(root.path()));
        let socket = journal::socket::connect_install(&directory, uid).unwrap();
        app_install_lease::Sender::fixture(socket, uid)
            .unwrap()
            .send(prepared.into_handoff())
            .unwrap();
        drop(owner);
        let mut control = connect(root.path());
        observed(&mut control, Mode::Installing);
        until(|| {
            fs::read(root.path().join("application-slot/current/state")).unwrap()[8]
                == app_slot::Phase::Published as u8
        });
        assert_excluded(root.path());
        assert_eq!(
            exchange(&mut control, Operation::CancelAppInstall).code,
            Code::Ok
        );
        until(|| {
            let reply = exchange(&mut control, Operation::Shutdown);
            assert!(matches!(reply.code, Code::Ok | Code::Busy));
            reply.mode == Mode::Stopped
        });
    });
}

#[tokio::test]
async fn invalid_canonical_receipt_rejects_valid_leases_before_any_native_stop() {
    let root = tempfile::tempdir().unwrap();
    let mut e = engine(root.path());
    e.request(1, Operation::EnsureBackend);
    until(|| {
        e.tick();
        e.backend_status == Some(Status::Running)
    });
    let backend = fs::read(root.path().join("backend")).unwrap();
    let (owner, prepared) = prepared_fixture(root.path()).await;
    let admission = app_slot::issuer_tests::received_fixture(root.path(), prepared);
    let state = root.path().join("application-slot/current/state");
    let mut record = fs::read(&state).unwrap();
    record[8] = app_slot::Phase::Published as u8; // Wrong phase and checksum.
    fs::write(&state, &record).unwrap();
    assert_eq!(e.accept_install(admission), Code::Invalid);
    assert!(e.install.is_none());
    assert_eq!(e.mode, Mode::Running);
    assert_eq!(e.backend_status, Some(Status::Running));
    assert_eq!(fs::read(root.path().join("backend")).unwrap(), backend);
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    assert_eq!(fs::read(&state).unwrap(), record);
    assert_eq!(
        fs::read(root.path().join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
    drop(owner);
    // Invalid journal is deliberately retained. This test closes the fixture
    // scopes through the already admitted broker, not via app recovery.
    until(|| {
        let reply = e.request(1, Operation::Shutdown);
        assert!(matches!(reply.code, Code::Ok | Code::Busy));
        e.mode == Mode::Stopped
    });
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn fixed_root_delivery_child() {
    use crate::{
        api::application::manual_candidate_fixture,
        update::{
            app_stage::AppStage,
            operation::{Kind, UpdateCoordinator},
            state_writers::StateWriters,
        },
    };
    use nix::mount::{MsFlags, mount};
    use std::sync::Arc;
    let Some(root) = std::env::var_os("NANOKVM_DELIVERY_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    assert!(nix::unistd::geteuid().is_root());
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    fs::create_dir_all(root.join("etc/kvm")).unwrap();
    fs::create_dir(root.join("proc")).unwrap();
    fs::create_dir(root.join("kvmapp")).unwrap();
    fs::write(root.join("kvmapp/identity"), b"fixed-root old app").unwrap();
    mount(
        Some("proc"),
        &root.join("proc"),
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID,
        None::<&str>,
    )
    .unwrap();
    nix::unistd::chroot(root).unwrap();
    std::env::set_current_dir("/").unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    // Only native enrollment/process execution are fixture supplied. Endpoint
    // connect, Incoming::open, prepared issuer and acceptance use fixed roots.
    let mut server = Server::new(broker(Path::new("/etc/kvm")), uid).unwrap();
    let (send, recv) = std::sync::mpsc::channel();
    server.cancel = Some(recv);
    std::thread::scope(|scope| {
        let thread = scope.spawn(move || server.run());
        let guard = Cancel(send);
        let coordinator = Arc::new(UpdateCoordinator::default());
        let owner = coordinator.acquire(Kind::ApplicationOffline).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let drain = runtime
            .block_on(StateWriters::default().drain(Duration::from_secs(1)))
            .unwrap();
        let candidate = manual_candidate_fixture(
            AppStage::prepare().unwrap(),
            &app_slot::issuer_tests::archive(),
        )
        .unwrap();
        let prepared =
            app_slot::prepare(candidate, owner.prepare_install_handoff(drain).unwrap()).unwrap();
        let id = prepared.transaction();
        app_install_lease::Sender::connect_broker()
            .unwrap()
            .send(prepared.into_handoff())
            .unwrap();
        drop(owner);
        let mut control = Channel::connect().unwrap();
        observed(&mut control, Mode::Installing);
        until(|| {
            fs::read("/etc/kvm/application-slot/current/state").unwrap()[8]
                == app_slot::Phase::Published as u8
        });
        let record = fs::read("/etc/kvm/application-slot/current/state").unwrap();
        assert_eq!(record[16..32], id);
        assert!(matches!(app_slot::status(), Err(app_slot::SlotError::Busy)));
        assert_eq!(
            exchange(&mut control, Operation::CancelAppInstall).code,
            Code::Ok
        );
        assert_eq!(fs::read("/kvmapp/identity").unwrap(), b"fixed-root old app");
        until(|| {
            let reply = exchange(&mut control, Operation::Shutdown);
            assert!(matches!(reply.code, Code::Ok | Code::Busy));
            reply.mode == Mode::Stopped
        });
        drop(guard);
        let result = thread.join().unwrap();
        assert!(result.is_ok() || result.unwrap_err().kind() == io::ErrorKind::Interrupted);
    });
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn actual_named_endpoint_uses_production_fixed_root_sender_receiver_and_issuer() {
    let root = tempfile::tempdir().unwrap();
    let mut worker = ChildOwner(
        Command::new("/usr/bin/unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--pid",
                "--fork",
                "--kill-child=KILL",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_owner::broker::ipc::tests::delivery::fixed_root_delivery_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_DELIVERY_FIXTURE", root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    let status = loop {
        if let Some(status) = worker.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(25),
            "fixed-root delivery deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(status.success());
    assert_eq!(
        fs::read(root.path().join("kvmapp/identity")).unwrap(),
        b"fixed-root old app"
    );
}
