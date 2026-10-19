use super::*;
use crate::native_owner::controller::Group;
use std::{
    fs::{self, File},
    path::Path,
    process::{Command, Stdio},
};
const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
fn broker(root: &Path) -> Broker {
    Broker {
        group: Group::default(),
        enrollment: super::super::boot::Permit::fixture(&File::open(root).unwrap()),
        journal: journal::Store::fixture(
            &File::open(root).unwrap(),
            nix::unistd::geteuid().as_raw(),
            BOOT,
        )
        .unwrap(),
    }
}
fn engine(root: &Path) -> Engine {
    let mut e = Engine::new(broker(root));
    e.fixture = Some(root.to_path_buf());
    e
}
fn until(mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < Duration::from_secs(6));
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub(super) fn owner_command(root: &Path, role: Role) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args([
        "--exact",
        "native_owner::broker::ipc::tests::owner_probe",
        "--nocapture",
    ])
    .env_clear()
    .env("NANOKVM_NATIVE_IPC_FIXTURE", root)
    .env(
        "NANOKVM_NATIVE_IPC_ROLE",
        if role == Role::KvmSystem {
            "kvm"
        } else {
            "hwmon"
        },
    )
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    c
}
#[test]
fn owner_probe() {
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_IPC_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    let role = std::env::var("NANOKVM_NATIVE_IPC_ROLE").unwrap();
    fs::write(root.join(role), std::process::id().to_string()).unwrap();
    let mut s = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"R").unwrap();
    let mut stop = [0];
    let _ = s.read(&mut stop);
    s.write_all(b"D\0").unwrap();
}
#[test]
fn maintenance_stays_durable_after_quiescence_and_only_owner_can_resume() {
    let root = tempfile::tempdir().unwrap();
    let mut e = engine(root.path());
    e.request(1, Operation::EnsureKvm);
    until(|| {
        e.tick();
        e.roles[0] == 2
    });
    assert_eq!(e.request(1, Operation::Pause).code, Code::Ok);
    until(|| {
        e.tick();
        e.mode == Mode::Paused
    });
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        3
    );
    for op in [
        Operation::Pause,
        Operation::Resume,
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::Shutdown,
    ] {
        assert_eq!(e.request(2, op).code, Code::Busy);
        assert!(matches!(e.owner, Some(Owner::Paused(_))));
    }
    assert_eq!(e.request(1, Operation::Resume).mode, Mode::Running);
    e.request(1, Operation::Shutdown);
    until(|| {
        e.tick();
        e.mode == Mode::Stopped
    });
}
#[test]
fn abandoned_maintenance_does_not_transfer_to_a_new_client_or_clean_journal() {
    let root = tempfile::tempdir().unwrap();
    let mut e = engine(root.path());
    e.request(10, Operation::Pause);
    until(|| {
        e.tick();
        e.mode == Mode::Paused
    });
    e.disconnected(10);
    assert_eq!(e.mode, Mode::Abandoned);
    for key in [10, 11] {
        for op in [
            Operation::Pause,
            Operation::Resume,
            Operation::Shutdown,
            Operation::EnsureHwmon,
        ] {
            assert_eq!(e.request(key, op).code, Code::Busy);
        }
    }
    drop(e);
    assert!(matches!(
        journal::Store::fixture(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw(),
            BOOT
        ),
        Err(super::super::JournalError::Unresolved)
    ));
}
#[test]
fn channel_retains_fragmented_pending_request_and_rejects_replacement() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut channel = Channel::verified(a, nix::unistd::geteuid().as_raw()).unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    channel.begin(Operation::Observe).unwrap();
    assert!(channel.poll().unwrap().is_none());
    assert_eq!(
        channel.begin(Operation::Pause).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let mut bytes = [0; FRAME];
    b.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, request(Operation::Observe, 1));
    let reply = Reply {
        code: Code::Ok,
        mode: Mode::Running,
        roles: [0; 2],
    }
    .bytes(1);
    b.write_all(&reply[..3]).unwrap();
    assert!(channel.poll().unwrap().is_none());
    b.write_all(&reply[3..]).unwrap();
    assert_eq!(channel.poll().unwrap().unwrap().mode, Mode::Running);
    channel.begin(Operation::Pause).unwrap();
}

#[test]
fn fragmented_request_has_no_effect_until_complete_and_lost_pause_reply_abandons() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = engine(root.path());
    let (server, mut peer) = UnixStream::pair().unwrap();
    let mut client = Client::new(server, 12, nix::unistd::geteuid().as_raw()).unwrap();
    let bytes = request(Operation::Pause, 1);
    for byte in &bytes[..FRAME - 1] {
        peer.write_all(&[*byte]).unwrap();
        assert!(!client.tick(&mut engine).unwrap());
        assert_eq!(engine.mode, Mode::Running);
        assert!(!root.path().join("native-runtime-owner/state").exists());
    }
    peer.write_all(&bytes[FRAME - 1..]).unwrap();
    assert!(!client.tick(&mut engine).unwrap());
    assert_eq!(engine.mode, Mode::Paused);
    assert!(client.writing);
    assert_eq!(client.sent, 0);
    // The complete Pause was applied but none of its reply reached the caller.
    // EOF cannot undo durable maintenance or transfer the lease to a new key.
    drop(peer);
    // A close need not surface on the next write tick; observe the same eventual
    // I/O error/EOF path as the server loop rather than assuming its timing.
    until(|| client.tick(&mut engine).is_err());
    engine.disconnected(client.key);
    assert_eq!(engine.mode, Mode::Abandoned);
    assert_eq!(engine.request(13, Operation::Resume).code, Code::Busy);
    drop(client);
    drop(engine);
    assert!(matches!(
        journal::Store::fixture(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw(),
            BOOT
        ),
        Err(super::super::JournalError::Unresolved)
    ));
}

#[test]
fn pending_reply_idle_budget_starts_after_request_work_not_before_it() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = engine(root.path());
    let (server, mut peer) = UnixStream::pair().unwrap();
    let mut client = Client::new(server, 12, nix::unistd::geteuid().as_raw()).unwrap();
    peer.write_all(&request(Operation::EnsureKvm, 1)).unwrap();
    assert!(!client.tick(&mut engine).unwrap());
    assert!(client.writing);
    assert_eq!(client.sent, 0);
    assert!(
        client.last_activity >= engine.fixture_request_completed.unwrap(),
        "request work consumed the pending reply's transport idle budget"
    );
    assert!(!client.tick(&mut engine).unwrap());
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut reply = [0; FRAME];
    peer.read_exact(&mut reply).unwrap();
    assert_eq!(&reply[..4], b"NKR1");
    engine.request(12, Operation::Shutdown);
    until(|| {
        engine.tick();
        engine.mode == Mode::Stopped
    });
}

#[test]
fn duplicate_unsolicited_reply_cannot_satisfy_the_next_operation() {
    let (a, mut b) = UnixStream::pair().unwrap();
    let mut channel = Channel::verified(a, nix::unistd::geteuid().as_raw()).unwrap();
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    channel.begin(Operation::Observe).unwrap();
    assert!(channel.poll().unwrap().is_none());
    let mut bytes = [0; FRAME];
    b.read_exact(&mut bytes).unwrap();
    let reply = Reply {
        code: Code::Ok,
        mode: Mode::Running,
        roles: [0; 2],
    }
    .bytes(1);
    b.write_all(&reply).unwrap();
    b.write_all(&reply).unwrap();
    assert_eq!(channel.poll().unwrap().unwrap().mode, Mode::Running);
    channel.begin(Operation::Pause).unwrap();
    assert_eq!(
        channel.poll().unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    b.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, request(Operation::Pause, 2));
    assert_eq!(
        channel.begin(Operation::Pause).unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

struct Cancel(std::sync::mpsc::Sender<()>);
impl Drop for Cancel {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}
fn serve(root: &Path, uid: u32, f: impl FnOnce()) {
    let mut server = Server::new(broker(root), uid).unwrap();
    server.engine.fixture = Some(root.to_path_buf());
    server.idle = Duration::from_millis(200);
    let (send, recv) = std::sync::mpsc::channel();
    server.cancel = Some(recv);
    std::thread::scope(|scope| {
        let thread = scope.spawn(move || server.run());
        let guard = Cancel(send);
        f();
        drop(guard);
        let result = thread.join().unwrap();
        assert!(result.is_ok() || result.unwrap_err().kind() == io::ErrorKind::Interrupted);
    });
}
fn connect(root: &Path) -> Channel {
    let directory = File::open(root.join("native-runtime-owner")).unwrap();
    let stream = journal::socket::connect(&directory, nix::unistd::geteuid().as_raw()).unwrap();
    Channel::verified(stream, nix::unistd::geteuid().as_raw()).unwrap()
}
fn exchange(channel: &mut Channel, op: Operation) -> Reply {
    channel.begin(op).unwrap();
    let mut reply = None;
    until(|| {
        reply = channel
            .poll()
            .unwrap_or_else(|error| panic!("{op:?} failed: {error}"));
        reply.is_some()
    });
    reply.unwrap()
}
fn observed(channel: &mut Channel, mode: Mode) {
    until(|| exchange(channel, Operation::Observe).mode == mode);
}

#[test]
fn real_protected_endpoint_roundtrip_pause_foreign_commands_and_shutdown() {
    let root = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    serve(root.path(), uid, || {
        let mut owner = connect(root.path());
        assert_eq!(exchange(&mut owner, Operation::EnsureKvm).code, Code::Ok);
        assert_eq!(exchange(&mut owner, Operation::EnsureHwmon).code, Code::Ok);
        until(|| exchange(&mut owner, Operation::Observe).roles == [2; 2]);
        exchange(&mut owner, Operation::Pause);
        observed(&mut owner, Mode::Paused);
        let mut other = connect(root.path());
        for op in [
            Operation::Pause,
            Operation::Resume,
            Operation::EnsureKvm,
            Operation::Shutdown,
        ] {
            assert_eq!(exchange(&mut other, op).code, Code::Busy);
        }
        assert_eq!(exchange(&mut owner, Operation::Resume).mode, Mode::Running);
        let reply = exchange(&mut owner, Operation::Shutdown);
        if reply.mode != Mode::Stopped {
            observed(&mut owner, Mode::Stopped);
        }
    });
    assert!(
        !root
            .path()
            .join("native-runtime-owner/control.sock")
            .exists()
    );
    drop(broker(root.path()));
}

#[test]
fn socket_eof_abandons_maintenance_durably_and_new_client_cannot_steal_it() {
    let root = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    serve(root.path(), uid, || {
        let mut owner = connect(root.path());
        let mut other = connect(root.path());
        exchange(&mut owner, Operation::Pause);
        observed(&mut owner, Mode::Paused);
        // Longer than the test idle budget: a live maintenance owner is retained.
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(exchange(&mut owner, Operation::Observe).mode, Mode::Paused);
        // The non-owner may idle out, so create a fresh independent connection.
        drop(other);
        other = connect(root.path());
        drop(owner);
        observed(&mut other, Mode::Abandoned);
        assert_eq!(exchange(&mut other, Operation::Resume).code, Code::Busy);
        assert_eq!(exchange(&mut other, Operation::Shutdown).code, Code::Busy);
    });
    assert!(matches!(
        journal::Store::fixture(&File::open(root.path()).unwrap(), uid, BOOT),
        Err(super::super::JournalError::Unresolved)
    ));
}

#[test]
fn actual_peer_uid_is_checked_before_requests_or_journal_changes() {
    let root = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    serve(root.path(), uid.wrapping_add(1), || {
        let mut client = connect(root.path());
        client.begin(Operation::EnsureKvm).unwrap();
        until(|| client.poll().is_err());
        assert!(!root.path().join("native-runtime-owner/state").exists());
        assert!(!root.path().join("kvm").exists());
    });
}

#[test]
fn same_request_replay_returns_cached_reply_and_conflicting_replay_abandons() {
    let root = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    serve(root.path(), uid, || {
        let mut client = connect(root.path());
        client.stream.set_nonblocking(false).unwrap();
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let pause = request(Operation::Pause, 1);
        client.stream.write_all(&pause).unwrap();
        let mut first = [0; FRAME];
        client.stream.read_exact(&mut first).unwrap();
        client.stream.write_all(&pause).unwrap();
        let mut second = [0; FRAME];
        client.stream.read_exact(&mut second).unwrap();
        assert_eq!(first, second);
        client
            .stream
            .write_all(&request(Operation::Resume, 1))
            .unwrap();
        drop(client);
        let mut other = connect(root.path());
        observed(&mut other, Mode::Abandoned);
        assert_eq!(exchange(&mut other, Operation::EnsureKvm).code, Code::Busy);
    });
}

#[test]
fn forged_frames_and_serial_gaps_do_not_launch_work() {
    let root = tempfile::tempdir().unwrap();
    let uid = nix::unistd::geteuid().as_raw();
    serve(root.path(), uid, || {
        for which in 0..4 {
            let mut client = connect(root.path());
            client.stream.set_nonblocking(false).unwrap();
            client
                .stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut bytes = request(Operation::EnsureKvm, 1);
            match which {
                0 => bytes[0] = 0,
                1 => bytes[5] = 1,
                2 => bytes[4] = 99,
                _ => bytes[15] = 2,
            };
            client.stream.write_all(&bytes).unwrap();
            let mut byte = [0];
            assert_eq!(client.stream.read(&mut byte).unwrap(), 0);
        }
        assert!(!root.path().join("native-runtime-owner/state").exists());
    });
}

#[test]
fn endpoint_never_clobbers_foreign_members_and_drop_checks_exact_inode() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    for link in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let broker = broker(root.path());
        let path = root.path().join("native-runtime-owner/control.sock");
        if link {
            symlink("/dev/null", &path).unwrap();
        } else {
            fs::write(&path, b"foreign fixture").unwrap();
        }
        assert!(broker.journal.endpoint().is_err());
        if link {
            assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
        } else {
            assert_eq!(fs::read(&path).unwrap(), b"foreign fixture");
        }
    }
    let root = tempfile::tempdir().unwrap();
    let broker = broker(root.path());
    let path = root.path().join("native-runtime-owner/control.sock");
    let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    drop(stale);
    let endpoint = broker.journal.endpoint().unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"replacement fixture").unwrap();
    drop(endpoint);
    assert_eq!(fs::read(&path).unwrap(), b"replacement fixture");
}

#[test]
fn wrong_response_serial_or_mode_poison_channel_without_reissuing() {
    for serial in [false, true] {
        let (a, mut b) = UnixStream::pair().unwrap();
        let mut channel = Channel::verified(a, nix::unistd::geteuid().as_raw()).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        channel.begin(Operation::Observe).unwrap();
        channel.poll().unwrap();
        let mut input = [0; FRAME];
        b.read_exact(&mut input).unwrap();
        let mut reply = Reply {
            code: Code::Ok,
            mode: Mode::Running,
            roles: [0; 2],
        }
        .bytes(if serial { 2 } else { 1 });
        if !serial {
            reply[5] = 255;
        }
        b.write_all(&reply).unwrap();
        assert_eq!(
            channel.poll().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            channel.begin(Operation::Pause).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn real_scope_cannot_inherit_journal_listener_or_client_control_descriptors() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    let endpoint = broker.journal.endpoint().unwrap();
    let _client = connect(root.path());
    let _accepted = rustix::net::accept_with(
        &endpoint.listener,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
    )
    .unwrap();
    let test = std::env::current_exe().unwrap();
    let fixture = test
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("nanokvm-native-owner-fixture");
    let mut command = Command::new(fixture);
    command
        .args(["scope", "tree"])
        .arg(root.path())
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    broker.start_owned(Role::KvmSystem, command).unwrap();
    until(|| broker.poll()[0] == Some(Status::Running));
    let mut pid = None;
    until(|| {
        pid = fs::read_to_string(root.path().join("leaf.pid"))
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw);
        pid.is_some()
    });
    struct Leaf(std::os::fd::OwnedFd);
    impl Drop for Leaf {
        fn drop(&mut self) {
            let _ = rustix::process::pidfd_send_signal(&self.0, rustix::process::Signal::KILL);
        }
    }
    let leaf = Leaf(
        rustix::process::pidfd_open(pid.unwrap(), rustix::process::PidfdFlags::empty()).unwrap(),
    );
    let mut drain = broker.begin_maintenance();
    until(|| matches!(drain.poll(), Ok(DrainStatus::Drained)));
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        3
    );
    let mut fds = [rustix::event::PollFd::new(
        &leaf.0,
        rustix::event::PollFlags::IN,
    )];
    assert_eq!(
        rustix::event::poll(
            &mut fds,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0
            })
        )
        .unwrap(),
        1
    );
    let Resume::Running(broker) = drain.resume() else {
        panic!("joined maintenance did not explicitly resume");
    };
    drop(endpoint);
    drop(broker);
}
