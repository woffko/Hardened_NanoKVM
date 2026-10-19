use super::*;
use crate::native_owner::controller::Group;
use std::{
    fs::{self, File},
    path::Path,
    process::{Command, Stdio},
};
const BOOT: &str = "12345678-1234-1234-1234-123456789abc";
const FIXTURE_WAIT: Duration = Duration::from_secs(6);
#[path = "app_delivery_tests.rs"]
mod delivery;
#[path = "app_engine_tests.rs"]
mod install_engine;
fn broker(root: &Path) -> Broker {
    Broker {
        group: Group::default(),
        enrollment: super::super::boot::Permit::fixture(&File::open(root).unwrap()),
        update_parent: Some(File::open(root).unwrap()),
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
#[track_caller]
fn until(mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < FIXTURE_WAIT);
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
        match role {
            Role::KvmSystem => "kvm",
            Role::Hwmon => "hwmon",
            Role::Backend => "backend",
        },
    )
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    c
}

pub(super) fn trial_owner_command(root: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "native_owner::broker::ipc::tests::trial_owner_probe",
            "--nocapture",
        ])
        .env_clear()
        .env("NANOKVM_NATIVE_IPC_FIXTURE", root)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
}

fn trial_gate(control: &mut UnixStream, root: &Path, marker: &str) -> bool {
    control
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let start = Instant::now();
    let mut stopped = false;
    while root.join(marker).exists() {
        assert!(
            start.elapsed() < Duration::from_secs(6),
            "trial fixture gate"
        );
        let mut byte = [0];
        match control.read(&mut byte) {
            Ok(1) => {
                assert_eq!(byte, *b"S");
                stopped = true;
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            result => panic!("trial gate lost control: {result:?}"),
        }
    }
    control
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    stopped
}

#[test]
fn trial_owner_probe() {
    use crate::app_trial_wire as wire;
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_IPC_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    let mut control = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
    control
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let mut begin = [0; wire::BYTES];
    control.read_exact(&mut begin).unwrap();
    let transaction = wire::parse(&begin, wire::Event::Begin).unwrap();
    let record = fs::read(root.join("application-slot/current/state")).unwrap();
    assert_eq!(record[8], app_slot::Phase::Published as u8);
    assert_eq!(record[16..32], transaction);
    assert_eq!(
        fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
        4
    );
    // Existence must imply a complete PID for the parent fixture's cleanup.
    let started = root.join("trial-owner-started.next");
    fs::write(&started, std::process::id().to_string()).unwrap();
    fs::rename(started, root.join("trial-owner-started")).unwrap();
    let failed = root.join("trial-ready-fail").exists();
    if !trial_gate(&mut control, root, "trial-ready-hold") {
        control.write_all(if failed { b"F" } else { b"R" }).unwrap();
        let mut first = [0];
        if let Err(error) = control.read_exact(&mut first) {
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            assert!(root.join("trial-allow-controller-loss").exists());
            // Only the childless protocol fixture accepts deliberate cleanup
            // this way. No native closure receipt or commit is emitted.
            fs::write(root.join("trial-controller-lost"), b"lost without commit").unwrap();
            return;
        }
        if first != *b"S" {
            assert!(!failed);
            let mut commit = [0; wire::BYTES];
            commit[0] = first[0];
            control.read_exact(&mut commit[1..]).unwrap();
            assert_eq!(
                wire::parse(&commit, wire::Event::Commit).unwrap(),
                transaction
            );
            assert_eq!(
                fs::read(root.join("application-slot/current/state")).unwrap()[8],
                app_slot::Phase::Committed as u8
            );
            assert_eq!(
                fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
                1
            );
            fs::write(root.join("trial-authorized"), commit).unwrap();
            if !trial_gate(&mut control, root, "trial-ack-hold") {
                control.write_all(b"K").unwrap();
                // A committed backend may legitimately remain idle while the
                // owner fsyncs retirement or waits for the next update. Only
                // handshake gates have a timeout; idle is not owner loss.
                control.set_read_timeout(None).unwrap();
                if let Err(error) = control.read_exact(&mut first) {
                    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                    assert!(root.join("trial-allow-controller-loss").exists());
                    // Known childless probe cleanup only, after retention
                    // assertions. No Stop or closure receipt is fabricated.
                    fs::write(root.join("trial-controller-lost"), b"lost after commit").unwrap();
                    return;
                }
                assert_eq!(first, *b"S");
            }
        }
    }
    assert_eq!(
        fs::read(root.join("native-runtime-owner/state")).unwrap()[44],
        4
    );
    fs::write(root.join("trial-stopping"), b"stopping").unwrap();
    until(|| !root.join("trial-stop-hold").exists());
    if root.join("trial-missing-receipt").exists() {
        return;
    }
    control
        .write_all(if failed { b"D\x03" } else { b"D\0" })
        .unwrap();
    if failed {
        std::process::exit(72);
    }
}

#[test]
fn owner_probe() {
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_IPC_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    let role = std::env::var("NANOKVM_NATIVE_IPC_ROLE").unwrap();
    fs::write(root.join(&role), std::process::id().to_string()).unwrap();
    let mut s = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
    // Mirror a live native role: it stays alive until actual Stop/EOF, never
    // fabricates a closure because unrelated test I/O kept it idle for10s.
    s.set_read_timeout(None).unwrap();
    s.write_all(b"R").unwrap();
    let mut stop = [0];
    s.read_exact(&mut stop).unwrap();
    assert_eq!(stop, *b"S");
    if role == "backend" && root.join("backend-stop-hold").exists() {
        fs::write(root.join("backend-stopping"), b"stopping").unwrap();
        until(|| !root.join("backend-stop-hold").exists());
    }
    s.write_all(b"D\0").unwrap();
}

#[test]
fn native_pause_keeps_backend_and_resume_never_publishes_false_closed() {
    let root = tempfile::tempdir().unwrap();
    let mut e = engine(root.path());
    for operation in [
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::EnsureBackend,
    ] {
        assert_eq!(e.request(1, operation).code, Code::Ok);
    }
    until(|| {
        e.tick();
        e.roles == [2; 2] && e.backend_status == Some(Status::Running)
    });
    let backend = fs::read(root.path().join("backend")).unwrap();
    assert_eq!(e.request(1, Operation::Pause).code, Code::Ok);
    until(|| {
        e.tick();
        e.mode == Mode::Paused
    });
    assert_eq!(e.request(1, Operation::BackendRunning).code, Code::Ok);
    assert_eq!(fs::read(root.path().join("backend")).unwrap(), backend);
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        3
    );
    assert_eq!(e.request(1, Operation::Resume).mode, Mode::Running);
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    assert_eq!(e.backend_status, Some(Status::Running));
    assert_eq!(e.request(1, Operation::Shutdown).code, Code::Ok);
    until(|| {
        e.tick();
        e.mode == Mode::Stopped
    });
    assert!(matches!(e.backend_status, Some(Status::Closed(_))));
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        2
    );
}

#[test]
fn update_or_configuration_owner_denies_backend_restart_and_full_shutdown_before_stop() {
    let root = tempfile::tempdir().unwrap();
    let mut e = engine(root.path());
    e.request(1, Operation::EnsureBackend);
    until(|| {
        e.tick();
        e.backend_status == Some(Status::Running)
    });
    let parent = File::open(root.path()).unwrap();
    let pid = fs::read(root.path().join("backend")).unwrap();
    let update = crate::update::operation_lock::ProcessLock::from_parent(
        &parent,
        nix::unistd::geteuid().as_raw(),
    )
    .unwrap();
    for op in [
        Operation::RestartBackend,
        Operation::RestartBackendSafe,
        Operation::Shutdown,
    ] {
        assert_eq!(e.request(1, op).code, Code::Busy);
        assert_eq!(e.backend_status, Some(Status::Running));
    }
    drop(update);
    let writers =
        crate::update::state_writers::StateWriters::for_test_parent(parent.try_clone().unwrap());
    let configuration = writers.configuration().unwrap();
    for op in [
        Operation::RestartBackend,
        Operation::RestartBackendSafe,
        Operation::Shutdown,
    ] {
        assert_eq!(e.request(1, op).code, Code::Busy);
        assert_eq!(e.backend_status, Some(Status::Running));
    }
    drop(configuration);
    assert_eq!(fs::read(root.path().join("backend")).unwrap(), pid);
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    e.request(1, Operation::Shutdown);
    until(|| {
        e.tick();
        e.mode == Mode::Stopped
    });
}

#[test]
fn restart_publishes_stopping_and_retains_admission_through_exact_backend_join() {
    let root = tempfile::tempdir().unwrap();
    let mut e = engine(root.path());
    e.request(1, Operation::EnsureBackend);
    until(|| {
        e.tick();
        e.backend_status == Some(Status::Running)
    });
    let prior = fs::read(root.path().join("backend")).unwrap();
    fs::write(root.path().join("backend-stop-hold"), b"hold").unwrap();
    assert_eq!(e.request(1, Operation::RestartBackend).code, Code::Ok);
    until(|| root.path().join("backend-stopping").exists());
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        4
    );
    let parent = File::open(root.path()).unwrap();
    assert!(matches!(
        crate::update::operation_lock::ProcessLock::from_parent(
            &parent,
            nix::unistd::geteuid().as_raw()
        ),
        Err(crate::update::operation_lock::LockError::Busy)
    ));
    assert_eq!(e.request(2, Operation::Pause).code, Code::Busy);
    assert_eq!(e.request(2, Operation::RestartBackend).code, Code::Busy);
    assert_eq!(
        e.request(2, Operation::BackendRunning).code,
        Code::Unavailable
    );
    assert_eq!(fs::read(root.path().join("backend")).unwrap(), prior);
    fs::remove_file(root.path().join("backend-stop-hold")).unwrap();
    until(|| {
        e.tick();
        e.backend_restart.is_none() && e.backend_status == Some(Status::Running)
    });
    assert_ne!(fs::read(root.path().join("backend")).unwrap(), prior);
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    drop(
        crate::update::operation_lock::ProcessLock::from_parent(
            &parent,
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap(),
    );
    e.request(1, Operation::Shutdown);
    until(|| {
        e.tick();
        e.mode == Mode::Stopped
    });
}

#[test]
fn safe_restart_publishes_fixed_policy_only_after_update_admission() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("kvmapp/kvm")).unwrap();
    fs::create_dir_all(root.path().join("etc/kvm")).unwrap();
    fs::write(root.path().join("kvmapp/kvm/type"), b"h264\n").unwrap();
    let mut e = engine(root.path());
    e.request(1, Operation::EnsureBackend);
    until(|| {
        e.tick();
        e.backend_status == Some(Status::Running)
    });
    let parent = File::open(root.path()).unwrap();
    let update = crate::update::operation_lock::ProcessLock::from_parent(
        &parent,
        nix::unistd::geteuid().as_raw(),
    )
    .unwrap();
    assert_eq!(e.request(1, Operation::RestartBackendSafe).code, Code::Busy);
    assert_eq!(
        fs::read(root.path().join("kvmapp/kvm/type")).unwrap(),
        b"h264\n"
    );
    assert!(!root.path().join("etc/kvm/h264_safe_mode").exists());
    drop(update);
    assert_eq!(e.request(1, Operation::RestartBackendSafe).code, Code::Ok);
    until(|| {
        e.tick();
        e.backend_restart.is_none() && e.backend_status == Some(Status::Running)
    });
    assert_eq!(
        fs::read(root.path().join("kvmapp/kvm/type")).unwrap(),
        b"mjpeg\n"
    );
    assert!(root.path().join("etc/kvm/h264_safe_mode").is_file());
    e.request(1, Operation::Shutdown);
    until(|| {
        e.tick();
        e.mode == Mode::Stopped
    });
}

#[test]
fn stopping_publication_failure_does_not_send_backend_stop_or_claim_completion() {
    for operation in [Operation::RestartBackend, Operation::Shutdown] {
        let root = tempfile::tempdir().unwrap();
        let mut e = engine(root.path());
        e.request(1, Operation::EnsureBackend);
        until(|| {
            e.tick();
            e.backend_status == Some(Status::Running)
        });
        let next = root.path().join("native-runtime-owner/.state.next");
        fs::write(&next, b"foreign evidence").unwrap();
        let reply = e.request(1, operation);
        assert_eq!(reply.code, Code::Uncertain);
        assert_eq!(reply.mode, Mode::Uncertain);
        assert!(e.backend_restart.is_none());
        e.tick();
        assert_eq!(e.backend_status, Some(Status::Running));
        assert_eq!(fs::read(next).unwrap(), b"foreign evidence");
        assert_eq!(
            fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
            1
        );
        // No Stop was sent, so releasing these short permits is safe. Durable
        // ambiguous evidence still blocks coordinator admission (root fixture).
        drop(
            crate::update::operation_lock::ProcessLock::from_parent(
                &File::open(root.path()).unwrap(),
                nix::unistd::geteuid().as_raw(),
            )
            .unwrap(),
        );
    }
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
    serve_prepared(server, f);
}
// A test may queue a specific packet before starting the server's idle clock.
// The same cancellation/join owner is retained on normal exit and assertion unwind.
fn serve_prepared(mut server: Server, f: impl FnOnce()) {
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

// Same bound as Channel-based fixtures, without turning a stream timeout into
// a frame boundary. Preserve every partial read; only transient pending errors
// are retried. EOF, other I/O errors and exhaustion remain failures.
fn raw_reply(stream: &mut impl Read) -> io::Result<[u8; FRAME]> {
    let start = Instant::now();
    let mut reply = [0; FRAME];
    let mut used = 0;
    while used < FRAME {
        if start.elapsed() >= FIXTURE_WAIT {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match stream.read(&mut reply[used..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => used += count,
            Err(error) if pending(&error) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(error),
        }
    }
    Ok(reply)
}

#[test]
fn raw_reply_preserves_partial_frames_and_never_consumes_the_next_frame() {
    struct Reader {
        source: io::Cursor<Vec<u8>>,
        call: usize,
    }
    impl Read for Reader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.call += 1;
            match self.call {
                1 => Err(io::ErrorKind::WouldBlock.into()),
                3 => Err(io::ErrorKind::Interrupted.into()),
                _ => {
                    let count = out.len().min(3);
                    self.source.read(&mut out[..count])
                }
            }
        }
    }
    let first = request(Operation::Pause, 1);
    let next = request(Operation::Resume, 2);
    let mut reader = Reader {
        source: io::Cursor::new([first, next].concat()),
        call: 0,
    };
    assert_eq!(raw_reply(&mut reader).unwrap(), first);
    assert_eq!(reader.source.position(), FRAME as u64);
    assert_eq!(raw_reply(&mut reader).unwrap(), next);
    assert_eq!(reader.source.position(), 2 * FRAME as u64);
    assert_eq!(
        raw_reply(&mut reader).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::TimedOut] {
        struct FailedReader(io::ErrorKind, usize);
        impl Read for FailedReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.1 += 1;
                Err(self.0.into())
            }
        }
        let mut failed = FailedReader(kind, 0);
        assert_eq!(raw_reply(&mut failed).unwrap_err().kind(), kind);
        assert_eq!(failed.1, 1, "non-pending errors must not be retried");
    }
}

#[test]
fn cached_replay_does_not_reexecute_request_and_conflicting_replay_stays_invalid() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = engine(root.path());
    let (server, mut peer) = UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    let mut client = Client::new(server, 12, nix::unistd::geteuid().as_raw()).unwrap();
    let pause = request(Operation::Pause, 1);
    peer.write_all(&pause).unwrap();
    assert!(!client.tick(&mut engine).unwrap());
    assert!(engine.fixture_request_completed.is_some());
    assert!(!client.tick(&mut engine).unwrap());
    let first = raw_reply(&mut peer).unwrap();
    assert_eq!(Reply::parse(&first, 1).unwrap().code, Code::Ok);
    // This existing cfg(test) marker is set on every Engine::request return.
    // Clearing it changes neither the journal, ownership nor the reply cache.
    engine.fixture_request_completed = None;
    peer.write_all(&pause).unwrap();
    assert!(!client.tick(&mut engine).unwrap());
    assert!(engine.fixture_request_completed.is_none());
    assert!(!client.tick(&mut engine).unwrap());
    assert_eq!(raw_reply(&mut peer).unwrap(), first);
    assert!(engine.fixture_request_completed.is_none());
    peer.write_all(&request(Operation::Resume, 1)).unwrap();
    assert_eq!(
        client.tick(&mut engine).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(engine.fixture_request_completed.is_none());
    engine.disconnected(client.key);
    assert_eq!(engine.mode, Mode::Abandoned);
    assert_eq!(engine.request(13, Operation::EnsureKvm).code, Code::Busy);
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
        let pause = request(Operation::Pause, 1);
        client.stream.write_all(&pause).unwrap();
        let first = raw_reply(&mut client.stream).unwrap();
        assert_eq!(Reply::parse(&first, 1).unwrap().code, Code::Ok);
        client.stream.write_all(&pause).unwrap();
        let second = raw_reply(&mut client.stream).unwrap();
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
