use super::*;
use crate::update::{operation_lock::ProcessLock, state_writers::StateWriters};

const OPS: [Operation; 4] = [
    Operation::EnsurePicoclaw,
    Operation::PicoclawRunning,
    Operation::StopPicoclaw,
    Operation::PicoclawStopped,
];

fn frame(op: Operation, home: &Home, serial: u64) -> [u8; FRAME] {
    let mut frame = request(op, serial);
    frame[16..].copy_from_slice(&home.fingerprint());
    frame
}

fn call(engine: &mut Engine, op: Operation) -> Reply {
    engine.request_frame(7, op, &frame(op, &Home::default(), 1))
}

fn configured(root: &Path) -> Engine {
    fs::write(root.join("pico-generation"), [1; 32]).unwrap();
    engine(root)
}

fn ready(engine: &mut Engine) {
    until(|| {
        engine.tick();
        call(engine, Operation::PicoclawRunning).code == Code::Ok
    });
}

fn close(mut engine: Engine) {
    assert_eq!(engine.request(7, Operation::Shutdown).code, Code::Ok);
    until(|| {
        engine.tick();
        engine.mode == Mode::Stopped
    });
}

#[test]
fn each_fixed_service_operation_requires_a_full_home_bound_frame() {
    for (op, byte) in OPS.into_iter().zip([14, 15, 16, 17]) {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut channel = Channel::verified(stream, nix::unistd::geteuid().as_raw()).unwrap();
        assert_eq!(
            channel.begin(op).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(channel.flight.is_none());
        channel.picoclaw_service(op, &Home::default()).unwrap();
        let bytes = channel.flight.as_ref().unwrap().bytes;
        let mut prefix = *b"NKC2\0\0\0\0\0\0\0\0\0\0\0\x01";
        prefix[4] = byte;
        assert_eq!(&bytes[..16], &prefix);
        assert_eq!(&bytes[16..], &Home::default().fingerprint());
        assert_eq!(parse_request(&bytes), Some((op, 1)));
        assert_eq!(
            channel
                .picoclaw_service(op, &Home::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn the_retired_onboarding_frame_bytes_decode_as_unknown() {
    // S96 onboarding is an Onboard job on the job transport; the older frame
    // operations 18 and 19 are never decoded or served.
    let mut bytes = frame(Operation::EnsurePicoclaw, &Home::default(), 1);
    for byte in [18, 19] {
        bytes[4] = byte;
        assert_eq!(parse_request(&bytes), None);
        assert_eq!(Operation::decode(byte), None);
    }
}

// The one-shot fixture an Onboard job launches in the mutation tests.
#[test]
fn onboard_probe() {
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_ONBOARD_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    fs::write(root.join("onboard-pid"), std::process::id().to_string()).unwrap();
    let mut control = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
    control.set_nonblocking(true).unwrap();
    control.write_all(b"R").unwrap();
    let mut stopped = false;
    until(|| {
        let mut byte = [0];
        match control.read(&mut byte) {
            Ok(1) => {
                assert_eq!(byte, *b"S");
                stopped = true;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!("onboard control lost: {other:?}"),
        }
        if stopped {
            fs::write(root.join("onboard-stopping"), b"stopping").unwrap();
        }
        (stopped && !root.join("onboard-stop-hold").exists())
            || root.join("onboard-release").exists()
    });
    if root.join("onboard-missing-receipt").exists() {
        return;
    }
    if stopped {
        control.write_all(b"D\0").unwrap();
    } else if root.join("onboard-fail").exists() {
        control.write_all(b"D\x02").unwrap();
        std::process::exit(71);
    } else {
        control.write_all(b"D\x01").unwrap();
    }
}

#[test]
fn a_wrong_home_refuses_even_mutating_commands_before_any_lifecycle_tick() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    engine.wanted = [true; 2];
    engine.backend_wanted = true;
    for op in OPS {
        let mut bytes = frame(op, &Home::default(), 1);
        bytes[FRAME - 1] ^= 1;
        assert_eq!(engine.request_frame(7, op, &bytes).code, Code::Invalid);
    }
    for name in [
        "picoclaw",
        "backend",
        "kvm",
        "hwmon",
        "native-runtime-owner/state",
    ] {
        assert!(!root.path().join(name).exists());
    }
    assert_eq!(
        call(&mut engine, Operation::PicoclawRunning).code,
        Code::Unavailable
    );
    assert_eq!(call(&mut engine, Operation::PicoclawStopped).code, Code::Ok);
    assert!(
        !root.path().join("backend").exists(),
        "queries do not tick wanted work"
    );
    engine.wanted = [false; 2];
    engine.backend_wanted = false;
    close(engine);
}

#[test]
fn fixed_ensure_binds_generation_without_adoption_or_implicit_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    ready(&mut engine);
    let first = fs::read(root.path().join("picoclaw")).unwrap();
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), first);
    fs::write(root.path().join("pico-generation"), [2; 32]).unwrap();
    assert_eq!(
        call(&mut engine, Operation::EnsurePicoclaw).code,
        Code::Invalid
    );
    assert_eq!(engine.picoclaw_status, Some(Status::Running));
    assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), first);
    assert_eq!(call(&mut engine, Operation::StopPicoclaw).code, Code::Ok);
    until(|| {
        engine.tick();
        call(&mut engine, Operation::PicoclawStopped).code == Code::Ok
    });
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    ready(&mut engine);
    assert_ne!(fs::read(root.path().join("picoclaw")).unwrap(), first);
    close(engine);
}

#[test]
fn launch_generation_follows_same_broker_into_a_new_engine_without_adoption_or_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    ready(&mut engine);
    let original = fs::read(root.path().join("picoclaw")).unwrap();
    let Some(Owner::Running(broker)) = engine.owner.take() else {
        panic!("running fixture broker absent");
    };
    drop(engine);
    let mut engine = Engine::new(broker);
    engine.fixture = Some(root.path().to_path_buf());
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    assert_eq!(call(&mut engine, Operation::PicoclawRunning).code, Code::Ok);
    assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), original);
    fs::write(root.path().join("pico-generation"), [2; 32]).unwrap();
    assert_eq!(
        call(&mut engine, Operation::EnsurePicoclaw).code,
        Code::Invalid
    );
    assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), original);
    close(engine);
}

#[test]
fn owned_stop_joins_with_config_held_and_retains_update_after_caller_loss() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    for op in [
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::EnsureBackend,
    ] {
        assert_eq!(engine.request(7, op).code, Code::Ok);
    }
    until(|| {
        engine.tick();
        engine.roles == [2; 2] && engine.backend_status == Some(Status::Running)
    });
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    ready(&mut engine);
    let backend = fs::read(root.path().join("backend")).unwrap();
    let kvm = fs::read(root.path().join("kvm")).unwrap();
    let writers = StateWriters::for_test_parent(File::open(root.path()).unwrap());
    let config = writers.configuration().unwrap();
    fs::write(root.path().join("picoclaw-stop-hold"), b"hold").unwrap();
    assert_eq!(call(&mut engine, Operation::StopPicoclaw).code, Code::Ok);
    until(|| root.path().join("picoclaw-stopping").exists());
    engine.tick();
    assert_eq!(
        call(&mut engine, Operation::PicoclawStopped).code,
        Code::Unavailable
    );
    assert!(engine.picoclaw_stop.is_some());
    assert!(
        ProcessLock::from_parent(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw()
        )
        .is_err()
    );
    assert_eq!(
        call(&mut engine, Operation::EnsurePicoclaw).code,
        Code::Busy
    );
    for op in [
        Operation::Pause,
        Operation::RestartBackend,
        Operation::Shutdown,
    ] {
        assert_eq!(engine.request(7, op).code, Code::Busy);
    }
    engine.disconnected(7);
    assert!(!engine.abandoned);
    assert!(engine.picoclaw_stop.is_some());
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    fs::remove_file(root.path().join("picoclaw-stop-hold")).unwrap();
    until(|| {
        engine.tick();
        engine.picoclaw_stop.is_none()
    });
    assert_eq!(call(&mut engine, Operation::PicoclawStopped).code, Code::Ok);
    assert_eq!(engine.backend_status, Some(Status::Running));
    assert_eq!(engine.roles, [2; 2]);
    assert_eq!(fs::read(root.path().join("backend")).unwrap(), backend);
    assert_eq!(fs::read(root.path().join("kvm")).unwrap(), kvm);
    drop(
        ProcessLock::from_parent(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap(),
    );
    drop(config);
    close(engine);
}

#[test]
fn start_contention_and_missing_generation_never_publish_native_intent() {
    for conflict in ["config", "update", "generation"] {
        let root = tempfile::tempdir().unwrap();
        let mut engine = configured(root.path());
        let writers = StateWriters::for_test_parent(File::open(root.path()).unwrap());
        let config = (conflict == "config").then(|| writers.configuration().unwrap());
        let update = (conflict == "update").then(|| {
            ProcessLock::from_parent(
                &File::open(root.path()).unwrap(),
                nix::unistd::geteuid().as_raw(),
            )
            .unwrap()
        });
        if conflict == "generation" {
            fs::remove_file(root.path().join("pico-generation")).unwrap();
        }
        assert_eq!(
            call(&mut engine, Operation::EnsurePicoclaw).code,
            if conflict == "generation" {
                Code::Unavailable
            } else {
                Code::Busy
            }
        );
        assert!(!root.path().join("picoclaw").exists());
        assert!(!root.path().join("native-runtime-owner/state").exists());
        drop(update);
        drop(config);
        close(engine);
    }
}

fn exchange_service(channel: &mut Channel, op: Operation) -> Reply {
    channel.picoclaw_service(op, &Home::default()).unwrap();
    let mut reply = None;
    until(|| {
        reply = channel.poll().unwrap();
        reply.is_some()
    });
    reply.unwrap()
}

#[test]
fn real_endpoint_stop_survives_its_client_and_does_not_stop_the_backend() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("pico-generation"), [3; 32]).unwrap();
    serve(root.path(), nix::unistd::geteuid().as_raw(), || {
        let mut channel = connect(root.path());
        assert_eq!(
            exchange(&mut channel, Operation::EnsureBackend).code,
            Code::Ok
        );
        until(|| exchange(&mut channel, Operation::BackendRunning).code == Code::Ok);
        assert_eq!(
            exchange_service(&mut channel, Operation::EnsurePicoclaw).code,
            Code::Ok
        );
        until(|| exchange_service(&mut channel, Operation::PicoclawRunning).code == Code::Ok);
        let backend = fs::read(root.path().join("backend")).unwrap();
        fs::write(root.path().join("picoclaw-stop-hold"), b"hold").unwrap();
        assert_eq!(
            exchange_service(&mut channel, Operation::StopPicoclaw).code,
            Code::Ok
        );
        until(|| root.path().join("picoclaw-stopping").exists());
        drop(channel);
        let mut observer = connect(root.path());
        assert_eq!(
            exchange_service(&mut observer, Operation::PicoclawStopped).code,
            Code::Unavailable
        );
        fs::remove_file(root.path().join("picoclaw-stop-hold")).unwrap();
        until(|| exchange_service(&mut observer, Operation::PicoclawStopped).code == Code::Ok);
        assert_eq!(
            exchange(&mut observer, Operation::BackendRunning).code,
            Code::Ok
        );
        assert_eq!(fs::read(root.path().join("backend")).unwrap(), backend);
    });
}

#[test]
fn missing_stop_receipt_pins_uncertainty_even_after_the_childless_owner_exits() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    ready(&mut engine);
    let pid: u32 = fs::read_to_string(root.path().join("picoclaw"))
        .unwrap()
        .parse()
        .unwrap();
    let process = std::path::PathBuf::from(format!("/proc/{pid}"));
    fs::write(
        root.path().join("picoclaw-missing-receipt"),
        b"fixture only",
    )
    .unwrap();
    assert_eq!(call(&mut engine, Operation::StopPicoclaw).code, Code::Ok);
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    // Test-only observation of this exact known fixture child: keep polling
    // the retained controller until try_wait has also reaped it. This is not
    // a production PID-based closure/adoption mechanism.
    until(|| {
        engine.tick();
        !process.exists()
    });
    assert_eq!(
        call(&mut engine, Operation::PicoclawStopped).code,
        Code::Uncertain
    );
    assert_eq!(
        call(&mut engine, Operation::EnsurePicoclaw).code,
        Code::Uncertain
    );
    assert!(engine.picoclaw_stop.is_some());
    assert!(
        ProcessLock::from_parent(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw()
        )
        .is_err()
    );
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    // This fixture owner is childless and reaped. Dropping it is not a closure
    // claim, a production recovery path, or permission to relaunch a native tree.
    drop(engine);
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
}

#[test]
fn cached_service_replay_never_restarts_or_stops_a_later_owned_generation() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("pico-generation"), [1; 32]).unwrap();
    serve(root.path(), nix::unistd::geteuid().as_raw(), || {
        let mut raw = connect(root.path());
        raw.stream.set_nonblocking(false).unwrap();
        raw.stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let start = frame(Operation::EnsurePicoclaw, &Home::default(), 1);
        raw.stream.write_all(&start).unwrap();
        let first = raw_reply(&mut raw.stream).unwrap();
        assert_eq!(Reply::parse(&first, 1).unwrap().code, Code::Ok);
        let mut observer = connect(root.path());
        until(|| exchange_service(&mut observer, Operation::PicoclawRunning).code == Code::Ok);
        let old = fs::read(root.path().join("picoclaw")).unwrap();
        fs::write(root.path().join("pico-generation"), [2; 32]).unwrap();
        raw.stream.write_all(&start).unwrap();
        assert_eq!(raw_reply(&mut raw.stream).unwrap(), first);
        let changed = frame(Operation::EnsurePicoclaw, &Home::default(), 2);
        raw.stream.write_all(&changed).unwrap();
        assert_eq!(
            Reply::parse(&raw_reply(&mut raw.stream).unwrap(), 2)
                .unwrap()
                .code,
            Code::Invalid
        );
        assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), old);
        let stop = frame(Operation::StopPicoclaw, &Home::default(), 3);
        raw.stream.write_all(&stop).unwrap();
        let stopped = raw_reply(&mut raw.stream).unwrap();
        assert_eq!(Reply::parse(&stopped, 3).unwrap().code, Code::Ok);
        until(|| exchange_service(&mut observer, Operation::PicoclawStopped).code == Code::Ok);
        assert_eq!(
            exchange_service(&mut observer, Operation::EnsurePicoclaw).code,
            Code::Ok
        );
        until(|| exchange_service(&mut observer, Operation::PicoclawRunning).code == Code::Ok);
        let new = fs::read(root.path().join("picoclaw")).unwrap();
        assert_ne!(new, old);
        // Last-request replay returns the old admission receipt, not another
        // Stop against a different process created after that request finished.
        raw.stream.write_all(&stop).unwrap();
        assert_eq!(raw_reply(&mut raw.stream).unwrap(), stopped);
        assert_eq!(
            exchange_service(&mut observer, Operation::PicoclawRunning).code,
            Code::Ok
        );
        assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), new);
        assert_eq!(
            exchange_service(&mut observer, Operation::StopPicoclaw).code,
            Code::Ok
        );
        until(|| exchange_service(&mut observer, Operation::PicoclawStopped).code == Code::Ok);
    });
}
