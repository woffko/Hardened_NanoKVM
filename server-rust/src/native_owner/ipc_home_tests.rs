use super::*;

fn query(home: &Home, serial: u64) -> [u8; FRAME] {
    let mut bytes = request(Operation::CheckPicoclawHome, serial);
    bytes[16..].copy_from_slice(&home.fingerprint());
    bytes
}

#[test]
fn home_query_has_an_independent_full_width_wire_vector() {
    // SHA256(domain || absolute UTF8 path), independently computed by hashlib.
    let expected = [
        0xb9, 0xc4, 0xe2, 0xc3, 0x2d, 0xb6, 0xc8, 0x19, 0x6b, 0x23, 0x2b, 0x53, 0xdb, 0xf3, 0x8b,
        0x24, 0x8b, 0xcf, 0x2a, 0x99, 0x11, 0x56, 0xa1, 0x55, 0x1a, 0x79, 0x42, 0x03, 0x25, 0x9e,
        0x57, 0xe8,
    ];
    let (a, _b) = UnixStream::pair().unwrap();
    let mut channel = Channel::verified(a, nix::unistd::geteuid().as_raw()).unwrap();
    assert_eq!(
        channel
            .begin(Operation::CheckPicoclawHome)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(channel.flight.is_none());
    channel.check_picoclaw_home(&Home::default()).unwrap();
    let bytes = &channel.flight.as_ref().unwrap().bytes;
    assert_eq!(&bytes[..16], b"NKC2\x0d\0\0\0\0\0\0\0\0\0\0\x01");
    assert_eq!(&bytes[16..], &expected);
    assert_eq!(
        parse_request(bytes),
        Some((Operation::CheckPicoclawHome, 1))
    );
    assert_eq!(
        channel
            .check_picoclaw_home(&Home::default())
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn checked_home_match_never_reselects_the_broker_or_publishes_native_intent() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    broker.group = Group::new(Home::fixture("agent", "/selected"));
    let mut engine = Engine::new(broker);
    engine.wanted = [true; 2];
    engine.backend_wanted = true;
    for home in [Home::fixture("agent", "/other"), Home::default()] {
        let bytes = query(&home, 1);
        let reply = engine.request_frame(1, Operation::CheckPicoclawHome, &bytes);
        assert_eq!(reply.code, Code::Invalid);
        assert_eq!(reply.mode, Mode::Running);
    }
    let home = Home::fixture("/selected/agent", "/irrelevant");
    let bytes = query(&home, 2);
    assert_eq!(
        engine
            .request_frame(1, Operation::CheckPicoclawHome, &bytes)
            .code,
        Code::Ok
    );
    assert_eq!(engine.home, home.fingerprint());
    assert!(!root.path().join("native-runtime-owner/state").exists());
    assert!(!root.path().join("kvm").exists());
    assert!(!root.path().join("hwmon").exists());
    assert!(!root.path().join("backend").exists());
    assert!(!root.path().join("picoclaw").exists());
    assert_eq!(engine.wanted, [true; 2]);
    assert!(engine.backend_wanted);
    engine.wanted = [false; 2];
    engine.backend_wanted = false;
    assert_eq!(engine.request(3, Operation::Pause).code, Code::Ok);
    until(|| {
        engine.tick();
        engine.mode == Mode::Paused
    });
    assert_eq!(
        engine
            .request_frame(1, Operation::CheckPicoclawHome, &bytes)
            .code,
        Code::Busy
    );
    assert_eq!(engine.request(3, Operation::Resume).code, Code::Ok);
    assert_eq!(
        engine
            .request_frame(1, Operation::CheckPicoclawHome, &bytes)
            .code,
        Code::Ok
    );
}

#[test]
fn real_endpoint_matches_full_home_digest_and_keeps_mismatch_non_mutating() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    broker.group = Group::new(Home::fixture("relative home", "/initial"));
    let uid = nix::unistd::geteuid().as_raw();
    serve_prepared(Server::new(broker, uid).unwrap(), || {
        let mut channel = connect(root.path());
        for (home, expected) in [
            (Home::fixture("relative home", "/wrong"), Code::Invalid),
            (
                Home::fixture("/initial/relative home", "/anything"),
                Code::Ok,
            ),
        ] {
            channel.check_picoclaw_home(&home).unwrap();
            let mut reply = None;
            until(|| {
                reply = channel.poll().unwrap();
                reply.is_some()
            });
            assert_eq!(reply.unwrap().code, expected);
        }
        assert!(!root.path().join("native-runtime-owner/state").exists());
        assert!(!root.path().join("picoclaw").exists());
    });
}

#[test]
fn cached_home_query_replay_cannot_change_context_and_legacy_frames_do_not_launch() {
    for legacy in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::geteuid().as_raw();
        serve(root.path(), uid, || {
            let mut channel = connect(root.path());
            channel.stream.set_nonblocking(false).unwrap();
            channel
                .stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            if legacy {
                let mut old = [0; 16];
                old[..4].copy_from_slice(b"NKC1");
                old[4] = Operation::EnsureKvm as u8;
                old[15] = 1;
                channel.stream.write_all(&old.repeat(3)).unwrap();
            } else {
                let bytes = query(&Home::default(), 1);
                channel.stream.write_all(&bytes).unwrap();
                let first = raw_reply(&mut channel.stream).unwrap();
                channel.stream.write_all(&bytes).unwrap();
                assert_eq!(raw_reply(&mut channel.stream).unwrap(), first);
                let mut conflict = bytes;
                conflict[FRAME - 1] ^= 1;
                channel.stream.write_all(&conflict).unwrap();
            }
            assert_eq!(channel.stream.read(&mut [0]).unwrap(), 0);
            assert!(!root.path().join("native-runtime-owner/state").exists());
            assert!(!root.path().join("kvm").exists());
        });
    }
}

#[test]
fn old_or_nonzero_reserved_reply_cannot_confirm_a_home_check() {
    for invalid in 0..3 {
        let (a, mut peer) = UnixStream::pair().unwrap();
        let mut channel = Channel::verified(a, nix::unistd::geteuid().as_raw()).unwrap();
        channel.check_picoclaw_home(&Home::default()).unwrap();
        assert!(channel.poll().unwrap().is_none());
        peer.read_exact(&mut [0; FRAME]).unwrap();
        let mut reply = Reply {
            code: Code::Ok,
            mode: Mode::Running,
            roles: [0; 2],
        }
        .bytes(1);
        if invalid == 0 {
            reply[..4].copy_from_slice(b"NKR1");
        } else if invalid == 1 {
            reply[FRAME - 1] = 1;
        } else {
            reply[5] = Mode::Paused as u8;
        }
        peer.write_all(&reply).unwrap();
        assert_eq!(
            channel.poll().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            channel
                .check_picoclaw_home(&Home::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
