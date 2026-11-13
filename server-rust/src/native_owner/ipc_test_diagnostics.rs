//! Bounded test-only transport observations, never replay/ownership authority.
use super::{Client, Engine};
use std::{io, time::Duration};

#[derive(Clone, Copy, Debug)]
pub(super) enum Origin {
    Fixture,
    DeliveryDaemon,
    FixedRootDelivery,
}

pub(super) fn client_close(
    origin: Origin,
    client: &Client,
    engine: &Engine,
    idle: Duration,
    error: Option<io::ErrorKind>,
) -> String {
    // Fixed enums/counts only: not frame bytes, error strings, paths or payloads.
    format!(
        "native-client-close: origin={origin:?}, pid={}, key={}, reason={}, error={error:?}, phase={}, read={}, sent={}, age={:?}, idle={idle:?}, mode={:?}, lease={:?}, install={}",
        std::process::id(),
        client.key,
        if error.is_some() { "error" } else { "idle" },
        if client.writing { "write" } else { "read" },
        client.read,
        client.sent,
        client.last_activity.elapsed(),
        engine.mode,
        engine.lease,
        engine.install.is_some()
    )
}

#[test]
fn close_observation_reports_phase_and_kind_without_frame_or_cached_reply() {
    use super::tests::broker;
    use std::{
        io::{Read as _, Write as _},
        net::Shutdown,
        os::unix::net::UnixStream,
        time::Instant,
    };
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(broker(root.path()));
    let (stream, mut peer) = UnixStream::pair().unwrap();
    let mut client = Client::new(stream, 42, nix::unistd::geteuid().as_raw()).unwrap();
    client.input.fill(0xab);
    client.output.fill(0xcd);
    client.last = Some((client.input, client.output));
    client.read = 17;
    client.sent = 8;
    client.last_activity = Instant::now() - Duration::from_secs(6);
    for writing in [false, true] {
        client.writing = writing;
        let text = client_close(
            Origin::DeliveryDaemon,
            &client,
            &engine,
            Duration::from_secs(5),
            Some(io::ErrorKind::BrokenPipe),
        );
        assert!(text.contains("origin=DeliveryDaemon"));
        assert!(text.contains("reason=error, error=Some(BrokenPipe)"));
        assert!(text.contains(if writing { "phase=write" } else { "phase=read" }));
        assert!(text.contains("key=42") && text.contains("read=17, sent=8"));
        assert!(!text.contains("[171,") && !text.contains("[205,"));
        assert!(text.len() < 1024);
    }
    let text = client_close(
        Origin::FixedRootDelivery,
        &client,
        &engine,
        Duration::from_secs(5),
        None,
    );
    assert!(text.contains("reason=idle, error=None"));
    assert_eq!(client.read, 17);
    assert_eq!(client.sent, 8);
    assert_eq!(client.input, [0xab; super::FRAME]);
    assert_eq!(client.output, [0xcd; super::FRAME]);
    // Observation did not close the socket or execute/replay the stored frame.
    assert!(engine.install.is_none());
    peer.write_all(b"!").unwrap();
    let mut probe = [0];
    assert_eq!(client.stream.read(&mut probe).unwrap(), 1);
    assert_eq!(probe, *b"!");
    peer.shutdown(Shutdown::Both).unwrap();
}
