use super::*;

const KEY_A: Report = Report::Keyboard([0, 0, 4, 0, 0, 0, 0, 0]);
const KEY_B: Report = Report::Keyboard([2, 0, 5, 0, 0, 0, 0, 0]);
const REL_DOWN: Report = Report::Relative([1, 4, 5, 1]);
const ABS_DOWN: Report = Report::Absolute([2, 11, 22, 33, 44, 255]);
const ABS_UP: Report = Report::Absolute([0, 11, 22, 33, 44, 0]);

#[derive(Default)]
struct Recording {
    attempts: Vec<Report>,
    effects: Vec<Report>,
    fail_at: Option<usize>,
    fail_after_effect: bool,
    closes: usize,
    fail_close: bool,
}

impl Sink for Recording {
    fn write(&mut self, report: Report) -> io::Result<()> {
        self.attempts.push(report);
        let fail = self.fail_at == Some(self.attempts.len());
        if !fail || self.fail_after_effect {
            self.effects.push(report);
        }
        if fail {
            return Err(io::Error::other("injected report error"));
        }
        Ok(())
    }
    fn close(&mut self) -> io::Result<()> {
        self.closes += 1;
        if self.fail_close {
            return Err(io::Error::other("injected close error"));
        }
        Ok(())
    }
}

fn effects(bus: &Bus<Recording>) -> Vec<Report> {
    bus.state.lock().unwrap().sink.effects.clone()
}

impl super::super::HidReports for Lease<'_, Recording> {
    fn keyboard(&self, report: &[u8; 8]) -> io::Result<usize> {
        self.write(Report::Keyboard(*report))
    }
    fn absolute(&self, report: &[u8; 6]) -> io::Result<usize> {
        self.write(Report::Absolute(*report))
    }
    fn settle_keyboard(&self) -> io::Result<usize> {
        self.release(Endpoint::Keyboard, true)
    }
    fn settle_absolute(&self) -> io::Result<usize> {
        self.release(Endpoint::Absolute, true)
    }
    fn finish(&self) -> io::Result<usize> {
        (*self).finish()
    }
}

#[test]
fn actual_pico_executor_preserves_reports_and_repeated_batches_without_truncation() {
    use crate::api::picoclaw::execute_reports_fixture;
    let bus = Bus::new(Recording::default());
    let owner = bus.begin().unwrap();
    let raw = br#"{"actions":[{"action":"click","x":1.0,"y":0.5},{"action":"drag","from":{"x":0.0,"y":0.0},"to":{"x":1.0,"y":1.0}},{"action":"scroll","amount":2,"direction":"down"},{"action":"type","text":"aA\n\t"},{"action":"hotkey","keys":["ctrl","alt","Delete"]},{"action":"wait","duration_ms":0}]}"#;
    let mut expected = vec![
        Report::Absolute([0, 0, 128, 0, 64, 0]),
        Report::Absolute([1, 0, 128, 0, 64, 0]),
        Report::Absolute([0, 0, 128, 0, 64, 0]),
        Report::Absolute([0, 1, 0, 1, 0, 0]),
        Report::Absolute([1, 1, 0, 1, 0, 0]),
    ];
    for value in [
        3277_u16, 6554, 9831, 13107, 16384, 19661, 22937, 26214, 29491, 32768,
    ] {
        let [lo, hi] = value.to_le_bytes();
        expected.push(Report::Absolute([1, lo, hi, lo, hi, 0]));
    }
    expected.push(Report::Absolute([0, 0, 128, 0, 128, 0]));
    for _ in 0..2 {
        expected.push(Report::Absolute([0, 0, 64, 0, 64, 255]));
        expected.push(Report::Absolute([0, 0, 64, 0, 64, 0]));
    }
    for key in [
        [0, 0, 4, 0, 0, 0, 0, 0],
        [2, 0, 4, 0, 0, 0, 0, 0],
        [0, 0, 40, 0, 0, 0, 0, 0],
        [0, 0, 43, 0, 0, 0, 0, 0],
        [5, 0, 76, 0, 0, 0, 0, 0],
    ] {
        expected.push(Report::Keyboard(key));
        expected.push(Report::Keyboard([0; 8]));
    }
    assert_eq!(expected.len(), 30);
    for _ in 0..3 {
        assert_eq!(execute_reports_fixture(&owner, raw).unwrap(), 30);
        assert_eq!(owner.finish().unwrap(), 0);
    }
    assert_eq!(effects(&bus), expected.repeat(3));
}

#[test]
fn actual_pico_report_executor_has_no_valid_prefix_effect_for_a_late_invalid_action() {
    let bus = Bus::new(Recording::default());
    let owner = bus.begin().unwrap();
    let raw = br#"{"actions":[{"action":"click","x":0.5,"y":0.5},{"action":"type","text":"valid prefix then unsupported \ud83d\ude42"}]}"#;
    assert!(crate::api::picoclaw::execute_reports_fixture(&owner, raw).is_err());
    assert!(effects(&bus).is_empty());
}

struct CancelAt<'a> {
    owner: Lease<'a, Recording>,
    replacement: Option<Lease<'a, Recording>>,
    call: &'a crate::api::picoclaw::execution::Call,
    at: usize,
    writes: std::cell::Cell<usize>,
}

impl CancelAt<'_> {
    fn write(&self, report: Report) -> io::Result<usize> {
        let count = self.owner.write(report)?;
        let written = self.writes.get() + 1;
        self.writes.set(written);
        if written == self.at {
            self.call.cancel_fixture();
            // After the owned write returned (bus lock released), a real later
            // owner can intervene before automatic key-up or error cleanup.
            if let Some(manual) = self.replacement {
                manual.write(match report {
                    Report::Keyboard(_) => KEY_B,
                    _ => ABS_DOWN,
                })?;
            }
        }
        Ok(count)
    }
}

impl super::super::HidReports for CancelAt<'_> {
    fn keyboard(&self, report: &[u8; 8]) -> io::Result<usize> {
        self.write(Report::Keyboard(*report))
    }
    fn absolute(&self, report: &[u8; 6]) -> io::Result<usize> {
        self.write(Report::Absolute(*report))
    }
    fn settle_keyboard(&self) -> io::Result<usize> {
        self.owner.release(Endpoint::Keyboard, true)
    }
    fn settle_absolute(&self) -> io::Result<usize> {
        self.owner.release(Endpoint::Absolute, true)
    }
    fn finish(&self) -> io::Result<usize> {
        self.owner.finish()
    }
}

#[test]
fn actual_executor_cancel_stops_report_loops_and_only_cleans_its_current_owner() {
    use crate::api::picoclaw::{execute_controlled_reports_fixture, execution::Call};
    for (raw, cancel_at, normal_effects) in [
        (r#"{"action":"click","x":0.5,"y":0.5}"#, 2, 3),
        (
            r#"{"action":"drag","from":{"x":0.0,"y":0.0},"to":{"x":1.0,"y":1.0}}"#,
            2,
            3,
        ),
        (
            r#"{"action":"scroll","amount":100,"direction":"down"}"#,
            1,
            2,
        ),
        (r#"{"action":"type","text":"aA\n\tlong remainder"}"#, 1, 2),
        (
            r#"{"action":"hotkey","keys":["ctrl","alt","Delete"]}"#,
            1,
            2,
        ),
    ] {
        for replace in [false, true] {
            let bus = Bus::new(Recording::default());
            let owner = bus.begin().unwrap();
            let manual = bus.begin().unwrap();
            let call = Call::fixture();
            let output = CancelAt {
                owner,
                replacement: replace.then_some(manual),
                call: &call,
                at: cancel_at,
                writes: std::cell::Cell::new(0),
            };
            let (result, clean) =
                execute_controlled_reports_fixture(&output, &call, raw.as_bytes());
            assert_eq!(result.unwrap_err(), "ACTION_CANCELLED");
            assert!(clean);
            assert_eq!(output.writes.get(), cancel_at);
            assert_eq!(owner.finish().unwrap(), 0);
            let actual = effects(&bus);
            if replace {
                assert_eq!(actual.len(), cancel_at + 1);
                assert!(actual.last().unwrap().held());
                assert_eq!(manual.finish().unwrap(), 1);
            } else {
                assert_eq!(actual.len(), normal_effects);
                assert!(!actual.last().unwrap().held());
                assert!(
                    bus.state
                        .lock()
                        .unwrap()
                        .current
                        .iter()
                        .flatten()
                        .all(|current| !current.needs_release)
                );
            }
        }
    }
}

#[test]
fn actual_executor_does_not_claim_clean_cancellation_after_failed_owned_compensation() {
    use crate::api::picoclaw::{execute_controlled_reports_fixture, execution::Call};
    for after_effect in [false, true] {
        let bus = Bus::new(Recording {
            fail_at: Some(2),
            fail_after_effect: after_effect,
            ..Recording::default()
        });
        let call = Call::fixture();
        let output = CancelAt {
            owner: bus.begin().unwrap(),
            replacement: None,
            call: &call,
            at: 1,
            writes: std::cell::Cell::new(0),
        };
        let (result, clean) = execute_controlled_reports_fixture(
            &output,
            &call,
            br#"{"action":"hotkey","keys":["ctrl","alt","Delete"]}"#,
        );
        assert_eq!(result.unwrap_err(), "HID_CLEANUP_UNCERTAIN");
        assert!(!clean);
        assert!(bus.state.lock().unwrap().current[0].unwrap().needs_release);
    }
}

#[test]
fn exact_keyboard_and_button_release_preserves_absolute_position_without_extra_motion() {
    let bus = Bus::new(Recording::default());
    let owner = bus.begin().unwrap();
    for report in [KEY_A, REL_DOWN, ABS_DOWN] {
        assert_eq!(owner.write(report).unwrap(), 1);
    }
    assert_eq!(owner.finish().unwrap(), 3);
    assert_eq!(owner.finish().unwrap(), 0);
    assert_eq!(
        effects(&bus),
        vec![
            KEY_A,
            REL_DOWN,
            ABS_DOWN,
            Report::Keyboard([0; 8]),
            Report::Relative([0; 4]),
            ABS_UP
        ]
    );
}

#[test]
fn stale_pico_or_websocket_cleanup_never_releases_a_later_owner() {
    for stale_first in [false, true] {
        let bus = Bus::new(Recording::default());
        let old = bus.begin().unwrap();
        let new = bus.begin().unwrap();
        for report in [KEY_A, REL_DOWN, ABS_DOWN] {
            old.write(report).unwrap();
        }
        if stale_first {
            assert_eq!(old.finish().unwrap(), 3);
        }
        for report in [KEY_B, REL_DOWN, ABS_DOWN] {
            new.write(report).unwrap();
        }
        let before = effects(&bus);
        assert_eq!(old.finish().unwrap(), 0);
        for endpoint in [Endpoint::Keyboard, Endpoint::Relative, Endpoint::Absolute] {
            assert_eq!(old.release(endpoint, true).unwrap(), 0);
        }
        assert_eq!(effects(&bus), before);
        assert_eq!(new.finish().unwrap(), 3);
    }
}

#[test]
fn cleanup_is_per_endpoint_and_momentary_scroll_settle_is_owner_checked() {
    let bus = Bus::new(Recording::default());
    let pico = bus.begin().unwrap();
    let manual = bus.begin().unwrap();
    pico.write(KEY_A).unwrap();
    pico.write(ABS_DOWN).unwrap();
    manual.write(ABS_DOWN).unwrap();
    assert_eq!(pico.finish().unwrap(), 1); // Only the still-owned keyboard.
    assert_eq!(pico.release(Endpoint::Absolute, true).unwrap(), 0);
    assert_eq!(manual.finish().unwrap(), 1);
    let wheel = Report::Absolute([0, 11, 22, 33, 44, 1]);
    pico.write(wheel).unwrap();
    assert_eq!(pico.finish().unwrap(), 0); // Wheel is not a held button.
    assert_eq!(pico.release(Endpoint::Absolute, true).unwrap(), 1);
    assert_eq!(effects(&bus).last(), Some(&ABS_UP));
}

#[test]
fn uncertain_write_can_be_compensated_but_never_after_a_new_writer() {
    for after_effect in [false, true] {
        for superseded in [false, true] {
            let bus = Bus::new(Recording {
                fail_at: Some(1),
                fail_after_effect: after_effect,
                ..Recording::default()
            });
            let old = bus.begin().unwrap();
            let new = bus.begin().unwrap();
            assert!(old.write(KEY_A).is_err());
            if superseded {
                new.write(KEY_B).unwrap();
            }
            let before = effects(&bus);
            assert_eq!(old.finish().unwrap(), usize::from(!superseded));
            if superseded {
                assert_eq!(effects(&bus), before);
            } else {
                assert_eq!(effects(&bus).last(), Some(&Report::Keyboard([0; 8])));
            }
        }
    }
}

#[test]
fn failed_normal_neutral_retains_possible_held_state_for_the_attempting_owner() {
    for (held, neutral) in [
        (KEY_A, Report::Keyboard([0; 8])),
        (REL_DOWN, Report::Relative([0; 4])),
        (ABS_DOWN, ABS_UP),
    ] {
        for after_effect in [false, true] {
            for new_owner in [false, true] {
                let bus = Bus::new(Recording {
                    fail_at: Some(2),
                    fail_after_effect: after_effect,
                    ..Recording::default()
                });
                let previous = bus.begin().unwrap();
                previous.write(held).unwrap();
                let attempting = if new_owner {
                    bus.begin().unwrap()
                } else {
                    previous
                };
                assert!(attempting.write(neutral).is_err());
                if new_owner {
                    let before = effects(&bus);
                    assert_eq!(previous.finish().unwrap(), 0);
                    assert_eq!(effects(&bus), before);
                }
                assert_eq!(attempting.finish().unwrap(), 1);
                assert_eq!(effects(&bus).last(), Some(&neutral));
                assert_eq!(attempting.finish().unwrap(), 0);
            }
        }
    }
}

#[test]
fn failed_normal_neutral_does_not_admit_jiggler_until_button_release_is_known() {
    for (held, neutral) in [(REL_DOWN, Report::Relative([0; 4])), (ABS_DOWN, ABS_UP)] {
        for after_effect in [false, true] {
            let bus = Bus::new(Recording {
                fail_at: Some(2),
                fail_after_effect: after_effect,
                ..Recording::default()
            });
            let manual = bus.begin().unwrap();
            let jiggler = bus.begin().unwrap();
            manual.write(held).unwrap();
            assert!(manual.write(neutral).is_err());
            assert_eq!(
                jiggler
                    .passive_mouse(Report::Relative([0, 10, 10, 0]), false)
                    .unwrap(),
                0
            );
            // A successful ordinary neutral report is sufficient too; cleanup
            // must neither remain falsely held nor replay another report.
            manual.write(neutral).unwrap();
            assert_eq!(manual.finish().unwrap(), 0);
            assert_eq!(
                jiggler
                    .passive_mouse(Report::Relative([0, 10, 10, 0]), false)
                    .unwrap(),
                1
            );
        }
    }
}

#[test]
fn failed_cleanup_retains_held_evidence_and_still_cleans_other_owned_endpoints() {
    for after_effect in [false, true] {
        let bus = Bus::new(Recording {
            fail_at: Some(4),
            fail_after_effect: after_effect,
            ..Recording::default()
        });
        let owner = bus.begin().unwrap();
        for report in [KEY_A, REL_DOWN, ABS_DOWN] {
            owner.write(report).unwrap();
        }
        assert!(owner.finish().is_err());
        {
            let state = bus.state.lock().unwrap();
            assert_eq!(state.sink.attempts.len(), 6);
            assert!(state.current[0].unwrap().report.held());
            assert!(!state.current[1].unwrap().report.held());
            assert!(!state.current[2].unwrap().report.held());
        }
        assert_eq!(owner.finish().unwrap(), 1);
        assert_eq!(owner.finish().unwrap(), 0);
    }
}

#[test]
fn later_writer_prevents_retry_of_a_previously_failed_cleanup() {
    let bus = Bus::new(Recording {
        fail_at: Some(2),
        ..Recording::default()
    });
    let old = bus.begin().unwrap();
    old.write(KEY_A).unwrap();
    assert!(old.finish().is_err());
    let later = bus.begin().unwrap();
    later.write(KEY_B).unwrap();
    let before = effects(&bus);
    assert_eq!(old.finish().unwrap(), 0);
    assert_eq!(effects(&bus), before);
}

#[test]
fn cached_fd_close_is_not_falsely_published_as_physical_key_release() {
    for fail_close in [false, true] {
        let bus = Bus::new(Recording {
            fail_close,
            ..Recording::default()
        });
        let owner = bus.begin().unwrap();
        owner.write(KEY_A).unwrap();
        assert_eq!(bus.close().is_err(), fail_close);
        assert_eq!(bus.state.lock().unwrap().sink.closes, 1);
        assert_eq!(owner.finish().unwrap(), 1);
        assert_eq!(effects(&bus), vec![KEY_A, Report::Keyboard([0; 8])]);
    }
}

#[test]
fn owner_id_exhaustion_fails_without_wrap_or_reusing_an_old_identity() {
    let bus = Bus::new(Recording::default());
    *bus.next.lock().unwrap() = u64::MAX - 1;
    let last = bus.begin().unwrap();
    assert_eq!(last.id, u64::MAX);
    assert!(bus.begin().is_err());
    last.write(KEY_A).unwrap();
    assert_eq!(last.finish().unwrap(), 1);
}

#[test]
fn passive_jiggler_does_not_release_held_buttons_on_either_mouse_endpoint() {
    for held in [REL_DOWN, ABS_DOWN] {
        let bus = Bus::new(Recording::default());
        let user = bus.begin().unwrap();
        let jiggler = bus.begin().unwrap();
        user.write(held).unwrap();
        let before = effects(&bus);
        for report in [Report::Relative([0, 10, 10, 0]), ABS_UP] {
            assert_eq!(jiggler.passive_mouse(report, false).unwrap(), 0);
        }
        assert_eq!(effects(&bus), before);
        user.finish().unwrap();
        assert_eq!(jiggler.passive_mouse(ABS_UP, false).unwrap(), 1);
        assert_eq!(jiggler.passive_mouse(ABS_UP, true).unwrap(), 1);
    }
}

#[test]
fn passive_pair_never_undoes_a_manual_move_on_the_other_mouse_endpoint() {
    for (first, other) in [
        (Report::Relative([0, 10, 10, 0]), ABS_UP),
        (ABS_UP, Report::Relative([0, 1, 1, 0])),
    ] {
        let bus = Bus::new(Recording::default());
        let jiggler = bus.begin().unwrap();
        let manual = bus.begin().unwrap();
        assert_eq!(jiggler.passive_mouse(first, false).unwrap(), 1);
        manual.write(other).unwrap();
        assert_eq!(jiggler.passive_mouse(first, true).unwrap(), 0);
        assert_eq!(effects(&bus), vec![first, other]);
        assert!(jiggler.passive_mouse(KEY_A, false).is_err());
    }
}

#[test]
fn blocked_io_does_not_block_owner_allocation_and_old_finish_cannot_follow_new_keydown() {
    use std::{sync::mpsc, time::Duration};
    struct Gated {
        recording: Recording,
        started: mpsc::SyncSender<()>,
        release: Option<mpsc::Receiver<()>>,
    }
    impl Sink for Gated {
        fn write(&mut self, report: Report) -> io::Result<()> {
            if let Some(release) = self.release.take() {
                self.started.send(()).unwrap();
                release.recv().unwrap();
            }
            self.recording.write(report)
        }
        fn close(&mut self) -> io::Result<()> {
            self.recording.close()
        }
    }
    let (started, observed) = mpsc::sync_channel(1);
    let (release, gate) = mpsc::sync_channel(1);
    let (allocated, allocation) = mpsc::sync_channel(1);
    let bus = Bus::new(Gated {
        recording: Recording::default(),
        started,
        release: Some(gate),
    });
    std::thread::scope(|scope| {
        let old = bus.begin().unwrap();
        let writing = scope.spawn(move || {
            old.write(KEY_A).unwrap();
            old.finish().unwrap();
        });
        let began = observed.recv_timeout(Duration::from_secs(5));
        if began.is_err() {
            let _ = release.send(());
        }
        began.unwrap();
        let writing_new = scope.spawn(|| {
            let newer = bus.begin().unwrap();
            allocated.send(newer.id).unwrap();
            newer.write(KEY_B).unwrap();
        });
        let new_owner = allocation.recv_timeout(Duration::from_secs(5));
        release.send(()).unwrap(); // Always release before any assertion panic.
        assert_ne!(new_owner.unwrap(), old.id);
        writing.join().unwrap();
        writing_new.join().unwrap();
    });
    assert_eq!(
        bus.state.lock().unwrap().sink.recording.effects.last(),
        Some(&KEY_B)
    );
}

struct WsRecordingOwner<S> {
    bus: std::sync::Arc<Bus<S>>,
    id: u64,
}

impl<S> Clone for WsRecordingOwner<S> {
    fn clone(&self) -> Self {
        Self {
            bus: std::sync::Arc::clone(&self.bus),
            id: self.id,
        }
    }
}

impl<S: Sink + Send + 'static> super::super::WsInput for WsRecordingOwner<S> {
    fn write(
        &self,
        report: Report,
        session: &crate::http::middleware::TransportSession,
    ) -> io::Result<usize> {
        Lease {
            bus: &self.bus,
            id: self.id,
        }
        .write_if(report, || session.is_active())
    }

    fn release(&self, endpoint: Endpoint) -> io::Result<usize> {
        Lease {
            bus: &self.bus,
            id: self.id,
        }
        .release(endpoint, false)
    }
}

fn ws_authority(
    session: &crate::auth::session::Session,
) -> crate::http::middleware::TransportSession {
    crate::http::middleware::TransportSession::capture(
        &crate::config::Config::default(),
        Some(axum::Extension(crate::http::middleware::CurrentSession(
            session.clone(),
        ))),
    )
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn ws_revocation_during_actual_worker_io_discards_queue_and_joins_owned_cleanup() {
    use std::{
        sync::mpsc as sync,
        time::{Duration, Instant},
    };
    struct Gated {
        recording: Recording,
        started: sync::SyncSender<()>,
        release: Option<sync::Receiver<()>>,
    }
    impl Sink for Gated {
        fn write(&mut self, report: Report) -> io::Result<()> {
            if let Some(release) = self.release.take() {
                self.started.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "synthetic WS I/O gate timeout")
                })?;
            }
            self.recording.write(report)
        }
        fn close(&mut self) -> io::Result<()> {
            self.recording.close()
        }
    }
    let cases: [(Report, Report, &'static [Endpoint]); 3] = [
        (KEY_A, KEY_B, &[Endpoint::Keyboard]),
        (
            REL_DOWN,
            Report::Relative([2, 1, 2, 0]),
            &[Endpoint::Relative, Endpoint::Absolute],
        ),
        (
            ABS_DOWN,
            Report::Absolute([1, 1, 2, 3, 4, 0]),
            &[Endpoint::Relative, Endpoint::Absolute],
        ),
    ];
    for (held, queued, endpoints) in cases {
        let sessions = crate::auth::session::SessionStore::new();
        let session = sessions.issue("admin", 60).await;
        let (started, observed) = sync::sync_channel(1);
        let (release, gate) = sync::sync_channel(1);
        let bus = std::sync::Arc::new(Bus::new(Gated {
            recording: Recording::default(),
            started,
            release: Some(gate),
        }));
        let id = bus.begin().unwrap().id;
        let owner = WsRecordingOwner {
            bus: std::sync::Arc::clone(&bus),
            id,
        };
        let (send, receive) = tokio::sync::mpsc::channel(2);
        send.send(held).await.unwrap();
        send.send(queued).await.unwrap();
        let worker = tokio::spawn(super::super::report_worker(
            receive,
            owner,
            ws_authority(&session),
            endpoints,
        ));
        tokio::task::yield_now().await;
        let began = observed.recv_timeout(Duration::from_secs(2));
        if began.is_err() {
            let _ = release.send(());
        }
        began.unwrap();
        let start = Instant::now();
        sessions.revoke(&session.token).await;
        let control_elapsed = start.elapsed();
        let still_pending_io = !worker.is_finished();
        release.send(()).unwrap(); // Release even before a timing assertion.
        let clean = tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .unwrap()
            .unwrap();
        assert!(control_elapsed < Duration::from_secs(1));
        assert!(
            still_pending_io,
            "cancel flag was incorrectly treated as a drain"
        );
        assert!(clean);
        assert_eq!(
            bus.state.lock().unwrap().sink.recording.effects,
            vec![held, held.neutral()]
        );
        assert!(send.is_closed());
    }
}

#[tokio::test]
async fn ws_revoked_or_closed_connection_never_drains_its_pending_input_as_new_writes() {
    for revoke in [false, true] {
        let sessions = crate::auth::session::SessionStore::new();
        let session = sessions.issue("admin", 60).await;
        let authority = ws_authority(&session);
        let bus = std::sync::Arc::new(Bus::new(Recording::default()));
        let id = bus.begin().unwrap().id;
        let owner = WsRecordingOwner {
            bus: std::sync::Arc::clone(&bus),
            id,
        };
        let (send, receive) = tokio::sync::mpsc::channel(2);
        send.send(KEY_A).await.unwrap();
        send.send(KEY_B).await.unwrap();
        if revoke {
            sessions.revoke(&session.token).await;
        }
        drop(send);
        assert!(
            super::super::report_worker(receive, owner, authority, &[Endpoint::Keyboard]).await
        );
        assert!(effects(&bus).is_empty());
    }
}

#[tokio::test]
async fn ws_worker_reports_failed_owned_cleanup_as_uncertain_not_a_clean_drain() {
    for after_effect in [false, true] {
        let sessions = crate::auth::session::SessionStore::new();
        let session = sessions.issue("admin", 60).await;
        let authority = ws_authority(&session);
        let bus = std::sync::Arc::new(Bus::new(Recording {
            fail_at: Some(2),
            fail_after_effect: after_effect,
            ..Recording::default()
        }));
        let lease = bus.begin().unwrap();
        let id = lease.id;
        lease.write(KEY_A).unwrap();
        let owner = WsRecordingOwner {
            bus: std::sync::Arc::clone(&bus),
            id,
        };
        let (_send, receive) = tokio::sync::mpsc::channel(1);
        sessions.revoke(&session.token).await;
        assert!(
            !super::super::report_worker(receive, owner, authority, &[Endpoint::Keyboard]).await
        );
        assert!(bus.state.lock().unwrap().current[0].unwrap().needs_release);
    }
}

#[tokio::test]
async fn ws_worker_preserves_fresh_input_after_failed_report_and_successful_owned_recovery() {
    use std::time::Duration;
    let sessions = crate::auth::session::SessionStore::new();
    let session = sessions.issue("admin", 60).await;
    let authority = ws_authority(&session);
    let bus = std::sync::Arc::new(Bus::new(Recording {
        fail_at: Some(1),
        fail_after_effect: true,
        ..Recording::default()
    }));
    let id = bus.begin().unwrap().id;
    let owner = WsRecordingOwner {
        bus: std::sync::Arc::clone(&bus),
        id,
    };
    let (send, receive) = tokio::sync::mpsc::channel(2);
    send.send(KEY_A).await.unwrap();
    send.send(KEY_B).await.unwrap();
    let worker = tokio::spawn(super::super::report_worker(
        receive,
        owner,
        authority,
        &[Endpoint::Keyboard],
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        while bus.state.lock().unwrap().sink.attempts.len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(effects(&bus), vec![KEY_A, Report::Keyboard([0; 8])]);
    // The queued old KEY_B was discarded; only this later explicit input may run.
    send.send(KEY_B).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while bus.state.lock().unwrap().sink.attempts.len() < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    sessions.revoke(&session.token).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), worker)
            .await
            .unwrap()
            .unwrap()
    );
    assert_eq!(
        effects(&bus),
        vec![
            KEY_A,
            Report::Keyboard([0; 8]),
            KEY_B,
            Report::Keyboard([0; 8])
        ]
    );
}

#[test]
fn guarded_report_rechecks_authority_after_delayed_bus_acquisition_before_device_effects() {
    use std::{
        sync::{Arc, Mutex, mpsc},
        time::Duration,
    };
    let bus = Arc::new(Bus::new(Recording::default()));
    let id = bus.begin().unwrap().id;
    let allowed = Arc::new(Mutex::new(true));
    let held = bus.state.lock().unwrap();
    let (started, ready) = mpsc::sync_channel(1);
    let (checking, checked) = mpsc::sync_channel(1);
    let writer_bus = Arc::clone(&bus);
    let writer_allowed = Arc::clone(&allowed);
    let writer = std::thread::spawn(move || {
        started.send(()).unwrap();
        Lease {
            bus: &writer_bus,
            id,
        }
        .write_if(KEY_A, || {
            checking.send(()).unwrap();
            *writer_allowed.lock().unwrap()
        })
    });
    let began = ready.recv_timeout(Duration::from_secs(2));
    let checked_before_bus_release = checked.recv_timeout(Duration::from_millis(20));
    *allowed.lock().unwrap() = false;
    drop(held); // Always release before assertions or joining the writer.
    let result = writer.join().unwrap();
    began.unwrap();
    assert!(matches!(
        checked_before_bus_release,
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    checked.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert!(effects(&bus).is_empty());
}

#[tokio::test]
async fn authenticated_hid_session_revoke_joins_cleanup_without_releasing_a_later_session_owner() {
    use crate::{
        config::Config,
        http::middleware::{CurrentSession, TransportSession, protected},
        state::AppState,
    };
    use axum::{
        Extension, Router,
        extract::{State, ws::WebSocketUpgrade},
        http::HeaderMap,
        middleware::from_fn_with_state,
        response::IntoResponse,
        routing::get,
    };
    use futures_util::{SinkExt, StreamExt};
    use std::{sync::Arc, time::Duration};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

    async fn fixture(
        State(state): State<AppState>,
        Extension(bus): Extension<Arc<Bus<Recording>>>,
        current: Option<Extension<CurrentSession>>,
        headers: HeaderMap,
        ws: WebSocketUpgrade,
    ) -> crate::Result<impl IntoResponse> {
        let session = TransportSession::capture(&state.config, current)?;
        if !crate::ws::origin::validate_ws_origin(&headers, &state.config) {
            return Err(crate::AppError::Forbidden(
                "invalid websocket origin".into(),
            ));
        }
        let id = bus.begin().unwrap().id;
        let owner = WsRecordingOwner { bus, id };
        Ok(ws.on_upgrade(move |socket| super::super::handle_socket_owned(socket, session, owner)))
    }

    fn event(report: Report) -> Message {
        let mut data = Vec::with_capacity(9);
        match report {
            Report::Keyboard(bytes) => {
                data.push(super::super::KEYBOARD_EVENT);
                data.extend_from_slice(&bytes);
            }
            Report::Relative(bytes) => {
                data.push(super::super::MOUSE_EVENT);
                data.extend_from_slice(&bytes);
            }
            Report::Absolute(bytes) => {
                data.push(super::super::MOUSE_EVENT);
                data.extend_from_slice(&bytes);
            }
        }
        Message::Binary(data.into())
    }

    async fn wait_effects(bus: &Bus<Recording>, minimum: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while effects(bus).len() < minimum {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    struct ServerTask(Option<tokio::task::JoinHandle<()>>);
    impl Drop for ServerTask {
        fn drop(&mut self) {
            if let Some(task) = &self.0 {
                task.abort();
            }
        }
    }

    let mut config = Config::default();
    config.security.allow_default_admin = false;
    let state = AppState::new(config).await.unwrap();
    let bus = Arc::new(Bus::new(Recording::default()));
    let router = Router::new()
        .route("/hid", get(fixture))
        .route_layer(from_fn_with_state(state.clone(), protected))
        .layer(Extension(Arc::clone(&bus)))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut server = ServerTask(Some(tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    })));
    let open = |token: String| async move {
        let mut request = format!("ws://{address}/hid").into_client_request().unwrap();
        request.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        request.headers_mut().insert(
            axum::http::header::ORIGIN,
            format!("http://{address}").parse().unwrap(),
        );
        tokio_tungstenite::connect_async(request).await.unwrap().0
    };

    let old = state.sessions.issue("admin", 60).await;
    let mut old_socket = open(old.token.clone()).await;
    old_socket.send(event(KEY_A)).await.unwrap();
    old_socket.send(event(ABS_DOWN)).await.unwrap();
    wait_effects(&bus, 2).await;
    let successor = state.sessions.issue("admin", 60).await;
    let mut new_socket = open(successor.token.clone()).await;
    new_socket.send(event(KEY_B)).await.unwrap();
    wait_effects(&bus, 3).await;
    state.sessions.revoke(&old.token).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match old_socket.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .unwrap();
    drop(old_socket);
    wait_effects(&bus, 4).await;
    let keyboard = effects(&bus)
        .into_iter()
        .filter(|report| matches!(report, Report::Keyboard(_)))
        .collect::<Vec<_>>();
    assert_eq!(keyboard, vec![KEY_A, KEY_B]);
    assert!(bus.state.lock().unwrap().current[0].unwrap().needs_release);
    assert!(!bus.state.lock().unwrap().current[2].unwrap().needs_release);
    new_socket.send(event(KEY_A)).await.unwrap();
    wait_effects(&bus, 5).await;
    state.sessions.revoke(&successor.token).await;
    wait_effects(&bus, 6).await;
    assert_eq!(effects(&bus).last(), Some(&Report::Keyboard([0; 8])));
    drop(new_socket);
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), server.0.take().unwrap())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn cached_fd_close_waits_off_tokio_under_a_report_bus_lock() {
    use std::{
        future::{Future, poll_fn},
        task::Poll,
        time::{Duration, Instant},
    };
    let (started, observed) = std::sync::mpsc::sync_channel(1);
    let held = std::thread::spawn(move || {
        // A fresh test-process device cache has no open endpoint FDs. This
        // holds only the report-bus mutex, never opens/restarts a host device.
        let _guard = super::super::HID.state.lock().unwrap();
        started.send(()).unwrap();
        std::thread::sleep(Duration::from_secs(2));
    });
    observed.recv_timeout(Duration::from_secs(5)).unwrap();
    let mut close = Box::pin(super::super::close_cached_hid_devices());
    let began = Instant::now();
    let first = poll_fn(|cx| Poll::Ready(close.as_mut().poll(cx))).await;
    let first_poll_time = began.elapsed();
    let pending = first.is_pending();
    tokio::time::sleep(Duration::from_millis(10)).await;
    let heartbeat_time = began.elapsed();
    let result = match first {
        Poll::Ready(result) => result,
        Poll::Pending => close.await,
    };
    held.join().unwrap();
    result.unwrap();
    assert!(pending);
    assert!(first_poll_time < Duration::from_secs(1));
    assert!(heartbeat_time < Duration::from_secs(1));
}
