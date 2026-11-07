use ::time::{OffsetDateTime, format_description::well_known::Rfc3339};
use async_stream::stream;
use axum::{
    Extension, Json,
    body::Body,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Response, header},
    response::IntoResponse,
};
use bytes::Bytes;
use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    future::Future,
    io,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::{broadcast, oneshot},
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};

use crate::{
    AppError, Result,
    error::ApiResponse,
    ffi::kvm,
    http::middleware::{CurrentSession, TransportSession},
    state::AppState,
    ws::{hid as hid_ws, origin::validate_ws_origin},
};

const FRAME_DETECT_INTERVAL: u8 = 60;

/// The frame-detect interval the user chose (0 = off) and the stop windows that
/// hold it off for a while. libkvm starts with detection off and the web
/// announces the stored choice at page load; a window ends at the configured
/// value, not at a constant, and a choice made inside a window takes effect
/// when the last window ends.
struct FrameDetect {
    configured: u8,
    windows: usize,
}

static FRAME_DETECT: Mutex<FrameDetect> = Mutex::new(FrameDetect {
    configured: 0,
    windows: 0,
});

impl FrameDetect {
    fn configure(&mut self, frame: u8, apply: impl FnOnce(u8) -> Result<()>) -> Result<()> {
        if self.windows == 0 {
            apply(frame)?;
        }
        self.configured = frame;
        Ok(())
    }

    fn stop_begin(&mut self, apply: impl FnOnce(u8) -> Result<()>) -> Result<()> {
        if self.windows == 0 {
            apply(0)?;
        }
        self.windows += 1;
        Ok(())
    }

    fn stop_end(&mut self, apply: impl FnOnce(u8) -> Result<()>) -> Result<()> {
        self.windows = self.windows.saturating_sub(1);
        if self.windows == 0 {
            apply(self.configured)?;
        }
        Ok(())
    }
}

fn frame_detect() -> Result<std::sync::MutexGuard<'static, FrameDetect>> {
    FRAME_DETECT
        .lock()
        .map_err(|_| AppError::Internal("frame detect state poisoned".to_string()))
}

#[cfg(test)]
#[path = "stream_session_tests.rs"]
mod session_lifetime_tests;
pub const CAPTURE_STATUS_EVENT: &str = "capture-status";
pub const CAPTURE_MODE_DIRECT: &str = "direct";
pub const CAPTURE_MODE_H264: &str = "h264";
pub const CAPTURE_MODE_MJPEG: &str = "mjpeg";
const CAPTURE_SEVERITY_ERROR: &str = "error";
const CAPTURE_SEVERITY_WARNING: &str = "warning";
const SCREEN_TYPE_FILE: &str = "/kvmapp/kvm/type";
const SCREEN_FPS_FILE: &str = "/kvmapp/kvm/fps";
const SCREEN_QUALITY_FILE: &str = "/kvmapp/kvm/qlty";
const SCREEN_RESOLUTION_FILE: &str = "/kvmapp/kvm/res";
const SCREEN_GOP_FILE: &str = "/kvmapp/kvm/gop";
const H264_SAFE_MODE_FILE: &str = "/etc/kvm/h264_safe_mode";
const MJPEG_FAILURE_LIMIT: usize = 3;
const MJPEG_FAILURE_BACKOFF: Duration = Duration::from_millis(500);
const MJPEG_FAILURE_COOLDOWN: Duration = Duration::from_secs(5);
/// libkvm's MJPEG result when frame detection found the screen unchanged.
const MJPEG_FRAME_UNCHANGED: i32 = 5;
const H264_READ_TIMEOUT: Duration = Duration::from_secs(5);
const H264_FAILURE_LIMIT: usize = 3;
/// After a failed read the source waits before the next one, and longer once
/// the failure limit is reached: a lost HDMI input is not polled at frame rate.
const H264_FAILURE_BACKOFF: Duration = Duration::from_millis(500);
const H264_FAILURE_COOLDOWN: Duration = Duration::from_secs(5);
const H264_KEYFRAME_REQUEST_HOLD: Duration = Duration::from_millis(250);
/// At most one keyframe request per interval: a peer flooding RTCP PLI/FIR
/// would otherwise reconfigure the encoder for every viewer several times a
/// second. Loss recovery once a second is still prompt.
const H264_KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_secs(1);

static SCREEN: LazyLock<Mutex<Screen>> = LazyLock::new(|| Mutex::new(Screen::default()));
static LATEST_MJPEG_FRAME: LazyLock<Mutex<Option<LatestMjpegFrame>>> =
    LazyLock::new(|| Mutex::new(None));
static MJPEG_FANOUT: LazyLock<StreamFanout<MjpegFrame>> = LazyLock::new(|| StreamFanout::new(4));
/// The one H.264 encoder is stateful: every read returns the next frame of
/// one sequence, so every viewer, Direct or WebRTC, must get every frame.
static H264_SOURCE: LazyLock<H264Source> =
    LazyLock::new(|| H264Source::new(8, request_h264_keyframe));
static MJPEG_FIRST_READ_LOGGED: AtomicBool = AtomicBool::new(false);
static MJPEG_FIRST_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static MJPEG_FIRST_ERROR_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_DIRECT_FIRST_READ_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_DIRECT_FIRST_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_DIRECT_FIRST_ERROR_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_CAPTURE_DISABLED: AtomicBool = AtomicBool::new(false);
static H264_CONSECUTIVE_FAILURES: AtomicUsize = AtomicUsize::new(0);
/// Set by the first failure of an outage, cleared by the next good frame.
static H264_OUTAGE_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_KEYFRAME_REQUEST_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static H264_LAST_KEYFRAME_REQUEST: Mutex<Option<Instant>> = Mutex::new(None);
static CAPTURE_STATUS: LazyLock<Mutex<CaptureStatusStore>> =
    LazyLock::new(|| Mutex::new(CaptureStatusStore::default()));

#[derive(Debug, Clone, Copy)]
struct Screen {
    mode: StreamMode,
    width: u16,
    height: u16,
    fps: u64,
    quality: u16,
    bit_rate: u16,
    gop: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    Mjpeg,
    H264,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H264Screen {
    pub width: u16,
    pub height: u16,
    pub fps: u64,
    pub bit_rate: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MjpegScreen {
    pub width: u16,
    pub height: u16,
    pub quality: u16,
}

#[derive(Debug, Clone)]
pub struct LatestMjpegFrame {
    pub data: Vec<u8>,
    pub width: u16,
    pub height: u16,
    captured_at: Instant,
}

#[derive(Debug, Clone)]
struct MjpegFrame {
    header: Bytes,
    data: Bytes,
}

/// One encoded frame of the single H.264 source. `packet` is the Direct
/// websocket framing (keyframe flag, timestamp, data); `data` borrows it.
#[derive(Debug, Clone)]
pub(crate) struct H264Frame {
    pub(crate) data: Bytes,
    packet: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum H264Viewer {
    Direct,
    WebRtc,
}

/// What the source does on its next tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H264SourceStep {
    Capture(H264Screen),
    /// Another client selected MJPEG; viewers stay connected for the switch
    /// back.
    Wait(u64),
    Stop,
}

struct H264Source {
    fanout: StreamFanout<H264Frame>,
    direct: AtomicUsize,
    webrtc: AtomicUsize,
    /// Asks the encoder for an I-frame; a viewer that joins a running stream
    /// or lost frames cannot decode anything before one arrives.
    keyframe: fn(&'static str),
}

/// A viewer's place in the fan-out. Dropping it leaves the stream; the source
/// stops after the last viewer.
pub(crate) struct H264Subscription {
    source: &'static H264Source,
    kind: H264Viewer,
    rx: broadcast::Receiver<H264Frame>,
}

impl H264Source {
    fn new(capacity: usize, keyframe: fn(&'static str)) -> Self {
        Self {
            fanout: StreamFanout::new(capacity),
            direct: AtomicUsize::new(0),
            webrtc: AtomicUsize::new(0),
            keyframe,
        }
    }

    fn counter(&self, kind: H264Viewer) -> &AtomicUsize {
        match kind {
            H264Viewer::Direct => &self.direct,
            H264Viewer::WebRtc => &self.webrtc,
        }
    }

    /// Join the stream; `start` runs the producer when none is running.
    fn subscribe(&'static self, kind: H264Viewer, start: impl FnOnce()) -> H264Subscription {
        self.fanout.clients.fetch_add(1, Ordering::AcqRel);
        self.counter(kind).fetch_add(1, Ordering::AcqRel);
        let rx = self.fanout.subscribe();
        if self
            .fanout
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            start();
        } else {
            (self.keyframe)("new h264 viewer");
        }
        H264Subscription {
            source: self,
            kind,
            rx,
        }
    }

    /// The capture status labels to report to: the UI shows one per viewer
    /// mode, and both kinds may be watching the one source.
    fn status_modes(&self) -> (&'static str, Option<&'static str>) {
        let direct = self.direct.load(Ordering::Acquire) > 0;
        let webrtc = self.webrtc.load(Ordering::Acquire) > 0;
        match (direct, webrtc) {
            (true, true) => (CAPTURE_MODE_H264, Some(CAPTURE_MODE_DIRECT)),
            (false, true) => (CAPTURE_MODE_H264, None),
            _ => (CAPTURE_MODE_DIRECT, None),
        }
    }
}

impl H264Subscription {
    /// The next frame, or `None` once the source is gone. Lost frames leave
    /// the decoder without its references: ask for a keyframe and go on with
    /// the newest frames rather than stopping.
    pub(crate) async fn recv(&mut self) -> Option<H264Frame> {
        loop {
            match self.rx.recv().await {
                Ok(frame) => return Some(frame),
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    (self.source.keyframe)("h264 viewer lagged");
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl Drop for H264Subscription {
    fn drop(&mut self) {
        self.source
            .counter(self.kind)
            .fetch_sub(1, Ordering::AcqRel);
        self.source.fanout.clients.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Join the H.264 stream as a Direct or WebRTC viewer.
pub(crate) fn subscribe_h264(kind: H264Viewer) -> H264Subscription {
    H264_SOURCE.subscribe(kind, || {
        tokio::spawn(run_h264_source());
    })
}

#[derive(Debug, Clone, Copy)]
enum H264FailureRecovery {
    RequestKeyframe,
    DisableAndRestart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum H264DirectProducerAction {
    Capture,
    WaitForH264Mode,
    StopDisabled,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureStatus {
    ok: bool,
    result: i32,
    message: &'static str,
    mode: &'static str,
    severity: &'static str,
    updated_at: String,
}

#[derive(Default)]
struct CaptureStatusStore {
    latest_by_mode: HashMap<&'static str, CaptureStatus>,
}

struct StreamFanout<T> {
    clients: AtomicUsize,
    running: AtomicBool,
    tx: broadcast::Sender<T>,
}

struct ClientGuard<'a> {
    clients: &'a AtomicUsize,
}

impl<T: Clone> StreamFanout<T> {
    fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            clients: AtomicUsize::new(0),
            running: AtomicBool::new(false),
            tx,
        }
    }

    fn add_client(&self) -> ClientGuard<'_> {
        self.clients.fetch_add(1, Ordering::AcqRel);
        ClientGuard {
            clients: &self.clients,
        }
    }

    fn client_count(&self) -> usize {
        self.clients.load(Ordering::Acquire)
    }

    fn subscribe(&self) -> broadcast::Receiver<T> {
        self.tx.subscribe()
    }

    fn send(&self, frame: T) {
        let _ = self.tx.send(frame);
    }
}

impl Drop for ClientGuard<'_> {
    fn drop(&mut self) {
        self.clients.fetch_sub(1, Ordering::AcqRel);
    }
}

impl CaptureStatus {
    fn new(mode: &'static str, result: i32) -> Self {
        let (message, severity) = capture_result_message(result);
        Self {
            ok: result >= 0,
            result,
            message,
            mode,
            severity,
            updated_at: now_rfc3339(),
        }
    }
}

pub fn capture_status_snapshot() -> Vec<CaptureStatus> {
    let Ok(store) = CAPTURE_STATUS.lock() else {
        return Vec::new();
    };

    let mut modes: Vec<_> = store.latest_by_mode.keys().copied().collect();
    modes.sort_unstable();

    modes
        .into_iter()
        .filter_map(|mode| store.latest_by_mode.get(mode).cloned())
        .collect()
}

pub fn update_capture_status(mode: &'static str, result: i32) {
    let next = CaptureStatus::new(mode, result);

    let should_broadcast = {
        let Ok(mut store) = CAPTURE_STATUS.lock() else {
            return;
        };

        if store
            .latest_by_mode
            .get(mode)
            .is_some_and(|last| same_public_status(last, &next))
        {
            false
        } else {
            store.latest_by_mode.insert(mode, next.clone());
            true
        }
    };

    if should_broadcast {
        broadcast_capture_status(&next);
    }
}

/// Report the latest status of `from` under `to` as well: one H.264 source
/// serves both viewer modes.
fn mirror_capture_status(from: &'static str, to: &'static str) {
    let result = {
        let Ok(store) = CAPTURE_STATUS.lock() else {
            return;
        };
        store.latest_by_mode.get(from).map(|status| status.result)
    };
    if let Some(result) = result {
        update_capture_status(to, result);
    }
}

pub fn broadcast_capture_status(status: &CaptureStatus) {
    match serde_json::to_string(status) {
        Ok(data) => hid_ws::broadcast_event(CAPTURE_STATUS_EVENT, &data),
        Err(err) => warn!(error = ?err, "failed to serialize capture status"),
    }
}

fn same_public_status(a: &CaptureStatus, b: &CaptureStatus) -> bool {
    if a.ok && b.ok {
        return true;
    }

    a.ok == b.ok && a.result == b.result && a.mode == b.mode
}

fn capture_result_message(result: i32) -> (&'static str, &'static str) {
    match result {
        -7 => ("HDMI input resolution error", CAPTURE_SEVERITY_ERROR),
        -6 => ("Unsupported HDMI resolution", CAPTURE_SEVERITY_ERROR),
        -5 => ("Retrieving image", CAPTURE_SEVERITY_WARNING),
        -4 => ("Changing image resolution", CAPTURE_SEVERITY_WARNING),
        -3 => ("Image buffer full", CAPTURE_SEVERITY_ERROR),
        -2 => ("Encoder error", CAPTURE_SEVERITY_ERROR),
        -1 => ("No image captured", CAPTURE_SEVERITY_ERROR),
        -8 => (
            "H.264 disabled after encoder failure",
            CAPTURE_SEVERITY_ERROR,
        ),
        value if value < 0 => ("Capture failed", CAPTURE_SEVERITY_ERROR),
        _ => ("", ""),
    }
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

impl Default for Screen {
    fn default() -> Self {
        let mut screen = Self {
            mode: StreamMode::Mjpeg,
            width: 0,
            height: 0,
            fps: 30,
            quality: 80,
            bit_rate: 3000,
            gop: 30,
        };

        if matches!(read_trimmed(SCREEN_TYPE_FILE).as_deref(), Some("h264")) {
            screen.mode = StreamMode::H264;
        }
        if let Some(value) = read_i32(SCREEN_RESOLUTION_FILE) {
            apply_resolution(&mut screen, value);
        }
        if let Some(value) = read_i32(SCREEN_QUALITY_FILE) {
            apply_quality(&mut screen, value);
        }
        if let Some(value) = read_i32(SCREEN_FPS_FILE) {
            screen.fps = validate_fps(value);
        }
        if let Some(value) = read_i32(SCREEN_GOP_FILE).and_then(|value| u8::try_from(value).ok()) {
            if (1..=100).contains(&value) {
                screen.gop = value;
            }
        }

        screen
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateFrameDetectReq {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct StopFrameDetectReq {
    pub duration: Option<u64>,
}

pub async fn mjpeg_stream(
    State(state): State<AppState>,
    current: Option<Extension<CurrentSession>>,
) -> Result<impl IntoResponse> {
    let session = TransportSession::capture(&state.config, current)?;
    let stream = stream! {
        if !session.is_active() {
            return;
        }
        let guard = MJPEG_FANOUT.add_client();
        let rx = MJPEG_FANOUT.subscribe();
        start_mjpeg_producer();
        let chunks = mjpeg_chunks(rx, session, guard);
        tokio::pin!(chunks);
        while let Some(chunk) = futures_util::StreamExt::next(&mut chunks).await {
            yield chunk;
        }
    };

    Ok(Response::builder()
        .header(
            header::CONTENT_TYPE,
            "multipart/x-mixed-replace; boundary=frame",
        )
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .header(header::PRAGMA, "no-cache")
        .body(Body::from_stream(stream))
        .expect("mjpeg response builder"))
}

fn mjpeg_chunks<'a>(
    mut rx: broadcast::Receiver<MjpegFrame>,
    session: TransportSession,
    guard: ClientGuard<'a>,
) -> impl futures_util::Stream<Item = std::result::Result<Bytes, io::Error>> + 'a {
    stream! {
        let _guard = guard;
        'frames: loop {
            let frame = tokio::select! {
                biased;
                _ = session.ended() => break,
                frame = rx.recv() => match frame {
                    Ok(frame) => frame,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            };
            for chunk in [frame.header, frame.data, Bytes::from_static(b"\r\n")] {
                if !session.is_active() {
                    break 'frames;
                }
                yield Ok::<Bytes, io::Error>(chunk);
            }
        }
    }
}

pub async fn h264_direct_stream(
    State(state): State<AppState>,
    current: Option<Extension<CurrentSession>>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    let session = TransportSession::capture(&state.config, current)?;
    if !validate_ws_origin(&headers, &state.config) {
        return Err(AppError::Forbidden("invalid websocket origin".to_string()));
    }

    Ok(ws.on_upgrade(move |socket| handle_h264_direct_socket(socket, session)))
}

async fn handle_h264_direct_socket(socket: WebSocket, session: TransportSession) {
    if !session.is_active() {
        return;
    }
    let subscription = subscribe_h264(H264Viewer::Direct);
    h264_client(socket, subscription, session).await;
}

async fn h264_client(
    mut socket: WebSocket,
    mut subscription: H264Subscription,
    session: TransportSession,
) {
    loop {
        let frame = tokio::select! {
            biased;
            _ = session.ended() => break,
            frame = subscription.recv() => match frame {
                Some(frame) => frame,
                None => break,
            },
        };
        let sent = tokio::select! {
            biased;
            _ = session.ended() => break,
            sent = socket.send(Message::Binary(frame.packet)) => sent,
        };
        if sent.is_err() {
            break;
        }
    }
    let _ = time::timeout(Duration::from_millis(250), socket.close()).await;
}

fn start_mjpeg_producer() {
    if MJPEG_FANOUT
        .running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        tokio::spawn(run_mjpeg_producer());
    }
}

async fn run_mjpeg_producer() {
    struct RunningGuard(&'static AtomicBool);
    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _guard = RunningGuard(&MJPEG_FANOUT.running);

    let mut fps = current_screen().fps;
    let mut interval = frame_interval(fps);
    let mut consecutive_failures = 0usize;

    loop {
        interval.tick().await;
        if MJPEG_FANOUT.client_count() == 0 {
            return;
        }

        let screen = current_screen();
        if screen.fps != fps {
            fps = screen.fps;
            interval = frame_interval(fps);
        }
        if screen.mode != StreamMode::Mjpeg {
            continue;
        }

        if !MJPEG_FIRST_READ_LOGGED.swap(true, Ordering::Relaxed) {
            info!(
                width = screen.width,
                height = screen.height,
                quality = screen.quality,
                "reading first mjpeg frame"
            );
        }
        let frame = tokio::task::spawn_blocking(move || {
            kvm::read_mjpeg(screen.width, screen.height, screen.quality)
        })
        .await;

        let (data, result) = match frame {
            Ok(Ok(frame)) => frame,
            Ok(Err(err)) => {
                update_capture_status(CAPTURE_MODE_MJPEG, -1);
                if !MJPEG_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                    warn!(error = ?err, "failed to read mjpeg frame");
                }
                backoff_after_mjpeg_failure(&mut consecutive_failures, -1, 0).await;
                continue;
            }
            Err(err) => {
                update_capture_status(CAPTURE_MODE_MJPEG, -1);
                if !MJPEG_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                    warn!(error = ?err, "mjpeg frame task failed");
                }
                backoff_after_mjpeg_failure(&mut consecutive_failures, -1, 0).await;
                continue;
            }
        };
        update_capture_status(CAPTURE_MODE_MJPEG, result);
        match classify_mjpeg_read(result, data.len()) {
            MjpegRead::Frame => {}
            // The capture works and the screen is still: nothing to send, and
            // no backoff that would stall the stream once the screen changes.
            // The next read waits for the next camera frame.
            MjpegRead::Unchanged => {
                consecutive_failures = 0;
                continue;
            }
            MjpegRead::Failure => {
                if !MJPEG_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                    warn!(result, bytes = data.len(), "mjpeg frame unavailable");
                }
                backoff_after_mjpeg_failure(&mut consecutive_failures, result, data.len()).await;
                continue;
            }
        }
        consecutive_failures = 0;
        if !MJPEG_FIRST_SUCCESS_LOGGED.swap(true, Ordering::Relaxed) {
            info!(result, bytes = data.len(), "read first mjpeg frame");
        }
        set_latest_mjpeg_frame(&data, screen.width, screen.height);

        let header = Bytes::from(format!(
            "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
            data.len()
        ));
        MJPEG_FANOUT.send(MjpegFrame {
            header,
            data: Bytes::from(data),
        });
    }
}

#[derive(Debug, PartialEq, Eq)]
enum MjpegRead {
    Frame,
    Unchanged,
    Failure,
}

fn classify_mjpeg_read(result: i32, bytes: usize) -> MjpegRead {
    if result == MJPEG_FRAME_UNCHANGED {
        MjpegRead::Unchanged
    } else if result < 0 || bytes == 0 {
        MjpegRead::Failure
    } else {
        MjpegRead::Frame
    }
}

async fn backoff_after_mjpeg_failure(consecutive_failures: &mut usize, result: i32, bytes: usize) {
    *consecutive_failures += 1;
    let delay = if *consecutive_failures >= MJPEG_FAILURE_LIMIT {
        MJPEG_FAILURE_COOLDOWN
    } else {
        MJPEG_FAILURE_BACKOFF
    };

    warn!(
        failures = *consecutive_failures,
        result,
        bytes,
        delay_ms = delay.as_millis() as u64,
        "mjpeg capture failure backoff"
    );
    time::sleep(delay).await;
}

async fn run_h264_source() {
    struct RunningGuard(&'static AtomicBool);
    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _guard = RunningGuard(&H264_SOURCE.fanout.running);
    pump_h264_frames(&H264_SOURCE, h264_source_step, |screen| async move {
        let (mode, mirror) = H264_SOURCE.status_modes();
        let frame = read_h264_capture_frame(mode, screen).await;
        if let Some(other) = mirror {
            mirror_capture_status(mode, other);
        }
        frame
    })
    .await;
}

fn h264_failure_backoff(failures: usize) -> Duration {
    if failures >= H264_FAILURE_LIMIT {
        H264_FAILURE_COOLDOWN
    } else {
        H264_FAILURE_BACKOFF
    }
}

fn h264_source_step() -> H264SourceStep {
    let screen = current_screen();
    match h264_direct_producer_action(screen.mode, h264_capture_disabled()) {
        H264DirectProducerAction::StopDisabled => H264SourceStep::Stop,
        H264DirectProducerAction::WaitForH264Mode => H264SourceStep::Wait(screen.fps),
        H264DirectProducerAction::Capture => H264SourceStep::Capture(H264Screen {
            width: screen.width,
            height: screen.height,
            fps: screen.fps.max(1),
            bit_rate: screen.bit_rate,
        }),
    }
}

/// Read frames at the screen's rate while the source has viewers and send
/// each one to all of them. Returns when the last viewer leaves or H.264
/// capture is disabled.
async fn pump_h264_frames<R, F>(
    source: &H264Source,
    mut step: impl FnMut() -> H264SourceStep,
    mut read: R,
) where
    R: FnMut(H264Screen) -> F,
    F: Future<Output = Option<(Vec<u8>, i32)>>,
{
    let start = Instant::now();
    let mut fps = 0;
    let mut failures = 0usize;
    let mut interval = frame_interval(30);
    let retune = |wanted: u64, fps: &mut u64, interval: &mut time::Interval| {
        if wanted != *fps {
            *fps = wanted;
            *interval = frame_interval(wanted);
        }
    };

    loop {
        interval.tick().await;
        if source.fanout.client_count() == 0 {
            return;
        }
        let screen = match step() {
            H264SourceStep::Stop => {
                update_capture_status(CAPTURE_MODE_DIRECT, -8);
                update_capture_status(CAPTURE_MODE_H264, -8);
                return;
            }
            H264SourceStep::Wait(wanted) => {
                retune(wanted, &mut fps, &mut interval);
                continue;
            }
            H264SourceStep::Capture(screen) => screen,
        };
        retune(screen.fps, &mut fps, &mut interval);
        if !H264_DIRECT_FIRST_READ_LOGGED.swap(true, Ordering::Relaxed) {
            info!(
                width = screen.width,
                height = screen.height,
                bit_rate = screen.bit_rate,
                "reading first h264 frame"
            );
        }

        let Some((data, result)) = read(screen).await else {
            if !H264_DIRECT_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                warn!("h264 frame unavailable");
            }
            failures += 1;
            time::sleep(h264_failure_backoff(failures)).await;
            continue;
        };
        failures = 0;

        if !H264_DIRECT_FIRST_SUCCESS_LOGGED.swap(true, Ordering::Relaxed) {
            info!(result, bytes = data.len(), "read first h264 frame");
        }

        let timestamp = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let packet = Bytes::from(h264_direct_packet(result == 3, timestamp, &data));
        source.fanout.send(H264Frame {
            data: packet.slice(H264_DIRECT_HEADER..),
            packet,
        });
    }
}

fn h264_direct_producer_action(
    mode: StreamMode,
    capture_disabled: bool,
) -> H264DirectProducerAction {
    if capture_disabled {
        H264DirectProducerAction::StopDisabled
    } else if mode == StreamMode::H264 {
        H264DirectProducerAction::Capture
    } else {
        /* Another client can temporarily select MJPEG while this Direct
         * websocket remains open.  Keep its producer alive so it resumes on
         * the same socket when H.264 is selected again. */
        H264DirectProducerAction::WaitForH264Mode
    }
}

pub async fn update_frame_detect(
    Json(req): Json<UpdateFrameDetectReq>,
) -> Result<impl IntoResponse> {
    let frame = if req.enabled {
        FRAME_DETECT_INTERVAL
    } else {
        0
    };
    libkvm(move || frame_detect()?.configure(frame, kvm::set_frame_detect)).await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn stop_frame_detect(Json(req): Json<StopFrameDetectReq>) -> Result<impl IntoResponse> {
    let duration = Duration::from_secs(req.duration.unwrap_or(10).max(1).min(300));
    // The window ends at the user's setting, which a page load or another
    // browser may have changed meanwhile, not at the enabled interval.
    owned_interval(
        || frame_detect()?.stop_begin(kvm::set_frame_detect),
        duration,
        || frame_detect()?.stop_end(kvm::set_frame_detect),
    )
    .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

/// Run a libkvm call on a blocking thread. Its calls wait on the capture mutex
/// that frame reads hold, which would stall an async worker and with it HID,
/// video and every other request.
pub(crate) async fn libkvm<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| AppError::Internal("libkvm call failed".to_string()))?
}

/// Apply `first`, wait `hold`, then apply `then`, all in a task of its own, so
/// a lost client cannot leave the first state in place. A failed `first`
/// changed nothing and skips `then`.
pub(crate) async fn owned_interval<F, G>(first: F, hold: Duration, then: G) -> Result<()>
where
    F: FnOnce() -> Result<()> + Send + 'static,
    G: FnOnce() -> Result<()> + Send + 'static,
{
    let (reply, done) = oneshot::channel();
    tokio::spawn(async move {
        let result = async {
            libkvm(first).await?;
            time::sleep(hold).await;
            libkvm(then).await
        }
        .await;
        drop(reply.send(result));
    });
    done.await
        .map_err(|_| AppError::Internal("libkvm interval ended without a result".to_string()))?
}

pub fn set_screen_value(kind: &str, value: i32) -> Result<()> {
    let mut screen = SCREEN
        .lock()
        .map_err(|_| AppError::Internal("screen lock poisoned".to_string()))?;

    match kind {
        "type" => {
            if value == 0 {
                write_screen_file(SCREEN_TYPE_FILE, "mjpeg")?;
                screen.mode = StreamMode::Mjpeg;
            } else {
                clear_h264_safe_mode();
                write_screen_file(SCREEN_TYPE_FILE, "h264")?;
                screen.mode = StreamMode::H264;
            }
        }
        "resolution" => {
            apply_resolution(&mut screen, value);
            write_screen_file(SCREEN_RESOLUTION_FILE, &value.to_string())?;
        }
        "quality" => {
            apply_quality(&mut screen, value);
            write_screen_file(SCREEN_QUALITY_FILE, &value.to_string())?;
        }
        "fps" => {
            screen.fps = validate_fps(value);
            write_screen_file(SCREEN_FPS_FILE, &value.to_string())?;
        }
        "gop" => {
            let gop = u8::try_from(value).unwrap_or(30);
            let gop = if (1..=100).contains(&gop) { gop } else { 30 };
            screen.gop = gop;
            kvm::set_h264_gop(gop)?;
            write_screen_file(SCREEN_GOP_FILE, &gop.to_string())?;
        }
        _ => return Err(AppError::BadRequest(format!("invalid screen type {kind}"))),
    }

    Ok(())
}

fn write_screen_file(path: &str, value: &str) -> Result<()> {
    crate::system::files::write_atomic(std::path::Path::new(path), value.as_bytes(), 0o644)
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_i32(path: &str) -> Option<i32> {
    read_trimmed(path)?.parse().ok()
}

fn apply_resolution(screen: &mut Screen, value: i32) {
    let height = u16::try_from(value).unwrap_or_default();
    if let Some((width, height)) = capture_resolution(height) {
        screen.width = width;
        screen.height = height;
    }
}

fn apply_quality(screen: &mut Screen, value: i32) {
    let value = u16::try_from(value).unwrap_or_default();
    if value > 100 {
        screen.bit_rate = value;
    } else {
        screen.quality = value;
    }
}

fn current_screen() -> Screen {
    let mut screen = SCREEN.lock().expect("screen lock should not be poisoned");
    normalize_screen(&mut screen);
    *screen
}

pub fn current_h264_screen() -> H264Screen {
    let screen = current_screen();
    H264Screen {
        width: screen.width,
        height: screen.height,
        fps: screen.fps.max(1),
        bit_rate: screen.bit_rate,
    }
}

pub fn is_h264_capture_active() -> bool {
    let screen = current_screen();
    screen.mode == StreamMode::H264 && !h264_capture_disabled()
}

pub fn h264_capture_disabled() -> bool {
    H264_CAPTURE_DISABLED.load(Ordering::Acquire)
        || std::path::Path::new(H264_SAFE_MODE_FILE).exists()
}

pub fn request_h264_keyframe(reason: &'static str) {
    if h264_capture_disabled() {
        return;
    }
    {
        let mut last = H264_LAST_KEYFRAME_REQUEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        if !keyframe_request_due(*last, now) {
            return;
        }
        if H264_KEYFRAME_REQUEST_IN_PROGRESS
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        *last = Some(now);
    }

    let gop = current_screen().gop;
    std::thread::spawn(move || {
        info!(reason, gop, "requesting h264 keyframe");
        if let Err(err) = kvm::set_h264_gop(1) {
            warn!(reason, error = ?err, "failed to request h264 keyframe");
        }
        std::thread::sleep(H264_KEYFRAME_REQUEST_HOLD);
        if let Err(err) = kvm::set_h264_gop(gop) {
            warn!(reason, error = ?err, "failed to restore h264 gop after keyframe request");
        }
        H264_KEYFRAME_REQUEST_IN_PROGRESS.store(false, Ordering::Release);
    });
}

fn keyframe_request_due(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|last| now.saturating_duration_since(last) >= H264_KEYFRAME_REQUEST_INTERVAL)
}

pub async fn read_h264_capture_frame(
    mode: &'static str,
    screen: H264Screen,
) -> Option<(Vec<u8>, i32)> {
    if h264_capture_disabled() {
        update_capture_status(mode, -8);
        return None;
    }

    let task = tokio::task::spawn_blocking(move || {
        kvm::read_h264(screen.width, screen.height, screen.bit_rate)
    });

    let frame = match time::timeout(H264_READ_TIMEOUT, task).await {
        Ok(Ok(Ok(frame))) => frame,
        Ok(Ok(Err(err))) => {
            record_h264_failure(
                mode,
                "failed to read h264 frame",
                Some(err.to_string()),
                H264FailureRecovery::DisableAndRestart,
            );
            return None;
        }
        Ok(Err(err)) => {
            record_h264_failure(
                mode,
                "h264 frame task failed",
                Some(err.to_string()),
                H264FailureRecovery::DisableAndRestart,
            );
            return None;
        }
        Err(_) => {
            disable_h264_capture(mode, "h264 frame read timed out", true);
            return None;
        }
    };

    let (data, result) = frame;
    update_capture_status(mode, result);
    if result < 0 || data.is_empty() {
        let recovery = if result == -2 {
            H264FailureRecovery::DisableAndRestart
        } else {
            H264FailureRecovery::RequestKeyframe
        };
        record_h264_failure(
            mode,
            "h264 frame unavailable",
            Some(format!("result={result} bytes={}", data.len())),
            recovery,
        );
        return None;
    }

    H264_CONSECUTIVE_FAILURES.store(0, Ordering::Release);
    H264_OUTAGE_LOGGED.store(false, Ordering::Release);
    Some((data, result))
}

pub fn current_mjpeg_screen() -> MjpegScreen {
    let screen = current_screen();
    MjpegScreen {
        width: screen.width,
        height: screen.height,
        quality: screen.quality,
    }
}

fn record_h264_failure(
    mode: &'static str,
    reason: &'static str,
    detail: Option<String>,
    recovery: H264FailureRecovery,
) {
    update_capture_status(mode, -1);
    let failures = H264_CONSECUTIVE_FAILURES.fetch_add(1, Ordering::AcqRel) + 1;
    // One line per outage, the rest at debug: a lost HDMI input must not write
    // a line per frame to the tmpfs log.
    if !H264_OUTAGE_LOGGED.swap(true, Ordering::AcqRel) {
        warn!(mode, failures, detail = ?detail, reason, "h264 capture failure");
    } else {
        debug!(mode, failures, detail = ?detail, reason, "h264 capture failure");
    }

    if failures >= H264_FAILURE_LIMIT {
        match recovery {
            H264FailureRecovery::RequestKeyframe => {
                H264_CONSECUTIVE_FAILURES.store(0, Ordering::Release);
                request_h264_keyframe(reason);
            }
            H264FailureRecovery::DisableAndRestart => disable_h264_capture(mode, reason, true),
        }
    }
}

fn disable_h264_capture(mode: &'static str, reason: &'static str, restart: bool) {
    H264_CAPTURE_DISABLED.store(true, Ordering::Release);
    H264_CONSECUTIVE_FAILURES.store(0, Ordering::Release);
    update_capture_status(mode, -8);

    let _ = write_screen_file(SCREEN_TYPE_FILE, "mjpeg");
    if let Ok(mut screen) = SCREEN.lock() {
        screen.mode = StreamMode::Mjpeg;
    }
    if let Some(parent) = std::path::Path::new(H264_SAFE_MODE_FILE).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(H264_SAFE_MODE_FILE, format!("{reason}\n"));

    warn!(mode, reason, "disabled h264 capture and switched to mjpeg");

    if restart {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(250));
            std::process::exit(75);
        });
    }
}

fn clear_h264_safe_mode() {
    H264_CAPTURE_DISABLED.store(false, Ordering::Release);
    H264_CONSECUTIVE_FAILURES.store(0, Ordering::Release);
    let _ = fs::remove_file(H264_SAFE_MODE_FILE);
}

pub fn latest_mjpeg_frame(max_age: Duration) -> Option<LatestMjpegFrame> {
    let frame = LATEST_MJPEG_FRAME.lock().ok()?.clone()?;
    (frame.captured_at.elapsed() <= max_age).then_some(frame)
}

impl LatestMjpegFrame {
    /// A frame read just now, outside the MJPEG producer.
    pub(crate) fn captured_now(data: Vec<u8>, width: u16, height: u16) -> Self {
        Self {
            data,
            width,
            height,
            captured_at: Instant::now(),
        }
    }
}

/// The MJPEG encoder is the one in use. A direct MJPEG read is safe then; in
/// H.264 mode it would recreate the encoder under a running stream.
pub fn is_mjpeg_mode() -> bool {
    current_screen().mode == StreamMode::Mjpeg
}

pub fn h264_frame_duration(fps: u64) -> Duration {
    Duration::from_millis((1000 / fps.max(1)).max(1))
}

fn set_latest_mjpeg_frame(data: &[u8], width: u16, height: u16) {
    if let Ok(mut frame) = LATEST_MJPEG_FRAME.lock() {
        *frame = Some(LatestMjpegFrame {
            data: data.to_vec(),
            width,
            height,
            captured_at: Instant::now(),
        });
    }
}

fn normalize_screen(screen: &mut Screen) {
    if let Some((width, height)) = capture_resolution(screen.height) {
        screen.width = width;
        screen.height = height;
    } else {
        screen.width = 1920;
        screen.height = 1080;
    }
    if !matches!(screen.quality, 50 | 60 | 80 | 100) {
        screen.quality = 80;
    }
    if !matches!(screen.bit_rate, 1000 | 2000 | 3000 | 5000) {
        screen.bit_rate = 3000;
    }
}

fn frame_interval(fps: u64) -> time::Interval {
    let mut interval = time::interval(h264_frame_duration(fps));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval
}

fn capture_resolution(height: u16) -> Option<(u16, u16)> {
    match height {
        // Avoid passing 0x0 to libkvm. The Go backend lets the native layer
        // resolve "auto", but H.264 capture can abort the Rust process on 0x0.
        0 => Some((1920, 1080)),
        1080 => Some((1920, 1080)),
        720 => Some((1280, 720)),
        600 => Some((800, 600)),
        480 => Some((640, 480)),
        _ => None,
    }
}

fn validate_fps(fps: i32) -> u64 {
    fps.clamp(10, 60) as u64
}

/// The Direct websocket framing: a keyframe flag and a timestamp before the
/// Annex B data.
const H264_DIRECT_HEADER: usize = 1 + 8;

fn h264_direct_packet(is_keyframe: bool, timestamp_micros: u64, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(H264_DIRECT_HEADER + data.len());
    packet.push(u8::from(is_keyframe));
    packet.extend_from_slice(&timestamp_micros.to_le_bytes());
    packet.extend_from_slice(data);
    packet
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    fn recorder(applied: &RefCell<Vec<u8>>) -> impl Fn(u8) -> super::Result<()> + '_ {
        move |frame| {
            applied.borrow_mut().push(frame);
            Ok(())
        }
    }

    #[test]
    fn a_stop_window_ends_at_the_configured_interval() {
        use super::{FRAME_DETECT_INTERVAL, FrameDetect};
        let applied = RefCell::new(Vec::new());
        let record = recorder(&applied);
        let mut state = FrameDetect {
            configured: 0,
            windows: 0,
        };
        state.configure(0, &record).unwrap();
        state.stop_begin(&record).unwrap();
        state.stop_end(&record).unwrap();
        assert_eq!(
            *applied.borrow(),
            [0, 0, 0],
            "a disabled choice stays disabled"
        );
        state.configure(FRAME_DETECT_INTERVAL, &record).unwrap();
        state.stop_begin(&record).unwrap();
        state.stop_end(&record).unwrap();
        assert_eq!(
            applied.borrow()[3..],
            [FRAME_DETECT_INTERVAL, 0, FRAME_DETECT_INTERVAL]
        );
    }

    #[test]
    fn a_choice_made_inside_a_window_waits_for_its_end() {
        use super::{FRAME_DETECT_INTERVAL, FrameDetect};
        let applied = RefCell::new(Vec::new());
        let record = recorder(&applied);
        let mut state = FrameDetect {
            configured: 0,
            windows: 0,
        };
        state.stop_begin(&record).unwrap();
        state.configure(FRAME_DETECT_INTERVAL, &record).unwrap();
        assert_eq!(*applied.borrow(), [0], "the page's pause is not cut short");
        assert_eq!(state.configured, FRAME_DETECT_INTERVAL);
        state.stop_end(&record).unwrap();
        assert_eq!(*applied.borrow(), [0, FRAME_DETECT_INTERVAL]);
        state.stop_begin(&record).unwrap();
        state.configure(0, &record).unwrap();
        state.stop_end(&record).unwrap();
        assert_eq!(applied.borrow()[2..], [0, 0]);
    }

    #[test]
    fn overlapping_windows_end_together() {
        use super::{FRAME_DETECT_INTERVAL, FrameDetect};
        let applied = RefCell::new(Vec::new());
        let record = recorder(&applied);
        let mut state = FrameDetect {
            configured: 0,
            windows: 0,
        };
        state.configure(FRAME_DETECT_INTERVAL, &record).unwrap();
        state.stop_begin(&record).unwrap();
        state.stop_begin(&record).unwrap();
        state.stop_end(&record).unwrap();
        assert_eq!(
            *applied.borrow(),
            [FRAME_DETECT_INTERVAL, 0],
            "one window still holds"
        );
        state.stop_end(&record).unwrap();
        assert_eq!(
            *applied.borrow(),
            [FRAME_DETECT_INTERVAL, 0, FRAME_DETECT_INTERVAL]
        );
    }

    #[test]
    fn a_failed_stop_opens_no_window() {
        use super::{AppError, FRAME_DETECT_INTERVAL, FrameDetect};
        let applied = RefCell::new(Vec::new());
        let record = recorder(&applied);
        let fail = |_: u8| -> super::Result<()> { Err(AppError::Internal("libkvm".to_string())) };
        let mut state = FrameDetect {
            configured: 0,
            windows: 0,
        };
        assert!(state.stop_begin(fail).is_err());
        assert_eq!(state.windows, 0);
        state.configure(FRAME_DETECT_INTERVAL, &record).unwrap();
        assert_eq!(
            *applied.borrow(),
            [FRAME_DETECT_INTERVAL],
            "applied at once: no window is open"
        );
    }

    #[test]
    fn keyframe_requests_are_spaced_by_their_interval() {
        use super::{H264_KEYFRAME_REQUEST_INTERVAL, keyframe_request_due};
        use std::time::{Duration, Instant};
        let now = Instant::now();
        assert!(keyframe_request_due(None, now));
        // A PLI/FIR flood inside the interval gets no further keyframes.
        for gap in [0, 125, 500, 999] {
            let last = now.checked_sub(Duration::from_millis(gap));
            if last.is_some() {
                assert!(!keyframe_request_due(last, now), "{gap} ms");
            }
        }
        if let Some(last) = now.checked_sub(H264_KEYFRAME_REQUEST_INTERVAL) {
            assert!(keyframe_request_due(Some(last), now));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_interval_restores_its_state_after_a_lost_client() {
        use super::{AppError, owned_interval};
        use std::sync::{
            Arc,
            atomic::{AtomicU8, Ordering},
        };
        use std::time::Duration;
        let state = Arc::new(AtomicU8::new(0));
        let request = tokio::spawn({
            let (first, then) = (Arc::clone(&state), Arc::clone(&state));
            owned_interval(
                move || {
                    first.store(1, Ordering::SeqCst);
                    Ok(())
                },
                Duration::from_millis(200),
                move || {
                    then.store(2, Ordering::SeqCst);
                    Ok(())
                },
            )
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(state.load(Ordering::SeqCst), 1);
        // The HTTP handler's future is dropped when its client goes away.
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(state.load(Ordering::SeqCst), 2);
        // A failed first step changes nothing, so the second never runs.
        let untouched = Arc::new(AtomicU8::new(0));
        let then = Arc::clone(&untouched);
        let failed = owned_interval(
            || Err(AppError::Internal("synthetic".into())),
            Duration::from_millis(1),
            move || {
                then.store(2, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(failed.is_err());
        assert_eq!(untouched.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_unchanged_mjpeg_frame_is_neither_sent_nor_a_failure() {
        use super::{MJPEG_FRAME_UNCHANGED, MjpegRead, classify_mjpeg_read};
        // Frame detection reports a still screen as 5, with or without bytes.
        assert_eq!(
            classify_mjpeg_read(MJPEG_FRAME_UNCHANGED, 0),
            MjpegRead::Unchanged
        );
        assert_eq!(
            classify_mjpeg_read(MJPEG_FRAME_UNCHANGED, 4096),
            MjpegRead::Unchanged
        );
        assert_eq!(classify_mjpeg_read(0, 4096), MjpegRead::Frame);
        assert_eq!(classify_mjpeg_read(0, 0), MjpegRead::Failure);
        for result in [-1, -2, -3] {
            assert_eq!(classify_mjpeg_read(result, 4096), MjpegRead::Failure);
        }
    }

    use super::{
        H264DirectProducerAction, Screen, StreamMode, h264_direct_packet,
        h264_direct_producer_action, normalize_screen,
    };

    #[test]
    fn default_screen_matches_go_auto_resolution_when_unconfigured() {
        let screen = Screen::default();

        assert!(matches!(screen.mode, StreamMode::Mjpeg | StreamMode::H264));
        assert!(matches!(screen.height, 0 | 480 | 600 | 720 | 1080));
    }

    #[test]
    fn auto_resolution_uses_safe_native_capture_size() {
        let mut screen = Screen {
            mode: StreamMode::Mjpeg,
            width: 0,
            height: 0,
            fps: 30,
            quality: 80,
            bit_rate: 3000,
            gop: 30,
        };
        normalize_screen(&mut screen);

        assert_eq!(screen.width, 1920);
        assert_eq!(screen.height, 1080);
    }

    #[test]
    fn unsupported_resolution_falls_back_to_native_capture_size() {
        let mut screen = Screen {
            mode: StreamMode::Mjpeg,
            width: 123,
            height: 999,
            fps: 30,
            quality: 80,
            bit_rate: 3000,
            gop: 30,
        };

        normalize_screen(&mut screen);

        assert_eq!(screen.width, 1920);
        assert_eq!(screen.height, 1080);
    }

    #[test]
    fn h264_direct_packet_matches_frontend_format() {
        let packet = h264_direct_packet(true, 0x0102_0304_0506_0708, &[0xaa, 0xbb]);

        assert_eq!(packet[0], 1);
        assert_eq!(
            &packet[1..9],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(&packet[9..], &[0xaa, 0xbb]);
    }

    use super::{H264Screen, H264Source, H264SourceStep, H264Viewer, pump_h264_frames};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    static KEYFRAME_REQUESTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    fn record_keyframe_request(reason: &'static str) {
        KEYFRAME_REQUESTS.lock().unwrap().push(reason);
    }
    fn keyframe_requests() -> Vec<&'static str> {
        KEYFRAME_REQUESTS.lock().unwrap().clone()
    }

    const SCREEN: H264Screen = H264Screen {
        width: 1280,
        height: 720,
        fps: 200,
        bit_rate: 3000,
    };

    /// A source whose reads deliver numbered frames and count themselves.
    struct Fake {
        source: &'static H264Source,
        reads: Arc<AtomicUsize>,
    }
    fn fake(capacity: usize) -> Fake {
        Fake {
            source: Box::leak(Box::new(H264Source::new(capacity, record_keyframe_request))),
            reads: Arc::new(AtomicUsize::new(0)),
        }
    }
    impl Fake {
        fn run(&self) -> tokio::task::JoinHandle<()> {
            let source = self.source;
            let reads = Arc::clone(&self.reads);
            tokio::spawn(async move {
                pump_h264_frames(
                    source,
                    || H264SourceStep::Capture(SCREEN),
                    move |_| {
                        let index = reads.fetch_add(1, Ordering::SeqCst);
                        async move {
                            tokio::time::sleep(Duration::from_millis(2)).await;
                            Some((vec![index as u8], if index == 0 { 3 } else { 4 }))
                        }
                    },
                )
                .await;
            })
        }
    }
    async fn collect(subscription: &mut super::H264Subscription, count: usize) -> Vec<u8> {
        let mut seen = Vec::new();
        while seen.len() < count {
            let frame = tokio::time::timeout(Duration::from_secs(5), subscription.recv())
                .await
                .expect("a frame in time")
                .expect("the source is alive");
            seen.push(frame.data[0]);
        }
        seen
    }

    #[tokio::test]
    async fn every_viewer_gets_every_frame_of_the_one_source() {
        let fake = fake(8);
        let mut direct = fake.source.subscribe(H264Viewer::Direct, || {});
        let mut webrtc = fake.source.subscribe(H264Viewer::WebRtc, || {});
        let pump = fake.run();
        let (a, b) = tokio::join!(collect(&mut direct, 20), collect(&mut webrtc, 20));
        let expected: Vec<u8> = (0..20).collect();
        assert_eq!(a, expected, "the Direct viewer missed frames");
        assert_eq!(b, expected, "the WebRTC viewer missed frames");
        // One read per frame: the viewers did not split the sequence.
        assert_eq!(fake.reads.load(Ordering::SeqCst).min(20), 20);
        assert!(
            !pump.is_finished(),
            "the source stopped while it had viewers"
        );
        drop(direct);
        drop(webrtc);
        tokio::time::timeout(Duration::from_secs(5), pump)
            .await
            .expect("the source stops after its last viewer")
            .unwrap();
    }

    #[tokio::test]
    async fn a_viewer_joining_a_running_source_asks_for_a_keyframe() {
        let fake = fake(8);
        let started = Arc::new(AtomicUsize::new(0));
        let first = {
            let started = Arc::clone(&started);
            fake.source.subscribe(H264Viewer::Direct, move || {
                started.fetch_add(1, Ordering::SeqCst);
            })
        };
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "the first viewer starts the source"
        );
        let before = keyframe_requests().len();
        let second = fake.source.subscribe(H264Viewer::WebRtc, || {
            panic!("a second viewer must not start another producer")
        });
        let requests = keyframe_requests();
        assert_eq!(requests.len(), before + 1);
        assert_eq!(requests[before], "new h264 viewer");
        assert_eq!(
            fake.source.status_modes(),
            (super::CAPTURE_MODE_H264, Some(super::CAPTURE_MODE_DIRECT))
        );
        drop(second);
        assert_eq!(
            fake.source.status_modes(),
            (super::CAPTURE_MODE_DIRECT, None)
        );
        drop(first);
        assert_eq!(fake.source.fanout.client_count(), 0);
    }

    #[tokio::test]
    async fn a_lagging_viewer_asks_for_a_keyframe_and_goes_on_with_newer_frames() {
        let fake = fake(2);
        let mut slow = fake.source.subscribe(H264Viewer::Direct, || {});
        let pump = fake.run();
        // Let the source overrun the two-frame channel.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let before = keyframe_requests().len();
        let frame = tokio::time::timeout(Duration::from_secs(5), slow.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            frame.data[0] > 2,
            "the viewer did not skip to newer frames: {}",
            frame.data[0]
        );
        let requests = keyframe_requests();
        assert!(
            requests.len() > before,
            "no keyframe was requested after the lag"
        );
        assert_eq!(requests[before], "h264 viewer lagged");
        drop(slow);
        tokio::time::timeout(Duration::from_secs(5), pump)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_read_backs_off_instead_of_retrying_every_frame() {
        let fake = fake(8);
        let viewer = fake.source.subscribe(H264Viewer::Direct, || {});
        let reads = Arc::clone(&fake.reads);
        let source = fake.source;
        let pump = tokio::spawn(async move {
            pump_h264_frames(
                source,
                || H264SourceStep::Capture(SCREEN),
                move |_| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    async { None::<(Vec<u8>, i32)> }
                },
            )
            .await;
        });
        tokio::time::sleep(Duration::from_millis(1400)).await;
        // At 200 fps that would be about 280 reads. With the backoff: one at
        // once, two more 500 ms apart, then the 5 s cooldown.
        assert_eq!(fake.reads.load(Ordering::SeqCst), 3);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(fake.reads.load(Ordering::SeqCst), 4);
        drop(viewer);
        tokio::time::timeout(Duration::from_secs(10), pump)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn the_source_stops_when_capture_is_disabled_and_waits_in_mjpeg_mode() {
        let fake = fake(8);
        let viewer = fake.source.subscribe(H264Viewer::Direct, || {});
        let reads = Arc::clone(&fake.reads);
        let steps = Arc::new(Mutex::new(vec![
            H264SourceStep::Wait(100),
            H264SourceStep::Wait(100),
            H264SourceStep::Capture(SCREEN),
            H264SourceStep::Stop,
        ]));
        let source = fake.source;
        let pump = tokio::spawn(async move {
            let steps = Arc::clone(&steps);
            pump_h264_frames(
                source,
                move || {
                    let mut steps = steps.lock().unwrap();
                    if steps.len() > 1 {
                        steps.remove(0)
                    } else {
                        steps[0]
                    }
                },
                move |_| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    async { Some((vec![7], 3)) }
                },
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(5), pump)
            .await
            .expect("a disabled capture stops the source")
            .unwrap();
        // Two waits read nothing; one capture read once; then the stop.
        assert_eq!(fake.reads.load(Ordering::SeqCst), 1);
        drop(viewer);
    }

    #[test]
    fn h264_direct_waits_for_global_mode_and_resumes_on_same_socket() {
        assert_eq!(
            h264_direct_producer_action(StreamMode::Mjpeg, false),
            H264DirectProducerAction::WaitForH264Mode
        );
        assert_eq!(
            h264_direct_producer_action(StreamMode::H264, false),
            H264DirectProducerAction::Capture
        );
        assert_eq!(
            h264_direct_producer_action(StreamMode::H264, true),
            H264DirectProducerAction::StopDisabled
        );
    }
}
