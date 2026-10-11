use ::time::{OffsetDateTime, format_description::well_known::Rfc3339};
use async_stream::stream;
use axum::{
    Json,
    body::Body,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Response, header},
    response::IntoResponse,
};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs, io,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::broadcast,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};

use crate::{
    AppError, Result,
    api::direct_flow::{DirectFlow, MAX_CONTROL_BYTES, Offer, parse_control},
    error::ApiResponse,
    ffi::kvm,
    hdmi_idle,
    state::AppState,
    ws::{hid as hid_ws, origin::validate_ws_origin},
};

const FRAME_DETECT_INTERVAL: u8 = 60;
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
const H264_READ_TIMEOUT: Duration = Duration::from_secs(5);
const H264_FAILURE_LIMIT: usize = 3;
const H264_KEYFRAME_REQUEST_HOLD: Duration = Duration::from_millis(250);
const H264_LAG_KEYFRAME_INTERVAL: Duration = Duration::from_secs(1);
/// A direct stream socket that cannot take a frame in this long is closed, so one
/// stalled client cannot hold the others up. The player reconnects on its own.
const DIRECT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const DIRECT_PING_INTERVAL: Duration = Duration::from_secs(15);
/// A direct client that sends nothing, not even a pong, for this long is gone.
const DIRECT_READ_IDLE: Duration = Duration::from_secs(30);

static SCREEN: LazyLock<Mutex<Screen>> = LazyLock::new(|| Mutex::new(Screen::default()));
static LATEST_MJPEG_FRAME: LazyLock<Mutex<Option<LatestMjpegFrame>>> =
    LazyLock::new(|| Mutex::new(None));
static MJPEG_FANOUT: LazyLock<StreamFanout<MjpegFrame>> =
    LazyLock::new(|| StreamFanout::new("mjpeg", 4));
/// The single H.264 capture source. libkvm hands out each encoded frame once, so
/// the direct stream and the WebRTC sender must share one reader.
static H264_SOURCE: LazyLock<StreamFanout<H264Frame>> =
    LazyLock::new(|| StreamFanout::new("direct", 16));
static H264_DIRECT_CONSUMERS: AtomicUsize = AtomicUsize::new(0);
static H264_WEBRTC_CONSUMERS: AtomicUsize = AtomicUsize::new(0);
static MJPEG_FIRST_READ_LOGGED: AtomicBool = AtomicBool::new(false);
static MJPEG_FIRST_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static MJPEG_FIRST_ERROR_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_DIRECT_FIRST_READ_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_DIRECT_FIRST_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_DIRECT_FIRST_ERROR_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_CAPTURE_DISABLED: AtomicBool = AtomicBool::new(false);
static H264_CONSECUTIVE_FAILURES: AtomicUsize = AtomicUsize::new(0);
static H264_KEYFRAME_REQUEST_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
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

#[derive(Debug, Clone)]
pub struct H264Frame {
    pub data: Bytes,
    pub keyframe: bool,
    timestamp_micros: u64,
    /// Wire packet of the direct stream, built only while a direct client is connected.
    packet: Option<Bytes>,
}

impl H264Frame {
    fn direct_packet(&self) -> Bytes {
        self.packet.clone().unwrap_or_else(|| {
            Bytes::from(h264_direct_packet(
                self.keyframe,
                self.timestamp_micros,
                &self.data,
            ))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H264ConsumerKind {
    Direct,
    WebRtc,
}

impl H264ConsumerKind {
    fn counter(self) -> &'static AtomicUsize {
        match self {
            H264ConsumerKind::Direct => &H264_DIRECT_CONSUMERS,
            H264ConsumerKind::WebRtc => &H264_WEBRTC_CONSUMERS,
        }
    }
}

/// Lets a consumer join, or resume after a gap, only at a keyframe: frames that
/// follow a gap cannot be decoded and show as corruption until the next keyframe.
struct KeyframeGate {
    waiting: bool,
    last_request: Option<Instant>,
}

impl KeyframeGate {
    fn new() -> Self {
        Self {
            waiting: true,
            last_request: None,
        }
    }

    /// Records a gap and says whether a keyframe should be requested now. Requests
    /// are rate limited, because each one briefly raises the bit rate for everyone.
    fn on_gap(&mut self, now: Instant) -> bool {
        self.waiting = true;
        let due = self
            .last_request
            .is_none_or(|last| now.duration_since(last) >= H264_LAG_KEYFRAME_INTERVAL);
        if due {
            self.last_request = Some(now);
        }
        due
    }

    fn admit(&mut self, keyframe: bool) -> bool {
        if self.waiting {
            if !keyframe {
                return false;
            }
            self.waiting = false;
        }
        true
    }
}

/// A consumer of the shared H.264 source. Dropping it ends the subscription.
pub struct H264Subscription {
    rx: broadcast::Receiver<H264Frame>,
    gate: KeyframeGate,
    kind: H264ConsumerKind,
    _client: ClientGuard,
}

impl H264Subscription {
    /// The next frame this consumer can decode, or `None` once the source is gone.
    /// Frames after a gap are skipped until the next keyframe.
    pub async fn next(&mut self) -> Option<H264Frame> {
        loop {
            match self.rx.recv().await {
                Ok(frame) => {
                    if self.gate.admit(frame.keyframe) {
                        return Some(frame);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    debug!(skipped, "h264 consumer lagged; waiting for a keyframe");
                    if self.gate.on_gap(Instant::now()) {
                        request_h264_keyframe("h264 consumer lagged");
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

impl Drop for H264Subscription {
    fn drop(&mut self) {
        self.kind.counter().fetch_sub(1, Ordering::AcqRel);
    }
}

/// Subscribes to the shared H.264 source and starts it when it is not running.
pub fn subscribe_h264(kind: H264ConsumerKind) -> H264Subscription {
    kind.counter().fetch_add(1, Ordering::AcqRel);
    let client = H264_SOURCE.add_client();
    let rx = H264_SOURCE.subscribe();
    start_h264_source();
    request_h264_keyframe("h264 consumer connected");
    H264Subscription {
        rx,
        gate: KeyframeGate::new(),
        kind,
        _client: client,
    }
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
    source: &'static str,
    clients: AtomicUsize,
    running: AtomicBool,
    tx: broadcast::Sender<T>,
}

struct ClientGuard {
    source: &'static str,
    clients: &'static AtomicUsize,
}

impl<T: Clone> StreamFanout<T> {
    fn new(source: &'static str, capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            source,
            clients: AtomicUsize::new(0),
            running: AtomicBool::new(false),
            tx,
        }
    }

    fn add_client(&'static self) -> ClientGuard {
        let count = self.clients.fetch_add(1, Ordering::AcqRel) + 1;
        hdmi_idle::report_viewers(self.source, count);
        ClientGuard {
            source: self.source,
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

impl Drop for ClientGuard {
    fn drop(&mut self) {
        let count = self.clients.fetch_sub(1, Ordering::AcqRel) - 1;
        hdmi_idle::report_viewers(self.source, count);
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

pub async fn mjpeg_stream() -> impl IntoResponse {
    let stream = stream! {
        let _guard = MJPEG_FANOUT.add_client();
        let mut rx = MJPEG_FANOUT.subscribe();
        start_mjpeg_producer();

        loop {
            let frame = match rx.recv().await {
                Ok(frame) => frame,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            };
            yield Ok::<Bytes, io::Error>(frame.header);
            yield Ok::<Bytes, io::Error>(frame.data);
            yield Ok::<Bytes, io::Error>(Bytes::from_static(b"\r\n"));
        }
    };

    Response::builder()
        .header(
            header::CONTENT_TYPE,
            "multipart/x-mixed-replace; boundary=frame",
        )
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::CONNECTION, "keep-alive")
        .header(header::PRAGMA, "no-cache")
        .body(Body::from_stream(stream))
        .expect("mjpeg response builder")
}

pub async fn h264_direct_stream(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    if !validate_ws_origin(&headers, &state.config) {
        return Err(AppError::Forbidden("invalid websocket origin".to_string()));
    }

    // `?flow=N` turns on decode-driven flow control; anything else leaves it off.
    let window = query
        .get("flow")
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|window| *window > 0);

    Ok(ws
        .max_message_size(MAX_CONTROL_BYTES)
        .on_upgrade(move |socket| handle_h264_direct_socket(socket, window)))
}

async fn handle_h264_direct_socket(socket: WebSocket, window: Option<usize>) {
    serve_h264_direct(socket, window, subscribe_h264(H264ConsumerKind::Direct)).await;
}

async fn serve_h264_direct(
    socket: WebSocket,
    window: Option<usize>,
    mut subscription: H264Subscription,
) {
    let (mut sink, mut stream) = socket.split();
    let flow = Arc::new(Mutex::new(DirectFlow::new(window)));

    // Acknowledgements and resync requests arrive while frames go out, so they are
    // read on their own half of the socket.
    let reader_flow = Arc::clone(&flow);
    let reader = async move {
        loop {
            match time::timeout(DIRECT_READ_IDLE, stream.next()).await {
                Ok(Some(Ok(Message::Binary(data)))) => {
                    if let Some(control) = parse_control(&data)
                        && let Ok(mut flow) = reader_flow.lock()
                    {
                        flow.apply(control);
                    }
                }
                Ok(Some(Ok(Message::Close(_)))) | Ok(Some(Err(_))) | Ok(None) | Err(_) => break,
                Ok(Some(Ok(_))) => {}
            }
        }
    };

    let writer = async move {
        let mut keyframe_requests = KeyframeGate::new();
        let mut ping = time::interval(DIRECT_PING_INTERVAL);
        ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ping.tick().await;

        loop {
            let message = tokio::select! {
                frame = subscription.next() => {
                    let Some(frame) = frame else { break };
                    let offer = match flow.lock() {
                        Ok(mut flow) => flow.offer(frame.keyframe, frame.timestamp_micros),
                        Err(_) => break,
                    };
                    if offer == Offer::Skip {
                        if keyframe_requests.on_gap(Instant::now()) {
                            request_h264_keyframe("direct client flow control");
                        }
                        continue;
                    }
                    Message::Binary(frame.direct_packet())
                }
                _ = ping.tick() => Message::Ping(Bytes::new()),
            };

            match time::timeout(DIRECT_WRITE_TIMEOUT, sink.send(message)).await {
                Ok(Ok(())) => {}
                _ => break,
            }
        }
    };

    tokio::select! {
        _ = reader => {}
        _ = writer => {}
    }
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

fn start_h264_source() {
    if H264_SOURCE
        .running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        tokio::spawn(run_h264_source());
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
        if result < 0 || result == 5 || data.is_empty() {
            if !MJPEG_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                warn!(result, bytes = data.len(), "mjpeg frame unavailable");
            }
            backoff_after_mjpeg_failure(&mut consecutive_failures, result, data.len()).await;
            continue;
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
    let _guard = RunningGuard(&H264_SOURCE.running);

    let start = Instant::now();
    let mut fps = current_screen().fps;
    let mut interval = frame_interval(fps);

    loop {
        interval.tick().await;
        if H264_SOURCE.client_count() == 0 {
            return;
        }

        let screen = current_screen();
        if screen.fps != fps {
            fps = screen.fps;
            interval = frame_interval(fps);
        }
        match h264_direct_producer_action(screen.mode, h264_capture_disabled()) {
            H264DirectProducerAction::StopDisabled => {
                update_h264_capture_status(primary_h264_mode(), -8);
                return;
            }
            H264DirectProducerAction::WaitForH264Mode => continue,
            H264DirectProducerAction::Capture => {}
        }
        if !H264_DIRECT_FIRST_READ_LOGGED.swap(true, Ordering::Relaxed) {
            info!(
                width = screen.width,
                height = screen.height,
                bit_rate = screen.bit_rate,
                "reading first h264 direct frame"
            );
        }

        let Some((data, result)) = read_h264_capture_frame(
            primary_h264_mode(),
            H264Screen {
                width: screen.width,
                height: screen.height,
                fps: screen.fps.max(1),
                bit_rate: screen.bit_rate,
            },
        )
        .await
        else {
            if !H264_DIRECT_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                warn!("h264 direct frame unavailable");
            }
            continue;
        };

        if !H264_DIRECT_FIRST_SUCCESS_LOGGED.swap(true, Ordering::Relaxed) {
            info!(result, bytes = data.len(), "read first h264 direct frame");
        }

        let timestamp = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let keyframe = result == 3;
        let packet = (H264_DIRECT_CONSUMERS.load(Ordering::Acquire) > 0)
            .then(|| Bytes::from(h264_direct_packet(keyframe, timestamp, &data)));
        H264_SOURCE.send(H264Frame {
            data: Bytes::from(data),
            keyframe,
            timestamp_micros: timestamp,
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
    kvm::set_frame_detect(if req.enabled {
        FRAME_DETECT_INTERVAL
    } else {
        0
    })?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn stop_frame_detect(Json(req): Json<StopFrameDetectReq>) -> Result<impl IntoResponse> {
    let duration = Duration::from_secs(req.duration.unwrap_or(10).max(1));
    kvm::set_frame_detect(0)?;
    time::sleep(duration).await;
    kvm::set_frame_detect(FRAME_DETECT_INTERVAL)?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
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
    if let Some(parent) = std::path::Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, value.as_bytes()).map_err(AppError::from)
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
    if H264_KEYFRAME_REQUEST_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
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

pub async fn read_h264_capture_frame(
    mode: &'static str,
    screen: H264Screen,
) -> Option<(Vec<u8>, i32)> {
    if h264_capture_disabled() {
        update_h264_capture_status(mode, -8);
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
    update_h264_capture_status(mode, result);
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

/// The mode label capture status is reported under: the direct stream when it has
/// clients, otherwise the WebRTC one.
fn primary_h264_mode() -> &'static str {
    if H264_DIRECT_CONSUMERS.load(Ordering::Acquire) > 0 {
        CAPTURE_MODE_DIRECT
    } else {
        CAPTURE_MODE_H264
    }
}

/// Reports a capture result under `mode` and under the other H.264 mode when it
/// has clients too, since both are fed by the same capture.
fn update_h264_capture_status(mode: &'static str, result: i32) {
    update_capture_status(mode, result);
    for (other, count) in [
        (CAPTURE_MODE_DIRECT, &H264_DIRECT_CONSUMERS),
        (CAPTURE_MODE_H264, &H264_WEBRTC_CONSUMERS),
    ] {
        if other != mode && count.load(Ordering::Acquire) > 0 {
            update_capture_status(other, result);
        }
    }
}

fn record_h264_failure(
    mode: &'static str,
    reason: &'static str,
    detail: Option<String>,
    recovery: H264FailureRecovery,
) {
    update_h264_capture_status(mode, -1);
    let failures = H264_CONSECUTIVE_FAILURES.fetch_add(1, Ordering::AcqRel) + 1;
    warn!(mode, failures, detail = ?detail, reason, "h264 capture failure");

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
    update_h264_capture_status(mode, -8);

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

fn h264_direct_packet(is_keyframe: bool, timestamp_micros: u64, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1 + 8 + data.len());
    packet.push(u8::from(is_keyframe));
    packet.extend_from_slice(&timestamp_micros.to_le_bytes());
    packet.extend_from_slice(data);
    packet
}

#[cfg(test)]
mod tests {
    use super::{
        H264_SOURCE, H264_WEBRTC_CONSUMERS, H264ConsumerKind, H264DirectProducerAction, H264Frame,
        H264Subscription, KeyframeGate, Screen, StreamMode, h264_direct_packet,
        h264_direct_producer_action, normalize_screen, serve_h264_direct,
    };
    use crate::api::direct_flow::MAX_CONTROL_BYTES;
    use axum::extract::ws::WebSocketUpgrade;
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use std::{
        sync::{Arc, Mutex, atomic::Ordering},
        time::{Duration, Instant},
    };
    use tokio::{sync::broadcast, time};

    fn frame(keyframe: bool, tag: &'static [u8]) -> H264Frame {
        H264Frame {
            data: Bytes::from_static(tag),
            keyframe,
            timestamp_micros: 7,
            packet: None,
        }
    }

    #[test]
    fn gate_admits_only_a_keyframe_to_start() {
        let mut gate = KeyframeGate::new();
        assert!(!gate.admit(false));
        assert!(!gate.admit(false));
        assert!(gate.admit(true));
        assert!(gate.admit(false));
    }

    #[test]
    fn gate_waits_for_a_keyframe_again_after_a_gap() {
        let mut gate = KeyframeGate::new();
        assert!(gate.admit(true));
        gate.on_gap(Instant::now());
        assert!(!gate.admit(false));
        assert!(gate.admit(true));
    }

    #[test]
    fn gate_rate_limits_keyframe_requests() {
        let mut gate = KeyframeGate::new();
        let start = Instant::now();
        assert!(gate.on_gap(start));
        assert!(!gate.on_gap(start + Duration::from_millis(200)));
        assert!(gate.on_gap(start + Duration::from_secs(2)));
    }

    #[test]
    fn direct_packet_is_built_on_demand_when_not_prebuilt() {
        let built = frame(true, b"\xaa\xbb").direct_packet();
        assert_eq!(built.as_ref(), h264_direct_packet(true, 7, &[0xaa, 0xbb]));

        let mut prebuilt = frame(false, b"x");
        prebuilt.packet = Some(Bytes::from_static(b"ready"));
        assert_eq!(prebuilt.direct_packet().as_ref(), b"ready");
    }

    #[tokio::test]
    async fn consumer_resumes_at_the_next_keyframe_after_lagging() {
        let (tx, rx) = broadcast::channel(2);
        H264_WEBRTC_CONSUMERS.fetch_add(1, Ordering::AcqRel);
        let mut subscription = H264Subscription {
            rx,
            gate: KeyframeGate::new(),
            kind: H264ConsumerKind::WebRtc,
            _client: H264_SOURCE.add_client(),
        };

        // A consumer that joins mid-GOP skips delta frames until a keyframe.
        tx.send(frame(false, b"p0")).unwrap();
        tx.send(frame(true, b"k1")).unwrap();
        assert_eq!(subscription.next().await.unwrap().data.as_ref(), b"k1");

        // Overflowing the channel drops frames; the consumer must not decode the
        // delta frames that follow the gap.
        for tag in [b"p1", b"p2", b"p3", b"p4"] {
            tx.send(frame(false, tag)).unwrap();
        }
        tx.send(frame(true, b"k2")).unwrap();
        assert_eq!(subscription.next().await.unwrap().data.as_ref(), b"k2");

        drop(tx);
        assert!(subscription.next().await.is_none());
    }

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
    fn direct_frame(keyframe: bool, timestamp_micros: u64) -> H264Frame {
        H264Frame {
            data: Bytes::from_static(b"\x00\x00\x00\x01"),
            keyframe,
            timestamp_micros,
            packet: None,
        }
    }

    /// The timestamp of the next frame the client receives, or `None` if none arrives soon.
    async fn next_direct_timestamp<S>(client: &mut S) -> Option<u64>
    where
        S: futures_util::Stream<
                Item = std::result::Result<
                    tokio_tungstenite::tungstenite::Message,
                    tokio_tungstenite::tungstenite::Error,
                >,
            > + Unpin,
    {
        loop {
            let message = time::timeout(Duration::from_millis(400), client.next())
                .await
                .ok()??
                .ok()?;
            if let tokio_tungstenite::tungstenite::Message::Binary(data) = message {
                return Some(u64::from_le_bytes(data[1..9].try_into().unwrap()));
            }
        }
    }

    #[tokio::test]
    async fn the_direct_stream_applies_flow_control_over_a_real_socket() {
        use axum::{Router, routing::get};
        use tokio_tungstenite::tungstenite::Message as ClientMessage;

        let (tx, rx) = broadcast::channel::<H264Frame>(16);
        let subscription = H264Subscription {
            rx,
            gate: KeyframeGate::new(),
            kind: H264ConsumerKind::Direct,
            _client: H264_SOURCE.add_client(),
        };
        let pending = Arc::new(Mutex::new(Some(subscription)));
        let app = Router::new().route(
            "/ws",
            get(move |ws: WebSocketUpgrade| {
                let subscription = pending.lock().unwrap().take().unwrap();
                async move {
                    ws.max_message_size(MAX_CONTROL_BYTES)
                        .on_upgrade(move |socket| serve_h264_direct(socket, Some(2), subscription))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ws"))
            .await
            .unwrap();

        // A window of two: the keyframe and one delta go out, the rest are dropped.
        for (keyframe, timestamp) in [(true, 1), (false, 2), (false, 3), (false, 4)] {
            tx.send(direct_frame(keyframe, timestamp)).unwrap();
        }
        assert_eq!(next_direct_timestamp(&mut client).await, Some(1));
        assert_eq!(next_direct_timestamp(&mut client).await, Some(2));
        assert_eq!(next_direct_timestamp(&mut client).await, None);

        // Acknowledging frees the window, but a delta frame after a gap is still dropped.
        let mut ack = vec![2_u8];
        ack.extend_from_slice(&2_u64.to_le_bytes());
        client
            .send(ClientMessage::Binary(ack.into()))
            .await
            .unwrap();
        time::sleep(Duration::from_millis(100)).await;
        tx.send(direct_frame(false, 5)).unwrap();
        assert_eq!(next_direct_timestamp(&mut client).await, None);

        // The next keyframe resumes the stream, and deltas follow it.
        tx.send(direct_frame(true, 6)).unwrap();
        tx.send(direct_frame(false, 7)).unwrap();
        assert_eq!(next_direct_timestamp(&mut client).await, Some(6));
        assert_eq!(next_direct_timestamp(&mut client).await, Some(7));

        // A resync request empties the window and waits for a keyframe again.
        client
            .send(ClientMessage::Binary(vec![3_u8].into()))
            .await
            .unwrap();
        time::sleep(Duration::from_millis(100)).await;
        tx.send(direct_frame(false, 8)).unwrap();
        assert_eq!(next_direct_timestamp(&mut client).await, None);
        tx.send(direct_frame(true, 9)).unwrap();
        assert_eq!(next_direct_timestamp(&mut client).await, Some(9));

        server.abort();
    }

    #[tokio::test]
    async fn a_direct_client_without_flow_control_receives_every_frame() {
        use axum::{Router, routing::get};

        let (tx, rx) = broadcast::channel::<H264Frame>(16);
        let subscription = H264Subscription {
            rx,
            gate: KeyframeGate::new(),
            kind: H264ConsumerKind::Direct,
            _client: H264_SOURCE.add_client(),
        };
        let pending = Arc::new(Mutex::new(Some(subscription)));
        let app =
            Router::new().route(
                "/ws",
                get(move |ws: WebSocketUpgrade| {
                    let subscription = pending.lock().unwrap().take().unwrap();
                    async move {
                        ws.on_upgrade(move |socket| serve_h264_direct(socket, None, subscription))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });

        let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ws"))
            .await
            .unwrap();

        tx.send(direct_frame(true, 1)).unwrap();
        for timestamp in 2..=6 {
            tx.send(direct_frame(false, timestamp)).unwrap();
        }
        for expected in 1..=6 {
            assert_eq!(next_direct_timestamp(&mut client).await, Some(expected));
        }

        server.abort();
    }
}
