use async_stream::stream;
use axum::{
    Json,
    body::Body,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Response, header},
    response::IntoResponse,
};
use bytes::Bytes;
use serde::Deserialize;
use std::{
    fs, io,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::broadcast,
    time::{self, MissedTickBehavior},
};
use tracing::{info, warn};

use crate::{
    AppError, Result, error::ApiResponse, ffi::kvm, state::AppState, ws::origin::validate_ws_origin,
};

const FRAME_DETECT_INTERVAL: u8 = 60;
const SCREEN_TYPE_FILE: &str = "/kvmapp/kvm/type";
const SCREEN_FPS_FILE: &str = "/kvmapp/kvm/fps";
const SCREEN_QUALITY_FILE: &str = "/kvmapp/kvm/qlty";
const SCREEN_RESOLUTION_FILE: &str = "/kvmapp/kvm/res";
const SCREEN_GOP_FILE: &str = "/kvmapp/kvm/gop";

static SCREEN: LazyLock<Mutex<Screen>> = LazyLock::new(|| Mutex::new(Screen::default()));
static LATEST_MJPEG_FRAME: LazyLock<Mutex<Option<LatestMjpegFrame>>> =
    LazyLock::new(|| Mutex::new(None));
static MJPEG_FANOUT: LazyLock<StreamFanout<MjpegFrame>> = LazyLock::new(|| StreamFanout::new(4));
static H264_DIRECT_FANOUT: LazyLock<StreamFanout<H264DirectFrame>> =
    LazyLock::new(|| StreamFanout::new(16));
static MJPEG_FIRST_READ_LOGGED: AtomicBool = AtomicBool::new(false);
static MJPEG_FIRST_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static MJPEG_FIRST_ERROR_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_DIRECT_FIRST_READ_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_DIRECT_FIRST_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_DIRECT_FIRST_ERROR_LOGGED: AtomicBool = AtomicBool::new(false);

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
struct H264DirectFrame {
    packet: Bytes,
}

struct StreamFanout<T> {
    clients: AtomicUsize,
    running: AtomicBool,
    tx: broadcast::Sender<T>,
}

struct ClientGuard {
    clients: &'static AtomicUsize,
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

    fn add_client(&'static self) -> ClientGuard {
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

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.clients.fetch_sub(1, Ordering::AcqRel);
    }
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
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    if !validate_ws_origin(&headers, &state.config) {
        return Err(AppError::Forbidden("invalid websocket origin".to_string()));
    }

    Ok(ws.on_upgrade(handle_h264_direct_socket))
}

async fn handle_h264_direct_socket(mut socket: WebSocket) {
    let _guard = H264_DIRECT_FANOUT.add_client();
    let mut rx = H264_DIRECT_FANOUT.subscribe();
    start_h264_direct_producer();

    loop {
        let frame = match rx.recv().await {
            Ok(frame) => frame,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        };
        if socket.send(Message::Binary(frame.packet)).await.is_err() {
            break;
        }
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

fn start_h264_direct_producer() {
    if H264_DIRECT_FANOUT
        .running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        tokio::spawn(run_h264_direct_producer());
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
                if !MJPEG_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                    warn!(error = ?err, "failed to read mjpeg frame");
                }
                continue;
            }
            Err(err) => {
                if !MJPEG_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                    warn!(error = ?err, "mjpeg frame task failed");
                }
                continue;
            }
        };
        if result < 0 || result == 5 || data.is_empty() {
            if !MJPEG_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                warn!(result, bytes = data.len(), "mjpeg frame unavailable");
            }
            continue;
        }
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

async fn run_h264_direct_producer() {
    struct RunningGuard(&'static AtomicBool);
    impl Drop for RunningGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _guard = RunningGuard(&H264_DIRECT_FANOUT.running);

    let start = Instant::now();
    let mut fps = current_screen().fps;
    let mut interval = frame_interval(fps);

    loop {
        interval.tick().await;
        if H264_DIRECT_FANOUT.client_count() == 0 {
            return;
        }

        let screen = current_screen();
        if screen.fps != fps {
            fps = screen.fps;
            interval = frame_interval(fps);
        }
        if !H264_DIRECT_FIRST_READ_LOGGED.swap(true, Ordering::Relaxed) {
            info!(
                width = screen.width,
                height = screen.height,
                bit_rate = screen.bit_rate,
                "reading first h264 direct frame"
            );
        }

        let frame = tokio::task::spawn_blocking(move || {
            kvm::read_h264(screen.width, screen.height, screen.bit_rate)
        })
        .await;

        let (data, result) = match frame {
            Ok(Ok(frame)) => frame,
            Ok(Err(err)) => {
                if !H264_DIRECT_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                    warn!(error = ?err, "failed to read h264 direct frame");
                }
                continue;
            }
            Err(err) => {
                if !H264_DIRECT_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                    warn!(error = ?err, "h264 direct frame task failed");
                }
                continue;
            }
        };

        if result < 0 || data.is_empty() {
            if !H264_DIRECT_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                warn!(result, bytes = data.len(), "h264 direct frame unavailable");
            }
            continue;
        }

        if !H264_DIRECT_FIRST_SUCCESS_LOGGED.swap(true, Ordering::Relaxed) {
            info!(result, bytes = data.len(), "read first h264 direct frame");
        }

        let timestamp = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
        let packet = h264_direct_packet(result == 3, timestamp, &data);
        H264_DIRECT_FANOUT.send(H264DirectFrame {
            packet: Bytes::from(packet),
        });
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
            write_screen_file(SCREEN_TYPE_FILE, if value == 0 { "mjpeg" } else { "h264" })?;
            screen.mode = if value == 0 {
                StreamMode::Mjpeg
            } else {
                StreamMode::H264
            };
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

pub fn current_mjpeg_screen() -> MjpegScreen {
    let screen = current_screen();
    MjpegScreen {
        width: screen.width,
        height: screen.height,
        quality: screen.quality,
    }
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
        // Match the Go backend: 0 means "auto" and is passed through to libkvm.
        0 => Some((0, 0)),
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
    use super::{Screen, StreamMode, h264_direct_packet, normalize_screen};

    #[test]
    fn default_screen_matches_go_auto_resolution_when_unconfigured() {
        let screen = Screen::default();

        assert!(matches!(screen.mode, StreamMode::Mjpeg | StreamMode::H264));
        assert!(matches!(screen.height, 0 | 480 | 600 | 720 | 1080));
    }

    #[test]
    fn auto_resolution_is_passed_to_libkvm() {
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

        assert_eq!(screen.width, 0);
        assert_eq!(screen.height, 0);
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
}
