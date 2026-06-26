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
    sync::atomic::{AtomicBool, Ordering},
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::time::{self, MissedTickBehavior};
use tracing::{info, warn};

use crate::{
    AppError, Result, error::ApiResponse, ffi::kvm, state::AppState, ws::origin::validate_ws_origin,
};

const FRAME_DETECT_INTERVAL: u8 = 60;
const SCREEN_TYPE_FILE: &str = "/kvmapp/kvm/type";
const SCREEN_FPS_FILE: &str = "/kvmapp/kvm/fps";
const SCREEN_QUALITY_FILE: &str = "/kvmapp/kvm/qlty";
const SCREEN_RESOLUTION_FILE: &str = "/kvmapp/kvm/res";

static SCREEN: LazyLock<Mutex<Screen>> = LazyLock::new(|| Mutex::new(Screen::default()));
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

impl Default for Screen {
    fn default() -> Self {
        Self {
            mode: StreamMode::Mjpeg,
            width: 1920,
            height: 1080,
            fps: 30,
            quality: 80,
            bit_rate: 3000,
            gop: 30,
        }
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
        let mut interval = time::interval(frame_interval());
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            let screen = current_screen();
            if screen.mode != StreamMode::Mjpeg {
                break;
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
                    warn!(
                        result,
                        bytes = data.len(),
                        "mjpeg frame unavailable"
                    );
                }
                continue;
            }
            if !MJPEG_FIRST_SUCCESS_LOGGED.swap(true, Ordering::Relaxed) {
                info!(result, bytes = data.len(), "read first mjpeg frame");
            }

            let header = format!(
                "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\n\r\n",
                data.len()
            );
            yield Ok::<Bytes, io::Error>(Bytes::from(header));
            yield Ok::<Bytes, io::Error>(Bytes::from(data));
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
    let start = Instant::now();
    let mut interval = time::interval(frame_interval());
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        let screen = current_screen();
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
        if socket.send(Message::Binary(packet.into())).await.is_err() {
            break;
        }
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
            let height = u16::try_from(value).unwrap_or_default();
            if let Some((width, height)) = capture_resolution(height) {
                screen.width = width;
                screen.height = height;
            }
            write_screen_file(SCREEN_RESOLUTION_FILE, &value.to_string())?;
        }
        "quality" => {
            let value = u16::try_from(value).unwrap_or_default();
            if value > 100 {
                screen.bit_rate = value;
            } else {
                screen.quality = value;
            }
            write_screen_file(SCREEN_QUALITY_FILE, &value.to_string())?;
        }
        "fps" => {
            screen.fps = validate_fps(value);
            write_screen_file(SCREEN_FPS_FILE, &value.to_string())?;
        }
        "gop" => {
            let gop = u8::try_from(value).unwrap_or(screen.gop);
            screen.gop = gop;
            kvm::set_h264_gop(gop)?;
        }
        _ => {}
    }

    Ok(())
}

fn write_screen_file(path: &str, value: &str) -> Result<()> {
    fs::write(path, value.as_bytes()).map_err(AppError::from)
}

fn current_screen() -> Screen {
    let mut screen = SCREEN.lock().expect("screen lock should not be poisoned");
    normalize_screen(&mut screen);
    *screen
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

fn frame_interval() -> Duration {
    let fps = SCREEN.lock().map(|screen| screen.fps.max(1)).unwrap_or(30);
    Duration::from_millis((1000 / fps).max(1))
}

fn capture_resolution(height: u16) -> Option<(u16, u16)> {
    match height {
        // The frontend uses 0 as "auto". The Go backend passes it through to
        // libkvm, but the Rust linked-libkvm path can hang the native driver on
        // first capture with 0x0. Capture at the known native default instead;
        // the browser still auto-scales because its local resolution remains 0.
        0 | 1080 => Some((1920, 1080)),
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
    fn default_screen_is_safe_for_capture() {
        let screen = Screen::default();

        assert_eq!(screen.width, 1920);
        assert_eq!(screen.height, 1080);
    }

    #[test]
    fn auto_resolution_maps_to_native_capture_size() {
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
}
