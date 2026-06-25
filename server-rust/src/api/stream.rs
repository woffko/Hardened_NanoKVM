use async_stream::stream;
use axum::{
    Json,
    body::Body,
    http::{Response, header},
    response::IntoResponse,
};
use bytes::Bytes;
use serde::Deserialize;
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    sync::{LazyLock, Mutex},
    time::Duration,
};
use tokio::time::{self, MissedTickBehavior};
use tracing::{info, warn};

use crate::{AppError, Result, error::ApiResponse, ffi::kvm};

const FRAME_DETECT_INTERVAL: u8 = 60;

static SCREEN: LazyLock<Mutex<Screen>> = LazyLock::new(|| Mutex::new(Screen::default()));
static MJPEG_FIRST_READ_LOGGED: AtomicBool = AtomicBool::new(false);
static MJPEG_FIRST_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static MJPEG_FIRST_ERROR_LOGGED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy)]
struct Screen {
    width: u16,
    height: u16,
    fps: u64,
    quality: u16,
    bit_rate: u16,
    gop: u8,
}

impl Default for Screen {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
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
        "resolution" => {
            let height = u16::try_from(value).unwrap_or_default();
            if let Some(width) = resolution_width(height) {
                screen.width = width;
                screen.height = height;
            }
        }
        "quality" => {
            let value = u16::try_from(value).unwrap_or_default();
            if value > 100 {
                screen.bit_rate = value;
            } else {
                screen.quality = value;
            }
        }
        "fps" => {
            screen.fps = validate_fps(value);
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

fn current_screen() -> Screen {
    let mut screen = SCREEN.lock().expect("screen lock should not be poisoned");
    normalize_screen(&mut screen);
    *screen
}

fn normalize_screen(screen: &mut Screen) {
    if resolution_width(screen.height).is_none() {
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

fn resolution_width(height: u16) -> Option<u16> {
    match height {
        1080 => Some(1920),
        720 => Some(1280),
        600 => Some(800),
        480 => Some(640),
        0 => Some(0),
        _ => None,
    }
}

fn validate_fps(fps: i32) -> u64 {
    fps.clamp(10, 60) as u64
}
