use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::IntoResponse,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    sync::{LazyLock, Mutex},
    thread,
    time::{Duration, Instant},
};

use crate::{AppError, Result, state::AppState, ws::origin::validate_ws_origin};

const HID_KEYBOARD: &str = "/dev/hidg0";
const HID_MOUSE_RELATIVE: &str = "/dev/hidg1";
const HID_MOUSE_ABSOLUTE: &str = "/dev/hidg2";
const HID_WRITE_TIMEOUT: Duration = Duration::from_millis(50);
const HID_WRITE_RETRY_DELAY: Duration = Duration::from_millis(1);
const MAX_WS_MESSAGE_BYTES: usize = 16;

const HEARTBEAT_EVENT: u8 = 0;
const KEYBOARD_EVENT: u8 = 1;
const MOUSE_EVENT: u8 = 2;

static HID: LazyLock<HidDevices> = LazyLock::new(HidDevices::default);

#[derive(Default)]
struct HidDevices {
    keyboard: Mutex<Option<File>>,
    relative_mouse: Mutex<Option<File>>,
    absolute_mouse: Mutex<Option<File>>,
}

impl HidDevices {
    fn write_keyboard(&self, report: &[u8]) -> io::Result<()> {
        self.write_device(&self.keyboard, HID_KEYBOARD, report)
    }

    fn write_relative_mouse(&self, report: &[u8]) -> io::Result<()> {
        self.write_device(&self.relative_mouse, HID_MOUSE_RELATIVE, report)
    }

    fn write_absolute_mouse(&self, report: &[u8]) -> io::Result<()> {
        self.write_device(&self.absolute_mouse, HID_MOUSE_ABSOLUTE, report)
    }

    fn write_device(
        &self,
        slot: &Mutex<Option<File>>,
        path: &'static str,
        report: &[u8],
    ) -> io::Result<()> {
        let mut guard = slot
            .lock()
            .map_err(|_| io::Error::other("hid device lock poisoned"))?;

        if guard.is_none() {
            *guard = Some(open_hid(path)?);
        }

        let result = write_with_timeout(guard.as_mut().expect("hid file is open"), report);
        if result.is_err() {
            *guard = None;
        }
        result
    }
}

pub async fn connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    if !validate_ws_origin(&headers, &state.config) {
        return Err(AppError::Forbidden("invalid websocket origin".to_string()));
    }

    Ok(ws
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(handle_socket))
}

async fn handle_socket(mut socket: WebSocket) {
    let mut absolute_buttons_active = false;
    let mut absolute_release_report = [0_u8; 6];

    while let Some(message) = socket.recv().await {
        let Ok(message) = message else {
            break;
        };

        let data = match message {
            Message::Binary(data) => data,
            Message::Text(text) => text.as_bytes().to_vec().into(),
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => continue,
        };

        if data.is_empty() || data.len() > MAX_WS_MESSAGE_BYTES {
            continue;
        }

        match data[0] {
            HEARTBEAT_EVENT => {}
            KEYBOARD_EVENT => {
                if data.len() != 9 {
                    continue;
                }
                let report = data[1..].to_vec();
                let _ = tokio::task::spawn_blocking(move || HID.write_keyboard(&report)).await;
            }
            MOUSE_EVENT => match data.len() - 1 {
                4 => {
                    let report = data[1..].to_vec();
                    let _ = tokio::task::spawn_blocking(move || HID.write_relative_mouse(&report))
                        .await;
                }
                6 => {
                    let report = data[1..].to_vec();
                    absolute_release_report = absolute_mouse_release_report(&report);
                    absolute_buttons_active = report.first().copied().unwrap_or_default() != 0;
                    let _ = tokio::task::spawn_blocking(move || HID.write_absolute_mouse(&report))
                        .await;
                }
                _ => {}
            },
            _ => {}
        }
    }

    let _ = tokio::task::spawn_blocking(move || {
        let _ = HID.write_keyboard(&[0; 8]);
        let _ = HID.write_relative_mouse(&[0; 4]);
        if absolute_buttons_active {
            let _ = HID.write_absolute_mouse(&absolute_release_report);
        }
    })
    .await;
}

fn open_hid(path: &'static str) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
}

fn write_with_timeout(file: &mut File, report: &[u8]) -> io::Result<()> {
    let deadline = Instant::now() + HID_WRITE_TIMEOUT;

    loop {
        match file.write(report) {
            Ok(n) if n == report.len() => return Ok(()),
            Ok(_) => return Err(io::Error::new(io::ErrorKind::WriteZero, "short HID write")),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "HID write timed out",
                    ));
                }
                thread::sleep(HID_WRITE_RETRY_DELAY);
            }
            Err(err) => return Err(err),
        }
    }
}

fn absolute_mouse_release_report(position_report: &[u8]) -> [u8; 6] {
    let mut report = [0_u8; 6];
    if position_report.len() >= 5 {
        report[1..5].copy_from_slice(&position_report[1..5]);
    }
    report
}
