use axum::{
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::IntoResponse,
};
use std::{
    fs,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{FileTypeExt, OpenOptionsExt},
    path::Path,
    sync::{LazyLock, Mutex},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

use crate::{AppError, Result, state::AppState, ws::origin::validate_ws_origin};

const HID_KEYBOARD: &str = "/dev/hidg0";
const HID_MOUSE_RELATIVE: &str = "/dev/hidg1";
const HID_MOUSE_ABSOLUTE: &str = "/dev/hidg2";
const HID_WRITE_TIMEOUT: Duration = Duration::from_millis(50);
const HID_WRITE_RETRY_DELAY: Duration = Duration::from_millis(1);
const HID_REOPEN_TIMEOUT: Duration = Duration::from_secs(2);
const HID_REOPEN_RETRY_DELAY: Duration = Duration::from_millis(100);
const HID_EVENT_QUEUE_CAPACITY: usize = 200;
const MAX_WS_MESSAGE_BYTES: usize = 16;
const MOUSE_JIGGLER_CONFIG: &str = "/etc/kvm/mouse-jiggler";
const MOUSE_JIGGLER_INTERVAL: Duration = Duration::from_secs(15);

const HEARTBEAT_EVENT: u8 = 0;
const KEYBOARD_EVENT: u8 = 1;
const MOUSE_EVENT: u8 = 2;
const JIGGLER_MODE_RELATIVE: &str = "relative";
const JIGGLER_MODE_ABSOLUTE: &str = "absolute";

static HID: LazyLock<HidDevices> = LazyLock::new(HidDevices::default);
static MOUSE_JIGGLER: LazyLock<Mutex<MouseJiggler>> =
    LazyLock::new(|| Mutex::new(MouseJiggler::from_config()));

#[derive(Default)]
struct HidDevices {
    keyboard: Mutex<Option<File>>,
    relative_mouse: Mutex<Option<File>>,
    absolute_mouse: Mutex<Option<File>>,
}

#[derive(Debug)]
struct MouseJiggler {
    enabled: bool,
    running: bool,
    mode: String,
    last_updated: Instant,
}

impl MouseJiggler {
    fn from_config() -> Self {
        let mode = fs::read_to_string(MOUSE_JIGGLER_CONFIG)
            .ok()
            .map(|value| normalize_jiggler_mode(value.trim()))
            .unwrap_or_else(|| JIGGLER_MODE_RELATIVE.to_string());
        Self {
            enabled: Path::new(MOUSE_JIGGLER_CONFIG).exists(),
            running: false,
            mode,
            last_updated: Instant::now(),
        }
    }
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
        let deadline = Instant::now() + HID_REOPEN_TIMEOUT;

        loop {
            let result = {
                let mut guard = slot
                    .lock()
                    .map_err(|_| io::Error::other("hid device lock poisoned"))?;

                let open_result = if guard.is_none() {
                    open_hid(path).map(|file| *guard = Some(file))
                } else {
                    Ok(())
                };

                match open_result {
                    Ok(()) => {
                        let result =
                            write_with_timeout(guard.as_mut().expect("hid file is open"), report);
                        if result.is_err() {
                            *guard = None;
                        }
                        result
                    }
                    Err(err) => Err(err),
                }
            };

            match result {
                Ok(()) => return Ok(()),
                Err(err) => {
                    if !is_reopen_retryable_hid_error(&err) || Instant::now() >= deadline {
                        return Err(hid_unavailable_error(path, err));
                    }

                    let delay = deadline
                        .saturating_duration_since(Instant::now())
                        .min(HID_REOPEN_RETRY_DELAY);
                    if delay.is_zero() {
                        return Err(hid_unavailable_error(path, err));
                    }
                    thread::sleep(delay);
                }
            }
        }
    }
}

pub fn write_keyboard_report(report: &[u8]) -> io::Result<()> {
    HID.write_keyboard(report)
}

pub fn write_relative_mouse_report(report: &[u8]) -> io::Result<()> {
    HID.write_relative_mouse(report)
}

pub fn write_absolute_mouse_report(report: &[u8]) -> io::Result<()> {
    HID.write_absolute_mouse(report)
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
    let (keyboard_tx, keyboard_rx) = mpsc::channel(HID_EVENT_QUEUE_CAPACITY);
    let (mouse_tx, mouse_rx) = mpsc::channel(HID_EVENT_QUEUE_CAPACITY);
    let keyboard_worker = tokio::spawn(keyboard_worker(keyboard_rx));
    let mouse_worker = tokio::spawn(mouse_worker(mouse_rx));

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
                touch_mouse_jiggler();
                let report = data[1..].to_vec();
                if keyboard_tx.send(report).await.is_err() {
                    break;
                }
            }
            MOUSE_EVENT => match data.len() - 1 {
                4 => {
                    touch_mouse_jiggler();
                    let report = data[1..].to_vec();
                    if mouse_tx.send(report).await.is_err() {
                        break;
                    }
                }
                6 => {
                    touch_mouse_jiggler();
                    let report = data[1..].to_vec();
                    if mouse_tx.send(report).await.is_err() {
                        break;
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    drop(keyboard_tx);
    drop(mouse_tx);
    let _ = keyboard_worker.await;
    let _ = mouse_worker.await;
}

async fn keyboard_worker(mut queue: mpsc::Receiver<Vec<u8>>) {
    while let Some(report) = queue.recv().await {
        if report.len() != 8 {
            continue;
        }

        if !write_hid_blocking(move || HID.write_keyboard(&report)).await {
            drain_hid_queue(&mut queue);
        }
    }

    let _ = write_hid_blocking(|| HID.write_keyboard(&[0; 8])).await;
}

async fn mouse_worker(mut queue: mpsc::Receiver<Vec<u8>>) {
    let mut absolute_buttons_active = false;
    let mut absolute_release_report = [0_u8; 6];

    while let Some(report) = queue.recv().await {
        match report.len() {
            4 => {
                if !write_hid_blocking(move || HID.write_relative_mouse(&report)).await {
                    drain_hid_queue(&mut queue);
                    let _ = write_hid_blocking(|| HID.write_relative_mouse(&[0; 4])).await;
                }
            }
            6 => {
                let release_report = absolute_mouse_release_report(&report);
                let buttons_active = report.first().copied().unwrap_or_default() != 0;
                if write_hid_blocking(move || HID.write_absolute_mouse(&report)).await {
                    absolute_release_report = release_report;
                    absolute_buttons_active = buttons_active;
                } else {
                    drain_hid_queue(&mut queue);
                    if absolute_buttons_active {
                        let report = absolute_release_report;
                        if write_hid_blocking(move || HID.write_absolute_mouse(&report)).await {
                            absolute_buttons_active = false;
                        }
                    } else if buttons_active {
                        let _ =
                            write_hid_blocking(move || HID.write_absolute_mouse(&release_report))
                                .await;
                    }
                }
            }
            _ => {}
        }
    }

    let _ = write_hid_blocking(|| HID.write_relative_mouse(&[0; 4])).await;
    if absolute_buttons_active {
        let report = absolute_release_report;
        let _ = write_hid_blocking(move || HID.write_absolute_mouse(&report)).await;
    }
}

async fn write_hid_blocking<F>(write: F) -> bool
where
    F: FnOnce() -> io::Result<()> + Send + 'static,
{
    matches!(tokio::task::spawn_blocking(write).await, Ok(Ok(())))
}

fn drain_hid_queue(queue: &mut mpsc::Receiver<Vec<u8>>) -> usize {
    let mut dropped = 0;
    while queue.try_recv().is_ok() {
        dropped += 1;
    }
    dropped
}

fn open_hid(path: &str) -> io::Result<File> {
    let metadata = fs::metadata(path)?;
    if !metadata.file_type().is_char_device() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{path} is not a HID character device"),
        ));
    }

    OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
}

fn is_reopen_retryable_hid_error(err: &io::Error) -> bool {
    match err.kind() {
        io::ErrorKind::Interrupted
        | io::ErrorKind::NotFound
        | io::ErrorKind::TimedOut
        | io::ErrorKind::WouldBlock => true,
        _ => matches!(
            err.raw_os_error(),
            Some(nix::libc::EAGAIN) | Some(nix::libc::ENODEV) | Some(nix::libc::ENXIO)
        ),
    }
}

fn hid_unavailable_error(path: &str, err: io::Error) -> io::Error {
    io::Error::new(
        err.kind(),
        format!(
            "{path}: HID device is unavailable; reconnect USB or reset HID and try again: {err}"
        ),
    )
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

pub fn mouse_jiggler_snapshot() -> Result<(bool, String)> {
    let state = MOUSE_JIGGLER
        .lock()
        .map_err(|_| AppError::Internal("mouse jiggler lock poisoned".to_string()))?;
    Ok((state.enabled, state.mode.clone()))
}

pub fn set_mouse_jiggler(enabled: bool, mode: &str) -> Result<()> {
    if enabled {
        let mode = validate_jiggler_mode(mode)?;
        fs::write(MOUSE_JIGGLER_CONFIG, mode.as_bytes())?;

        let mut should_spawn = false;
        {
            let mut state = MOUSE_JIGGLER
                .lock()
                .map_err(|_| AppError::Internal("mouse jiggler lock poisoned".to_string()))?;
            state.enabled = true;
            state.mode = mode;
            state.last_updated = Instant::now();
            if !state.running {
                state.running = true;
                should_spawn = true;
            }
        }

        if should_spawn {
            tokio::spawn(mouse_jiggler_loop());
        }
    } else {
        remove_file_if_exists(MOUSE_JIGGLER_CONFIG)?;
        let mut state = MOUSE_JIGGLER
            .lock()
            .map_err(|_| AppError::Internal("mouse jiggler lock poisoned".to_string()))?;
        state.enabled = false;
        state.mode = JIGGLER_MODE_RELATIVE.to_string();
        state.last_updated = Instant::now();
    }

    Ok(())
}

fn touch_mouse_jiggler() {
    if let Ok(mut state) = MOUSE_JIGGLER.lock() {
        if state.running {
            state.last_updated = Instant::now();
        }
    }
}

async fn mouse_jiggler_loop() {
    loop {
        tokio::time::sleep(MOUSE_JIGGLER_INTERVAL).await;
        let mode = {
            let Ok(mut state) = MOUSE_JIGGLER.lock() else {
                return;
            };
            if !state.enabled {
                state.running = false;
                return;
            }
            if state.last_updated.elapsed() <= MOUSE_JIGGLER_INTERVAL {
                continue;
            }
            state.last_updated = Instant::now();
            state.mode.clone()
        };

        let _ = tokio::task::spawn_blocking(move || move_mouse_jiggler(&mode)).await;
    }
}

fn move_mouse_jiggler(mode: &str) -> io::Result<()> {
    if mode == JIGGLER_MODE_ABSOLUTE {
        HID.write_absolute_mouse(&[0x00, 0x00, 0x3f, 0x00, 0x3f, 0x00])?;
        thread::sleep(Duration::from_millis(100));
        HID.write_absolute_mouse(&[0x00, 0xff, 0x3f, 0xff, 0x3f, 0x00])
    } else {
        HID.write_relative_mouse(&[0x00, 0x0a, 0x0a, 0x00])?;
        thread::sleep(Duration::from_millis(100));
        HID.write_relative_mouse(&[0x00, 0xf6, 0xf6, 0x00])
    }
}

fn validate_jiggler_mode(mode: &str) -> Result<String> {
    let mode = normalize_jiggler_mode(mode);
    if mode == JIGGLER_MODE_RELATIVE || mode == JIGGLER_MODE_ABSOLUTE {
        Ok(mode)
    } else {
        Err(AppError::BadRequest(
            "invalid mouse jiggler mode".to_string(),
        ))
    }
}

fn normalize_jiggler_mode(mode: &str) -> String {
    match mode.trim() {
        JIGGLER_MODE_ABSOLUTE => JIGGLER_MODE_ABSOLUTE.to_string(),
        JIGGLER_MODE_RELATIVE | "" => JIGGLER_MODE_RELATIVE.to_string(),
        other => other.to_string(),
    }
}

fn remove_file_if_exists(path: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_jiggler_modes() {
        assert_eq!(validate_jiggler_mode("relative").unwrap(), "relative");
        assert_eq!(validate_jiggler_mode("absolute").unwrap(), "absolute");
        assert!(validate_jiggler_mode("diagonal").is_err());
    }
}
