use axum::{
    Extension,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::{
    fs,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{FileTypeExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::{LazyLock, Mutex},
    thread,
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc};

use crate::{
    AppError, Result,
    http::middleware::{CurrentSession, TransportSession},
    state::AppState,
    system::usb,
    ws::origin::validate_ws_origin,
};

#[path = "hid_ownership.rs"]
mod ownership;
use ownership::{Bus, Endpoint, Lease, Report, Sink};

const HID_KEYBOARD: &str = "/dev/hidg0";
const HID_MOUSE_RELATIVE: &str = "/dev/hidg1";
const HID_MOUSE_ABSOLUTE: &str = "/dev/hidg2";
const HID_WRITE_TIMEOUT: Duration = Duration::from_millis(50);
const HID_WRITE_RETRY_DELAY: Duration = Duration::from_millis(1);
const HID_REOPEN_TIMEOUT: Duration = Duration::from_secs(2);
const HID_REOPEN_RETRY_DELAY: Duration = Duration::from_millis(100);
const HID_RECOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const HID_RECOVERY_RETRY_DELAY: Duration = Duration::from_millis(100);
/// At most one USB gadget reset per this interval: each reset also drops
/// virtual media and the USB network, and it cannot help while the host is off.
const HID_RECOVERY_COOLDOWN: Duration = Duration::from_secs(60);
const HID_EVENT_QUEUE_CAPACITY: usize = 200;
const MAX_WS_MESSAGE_BYTES: usize = 16;
const MOUSE_JIGGLER_CONFIG: &str = "/etc/kvm/mouse-jiggler";
const MOUSE_JIGGLER_INTERVAL: Duration = Duration::from_secs(15);
const USB_DEV_SCRIPT: &str = "/etc/init.d/S03usbdev";
const USB_UDC_CLASS: &str = "/sys/class/udc";

const HEARTBEAT_EVENT: u8 = 0;
const KEYBOARD_EVENT: u8 = 1;
const MOUSE_EVENT: u8 = 2;
const JIGGLER_MODE_RELATIVE: &str = "relative";
const JIGGLER_MODE_ABSOLUTE: &str = "absolute";

static HID: LazyLock<Bus<HidDevices>> = LazyLock::new(|| Bus::new(HidDevices::default()));
static MOUSE_JIGGLER: LazyLock<Mutex<MouseJiggler>> =
    LazyLock::new(|| Mutex::new(MouseJiggler::from_config()));
static WS_EVENTS: LazyLock<broadcast::Sender<String>> = LazyLock::new(|| {
    let (tx, _) = broadcast::channel(64);
    tx
});

#[derive(Serialize)]
struct WsEnvelope<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    data: &'a str,
}

#[derive(Default)]
struct HidDevices {
    keyboard: Mutex<Option<File>>,
    relative_mouse: Mutex<Option<File>>,
    absolute_mouse: Mutex<Option<File>>,
    /// When the last gadget reset was attempted.
    recovery: Mutex<Option<Instant>>,
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
        Self::from_config_at(Path::new(MOUSE_JIGGLER_CONFIG))
    }

    fn from_config_at(path: &Path) -> Self {
        let mode = fs::read_to_string(path)
            .ok()
            .map(|value| normalize_jiggler_mode(value.trim()))
            .unwrap_or_else(|| JIGGLER_MODE_RELATIVE.to_string());
        Self {
            enabled: path.exists(),
            running: false,
            mode,
            last_updated: Instant::now(),
        }
    }

    /// Mark a loop as running when the jiggler is enabled and none runs yet.
    /// True means the caller must start that loop.
    fn claim_loop(&mut self) -> bool {
        if !self.enabled || self.running {
            return false;
        }
        self.running = true;
        self.last_updated = Instant::now();
        true
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
        let mut deadline = Instant::now() + HID_REOPEN_TIMEOUT;
        let mut recovered = false;

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
                        if !recovered && should_try_hid_recovery(&err) {
                            match self.recover_usb_device(path) {
                                Ok(()) => {
                                    recovered = true;
                                    deadline = Instant::now() + HID_REOPEN_TIMEOUT;
                                    continue;
                                }
                                // A skipped reset (host off or asleep, or a
                                // reset just done) is expected; do not flood.
                                Err(recovery_err)
                                    if recovery_err.kind() == io::ErrorKind::WouldBlock =>
                                {
                                    tracing::debug!(
                                        path,
                                        error = %err,
                                        reason = %recovery_err,
                                        "HID recovery skipped after write failure"
                                    );
                                }
                                Err(recovery_err) => {
                                    tracing::warn!(
                                        path,
                                        error = %err,
                                        recovery_error = %recovery_err,
                                        "failed to recover HID device after write failure"
                                    );
                                }
                            }
                        }
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

    fn close_all(&self) -> io::Result<()> {
        close_hid_slot(&self.keyboard)?;
        close_hid_slot(&self.relative_mouse)?;
        close_hid_slot(&self.absolute_mouse)
    }

    fn recover_usb_device(&self, path: &str) -> io::Result<()> {
        let _gadget_guard = usb::GADGET_LOCK.try_lock().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "USB gadget operation is in progress",
            )
        })?;
        let mut last_reset = self
            .recovery
            .lock()
            .map_err(|_| io::Error::other("hid recovery lock poisoned"))?;

        let state = read_usb_udc_state().unwrap_or(None);
        match gadget_reset_decision(state.as_deref(), *last_reset, Instant::now()) {
            ResetDecision::NotNeeded => return Ok(()),
            ResetDecision::Skip(reason) => {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, reason));
            }
            ResetDecision::Reset => {}
        }

        tracing::warn!(
            path,
            state = state.as_deref().unwrap_or("unknown"),
            "HID write failed while USB gadget is not configured; resetting USB gadget"
        );
        *last_reset = Some(Instant::now());
        self.close_all()?;
        run_usb_dev_restart()?;
        wait_for_usb_udc_configured(HID_RECOVERY_TIMEOUT)
    }
}

impl Sink for HidDevices {
    fn write(&mut self, report: Report) -> io::Result<()> {
        match report {
            Report::Keyboard(report) => self.write_keyboard(&report),
            Report::Relative(report) => self.write_relative_mouse(&report),
            Report::Absolute(report) => self.write_absolute_mouse(&report),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        self.close_all()
    }
}

#[derive(Clone)]
pub(crate) struct InputOwner {
    lease: Lease<'static, HidDevices>,
}

pub(crate) fn begin_input() -> io::Result<InputOwner> {
    Ok(InputOwner {
        lease: HID.begin()?,
    })
}

/// Statically dispatched action I/O; the real implementation retains a bus
/// lease, while fixtures inject the same ownership core with a recording sink.
pub(crate) trait HidReports {
    fn keyboard(&self, report: &[u8; 8]) -> io::Result<usize>;
    fn absolute(&self, report: &[u8; 6]) -> io::Result<usize>;
    fn settle_keyboard(&self) -> io::Result<usize>;
    fn settle_absolute(&self) -> io::Result<usize>;
    fn finish(&self) -> io::Result<usize>;
}

impl HidReports for InputOwner {
    fn keyboard(&self, report: &[u8; 8]) -> io::Result<usize> {
        touch_mouse_jiggler();
        self.lease.write(Report::Keyboard(*report))
    }
    fn absolute(&self, report: &[u8; 6]) -> io::Result<usize> {
        touch_mouse_jiggler();
        self.lease.write(Report::Absolute(*report))
    }
    fn settle_keyboard(&self) -> io::Result<usize> {
        self.lease.release(Endpoint::Keyboard, true)
    }
    fn settle_absolute(&self) -> io::Result<usize> {
        self.lease.release(Endpoint::Absolute, true)
    }
    fn finish(&self) -> io::Result<usize> {
        self.lease.finish()
    }
}

// The WS executor is statically dispatched over the same ownership bus in
// production and recording fixtures. Session authority is checked under that
// bus lock, not only before queueing a blocking write.
trait WsInput: Clone + Send + Sync + 'static {
    fn write(&self, report: Report, session: &TransportSession) -> io::Result<usize>;
    fn release(&self, endpoint: Endpoint) -> io::Result<usize>;
}

impl WsInput for InputOwner {
    fn write(&self, report: Report, session: &TransportSession) -> io::Result<usize> {
        touch_mouse_jiggler();
        self.lease.write_if(report, || session.is_active())
    }

    fn release(&self, endpoint: Endpoint) -> io::Result<usize> {
        self.lease.release(endpoint, false)
    }
}

pub async fn close_cached_hid_devices() -> io::Result<()> {
    // All callers retain run_exclusive's gadget guard, so at most one cache
    // close is queued. Never wait behind report/recovery I/O on a Tokio worker.
    tokio::task::spawn_blocking(|| HID.close())
        .await
        .map_err(|error| io::Error::other(format!("HID cache close task failed: {error}")))?
}

pub fn broadcast_event(kind: &str, data: &str) {
    if let Some(message) = ws_event_message(kind, data) {
        let _ = WS_EVENTS.send(message);
    }
}

pub async fn connect(
    State(state): State<AppState>,
    current: Option<Extension<CurrentSession>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    let session = TransportSession::capture(&state.config, current)?;
    if !validate_ws_origin(&headers, &state.config) {
        return Err(AppError::Forbidden("invalid websocket origin".to_string()));
    }

    Ok(ws
        .max_message_size(MAX_WS_MESSAGE_BYTES)
        .on_upgrade(move |socket| handle_socket(socket, session)))
}

async fn handle_socket(socket: WebSocket, session: TransportSession) {
    if !session.is_active() {
        return;
    }
    let Ok(owner) = begin_input() else {
        return;
    };
    handle_socket_owned(socket, session, owner).await;
}

async fn handle_socket_owned<Owner: WsInput>(
    socket: WebSocket,
    session: TransportSession,
    owner: Owner,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (keyboard_tx, keyboard_rx) = mpsc::channel(HID_EVENT_QUEUE_CAPACITY);
    let (mouse_tx, mouse_rx) = mpsc::channel(HID_EVENT_QUEUE_CAPACITY);
    let mut workers = tokio::task::JoinSet::new();
    workers.spawn(report_worker(
        keyboard_rx,
        owner.clone(),
        session.clone(),
        &[Endpoint::Keyboard],
    ));
    workers.spawn(report_worker(
        mouse_rx,
        owner,
        session.clone(),
        &[Endpoint::Relative, Endpoint::Absolute],
    ));
    send_capture_status_snapshot(&mut ws_tx, &session).await;

    let mut event_rx = WS_EVENTS.subscribe();
    let event_session = session.clone();
    let event_writer = tokio::spawn(async move {
        loop {
            let message = tokio::select! {
                biased;
                _ = event_session.ended() => break,
                message = event_rx.recv() => match message {
                    Ok(message) => message,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            };
            let sent = tokio::select! {
                biased;
                _ = event_session.ended() => break,
                sent = ws_tx.send(Message::Text(message.into())) => sent,
            };
            if sent.is_err() {
                break;
            }
        }
    });

    let mut clean = true;
    loop {
        let message = tokio::select! {
            biased;
            _ = session.ended() => break,
            finished = workers.join_next() => {
                clean &= matches!(finished, Some(Ok(true)));
                break;
            }
            message = ws_rx.next() => message,
        };
        let Some(Ok(message)) = message else {
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
                let Ok(report) = data[1..].try_into() else {
                    continue;
                };
                if !enqueue_report(&keyboard_tx, Report::Keyboard(report), &session).await {
                    break;
                }
            }
            MOUSE_EVENT => match data.len() - 1 {
                4 => {
                    touch_mouse_jiggler();
                    let Ok(report) = data[1..].try_into() else {
                        continue;
                    };
                    if !enqueue_report(&mouse_tx, Report::Relative(report), &session).await {
                        break;
                    }
                }
                6 => {
                    touch_mouse_jiggler();
                    let Ok(report) = data[1..].try_into() else {
                        continue;
                    };
                    if !enqueue_report(&mouse_tx, Report::Absolute(report), &session).await {
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
    event_writer.abort();
    let _ = event_writer.await;
    while let Some(finished) = workers.join_next().await {
        clean &= matches!(finished, Ok(true));
    }
    tracing::debug!(clean, "HID websocket workers joined");
}

async fn send_capture_status_snapshot(
    ws_tx: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    session: &TransportSession,
) {
    for status in crate::api::stream::capture_status_snapshot() {
        let Ok(data) = serde_json::to_string(&status) else {
            continue;
        };
        let Some(message) = ws_event_message(crate::api::stream::CAPTURE_STATUS_EVENT, &data)
        else {
            continue;
        };
        let sent = tokio::select! {
            biased;
            _ = session.ended() => break,
            sent = ws_tx.send(Message::Text(message.into())) => sent,
        };
        if sent.is_err() {
            break;
        }
    }
}

fn ws_event_message(kind: &str, data: &str) -> Option<String> {
    serde_json::to_string(&WsEnvelope { kind, data }).ok()
}

async fn enqueue_report(
    queue: &mpsc::Sender<Report>,
    report: Report,
    session: &TransportSession,
) -> bool {
    tokio::select! {
        biased;
        _ = session.ended() => false,
        sent = queue.send(report) => sent.is_ok(),
    }
}

async fn report_worker<Owner: WsInput>(
    mut queue: mpsc::Receiver<Report>,
    owner: Owner,
    session: TransportSession,
    endpoints: &'static [Endpoint],
) -> bool {
    loop {
        let report = tokio::select! {
            biased;
            _ = session.ended() => break,
            report = queue.recv() => match report {
                Some(report) => report,
                None => break,
            },
        };
        if queue.is_closed() || !session.is_active() {
            break;
        }
        let writer = owner.clone();
        let authority = session.clone();
        if !write_hid_blocking(move || writer.write(report, &authority)).await {
            drain_hid_queue(&mut queue);
            if !finish_ws_input(&owner, endpoints).await {
                return false;
            }
        }
    }

    // Never execute the revoked/closed connection's pending queue as cleanup.
    // The current I/O is joined first, then only its owned endpoints compensate.
    queue.close();
    finish_ws_input(&owner, endpoints).await
}

async fn finish_ws_input<Owner: WsInput>(owner: &Owner, endpoints: &[Endpoint]) -> bool {
    let mut clean = true;
    for &endpoint in endpoints {
        let writer = owner.clone();
        if !write_hid_blocking(move || writer.release(endpoint)).await {
            clean = false;
        }
    }
    clean
}

async fn write_hid_blocking<F>(write: F) -> bool
where
    F: FnOnce() -> io::Result<usize> + Send + 'static,
{
    matches!(tokio::task::spawn_blocking(write).await, Ok(Ok(_)))
}

fn drain_hid_queue<T>(queue: &mut mpsc::Receiver<T>) -> usize {
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

fn should_try_hid_recovery(err: &io::Error) -> bool {
    is_hid_endpoint_gone_error(err)
        || (is_reopen_retryable_hid_error(err) && !usb_udc_is_configured().unwrap_or(true))
}

fn is_hid_endpoint_gone_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(nix::libc::ENODEV) | Some(nix::libc::ENXIO)
    )
}

fn close_hid_slot(slot: &Mutex<Option<File>>) -> io::Result<()> {
    let mut guard = slot
        .lock()
        .map_err(|_| io::Error::other("hid device lock poisoned"))?;
    if let Some(file) = guard.take() {
        drop(file);
    }
    Ok(())
}

fn usb_udc_is_configured() -> io::Result<bool> {
    Ok(read_usb_udc_state()?.as_deref() == Some("configured"))
}

#[derive(Debug, PartialEq, Eq)]
enum ResetDecision {
    NotNeeded,
    Skip(&'static str),
    Reset,
}

/// Whether a failed HID write may reset the USB gadget. A reset cannot help
/// while the host is off ("not attached"), and while it sleeps ("suspended")
/// it would break wakeup by keyboard. Other states may be a stuck enumeration,
/// reset at most once per cooldown.
fn gadget_reset_decision(
    state: Option<&str>,
    last_reset: Option<Instant>,
    now: Instant,
) -> ResetDecision {
    match state {
        Some("configured") => ResetDecision::NotNeeded,
        Some("not attached") => ResetDecision::Skip("the USB host is not attached"),
        Some("suspended") => ResetDecision::Skip("the USB host is suspended"),
        _ if last_reset
            .is_some_and(|last| now.saturating_duration_since(last) < HID_RECOVERY_COOLDOWN) =>
        {
            ResetDecision::Skip("the USB gadget was reset recently")
        }
        _ => ResetDecision::Reset,
    }
}

fn read_usb_udc_state() -> io::Result<Option<String>> {
    let entries = match fs::read_dir(USB_UDC_CLASS) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    for entry in entries {
        let entry = entry?;
        let state_path = entry.path().join("state");
        match fs::read_to_string(&state_path) {
            Ok(state) => return Ok(Some(state.trim().to_string())),
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        }
    }

    Ok(None)
}

fn run_usb_dev_restart() -> io::Result<()> {
    let output = Command::new(USB_DEV_SCRIPT)
        .arg("restart")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(io::Error::other(format!(
        "{USB_DEV_SCRIPT} restart failed with status {}: {}{}",
        output.status.code().unwrap_or(-1),
        stdout.trim(),
        stderr.trim()
    )))
}

fn wait_for_usb_udc_configured(timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;

    loop {
        let last_state = match read_usb_udc_state()? {
            Some(state) if state == "configured" => return Ok(()),
            Some(state) => state,
            None => String::from("unknown"),
        };

        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "USB gadget did not reach configured state after restart; last state: {}",
                    last_state
                ),
            ));
        }

        thread::sleep(HID_RECOVERY_RETRY_DELAY);
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

pub fn mouse_jiggler_snapshot() -> Result<(bool, String)> {
    let state = MOUSE_JIGGLER
        .lock()
        .map_err(|_| AppError::Internal("mouse jiggler lock poisoned".to_string()))?;
    Ok((state.enabled, state.mode.clone()))
}

pub fn set_mouse_jiggler(enabled: bool, mode: &str) -> Result<()> {
    if enabled {
        let mode = validate_jiggler_mode(mode)?;
        crate::system::files::write_atomic(
            Path::new(MOUSE_JIGGLER_CONFIG),
            mode.as_bytes(),
            0o644,
        )?;

        let should_spawn = {
            let mut state = MOUSE_JIGGLER
                .lock()
                .map_err(|_| AppError::Internal("mouse jiggler lock poisoned".to_string()))?;
            state.enabled = true;
            state.mode = mode;
            state.last_updated = Instant::now();
            state.claim_loop()
        };

        if should_spawn {
            tokio::spawn(mouse_jiggler_loop());
        }
    } else {
        crate::system::files::remove_file(Path::new(MOUSE_JIGGLER_CONFIG))?;
        let mut state = MOUSE_JIGGLER
            .lock()
            .map_err(|_| AppError::Internal("mouse jiggler lock poisoned".to_string()))?;
        state.enabled = false;
        state.mode = JIGGLER_MODE_RELATIVE.to_string();
        state.last_updated = Instant::now();
    }

    Ok(())
}

/// Resume a jiggler that was enabled before the backend restarted. Its setting
/// survives a reboot, so it must run again without being set anew. The frozen
/// app trial never calls this: it drives no input.
pub fn start_persisted_mouse_jiggler() {
    let should_spawn = MOUSE_JIGGLER
        .lock()
        .map(|mut state| state.claim_loop())
        .unwrap_or(false);
    if should_spawn {
        tokio::spawn(mouse_jiggler_loop());
    }
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
    let owner = begin_input()?;
    let (first, second) = if mode == JIGGLER_MODE_ABSOLUTE {
        (
            Report::Absolute([0x00, 0x00, 0x3f, 0x00, 0x3f, 0x00]),
            Report::Absolute([0x00, 0xff, 0x3f, 0xff, 0x3f, 0x00]),
        )
    } else {
        (
            Report::Relative([0x00, 0x0a, 0x0a, 0x00]),
            Report::Relative([0x00, 0xf6, 0xf6, 0x00]),
        )
    };
    if owner.lease.passive_mouse(first, false)? != 0 {
        thread::sleep(Duration::from_millis(100));
        owner.lease.passive_mouse(second, true)?;
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_usb_gadget_is_reset_only_when_it_can_help_and_not_too_often() {
        let now = Instant::now();
        let recently = now.checked_sub(Duration::from_secs(10));
        let long_ago = now.checked_sub(HID_RECOVERY_COOLDOWN + Duration::from_secs(1));
        assert_eq!(
            gadget_reset_decision(Some("configured"), None, now),
            ResetDecision::NotNeeded
        );
        for state in ["not attached", "suspended"] {
            assert!(matches!(
                gadget_reset_decision(Some(state), None, now),
                ResetDecision::Skip(_)
            ));
        }
        for state in [Some("default"), Some("addressed"), Some("powered"), None] {
            assert_eq!(
                gadget_reset_decision(state, None, now),
                ResetDecision::Reset
            );
            assert_eq!(
                gadget_reset_decision(state, long_ago, now),
                ResetDecision::Reset
            );
            if recently.is_some() {
                assert!(matches!(
                    gadget_reset_decision(state, recently, now),
                    ResetDecision::Skip(_)
                ));
            }
        }
    }

    #[test]
    fn a_persisted_jiggler_claims_one_loop_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mouse-jiggler");
        let mut absent = MouseJiggler::from_config_at(&path);
        assert!(!absent.enabled);
        assert!(!absent.claim_loop());

        fs::write(&path, b"absolute\n").unwrap();
        let mut persisted = MouseJiggler::from_config_at(&path);
        assert!(persisted.enabled);
        assert_eq!(persisted.mode, JIGGLER_MODE_ABSOLUTE);
        // A restart finds the setting enabled but no loop running.
        assert!(!persisted.running);
        assert!(persisted.claim_loop());
        assert!(persisted.running);
        // A second start, or enabling it again, does not add a second loop.
        assert!(!persisted.claim_loop());
    }

    #[test]
    fn validates_jiggler_modes() {
        assert_eq!(validate_jiggler_mode("relative").unwrap(), "relative");
        assert_eq!(validate_jiggler_mode("absolute").unwrap(), "absolute");
        assert!(validate_jiggler_mode("diagonal").is_err());
    }
}
