use axum::{
    Extension, Json,
    extract::{
        ConnectInfo, Query, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use nix::{
    ifaddrs::getifaddrs,
    net::if_::InterfaceFlags,
    pty::{ForkptyResult, Winsize, forkpty},
    sys::{
        signal::{Signal, kill},
        wait::waitpid,
    },
    unistd::Pid,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{Read, Write},
    os::fd::AsRawFd,
    path::Path,
    ptr,
    time::{Duration, Instant as StdInstant},
};
use tokio::{sync::mpsc, task, time};
use tracing::{debug, info, warn};

use crate::{
    AppError, Result,
    api::stream,
    auth::{
        compat_crypto::decode_frontend_password,
        session::{SessionEnd, SessionLifetime},
    },
    config::Config,
    error::ApiResponse,
    ffi::kvm,
    http::{
        cookie::{session_cookie, session_cookie_secure},
        middleware::CurrentSession,
        tls,
    },
    state::{AppState, is_allowed_session_lock_duration},
    system::{
        command::{AllowedCommand, run_allowed},
        files, usb,
    },
    update::state_writers::ConfigPermit,
    ws::{hid as hid_ws, origin::validate_ws_origin},
};

const BOOT_VERSION_FILE: &str = "/boot/ver";
const APP_VERSION_FILE: &str = "/kvmapp/version";
const DEVICE_KEY_FILE: &str = "/device_key";
const PROC_UPTIME_FILE: &str = "/proc/uptime";
const HARDWARE_VERSION_FILE: &str = "/etc/kvm/hw";
const ETC_HOSTNAME_FILE: &str = "/etc/hostname";
const BOOT_HOSTNAME_FILE: &str = "/boot/hostname";
const ETC_HOSTS_FILE: &str = "/etc/hosts";
const WEB_TITLE_FILE: &str = "/etc/kvm/web-title";
const HDMI_DISABLE_FILE: &str = "/etc/kvm/hdmi_disable";
const SSH_STOP_FLAG: &str = "/etc/kvm/ssh_stop";
const SSH_PROCESS_NAME: &str = "sshd";
const OLED_EXIST_FILE: &str = "/etc/kvm/oled_exist";
const OLED_SLEEP_FILE: &str = "/etc/kvm/oled_sleep";
const GO_MEM_LIMIT_FILE: &str = "/etc/kvm/GOMEMLIMIT";
const SWAP_FILE: &str = "/swapfile";
const INITTAB_PATH: &str = "/etc/inittab";
const SWAP_INITTAB_LINE: &str = "si11::sysinit:/sbin/swapon /swapfile";
const AVAHI_DAEMON_PID: &str = "/run/avahi-daemon/pid";
const AVAHI_DAEMON_SCRIPT: &str = "/etc/init.d/S50avahi-daemon";
const AVAHI_DAEMON_BACKUP_SCRIPT: &str = "/kvmapp/system/init.d/S50avahi-daemon";
const VIRTUAL_NETWORK_FLAG: &str = "/boot/usb.rndis0";
const VIRTUAL_DISK_FLAG: &str = "/boot/usb.disk0";
const VIRTUAL_NETWORK_CONFIG: &str = "/sys/kernel/config/usb_gadget/g0/configs/c.1/rndis.usb0";
const VIRTUAL_DISK_CONFIG: &str = "/sys/kernel/config/usb_gadget/g0/configs/c.1/mass_storage.disk0";
const TLS_CERT_FILE: &str = "/etc/kvm/server.crt";
const TLS_KEY_FILE: &str = "/etc/kvm/server.key";
const TERMINAL_MAX_MESSAGE_SIZE: usize = 1024;
const TERMINAL_DEFAULT_ROWS: u16 = 24;
const TERMINAL_DEFAULT_COLS: u16 = 80;
const TERMINAL_TICKET_TTL_SECS: u64 = 120;

#[derive(Debug, Serialize)]
pub struct IpInfo {
    pub name: String,
    pub addr: String,
    pub version: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct InfoRsp {
    pub ips: Vec<IpInfo>,
    pub mdns: String,
    pub image: String,
    pub application: String,
    pub uptime: u64,
    #[serde(rename = "deviceKey")]
    pub device_key: String,
}

#[derive(Debug, Serialize)]
pub struct HardwareRsp {
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct HostnameRsp {
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
struct TerminalWinSize {
    rows: u16,
    cols: u16,
}

struct TerminalPty {
    master: File,
    child: Pid,
}

/// Queued terminal input messages before the websocket loop waits.
const TERMINAL_INPUT_QUEUE: usize = 16;

#[derive(Debug, Deserialize)]
pub struct SetHostnameReq {
    pub hostname: String,
}

#[derive(Debug, Deserialize)]
pub struct SetScreenReq {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: i32,
}

#[derive(Debug, Serialize)]
pub struct WebTitleRsp {
    pub title: String,
}

#[derive(Debug, Deserialize)]
pub struct SetWebTitleReq {
    pub title: String,
}

#[derive(Debug, Deserialize)]
pub struct SetTlsReq {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetTerminalReq {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct TerminalUnlockReq {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct TerminalUnlockRsp {
    pub ticket: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
}

#[derive(Debug, Deserialize)]
pub struct TerminalConnectQuery {
    pub ticket: String,
}

#[derive(Debug, Serialize)]
pub struct SessionLockRsp {
    pub duration: u64,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SetSessionLockReq {
    pub duration: u64,
}

#[derive(Debug, Deserialize)]
pub struct SetGpioReq {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub duration: u64,
}

#[derive(Debug, Serialize)]
pub struct GpioRsp {
    pub pwr: bool,
    pub hdd: bool,
}

#[derive(Debug, Serialize)]
pub struct EnabledRsp {
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct OledRsp {
    pub exist: bool,
    pub sleep: i32,
}

#[derive(Debug, Deserialize)]
pub struct SetOledReq {
    pub sleep: i32,
}

#[derive(Debug, Serialize)]
pub struct VirtualDeviceRsp {
    pub network: bool,
    pub media: bool,
    pub disk: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateVirtualDeviceReq {
    pub device: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateVirtualDeviceRsp {
    pub on: bool,
}

#[derive(Debug, Serialize)]
pub struct MemoryLimitRsp {
    pub enabled: bool,
    pub limit: i64,
}

#[derive(Debug, Deserialize)]
pub struct SetMemoryLimitReq {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct SwapRsp {
    pub size: i64,
}

#[derive(Debug, Deserialize)]
pub struct SetSwapReq {
    #[serde(default)]
    pub size: i64,
}

#[derive(Debug, Serialize)]
pub struct MouseJigglerRsp {
    pub enabled: bool,
    pub mode: String,
}

#[derive(Debug, Deserialize)]
pub struct SetMouseJigglerReq {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: String,
}

pub async fn get_info() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(InfoRsp {
        ips: get_ips(),
        mdns: get_mdns(),
        image: get_image_version(),
        application: read_trimmed(APP_VERSION_FILE).unwrap_or_else(|| "1.0.0".to_string()),
        uptime: get_uptime_seconds(),
        device_key: read_trimmed(DEVICE_KEY_FILE).unwrap_or_default(),
    })))
}

pub async fn get_hardware() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(HardwareRsp {
        version: get_hardware_version(),
    })))
}

pub async fn get_hostname() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(HostnameRsp {
        hostname: read_trimmed(ETC_HOSTNAME_FILE).unwrap_or_default(),
    })))
}

pub async fn set_hostname(
    State(state): State<AppState>,
    Json(req): Json<SetHostnameReq>,
) -> Result<impl IntoResponse> {
    validate_hostname(&req.hostname)?;
    let permit = state.writers.configuration()?;
    let hostname = req.hostname;
    permit
        .run(move |writer| async move {
            writer
                .blocking(move |_| {
                    let old_hostname = read_trimmed(ETC_HOSTNAME_FILE).unwrap_or_default();
                    if old_hostname != hostname
                        && let Ok(hosts) = fs::read_to_string(ETC_HOSTS_FILE)
                        && let Some(hosts) = rename_host_entries(&hosts, &old_hostname, &hostname)
                    {
                        files::write_atomic(Path::new(ETC_HOSTS_FILE), hosts.as_bytes(), 0o644)?;
                    }
                    fs::write(BOOT_HOSTNAME_FILE, hostname.as_bytes())?;
                    files::write_atomic(Path::new(ETC_HOSTNAME_FILE), hostname.as_bytes(), 0o644)
                })
                .await?;
            let _ = writer
                .command(
                    AllowedCommand::Hostname,
                    ["-F", ETC_HOSTNAME_FILE],
                    Duration::from_secs(2),
                )
                .await;
            Ok(())
        })
        .await?;

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

/// Rename `old` where it is a whole host name on an `/etc/hosts` entry: never
/// inside another name, in the address field or in a comment. `None` when
/// nothing changes, which includes an empty `old`.
fn rename_host_entries(hosts: &str, old: &str, new: &str) -> Option<String> {
    if old.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(hosts.len() + new.len());
    let mut changed = false;
    for line in hosts.split_inclusive('\n') {
        let (entry, comment) = line.split_at(line.find('#').unwrap_or(line.len()));
        let mut field = 0;
        let mut start = None;
        let mut push = |token: &str, field: usize, out: &mut String| {
            if field > 0 && token == old {
                out.push_str(new);
                changed = true;
            } else {
                out.push_str(token);
            }
        };
        for (index, character) in entry.char_indices() {
            if character.is_whitespace() {
                if let Some(begin) = start.take() {
                    push(&entry[begin..index], field, &mut out);
                    field += 1;
                }
                out.push(character);
            } else if start.is_none() {
                start = Some(index);
            }
        }
        if let Some(begin) = start {
            push(&entry[begin..], field, &mut out);
        }
        out.push_str(comment);
    }
    changed.then_some(out)
}

pub async fn set_screen(Json(req): Json<SetScreenReq>) -> Result<impl IntoResponse> {
    let (kind, value) = (req.kind.clone(), req.value);
    stream::libkvm(move || stream::set_screen_value(&kind, value)).await?;
    info!(kind = %req.kind, value = req.value, "updated screen setting");
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_web_title() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(WebTitleRsp {
        title: read_trimmed(WEB_TITLE_FILE).unwrap_or_default(),
    })))
}

pub async fn set_web_title(Json(req): Json<SetWebTitleReq>) -> Result<impl IntoResponse> {
    if req.title.is_empty() || req.title == "NanoKVM" {
        match fs::remove_file(WEB_TITLE_FILE) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    } else {
        if req.title.len() > 128 || req.title.contains(['\n', '\r']) {
            return Err(AppError::BadRequest("invalid web title".to_string()));
        }
        fs::write(WEB_TITLE_FILE, req.title.as_bytes())?;
    }

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_gpio() -> Result<impl IntoResponse> {
    let gpio = hardware_gpio();
    let pwr = read_gpio(&gpio.power_led)?;
    let hdd = gpio
        .hdd_led
        .as_deref()
        .map(read_gpio)
        .transpose()?
        .unwrap_or(false);

    Ok(Json(ApiResponse::ok(GpioRsp { pwr, hdd })))
}

pub async fn set_gpio(Json(req): Json<SetGpioReq>) -> Result<impl IntoResponse> {
    let gpio = hardware_gpio();
    let device = match req.kind.as_str() {
        "power" => gpio.power,
        "reset" => gpio.reset,
        _ => return Err(AppError::BadRequest("invalid power event".to_string())),
    };
    let duration = if req.duration == 0 {
        Duration::from_millis(800)
    } else {
        Duration::from_millis(req.duration.clamp(50, 5_000))
    };

    write_gpio_pulse(&device, duration).await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_hdmi_state() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(EnabledRsp {
        enabled: !Path::new(HDMI_DISABLE_FILE).exists(),
    })))
}

pub async fn enable_hdmi() -> Result<impl IntoResponse> {
    stream::libkvm(|| kvm::set_hdmi(true)).await?;
    persist_hdmi_enabled()?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn disable_hdmi() -> Result<impl IntoResponse> {
    stream::libkvm(|| kvm::set_hdmi(false)).await?;
    persist_hdmi_disabled()?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn reset_hdmi() -> Result<impl IntoResponse> {
    reset_hdmi_capture(Path::new(HDMI_DISABLE_FILE).exists()).await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

/// Off, 1 s, on, for a capture that is on. A capture the user disabled is
/// refused by name and stays disabled: a reset pulses, it does not persist a
/// setting. A lost client must not leave HDMI capture switched off.
async fn reset_hdmi_capture(disabled: bool) -> Result<()> {
    if disabled {
        return Err(AppError::BadRequest(
            "HDMI capture is disabled; enable it before a reset".to_string(),
        ));
    }
    stream::owned_interval(
        || kvm::set_hdmi(false).map(drop),
        Duration::from_secs(1),
        || kvm::set_hdmi(true).map(drop),
    )
    .await
}

pub async fn get_ssh_state() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(EnabledRsp {
        enabled: ssh_enabled().await,
    })))
}

pub async fn enable_ssh() -> Result<impl IntoResponse> {
    if ssh_enabled().await {
        return Ok(Json(ApiResponse::ok(EnabledRsp { enabled: true })));
    }

    let result = run_checked(
        AllowedCommand::ServiceSshd,
        ["permanent_on"],
        Duration::from_secs(5),
        "enable ssh failed",
    )
    .await;
    wait_for_ssh_state(true, Duration::from_secs(3)).await;
    let enabled = ssh_enabled().await;
    if let Err(err) = result
        && !enabled
    {
        return Err(err);
    }
    Ok(Json(ApiResponse::ok(EnabledRsp { enabled })))
}

pub async fn disable_ssh() -> Result<impl IntoResponse> {
    if ssh_stop_requested() && !sshd_is_running().await {
        return Ok(Json(ApiResponse::ok(EnabledRsp { enabled: false })));
    }

    let result = run_checked(
        AllowedCommand::ServiceSshd,
        ["permanent_off"],
        Duration::from_secs(5),
        "disable ssh failed",
    )
    .await;
    wait_for_ssh_state(false, Duration::from_secs(3)).await;
    let enabled = ssh_enabled().await;
    if let Err(err) = result
        && (enabled || !ssh_stop_requested())
    {
        return Err(err);
    }
    Ok(Json(ApiResponse::ok(EnabledRsp { enabled })))
}

async fn ssh_enabled() -> bool {
    !ssh_stop_requested() && sshd_is_running().await
}

fn ssh_stop_requested() -> bool {
    Path::new(SSH_STOP_FLAG).exists()
}

async fn sshd_is_running() -> bool {
    match run_allowed(
        AllowedCommand::Pidof,
        [SSH_PROCESS_NAME],
        Duration::from_secs(2),
    )
    .await
    {
        Ok(output) => output.status == 0 && !output.stdout.is_empty(),
        Err(err) => {
            debug!(error = %err, "failed to check sshd process");
            false
        }
    }
}

async fn wait_for_ssh_state(enabled: bool, timeout: Duration) {
    let deadline = StdInstant::now() + timeout;
    loop {
        if ssh_enabled().await == enabled {
            return;
        }
        if StdInstant::now() >= deadline {
            return;
        }
        time::sleep(Duration::from_millis(200)).await;
    }
}

pub async fn get_mdns_state() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(EnabledRsp {
        enabled: avahi_daemon_pid().is_some(),
    })))
}

pub async fn enable_mdns() -> Result<impl IntoResponse> {
    if avahi_daemon_pid().is_some() {
        return Ok(Json(ApiResponse::<()>::ok_empty()));
    }

    if Path::new(AVAHI_DAEMON_BACKUP_SCRIPT).exists() {
        fs::copy(AVAHI_DAEMON_BACKUP_SCRIPT, AVAHI_DAEMON_SCRIPT)?;
    }
    run_checked(
        AllowedCommand::ServiceAvahiDaemon,
        ["start"],
        Duration::from_secs(5),
        "enable mdns failed",
    )
    .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn disable_mdns() -> Result<impl IntoResponse> {
    let Some(pid) = avahi_daemon_pid() else {
        return Ok(Json(ApiResponse::<()>::ok_empty()));
    };
    if !valid_pid(&pid) {
        return Err(AppError::Internal("invalid avahi pid".to_string()));
    }

    run_checked(
        AllowedCommand::Kill,
        ["-9", pid.as_str()],
        Duration::from_secs(2),
        "disable mdns failed",
    )
    .await?;
    remove_file_if_exists(AVAHI_DAEMON_PID)?;
    remove_file_if_exists(AVAHI_DAEMON_SCRIPT)?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_oled() -> Result<impl IntoResponse> {
    if !Path::new(OLED_EXIST_FILE).exists() {
        return Ok(Json(ApiResponse::ok(OledRsp {
            exist: false,
            sleep: 0,
        })));
    }

    let sleep = read_trimmed(OLED_SLEEP_FILE)
        .and_then(|value| value.parse::<i32>().ok())
        .unwrap_or(0);
    Ok(Json(ApiResponse::ok(OledRsp { exist: true, sleep })))
}

pub async fn set_oled(Json(req): Json<SetOledReq>) -> Result<impl IntoResponse> {
    if req.sleep < 0 || req.sleep > 24 * 60 * 60 {
        return Err(AppError::BadRequest("invalid OLED sleep".to_string()));
    }
    fs::write(OLED_SLEEP_FILE, req.sleep.to_string().as_bytes())?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_virtual_device() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(VirtualDeviceRsp {
        network: Path::new(VIRTUAL_NETWORK_FLAG).exists(),
        media: false,
        disk: Path::new(VIRTUAL_DISK_FLAG).exists(),
    })))
}

pub async fn update_virtual_device(
    Json(req): Json<UpdateVirtualDeviceReq>,
) -> Result<impl IntoResponse> {
    let on = usb::run_exclusive(update_virtual_device_locked(req)).await?;
    Ok(Json(ApiResponse::ok(UpdateVirtualDeviceRsp { on })))
}

async fn update_virtual_device_locked(req: UpdateVirtualDeviceReq) -> Result<bool> {
    let (flag, config_dir) = match req.device.as_str() {
        "network" => (VIRTUAL_NETWORK_FLAG, VIRTUAL_NETWORK_CONFIG),
        "disk" => (VIRTUAL_DISK_FLAG, VIRTUAL_DISK_CONFIG),
        _ => return Err(AppError::BadRequest("invalid virtual device".to_string())),
    };

    let old_flag = match fs::read(flag) {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err.into()),
    };
    hid_ws::close_cached_hid_devices().await?;
    if let Err(stop_error) = run_usbdev("stop").await {
        // stop may already have disconnected UDC before its later failure.
        // Attempt recovery even though no configuration change was made.
        run_usbdev("start").await?;
        return Err(stop_error);
    }
    let change = (|| -> Result<()> {
        if old_flag.is_some() {
            // A configfs function link is a symlink, not a directory tree.
            remove_file_if_exists(config_dir)?;
            remove_file_if_exists(flag)?;
        } else {
            fs::write(flag, b"")?;
        }
        Ok(())
    })();
    // Always try to reconnect, including after a failed flag/config change.
    let restart = run_usbdev("start").await;
    if change.is_err() || restart.is_err() {
        // A failed start may have partly linked/rebound functions. Disconnect
        // again before restoring flags and retrying, rather than editing a
        // live composite gadget.
        let restop = run_usbdev("stop").await;
        let restore = match old_flag {
            Some(contents) => fs::write(flag, contents).map_err(AppError::from),
            None => remove_file_if_exists(flag).and_then(|()| remove_file_if_exists(config_dir)),
        };
        let recovery = run_usbdev("start").await;
        restore?;
        restop?;
        recovery?;
        change?;
        restart?;
    }
    Ok(Path::new(flag).exists())
}

pub async fn reboot() -> Result<impl IntoResponse> {
    run_checked(
        AllowedCommand::Reboot,
        std::iter::empty::<&str>(),
        Duration::from_secs(2),
        "reboot failed",
    )
    .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn terminal(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    Query(query): Query<TerminalConnectQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    if state.config.auth_disabled() || !state.terminal_enabled() {
        return Err(AppError::Forbidden("terminal is disabled".to_string()));
    }
    if !validate_ws_origin(&headers, &state.config) {
        return Err(AppError::Forbidden("invalid websocket origin".to_string()));
    }
    if !state
        .terminal_tickets
        .consume(&query.ticket, &session)
        .await
    {
        return Err(AppError::Forbidden(
            "terminal unlock is required".to_string(),
        ));
    }

    Ok(ws
        .max_message_size(TERMINAL_MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| handle_terminal_socket(socket, session.lifetime()))
        .into_response())
}

// The root shell lives only as long as the session that unlocked it: logout,
// a password change or expiry end it, while a renewal keeps it open.
async fn handle_terminal_socket(mut socket: WebSocket, lifetime: SessionLifetime) {
    let terminal = match spawn_terminal_pty() {
        Ok(terminal) => terminal,
        Err(err) => {
            warn!(error = ?err, "failed to start terminal pty");
            let _ = socket
                .send(Message::Close(Some(CloseFrame {
                    code: 1011,
                    reason: "failed to start terminal".into(),
                })))
                .await;
            return;
        }
    };

    let TerminalPty { master, child } = terminal;
    let mut pty_reader = match master.try_clone() {
        Ok(file) => file,
        Err(err) => {
            warn!(error = ?err, "failed to clone terminal pty");
            cleanup_terminal_process_blocking(child);
            return;
        }
    };
    let pty_winsize = match master.try_clone() {
        Ok(file) => file,
        Err(err) => {
            warn!(error = ?err, "failed to clone terminal pty");
            cleanup_terminal_process_blocking(child);
            return;
        }
    };
    let (pty_writer, writer_task) = spawn_pty_writer(master);
    let (pty_tx, mut pty_rx) = mpsc::channel::<Vec<u8>>(16);
    let reader_task = task::spawn_blocking(move || {
        let mut buffer = [0_u8; TERMINAL_MAX_MESSAGE_SIZE];
        loop {
            match pty_reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if pty_tx.blocking_send(buffer[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let (mut ws_tx, mut ws_rx) = socket.split();
    debug!("terminal websocket connected");
    let session_end = lifetime.ended();
    tokio::pin!(session_end);

    loop {
        tokio::select! {
            end = &mut session_end => {
                let _ = ws_tx.send(Message::Close(Some(CloseFrame {
                    code: 1008,
                    reason: terminal_session_end_reason(end).into(),
                }))).await;
                break;
            }
            data = pty_rx.recv() => {
                let Some(data) = data else {
                    break;
                };
                if ws_tx.send(Message::Binary(data.into())).await.is_err() {
                    break;
                }
            }
            message = ws_rx.next() => {
                let message = match message {
                    Some(Ok(message)) => message,
                    Some(Err(err)) => {
                        debug!(error = ?err, "terminal websocket read failed");
                        break;
                    }
                    None => break,
                };

                match message {
                    Message::Text(text) => {
                        // A shell that stopped reading fills the queue and then
                        // holds this loop, never a runtime worker; the session
                        // end still wins over the wait.
                        let delivered = tokio::select! {
                            biased;
                            end = &mut session_end => Err(end),
                            sent = pty_writer.send(text.as_bytes().to_vec()) => Ok(sent.is_ok()),
                        };
                        match delivered {
                            Ok(true) => {}
                            Ok(false) => break,
                            Err(end) => {
                                let _ = ws_tx.send(Message::Close(Some(CloseFrame {
                                    code: 1008,
                                    reason: terminal_session_end_reason(end).into(),
                                }))).await;
                                break;
                            }
                        }
                    }
                    Message::Binary(data) => {
                        if let Some(size) = parse_terminal_winsize(&data) {
                            set_terminal_winsize(&pty_winsize, &size);
                        }
                    }
                    Message::Ping(data) => {
                        if ws_tx.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Close(_) => break,
                }
            }
        }
    }

    drop(pty_writer);
    drop(pty_winsize);
    let _ = task::spawn_blocking(move || cleanup_terminal_process_blocking(child)).await;
    let _ = reader_task.await;
    let _ = writer_task.await;
    debug!("terminal websocket disconnected");
}

pub async fn unlock_terminal(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    ConnectInfo(addr): ConnectInfo<tls::ClientAddr>,
    Json(req): Json<TerminalUnlockReq>,
) -> Result<impl IntoResponse> {
    if state.config.auth_disabled() || !state.terminal_enabled() {
        return Err(AppError::Forbidden("terminal is disabled".to_string()));
    }
    if req.username != session.username {
        return Err(AppError::InvalidCredentials);
    }

    let source = addr.0.ip();
    let source_ip = source.to_string();
    let limiter_username = format!("terminal:{}", session.username);
    {
        let mut limiter = state.login_limiter.write().await;
        if limiter.check(source, &limiter_username) {
            return Err(AppError::RateLimited(
                "terminal unlock locked due to too many failed attempts".to_string(),
            ));
        }
    }

    let password = zeroize::Zeroizing::new(decode_frontend_password(&req.password)?);
    if !crate::api::account::verify_bounded(
        &state.login_hashing,
        &state.accounts,
        &session.username,
        password,
    )
    .await?
    {
        let mut limiter = state.login_limiter.write().await;
        let locked = limiter.record_failure(source, &limiter_username);
        if locked {
            warn!(source_ip, username = ?session.username, "terminal unlock lockout threshold reached");
        }
        return Err(AppError::InvalidCredentials);
    }

    state
        .login_limiter
        .write()
        .await
        .record_success(source, &limiter_username);
    let ticket = state
        .terminal_tickets
        .issue(&session, TERMINAL_TICKET_TTL_SECS)
        .await;

    Ok(Json(ApiResponse::ok(TerminalUnlockRsp {
        ticket: ticket.token,
        expires_at: ticket.expires_at_unix,
    })))
}

pub async fn get_terminal_enabled(State(state): State<AppState>) -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(EnabledRsp {
        enabled: state.terminal_enabled(),
    })))
}

pub async fn set_terminal_enabled(
    State(state): State<AppState>,
    Json(req): Json<SetTerminalReq>,
) -> Result<impl IntoResponse> {
    let permit = state.writers.configuration()?;
    permit
        .run(move |writer| async move {
            writer
                .blocking(move |permit| {
                    let mut config = Config::read_for(permit)?;
                    config.security.allow_terminal = req.enabled;
                    config.write(permit)?;
                    state.set_terminal_enabled(req.enabled);
                    Ok(())
                })
                .await
        })
        .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_session_lock(State(state): State<AppState>) -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(SessionLockRsp {
        duration: state.session_lock_duration(),
        expires_at: None,
    })))
}

pub async fn set_session_lock(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    Json(req): Json<SetSessionLockReq>,
) -> Result<impl IntoResponse> {
    if !is_allowed_session_lock_duration(req.duration) {
        return Err(AppError::BadRequest(
            "unsupported session lock duration".to_string(),
        ));
    }

    let permit = state.writers.configuration()?;
    permit
        .run(move |writer| async move {
            let runtime = state.clone();
            writer
                .blocking(move |permit| {
                    let mut config = Config::read_for(permit)?;
                    config.security.access_token_duration = req.duration;
                    config.write(permit)?;
                    runtime.set_session_lock_duration(req.duration);
                    Ok(())
                })
                .await?;
            let session = state.sessions.retime(&session.token, req.duration).await;
            let mut headers = HeaderMap::new();
            if let Some(session) = &session {
                headers.insert(
                    axum::http::header::SET_COOKIE,
                    session_cookie(
                        &session.token,
                        req.duration,
                        session_cookie_secure(&state.config.proto),
                    )?,
                );
            }
            Ok((
                headers,
                Json(ApiResponse::ok(SessionLockRsp {
                    duration: req.duration,
                    expires_at: session.map(|session| session.expires_at_unix),
                })),
            ))
        })
        .await
}

fn terminal_session_end_reason(end: SessionEnd) -> &'static str {
    match end {
        SessionEnd::Revoked => "terminal session revoked",
        SessionEnd::Expired => "terminal session expired",
        SessionEnd::Uncertain => "terminal session ended",
    }
}

/// PTY input goes through a thread of its own. A shell that stopped reading
/// (flow control, a stuck foreground job) blocks the write, and that must
/// stall this terminal only, not a runtime worker and every request on it.
fn spawn_pty_writer(mut pty: File) -> (mpsc::Sender<Vec<u8>>, task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(TERMINAL_INPUT_QUEUE);
    let task = task::spawn_blocking(move || {
        while let Some(data) = rx.blocking_recv() {
            if pty.write_all(&data).is_err() {
                break;
            }
        }
    });
    (tx, task)
}

fn spawn_terminal_pty() -> std::io::Result<TerminalPty> {
    let winsize = Winsize {
        ws_row: TERMINAL_DEFAULT_ROWS,
        ws_col: TERMINAL_DEFAULT_COLS,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    match unsafe { forkpty(Some(&winsize), None) }
        .map_err(|err| std::io::Error::other(format!("forkpty failed: {err}")))?
    {
        ForkptyResult::Child => exec_terminal_shell(),
        ForkptyResult::Parent { child, master } => Ok(TerminalPty {
            master: File::from(master),
            child,
        }),
    }
}

fn exec_terminal_shell() -> ! {
    let shell = b"/bin/sh\0";
    unsafe {
        nix::libc::execl(
            shell.as_ptr().cast(),
            shell.as_ptr().cast(),
            ptr::null::<nix::libc::c_char>(),
        );
        nix::libc::_exit(127);
    }
}

fn parse_terminal_winsize(data: &[u8]) -> Option<Winsize> {
    let win_size: TerminalWinSize = serde_json::from_slice(data).ok()?;
    if win_size.rows == 0 || win_size.cols == 0 {
        return None;
    }
    Some(Winsize {
        ws_row: win_size.rows,
        ws_col: win_size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    })
}

fn set_terminal_winsize(pty: &File, winsize: &Winsize) {
    let result = unsafe { nix::libc::ioctl(pty.as_raw_fd(), nix::libc::TIOCSWINSZ, winsize) };
    if result < 0 {
        debug!(
            error = ?std::io::Error::last_os_error(),
            "failed to resize terminal pty"
        );
    }
}

// The shell leads its own session (forkpty). Until it is reaped its pid cannot
// be reused, so every live process with that session ID was started from this
// terminal: end them all, not only the shell. A process that called setsid()
// itself is beyond this reach; there are no cgroups on this kernel.
fn cleanup_terminal_process_blocking(child: Pid) {
    signal_terminal_session(child, Signal::SIGTERM);
    std::thread::sleep(Duration::from_millis(50));
    signal_terminal_session(child, Signal::SIGKILL);
    let _ = waitpid(child, None);
}

/// Bound on the /proc entries scanned for one terminal's session.
const MAX_PROC_ENTRIES: usize = 4096;

fn signal_terminal_session(session: Pid, signal: Signal) {
    let _ = kill(session, signal);
    let Ok(entries) = fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten().take(MAX_PROC_ENTRIES) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw)
        else {
            continue;
        };
        // Pin the process before reading its session: a pid reused after
        // this open names another process, and the pidfd signal then fails.
        let Ok(process) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
        else {
            continue;
        };
        if session_of(pid.as_raw_nonzero().get()) == Some(session.as_raw()) {
            let _ = rustix::process::pidfd_send_signal(
                &process,
                rustix::process::Signal::from_named_raw(signal as i32)
                    .unwrap_or(rustix::process::Signal::KILL),
            );
        }
    }
}

// Field 6 of /proc/<pid>/stat. The command name may hold spaces and ')', so
// fields are counted after its last ')': state, ppid, pgrp, session.
fn session_of(pid: i32) -> Option<i32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(3)?.parse().ok()
}

pub async fn get_memory_limit() -> Result<impl IntoResponse> {
    if !Path::new(GO_MEM_LIMIT_FILE).exists() {
        return Ok(Json(ApiResponse::ok(MemoryLimitRsp {
            enabled: false,
            limit: 0,
        })));
    }

    let limit = read_memory_limit()?;
    Ok(Json(ApiResponse::ok(MemoryLimitRsp {
        enabled: true,
        limit,
    })))
}

pub async fn set_memory_limit(Json(req): Json<SetMemoryLimitReq>) -> Result<impl IntoResponse> {
    if req.enabled {
        let limit = normalize_memory_limit(req.limit)?;
        fs::write(GO_MEM_LIMIT_FILE, limit.to_string().as_bytes())?;
    } else {
        remove_file_if_exists(GO_MEM_LIMIT_FILE)?;
    }

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_swap() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(SwapRsp {
        size: get_swap_size(),
    })))
}

pub async fn set_swap(Json(req): Json<SetSwapReq>) -> Result<impl IntoResponse> {
    validate_swap_size(req.size)?;
    let current = get_swap_size();
    if req.size == current {
        return Ok(Json(ApiResponse::<()>::ok_empty()));
    }

    if req.size == 0 {
        disable_swap().await?;
        disable_swap_inittab()?;
    } else {
        enable_swap(req.size).await?;
        enable_swap_inittab()?;
    }

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_mouse_jiggler() -> Result<impl IntoResponse> {
    let (enabled, mode) = hid_ws::mouse_jiggler_snapshot()?;
    Ok(Json(ApiResponse::ok(MouseJigglerRsp { enabled, mode })))
}

pub async fn set_mouse_jiggler(Json(req): Json<SetMouseJigglerReq>) -> Result<impl IntoResponse> {
    hid_ws::set_mouse_jiggler(req.enabled, &req.mode)?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn set_tls(
    State(state): State<AppState>,
    Json(req): Json<SetTlsReq>,
) -> Result<Json<ApiResponse<()>>> {
    let permit = state.writers.configuration()?;
    permit
        .run(move |writer| async move {
            let mut config = writer
                .blocking(move |permit| {
                    let mut config = Config::read_for(permit)?;
                    if req.enabled {
                        tls::prepare_server_cert(TLS_CERT_FILE, TLS_KEY_FILE, tls_names())?;
                        config.proto = "https".to_string();
                        config.cert.crt = TLS_CERT_FILE.to_string();
                        config.cert.key = TLS_KEY_FILE.to_string();
                    }
                    Ok(config)
                })
                .await?;
            if !req.enabled {
                state
                    .firewall
                    .force_moderate_mode(&state.writers, &writer)
                    .await?;
                config.proto = "http".to_string();
            }
            writer.blocking(move |permit| config.write(permit)).await?;
            schedule_device_reboot(writer, "TLS protocol update");
            Ok(())
        })
        .await?;

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

/// Names for a new self-signed certificate: loopback, and the device's host
/// name with its mDNS name when the name is a valid host label.
pub fn tls_names() -> Vec<String> {
    let mut names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(hostname) = read_trimmed(ETC_HOSTNAME_FILE)
        && validate_hostname(&hostname).is_ok()
    {
        names.push(format!("{hostname}.local"));
        names.push(hostname);
    }
    names
}

fn schedule_device_reboot(writer: ConfigPermit, reason: &'static str) {
    tokio::spawn(async move {
        time::sleep(Duration::from_millis(1000)).await;
        match writer
            .command(
                AllowedCommand::Reboot,
                std::iter::empty::<&str>(),
                Duration::from_secs(2),
            )
            .await
        {
            Ok(output) if output.status == 0 => {
                tracing::info!(reason, "scheduled device reboot completed")
            }
            Ok(output) => tracing::warn!(
                reason,
                status = output.status,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "scheduled device reboot failed"
            ),
            Err(err) => {
                tracing::warn!(reason, error = ?err, "failed to reboot device")
            }
        }
        drop(writer);
    });
}

fn get_ips() -> Vec<IpInfo> {
    let mut ips = Vec::new();
    let mut seen = HashSet::new();
    let Ok(addrs) = getifaddrs() else {
        return ips;
    };

    for iface in addrs {
        if !iface.flags.contains(InterfaceFlags::IFF_UP) {
            continue;
        }
        let Some(kind) = interface_type(&iface.interface_name) else {
            continue;
        };
        let Some(address) = iface.address else {
            continue;
        };
        let Some(ipv4) = address.as_sockaddr_in().map(|addr| addr.ip()) else {
            if let Some(ipv6) = address.as_sockaddr_in6().map(|addr| addr.ip()) {
                if ipv6.is_loopback() {
                    continue;
                }
                if !seen.insert(format!("{}-ipv6-{ipv6}", iface.interface_name)) {
                    continue;
                }
                ips.push(IpInfo {
                    name: iface.interface_name,
                    addr: ipv6.to_string(),
                    version: "IPv6".to_string(),
                    kind: kind.to_string(),
                });
            }
            continue;
        };

        if !seen.insert(format!("{}-ipv4-{ipv4}", iface.interface_name)) {
            continue;
        }
        ips.push(IpInfo {
            name: iface.interface_name,
            addr: ipv4.to_string(),
            version: "IPv4".to_string(),
            kind: kind.to_string(),
        });
    }

    ips
}

fn interface_type(name: &str) -> Option<&'static str> {
    if name.starts_with("eth") || name.starts_with("en") {
        Some("Wired")
    } else if name.starts_with("wlan") || name.starts_with("wl") {
        Some("Wireless")
    } else {
        None
    }
}

fn get_mdns() -> String {
    read_trimmed(ETC_HOSTNAME_FILE)
        .map(|hostname| format!("{hostname}.local"))
        .unwrap_or_default()
}

fn get_image_version() -> String {
    let image = read_trimmed(BOOT_VERSION_FILE).unwrap_or_default();
    match image.as_str() {
        "2024-06-23-20-59-2d2bfb.img" => "v1.0.0".to_string(),
        "2024-07-23-20-18-587710.img" => "v1.1.0".to_string(),
        "2024-08-08-19-44-bef2ca.img" => "v1.2.0".to_string(),
        "2024-11-13-09-59-9c961a.img" => "v1.3.0".to_string(),
        "2025-02-17-19-08-3649fe.img" => "v1.4.0".to_string(),
        "2025-04-17-14-21-98d17d.img" => "v1.4.1".to_string(),
        "2026-01-05-1_4_1.img" => "v1.4.2".to_string(),
        _ => image,
    }
}

fn get_uptime_seconds() -> u64 {
    read_trimmed(PROC_UPTIME_FILE)
        .and_then(|uptime| {
            uptime
                .split_whitespace()
                .next()
                .and_then(|seconds| seconds.split('.').next())
                .and_then(|seconds| seconds.parse::<u64>().ok())
        })
        .unwrap_or_default()
}

fn get_hardware_version() -> String {
    match read_trimmed(HARDWARE_VERSION_FILE).as_deref() {
        Some("beta") => "Beta",
        Some("pcie") => "PCIE",
        Some("alpha") | None => "Alpha",
        Some(_) => "Alpha",
    }
    .to_string()
}

fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty() || hostname.len() > 63 {
        return Err(AppError::BadRequest("invalid hostname".to_string()));
    }
    if hostname.starts_with('-') || hostname.ends_with('-') {
        return Err(AppError::BadRequest("invalid hostname".to_string()));
    }
    if !hostname
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(AppError::BadRequest("invalid hostname".to_string()));
    }
    Ok(())
}

fn read_trimmed(path: &str) -> Option<String> {
    if !Path::new(path).exists() {
        return None;
    }
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_memory_limit() -> Result<i64> {
    let value = read_trimmed(GO_MEM_LIMIT_FILE)
        .ok_or_else(|| AppError::Internal("memory limit file is empty".to_string()))?;
    value
        .parse::<i64>()
        .map_err(|_| AppError::Internal("invalid memory limit".to_string()))
}

fn normalize_memory_limit(limit: i64) -> Result<i64> {
    if !(1..=4096).contains(&limit) {
        return Err(AppError::BadRequest("invalid memory limit".to_string()));
    }
    Ok(limit.max(50))
}

fn get_swap_size() -> i64 {
    fs::metadata(SWAP_FILE)
        .map(|metadata| (metadata.len() / 1024 / 1024) as i64)
        .unwrap_or(0)
}

fn validate_swap_size(size: i64) -> Result<()> {
    match size {
        0 | 64 | 128 | 256 | 512 => Ok(()),
        _ => Err(AppError::BadRequest("invalid swap size".to_string())),
    }
}

async fn enable_swap(size: i64) -> Result<()> {
    if get_swap_size() > 0 {
        disable_swap().await?;
    }

    run_checked(
        AllowedCommand::Fallocate,
        vec!["-l".to_string(), format!("{size}M"), SWAP_FILE.to_string()],
        Duration::from_secs(15),
        "create swap file failed",
    )
    .await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(SWAP_FILE, fs::Permissions::from_mode(0o600))?;
    }
    run_checked(
        AllowedCommand::Mkswap,
        [SWAP_FILE],
        Duration::from_secs(10),
        "format swap failed",
    )
    .await?;
    run_checked(
        AllowedCommand::Swapon,
        [SWAP_FILE],
        Duration::from_secs(10),
        "enable swap failed",
    )
    .await
}

async fn disable_swap() -> Result<()> {
    if is_swap_active() {
        run_checked(
            AllowedCommand::Swapoff,
            [SWAP_FILE],
            Duration::from_secs(10),
            "disable swap failed",
        )
        .await?;
    }
    remove_file_if_exists(SWAP_FILE)
}

fn is_swap_active() -> bool {
    fs::read_to_string("/proc/swaps")
        .ok()
        .map(|content| {
            content
                .lines()
                .skip(1)
                .filter_map(|line| line.split_whitespace().next())
                .any(|path| path == SWAP_FILE)
        })
        .unwrap_or(false)
}

fn enable_swap_inittab() -> Result<()> {
    let input = fs::read_to_string(INITTAB_PATH)?;
    let mut output = remove_swap_inittab_lines(&input);
    if !output.is_empty() {
        output.push('\n');
    }
    output.push_str(SWAP_INITTAB_LINE);
    output.push('\n');
    write_inittab(&output)
}

fn disable_swap_inittab() -> Result<()> {
    let input = fs::read_to_string(INITTAB_PATH)?;
    let output = remove_swap_inittab_lines(&input);
    write_inittab(&output)
}

fn remove_swap_inittab_lines(input: &str) -> String {
    input
        .lines()
        .filter(|line| !line.trim_end().ends_with(SWAP_FILE))
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_inittab(content: &str) -> Result<()> {
    files::write_atomic(Path::new(INITTAB_PATH), content.as_bytes(), 0o644)
}

#[derive(Debug, Clone)]
struct HardwareGpio {
    reset: String,
    power: String,
    power_led: String,
    hdd_led: Option<String>,
}

fn hardware_gpio() -> HardwareGpio {
    match read_trimmed(HARDWARE_VERSION_FILE).as_deref() {
        Some("beta") | Some("pcie") => HardwareGpio {
            reset: "/sys/class/gpio/gpio505/value".to_string(),
            power: "/sys/class/gpio/gpio503/value".to_string(),
            power_led: "/sys/class/gpio/gpio504/value".to_string(),
            hdd_led: None,
        },
        _ => HardwareGpio {
            reset: "/sys/class/gpio/gpio507/value".to_string(),
            power: "/sys/class/gpio/gpio503/value".to_string(),
            power_led: "/sys/class/gpio/gpio504/value".to_string(),
            hdd_led: Some("/sys/class/gpio/gpio505/value".to_string()),
        },
    }
}

fn read_gpio(path: &str) -> Result<bool> {
    let value = fs::read_to_string(path)?;
    let value = value.trim().parse::<i32>().map_err(|_| {
        AppError::Internal(format!(
            "invalid gpio value in {}",
            Path::new(path).display()
        ))
    })?;
    Ok(value == 0)
}

/// Lines with a pulse in progress. A second pulse on the same line would cut
/// the first one short, or turn one long press into two.
static PULSING: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Press a power or reset line for `duration`, then release it. The pulse runs
/// in its own task, so a lost client cannot leave the button pressed. If that
/// task is dropped, as at backend shutdown, its guard still releases the line.
async fn write_gpio_pulse(path: &str, duration: Duration) -> Result<()> {
    let line = PulseLine::claim(path)?;
    let (reply, done) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        drop(reply.send(pulse(line, duration).await));
    });
    done.await
        .map_err(|_| AppError::Internal("gpio pulse ended without a result".to_string()))?
}

async fn pulse(line: PulseLine, duration: Duration) -> Result<()> {
    let pressed = Pressed::press(line)?;
    time::sleep(duration).await;
    pressed.release()
}

/// Exclusive use of one GPIO line until dropped.
struct PulseLine(String);

impl PulseLine {
    fn claim(path: &str) -> Result<Self> {
        let mut pulsing = PULSING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if pulsing.iter().any(|line| line == path) {
            return Err(AppError::Conflict(
                "a power or reset pulse is already in progress".to_string(),
            ));
        }
        pulsing.push(path.to_string());
        Ok(Self(path.to_string()))
    }
}

impl Drop for PulseLine {
    fn drop(&mut self) {
        let mut pulsing = PULSING
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pulsing.retain(|line| line != &self.0);
    }
}

/// A pressed line. Dropped without `release`, it still writes 0.
struct Pressed(Option<PulseLine>);

impl Pressed {
    fn press(line: PulseLine) -> Result<Self> {
        if let Err(error) = fs::write(&line.0, b"1") {
            // The line state is unknown after a failed write: release it.
            let _ = fs::write(&line.0, b"0");
            return Err(error.into());
        }
        Ok(Self(Some(line)))
    }

    fn release(mut self) -> Result<()> {
        match self.0.take() {
            Some(line) => release(&line.0),
            None => Ok(()),
        }
    }
}

impl Drop for Pressed {
    fn drop(&mut self) {
        if let Some(line) = self.0.take() {
            let _ = release(&line.0);
        }
    }
}

fn release(path: &str) -> Result<()> {
    fs::write(path, b"0").map_err(|error| {
        tracing::error!(%error, "gpio line release failed; the button may stay pressed");
        AppError::from(error)
    })
}

fn persist_hdmi_enabled() -> Result<()> {
    remove_file_if_exists(HDMI_DISABLE_FILE)
}

fn persist_hdmi_disabled() -> Result<()> {
    fs::write(HDMI_DISABLE_FILE, b"")?;
    Ok(())
}

fn avahi_daemon_pid() -> Option<String> {
    read_trimmed(AVAHI_DAEMON_PID).filter(|pid| valid_pid(pid))
}

fn valid_pid(pid: &str) -> bool {
    !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit())
}

async fn run_usbdev(action: &'static str) -> Result<()> {
    run_checked(
        AllowedCommand::ServiceUsbDev,
        [action],
        Duration::from_secs(10),
        "usb gadget update failed",
    )
    .await
}

async fn run_checked<I, S>(
    command: AllowedCommand,
    args: I,
    timeout: Duration,
    message: &'static str,
) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = run_allowed(command, args, timeout).await?;
    if output.status != 0 {
        return Err(AppError::Internal(format!(
            "{message}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
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

    #[tokio::test(flavor = "current_thread")]
    async fn a_reset_keeps_a_disabled_capture_disabled() {
        // Refused by name before any libkvm call; on this host libkvm cannot be
        // loaded, so reaching it would be a different error.
        match reset_hdmi_capture(true).await {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("disabled"), "{message}")
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_pty_blocks_only_the_terminal_writer_thread() {
        let (read_end, write_end) = nix::unistd::pipe().unwrap();
        let (writer, task) = spawn_pty_writer(File::from(write_end));
        // More than the pipe buffer, with a reader that never reads: the
        // writer thread blocks in write_all.
        let chunk = vec![b'x'; 64 * 1024];
        let mut queued = 0;
        while writer.try_send(chunk.clone()).is_ok() {
            queued += 1;
        }
        assert!(queued >= 2, "{queued}");
        // This is the only runtime thread: a timer firing shows no write ran
        // on it.
        time::timeout(
            Duration::from_millis(300),
            time::sleep(Duration::from_millis(50)),
        )
        .await
        .expect("the runtime kept running while the pty writer was stuck");
        assert!(!task.is_finished());
        drop(writer);
        drop(read_end);
        time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the writer ends once its reader is gone")
            .unwrap();
    }

    #[test]
    fn a_new_hostname_replaces_only_whole_host_names() {
        let hosts = "127.0.0.1\tlocalhost\n127.0.1.1\tkvm-1234 kvm-1234.local nanokvm\n# kvm-1234 was here\n10.0.0.2 kvm-1234";
        assert_eq!(
            rename_host_entries(hosts, "kvm-1234", "desk").as_deref(),
            Some(
                "127.0.0.1\tlocalhost\n127.0.1.1\tdesk kvm-1234.local nanokvm\n# kvm-1234 was here\n10.0.0.2 desk"
            )
        );
        // RC12 replaced substrings, and an empty old name everywhere.
        assert_eq!(rename_host_entries(hosts, "kvm", "desk"), None);
        assert_eq!(rename_host_entries(hosts, "", "desk"), None);
        // An address field is never rewritten.
        assert_eq!(rename_host_entries("kvm 127.0.0.1\n", "kvm", "desk"), None);
    }

    fn gpio_line(dir: &tempfile::TempDir, name: &str) -> (std::path::PathBuf, String) {
        let line = dir.path().join(name);
        fs::write(&line, b"0").unwrap();
        let path = line.to_str().unwrap().to_string();
        (line, path)
    }

    async fn pressed_within(line: &Path, limit: Duration) -> bool {
        let started = StdInstant::now();
        while started.elapsed() < limit {
            if fs::read(line).unwrap() == b"1" {
                return true;
            }
            time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pulse_is_released_even_when_its_client_goes_away() {
        let dir = tempfile::tempdir().unwrap();
        let (line, path) = gpio_line(&dir, "power");
        let request = tokio::spawn({
            let path = path.clone();
            async move { write_gpio_pulse(&path, Duration::from_millis(300)).await }
        });
        assert!(pressed_within(&line, Duration::from_secs(1)).await);
        // An overlapping pulse on the same line is refused, not queued.
        assert!(matches!(
            write_gpio_pulse(&path, Duration::from_millis(50)).await,
            Err(AppError::Conflict(_))
        ));
        // The HTTP handler's future is dropped when its client goes away.
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        time::sleep(Duration::from_millis(500)).await;
        assert_eq!(fs::read(&line).unwrap(), b"0");
        // The line is free again once the pulse has ended.
        write_gpio_pulse(&path, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(fs::read(&line).unwrap(), b"0");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pulses_on_different_lines_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let (power, power_path) = gpio_line(&dir, "power");
        let (reset, reset_path) = gpio_line(&dir, "reset");
        let first =
            tokio::spawn(
                async move { write_gpio_pulse(&power_path, Duration::from_millis(300)).await },
            );
        assert!(pressed_within(&power, Duration::from_secs(1)).await);
        write_gpio_pulse(&reset_path, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(fs::read(&reset).unwrap(), b"0");
        first.await.unwrap().unwrap();
        assert_eq!(fs::read(&power).unwrap(), b"0");
    }

    #[test]
    fn a_pulse_dropped_at_shutdown_still_releases_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let (line, path) = gpio_line(&dir, "reset");
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .build()
            .unwrap();
        runtime.spawn({
            let path = path.clone();
            async move { write_gpio_pulse(&path, Duration::from_secs(30)).await }
        });
        let started = StdInstant::now();
        while fs::read(&line).unwrap() != b"1" {
            assert!(started.elapsed() < Duration::from_secs(1));
            std::thread::sleep(Duration::from_millis(5));
        }
        // Dropping the runtime drops the pulse task in the middle of its press.
        drop(runtime);
        assert_eq!(fs::read(&line).unwrap(), b"0");
        drop(PulseLine::claim(&path).unwrap());
    }

    #[test]
    fn validates_numeric_pids_only() {
        assert!(valid_pid("12345"));
        assert!(!valid_pid(""));
        assert!(!valid_pid("12x45"));
        assert!(!valid_pid("1;reboot"));
    }

    #[test]
    fn beta_gpio_omits_hdd_led() {
        let gpio = HardwareGpio {
            reset: "/sys/class/gpio/gpio505/value".to_string(),
            power: "/sys/class/gpio/gpio503/value".to_string(),
            power_led: "/sys/class/gpio/gpio504/value".to_string(),
            hdd_led: None,
        };
        assert_eq!(gpio.reset, "/sys/class/gpio/gpio505/value");
        assert!(gpio.hdd_led.is_none());
    }

    #[test]
    fn normalizes_memory_limit() {
        assert_eq!(normalize_memory_limit(75).unwrap(), 75);
        assert_eq!(normalize_memory_limit(1).unwrap(), 50);
        assert!(normalize_memory_limit(0).is_err());
        assert!(normalize_memory_limit(4097).is_err());
    }

    #[test]
    fn validates_swap_sizes() {
        assert!(validate_swap_size(0).is_ok());
        assert!(validate_swap_size(64).is_ok());
        assert!(validate_swap_size(256).is_ok());
        assert!(validate_swap_size(123).is_err());
    }

    #[test]
    fn parses_terminal_resize_messages() {
        let size = parse_terminal_winsize(br#"{"rows":40,"cols":120}"#).unwrap();
        assert_eq!(size.ws_row, 40);
        assert_eq!(size.ws_col, 120);
        assert!(parse_terminal_winsize(br#"{"rows":0,"cols":120}"#).is_none());
        assert!(parse_terminal_winsize(b"not json").is_none());
    }

    #[test]
    fn removes_swap_inittab_lines() {
        let input = "tty::respawn:/bin/login\nsi11::sysinit:/sbin/swapon /swapfile\n";
        assert_eq!(remove_swap_inittab_lines(input), "tty::respawn:/bin/login");
    }

    // A real listener and PTY: logout ends the unlocked terminal and every
    // process started from it, including a job that ignores SIGHUP.
    #[tokio::test]
    async fn logout_closes_the_terminal_and_ends_its_whole_pty_session() {
        use crate::http::middleware::protected;
        use axum::{Router, middleware::from_fn_with_state, routing::get};
        use tokio_tungstenite::tungstenite::{
            Message as WsMessage, client::IntoClientRequest, protocol::frame::coding::CloseCode,
        };

        let mut config = Config {
            stun: "disable".into(),
            ..Config::default()
        };
        config.security.allow_terminal = true;
        let state = AppState::new(config).await.unwrap();
        let login = state.sessions.issue("admin", 60).await;
        let ticket = state.terminal_tickets.issue(&login, 120).await;
        let router = Router::new()
            .route("/api/vm/terminal", get(terminal))
            .route_layer(from_fn_with_state(state.clone(), protected))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut request = format!("ws://{address}/api/vm/terminal?ticket={}", ticket.token)
            .into_client_request()
            .unwrap();
        let headers = request.headers_mut();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", login.token).parse().unwrap(),
        );
        headers.insert(
            axum::http::header::ORIGIN,
            format!("http://{address}").parse().unwrap(),
        );
        let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        socket
            .send(WsMessage::Text(
                "(trap '' HUP; exec sleep 300) & echo \"JOB:$!:END\"\n".into(),
            ))
            .await
            .unwrap();
        let mut output = String::new();
        let job: i32 = time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(WsMessage::Binary(bytes)) =
                    socket.next().await.map(|message| message.unwrap())
                {
                    output.push_str(&String::from_utf8_lossy(&bytes));
                }
                if let Some(pid) = output
                    .split("JOB:")
                    .skip(1)
                    .find_map(|rest| rest.split(":END").next()?.parse().ok())
                {
                    return pid;
                }
            }
        })
        .await
        .expect("the job announced its pid");
        assert!(Path::new(&format!("/proc/{job}")).exists());
        state.sessions.revoke(&login.token).await;
        let closed = time::timeout(Duration::from_secs(5), async {
            loop {
                match socket.next().await {
                    Some(Ok(WsMessage::Close(frame))) => return frame,
                    Some(Ok(_)) => continue,
                    other => panic!("terminal ended without a close frame: {other:?}"),
                }
            }
        })
        .await
        .expect("logout closes the terminal")
        .expect("a close frame");
        assert_eq!(closed.code, CloseCode::Policy);
        assert_eq!(closed.reason.as_str(), "terminal session revoked");
        // The job ignored SIGHUP; only the session-wide cleanup ends it.
        time::timeout(Duration::from_secs(5), async {
            while session_of(job).is_some() && !zombie(job) {
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the terminal's background job is gone");
        server.abort();
    }

    // A killed orphan may linger unreaped under a non-reaping parent.
    fn zombie(pid: i32) -> bool {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                let rest = &stat[stat.rfind(')')? + 1..];
                rest.split_whitespace().next().map(|state| state == "Z")
            })
            .unwrap_or(true)
    }
}
