use axum::{Json, extract::State, response::IntoResponse};
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, path::Path, time::Duration};
use tokio::time;

use crate::{
    AppError, Result,
    api::stream,
    error::ApiResponse,
    ffi::kvm,
    state::AppState,
    system::command::{AllowedCommand, run_allowed},
    ws::hid as hid_ws,
};

const BOOT_VERSION_FILE: &str = "/boot/ver";
const APP_VERSION_FILE: &str = "/kvmapp/version";
const DEVICE_KEY_FILE: &str = "/device_key";
const HARDWARE_VERSION_FILE: &str = "/etc/kvm/hw";
const ETC_HOSTNAME_FILE: &str = "/etc/hostname";
const BOOT_HOSTNAME_FILE: &str = "/boot/hostname";
const ETC_HOSTS_FILE: &str = "/etc/hosts";
const WEB_TITLE_FILE: &str = "/etc/kvm/web-title";
const HDMI_DISABLE_FILE: &str = "/etc/kvm/hdmi_disable";
const SSH_STOP_FLAG: &str = "/etc/kvm/ssh_stop";
const OLED_EXIST_FILE: &str = "/etc/kvm/oled_exist";
const OLED_SLEEP_FILE: &str = "/etc/kvm/oled_sleep";
const GO_MEM_LIMIT_FILE: &str = "/etc/kvm/GOMEMLIMIT";
const SWAP_FILE: &str = "/swapfile";
const INITTAB_PATH: &str = "/etc/inittab";
const TEMP_INITTAB_PATH: &str = "/etc/.inittab.tmp";
const SWAP_INITTAB_LINE: &str = "si11::sysinit:/sbin/swapon /swapfile";
const AVAHI_DAEMON_PID: &str = "/run/avahi-daemon/pid";
const AVAHI_DAEMON_SCRIPT: &str = "/etc/init.d/S50avahi-daemon";
const AVAHI_DAEMON_BACKUP_SCRIPT: &str = "/kvmapp/system/init.d/S50avahi-daemon";
const VIRTUAL_NETWORK_FLAG: &str = "/boot/usb.rndis0";
const VIRTUAL_DISK_FLAG: &str = "/boot/usb.disk0";
const VIRTUAL_NETWORK_CONFIG: &str = "/sys/kernel/config/usb_gadget/g0/configs/c.1/rndis.usb0";
const VIRTUAL_DISK_CONFIG: &str = "/sys/kernel/config/usb_gadget/g0/configs/c.1/mass_storage.disk0";

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

pub async fn set_hostname(Json(req): Json<SetHostnameReq>) -> Result<impl IntoResponse> {
    validate_hostname(&req.hostname)?;
    let old_hostname = read_trimmed(ETC_HOSTNAME_FILE).unwrap_or_default();

    if old_hostname != req.hostname {
        if let Ok(hosts) = fs::read_to_string(ETC_HOSTS_FILE) {
            fs::write(ETC_HOSTS_FILE, hosts.replace(&old_hostname, &req.hostname))?;
        }
    }

    fs::write(BOOT_HOSTNAME_FILE, req.hostname.as_bytes())?;
    fs::write(ETC_HOSTNAME_FILE, req.hostname.as_bytes())?;
    let _ = run_allowed(
        AllowedCommand::Hostname,
        ["-F", ETC_HOSTNAME_FILE],
        Duration::from_secs(2),
    )
    .await;

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn set_screen(Json(req): Json<SetScreenReq>) -> Result<impl IntoResponse> {
    stream::set_screen_value(&req.kind, req.value)?;
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
    kvm::set_hdmi(true)?;
    persist_hdmi_enabled()?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn disable_hdmi() -> Result<impl IntoResponse> {
    kvm::set_hdmi(false)?;
    persist_hdmi_disabled()?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn reset_hdmi() -> Result<impl IntoResponse> {
    kvm::set_hdmi(false)?;
    time::sleep(Duration::from_secs(1)).await;
    kvm::set_hdmi(true)?;
    persist_hdmi_enabled()?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_ssh_state() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(EnabledRsp {
        enabled: !Path::new(SSH_STOP_FLAG).exists(),
    })))
}

pub async fn enable_ssh() -> Result<impl IntoResponse> {
    run_checked(
        AllowedCommand::ServiceSshd,
        ["permanent_on"],
        Duration::from_secs(5),
        "enable ssh failed",
    )
    .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn disable_ssh() -> Result<impl IntoResponse> {
    run_checked(
        AllowedCommand::ServiceSshd,
        ["permanent_off"],
        Duration::from_secs(5),
        "disable ssh failed",
    )
    .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
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
    let (flag, config_dir) = match req.device.as_str() {
        "network" => (VIRTUAL_NETWORK_FLAG, VIRTUAL_NETWORK_CONFIG),
        "disk" => (VIRTUAL_DISK_FLAG, VIRTUAL_DISK_CONFIG),
        _ => return Err(AppError::BadRequest("invalid virtual device".to_string())),
    };

    let exists = Path::new(flag).exists();
    run_usbdev("stop").await?;
    if exists {
        remove_dir_if_exists(config_dir)?;
        remove_file_if_exists(flag)?;
    } else {
        fs::write(flag, b"")?;
    }
    run_usbdev("start").await?;

    Ok(Json(ApiResponse::ok(UpdateVirtualDeviceRsp {
        on: Path::new(flag).exists(),
    })))
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

pub async fn terminal(State(state): State<AppState>) -> Result<Json<ApiResponse<()>>> {
    if state.config.auth_disabled() || !state.config.security.allow_terminal {
        return Err(AppError::Forbidden("terminal is disabled".to_string()));
    }

    Err(AppError::Unsupported(
        "terminal websocket is not implemented in the Rust backend".to_string(),
    ))
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

pub async fn set_tls() -> Result<Json<ApiResponse<()>>> {
    Err(AppError::Unsupported(
        "TLS toggle is disabled until the Rust backend implements HTTPS listener support"
            .to_string(),
    ))
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
        if seen.contains(&iface.interface_name) {
            continue;
        }
        let Some(address) = iface.address else {
            continue;
        };
        let Some(ipv4) = address.as_sockaddr_in().map(|addr| addr.ip()) else {
            continue;
        };

        seen.insert(iface.interface_name.clone());
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
    fs::write(TEMP_INITTAB_PATH, content.as_bytes())?;
    fs::rename(TEMP_INITTAB_PATH, INITTAB_PATH)?;
    Ok(())
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

async fn write_gpio_pulse(path: &str, duration: Duration) -> Result<()> {
    fs::write(path, b"1")?;
    time::sleep(duration).await;
    fs::write(path, b"0")?;
    Ok(())
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

fn remove_dir_if_exists(path: &str) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn removes_swap_inittab_lines() {
        let input = "tty::respawn:/bin/login\nsi11::sysinit:/sbin/swapon /swapfile\n";
        assert_eq!(remove_swap_inittab_lines(input), "tty::respawn:/bin/login");
    }
}
