use axum::{Json, response::IntoResponse};
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, path::Path, time::Duration};

use crate::{
    AppError, Result,
    api::stream,
    error::ApiResponse,
    system::command::{AllowedCommand, run_allowed},
};

const BOOT_VERSION_FILE: &str = "/boot/ver";
const APP_VERSION_FILE: &str = "/kvmapp/version";
const DEVICE_KEY_FILE: &str = "/device_key";
const HARDWARE_VERSION_FILE: &str = "/etc/kvm/hw";
const ETC_HOSTNAME_FILE: &str = "/etc/hostname";
const BOOT_HOSTNAME_FILE: &str = "/boot/hostname";
const ETC_HOSTS_FILE: &str = "/etc/hosts";
const WEB_TITLE_FILE: &str = "/etc/kvm/web-title";

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
