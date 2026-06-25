use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use std::{io::Write, net::IpAddr};

use crate::{
    AppError, Result,
    error::ApiResponse,
    system::command::{self, AllowedCommand},
};

const TAILSCALE_PATH: &str = "/usr/bin/tailscale";
const TAILSCALED_PATH: &str = "/usr/sbin/tailscaled";
const TAILSCALED_SCRIPT: &str = "/etc/init.d/S98tailscaled";
const TAILSCALED_SCRIPT_BACKUP: &str = "/kvmapp/system/init.d/S98tailscaled";
const GO_MEM_LIMIT_FILE: &str = "/etc/kvm/GOMEMLIMIT";
const GO_MEM_LIMIT_FOR_TAILSCALE: &str = "75\n";
const TAILSCALE_STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const TAILSCALE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TailscaleState {
    NotInstall,
    NotRunning,
    NotLogin,
    Stopped,
    Running,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct GetTailscaleStatusRsp {
    pub state: TailscaleState,
    pub name: String,
    pub ip: String,
    pub account: String,
}

#[derive(Debug, Deserialize)]
struct RawTailscaleStatus {
    #[serde(rename = "BackendState")]
    backend_state: String,
    #[serde(rename = "Self", default)]
    self_node: RawTailscaleSelf,
    #[serde(rename = "CurrentTailnet", default)]
    current_tailnet: RawTailscaleTailnet,
}

#[derive(Debug, Default, Deserialize)]
struct RawTailscaleSelf {
    #[serde(rename = "HostName", default)]
    host_name: String,
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_ips: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawTailscaleTailnet {
    #[serde(rename = "Name", default)]
    name: String,
}

pub async fn get_status() -> Result<impl IntoResponse> {
    if !is_installed() {
        return Ok(Json(ApiResponse::ok(not_installed_status())));
    }

    let output = command::run_allowed(
        AllowedCommand::Tailscale,
        ["status", "--json"],
        TAILSCALE_STATUS_TIMEOUT,
    )
    .await;

    let Ok(output) = output else {
        return Ok(Json(ApiResponse::ok(not_running_status())));
    };
    if output.status != 0 {
        return Ok(Json(ApiResponse::ok(not_running_status())));
    }

    match parse_status_output(&output.stdout) {
        Ok(status) => Ok(Json(ApiResponse::ok(status))),
        Err(err) => {
            tracing::warn!(error = %err, "failed to parse tailscale status");
            Ok(Json(ApiResponse::ok(not_running_status())))
        }
    }
}

pub async fn start() -> Result<impl IntoResponse> {
    ensure_installed()?;
    install_tailscaled_script()?;
    run_service(["start"], "start tailscale").await?;
    ensure_go_mem_limit()?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn restart() -> Result<impl IntoResponse> {
    ensure_installed()?;
    install_tailscaled_script()?;
    run_service(["restart"], "restart tailscale").await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn stop() -> Result<impl IntoResponse> {
    ensure_installed()?;
    run_service(["stop"], "stop tailscale").await?;
    remove_file_if_exists(TAILSCALED_SCRIPT)?;
    remove_file_if_exists(GO_MEM_LIMIT_FILE)?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn up() -> Result<impl IntoResponse> {
    ensure_installed()?;
    run_tailscale(["up", "--accept-dns=false"], "tailscale up").await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn down() -> Result<impl IntoResponse> {
    ensure_installed()?;
    run_tailscale(["down"], "tailscale down").await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn logout() -> Result<impl IntoResponse> {
    ensure_installed()?;
    run_tailscale(["logout"], "tailscale logout").await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

fn is_installed() -> bool {
    fs::metadata(TAILSCALE_PATH)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
        && fs::metadata(TAILSCALED_PATH)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
}

fn ensure_installed() -> Result<()> {
    if is_installed() {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "tailscale is not installed".to_string(),
        ))
    }
}

fn install_tailscaled_script() -> Result<()> {
    let metadata = fs::symlink_metadata(TAILSCALED_SCRIPT_BACKUP)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::BadRequest(
            "invalid tailscaled init script".to_string(),
        ));
    }
    let data = fs::read(TAILSCALED_SCRIPT_BACKUP)?;
    write_file(
        Path::new(TAILSCALED_SCRIPT),
        &data,
        metadata.permissions().mode() & 0o777,
    )
}

async fn run_service<const N: usize>(args: [&str; N], action: &str) -> Result<()> {
    let output = command::run_allowed(
        AllowedCommand::ServiceTailscaled,
        args,
        TAILSCALE_COMMAND_TIMEOUT,
    )
    .await?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(AppError::Internal(command_error(action, output)))
    }
}

async fn run_tailscale<const N: usize>(args: [&str; N], action: &str) -> Result<()> {
    let output =
        command::run_allowed(AllowedCommand::Tailscale, args, TAILSCALE_COMMAND_TIMEOUT).await?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(AppError::Internal(command_error(action, output)))
    }
}

fn ensure_go_mem_limit() -> Result<()> {
    if Path::new(GO_MEM_LIMIT_FILE).exists() {
        return Ok(());
    }
    write_file(
        Path::new(GO_MEM_LIMIT_FILE),
        GO_MEM_LIMIT_FOR_TAILSCALE.as_bytes(),
        0o644,
    )
}

fn parse_status_output(output: &[u8]) -> serde_json::Result<GetTailscaleStatusRsp> {
    let raw = String::from_utf8_lossy(output);
    let json_start = raw.find('{').unwrap_or(0);
    let status: RawTailscaleStatus = serde_json::from_str(&raw[json_start..])?;
    Ok(status_response(status))
}

fn status_response(status: RawTailscaleStatus) -> GetTailscaleStatusRsp {
    let state = match status.backend_state.as_str() {
        "NoState" | "Starting" => TailscaleState::NotRunning,
        "NeedsLogin" | "NeedsMachineAuth" | "InUseOtherUser" => TailscaleState::NotLogin,
        "Running" => TailscaleState::Running,
        "Stopped" => TailscaleState::Stopped,
        _ => TailscaleState::NotRunning,
    };

    GetTailscaleStatusRsp {
        state,
        name: status.self_node.host_name,
        ip: first_ipv4(&status.self_node.tailscale_ips).unwrap_or_default(),
        account: status.current_tailnet.name,
    }
}

fn first_ipv4(ips: &[String]) -> Option<String> {
    ips.iter().find_map(|ip| match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(ip) => Some(ip.to_string()),
        IpAddr::V6(_) => None,
    })
}

fn not_installed_status() -> GetTailscaleStatusRsp {
    empty_status(TailscaleState::NotInstall)
}

fn not_running_status() -> GetTailscaleStatusRsp {
    empty_status(TailscaleState::NotRunning)
}

fn empty_status(state: TailscaleState) -> GetTailscaleStatusRsp {
    GetTailscaleStatusRsp {
        state,
        name: String::new(),
        ip: String::new(),
        account: String::new(),
    }
}

fn write_file(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = tmp_path_for(path);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    file.write_all(content)?;
    file.flush()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

fn tmp_path_for(path: &Path) -> std::path::PathBuf {
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    path.with_file_name(format!(".{filename}.{}.{}.tmp", std::process::id(), stamp))
}

fn remove_file_if_exists(path: &str) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn command_error(message: &str, output: crate::system::command::CommandOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr.trim();
    if !detail.is_empty() {
        format!("{message}: {detail}")
    } else {
        let detail = stdout.trim();
        if detail.is_empty() {
            message.to_string()
        } else {
            format!("{message}: {detail}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prefixed_running_status() {
        let parsed = parse_status_output(
            br#"noise before json
{
  "BackendState": "Running",
  "Self": {
    "HostName": "kvm-bd3e",
    "TailscaleIPs": ["fd7a:115c:a1e0::1", "100.64.1.2"]
  },
  "CurrentTailnet": { "Name": "example.ts.net" }
}"#,
        )
        .unwrap();

        assert_eq!(parsed.state, TailscaleState::Running);
        assert_eq!(parsed.name, "kvm-bd3e");
        assert_eq!(parsed.ip, "100.64.1.2");
        assert_eq!(parsed.account, "example.ts.net");
    }

    #[test]
    fn maps_login_required_state() {
        let parsed = parse_status_output(br#"{"BackendState":"NeedsLogin"}"#).unwrap();

        assert_eq!(parsed.state, TailscaleState::NotLogin);
        assert_eq!(parsed.ip, "");
    }

    #[test]
    fn formats_temporary_paths_next_to_target() {
        let path = tmp_path_for(Path::new("/etc/init.d/S98tailscaled"));
        assert_eq!(path.parent(), Some(Path::new("/etc/init.d")));
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".S98tailscaled.")
        );
    }
}
