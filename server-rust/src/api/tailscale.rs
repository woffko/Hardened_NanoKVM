use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use std::{io::Write, net::IpAddr};
use tokio::task;

use crate::{
    AppError, Result,
    error::ApiResponse,
    system::command::{self, AllowedCommand},
    update::archive::extract_tar_gz_safe,
};

const TAILSCALE_ORIGINAL_URL: &str =
    "https://pkgs.tailscale.com/stable/tailscale_latest_riscv64.tgz";
const TAILSCALE_WORKSPACE: &str = "/root/.tailscale";
const TAILSCALE_ARCHIVE_NAME: &str = "tailscale_riscv64.tgz";
const TAILSCALE_PATH: &str = "/usr/bin/tailscale";
const TAILSCALED_PATH: &str = "/usr/sbin/tailscaled";
const TAILSCALED_SCRIPT: &str = "/etc/init.d/S98tailscaled";
const TAILSCALED_SCRIPT_BACKUP: &str = "/kvmapp/system/init.d/S98tailscaled";
const GO_MEM_LIMIT_FILE: &str = "/etc/kvm/GOMEMLIMIT";
const GO_MEM_LIMIT_FOR_TAILSCALE: &str = "75\n";
const TAILSCALE_STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const TAILSCALE_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const TAILSCALE_INSTALL_TIMEOUT: Duration = Duration::from_secs(600);
const TAILSCALE_LOGIN_TIMEOUT: Duration = Duration::from_secs(600);

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

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct LoginTailscaleRsp {
    pub url: String,
}

#[derive(Debug, Deserialize)]
struct RawTailscaleStatus {
    #[serde(rename = "BackendState")]
    backend_state: String,
    #[serde(rename = "Self", default)]
    self_node: Option<RawTailscaleSelf>,
    #[serde(rename = "CurrentTailnet", default)]
    current_tailnet: Option<RawTailscaleTailnet>,
}

#[derive(Debug, Default, Deserialize)]
struct RawTailscaleSelf {
    #[serde(rename = "HostName", default)]
    host_name: String,
    #[serde(rename = "TailscaleIPs", default)]
    tailscale_ips: Option<Vec<String>>,
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

pub async fn install() -> Result<impl IntoResponse> {
    if !is_installed() {
        if let Err(err) = install_tailscale().await {
            tracing::error!(error = %err, "failed to install tailscale");
            return Ok(Json(ApiResponse::<()>::err(-1, "install failed")));
        }

        if let Err(err) = start_service().await {
            tracing::warn!(error = %err, "failed to start tailscale after install");
        }
    }

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn uninstall() -> Result<impl IntoResponse> {
    let _ = run_service(["stop"], "stop tailscale").await;
    let _ = remove_file_if_exists(TAILSCALED_SCRIPT);
    let _ = remove_file_if_exists(GO_MEM_LIMIT_FILE);
    let _ = remove_file_if_exists(TAILSCALE_PATH);
    let _ = remove_file_if_exists(TAILSCALED_PATH);

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn start() -> Result<impl IntoResponse> {
    match start_service().await {
        Ok(()) => Ok(Json(ApiResponse::<()>::ok_empty())),
        Err(err) => {
            tracing::error!(error = %err, "failed to start tailscale");
            Ok(Json(ApiResponse::<()>::err(-1, "start failed")))
        }
    }
}

pub async fn restart() -> Result<impl IntoResponse> {
    match restart_service().await {
        Ok(()) => Ok(Json(ApiResponse::<()>::ok_empty())),
        Err(err) => {
            tracing::error!(error = %err, "failed to restart tailscale");
            Ok(Json(ApiResponse::<()>::err(-1, "restart failed")))
        }
    }
}

pub async fn stop() -> Result<impl IntoResponse> {
    match stop_service().await {
        Ok(()) => Ok(Json(ApiResponse::<()>::ok_empty())),
        Err(err) => {
            tracing::error!(error = %err, "failed to stop tailscale");
            Ok(Json(ApiResponse::<()>::err(-1, "stop failed")))
        }
    }
}

pub async fn up() -> Result<impl IntoResponse> {
    match up_service().await {
        Ok(()) => Ok(Json(ApiResponse::<()>::ok_empty())),
        Err(err) => {
            tracing::error!(error = %err, "failed to run tailscale up");
            Ok(Json(ApiResponse::<()>::err(-1, "tailscale up failed")))
        }
    }
}

pub async fn down() -> Result<impl IntoResponse> {
    match down_service().await {
        Ok(()) => Ok(Json(ApiResponse::<()>::ok_empty())),
        Err(err) => {
            tracing::error!(error = %err, "failed to run tailscale down");
            Ok(Json(ApiResponse::<()>::err(-1, "tailscale down failed")))
        }
    }
}

pub async fn login() -> Result<axum::response::Response> {
    let mut status = raw_status().await;
    if status.is_err() {
        let _ = start_service().await;
        status = raw_status().await;
    }

    let Ok(status) = status else {
        tracing::error!("failed to get tailscale status before login");
        return Ok(Json(ApiResponse::<()>::err(-1, "unknown status")).into_response());
    };

    if status.backend_state == "Running" {
        return Ok(Json(ApiResponse::ok(LoginTailscaleRsp::default())).into_response());
    }

    match login_service().await {
        Ok(url) => {
            if let Err(err) = ensure_go_mem_limit() {
                tracing::warn!(error = %err, "failed to set tailscale memory limit after login");
            }
            Ok(Json(ApiResponse::ok(LoginTailscaleRsp { url })).into_response())
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to run tailscale login");
            Ok(Json(ApiResponse::<()>::err(-2, "login failed")).into_response())
        }
    }
}

pub async fn logout() -> Result<impl IntoResponse> {
    match logout_service().await {
        Ok(()) => Ok(Json(ApiResponse::<()>::ok_empty())),
        Err(err) => {
            tracing::error!(error = %err, "failed to run tailscale logout");
            Ok(Json(ApiResponse::<()>::err(-1, "logout failed")))
        }
    }
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

async fn install_tailscale() -> Result<()> {
    prepare_workspace()?;
    let _cleanup = WorkspaceCleanup;

    let archive_path = Path::new(TAILSCALE_WORKSPACE).join(TAILSCALE_ARCHIVE_NAME);
    download_tailscale(&archive_path).await?;

    let workspace = PathBuf::from(TAILSCALE_WORKSPACE);
    let extract_archive = archive_path.clone();
    let top_dir = task::spawn_blocking(move || extract_tar_gz_safe(&extract_archive, &workspace))
        .await
        .map_err(|err| AppError::Internal(format!("tailscale extract task failed: {err}")))??;

    install_binary(&top_dir.join("tailscale"), Path::new(TAILSCALE_PATH))?;
    install_binary(&top_dir.join("tailscaled"), Path::new(TAILSCALED_PATH))?;
    Ok(())
}

async fn start_service() -> Result<()> {
    ensure_installed()?;
    install_tailscaled_script()?;
    run_service(["start"], "start tailscale").await?;
    ensure_go_mem_limit()
}

async fn restart_service() -> Result<()> {
    ensure_installed()?;
    install_tailscaled_script()?;
    run_service(["restart"], "restart tailscale").await
}

async fn stop_service() -> Result<()> {
    ensure_installed()?;
    run_service(["stop"], "stop tailscale").await?;
    remove_file_if_exists(TAILSCALED_SCRIPT)?;
    remove_file_if_exists(GO_MEM_LIMIT_FILE)
}

async fn up_service() -> Result<()> {
    ensure_installed()?;
    run_tailscale(["up", "--accept-dns=false"], "tailscale up").await
}

async fn down_service() -> Result<()> {
    ensure_installed()?;
    run_tailscale(["down"], "tailscale down").await
}

async fn logout_service() -> Result<()> {
    ensure_installed()?;
    run_tailscale(["logout"], "tailscale logout").await
}

async fn login_service() -> Result<String> {
    ensure_installed()?;
    command::read_allowed_stderr_until(
        AllowedCommand::Tailscale,
        ["login", "--accept-dns=false", "--timeout=10m"],
        TAILSCALE_LOGIN_TIMEOUT,
        parse_login_url,
    )
    .await?
    .ok_or_else(|| AppError::Internal("login URL was not emitted".to_string()))
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

fn prepare_workspace() -> Result<()> {
    let workspace = Path::new(TAILSCALE_WORKSPACE);
    match fs::symlink_metadata(workspace) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(AppError::BadRequest(
                "invalid tailscale workspace".to_string(),
            ));
        }
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(workspace)?,
        Ok(_) => fs::remove_file(workspace)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::create_dir_all(workspace)?;
    fs::set_permissions(workspace, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

struct WorkspaceCleanup;

impl Drop for WorkspaceCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(TAILSCALE_WORKSPACE);
    }
}

async fn download_tailscale(target: &Path) -> Result<()> {
    match download_tailscale_with_curl(target).await {
        Ok(()) => Ok(()),
        Err(curl_err) => {
            tracing::warn!(error = %curl_err, "curl tailscale download failed, trying wget");
            let _ = remove_file_if_exists_path(target);
            download_tailscale_with_wget(target)
                .await
                .map_err(|wget_err| {
                    AppError::Internal(format!(
                        "download tailscale failed; curl: {curl_err}; wget: {wget_err}"
                    ))
                })
        }
    }
}

async fn download_tailscale_with_curl(target: &Path) -> Result<()> {
    let args = vec![
        OsString::from("-f"),
        OsString::from("-L"),
        OsString::from("-sS"),
        OsString::from("--connect-timeout"),
        OsString::from("20"),
        OsString::from("--max-time"),
        OsString::from("600"),
        OsString::from("--output"),
        target.as_os_str().to_os_string(),
        OsString::from(TAILSCALE_ORIGINAL_URL),
    ];
    run_download_command(AllowedCommand::Curl, args, "download tailscale with curl").await
}

async fn download_tailscale_with_wget(target: &Path) -> Result<()> {
    let args = vec![
        OsString::from("-q"),
        OsString::from("-O"),
        target.as_os_str().to_os_string(),
        OsString::from(TAILSCALE_ORIGINAL_URL),
    ];
    run_download_command(AllowedCommand::Wget, args, "download tailscale with wget").await
}

async fn run_download_command(
    command: AllowedCommand,
    args: Vec<OsString>,
    action: &str,
) -> Result<()> {
    let output = command::run_allowed(command, args, TAILSCALE_INSTALL_TIMEOUT).await?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(AppError::Internal(command_error(action, output)))
    }
}

fn install_binary(src: &Path, target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(src)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::BadRequest(
            "invalid tailscale archive content".to_string(),
        ));
    }
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }

    match fs::rename(src, target) {
        Ok(()) => {}
        Err(rename_err) => {
            tracing::warn!(
                error = %rename_err,
                src = %src.display(),
                target = %target.display(),
                "rename failed, copying tailscale binary"
            );
            let tmp = tmp_path_for(target);
            fs::copy(src, &tmp)?;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
            if let Err(err) = fs::rename(&tmp, target) {
                let _ = fs::remove_file(&tmp);
                return Err(err.into());
            }
            let _ = fs::remove_file(src);
        }
    }

    fs::set_permissions(target, fs::Permissions::from_mode(0o755))?;
    Ok(())
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

async fn raw_status() -> Result<RawTailscaleStatus> {
    ensure_installed()?;
    let output = command::run_allowed(
        AllowedCommand::Tailscale,
        ["status", "--json"],
        TAILSCALE_STATUS_TIMEOUT,
    )
    .await?;
    if output.status != 0 {
        return Err(AppError::Internal(command_error(
            "tailscale status",
            output,
        )));
    }
    parse_raw_status_output(&output.stdout)
        .map_err(|err| AppError::Internal(format!("parse tailscale status: {err}")))
}

fn parse_raw_status_output(output: &[u8]) -> serde_json::Result<RawTailscaleStatus> {
    let raw = String::from_utf8_lossy(output);
    let json_start = raw.find('{').unwrap_or(0);
    serde_json::from_str(&raw[json_start..])
}

fn parse_status_output(output: &[u8]) -> serde_json::Result<GetTailscaleStatusRsp> {
    parse_raw_status_output(output).map(status_response)
}

fn status_response(status: RawTailscaleStatus) -> GetTailscaleStatusRsp {
    let state = match status.backend_state.as_str() {
        "NoState" | "Starting" => TailscaleState::NotRunning,
        "NeedsLogin" | "NeedsMachineAuth" | "InUseOtherUser" => TailscaleState::NotLogin,
        "Running" => TailscaleState::Running,
        "Stopped" => TailscaleState::Stopped,
        _ => TailscaleState::NotRunning,
    };

    let self_node = status.self_node.unwrap_or_default();
    let current_tailnet = status.current_tailnet.unwrap_or_default();
    let tailscale_ips = self_node.tailscale_ips.unwrap_or_default();

    GetTailscaleStatusRsp {
        state,
        name: self_node.host_name,
        ip: first_ipv4(&tailscale_ips).unwrap_or_default(),
        account: current_tailnet.name,
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
    remove_file_if_exists_path(Path::new(path))
}

fn remove_file_if_exists_path(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn parse_login_url(line: &str) -> Option<String> {
    let start = line.find("https")?;
    let url: String = line[start..]
        .chars()
        .take_while(|ch| !ch.is_control())
        .filter(|ch| !ch.is_whitespace())
        .collect();
    if url.starts_with("https://") {
        Some(url)
    } else {
        None
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
    fn accepts_null_tailscale_status_fields() {
        let parsed = parse_status_output(
            br#"{
  "BackendState": "NeedsLogin",
  "Self": {
    "HostName": "kvm-bd3e",
    "TailscaleIPs": null
  },
  "CurrentTailnet": null
}"#,
        )
        .unwrap();

        assert_eq!(parsed.state, TailscaleState::NotLogin);
        assert_eq!(parsed.name, "kvm-bd3e");
        assert_eq!(parsed.ip, "");
        assert_eq!(parsed.account, "");
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

    #[test]
    fn parses_tailscale_login_url_from_stderr_line() {
        assert_eq!(
            parse_login_url("\t https://login.tailscale.com/a/abc123 \r").unwrap(),
            "https://login.tailscale.com/a/abc123"
        );
        assert_eq!(
            parse_login_url("To authenticate, visit: https://login.tailscale.com/a/abc123")
                .unwrap(),
            "https://login.tailscale.com/a/abc123"
        );
        assert!(parse_login_url("no login URL here").is_none());
    }
}
