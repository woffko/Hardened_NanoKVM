use axum::{
    Json,
    extract::{Path as AxumPath, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use sha2::{Digest, Sha512};
use std::{
    ffi::OsString,
    fs, io,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{LazyLock, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tar::Archive;
use tokio::{net::TcpStream, task, time};

use crate::{
    AppError, Result,
    auth::token::random_token,
    error::ApiResponse,
    system::command::{self, AllowedCommand},
};

const PICOCLAW_BINARY_PATH: &str = "/usr/bin/picoclaw";
const PICOCLAW_CACHE_DIR: &str = "/root/.picoclaw-cache";
const PICOCLAW_DOWNLOAD_URL: &str =
    "https://cdn.sipeed.com/nanokvm/resources/picoclaw/v0.2.8/picoclaw_Linux_riscv64.tar.gz";
const PICOCLAW_CHECKSUM_URL: &str =
    "https://cdn.sipeed.com/nanokvm/resources/picoclaw/v0.2.8/sha512.txt";
const ETC_INIT_PICOCLAW_SCRIPT: &str = "/etc/init.d/S96picoclaw";
const KVMAPP_PICOCLAW_SCRIPT: &str = "/kvmapp/system/init.d/S96picoclaw";
const DEFAULT_GATEWAY_HOST: &str = "127.0.0.1";
const DEFAULT_GATEWAY_PORT: u16 = 18790;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_READ_TIMEOUT_MS: i32 = 60_000;
const DEFAULT_WRITE_TIMEOUT_MS: i32 = 10_000;
const DEFAULT_PING_INTERVAL_MS: i32 = 30_000;
const PICOCLAW_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PICOCLAW_START_TIMEOUT: Duration = Duration::from_secs(15);
const PICOCLAW_STOP_TIMEOUT: Duration = Duration::from_secs(15);
const PICOCLAW_ONBOARD_TIMEOUT: Duration = Duration::from_secs(60);
const INTERNAL_TOKEN_HEADER: &str = "X-NanoKVM-Internal-Token";
const INTERNAL_TOKEN_FILE: &str = "/etc/kvm/.picoclaw_internal_token";

const CODE_INVALID_ACTION: &str = "INVALID_ACTION";
const CODE_RUNTIME_UNAVAILABLE: &str = "RUNTIME_UNAVAILABLE";
const CODE_RUNTIME_START_FAILED: &str = "RUNTIME_START_FAILED";

static RUNTIME_STATUS: LazyLock<RwLock<RuntimeStatus>> =
    LazyLock::new(|| RwLock::new(RuntimeStatus::checking()));
static INTERNAL_TOKEN_CACHE: LazyLock<RwLock<Option<String>>> = LazyLock::new(|| RwLock::new(None));

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub ready: bool,
    pub installed: bool,
    pub installing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_progress: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    pub model_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_name: Option<String>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_session: Option<String>,
}

#[derive(Debug, Serialize)]
struct RuntimeStartResult {
    started: bool,
    command: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    output: String,
    status: RuntimeStatus,
}

#[derive(Debug, Serialize)]
struct RuntimeInstallResult {
    installed: bool,
    binary: String,
    download: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    output: String,
    status: RuntimeStatus,
}

#[derive(Debug, Serialize)]
struct RuntimeSessionRsp {
    current_session: String,
    checked_at: String,
}

#[derive(Debug, Serialize)]
struct PicoclawErrorBody {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    index: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ModelConfigUpdateRequest {
    model: String,
    api_base: String,
    api_key: String,
}

#[derive(Debug, Deserialize)]
pub struct AgentProfileUpdateRequest {
    profile: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionsQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct SessionListItem {
    id: String,
    title: String,
    preview: String,
    message_count: usize,
    created: String,
    updated: String,
}

impl RuntimeStatus {
    fn checking() -> Self {
        Self {
            ready: false,
            installed: false,
            installing: false,
            install_progress: Some(0),
            install_stage: None,
            install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
            agent_profile: None,
            model_configured: false,
            model_name: None,
            status: "checking".to_string(),
            config_error: None,
            last_error: None,
            checked_at: None,
            current_session: None,
        }
    }

    fn with_checked_at(mut self) -> Self {
        self.checked_at = Some(now_string());
        self.install_path = Some(PICOCLAW_BINARY_PATH.to_string());
        self.agent_profile = Some(detect_agent_profile());
        self
    }
}

pub async fn get_runtime_status() -> Result<Response> {
    let status = refresh_runtime_status().await;
    Ok(Json(ApiResponse::ok(status)).into_response())
}

pub async fn start_runtime() -> Result<Response> {
    match start_runtime_inner().await {
        Ok((command, output)) => Ok(Json(ApiResponse::ok(RuntimeStartResult {
            started: true,
            command,
            output,
            status: runtime_status(),
        }))
        .into_response()),
        Err(err) => Ok(picoclaw_error(CODE_RUNTIME_START_FAILED, err)),
    }
}

pub async fn stop_runtime() -> Result<Response> {
    match stop_runtime_inner().await {
        Ok((command, output)) => Ok(Json(ApiResponse::ok(RuntimeStartResult {
            started: false,
            command,
            output,
            status: runtime_status(),
        }))
        .into_response()),
        Err(err) => Ok(picoclaw_error(CODE_RUNTIME_START_FAILED, err)),
    }
}

pub async fn install_runtime() -> Result<Response> {
    let current = runtime_status();
    if current.installing {
        return Ok(Json(ApiResponse::ok(RuntimeInstallResult {
            installed: false,
            binary: PICOCLAW_BINARY_PATH.to_string(),
            download: PICOCLAW_DOWNLOAD_URL.to_string(),
            output: "picoclaw installation is already in progress".to_string(),
            status: current,
        }))
        .into_response());
    }

    if is_installed() {
        let settings = load_gateway_settings().ok();
        set_runtime_status(installed_status(settings.as_ref()));
        return Ok(Json(ApiResponse::ok(RuntimeInstallResult {
            installed: true,
            binary: PICOCLAW_BINARY_PATH.to_string(),
            download: PICOCLAW_DOWNLOAD_URL.to_string(),
            output: "picoclaw is already installed".to_string(),
            status: runtime_status(),
        }))
        .into_response());
    }

    set_runtime_status(RuntimeStatus {
        ready: false,
        installed: false,
        installing: true,
        install_progress: Some(0),
        install_stage: Some("preparing".to_string()),
        install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
        agent_profile: Some(detect_agent_profile()),
        model_configured: false,
        model_name: None,
        status: "installing".to_string(),
        config_error: None,
        last_error: None,
        checked_at: Some(now_string()),
        current_session: None,
    });

    tokio::spawn(async {
        if let Err(err) = run_install_runtime().await {
            set_runtime_status(RuntimeStatus {
                ready: false,
                installed: false,
                installing: false,
                install_progress: Some(0),
                install_stage: Some("install_failed".to_string()),
                install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
                agent_profile: Some(detect_agent_profile()),
                model_configured: false,
                model_name: None,
                status: "install_failed".to_string(),
                config_error: None,
                last_error: Some(err.to_string()),
                checked_at: Some(now_string()),
                current_session: None,
            });
        }
    });

    Ok(Json(ApiResponse::ok(RuntimeInstallResult {
        installed: false,
        binary: PICOCLAW_BINARY_PATH.to_string(),
        download: PICOCLAW_DOWNLOAD_URL.to_string(),
        output: "picoclaw installation started".to_string(),
        status: runtime_status(),
    }))
    .into_response())
}

pub async fn uninstall_runtime() -> Result<Response> {
    if runtime_status().installing {
        return Ok(picoclaw_error(
            CODE_RUNTIME_START_FAILED,
            "cannot uninstall while installation is in progress",
        ));
    }

    let _ = stop_runtime_inner().await;
    if let Ok(config_path) = resolve_config_path() {
        if let Some(parent) = config_path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
    let _ = fs::remove_file(PICOCLAW_BINARY_PATH);
    let _ = fs::remove_dir_all(PICOCLAW_CACHE_DIR);

    set_runtime_status(RuntimeStatus {
        ready: false,
        installed: false,
        installing: false,
        install_progress: Some(0),
        install_stage: None,
        install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
        agent_profile: Some(detect_agent_profile()),
        model_configured: false,
        model_name: None,
        status: "not_installed".to_string(),
        config_error: None,
        last_error: None,
        checked_at: Some(now_string()),
        current_session: None,
    });

    Ok(Json(ApiResponse::ok(RuntimeInstallResult {
        installed: false,
        binary: PICOCLAW_BINARY_PATH.to_string(),
        download: PICOCLAW_DOWNLOAD_URL.to_string(),
        output: "picoclaw uninstalled successfully".to_string(),
        status: runtime_status(),
    }))
    .into_response())
}

pub async fn get_runtime_session() -> Result<Response> {
    Ok(Json(ApiResponse::ok(RuntimeSessionRsp {
        current_session: String::new(),
        checked_at: now_string(),
    }))
    .into_response())
}

pub async fn release_runtime_session() -> Result<Response> {
    Ok(Json(ApiResponse::ok(json!({
        "released": true,
        "current_session": ""
    })))
    .into_response())
}

pub async fn update_model_config(Json(req): Json<ModelConfigUpdateRequest>) -> Result<Response> {
    let api_base = req.api_base.trim();
    let api_key = req.api_key.trim();
    let model = req.model.trim();
    if api_base.is_empty() {
        return Ok(picoclaw_error(
            CODE_RUNTIME_UNAVAILABLE,
            "model api_base is required",
        ));
    }
    if api_key.is_empty() {
        return Ok(picoclaw_error(
            CODE_RUNTIME_UNAVAILABLE,
            "model api_key is required",
        ));
    }
    if model.is_empty() {
        return Ok(picoclaw_error(
            CODE_RUNTIME_UNAVAILABLE,
            "model identifier is required",
        ));
    }

    match update_model_config_file(api_base, api_key, model) {
        Ok(model_name) => {
            let _ = ensure_startup_defaults();
            let status = refresh_runtime_status().await;
            Ok(Json(ApiResponse::ok(json!({
                "model_name": model_name,
                "status": status
            })))
            .into_response())
        }
        Err(err) => Ok(picoclaw_error(CODE_RUNTIME_UNAVAILABLE, err.to_string())),
    }
}

pub async fn update_agent_profile(Json(req): Json<AgentProfileUpdateRequest>) -> Result<Response> {
    let profile = req.profile.trim();
    if profile != "default" && profile != "kvm" {
        return Ok(picoclaw_error(CODE_INVALID_ACTION, "invalid agent profile"));
    }

    match apply_agent_profile(profile) {
        Ok(()) => {
            let status = refresh_runtime_status().await;
            Ok(Json(ApiResponse::ok(json!({
                "profile": profile,
                "status": status
            })))
            .into_response())
        }
        Err(err) => Ok(picoclaw_error(CODE_RUNTIME_UNAVAILABLE, err.to_string())),
    }
}

pub async fn list_sessions(Query(query): Query<SessionsQuery>) -> Result<Response> {
    let _offset = query.offset.unwrap_or(0);
    let _limit = query.limit.unwrap_or(20);
    Ok(Json(ApiResponse::ok(Vec::<SessionListItem>::new())).into_response())
}

pub async fn get_session(AxumPath(_id): AxumPath<String>) -> Result<Response> {
    Ok(picoclaw_error(CODE_INVALID_ACTION, "session not found"))
}

pub async fn delete_session(AxumPath(_id): AxumPath<String>) -> Result<Response> {
    Ok(Json(ApiResponse::ok(json!({ "deleted": true }))).into_response())
}

pub async fn unsupported_local_route() -> Result<Response> {
    Ok(picoclaw_error(
        CODE_RUNTIME_UNAVAILABLE,
        "picoclaw local control route is not implemented in Rust yet",
    ))
}

pub fn loopback_http_allowed_path(path: &str) -> bool {
    matches!(
        path,
        "/api/picoclaw/mcp"
            | "/api/picoclaw/runtime/session"
            | "/api/picoclaw/screenshot"
            | "/api/picoclaw/actions"
            | "/api/picoclaw/load-image"
    )
}

pub fn has_valid_loopback_internal_token(
    headers: &axum::http::HeaderMap,
    remote: Option<SocketAddr>,
) -> bool {
    if !remote.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return false;
    }
    let Ok(token) = internal_token() else {
        return false;
    };
    let provided = headers
        .get(INTERNAL_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    constant_time_eq(provided, &token)
}

fn runtime_status() -> RuntimeStatus {
    RUNTIME_STATUS
        .read()
        .map(|status| status.clone())
        .unwrap_or_else(|_| RuntimeStatus::checking())
}

fn set_runtime_status(status: RuntimeStatus) {
    if let Ok(mut current) = RUNTIME_STATUS.write() {
        *current = status.with_checked_at();
    }
}

async fn refresh_runtime_status() -> RuntimeStatus {
    if runtime_status().installing {
        return runtime_status();
    }

    let status = match ensure_runtime_ready().await {
        Ok(status) => status,
        Err(status) => status,
    };
    set_runtime_status(status);
    runtime_status()
}

async fn ensure_runtime_ready() -> std::result::Result<RuntimeStatus, RuntimeStatus> {
    if !is_installed() {
        return Err(RuntimeStatus {
            ready: false,
            installed: false,
            installing: false,
            install_progress: Some(0),
            install_stage: None,
            install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
            agent_profile: Some(detect_agent_profile()),
            model_configured: false,
            model_name: None,
            status: "not_installed".to_string(),
            config_error: None,
            last_error: None,
            checked_at: Some(now_string()),
            current_session: None,
        });
    }

    if resolve_config_path()
        .ok()
        .filter(|path| path.exists())
        .is_none()
    {
        let _ = run_script("onboard", PICOCLAW_ONBOARD_TIMEOUT).await;
    }

    let settings = match load_gateway_settings() {
        Ok(settings) => settings,
        Err(err) => {
            return Err(RuntimeStatus {
                ready: false,
                installed: true,
                installing: false,
                install_progress: Some(0),
                install_stage: None,
                install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
                agent_profile: Some(detect_agent_profile()),
                model_configured: false,
                model_name: None,
                status: "model_not_configured".to_string(),
                config_error: None,
                last_error: Some(err.to_string()),
                checked_at: Some(now_string()),
                current_session: None,
            });
        }
    };

    if !settings.model_configured {
        return Err(RuntimeStatus {
            ready: false,
            installed: true,
            installing: false,
            install_progress: Some(0),
            install_stage: None,
            install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
            agent_profile: Some(detect_agent_profile()),
            model_configured: false,
            model_name: Some(settings.target_model_name),
            status: "model_not_configured".to_string(),
            config_error: None,
            last_error: None,
            checked_at: Some(now_string()),
            current_session: None,
        });
    }

    let host_port = format!("{}:{}", settings.gateway_host, settings.gateway_port);
    let timeout = Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS);
    match time::timeout(timeout, TcpStream::connect(&host_port)).await {
        Ok(Ok(_)) => Ok(RuntimeStatus {
            ready: true,
            installed: true,
            installing: false,
            install_progress: Some(100),
            install_stage: Some("installed".to_string()),
            install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
            agent_profile: Some(detect_agent_profile()),
            model_configured: true,
            model_name: Some(settings.model_name),
            status: "ready".to_string(),
            config_error: None,
            last_error: None,
            checked_at: Some(now_string()),
            current_session: None,
        }),
        Ok(Err(err)) => Err(RuntimeStatus {
            ready: false,
            installed: true,
            installing: false,
            install_progress: Some(100),
            install_stage: Some("installed".to_string()),
            install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
            agent_profile: Some(detect_agent_profile()),
            model_configured: true,
            model_name: Some(settings.model_name),
            status: "unavailable".to_string(),
            config_error: None,
            last_error: Some(err.to_string()),
            checked_at: Some(now_string()),
            current_session: None,
        }),
        Err(_) => Err(RuntimeStatus {
            ready: false,
            installed: true,
            installing: false,
            install_progress: Some(100),
            install_stage: Some("installed".to_string()),
            install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
            agent_profile: Some(detect_agent_profile()),
            model_configured: true,
            model_name: Some(settings.model_name),
            status: "unavailable".to_string(),
            config_error: None,
            last_error: Some("gateway connection timed out".to_string()),
            checked_at: Some(now_string()),
            current_session: None,
        }),
    }
}

async fn start_runtime_inner() -> std::result::Result<(String, String), String> {
    if !is_installed() {
        set_runtime_status(RuntimeStatus {
            ready: false,
            installed: false,
            installing: false,
            install_progress: Some(0),
            install_stage: None,
            install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
            agent_profile: Some(detect_agent_profile()),
            model_configured: false,
            model_name: None,
            status: "not_installed".to_string(),
            config_error: None,
            last_error: Some("picoclaw is not installed".to_string()),
            checked_at: Some(now_string()),
            current_session: None,
        });
        return Err("picoclaw is not installed".to_string());
    }

    ensure_startup_defaults().map_err(|err| err.to_string())?;
    let (command, output) = run_script("start", PICOCLAW_START_TIMEOUT)
        .await
        .map_err(|err| err.to_string())?;
    time::sleep(Duration::from_millis(1500)).await;
    let status = refresh_runtime_status().await;
    if status.ready {
        Ok((command, output))
    } else {
        Err(status
            .last_error
            .unwrap_or_else(|| "failed to start picoclaw runtime".to_string()))
    }
}

async fn stop_runtime_inner() -> std::result::Result<(String, String), String> {
    let (command, output) = run_script("stop", PICOCLAW_STOP_TIMEOUT)
        .await
        .map_err(|err| err.to_string())?;
    time::sleep(Duration::from_millis(500)).await;

    let settings = load_gateway_settings().ok();
    set_runtime_status(RuntimeStatus {
        ready: false,
        installed: is_installed(),
        installing: false,
        install_progress: Some(if is_installed() { 100 } else { 0 }),
        install_stage: if is_installed() {
            Some("installed".to_string())
        } else {
            None
        },
        install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
        agent_profile: Some(detect_agent_profile()),
        model_configured: settings
            .as_ref()
            .map(|settings| settings.model_configured)
            .unwrap_or(false),
        model_name: settings
            .as_ref()
            .map(|settings| settings.model_name.clone())
            .filter(|name| !name.is_empty()),
        status: "stopped".to_string(),
        config_error: None,
        last_error: None,
        checked_at: Some(now_string()),
        current_session: None,
    });
    Ok((command, output))
}

async fn run_install_runtime() -> Result<()> {
    let cache = Path::new(PICOCLAW_CACHE_DIR);
    let _ = fs::remove_dir_all(cache);
    fs::create_dir_all(cache)?;

    set_install_progress("downloading", 5, None);
    let checksum_path = cache.join("sha512.txt");
    download_to(PICOCLAW_CHECKSUM_URL, &checksum_path).await?;
    let expected_digest = parse_sha512_digest(
        &fs::read_to_string(&checksum_path)?,
        Path::new(PICOCLAW_DOWNLOAD_URL)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(""),
    )?;

    set_install_progress("downloading", 10, None);
    let archive_path = cache.join("picoclaw.tar.gz");
    download_to(PICOCLAW_DOWNLOAD_URL, &archive_path).await?;

    set_install_progress("verifying", 82, None);
    verify_sha512(&archive_path, &expected_digest)?;

    set_install_progress("extracting", 85, None);
    let extracted = {
        let archive_path = archive_path.clone();
        let cache = cache.to_path_buf();
        task::spawn_blocking(move || extract_picoclaw_binary(&archive_path, &cache))
            .await
            .map_err(|err| AppError::Internal(format!("picoclaw extract task failed: {err}")))??
    };

    set_install_progress("installing", 95, None);
    install_binary(&extracted, Path::new(PICOCLAW_BINARY_PATH))?;

    let _ = fs::remove_dir_all(cache);
    set_runtime_status(RuntimeStatus {
        ready: false,
        installed: true,
        installing: false,
        install_progress: Some(100),
        install_stage: Some("installed".to_string()),
        install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
        agent_profile: Some(detect_agent_profile()),
        model_configured: false,
        model_name: None,
        status: "installed".to_string(),
        config_error: None,
        last_error: None,
        checked_at: Some(now_string()),
        current_session: None,
    });
    Ok(())
}

fn set_install_progress(stage: &str, progress: i32, last_error: Option<String>) {
    set_runtime_status(RuntimeStatus {
        ready: false,
        installed: false,
        installing: true,
        install_progress: Some(progress.clamp(0, 100)),
        install_stage: Some(stage.to_string()),
        install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
        agent_profile: Some(detect_agent_profile()),
        model_configured: false,
        model_name: None,
        status: "installing".to_string(),
        config_error: None,
        last_error,
        checked_at: Some(now_string()),
        current_session: None,
    });
}

async fn download_to(url: &str, target: &Path) -> Result<()> {
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
        OsString::from(url),
    ];
    let curl = command::run_allowed(AllowedCommand::Curl, args, PICOCLAW_DOWNLOAD_TIMEOUT).await;
    if let Ok(output) = curl {
        if output.status == 0 {
            return Ok(());
        }
    }

    let args = vec![
        OsString::from("-q"),
        OsString::from("-O"),
        target.as_os_str().to_os_string(),
        OsString::from(url),
    ];
    let output =
        command::run_allowed(AllowedCommand::Wget, args, PICOCLAW_DOWNLOAD_TIMEOUT).await?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(AppError::Internal(command_error(
            "download picoclaw",
            output,
        )))
    }
}

fn parse_sha512_digest(raw: &str, expected_name: &str) -> Result<String> {
    let mut fallback = None;
    for line in raw.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() || !is_sha512_digest(fields[0]) {
            continue;
        }
        if fields.len() == 1 {
            fallback.get_or_insert_with(|| fields[0].to_ascii_lowercase());
            continue;
        }
        let name = fields[fields.len() - 1].trim_start_matches('*');
        if expected_name.is_empty() || name == expected_name {
            return Ok(fields[0].to_ascii_lowercase());
        }
    }
    fallback.ok_or_else(|| AppError::Internal("failed to parse sha512 digest".to_string()))
}

fn is_sha512_digest(value: &str) -> bool {
    value.len() == 128 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn verify_sha512(path: &Path, expected: &str) -> Result<()> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha512::new();
    io::copy(&mut file, &mut hasher)?;
    let actual = format!("{:x}", hasher.finalize());
    if actual == expected.to_ascii_lowercase() {
        Ok(())
    } else {
        Err(AppError::Internal(format!("sha512 mismatch: got {actual}")))
    }
}

fn extract_picoclaw_binary(archive_path: &Path, destination: &Path) -> Result<PathBuf> {
    let file = fs::File::open(archive_path)?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.into_owned();
        if path.file_name().and_then(|name| name.to_str()) != Some("picoclaw") {
            continue;
        }
        let target = destination.join("picoclaw");
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&target)?;
        io::copy(&mut entry, &mut out)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        return Ok(target);
    }
    Err(AppError::Internal(
        "picoclaw binary not found in archive".to_string(),
    ))
}

fn install_binary(src: &Path, target: &Path) -> Result<()> {
    let tmp = target.with_extension("tmp");
    fs::copy(src, &tmp)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
    fs::rename(&tmp, target)?;
    Ok(())
}

async fn run_script(action: &'static str, timeout: Duration) -> Result<(String, String)> {
    let (command, display) = if Path::new(ETC_INIT_PICOCLAW_SCRIPT).exists() {
        (
            AllowedCommand::ServicePicoclawEtc,
            format!("{ETC_INIT_PICOCLAW_SCRIPT} {action}"),
        )
    } else if Path::new(KVMAPP_PICOCLAW_SCRIPT).exists() {
        (
            AllowedCommand::ServicePicoclawKvmapp,
            format!("{KVMAPP_PICOCLAW_SCRIPT} {action}"),
        )
    } else {
        return Err(AppError::Internal(format!(
            "picoclaw start script not found: {ETC_INIT_PICOCLAW_SCRIPT} or {KVMAPP_PICOCLAW_SCRIPT}"
        )));
    };

    let output = command::run_allowed(command, [action], timeout).await?;
    let trimmed = command_output_text(&output);
    if output.status == 0 {
        Ok((display, trimmed))
    } else {
        Err(AppError::Internal(if trimmed.is_empty() {
            format!("picoclaw script {action} failed")
        } else {
            trimmed
        }))
    }
}

fn is_installed() -> bool {
    fs::metadata(PICOCLAW_BINARY_PATH)
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

fn installed_status(settings: Option<&GatewaySettings>) -> RuntimeStatus {
    RuntimeStatus {
        ready: false,
        installed: true,
        installing: false,
        install_progress: Some(100),
        install_stage: Some("installed".to_string()),
        install_path: Some(PICOCLAW_BINARY_PATH.to_string()),
        agent_profile: Some(detect_agent_profile()),
        model_configured: settings
            .map(|settings| settings.model_configured)
            .unwrap_or(false),
        model_name: settings
            .map(|settings| settings.model_name.clone())
            .filter(|name| !name.is_empty()),
        status: "installed".to_string(),
        config_error: None,
        last_error: None,
        checked_at: Some(now_string()),
        current_session: None,
    }
}

#[derive(Debug)]
struct GatewaySettings {
    gateway_host: String,
    gateway_port: u16,
    model_configured: bool,
    model_name: String,
    target_model_name: String,
}

fn load_gateway_settings() -> Result<GatewaySettings> {
    let doc = load_config_document()?;
    let gateway = doc.raw.get("gateway").and_then(JsonValue::as_object);
    let gateway_host = gateway
        .and_then(|gateway| gateway.get("host"))
        .and_then(JsonValue::as_str)
        .filter(|host| !host.is_empty() && *host != "0.0.0.0")
        .unwrap_or(DEFAULT_GATEWAY_HOST)
        .to_string();
    let gateway_port = gateway
        .and_then(|gateway| gateway.get("port"))
        .and_then(JsonValue::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port > 0)
        .unwrap_or(DEFAULT_GATEWAY_PORT);

    let target_model_name = doc
        .raw
        .pointer("/agents/defaults/model_name")
        .and_then(JsonValue::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let model_configured = is_model_configured(&doc.raw, &doc.security, &target_model_name);
    let model_name = if model_configured {
        target_model_name.clone()
    } else {
        String::new()
    };

    Ok(GatewaySettings {
        gateway_host,
        gateway_port,
        model_configured,
        model_name,
        target_model_name,
    })
}

struct ConfigDocument {
    config_path: PathBuf,
    security_path: PathBuf,
    raw: JsonValue,
    security: serde_yaml::Value,
}

fn load_config_document() -> Result<ConfigDocument> {
    let config_path = resolve_config_path()?;
    let data = fs::read(&config_path)?;
    let raw: JsonValue = serde_json::from_slice(&data)
        .map_err(|err| AppError::Internal(format!("failed to parse picoclaw config: {err}")))?;
    let security_path = config_path
        .parent()
        .unwrap_or_else(|| Path::new("/root/.picoclaw"))
        .join(".security.yml");
    let security = match fs::read(&security_path) {
        Ok(data) => serde_yaml::from_slice(&data).map_err(|err| {
            AppError::Internal(format!("failed to parse picoclaw security config: {err}"))
        })?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
        }
        Err(err) => return Err(err.into()),
    };

    Ok(ConfigDocument {
        config_path,
        security_path,
        raw,
        security,
    })
}

fn resolve_config_path() -> Result<PathBuf> {
    let home = std::env::var("PICOCLAW_HOME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root/.picoclaw"));
    Ok(home.join("config.json"))
}

fn is_model_configured(config: &JsonValue, security: &serde_yaml::Value, model_name: &str) -> bool {
    if model_name.is_empty() {
        return false;
    }

    let Some(models) = config.get("model_list").and_then(JsonValue::as_array) else {
        return false;
    };
    for (idx, model) in models.iter().enumerate() {
        if model
            .get("model_name")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            != Some(model_name)
        {
            continue;
        }
        if model
            .get("api_base")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            continue;
        }
        if model
            .get("api_key")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some()
        {
            return true;
        }
        if model
            .get("api_keys")
            .and_then(JsonValue::as_array)
            .map(|keys| !keys.is_empty())
            .unwrap_or(false)
        {
            return true;
        }
        if security_has_model_key(security, model_name, idx) {
            return true;
        }
    }
    false
}

fn security_has_model_key(security: &serde_yaml::Value, model_name: &str, index: usize) -> bool {
    let Some(model_list) = security
        .get("model_list")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return false;
    };
    let keys = [model_name.to_string(), format!("{model_name}:{index}")];
    keys.iter().any(|key| {
        model_list
            .get(serde_yaml::Value::String(key.clone()))
            .and_then(|entry| entry.get("api_keys"))
            .and_then(serde_yaml::Value::as_sequence)
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    })
}

fn update_model_config_file(api_base: &str, api_key: &str, model: &str) -> Result<String> {
    let mut doc = load_config_document()?;
    let model_name = extract_model_name(model)
        .ok_or_else(|| AppError::Internal("model identifier is required".to_string()))?;
    let raw = doc
        .raw
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("picoclaw config root is not an object".to_string()))?;

    let models = raw
        .entry("model_list".to_string())
        .or_insert_with(|| JsonValue::Array(Vec::new()));
    if !models.is_array() {
        *models = JsonValue::Array(Vec::new());
    }
    let models = models.as_array_mut().expect("model_list array");
    let mut updated_index = None;
    for (idx, item) in models.iter_mut().enumerate() {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        if item
            .get("model_name")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            == Some(model_name.as_str())
        {
            item.insert(
                "model_name".to_string(),
                JsonValue::String(model_name.clone()),
            );
            item.insert("model".to_string(), JsonValue::String(model.to_string()));
            item.insert(
                "api_base".to_string(),
                JsonValue::String(api_base.to_string()),
            );
            item.remove("api_key");
            item.remove("api_keys");
            updated_index = Some(idx);
            break;
        }
    }
    let updated_index = match updated_index {
        Some(idx) => idx,
        None => {
            let mut item = JsonMap::new();
            item.insert(
                "model_name".to_string(),
                JsonValue::String(model_name.clone()),
            );
            item.insert("model".to_string(), JsonValue::String(model.to_string()));
            item.insert(
                "api_base".to_string(),
                JsonValue::String(api_base.to_string()),
            );
            models.push(JsonValue::Object(item));
            models.len() - 1
        }
    };

    let agents = raw
        .entry("agents".to_string())
        .or_insert_with(|| JsonValue::Object(JsonMap::new()));
    if !agents.is_object() {
        *agents = JsonValue::Object(JsonMap::new());
    }
    let defaults = agents
        .as_object_mut()
        .expect("agents object")
        .entry("defaults".to_string())
        .or_insert_with(|| JsonValue::Object(JsonMap::new()));
    if !defaults.is_object() {
        *defaults = JsonValue::Object(JsonMap::new());
    }
    let defaults = defaults.as_object_mut().expect("defaults object");
    defaults.insert(
        "model_name".to_string(),
        JsonValue::String(model_name.clone()),
    );
    defaults.remove("model");

    save_json(&doc.config_path, &doc.raw)?;
    save_model_secret(
        &mut doc.security,
        &doc.security_path,
        &model_name,
        updated_index,
        api_key,
    )?;
    Ok(model_name)
}

fn extract_model_name(model: &str) -> Option<String> {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(
        trimmed
            .rsplit('/')
            .next()
            .unwrap_or(trimmed)
            .trim()
            .to_string(),
    )
}

fn save_json(path: &Path, value: &JsonValue) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(value)
        .map_err(|err| AppError::Internal(format!("failed to encode picoclaw config: {err}")))?;
    fs::write(path, data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn save_model_secret(
    security: &mut serde_yaml::Value,
    path: &Path,
    model_name: &str,
    index: usize,
    api_key: &str,
) -> Result<()> {
    if !security.is_mapping() {
        *security = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    let root = security.as_mapping_mut().expect("security mapping");
    let model_list_key = serde_yaml::Value::String("model_list".to_string());
    root.entry(model_list_key.clone())
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    if !root[&model_list_key].is_mapping() {
        root.insert(
            model_list_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }
    let model_list = root
        .get_mut(&model_list_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .expect("model_list mapping");
    let mut entry = serde_yaml::Mapping::new();
    entry.insert(
        serde_yaml::Value::String("api_keys".to_string()),
        serde_yaml::Value::Sequence(vec![serde_yaml::Value::String(api_key.to_string())]),
    );
    model_list.insert(
        serde_yaml::Value::String(format!("{model_name}:{index}")),
        serde_yaml::Value::Mapping(entry),
    );

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_yaml::to_string(security)
        .map_err(|err| AppError::Internal(format!("failed to encode picoclaw security: {err}")))?;
    fs::write(path, data)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn ensure_startup_defaults() -> Result<()> {
    let mut doc = load_config_document()?;
    let raw = doc
        .raw
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("picoclaw config root is not an object".to_string()))?;
    ensure_object_path(raw, &["agents", "defaults"])
        .insert("restrict_to_workspace".to_string(), JsonValue::Bool(false));
    ensure_object_path(raw, &["agents", "defaults"]).insert(
        "allow_read_outside_workspace".to_string(),
        JsonValue::Bool(true),
    );
    ensure_object_path(raw, &["gateway"]).insert(
        "host".to_string(),
        JsonValue::String(DEFAULT_GATEWAY_HOST.to_string()),
    );
    ensure_object_path(raw, &["gateway"]).insert(
        "port".to_string(),
        JsonValue::Number(serde_json::Number::from(DEFAULT_GATEWAY_PORT)),
    );
    let pico = ensure_object_path(raw, &["channel_list", "pico"]);
    pico.insert("type".to_string(), JsonValue::String("pico".to_string()));
    pico.insert("enabled".to_string(), JsonValue::Bool(true));
    let settings = ensure_object_path(raw, &["channel_list", "pico", "settings"]);
    settings.insert("allow_token_query".to_string(), JsonValue::Bool(false));
    settings.insert(
        "ping_interval".to_string(),
        JsonValue::Number(serde_json::Number::from(DEFAULT_PING_INTERVAL_MS / 1000)),
    );
    settings.insert(
        "read_timeout".to_string(),
        JsonValue::Number(serde_json::Number::from(DEFAULT_READ_TIMEOUT_MS / 1000)),
    );
    settings.insert(
        "write_timeout".to_string(),
        JsonValue::Number(serde_json::Number::from(DEFAULT_WRITE_TIMEOUT_MS / 1000)),
    );
    ensure_object_path(raw, &["tools", "mcp"]).insert("enabled".to_string(), JsonValue::Bool(true));
    let token = internal_token()?;
    let server = ensure_object_path(raw, &["tools", "mcp", "servers", "nanokvm"]);
    server.insert("enabled".to_string(), JsonValue::Bool(true));
    server.insert("type".to_string(), JsonValue::String("http".to_string()));
    server.insert(
        "url".to_string(),
        JsonValue::String("http://127.0.0.1:80/api/picoclaw/mcp".to_string()),
    );
    let headers = ensure_object_path(raw, &["tools", "mcp", "servers", "nanokvm", "headers"]);
    headers.insert(INTERNAL_TOKEN_HEADER.to_string(), JsonValue::String(token));
    save_json(&doc.config_path, &doc.raw)
}

fn ensure_object_path<'a>(
    root: &'a mut JsonMap<String, JsonValue>,
    path: &[&str],
) -> &'a mut JsonMap<String, JsonValue> {
    let mut current = root;
    for key in path {
        let entry = current
            .entry((*key).to_string())
            .or_insert_with(|| JsonValue::Object(JsonMap::new()));
        if !entry.is_object() {
            *entry = JsonValue::Object(JsonMap::new());
        }
        current = entry.as_object_mut().expect("object path");
    }
    current
}

fn apply_agent_profile(profile: &str) -> Result<()> {
    let source = resolve_agent_profile_source(profile)?;
    let workspace = resolve_workspace_path()?;
    fs::create_dir_all(&workspace)?;
    let content = fs::read(source)?;
    fs::write(workspace.join("AGENT.md"), content)?;
    Ok(())
}

fn resolve_agent_profile_source(profile: &str) -> Result<PathBuf> {
    let filename = match profile {
        "default" => "AGENT.md",
        "kvm" => "AGENT_KVM.md",
        _ => return Err(AppError::BadRequest("invalid agent profile".to_string())),
    };
    let candidates = [
        PathBuf::from("/kvmapp/picoclaw").join(filename),
        std::env::current_exe()
            .ok()
            .and_then(|path| {
                path.parent()
                    .map(|parent| parent.join("../picoclaw").join(filename))
            })
            .unwrap_or_else(|| PathBuf::from("/nonexistent")),
    ];
    candidates
        .into_iter()
        .find(|path| path.exists())
        .ok_or_else(|| AppError::Internal(format!("agent profile source not found: {filename}")))
}

fn detect_agent_profile() -> String {
    let Ok(workspace) = resolve_workspace_path() else {
        return "kvm".to_string();
    };
    let content = fs::read_to_string(workspace.join("AGENT.md")).unwrap_or_default();
    for line in content.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("name:") {
            return if name.trim() == "pico" {
                "default".to_string()
            } else {
                "kvm".to_string()
            };
        }
    }
    "kvm".to_string()
}

fn resolve_workspace_path() -> Result<PathBuf> {
    let config_path = resolve_config_path()?;
    if let Ok(doc) = load_config_document() {
        if let Some(workspace) = doc
            .raw
            .pointer("/agents/defaults/workspace")
            .and_then(JsonValue::as_str)
            .and_then(expand_home_path)
        {
            return Ok(workspace);
        }
    }
    Ok(config_path
        .parent()
        .unwrap_or_else(|| Path::new("/root/.picoclaw"))
        .join("workspace"))
}

fn expand_home_path(path: &str) -> Option<PathBuf> {
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    if path == "~" {
        return Some(PathBuf::from("/root"));
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return Some(PathBuf::from("/root").join(rest));
    }
    Some(PathBuf::from(path))
}

fn picoclaw_error(code: &str, message: impl Into<String>) -> Response {
    (
        StatusCode::OK,
        Json(PicoclawErrorBody {
            code: code.to_string(),
            message: message.into(),
            session_id: None,
            index: None,
        }),
    )
        .into_response()
}

fn internal_token() -> Result<String> {
    if let Ok(guard) = INTERNAL_TOKEN_CACHE.read() {
        if let Some(token) = guard.as_ref() {
            return Ok(token.clone());
        }
    }

    let path = Path::new(INTERNAL_TOKEN_FILE);
    let token = match fs::read_to_string(path) {
        Ok(value) => value.trim().to_string(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let token = random_token(32);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, format!("{token}\n"))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            token
        }
        Err(err) => return Err(err.into()),
    };

    if let Ok(mut guard) = INTERNAL_TOKEN_CACHE.write() {
        *guard = Some(token.clone());
    }
    Ok(token)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut diff = a.len() ^ b.len();
    for idx in 0..a.len().max(b.len()) {
        let left = a.get(idx).copied().unwrap_or(0);
        let right = b.get(idx).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    diff == 0
}

fn now_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn command_output_text(output: &crate::system::command::CommandOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn command_error(message: &str, output: crate::system::command::CommandOutput) -> String {
    let detail = command_output_text(&output);
    if detail.is_empty() {
        message.to_string()
    } else {
        format!("{message}: {detail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sha512_for_named_archive() {
        let digest = "a".repeat(128);
        let raw = format!("{digest}  picoclaw_Linux_riscv64.tar.gz\n");
        assert_eq!(
            parse_sha512_digest(&raw, "picoclaw_Linux_riscv64.tar.gz").unwrap(),
            digest
        );
    }

    #[test]
    fn extracts_model_name_from_provider_path() {
        assert_eq!(
            extract_model_name("openai/gpt-4.1").unwrap(),
            "gpt-4.1".to_string()
        );
        assert_eq!(
            extract_model_name("gpt-4.1").unwrap(),
            "gpt-4.1".to_string()
        );
    }
}
