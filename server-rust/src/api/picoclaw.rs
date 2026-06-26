use axum::{
    Json,
    body::Bytes,
    extract::{Path as AxumPath, Query},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
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
    sync::{LazyLock, Mutex, RwLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tar::Archive;
use tokio::{net::TcpStream, task, time};

use crate::{
    AppError, Result,
    api::{hid, stream},
    auth::token::random_token,
    error::ApiResponse,
    system::command::{self, AllowedCommand},
    ws::hid as hid_ws,
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
const SESSION_ID_HEADER: &str = "X-PicoClaw-Session-ID";

const CODE_PICOCLAW_LOCK_HELD: &str = "AI_LOCK_HELD";
const CODE_INVALID_ACTION: &str = "INVALID_ACTION";
const CODE_SCREENSHOT_FAILED: &str = "SCREENSHOT_FAILED";
const CODE_HID_WRITE_FAILED: &str = "HID_WRITE_FAILED";
const CODE_RUNTIME_UNAVAILABLE: &str = "RUNTIME_UNAVAILABLE";
const CODE_RUNTIME_START_FAILED: &str = "RUNTIME_START_FAILED";
const CODE_SESSION_ID_MISSING: &str = "SESSION_ID_MISSING";
const CODE_SESSION_ID_INVALID: &str = "SESSION_ID_INVALID";

const SESSION_LOCK_DURATION: Duration = Duration::from_secs(30 * 60);
const CACHED_FRAME_MAX_AGE: Duration = Duration::from_secs(2);
const DEFAULT_SCREENSHOT_WIDTH: u16 = 960;
const DEFAULT_SCREENSHOT_HEIGHT: u16 = 540;
const DEFAULT_SCREENSHOT_QUALITY: u16 = 60;
const DEFAULT_CLICK_HOLD: Duration = Duration::from_millis(40);
const DEFAULT_DRAG_STEPS: usize = 10;
const DEFAULT_SCROLL_STEP: Duration = Duration::from_millis(20);

static RUNTIME_STATUS: LazyLock<RwLock<RuntimeStatus>> =
    LazyLock::new(|| RwLock::new(RuntimeStatus::checking()));
static INTERNAL_TOKEN_CACHE: LazyLock<RwLock<Option<String>>> = LazyLock::new(|| RwLock::new(None));
static SESSION_LOCK: LazyLock<Mutex<PicoSessionLock>> =
    LazyLock::new(|| Mutex::new(PicoSessionLock::default()));

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

#[derive(Debug, Clone)]
struct PicoclawErrorData {
    code: &'static str,
    message: String,
    session_id: Option<String>,
    index: Option<usize>,
}

#[derive(Debug, Default)]
struct PicoSessionLock {
    owner_session_id: String,
    acquired_at: Option<Instant>,
    expires_at: Option<Instant>,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScreenshotQuery {
    format: String,
    width: u16,
    height: u16,
    quality: u16,
}

impl Default for ScreenshotQuery {
    fn default() -> Self {
        Self {
            format: String::new(),
            width: 0,
            height: 0,
            quality: 0,
        }
    }
}

#[derive(Debug, Serialize)]
struct ScreenshotMeta {
    #[serde(skip_serializing_if = "String::is_empty")]
    image_base64: String,
    source_width: u16,
    source_height: u16,
    capture_width: u16,
    capture_height: u16,
    format: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct Point {
    x: Option<f64>,
    y: Option<f64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct Action {
    action: String,
    x: Option<f64>,
    y: Option<f64>,
    from: Option<Point>,
    to: Option<Point>,
    button: String,
    text: String,
    keys: Option<JsonValue>,
    direction: String,
    amount: i32,
    duration_ms: i32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct ActionBatch {
    actions: Vec<Action>,
}

#[derive(Debug, Serialize)]
struct ActionResult {
    action: String,
    duration_ms: i64,
    hid_writes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_actions: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct LoadImageRequest {
    path: String,
    prompt: String,
    filename: String,
}

impl Default for LoadImageRequest {
    fn default() -> Self {
        Self {
            path: String::new(),
            prompt: String::new(),
            filename: String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: JsonValue,
    method: String,
    params: Option<JsonValue>,
}

impl Default for JsonRpcRequest {
    fn default() -> Self {
        Self {
            jsonrpc: String::new(),
            id: JsonValue::Null,
            method: String::new(),
            params: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
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

impl PicoclawErrorData {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            session_id: None,
            index: None,
        }
    }

    fn with_session(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }

    fn with_index(mut self, index: usize) -> Self {
        self.index = Some(index);
        self
    }
}

impl PicoSessionLock {
    fn clear_expired(&mut self, now: Instant) {
        if self.owner_session_id.is_empty() {
            return;
        }
        if self.expires_at.is_some_and(|expires_at| now >= expires_at) {
            self.owner_session_id.clear();
            self.acquired_at = None;
            self.expires_at = None;
        }
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
        current_session: session_lock_owner(),
        checked_at: now_string(),
    }))
    .into_response())
}

pub async fn release_runtime_session(headers: HeaderMap) -> Result<Response> {
    let session_id = match require_session_id(&headers) {
        Ok(session_id) => session_id,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };

    release_session_lock(&session_id);
    release_all_hid_state();

    Ok(Json(ApiResponse::ok(json!({
        "released": true,
        "current_session": session_lock_owner()
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

pub async fn screenshot(
    headers: HeaderMap,
    Query(query): Query<ScreenshotQuery>,
) -> Result<Response> {
    let session_id = match require_session_id(&headers) {
        Ok(session_id) => session_id,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };
    let release_after = match acquire_session_lock(&session_id) {
        Ok(release_after) => release_after,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };

    let wants_base64 = query.format == "base64";
    let capture = task::spawn_blocking(move || capture_screenshot_blocking(query)).await;

    if release_after {
        release_session_lock(&session_id);
    }

    let (data, mut meta) = match capture {
        Ok(Ok(capture)) => capture,
        Ok(Err(err)) => return Ok(picoclaw_error_data(err)),
        Err(err) => {
            return Ok(picoclaw_error(
                CODE_SCREENSHOT_FAILED,
                format!("screenshot task failed: {err}"),
            ));
        }
    };

    if wants_base64 {
        meta.image_base64 = BASE64_STANDARD.encode(data);
        return Ok(Json(ApiResponse::ok(meta)).into_response());
    }

    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "image/jpeg")], data).into_response())
}

pub async fn actions(headers: HeaderMap, body: Bytes) -> Result<Response> {
    let session_id = match require_session_id(&headers) {
        Ok(session_id) => session_id,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };
    let actions = match normalize_actions(&body) {
        Ok(actions) => actions,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };
    let release_after = match acquire_session_lock(&session_id) {
        Ok(release_after) => release_after,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };

    let exec_session_id = session_id.clone();
    let result =
        task::spawn_blocking(move || execute_actions_blocking(&exec_session_id, &actions)).await;

    if release_after {
        release_session_lock(&session_id);
    }

    match result {
        Ok(Ok(result)) => Ok(Json(ApiResponse::ok(result)).into_response()),
        Ok(Err(err)) => Ok(picoclaw_error_data(err)),
        Err(err) => Ok(picoclaw_error(
            CODE_INVALID_ACTION,
            format!("action task failed: {err}"),
        )),
    }
}

pub async fn mcp(headers: HeaderMap, body: Bytes) -> Result<Response> {
    let req = match serde_json::from_slice::<JsonRpcRequest>(&body) {
        Ok(req) => req,
        Err(_) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(json_rpc_error(JsonValue::Null, -32700, "parse error")),
            )
                .into_response());
        }
    };

    if req.jsonrpc != "2.0" {
        return Ok(Json(json_rpc_error(
            req.id,
            -32600,
            "invalid request: jsonrpc must be 2.0",
        ))
        .into_response());
    }

    let response = match req.method.as_str() {
        "initialize" => json_rpc_result(
            req.id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "nanokvm", "version": "1.0.0" }
            }),
        ),
        "tools/list" => json_rpc_result(req.id, json!({ "tools": mcp_tool_definitions() })),
        "tools/call" => mcp_tools_call(&headers, req),
        "ping" => json_rpc_result(req.id, json!({})),
        method => json_rpc_error(req.id, -32601, format!("method not found: {method}")),
    };

    Ok(Json(response).into_response())
}

pub async fn load_image(headers: HeaderMap, body: Bytes) -> Result<Response> {
    let req = match serde_json::from_slice::<LoadImageRequest>(&body) {
        Ok(req) => req,
        Err(_) => {
            return Ok(picoclaw_error(
                CODE_INVALID_ACTION,
                "invalid load image payload",
            ));
        }
    };

    let source_path = req.path.trim();
    let _ = req.filename.trim();
    let _instruction = build_load_image_instruction(source_path, &req.prompt);
    if source_path.is_empty() {
        return Ok(picoclaw_error(
            CODE_INVALID_ACTION,
            "image path is required",
        ));
    }

    let session_id = headers
        .get(SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(session_lock_owner);
    if session_id.is_empty() {
        return Ok(picoclaw_error(
            CODE_SESSION_ID_MISSING,
            "missing X-PicoClaw-Session-ID",
        ));
    }

    Ok(picoclaw_error_with_session(
        CODE_RUNTIME_UNAVAILABLE,
        "picoclaw session is not connected",
        session_id,
    ))
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

fn require_session_id(headers: &HeaderMap) -> std::result::Result<String, PicoclawErrorData> {
    let session_id = headers
        .get(SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if session_id.is_empty() {
        return Err(PicoclawErrorData::new(
            CODE_SESSION_ID_MISSING,
            "missing X-PicoClaw-Session-ID",
        ));
    }
    Ok(session_id.to_string())
}

fn acquire_session_lock(session_id: &str) -> std::result::Result<bool, PicoclawErrorData> {
    if session_id.trim().is_empty() {
        return Err(PicoclawErrorData::new(
            CODE_SESSION_ID_INVALID,
            "invalid PicoClaw session",
        ));
    }

    let mut lock = SESSION_LOCK
        .lock()
        .map_err(|_| PicoclawErrorData::new(CODE_RUNTIME_UNAVAILABLE, "session lock poisoned"))?;
    let now = Instant::now();
    lock.clear_expired(now);

    if lock.owner_session_id.is_empty() || lock.owner_session_id == session_id {
        let acquired = lock.owner_session_id.is_empty();
        lock.owner_session_id = session_id.to_string();
        if lock.acquired_at.is_none() {
            lock.acquired_at = Some(now);
        }
        lock.expires_at = Some(now + SESSION_LOCK_DURATION);
        return Ok(acquired);
    }

    Err(PicoclawErrorData::new(
        CODE_PICOCLAW_LOCK_HELD,
        "another PicoClaw session is running",
    )
    .with_session(lock.owner_session_id.clone()))
}

fn ensure_session_lock(session_id: &str) -> std::result::Result<(), PicoclawErrorData> {
    acquire_session_lock(session_id).map(|_| ())
}

fn release_session_lock(session_id: &str) -> bool {
    let Ok(mut lock) = SESSION_LOCK.lock() else {
        return false;
    };
    if lock.owner_session_id.is_empty() {
        return true;
    }
    if !session_id.is_empty() && lock.owner_session_id != session_id {
        return false;
    }

    lock.owner_session_id.clear();
    lock.acquired_at = None;
    lock.expires_at = None;
    true
}

fn session_lock_owner() -> String {
    let Ok(mut lock) = SESSION_LOCK.lock() else {
        return String::new();
    };
    lock.clear_expired(Instant::now());
    lock.owner_session_id.clone()
}

fn capture_screenshot_blocking(
    query: ScreenshotQuery,
) -> std::result::Result<(Vec<u8>, ScreenshotMeta), PicoclawErrorData> {
    let (_width, _height, _quality, source_width, source_height) =
        resolve_screenshot_request(&query);
    let Some(frame) = stream::latest_mjpeg_frame(CACHED_FRAME_MAX_AGE) else {
        return Err(PicoclawErrorData::new(
            CODE_SCREENSHOT_FAILED,
            "no cached MJPEG frame available",
        ));
    };

    Ok((
        frame.data,
        ScreenshotMeta {
            image_base64: String::new(),
            source_width,
            source_height,
            capture_width: frame.width,
            capture_height: frame.height,
            format: "jpeg".to_string(),
        },
    ))
}

fn resolve_screenshot_request(query: &ScreenshotQuery) -> (u16, u16, u16, u16, u16) {
    let screen = stream::current_mjpeg_screen();
    let source_width = screen.width;
    let source_height = screen.height;
    let mut width = screen.width;
    let mut height = screen.height;
    let mut quality = screen.quality;

    if query.format == "base64" {
        (width, height) = fit_within_bounds(
            width,
            height,
            DEFAULT_SCREENSHOT_WIDTH,
            DEFAULT_SCREENSHOT_HEIGHT,
        );
        if quality == 0 || quality > DEFAULT_SCREENSHOT_QUALITY {
            quality = DEFAULT_SCREENSHOT_QUALITY;
        }
    }

    (width, height) = apply_requested_dimensions(width, height, query.width, query.height);
    (width, height) = safe_screenshot_capture_dimensions(width, height);
    if query.quality > 0 {
        quality = query.quality;
    }

    (width, height, quality, source_width, source_height)
}

fn apply_requested_dimensions(
    default_width: u16,
    default_height: u16,
    requested_width: u16,
    requested_height: u16,
) -> (u16, u16) {
    match (requested_width, requested_height) {
        (width, height) if width > 0 && height > 0 => (width, height),
        (width, _) if width > 0 => fit_within_bounds(default_width, default_height, width, 0),
        (_, height) if height > 0 => fit_within_bounds(default_width, default_height, 0, height),
        _ => (default_width, default_height),
    }
}

fn fit_within_bounds(
    source_width: u16,
    source_height: u16,
    max_width: u16,
    max_height: u16,
) -> (u16, u16) {
    if source_width == 0 || source_height == 0 || (max_width == 0 && max_height == 0) {
        return (source_width, source_height);
    }

    let width = u32::from(source_width);
    let height = u32::from(source_height);
    let mut limited_width = width;
    let mut limited_height = height;

    if max_width > 0 && limited_width > u32::from(max_width) {
        limited_width = u32::from(max_width);
        limited_height = height.saturating_mul(limited_width) / width;
    }
    if max_height > 0 && limited_height > u32::from(max_height) {
        limited_height = u32::from(max_height);
        limited_width = width.saturating_mul(limited_height) / height;
    }

    (
        limited_width.clamp(1, u32::from(u16::MAX)) as u16,
        limited_height.clamp(1, u32::from(u16::MAX)) as u16,
    )
}

fn safe_screenshot_capture_dimensions(width: u16, height: u16) -> (u16, u16) {
    if is_roughly_4_3(width, height) {
        if width <= 640 && height <= 480 {
            return (640, 480);
        }
        if width <= 800 && height <= 600 {
            return (800, 600);
        }
    }

    if width <= 1280 && height <= 720 {
        return (1280, 720);
    }

    (1920, 1080)
}

fn is_roughly_4_3(width: u16, height: u16) -> bool {
    if width == 0 || height == 0 {
        return false;
    }
    let lhs = i32::from(width) * 3;
    let rhs = i32::from(height) * 4;
    (lhs - rhs).abs() <= 8
}

fn normalize_actions(raw: &[u8]) -> std::result::Result<Vec<Action>, PicoclawErrorData> {
    if raw.is_empty() {
        return Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "empty action payload",
        ));
    }

    if let Ok(batch) = serde_json::from_slice::<ActionBatch>(raw) {
        if !batch.actions.is_empty() {
            return Ok(batch.actions);
        }
    }

    let action = serde_json::from_slice::<Action>(raw)
        .map_err(|_| PicoclawErrorData::new(CODE_INVALID_ACTION, "invalid action payload"))?;
    if action.action.trim().is_empty() {
        return Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "invalid action payload",
        ));
    }
    Ok(vec![action])
}

fn execute_actions_blocking(
    session_id: &str,
    actions: &[Action],
) -> std::result::Result<ActionResult, PicoclawErrorData> {
    let started_at = Instant::now();
    if actions.is_empty() {
        return Err(PicoclawErrorData::new(CODE_INVALID_ACTION, "empty actions"));
    }

    let mut total_writes = 0;
    for (idx, action) in actions.iter().enumerate() {
        if let Err(err) = ensure_session_lock(session_id) {
            release_all_hid_state();
            return Err(err.with_index(idx));
        }
        match execute_action_blocking(action) {
            Ok(writes) => total_writes += writes,
            Err(err) => {
                release_all_hid_state();
                return Err(err.with_index(idx));
            }
        }
    }

    Ok(ActionResult {
        action: if actions.len() > 1 {
            "batch".to_string()
        } else {
            actions[0].action.clone()
        },
        duration_ms: started_at.elapsed().as_millis().min(i64::MAX as u128) as i64,
        hid_writes: total_writes,
        executed_actions: (actions.len() > 1).then_some(actions.len()),
    })
}

fn execute_action_blocking(action: &Action) -> std::result::Result<usize, PicoclawErrorData> {
    match action.action.trim().to_ascii_lowercase().as_str() {
        "click" => {
            let (x, y) = normalized_point(action.x, action.y)?;
            let button = mouse_button(&action.button)?;
            let mut writes = 0;
            writes += send_mouse_move_with_button(x, y, 0x00, 0)?;
            writes += send_mouse_move_with_button(x, y, button, 0)?;
            thread::sleep(DEFAULT_CLICK_HOLD);
            writes += send_mouse_move_with_button(x, y, 0x00, 0)?;
            Ok(writes)
        }
        "move" => {
            let (x, y) = normalized_point(action.x, action.y)?;
            send_mouse_move_with_button(x, y, 0x00, 0)
        }
        "wait" => {
            if action.duration_ms < 0 {
                return Err(PicoclawErrorData::new(
                    CODE_INVALID_ACTION,
                    "wait duration must be >= 0",
                ));
            }
            thread::sleep(Duration::from_millis(action.duration_ms as u64));
            Ok(0)
        }
        "drag" => {
            let (from_x, from_y) = normalized_nested_point(action.from.as_ref())?;
            let (to_x, to_y) = normalized_nested_point(action.to.as_ref())?;
            let button = mouse_button(&action.button)?;
            let mut writes = 0;
            writes += send_mouse_move_with_button(from_x, from_y, 0x00, 0)?;
            writes += send_mouse_move_with_button(from_x, from_y, button, 0)?;
            for step in 1..=DEFAULT_DRAG_STEPS {
                let ratio = step as f64 / DEFAULT_DRAG_STEPS as f64;
                let x = from_x + (to_x - from_x) * ratio;
                let y = from_y + (to_y - from_y) * ratio;
                writes += send_mouse_move_with_button(x, y, button, 0)?;
            }
            writes += send_mouse_move_with_button(to_x, to_y, 0x00, 0)?;
            Ok(writes)
        }
        "scroll" => {
            let (x, y) = if action.x.is_some() || action.y.is_some() {
                normalized_point(action.x, action.y)?
            } else {
                (0.5, 0.5)
            };
            let amount = if action.amount == 0 { 1 } else { action.amount };
            if amount < 0 {
                return Err(PicoclawErrorData::new(
                    CODE_INVALID_ACTION,
                    "scroll amount must be > 0",
                ));
            }
            let wheel = match action.direction.trim().to_ascii_lowercase().as_str() {
                "" | "up" => 1,
                "down" => -1,
                _ => {
                    return Err(PicoclawErrorData::new(
                        CODE_INVALID_ACTION,
                        "invalid scroll direction",
                    ));
                }
            };
            let mut writes = 0;
            for _ in 0..amount {
                writes += send_mouse_move_with_button(x, y, 0x00, wheel)?;
                writes += send_mouse_move_with_button(x, y, 0x00, 0)?;
                thread::sleep(DEFAULT_SCROLL_STEP);
            }
            Ok(writes)
        }
        "type" => {
            if action.text.is_empty() {
                return Err(PicoclawErrorData::new(
                    CODE_INVALID_ACTION,
                    "type requires text",
                ));
            }
            hid::type_text_blocking(&action.text, "")
                .map_err(|err| PicoclawErrorData::new(CODE_INVALID_ACTION, err.to_string()))
        }
        "hotkey" => {
            let keys = normalize_hotkey_keys(action.keys.as_ref())?;
            let report = build_hotkey_report(&keys)?;
            let mut writes = 0;
            writes += send_keyboard_report(&report)?;
            thread::sleep(DEFAULT_CLICK_HOLD);
            writes += send_keyboard_report(&[0; 8])?;
            Ok(writes)
        }
        _ => Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "unknown or invalid action",
        )),
    }
}

fn normalized_point(
    x: Option<f64>,
    y: Option<f64>,
) -> std::result::Result<(f64, f64), PicoclawErrorData> {
    let (Some(x), Some(y)) = (x, y) else {
        return Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "action requires x and y",
        ));
    };
    if !(0.0..=1.0).contains(&x) || !(0.0..=1.0).contains(&y) {
        return Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "coordinates must be within [0,1]",
        ));
    }
    Ok((x, y))
}

fn normalized_nested_point(
    point: Option<&Point>,
) -> std::result::Result<(f64, f64), PicoclawErrorData> {
    let Some(point) = point else {
        return Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "action requires point coordinates",
        ));
    };
    normalized_point(point.x, point.y)
}

fn mouse_button(button: &str) -> std::result::Result<u8, PicoclawErrorData> {
    match button.trim().to_ascii_lowercase().as_str() {
        "" | "left" => Ok(1 << 0),
        "right" => Ok(1 << 1),
        "middle" => Ok(1 << 2),
        "back" => Ok(1 << 3),
        "forward" => Ok(1 << 4),
        _ => Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "invalid mouse button",
        )),
    }
}

fn send_mouse_move_with_button(
    x: f64,
    y: f64,
    buttons: u8,
    wheel: i32,
) -> std::result::Result<usize, PicoclawErrorData> {
    let absolute_x = to_absolute_hid_coord(x);
    let absolute_y = to_absolute_hid_coord(y);
    let report = [
        buttons,
        (absolute_x & 0xff) as u8,
        (absolute_x >> 8) as u8,
        (absolute_y & 0xff) as u8,
        (absolute_y >> 8) as u8,
        (wheel as i8) as u8,
    ];
    hid_ws::write_absolute_mouse_report(&report).map_err(|err| {
        PicoclawErrorData::new(
            CODE_HID_WRITE_FAILED,
            format!("failed to write HID mouse report: {err}"),
        )
    })?;
    Ok(1)
}

fn send_keyboard_report(report: &[u8; 8]) -> std::result::Result<usize, PicoclawErrorData> {
    hid_ws::write_keyboard_report(report).map_err(|err| {
        PicoclawErrorData::new(
            CODE_HID_WRITE_FAILED,
            format!("failed to write HID keyboard report: {err}"),
        )
    })?;
    Ok(1)
}

fn to_absolute_hid_coord(normalized: f64) -> u16 {
    let normalized = normalized.clamp(0.0, 1.0);
    (f64::from(0x7fff) * normalized).floor() as u16 + 1
}

fn release_all_hid_state() {
    let _ = hid_ws::write_keyboard_report(&[0; 8]);
    let _ = hid_ws::write_relative_mouse_report(&[0; 4]);
    let _ = hid_ws::write_absolute_mouse_report(&[0; 6]);
}

fn normalize_hotkey_keys(
    value: Option<&JsonValue>,
) -> std::result::Result<Vec<String>, PicoclawErrorData> {
    let Some(value) = value else {
        return Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "hotkey requires at least one key",
        ));
    };

    let keys = match value {
        JsonValue::Array(items) => items
            .iter()
            .filter_map(JsonValue::as_str)
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>(),
        JsonValue::String(csv) => csv
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>(),
        _ => {
            return Err(PicoclawErrorData::new(
                CODE_INVALID_ACTION,
                "invalid hotkey keys",
            ));
        }
    };

    if keys.is_empty() {
        return Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "hotkey requires at least one key",
        ));
    }
    Ok(keys)
}

fn build_hotkey_report(keys: &[String]) -> std::result::Result<[u8; 8], PicoclawErrorData> {
    if keys.is_empty() {
        return Err(PicoclawErrorData::new(
            CODE_INVALID_ACTION,
            "hotkey requires at least one key",
        ));
    }

    let mut report = [0_u8; 8];
    let mut next_index = 2;
    for key in keys {
        let (code, is_modifier) = resolve_key(key)?;
        if is_modifier {
            report[0] |= code;
            continue;
        }
        if next_index >= report.len() {
            return Err(PicoclawErrorData::new(
                CODE_INVALID_ACTION,
                "hotkey supports at most 6 non-modifier keys",
            ));
        }
        report[next_index] = code;
        next_index += 1;
    }

    Ok(report)
}

fn resolve_key(key: &str) -> std::result::Result<(u8, bool), PicoclawErrorData> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err(PicoclawErrorData::new(CODE_INVALID_ACTION, "empty key"));
    }

    if let Some(modifier) = modifier_code(trimmed) {
        return Ok((modifier, true));
    }
    if let Some(code) = key_code(trimmed) {
        return Ok((code, false));
    }

    let upper = trimmed.to_ascii_uppercase();
    if let Some(alias) = key_alias(&upper) {
        if let Some(modifier) = modifier_code(alias) {
            return Ok((modifier, true));
        }
        if let Some(code) = key_code(alias) {
            return Ok((code, false));
        }
    }

    if upper.len() == 1 {
        let byte = upper.as_bytes()[0];
        if byte.is_ascii_uppercase() {
            return Ok((byte - b'A' + 0x04, false));
        }
        if byte.is_ascii_digit() {
            let code = if byte == b'0' {
                0x27
            } else {
                byte - b'1' + 0x1e
            };
            return Ok((code, false));
        }
    }

    Err(PicoclawErrorData::new(
        CODE_INVALID_ACTION,
        format!("unsupported key: {key}"),
    ))
}

fn modifier_code(key: &str) -> Option<u8> {
    match key {
        "ControlLeft" => Some(1 << 0),
        "ShiftLeft" => Some(1 << 1),
        "AltLeft" => Some(1 << 2),
        "MetaLeft" => Some(1 << 3),
        "ControlRight" => Some(1 << 4),
        "ShiftRight" => Some(1 << 5),
        "AltRight" => Some(1 << 6),
        "MetaRight" => Some(1 << 7),
        _ => None,
    }
}

fn key_alias(key: &str) -> Option<&'static str> {
    match key {
        "CTRL" | "CONTROL" => Some("ControlLeft"),
        "SHIFT" => Some("ShiftLeft"),
        "ALT" | "OPTION" => Some("AltLeft"),
        "META" | "WIN" | "WINDOWS" | "COMMAND" | "CMD" | "SUPER" => Some("MetaLeft"),
        "ESC" => Some("Escape"),
        "RETURN" | "ENTER" => Some("Enter"),
        "DEL" => Some("Delete"),
        "INS" => Some("Insert"),
        "UP" => Some("ArrowUp"),
        "DOWN" => Some("ArrowDown"),
        "LEFT" => Some("ArrowLeft"),
        "RIGHT" => Some("ArrowRight"),
        "SPACEBAR" | "SPACE" => Some("Space"),
        "TAB" => Some("Tab"),
        "BACKSPACE" => Some("Backspace"),
        "PGUP" => Some("PageUp"),
        "PGDN" => Some("PageDown"),
        _ => None,
    }
}

fn key_code(key: &str) -> Option<u8> {
    match key {
        "KeyA" => Some(0x04),
        "KeyB" => Some(0x05),
        "KeyC" => Some(0x06),
        "KeyD" => Some(0x07),
        "KeyE" => Some(0x08),
        "KeyF" => Some(0x09),
        "KeyG" => Some(0x0a),
        "KeyH" => Some(0x0b),
        "KeyI" => Some(0x0c),
        "KeyJ" => Some(0x0d),
        "KeyK" => Some(0x0e),
        "KeyL" => Some(0x0f),
        "KeyM" => Some(0x10),
        "KeyN" => Some(0x11),
        "KeyO" => Some(0x12),
        "KeyP" => Some(0x13),
        "KeyQ" => Some(0x14),
        "KeyR" => Some(0x15),
        "KeyS" => Some(0x16),
        "KeyT" => Some(0x17),
        "KeyU" => Some(0x18),
        "KeyV" => Some(0x19),
        "KeyW" => Some(0x1a),
        "KeyX" => Some(0x1b),
        "KeyY" => Some(0x1c),
        "KeyZ" => Some(0x1d),
        "Digit1" => Some(0x1e),
        "Digit2" => Some(0x1f),
        "Digit3" => Some(0x20),
        "Digit4" => Some(0x21),
        "Digit5" => Some(0x22),
        "Digit6" => Some(0x23),
        "Digit7" => Some(0x24),
        "Digit8" => Some(0x25),
        "Digit9" => Some(0x26),
        "Digit0" => Some(0x27),
        "Enter" => Some(0x28),
        "Escape" => Some(0x29),
        "Backspace" => Some(0x2a),
        "Tab" => Some(0x2b),
        "Space" => Some(0x2c),
        "Minus" => Some(0x2d),
        "Equal" => Some(0x2e),
        "BracketLeft" => Some(0x2f),
        "BracketRight" => Some(0x30),
        "Backslash" => Some(0x31),
        "IntlHash" => Some(0x32),
        "Semicolon" => Some(0x33),
        "Quote" => Some(0x34),
        "Backquote" => Some(0x35),
        "Comma" => Some(0x36),
        "Period" => Some(0x37),
        "Slash" => Some(0x38),
        "CapsLock" => Some(0x39),
        "F1" => Some(0x3a),
        "F2" => Some(0x3b),
        "F3" => Some(0x3c),
        "F4" => Some(0x3d),
        "F5" => Some(0x3e),
        "F6" => Some(0x3f),
        "F7" => Some(0x40),
        "F8" => Some(0x41),
        "F9" => Some(0x42),
        "F10" => Some(0x43),
        "F11" => Some(0x44),
        "F12" => Some(0x45),
        "PrintScreen" => Some(0x46),
        "ScrollLock" => Some(0x47),
        "Pause" => Some(0x48),
        "Insert" => Some(0x49),
        "Home" => Some(0x4a),
        "PageUp" => Some(0x4b),
        "Delete" => Some(0x4c),
        "End" => Some(0x4d),
        "PageDown" => Some(0x4e),
        "ArrowRight" => Some(0x4f),
        "ArrowLeft" => Some(0x50),
        "ArrowDown" => Some(0x51),
        "ArrowUp" => Some(0x52),
        "NumLock" => Some(0x53),
        "NumpadDivide" => Some(0x54),
        "NumpadMultiply" => Some(0x55),
        "NumpadSubtract" => Some(0x56),
        "NumpadAdd" => Some(0x57),
        "NumpadEnter" => Some(0x58),
        "Numpad1" => Some(0x59),
        "Numpad2" => Some(0x5a),
        "Numpad3" => Some(0x5b),
        "Numpad4" => Some(0x5c),
        "Numpad5" => Some(0x5d),
        "Numpad6" => Some(0x5e),
        "Numpad7" => Some(0x5f),
        "Numpad8" => Some(0x60),
        "Numpad9" => Some(0x61),
        "Numpad0" => Some(0x62),
        "NumpadDecimal" => Some(0x63),
        "IntlBackslash" => Some(0x64),
        "ContextMenu" => Some(0x65),
        "Power" => Some(0x66),
        "NumpadEqual" => Some(0x67),
        "F13" => Some(0x68),
        "F14" => Some(0x69),
        "F15" => Some(0x6a),
        "F16" => Some(0x6b),
        "F17" => Some(0x6c),
        "F18" => Some(0x6d),
        "F19" => Some(0x6e),
        "F20" => Some(0x6f),
        "F21" => Some(0x70),
        "F22" => Some(0x71),
        "F23" => Some(0x72),
        "F24" => Some(0x73),
        "Execute" => Some(0x74),
        "Help" => Some(0x75),
        "Props" => Some(0x76),
        "Select" => Some(0x77),
        "Stop" => Some(0x78),
        "Again" => Some(0x79),
        "Undo" => Some(0x7a),
        "Cut" => Some(0x7b),
        "Copy" => Some(0x7c),
        "Paste" => Some(0x7d),
        "Find" => Some(0x7e),
        "AudioVolumeMute" | "VolumeMute" => Some(0x7f),
        "AudioVolumeUp" | "VolumeUp" => Some(0x80),
        "AudioVolumeDown" | "VolumeDown" => Some(0x81),
        "LockingCapsLock" => Some(0x82),
        "LockingNumLock" => Some(0x83),
        "LockingScrollLock" => Some(0x84),
        "NumpadComma" => Some(0x85),
        "NumpadEqual2" => Some(0x86),
        "IntlRo" => Some(0x87),
        "KanaMode" => Some(0x88),
        "IntlYen" => Some(0x89),
        "Convert" => Some(0x8a),
        "NonConvert" => Some(0x8b),
        "International6" => Some(0x8c),
        "International7" => Some(0x8d),
        "International8" => Some(0x8e),
        "International9" => Some(0x8f),
        "Lang1" => Some(0x90),
        "Lang2" => Some(0x91),
        "Lang3" => Some(0x92),
        "Lang4" => Some(0x93),
        "Lang5" => Some(0x94),
        "Lang6" => Some(0x95),
        "Lang7" => Some(0x96),
        "Lang8" => Some(0x97),
        "Lang9" => Some(0x98),
        "NumpadParenLeft" => Some(0xb6),
        "NumpadParenRight" => Some(0xb7),
        "NumpadBackspace" => Some(0xbb),
        "NumpadMemoryStore" => Some(0xd0),
        "NumpadMemoryRecall" => Some(0xd1),
        "NumpadMemoryClear" => Some(0xd2),
        "NumpadMemoryAdd" => Some(0xd3),
        "NumpadMemorySubtract" => Some(0xd4),
        "NumpadClear" => Some(0xd8),
        "NumpadClearEntry" => Some(0xd9),
        "BrowserSearch" | "LaunchApp2" => Some(0xf0),
        "BrowserHome" => Some(0xf1),
        "BrowserBack" => Some(0xf2),
        "BrowserForward" => Some(0xf3),
        "BrowserStop" => Some(0xf4),
        "BrowserRefresh" => Some(0xf5),
        "BrowserFavorites" => Some(0xf6),
        "MediaPlayPause" => Some(0xe8),
        "MediaStop" => Some(0xe9),
        "MediaTrackPrevious" => Some(0xea),
        "MediaTrackNext" => Some(0xeb),
        "Eject" => Some(0xec),
        "MediaSelect" => Some(0xed),
        "LaunchMail" => Some(0xee),
        "LaunchApp1" => Some(0xef),
        "Sleep" => Some(0xf8),
        "Wake" => Some(0xf9),
        "MediaRewind" => Some(0xfa),
        "MediaFastForward" => Some(0xfb),
        _ => None,
    }
}

fn mcp_tools_call(headers: &HeaderMap, req: JsonRpcRequest) -> JsonRpcResponse {
    let Some(params) = req.params.as_ref() else {
        return json_rpc_error(req.id, -32602, "invalid params");
    };
    let name = params
        .get("name")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    let arguments = params.get("arguments").cloned().unwrap_or(JsonValue::Null);

    match name {
        "kvm_screenshot" => mcp_screenshot(req.id, arguments),
        "kvm_actions" => mcp_actions(headers, req.id, arguments),
        _ => json_rpc_error(req.id, -32602, format!("unknown tool: {name}")),
    }
}

fn mcp_screenshot(id: JsonValue, arguments: JsonValue) -> JsonRpcResponse {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct ScreenshotArgs {
        width: u16,
        height: u16,
        quality: u16,
    }

    let args = serde_json::from_value::<ScreenshotArgs>(arguments).unwrap_or_default();
    let query = ScreenshotQuery {
        format: "base64".to_string(),
        width: args.width,
        height: args.height,
        quality: args.quality,
    };

    match capture_screenshot_blocking(query) {
        Ok((data, meta)) => {
            let b64 = BASE64_STANDARD.encode(data);
            json_rpc_result(
                id,
                json!({
                    "content": [
                        { "type": "text", "text": "screenshot captured" },
                        { "type": "image", "data": b64, "mimeType": "image/jpeg" }
                    ],
                    "meta": {
                        "source_width": meta.source_width,
                        "source_height": meta.source_height,
                        "capture_width": meta.capture_width,
                        "capture_height": meta.capture_height
                    }
                }),
            )
        }
        Err(err) => mcp_tool_error(id, err.message),
    }
}

fn mcp_actions(headers: &HeaderMap, id: JsonValue, arguments: JsonValue) -> JsonRpcResponse {
    let batch = match serde_json::from_value::<ActionBatch>(arguments) {
        Ok(batch) if !batch.actions.is_empty() => batch,
        _ => return mcp_tool_error(id, "invalid actions payload"),
    };

    let session_id = headers
        .get(SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(session_lock_owner);

    match execute_actions_blocking(&session_id, &batch.actions) {
        Ok(result) => {
            let text = serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string());
            json_rpc_result(id, json!({ "content": [{ "type": "text", "text": text }] }))
        }
        Err(err) => mcp_tool_error(id, err.message),
    }
}

fn mcp_tool_definitions() -> JsonValue {
    json!([
        {
            "name": "kvm_screenshot",
            "description": "Capture the current HDMI frame from the downstream remote host as a base64-encoded JPEG image.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "width": { "type": "integer", "description": "Target width in pixels (optional, default: 960)" },
                    "height": { "type": "integer", "description": "Target height in pixels (optional)" },
                    "quality": { "type": "integer", "description": "JPEG quality 1-100 (optional, default: 60)" }
                }
            }
        },
        {
            "name": "kvm_actions",
            "description": "Send one or more HID actions (click, type, hotkey, scroll, drag, move, wait) to the downstream remote host. Use normalized [0,1] coordinates for mouse actions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actions": {
                        "type": "array",
                        "description": "Array of action objects. Each requires an 'action' field (click, move, type, hotkey, scroll, drag, wait).",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": { "type": "string" },
                                "x": { "type": "number" },
                                "y": { "type": "number" },
                                "button": { "type": "string" },
                                "text": { "type": "string" },
                                "keys": { "type": "array", "items": { "type": "string" } },
                                "direction": { "type": "string" },
                                "amount": { "type": "integer" },
                                "duration_ms": { "type": "integer" },
                                "from": { "type": "object", "properties": { "x": { "type": "number" }, "y": { "type": "number" } } },
                                "to": { "type": "object", "properties": { "x": { "type": "number" }, "y": { "type": "number" } } }
                            },
                            "required": ["action"]
                        }
                    }
                },
                "required": ["actions"]
            }
        }
    ])
}

fn json_rpc_result(id: JsonValue, result: JsonValue) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(result),
        error: None,
    }
}

fn json_rpc_error(id: JsonValue, code: i32, message: impl Into<String>) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
        }),
    }
}

fn mcp_tool_error(id: JsonValue, message: impl Into<String>) -> JsonRpcResponse {
    json_rpc_result(
        id,
        json!({
            "isError": true,
            "content": [{ "type": "text", "text": message.into() }]
        }),
    )
}

fn build_load_image_instruction(source_path: &str, prompt: &str) -> String {
    let args_json = serde_json::to_string(&json!({ "path": source_path }))
        .unwrap_or_else(|_| "{\"path\":\"\"}".to_string());
    format!(
        "Call `load_image` first with this exact argument object:\n```json\n{args_json}\n```\n\nDo not ask the user to re-upload the image. Do not modify the path. Do not use `read_file` or any other tool to inspect this image directly.\n\nAfter `load_image` succeeds, treat the loaded image as the current task input and continue with this request:\n{}",
        normalize_image_prompt(prompt)
    )
}

fn normalize_image_prompt(prompt: &str) -> &str {
    let prompt = prompt.trim();
    if prompt.is_empty() {
        "Describe the image briefly."
    } else {
        prompt
    }
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

fn picoclaw_error_data(err: PicoclawErrorData) -> Response {
    (
        StatusCode::OK,
        Json(PicoclawErrorBody {
            code: err.code.to_string(),
            message: err.message,
            session_id: err.session_id,
            index: err.index,
        }),
    )
        .into_response()
}

fn picoclaw_error_with_session(
    code: &str,
    message: impl Into<String>,
    session_id: String,
) -> Response {
    (
        StatusCode::OK,
        Json(PicoclawErrorBody {
            code: code.to_string(),
            message: message.into(),
            session_id: Some(session_id),
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

    #[test]
    fn screenshot_dimensions_preserve_aspect_ratio() {
        assert_eq!(fit_within_bounds(1920, 1080, 960, 540), (960, 540));
        assert_eq!(fit_within_bounds(1920, 1080, 320, 0), (320, 180));
        assert_eq!(fit_within_bounds(1920, 1080, 0, 270), (480, 270));
    }

    #[test]
    fn screenshot_capture_dimensions_use_safe_libkvm_sizes() {
        assert_eq!(safe_screenshot_capture_dimensions(320, 180), (1280, 720));
        assert_eq!(safe_screenshot_capture_dimensions(960, 540), (1280, 720));
        assert_eq!(safe_screenshot_capture_dimensions(640, 480), (640, 480));
        assert_eq!(safe_screenshot_capture_dimensions(800, 600), (800, 600));
    }

    #[test]
    fn action_payload_accepts_single_or_batch() {
        let single = normalize_actions(br#"{"action":"wait","duration_ms":1}"#).unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].action, "wait");

        let batch = normalize_actions(
            br#"{"actions":[{"action":"wait"},{"action":"hotkey","keys":"ctrl,c"}]}"#,
        )
        .unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[1].action, "hotkey");
    }

    #[test]
    fn hotkey_report_matches_hid_usage_codes() {
        let report = build_hotkey_report(&[
            "ctrl".to_string(),
            "AltLeft".to_string(),
            "Delete".to_string(),
        ])
        .unwrap();
        assert_eq!(report[0], (1 << 0) | (1 << 2));
        assert_eq!(report[2], 0x4c);
    }

    #[test]
    fn absolute_hid_coords_match_go_formula() {
        assert_eq!(to_absolute_hid_coord(0.0), 1);
        assert_eq!(to_absolute_hid_coord(1.0), 0x8000);
    }

    #[test]
    fn mcp_initialize_shape_matches_go_contract() {
        let response = json_rpc_result(
            json!(1),
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "nanokvm", "version": "1.0.0" }
            }),
        );
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["result"]["serverInfo"]["name"], "nanokvm");
    }

    #[test]
    fn load_image_instruction_preserves_exact_path() {
        let instruction = build_load_image_instruction("/tmp/image.png", "");
        assert!(instruction.contains("\"path\":\"/tmp/image.png\""));
        assert!(instruction.contains("Describe the image briefly."));
    }
}
