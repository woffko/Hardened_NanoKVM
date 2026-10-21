use axum::{
    Json,
    body::Bytes,
    extract::{
        Path as AxumPath, Query, State,
        ws::{CloseFrame as AxumCloseFrame, Message as AxumWsMessage, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use flate2::read::GzDecoder;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use sha2::{Digest, Sha512};
use std::{
    ffi::OsString,
    fs, io,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tar::Archive;
use tokio::{net::TcpStream, task, time};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        Message as TungsteniteMessage, client::IntoClientRequest, http::header as ws_header,
    },
};
use tracing::debug;

use crate::{
    AppError, Result,
    api::{hid, stream},
    auth::token::random_token,
    error::ApiResponse,
    state::AppState,
    system::command::{self, AllowedCommand},
    ws::hid as hid_ws,
};

#[path = "picoclaw_action_plan.rs"]
mod action_plan;
use action_plan::{Batch as PreparedBatch, PreparedAction};
#[path = "picoclaw_execution.rs"]
pub(crate) mod execution;
use execution::{Call, Completion};
#[path = "picoclaw_worker.rs"]
pub(crate) mod worker;

const PICOCLAW_BINARY_PATH: &str = "/usr/bin/picoclaw";
const PICOCLAW_CACHE_DIR: &str = "/root/.picoclaw-cache";
const PICOCLAW_DOWNLOAD_URL: &str =
    "https://cdn.sipeed.com/nanokvm/resources/picoclaw/v0.2.8/picoclaw_Linux_riscv64.tar.gz";
const PICOCLAW_CHECKSUM_URL: &str =
    "https://cdn.sipeed.com/nanokvm/resources/picoclaw/v0.2.8/sha512.txt";
const DEFAULT_GATEWAY_HOST: &str = "127.0.0.1";
const DEFAULT_GATEWAY_PORT: u16 = 18790;
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_READ_TIMEOUT_MS: i32 = 60_000;
const DEFAULT_WRITE_TIMEOUT_MS: i32 = 10_000;
const DEFAULT_PING_INTERVAL_MS: i32 = 30_000;
const DEFAULT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const PICOCLAW_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PICOCLAW_START_TIMEOUT: Duration = Duration::from_secs(15);
const PICOCLAW_STOP_TIMEOUT: Duration = Duration::from_secs(15);
const PICOCLAW_ONBOARD_TIMEOUT: Duration = Duration::from_secs(90);
const INTERNAL_TOKEN_HEADER: &str = "X-NanoKVM-Internal-Token";
const SESSION_ID_HEADER: &str = "X-PicoClaw-Session-ID";

const CODE_PICOCLAW_LOCK_HELD: &str = "AI_LOCK_HELD";
const CODE_INVALID_ACTION: &str = "INVALID_ACTION";
const CODE_SCREENSHOT_FAILED: &str = "SCREENSHOT_FAILED";
const CODE_HID_WRITE_FAILED: &str = "HID_WRITE_FAILED";
const CODE_RUNTIME_UNAVAILABLE: &str = "RUNTIME_UNAVAILABLE";
const CODE_RUNTIME_START_FAILED: &str = "RUNTIME_START_FAILED";
const CODE_SESSION_ID_MISSING: &str = "SESSION_ID_MISSING";
const CODE_SESSION_ID_INVALID: &str = "SESSION_ID_INVALID";

const CLOSE_NORMAL: u16 = 1000;
const CLOSE_MESSAGE_TOO_BIG: u16 = 1009;
const CLOSE_PICOCLAW_TAKEN_OVER: u16 = 4004;
const CLOSE_UPSTREAM_CLOSED: u16 = 4005;

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
    #[serde(deserialize_with = "action_plan::deserialize_actions")]
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

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct GatewayQuery {
    session_id: String,
}

impl Default for GatewayQuery {
    fn default() -> Self {
        Self {
            session_id: String::new(),
        }
    }
}

#[derive(Debug)]
struct GatewayClose {
    code: u16,
    reason: String,
}

impl GatewayClose {
    fn new(code: u16, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    fn normal(reason: impl Into<String>) -> Self {
        Self::new(CLOSE_NORMAL, reason)
    }

    fn upstream(reason: impl Into<String>) -> Self {
        Self::new(CLOSE_UPSTREAM_CLOSED, reason)
    }
}

type GatewayUpstream = WebSocketStream<MaybeTlsStream<TcpStream>>;

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

    if let Err(err) = stop_runtime_inner().await {
        return Ok(picoclaw_error(CODE_RUNTIME_START_FAILED, err));
    }
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

pub async fn release_runtime_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response> {
    let session_id = match require_session_id(&headers) {
        Ok(session_id) => session_id,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };

    let receipt = match state.picoclaw_worker.cancel(Some(&session_id)) {
        Ok(receipt) => receipt,
        Err(error) => return Ok(picoclaw_error_data(error)),
    };
    let released = release_session_lock(&session_id);
    let cancelled_calls = receipt.wait(Duration::from_secs(1)).await;

    Ok(Json(ApiResponse::ok(json!({
        "released": released,
        "execution_stop_verified": false,
        "cancelled_calls": cancelled_calls,
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

    let (api_base, api_key, model) = (api_base.to_string(), api_key.to_string(), model.to_string());
    let result = crate::update::state_writers::StateWriters::default()
        .configuration()?
        .blocking(move |permit| {
            let model_name = update_model_config_file(permit, &api_base, &api_key, &model)?;
            write_startup_defaults(permit)?;
            Ok(model_name)
        })
        .await;
    match result {
        Ok(model_name) => {
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
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ScreenshotQuery>,
) -> Result<Response> {
    let session_id = match require_session_id(&headers) {
        Ok(session_id) => session_id,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };
    let wants_base64 = query.format == "base64";
    let (data, mut meta) = match state
        .picoclaw_worker
        .screenshot(Some(session_id), query)
        .await
    {
        Ok(capture) => capture,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };

    if wants_base64 {
        meta.image_base64 = BASE64_STANDARD.encode(data);
        return Ok(Json(ApiResponse::ok(meta)).into_response());
    }

    Ok((StatusCode::OK, [(header::CONTENT_TYPE, "image/jpeg")], data).into_response())
}

pub async fn actions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let session_id = match require_session_id(&headers) {
        Ok(session_id) => session_id,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };
    let actions = match normalize_actions(&body).and_then(PreparedBatch::prepare) {
        Ok(actions) => actions,
        Err(err) => return Ok(picoclaw_error_data(err)),
    };
    match state.picoclaw_worker.actions(session_id, actions).await {
        Ok(result) => Ok(Json(ApiResponse::ok(result)).into_response()),
        Err(err) => Ok(picoclaw_error_data(err)),
    }
}

pub async fn mcp(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
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
        "tools/call" => mcp_tools_call(&state, &headers, req).await,
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

pub async fn gateway_ws(
    State(state): State<AppState>,
    Query(query): Query<GatewayQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    let session_id = gateway_session_id(&query);
    if let Err(err) = ensure_session_lock(&session_id) {
        return Ok(picoclaw_error_data_status(StatusCode::CONFLICT, err));
    }

    if !is_installed() {
        release_session_lock(&session_id);
        update_runtime_gateway_state(
            false,
            "not_installed",
            Some("picoclaw is not installed".to_string()),
            None,
        );
        return Ok(picoclaw_error_with_session(
            CODE_RUNTIME_UNAVAILABLE,
            "picoclaw is not installed",
            session_id,
        ));
    }

    if let Err(err) = ensure_startup_defaults().await {
        release_session_lock(&session_id);
        update_runtime_gateway_state(false, "config_error", Some(err.to_string()), None);
        return Ok(picoclaw_error_with_session(
            CODE_RUNTIME_UNAVAILABLE,
            err.to_string(),
            session_id,
        ));
    }

    let settings = match load_gateway_settings() {
        Ok(settings) => settings,
        Err(err) => {
            release_session_lock(&session_id);
            update_runtime_gateway_state(false, "config_error", Some(err.to_string()), None);
            return Ok(picoclaw_error_with_session(
                CODE_RUNTIME_UNAVAILABLE,
                err.to_string(),
                session_id,
            ));
        }
    };

    update_runtime_gateway_state(false, "connecting", None, Some(&session_id));
    let upstream = match connect_gateway_upstream(&settings, &session_id).await {
        Ok(upstream) => upstream,
        Err(err) => {
            release_session_lock(&session_id);
            update_runtime_gateway_state(false, "unavailable", Some(err.clone()), None);
            return Ok(picoclaw_error_with_session(
                CODE_RUNTIME_UNAVAILABLE,
                err,
                session_id,
            ));
        }
    };

    update_runtime_gateway_state(true, "ready", None, Some(&session_id));
    Ok(ws
        .on_upgrade(move |socket| {
            handle_gateway_socket(
                session_id,
                socket,
                upstream,
                settings,
                state.picoclaw_worker,
            )
        })
        .into_response())
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
    authorize_loopback_internal_token(headers, remote, crate::update::picoclaw_token::read)
}

fn authorize_loopback_internal_token(
    headers: &HeaderMap,
    remote: Option<SocketAddr>,
    load: impl FnOnce() -> Result<String>,
) -> bool {
    if !remote.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return false;
    }
    let mut values = headers.get_all(INTERNAL_TOKEN_HEADER).iter();
    let Some(provided) = values.next().and_then(|value| value.to_str().ok()) else {
        return false;
    };
    if values.next().is_some() || !crate::update::picoclaw_token::valid_token(provided) {
        return false;
    }
    let Ok(token) = load() else {
        return false;
    };
    let token = zeroize::Zeroizing::new(token);
    if !crate::update::picoclaw_token::valid_token(&token) {
        return false;
    }
    constant_time_eq(provided, &token)
}

#[cfg(test)]
#[path = "picoclaw_internal_auth_tests.rs"]
mod internal_auth_tests;

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

fn check_session_lock(session_id: &str) -> std::result::Result<(), PicoclawErrorData> {
    let mut lock = SESSION_LOCK
        .lock()
        .map_err(|_| PicoclawErrorData::new(CODE_RUNTIME_UNAVAILABLE, "session lock poisoned"))?;
    lock.clear_expired(Instant::now());
    if lock.owner_session_id != session_id || lock.owner_session_id.is_empty() {
        return Err(PicoclawErrorData::new(
            CODE_SESSION_ID_INVALID,
            "PicoClaw input session is no longer active",
        ));
    }
    Ok(())
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

fn gateway_session_id(query: &GatewayQuery) -> String {
    let session_id = query.session_id.trim();
    if session_id.is_empty() {
        format!("rust-{}", random_token(16))
    } else {
        session_id.to_string()
    }
}

async fn connect_gateway_upstream(
    settings: &GatewaySettings,
    session_id: &str,
) -> std::result::Result<GatewayUpstream, String> {
    let url = build_gateway_url(settings, session_id);
    let mut request = url
        .into_client_request()
        .map_err(|err| format!("invalid gateway url: {err}"))?;

    if !settings.token.is_empty() {
        let header_value = format!("Bearer {}", settings.token)
            .parse()
            .map_err(|err| format!("invalid gateway token: {err}"))?;
        request
            .headers_mut()
            .insert(ws_header::AUTHORIZATION, header_value);
    }

    let timeout = Duration::from_millis(settings.connect_timeout_ms);
    match time::timeout(timeout, connect_async(request)).await {
        Ok(Ok((upstream, _))) => Ok(upstream),
        Ok(Err(err)) => Err(format!("gateway is unavailable: {err}")),
        Err(_) => Err("gateway connection timed out".to_string()),
    }
}

fn build_gateway_url(settings: &GatewaySettings, session_id: &str) -> String {
    let mut query = format!("session_id={}", urlencoding::encode(session_id));
    if settings.allow_token_query && !settings.token.is_empty() {
        query.push_str("&token=");
        query.push_str(&urlencoding::encode(&settings.token));
    }

    format!(
        "ws://{}:{}/pico/ws?{}",
        settings.gateway_host, settings.gateway_port, query
    )
}

async fn handle_gateway_socket(
    session_id: String,
    socket: WebSocket,
    upstream: GatewayUpstream,
    settings: GatewaySettings,
    worker: Arc<worker::Worker>,
) {
    let (mut downstream_tx, mut downstream_rx) = socket.split();
    let (mut upstream_tx, mut upstream_rx) = upstream.split();
    let mut ping = time::interval(Duration::from_millis(settings.ping_interval_ms));
    let read_timeout = Duration::from_millis(settings.read_timeout_ms.max(1) as u64);
    let write_timeout = Duration::from_millis(settings.write_timeout_ms.max(1) as u64);
    let mut read_deadline = Box::pin(time::sleep(read_timeout));

    ping.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    debug!(session_id, "picoclaw gateway websocket connected");

    let close = loop {
        tokio::select! {
            _ = &mut read_deadline => {
                break GatewayClose::upstream("gateway read timeout");
            }
            downstream = downstream_rx.next() => {
                read_deadline.as_mut().reset(time::Instant::now() + read_timeout);
                let message = match downstream {
                    Some(Ok(message)) => message,
                    Some(Err(err)) => {
                        break GatewayClose::normal(format!("downstream closed: {err}"));
                    }
                    None => break GatewayClose::normal("downstream closed"),
                };

                if let Err(close) = renew_gateway_session(&session_id) {
                    break close;
                }
                if let Err(close) = validate_gateway_message_size(axum_message_len(&message), settings.max_message_bytes) {
                    break close;
                }

                match gateway_requests_cancel(&message, &session_id) {
                    Ok(true) => {
                        if let Err(error) = worker.cancel(Some(&session_id)) {
                            break GatewayClose::upstream(error.message);
                        }
                    }
                    Ok(false) => {}
                    Err(close) => break close,
                }

                let is_close = matches!(message, AxumWsMessage::Close(_));
                match time::timeout(write_timeout, upstream_tx.send(axum_to_tungstenite_message(message))).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => break GatewayClose::upstream(format!("upstream write failed: {err}")),
                    Err(_) => break GatewayClose::upstream("upstream write timed out"),
                }
                if is_close {
                    break GatewayClose::normal("downstream closed");
                }
            }
            upstream = upstream_rx.next() => {
                read_deadline.as_mut().reset(time::Instant::now() + read_timeout);
                let message = match upstream {
                    Some(Ok(message)) => message,
                    Some(Err(err)) => break GatewayClose::upstream(format!("upstream closed: {err}")),
                    None => break GatewayClose::upstream("upstream closed"),
                };

                if let Err(close) = renew_gateway_session(&session_id) {
                    break close;
                }
                if let Err(close) = validate_gateway_message_size(tungstenite_message_len(&message), settings.max_message_bytes) {
                    break close;
                }

                let is_close = matches!(message, TungsteniteMessage::Close(_));
                let Some(message) = tungstenite_to_axum_message(message) else {
                    break GatewayClose::upstream("upstream sent unsupported binary message");
                };
                match time::timeout(write_timeout, downstream_tx.send(message)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => break GatewayClose::normal(format!("downstream write failed: {err}")),
                    Err(_) => break GatewayClose::normal("downstream write timed out"),
                }
                if is_close {
                    break GatewayClose::upstream("upstream closed");
                }
            }
            _ = ping.tick() => {
                if let Err(close) = renew_gateway_session(&session_id) {
                    break close;
                }
                match time::timeout(
                    write_timeout,
                    upstream_tx.send(TungsteniteMessage::Ping(Bytes::from_static(b"upstream"))),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => break GatewayClose::upstream("upstream ping failed"),
                    Err(_) => break GatewayClose::upstream("upstream ping timed out"),
                }
                match time::timeout(
                    write_timeout,
                    downstream_tx.send(AxumWsMessage::Ping(Bytes::from_static(b"downstream"))),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => break GatewayClose::normal("downstream ping failed"),
                    Err(_) => break GatewayClose::normal("downstream ping timed out"),
                }
            }
        }
    };

    // Record cancellation before any potentially stalled transport close.
    // This cancels selected admitted calls, not future task/session authority.
    let _ = worker.cancel(Some(&session_id));
    release_session_lock(&session_id);
    if close.code != CLOSE_NORMAL {
        let _ = time::timeout(
            write_timeout,
            downstream_tx.send(AxumWsMessage::Close(Some(AxumCloseFrame {
                code: close.code,
                reason: close.reason.clone().into(),
            }))),
        )
        .await;
    }
    let _ = time::timeout(
        write_timeout,
        upstream_tx.send(TungsteniteMessage::Close(None)),
    )
    .await;

    update_runtime_gateway_state(false, "closed", Some(close.reason.clone()), None);
    debug!(
        session_id,
        code = close.code,
        reason = close.reason,
        "picoclaw gateway websocket closed"
    );
}

fn gateway_requests_cancel(
    message: &AxumWsMessage,
    session_id: &str,
) -> std::result::Result<bool, GatewayClose> {
    let text = match message {
        AxumWsMessage::Text(text) => text,
        AxumWsMessage::Binary(_) => {
            return Err(GatewayClose::normal(
                "binary gateway control is unsupported",
            ));
        }
        _ => return Ok(false),
    };
    #[derive(Deserialize)]
    struct Envelope {
        #[serde(default)]
        r#type: Option<String>,
        #[serde(default)]
        session_id: Option<String>,
    }
    let envelope: Envelope = serde_json::from_str(text)
        .map_err(|_| GatewayClose::normal("invalid gateway control envelope"))?;
    if envelope
        .session_id
        .as_deref()
        .is_some_and(|id| id != session_id)
    {
        return Err(GatewayClose::normal("gateway session mismatch"));
    }
    Ok(envelope.r#type.as_deref() == Some("message.cancel"))
}

fn renew_gateway_session(session_id: &str) -> std::result::Result<(), GatewayClose> {
    ensure_session_lock(session_id)
        .map_err(|err| GatewayClose::new(CLOSE_PICOCLAW_TAKEN_OVER, err.message))
}

fn validate_gateway_message_size(
    len: usize,
    limit: usize,
) -> std::result::Result<(), GatewayClose> {
    if len > limit {
        Err(GatewayClose::new(
            CLOSE_MESSAGE_TOO_BIG,
            "gateway message is too large",
        ))
    } else {
        Ok(())
    }
}

fn axum_message_len(message: &AxumWsMessage) -> usize {
    match message {
        AxumWsMessage::Text(text) => text.as_str().len(),
        AxumWsMessage::Binary(data) | AxumWsMessage::Ping(data) | AxumWsMessage::Pong(data) => {
            data.len()
        }
        AxumWsMessage::Close(frame) => frame
            .as_ref()
            .map(|frame| frame.reason.as_str().len())
            .unwrap_or(0),
    }
}

fn tungstenite_message_len(message: &TungsteniteMessage) -> usize {
    match message {
        TungsteniteMessage::Text(text) => text.as_str().len(),
        TungsteniteMessage::Binary(data)
        | TungsteniteMessage::Ping(data)
        | TungsteniteMessage::Pong(data) => data.len(),
        TungsteniteMessage::Close(frame) => frame
            .as_ref()
            .map(|frame| frame.reason.as_str().len())
            .unwrap_or(0),
        TungsteniteMessage::Frame(frame) => frame.payload().len(),
    }
}

fn axum_to_tungstenite_message(message: AxumWsMessage) -> TungsteniteMessage {
    match message {
        AxumWsMessage::Text(text) => TungsteniteMessage::Text(text.as_str().to_string().into()),
        AxumWsMessage::Binary(data) => TungsteniteMessage::Binary(data),
        AxumWsMessage::Ping(data) => TungsteniteMessage::Ping(data),
        AxumWsMessage::Pong(data) => TungsteniteMessage::Pong(data),
        AxumWsMessage::Close(_) => TungsteniteMessage::Close(None),
    }
}

fn tungstenite_to_axum_message(message: TungsteniteMessage) -> Option<AxumWsMessage> {
    match message {
        TungsteniteMessage::Text(text) => Some(AxumWsMessage::Text(text.as_str().into())),
        TungsteniteMessage::Ping(data) => Some(AxumWsMessage::Ping(data)),
        TungsteniteMessage::Pong(data) => Some(AxumWsMessage::Pong(data)),
        TungsteniteMessage::Close(_) => Some(AxumWsMessage::Close(None)),
        TungsteniteMessage::Binary(_) | TungsteniteMessage::Frame(_) => None,
    }
}

fn update_runtime_gateway_state(
    ready: bool,
    status: &str,
    last_error: Option<String>,
    session_id: Option<&str>,
) {
    let Ok(mut current) = RUNTIME_STATUS.write() else {
        return;
    };
    current.ready = ready;
    current.status = status.to_string();
    current.config_error = if status == "config_error" {
        last_error.clone()
    } else {
        None
    };
    current.last_error = last_error;
    current.current_session = session_id
        .map(str::trim)
        .filter(|session_id| !session_id.is_empty())
        .map(ToOwned::to_owned);
    current.checked_at = Some(now_string());
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

    #[derive(Deserialize)]
    struct Payload {
        #[serde(default, deserialize_with = "action_plan::deserialize_present_actions")]
        actions: Option<Vec<Action>>,
        #[serde(flatten)]
        single: Action,
    }
    let payload = serde_json::from_slice::<Payload>(raw)
        .map_err(|_| PicoclawErrorData::new(CODE_INVALID_ACTION, "invalid action payload"))?;
    if let Some(actions) = payload.actions {
        if actions.is_empty() || !payload.single.action.trim().is_empty() {
            return Err(PicoclawErrorData::new(
                CODE_INVALID_ACTION,
                "invalid action batch",
            ));
        }
        return Ok(actions);
    }
    let action = payload.single;
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
    batch: &PreparedBatch,
    call: &Call,
) -> Completion<ActionResult> {
    let owner = match hid_ws::begin_input() {
        Ok(owner) => owner,
        Err(error) => {
            return Completion {
                result: Err(hid_owner_error(error)),
                clean: true,
            };
        }
    };
    execute_prepared(&owner, Some(session_id), batch, call)
}

fn execute_prepared<Output: hid_ws::HidReports>(
    owner: &Output,
    session_id: Option<&str>,
    batch: &PreparedBatch,
    call: &Call,
) -> Completion<ActionResult> {
    let started_at = Instant::now();
    let (actions, result_action) = batch.parts();
    let mut total_writes = 0;
    let result = (|| {
        for (idx, action) in actions.iter().enumerate() {
            call.check().map_err(|error| error.with_index(idx))?;
            if let Some(session_id) = session_id {
                // Never reacquire authority after release/expiry. Full task
                // generation binding is a separate gateway/bridge boundary.
                check_session_lock(session_id).map_err(|error| error.with_index(idx))?;
            }
            total_writes += execute_action_blocking(owner, action, call)
                .map_err(|error| error.with_index(idx))?;
        }
        call.check()
    })();
    // Cancellation/deadline never suppresses owned compensation. A failed
    // cleanup must stop this executor, not hand its slot to the next call.
    let cleanup = owner.finish();
    let clean = cleanup.is_ok();
    let result = match cleanup {
        Err(_) => {
            let mut error = PicoclawErrorData::new(
                "HID_CLEANUP_UNCERTAIN",
                "owned HID cleanup failed; executor retained for recovery",
            );
            error.index = result.as_ref().err().and_then(|error| error.index);
            Err(error)
        }
        Ok(writes) => result.map(|()| ActionResult {
            action: result_action.to_string(),
            duration_ms: started_at.elapsed().as_millis().min(i64::MAX as u128) as i64,
            hid_writes: total_writes + writes,
            executed_actions: (actions.len() > 1).then_some(actions.len()),
        }),
    };
    Completion { result, clean }
}

fn execute_action_blocking<Output: hid_ws::HidReports>(
    owner: &Output,
    action: &PreparedAction,
    call: &Call,
) -> std::result::Result<usize, PicoclawErrorData> {
    match *action {
        PreparedAction::Click {
            point: (x, y),
            button,
        } => {
            let mut writes = 0;
            writes += send_mouse_move_with_button(owner, x, y, 0x00, 0, call)?;
            writes += send_mouse_move_with_button(owner, x, y, button, 0, call)?;
            call.wait(DEFAULT_CLICK_HOLD)?;
            writes += owner.settle_absolute().map_err(hid_owner_error)?;
            Ok(writes)
        }
        PreparedAction::Move { point: (x, y) } => {
            send_mouse_move_with_button(owner, x, y, 0x00, 0, call)
        }
        PreparedAction::Wait(duration) => {
            call.wait(duration)?;
            Ok(0)
        }
        PreparedAction::Drag {
            from: (from_x, from_y),
            to: (to_x, to_y),
            button,
        } => {
            let mut writes = 0;
            writes += send_mouse_move_with_button(owner, from_x, from_y, 0x00, 0, call)?;
            writes += send_mouse_move_with_button(owner, from_x, from_y, button, 0, call)?;
            for step in 1..=DEFAULT_DRAG_STEPS {
                let ratio = step as f64 / DEFAULT_DRAG_STEPS as f64;
                let x = from_x + (to_x - from_x) * ratio;
                let y = from_y + (to_y - from_y) * ratio;
                writes += send_mouse_move_with_button(owner, x, y, button, 0, call)?;
            }
            writes += owner.settle_absolute().map_err(hid_owner_error)?;
            Ok(writes)
        }
        PreparedAction::Scroll {
            point: (x, y),
            amount,
            wheel,
        } => {
            let mut writes = 0;
            for _ in 0..amount {
                writes += send_mouse_move_with_button(owner, x, y, 0x00, i32::from(wheel), call)?;
                writes += owner.settle_absolute().map_err(hid_owner_error)?;
                call.wait(DEFAULT_SCROLL_STEP)?;
            }
            Ok(writes)
        }
        PreparedAction::Type(ref reports) => {
            let mut writes = 0;
            for report in reports {
                writes += send_keyboard_report(owner, report, call)?;
                writes += owner.settle_keyboard().map_err(hid_owner_error)?;
                call.wait(hid::PASTE_KEY_DELAY)?;
            }
            Ok(writes)
        }
        PreparedAction::Hotkey(report) => {
            let mut writes = 0;
            writes += send_keyboard_report(owner, &report, call)?;
            call.wait(DEFAULT_CLICK_HOLD)?;
            writes += owner.settle_keyboard().map_err(hid_owner_error)?;
            Ok(writes)
        }
    }
}

#[cfg(test)]
pub(crate) fn execute_reports_fixture<Output: hid_ws::HidReports>(
    owner: &Output,
    raw: &[u8],
) -> std::result::Result<usize, String> {
    // Real parser/preflight and actual action executor; no session/worker or
    // device-runtime acceptance is inferred from this report-only seam.
    let batch = normalize_actions(raw)
        .and_then(PreparedBatch::prepare)
        .map_err(|error| error.message)?;
    let call = Call::new(0, None);
    call.start().map_err(|error| error.message)?;
    execute_prepared(owner, None, &batch, &call)
        .result
        .map(|result| result.hid_writes)
        .map_err(|error| error.message)
}

#[cfg(test)]
pub(crate) fn execute_controlled_reports_fixture<Output: hid_ws::HidReports>(
    owner: &Output,
    call: &Call,
    raw: &[u8],
) -> (std::result::Result<usize, String>, bool) {
    let batch = normalize_actions(raw)
        .and_then(PreparedBatch::prepare)
        .unwrap();
    let completion = execute_prepared(owner, None, &batch, call);
    (
        completion
            .result
            .map(|result| result.hid_writes)
            .map_err(|error| error.code.to_string()),
        completion.clean,
    )
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

fn send_mouse_move_with_button<Output: hid_ws::HidReports>(
    owner: &Output,
    x: f64,
    y: f64,
    buttons: u8,
    wheel: i32,
    call: &Call,
) -> std::result::Result<usize, PicoclawErrorData> {
    call.check()?;
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
    owner.absolute(&report).map_err(|err| {
        PicoclawErrorData::new(
            CODE_HID_WRITE_FAILED,
            format!("failed to write HID mouse report: {err}"),
        )
    })
}

fn send_keyboard_report<Output: hid_ws::HidReports>(
    owner: &Output,
    report: &[u8; 8],
    call: &Call,
) -> std::result::Result<usize, PicoclawErrorData> {
    call.check()?;
    owner.keyboard(report).map_err(|err| {
        PicoclawErrorData::new(
            CODE_HID_WRITE_FAILED,
            format!("failed to write HID keyboard report: {err}"),
        )
    })
}

fn to_absolute_hid_coord(normalized: f64) -> u16 {
    let normalized = normalized.clamp(0.0, 1.0);
    (f64::from(0x7fff) * normalized).floor() as u16 + 1
}

fn hid_owner_error(error: io::Error) -> PicoclawErrorData {
    PicoclawErrorData::new(
        CODE_HID_WRITE_FAILED,
        format!("HID owner operation failed: {error}"),
    )
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

async fn mcp_tools_call(
    state: &AppState,
    headers: &HeaderMap,
    req: JsonRpcRequest,
) -> JsonRpcResponse {
    let Some(params) = req.params.as_ref() else {
        return json_rpc_error(req.id, -32602, "invalid params");
    };
    let name = params
        .get("name")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    let arguments = params.get("arguments").cloned().unwrap_or(JsonValue::Null);

    match name {
        "kvm_screenshot" => mcp_screenshot(state, req.id, arguments).await,
        "kvm_actions" => mcp_actions(state, headers, req.id, arguments).await,
        _ => json_rpc_error(req.id, -32602, format!("unknown tool: {name}")),
    }
}

async fn mcp_screenshot(state: &AppState, id: JsonValue, arguments: JsonValue) -> JsonRpcResponse {
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

    match state.picoclaw_worker.screenshot(None, query).await {
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

async fn mcp_actions(
    state: &AppState,
    headers: &HeaderMap,
    id: JsonValue,
    arguments: JsonValue,
) -> JsonRpcResponse {
    let batch = match serde_json::from_value::<ActionBatch>(arguments) {
        Ok(batch) if !batch.actions.is_empty() => batch,
        _ => return mcp_tool_error(id, "invalid actions payload"),
    };
    let batch = match PreparedBatch::prepare(batch.actions) {
        Ok(batch) => batch,
        Err(error) => return mcp_tool_error(id, error.message),
    };

    let session_id = headers
        .get(SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(session_lock_owner);

    match state.picoclaw_worker.actions(session_id, batch).await {
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
            "description": "Send an ordered batch of 1-64 HID actions to the downstream remote host. Use normalized [0,1] mouse coordinates. Per call: wait <=5000 ms/action, scroll <=100 ticks/action, typing <=4096 UTF-8 bytes total, scheduled delays <=30 s total. Continue long tasks in sequential bounded calls; oversized calls are rejected, never truncated.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actions": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 64,
                        "description": "Array of action objects. Each requires an 'action' field (click, move, type, hotkey, scroll, drag, wait).",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": { "type": "string", "enum": ["click", "move", "type", "hotkey", "scroll", "drag", "wait"] },
                                "x": { "type": "number" },
                                "y": { "type": "number" },
                                "button": { "type": "string" },
                                "text": { "type": "string", "description": "At most 4096 UTF-8 bytes across all type actions in this call; typing delay also consumes the aggregate scheduled-time budget." },
                                "keys": { "type": "array", "maxItems": 14, "items": { "type": "string" } },
                                "direction": { "type": "string" },
                                "amount": { "type": "integer", "minimum": 0, "maximum": 100 },
                                "duration_ms": { "type": "integer", "minimum": 0, "maximum": 5000 },
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

    let prepared = if resolve_config_path()
        .ok()
        .filter(|path| path.exists())
        .is_none()
    {
        onboard_runtime_config().await
    } else {
        Ok(())
    };

    let settings = match prepared.and_then(|()| load_gateway_settings()) {
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

    let support = native_control_ready()
        .await
        .map_err(|err| err.to_string())?;
    ensure_startup_defaults()
        .await
        .map_err(|err| err.to_string())?;
    let (command, output) = run_native_control(PicoControl::Ensure, support)
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
    let support = native_control_ready()
        .await
        .map_err(|err| err.to_string())?;
    let (command, output) = run_native_control(PicoControl::Stop, support)
        .await
        .map_err(|err| err.to_string())?;

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

enum PicoControl {
    Ensure,
    Stop,
    Onboard,
}

async fn native_control_ready() -> Result<crate::native_owner::broker::boot::Permit> {
    // Admit before queuing a blocking callback, not inside it. Contenders fail
    // immediately instead of growing a queue of helper-hashing/fsync tasks.
    let admission = crate::update::operation_lock::ProcessLock::acquire()
        .map_err(|_| AppError::Conflict("picoclaw native control admission unavailable".into()))?;
    task::spawn_blocking(move || {
        // Management may remain available when boot-support publication fails.
        // Never let an old ctl/broker's empty scope stand in for a stopped
        // legacy gateway. Check this backend's exact helpers under admission,
        // then retain its current fresh-boot consumer profile through control.
        let _admission = admission;
        crate::update::native_bootstrap::check_installed().map_err(|_| {
            AppError::Conflict("picoclaw requires matching current native support".into())
        })?;
        crate::native_owner::broker::boot::require_ready().map_err(|_| {
            AppError::Conflict(
                "picoclaw requires a fresh enrolled boot with current scripts".into(),
            )
        })
    })
    .await
    .map_err(|_| AppError::Internal("picoclaw native preflight task failed".into()))?
}

async fn run_native_control(
    control: PicoControl,
    support: crate::native_owner::broker::boot::Permit,
) -> Result<(String, String)> {
    let (argument, timeout) = match control {
        PicoControl::Ensure => ("ensure-picoclaw", PICOCLAW_START_TIMEOUT),
        PicoControl::Stop => ("stop-picoclaw", PICOCLAW_STOP_TIMEOUT),
        PicoControl::Onboard => ("onboard-picoclaw", PICOCLAW_ONBOARD_TIMEOUT),
    };
    // The command owner retains the boot proof through cancellation, capture
    // cleanup and direct-child reap. Broker Stop independently retains its
    // Update exclusion and owned tree until receipt/reap/EOF, even if ctl dies.
    let output = command::run_allowed_owned(
        AllowedCommand::NativePicoclawControl,
        [argument],
        timeout,
        support,
    )
    .await?;
    if output.status == 0 {
        Ok((
            format!("/usr/libexec/nanokvm-native-ctl {argument}"),
            command_output_text(&output),
        ))
    } else {
        Err(AppError::Conflict(
            "picoclaw native operation did not confirm completion; no fallback attempted".into(),
        ))
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

#[derive(Debug, Clone)]
struct GatewaySettings {
    gateway_host: String,
    gateway_port: u16,
    token: String,
    allow_token_query: bool,
    connect_timeout_ms: u64,
    read_timeout_ms: i32,
    write_timeout_ms: i32,
    ping_interval_ms: u64,
    max_message_bytes: usize,
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
    let pico_settings = doc.raw.pointer("/channel_list/pico/settings");
    let token = resolved_pico_token(&doc.raw, &doc.security);
    let allow_token_query = pico_settings
        .and_then(|settings| settings.get("allow_token_query"))
        .and_then(JsonValue::as_bool)
        .unwrap_or(false);
    let read_timeout_ms = pico_settings
        .and_then(|settings| settings.get("read_timeout"))
        .and_then(JsonValue::as_i64)
        .and_then(seconds_to_millis_i32)
        .unwrap_or(DEFAULT_READ_TIMEOUT_MS);
    let write_timeout_ms = pico_settings
        .and_then(|settings| settings.get("write_timeout"))
        .and_then(JsonValue::as_i64)
        .and_then(seconds_to_millis_i32)
        .unwrap_or(DEFAULT_WRITE_TIMEOUT_MS);
    let ping_interval_ms = pico_settings
        .and_then(|settings| settings.get("ping_interval"))
        .and_then(JsonValue::as_u64)
        .map(|seconds| seconds.saturating_mul(1000))
        .filter(|millis| *millis > 0)
        .unwrap_or(DEFAULT_PING_INTERVAL_MS as u64);
    let max_message_bytes = pico_settings
        .and_then(|settings| settings.get("max_message_bytes"))
        .and_then(JsonValue::as_u64)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_MAX_MESSAGE_BYTES);

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
        token,
        allow_token_query,
        connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
        read_timeout_ms,
        write_timeout_ms,
        ping_interval_ms,
        max_message_bytes,
        model_configured,
        model_name,
        target_model_name,
    })
}

fn seconds_to_millis_i32(seconds: i64) -> Option<i32> {
    if seconds <= 0 {
        return None;
    }
    i32::try_from(seconds.saturating_mul(1000)).ok()
}

struct ConfigDocument {
    config_path: PathBuf,
    raw: JsonValue,
    security: serde_yaml::Value,
}

fn load_config_document() -> Result<ConfigDocument> {
    let config_path = resolve_config_path()?;
    load_config_document_at(config_path)
}

fn load_config_document_at(config_path: PathBuf) -> Result<ConfigDocument> {
    let crate::update::picoclaw_config::RawDocuments {
        config: data,
        security: security_data,
    } = crate::update::picoclaw_config::read_pair(&config_path)?;
    let raw: JsonValue = serde_json::from_slice(&data)
        .map_err(|err| AppError::Internal(format!("failed to parse picoclaw config: {err}")))?;
    let security = match security_data {
        Some(data) => serde_yaml::from_slice(&data).map_err(|err| {
            AppError::Internal(format!("failed to parse picoclaw security config: {err}"))
        })?,
        None => serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
    };

    Ok(ConfigDocument {
        config_path,
        raw,
        security,
    })
}

async fn onboard_runtime_config() -> Result<()> {
    // The broker owns Update -> Config across native completion and checked
    // import. Holding Config here would invert/reacquire those admissions.
    let support = native_control_ready().await?;
    run_native_control(PicoControl::Onboard, support).await?;
    task::spawn_blocking(|| load_config_document().map(|_| ()))
        .await
        .map_err(|_| AppError::Internal("picoclaw onboarding validation task failed".into()))?
}

fn resolve_config_path() -> Result<PathBuf> {
    Ok(crate::native_owner::picoclaw_home::resolve()?.join("config.json"))
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

fn update_model_config_file(
    permit: &crate::update::state_writers::ConfigPermit,
    api_base: &str,
    api_key: &str,
    model: &str,
) -> Result<String> {
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

    set_model_secret(&mut doc.security, &model_name, updated_index, api_key);
    save_config_document(permit, &doc)?;
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

fn save_config_document(
    permit: &crate::update::state_writers::ConfigPermit,
    doc: &ConfigDocument,
) -> Result<()> {
    let encoded = encode_config_document(doc)?;
    crate::update::picoclaw_config::replace_pair(
        permit,
        &doc.config_path,
        &encoded.config,
        Some(encoded.security.as_bytes()),
    )
}

// Never Debug/log these credential-bearing buffers. Startup comparison uses
// canonical encodings, not the on-disk formatting/comments; unchanged inputs
// must not replace the pair or change a running scope's exact-byte generation.
#[derive(PartialEq, Eq)]
struct ConfigEncoding {
    config: zeroize::Zeroizing<Vec<u8>>,
    security: zeroize::Zeroizing<String>,
}

fn encode_config_document(doc: &ConfigDocument) -> Result<ConfigEncoding> {
    let config =
        zeroize::Zeroizing::new(serde_json::to_vec_pretty(&doc.raw).map_err(|err| {
            AppError::Internal(format!("failed to encode picoclaw config: {err}"))
        })?);
    let security =
        zeroize::Zeroizing::new(serde_yaml::to_string(&doc.security).map_err(|err| {
            AppError::Internal(format!("failed to encode picoclaw security: {err}"))
        })?);
    Ok(ConfigEncoding { config, security })
}

#[cfg(all(test, feature = "sandbox-test-fixture"))]
fn save_json(
    permit: &crate::update::state_writers::ConfigPermit,
    path: &Path,
    value: &JsonValue,
) -> Result<()> {
    let data =
        zeroize::Zeroizing::new(serde_json::to_vec_pretty(value).map_err(|err| {
            AppError::Internal(format!("failed to encode picoclaw config: {err}"))
        })?);
    crate::update::picoclaw_config::replace(permit, path, &data)
}

#[cfg(all(test, feature = "sandbox-test-fixture"))]
fn save_yaml(
    permit: &crate::update::state_writers::ConfigPermit,
    path: &Path,
    value: &serde_yaml::Value,
) -> Result<()> {
    let data =
        zeroize::Zeroizing::new(serde_yaml::to_string(value).map_err(|err| {
            AppError::Internal(format!("failed to encode picoclaw security: {err}"))
        })?);
    crate::update::picoclaw_config::replace(permit, path, data.as_bytes())
}

fn resolved_pico_token(config: &JsonValue, security: &serde_yaml::Value) -> String {
    let security_token = security
        .get("channel_list")
        .and_then(|channels| channels.get("pico"))
        .and_then(|pico| {
            pico.get("settings")
                .and_then(|settings| settings.get("token"))
                .or_else(|| pico.get("token"))
        })
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty());
    if let Some(token) = security_token {
        return token.to_string();
    }

    config
        .pointer("/channel_list/pico/settings/token")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .unwrap_or("")
        .to_string()
}

fn ensure_pico_security_token(doc: &mut ConfigDocument) -> Result<String> {
    let token = {
        let current = resolved_pico_token(&doc.raw, &doc.security);
        if current.is_empty() {
            random_token(36)
        } else {
            current
        }
    };

    set_pico_security_token(&mut doc.security, &token);
    Ok(token)
}

fn set_pico_security_token(security: &mut serde_yaml::Value, token: &str) {
    if !security.is_mapping() {
        *security = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    }
    let root = security.as_mapping_mut().expect("security mapping");
    let channel_list_key = serde_yaml::Value::String("channel_list".to_string());
    root.entry(channel_list_key.clone())
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    if !root[&channel_list_key].is_mapping() {
        root.insert(
            channel_list_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }

    let channel_list = root
        .get_mut(&channel_list_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .expect("channel_list mapping");
    let pico_key = serde_yaml::Value::String("pico".to_string());
    channel_list
        .entry(pico_key.clone())
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    if !channel_list[&pico_key].is_mapping() {
        channel_list.insert(
            pico_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }

    let pico = channel_list
        .get_mut(&pico_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .expect("pico mapping");
    let settings_key = serde_yaml::Value::String("settings".to_string());
    pico.entry(settings_key.clone())
        .or_insert_with(|| serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));
    if !pico[&settings_key].is_mapping() {
        pico.insert(
            settings_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }

    let settings = pico
        .get_mut(&settings_key)
        .and_then(serde_yaml::Value::as_mapping_mut)
        .expect("pico settings mapping");
    settings.insert(
        serde_yaml::Value::String("token".to_string()),
        serde_yaml::Value::String(token.to_string()),
    );
}

fn set_model_secret(
    security: &mut serde_yaml::Value,
    model_name: &str,
    index: usize,
    api_key: &str,
) {
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
}

async fn ensure_startup_defaults() -> Result<()> {
    crate::update::state_writers::StateWriters::default()
        .configuration()?
        .blocking(write_startup_defaults)
        .await
}

fn write_startup_defaults(permit: &crate::update::state_writers::ConfigPermit) -> Result<()> {
    let mut doc = load_config_document()?;
    // A virtual committed-intent read is not evidence that upstream is using a
    // coherent installed pair. A connection must not settle a pending journal;
    // only stopped native preparation can establish that boundary.
    crate::update::picoclaw_config::current_generation(&doc.config_path)?;
    for path in ["/agents", "/agents/defaults"] {
        if doc
            .raw
            .pointer(path)
            .is_some_and(|value| !value.is_object())
        {
            return Err(AppError::Config(
                "invalid picoclaw local tool policy".into(),
            ));
        }
    }
    for path in [
        "/agents/defaults/restrict_to_workspace",
        "/agents/defaults/allow_read_outside_workspace",
    ] {
        if doc
            .raw
            .pointer(path)
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(AppError::Config(
                "invalid picoclaw local tool policy".into(),
            ));
        }
    }
    let before = encode_config_document(&doc)?;
    let _ = ensure_pico_security_token(&mut doc)?;
    let raw = doc
        .raw
        .as_object_mut()
        .ok_or_else(|| AppError::Internal("picoclaw config root is not an object".to_string()))?;
    let defaults = ensure_object_path(raw, &["agents", "defaults"]);
    defaults
        .entry("restrict_to_workspace".to_string())
        .or_insert(JsonValue::Bool(true));
    defaults
        .entry("allow_read_outside_workspace".to_string())
        .or_insert(JsonValue::Bool(false));
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
    let token = crate::update::picoclaw_token::ensure(permit)?;
    let server = ensure_object_path(raw, &["tools", "mcp", "servers", "nanokvm"]);
    server.insert("enabled".to_string(), JsonValue::Bool(true));
    server.insert("type".to_string(), JsonValue::String("http".to_string()));
    server.insert(
        "url".to_string(),
        JsonValue::String("http://127.0.0.1:80/api/picoclaw/mcp".to_string()),
    );
    let headers = ensure_object_path(raw, &["tools", "mcp", "servers", "nanokvm", "headers"]);
    headers.insert(INTERNAL_TOKEN_HEADER.to_string(), JsonValue::String(token));
    let after = encode_config_document(&doc)?;
    if before != after {
        crate::update::picoclaw_config::replace_pair(
            permit,
            &doc.config_path,
            &after.config,
            Some(after.security.as_bytes()),
        )?;
    }
    Ok(())
}

#[cfg(all(test, feature = "sandbox-test-fixture"))]
#[path = "picoclaw_config_publication_tests.rs"]
mod config_publication_tests;

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

fn picoclaw_error_data_status(status: StatusCode, err: PicoclawErrorData) -> Response {
    (
        status,
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

    #[test]
    fn gateway_url_matches_picoclaw_contract() {
        let settings = GatewaySettings {
            gateway_host: "127.0.0.1".to_string(),
            gateway_port: 18790,
            token: "token value".to_string(),
            allow_token_query: true,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            read_timeout_ms: DEFAULT_READ_TIMEOUT_MS,
            write_timeout_ms: DEFAULT_WRITE_TIMEOUT_MS,
            ping_interval_ms: DEFAULT_PING_INTERVAL_MS as u64,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            model_configured: true,
            model_name: "model".to_string(),
            target_model_name: "model".to_string(),
        };

        assert_eq!(
            build_gateway_url(&settings, "session 1"),
            "ws://127.0.0.1:18790/pico/ws?session_id=session%201&token=token%20value"
        );
    }

    #[test]
    fn resolved_pico_token_prefers_security_config() {
        let config = json!({
            "channel_list": {
                "pico": {
                    "settings": {
                        "token": "config-token"
                    }
                }
            }
        });
        let security: serde_yaml::Value = serde_yaml::from_str(
            r#"
channel_list:
  pico:
    settings:
      token: security-token
"#,
        )
        .unwrap();

        assert_eq!(resolved_pico_token(&config, &security), "security-token");
        assert_eq!(
            resolved_pico_token(&config, &serde_yaml::Value::Null),
            "config-token"
        );
    }
}
