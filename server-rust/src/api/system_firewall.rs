use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Json, extract::State, response::IntoResponse};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, oneshot},
    task::JoinHandle,
    time,
};

use crate::{
    AppError, Result,
    config::Config,
    error::ApiResponse,
    state::AppState,
    system::command::{AllowedCommand, CommandOutput, run_allowed},
    update::state_writers::{ConfigPermit, FirewallPermit, StateWriters},
};

const CONFIG_FILE: &str = "/etc/kvm/firewall.json";
const PENDING_FILE: &str = "/tmp/hardened-firewall-pending.json";
const MAX_PENDING_BYTES: usize = 1024;
const MODE_BASELINE: &str = "baseline";
const MODE_MODERATE: &str = "moderate";
const MODE_RESTRICTED: &str = "restricted";
const MODE_PARANOID: &str = "paranoid";
const PARANOID_BLOCKED_MESSAGE: &str = "online updates are blocked by Paranoid Firewall mode";
const WEBRTC_BLOCKED_MESSAGE: &str =
    "H.264 WebRTC is disabled in Restricted and Paranoid Firewall modes";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct FirewallConfig {
    pub mode: String,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            mode: MODE_MODERATE.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetFirewallReq {
    pub mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallStatusRsp {
    config: FirewallConfig,
    effective_mode: String,
    moderate_active: bool,
    restricted_active: bool,
    paranoid_active: bool,
    webrtc_blocked: bool,
    paranoid_available: bool,
    confirmation_required: bool,
    https_enabled: bool,
    https_port: u16,
    backend: FirewallBackendRsp,
    rules: FirewallRulesRsp,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallBackendRsp {
    iptables: ToolStatus,
    ip6tables: ToolStatus,
    nft: ToolStatus,
    preferred: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolStatus {
    installed: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRulesRsp {
    ipv4: String,
    ipv6: String,
    nft: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct PendingRollback {
    transaction_id: [u8; 16],
    previous_mode: String,
    requested_mode: String,
    created_at: u64,
}

#[derive(Clone)]
struct FirewallPaths {
    config: PathBuf,
    pending: PathBuf,
}

#[derive(Clone, Copy)]
enum PendingAction {
    Confirm,
    Rollback,
}

struct PendingTask {
    signal: Option<oneshot::Sender<PendingAction>>,
    task: JoinHandle<Result<()>>,
}

#[derive(Default)]
struct ControlState {
    pending: Option<PendingTask>,
    failed: bool,
}

pub struct FirewallController {
    control: Arc<Mutex<ControlState>>,
    paths: Arc<FirewallPaths>,
    rollback_delay: Duration,
    #[cfg(test)]
    command: Option<PathBuf>,
}

impl Default for FirewallController {
    fn default() -> Self {
        Self {
            control: Arc::new(Mutex::new(ControlState::default())),
            paths: Arc::new(FirewallPaths {
                config: CONFIG_FILE.into(),
                pending: PENDING_FILE.into(),
            }),
            rollback_delay: Duration::from_secs(60),
            #[cfg(test)]
            command: None,
        }
    }
}

impl FirewallController {
    /// JoinHandle stays in the slot until completion, even if the waiter is
    /// cancelled. A lost channel requests rollback, never implicit confirmation.
    async fn settle(control: &mut ControlState, action: PendingAction) -> Result<()> {
        let Some(pending) = control.pending.as_mut() else {
            return Ok(());
        };
        if let Some(signal) = pending.signal.take() {
            let _ = signal.send(action);
        }
        let result = (&mut pending.task)
            .await
            .unwrap_or_else(|_| Err(AppError::Internal("firewall rollback owner failed".into())));
        control.pending = None;
        if result.is_err() {
            control.failed = true;
        }
        result
    }

    pub(crate) async fn stop_and_join(&self) -> Result<()> {
        let mut control = self.control.lock().await;
        Self::settle(&mut control, PendingAction::Rollback).await?;
        if control.failed || self.paths.pending.try_exists()? {
            return Err(AppError::Conflict(
                "firewall pending state requires recovery".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn force_moderate_mode(
        &self,
        writers: &StateWriters,
        config: &ConfigPermit,
    ) -> Result<()> {
        let mut control = self
            .control
            .try_lock()
            .map_err(|_| AppError::Conflict("firewall operation already in progress".into()))?;
        // Explicit TLS downgrade is a recovery action. A failed/unowned marker
        // must not prevent the user from explicitly selecting Moderate mode.
        let _ = Self::settle(&mut control, PendingAction::Rollback).await;
        let writer = writers.firewall(config)?;
        control.failed = true;
        self.write_and_apply(&writer, FirewallConfig::default(), true)
            .await?;
        control.failed = false;
        Ok(())
    }

    async fn write_and_apply(
        &self,
        writer: &FirewallPermit,
        config: FirewallConfig,
        clear_pending: bool,
    ) -> Result<()> {
        let paths = Arc::clone(&self.paths);
        writer
            .blocking(move |_| {
                write_config_at(&paths.config, &config)?;
                if clear_pending {
                    remove_file_if_exists(&paths.pending)?;
                }
                Ok(())
            })
            .await?;
        self.apply(writer).await
    }

    fn command(&self, production: AllowedCommand) -> AllowedCommand {
        #[cfg(test)]
        if let Some(path) = &self.command {
            return AllowedCommand::CustomForTest(path.clone());
        }
        production
    }

    async fn apply(&self, writer: &FirewallPermit) -> Result<()> {
        let output = writer
            .command(
                self.command(AllowedCommand::ServiceFirewall),
                ["restart"],
                Duration::from_secs(10),
            )
            .await?;
        check_firewall_output(output)
    }

    async fn rules(&self) -> FirewallRulesRsp {
        #[cfg(test)]
        if self.command.is_some() {
            return FirewallRulesRsp {
                ipv4: String::new(),
                ipv6: String::new(),
                nft: String::new(),
            };
        }
        read_rules().await
    }

    fn spawn_rollback(
        self: &Arc<Self>,
        writer: FirewallPermit,
        pending: PendingRollback,
    ) -> PendingTask {
        let (signal, receive) = oneshot::channel();
        let controller = Arc::clone(self);
        let task = tokio::spawn(async move {
            let action = time::timeout(controller.rollback_delay, receive).await;
            let confirm = matches!(action, Ok(Ok(PendingAction::Confirm)));
            let paths = Arc::clone(&controller.paths);
            let previous = writer
                .blocking(move |_| {
                    let current = read_pending_at(&paths.pending)?;
                    if current != pending {
                        return Err(AppError::Conflict(
                            "firewall pending state changed outside its owner".into(),
                        ));
                    }
                    Ok(FirewallConfig {
                        mode: pending.previous_mode,
                    })
                })
                .await?;
            if !confirm {
                controller.write_and_apply(&writer, previous, false).await?;
            }
            let paths = Arc::clone(&controller.paths);
            writer
                .blocking(move |_| remove_file_if_exists(&paths.pending))
                .await
        });
        PendingTask {
            signal: Some(signal),
            task,
        }
    }
}

pub fn paranoid_mode_enabled() -> bool {
    effective_mode()
        .map(|mode| mode == MODE_PARANOID)
        .unwrap_or(false)
}

pub fn paranoid_blocked_message() -> &'static str {
    PARANOID_BLOCKED_MESSAGE
}

pub fn webrtc_blocked_by_firewall() -> bool {
    effective_mode()
        .map(|mode| matches!(mode.as_str(), MODE_RESTRICTED | MODE_PARANOID))
        .unwrap_or(false)
}

pub fn webrtc_blocked_message() -> &'static str {
    WEBRTC_BLOCKED_MESSAGE
}

pub async fn get_status(State(state): State<AppState>) -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(
        build_status(&state.firewall, &Config::read()?).await?,
    )))
}

pub async fn set_config(
    State(state): State<AppState>,
    Json(req): Json<SetFirewallReq>,
) -> Result<impl IntoResponse> {
    let requested = normalize_mode(&req.mode)?;
    let config = state.writers.configuration()?;
    let control = Arc::clone(&state.firewall.control)
        .try_lock_owned()
        .map_err(|_| AppError::Conflict("firewall operation already in progress".into()))?;
    let status = config
        .run(move |config| async move {
            let mut control = control;
            let settled = FirewallController::settle(&mut control, PendingAction::Rollback).await;
            if mode_requires_https(&requested.mode) {
                settled?;
                if control.failed || state.firewall.paths.pending.try_exists()? {
                    return Err(AppError::Conflict(
                        "firewall pending state requires recovery".into(),
                    ));
                }
            }
            let writer = state.writers.firewall(&config)?;
            let server_config = config.blocking(Config::read_for).await?;
            if mode_requires_https(&requested.mode) {
                ensure_https_mode_can_be_enabled(
                    &state.firewall,
                    &writer,
                    &server_config,
                    &requested.mode,
                )
                .await?;
            }
            let paths = Arc::clone(&state.firewall.paths);
            let requested_write = requested.clone();
            control.failed = true;
            let pending = writer
                .blocking(move |_| {
                    let previous = read_config_at(&paths.config)?;
                    let pending = if mode_requires_https(&requested_write.mode) {
                        let mut transaction_id = [0; 16];
                        OsRng.try_fill_bytes(&mut transaction_id).map_err(|_| {
                            AppError::Internal("firewall transaction randomness unavailable".into())
                        })?;
                        let pending = PendingRollback {
                            transaction_id,
                            previous_mode: previous.mode.clone(),
                            requested_mode: requested_write.mode.clone(),
                            created_at: unix_now(),
                        };
                        write_pending_at(&paths.pending, &pending)?;
                        Some(pending)
                    } else {
                        remove_file_if_exists(&paths.pending)?;
                        None
                    };
                    write_config_at(&paths.config, &requested_write)?;
                    Ok((previous, pending))
                })
                .await?;
            if let Err(error) = state.firewall.apply(&writer).await {
                // Recovery failure remains a failed pending state, never a drained
                // success. Durable firewall publication/recovery is separate work.
                control.failed = true;
                state
                    .firewall
                    .write_and_apply(&writer, pending.0, false)
                    .await?;
                let paths = Arc::clone(&state.firewall.paths);
                writer
                    .blocking(move |_| remove_file_if_exists(&paths.pending))
                    .await?;
                control.failed = false;
                return Err(error);
            }
            control.failed = false;
            if let Some(pending) = pending.1 {
                control.pending = Some(state.firewall.spawn_rollback(writer, pending));
            }
            build_status(&state.firewall, &server_config).await
        })
        .await?;
    Ok(Json(ApiResponse::ok(status)))
}

pub async fn confirm_pending(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let config = state.writers.configuration()?;
    let control = Arc::clone(&state.firewall.control)
        .try_lock_owned()
        .map_err(|_| AppError::Conflict("firewall operation already in progress".into()))?;
    let status = config
        .run(move |config| async move {
            let mut control = control;
            FirewallController::settle(&mut control, PendingAction::Confirm).await?;
            if control.failed || state.firewall.paths.pending.try_exists()? {
                return Err(AppError::Conflict(
                    "firewall pending state requires recovery".into(),
                ));
            }
            let server_config = config.blocking(Config::read_for).await?;
            build_status(&state.firewall, &server_config).await
        })
        .await?;
    Ok(Json(ApiResponse::ok(status)))
}

async fn build_status(
    controller: &FirewallController,
    server_config: &Config,
) -> Result<FirewallStatusRsp> {
    let config = read_config_at(&controller.paths.config)?;
    let https_enabled = https_enabled(server_config);
    let effective_mode = effective_mode_for(&config, server_config);
    let moderate_active = effective_mode == MODE_MODERATE;
    let restricted_active = effective_mode == MODE_RESTRICTED;
    let paranoid_active = effective_mode == MODE_PARANOID;
    let webrtc_blocked = restricted_active || paranoid_active;
    let confirmation_required = controller.paths.pending.try_exists()?;

    let message = if mode_requires_https(&config.mode) && !https_enabled {
        "Enable HTTPS before restricted firewall modes can be applied.".to_string()
    } else if paranoid_active {
        PARANOID_BLOCKED_MESSAGE.to_string()
    } else {
        String::new()
    };

    Ok(FirewallStatusRsp {
        config,
        effective_mode,
        moderate_active,
        restricted_active,
        paranoid_active,
        webrtc_blocked,
        paranoid_available: https_enabled,
        confirmation_required,
        https_enabled,
        https_port: server_config.port.https,
        backend: FirewallBackendRsp {
            iptables: tool_status("/usr/sbin/iptables"),
            ip6tables: tool_status("/usr/sbin/ip6tables"),
            nft: tool_status("/usr/sbin/nft"),
            preferred: "iptables-legacy",
        },
        rules: controller.rules().await,
        message,
    })
}

fn effective_mode() -> Result<String> {
    let config = read_config().unwrap_or_default();
    let server_config = Config::read().unwrap_or_default();
    Ok(effective_mode_for(&config, &server_config))
}

fn effective_mode_for(config: &FirewallConfig, server_config: &Config) -> String {
    if mode_requires_https(&config.mode) && !https_enabled(server_config) {
        return MODE_MODERATE.to_string();
    }

    config.mode.clone()
}

fn https_enabled(config: &Config) -> bool {
    config.proto.eq_ignore_ascii_case("https")
}

fn mode_requires_https(mode: &str) -> bool {
    matches!(mode, MODE_RESTRICTED | MODE_PARANOID)
}

async fn ensure_https_mode_can_be_enabled(
    controller: &FirewallController,
    writer: &FirewallPermit,
    config: &Config,
    mode: &str,
) -> Result<()> {
    if !https_enabled(config) {
        return Err(AppError::BadRequest(format!(
            "enable HTTPS before enabling {mode} Firewall mode"
        )));
    }

    let output = writer
        .command(
            controller.command(AllowedCommand::Curl),
            ["-kfsS", "--max-time", "3", "https://127.0.0.1/api/health"],
            Duration::from_secs(5),
        )
        .await?;
    if output.status != 0 {
        return Err(AppError::BadRequest(command_error(
            "HTTPS health check failed",
            output,
        )));
    }

    Ok(())
}

fn normalize_mode(mode: &str) -> Result<FirewallConfig> {
    match mode {
        MODE_BASELINE | MODE_MODERATE | MODE_RESTRICTED | MODE_PARANOID => Ok(FirewallConfig {
            mode: mode.to_string(),
        }),
        _ => Err(AppError::BadRequest("invalid firewall mode".to_string())),
    }
}

fn read_config() -> Result<FirewallConfig> {
    read_config_at(Path::new(CONFIG_FILE))
}

fn read_config_at(path: &Path) -> Result<FirewallConfig> {
    match fs::read_to_string(path) {
        Ok(content) => {
            let config: FirewallConfig = serde_json::from_str(&content)
                .map_err(|err| AppError::Config(format!("invalid firewall config: {err}")))?;
            normalize_mode(&config.mode)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(FirewallConfig::default()),
        Err(err) => Err(AppError::Io(err)),
    }
}

fn write_config_at(path: &Path, config: &FirewallConfig) -> Result<()> {
    let content = serde_json::to_vec_pretty(config)
        .map_err(|err| AppError::Internal(format!("encode firewall config: {err}")))?;
    write_file_atomic(path, &content, 0o644)
}

fn write_pending_at(path: &Path, pending: &PendingRollback) -> Result<()> {
    let content = serde_json::to_vec_pretty(pending)
        .map_err(|err| AppError::Internal(format!("encode firewall pending state: {err}")))?;
    write_file_atomic(path, &content, 0o600)
}

fn read_pending_at(path: &Path) -> Result<PendingRollback> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > MAX_PENDING_BYTES as u64
    {
        return Err(AppError::Conflict("unsafe firewall pending state".into()));
    }
    let mut bytes = Vec::with_capacity(MAX_PENDING_BYTES + 1);
    file.take((MAX_PENDING_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PENDING_BYTES {
        return Err(AppError::Conflict(
            "oversized firewall pending state".into(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| AppError::Conflict("invalid firewall pending state".into()))
}

fn check_firewall_output(output: CommandOutput) -> Result<()> {
    if output.status != 0 {
        return Err(AppError::Internal(command_error(
            "failed to apply firewall settings",
            output,
        )));
    }
    Ok(())
}

async fn read_rules() -> FirewallRulesRsp {
    FirewallRulesRsp {
        ipv4: command_text(AllowedCommand::IptablesSave, std::iter::empty::<&str>()).await,
        ipv6: command_text(AllowedCommand::Ip6tablesSave, std::iter::empty::<&str>()).await,
        nft: command_text(AllowedCommand::Nft, ["list", "ruleset"]).await,
    }
}

async fn command_text<I, S>(command: AllowedCommand, args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    match run_allowed(command, args, Duration::from_secs(5)).await {
        Ok(output) if output.status == 0 => String::from_utf8_lossy(&output.stdout).to_string(),
        Ok(output) => command_error("command failed", output),
        Err(err) => err.to_string(),
    }
}

fn tool_status(path: &str) -> ToolStatus {
    ToolStatus {
        installed: Path::new(path).exists(),
        detail: path.to_string(),
    }
}

fn write_file_atomic(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Internal("path has no parent".to_string()))?;
    fs::create_dir_all(parent)?;

    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| AppError::Internal("path has invalid filename".to_string()))?
    ));
    fs::write(&tmp, content)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(AppError::Io(err)),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn command_error(message: &str, output: CommandOutput) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr.trim();
    if !detail.is_empty() {
        format!("{message}: {detail}")
    } else if !stdout.trim().is_empty() {
        format!("{message}: {}", stdout.trim())
    } else {
        message.to_string()
    }
}

#[cfg(test)]
#[path = "system_firewall_tests.rs"]
mod writer_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_firewall_modes() {
        assert_eq!(normalize_mode("baseline").unwrap().mode, MODE_BASELINE);
        assert_eq!(normalize_mode("moderate").unwrap().mode, MODE_MODERATE);
        assert_eq!(normalize_mode("restricted").unwrap().mode, MODE_RESTRICTED);
        assert_eq!(normalize_mode("paranoid").unwrap().mode, MODE_PARANOID);
        assert!(normalize_mode("off").is_err());
    }

    #[test]
    fn defaults_to_moderate_mode() {
        assert_eq!(FirewallConfig::default().mode, MODE_MODERATE);
    }

    #[test]
    fn paranoid_requires_https_for_effective_mode() {
        let firewall = FirewallConfig {
            mode: MODE_PARANOID.to_string(),
        };
        let mut config = Config {
            proto: "http".to_string(),
            ..Config::default()
        };
        assert_eq!(effective_mode_for(&firewall, &config), MODE_MODERATE);

        config.proto = "https".to_string();
        assert_eq!(effective_mode_for(&firewall, &config), MODE_PARANOID);
    }

    #[test]
    fn restricted_requires_https_for_effective_mode() {
        let firewall = FirewallConfig {
            mode: MODE_RESTRICTED.to_string(),
        };
        let mut config = Config {
            proto: "http".to_string(),
            ..Config::default()
        };
        assert_eq!(effective_mode_for(&firewall, &config), MODE_MODERATE);

        config.proto = "https".to_string();
        assert_eq!(effective_mode_for(&firewall, &config), MODE_RESTRICTED);
    }

    #[test]
    fn moderate_does_not_require_https_for_effective_mode() {
        let firewall = FirewallConfig {
            mode: MODE_MODERATE.to_string(),
        };
        let config = Config {
            proto: "http".to_string(),
            ..Config::default()
        };
        assert_eq!(effective_mode_for(&firewall, &config), MODE_MODERATE);
    }
}
