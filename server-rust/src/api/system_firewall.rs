use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use tokio::time;

use crate::{
    AppError, Result,
    config::Config,
    error::ApiResponse,
    system::command::{AllowedCommand, CommandOutput, run_allowed},
};

const CONFIG_FILE: &str = "/etc/kvm/firewall.json";
const PENDING_FILE: &str = "/tmp/hardened-firewall-pending.json";
const MODE_BASELINE: &str = "baseline";
const MODE_MODERATE: &str = "moderate";
const MODE_RESTRICTED: &str = "restricted";
const MODE_PARANOID: &str = "paranoid";
const PARANOID_BLOCKED_MESSAGE: &str = "online updates are blocked by Paranoid Firewall mode";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingRollback {
    previous_mode: String,
    requested_mode: String,
    created_at: u64,
}

pub fn paranoid_mode_enabled() -> bool {
    effective_mode()
        .map(|mode| mode == MODE_PARANOID)
        .unwrap_or(false)
}

pub fn paranoid_blocked_message() -> &'static str {
    PARANOID_BLOCKED_MESSAGE
}

pub async fn force_moderate_mode() -> Result<()> {
    let moderate = FirewallConfig {
        mode: MODE_MODERATE.to_string(),
    };
    write_config(&moderate)?;
    remove_file_if_exists(PENDING_FILE)?;
    apply_firewall().await
}

pub async fn get_status() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(build_status().await?)))
}

pub async fn set_config(Json(req): Json<SetFirewallReq>) -> Result<impl IntoResponse> {
    let requested = normalize_mode(&req.mode)?;
    let previous = read_config().unwrap_or_default();

    if mode_requires_https(&requested.mode) {
        ensure_https_mode_can_be_enabled(&requested.mode).await?;
        write_pending(&PendingRollback {
            previous_mode: previous.mode.clone(),
            requested_mode: requested.mode.clone(),
            created_at: unix_now(),
        })?;
    } else {
        remove_file_if_exists(PENDING_FILE)?;
    }

    write_config(&requested)?;
    if let Err(err) = apply_firewall().await {
        write_config(&previous)?;
        let _ = apply_firewall().await;
        remove_file_if_exists(PENDING_FILE)?;
        return Err(err);
    }

    if mode_requires_https(&requested.mode) {
        spawn_pending_rollback(previous);
    }

    Ok(Json(ApiResponse::ok(build_status().await?)))
}

pub async fn confirm_pending() -> Result<impl IntoResponse> {
    remove_file_if_exists(PENDING_FILE)?;
    Ok(Json(ApiResponse::ok(build_status().await?)))
}

async fn build_status() -> Result<FirewallStatusRsp> {
    let config = read_config().unwrap_or_default();
    let server_config = Config::read().unwrap_or_default();
    let https_enabled = https_enabled(&server_config);
    let effective_mode = effective_mode_for(&config, &server_config);
    let moderate_active = effective_mode == MODE_MODERATE;
    let restricted_active = effective_mode == MODE_RESTRICTED;
    let paranoid_active = effective_mode == MODE_PARANOID;
    let confirmation_required = Path::new(PENDING_FILE).exists();

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
        rules: read_rules().await,
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

async fn ensure_https_mode_can_be_enabled(mode: &str) -> Result<()> {
    let config = Config::read()?;
    if !https_enabled(&config) {
        return Err(AppError::BadRequest(format!(
            "enable HTTPS before enabling {mode} Firewall mode"
        )));
    }

    let output = run_allowed(
        AllowedCommand::Curl,
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
    match fs::read_to_string(CONFIG_FILE) {
        Ok(content) => {
            let config: FirewallConfig = serde_json::from_str(&content)
                .map_err(|err| AppError::Config(format!("invalid firewall config: {err}")))?;
            normalize_mode(&config.mode)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(FirewallConfig::default()),
        Err(err) => Err(AppError::Io(err)),
    }
}

fn write_config(config: &FirewallConfig) -> Result<()> {
    let content = serde_json::to_vec_pretty(config)
        .map_err(|err| AppError::Internal(format!("encode firewall config: {err}")))?;
    write_file_atomic(Path::new(CONFIG_FILE), &content, 0o644)
}

fn write_pending(pending: &PendingRollback) -> Result<()> {
    let content = serde_json::to_vec_pretty(pending)
        .map_err(|err| AppError::Internal(format!("encode firewall pending state: {err}")))?;
    write_file_atomic(Path::new(PENDING_FILE), &content, 0o600)
}

fn spawn_pending_rollback(previous: FirewallConfig) {
    tokio::spawn(async move {
        time::sleep(Duration::from_secs(60)).await;
        if !Path::new(PENDING_FILE).exists() {
            return;
        }

        if let Err(err) = write_config(&previous) {
            tracing::warn!(error = ?err, "failed to restore previous firewall config");
            return;
        }
        if let Err(err) = apply_firewall().await {
            tracing::warn!(error = ?err, "failed to rollback unconfirmed firewall mode");
            return;
        }
        if let Err(err) = fs::remove_file(PENDING_FILE) {
            tracing::warn!(error = ?err, "failed to clear firewall pending rollback marker");
        }
    });
}

async fn apply_firewall() -> Result<()> {
    let output = run_allowed(
        AllowedCommand::ServiceFirewall,
        ["restart"],
        Duration::from_secs(10),
    )
    .await?;
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

fn remove_file_if_exists(path: &str) -> Result<()> {
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
