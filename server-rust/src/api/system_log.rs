use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

use axum::{
    Json,
    extract::{ConnectInfo, Query},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::{
    AppError, Result,
    error::ApiResponse,
    http::tls::ClientAddr,
    system::{
        audit,
        command::{AllowedCommand, CommandOutput, run_allowed},
    },
};

const CONFIG_FILE: &str = "/etc/kvm/syslog.json";
const SYSLOGD_DEFAULT_FILE: &str = "/etc/default/syslogd";
const KLOGD_DEFAULT_FILE: &str = "/etc/default/klogd";
const LOG_DIR: &str = "/tmp/hardened-syslog";
const LOG_FILE: &str = "/tmp/hardened-syslog/messages";
const FALLBACK_LOG_FILES: &[&str] = &["/var/log/messages", "/tmp/messages"];
const BACKEND_LOG_FILE: &str = "/tmp/nanokvm-server.log";
const MAX_LOG_VIEW_BYTES: usize = 256 * 1024;
const DEFAULT_LINES: usize = 200;
const MAX_LINES: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SystemLogConfig {
    pub remote_enabled: bool,
    pub remote_host: String,
    pub remote_port: u16,
    pub priority: u8,
    pub buffer_kb: u16,
    pub rotations: u8,
    pub small_output: bool,
    pub strip_timestamps: bool,
    pub kernel_enabled: bool,
    pub kernel_console_level: u8,
}

impl Default for SystemLogConfig {
    fn default() -> Self {
        Self {
            remote_enabled: false,
            remote_host: String::new(),
            remote_port: 514,
            priority: 8,
            buffer_kb: 200,
            rotations: 1,
            small_output: false,
            strip_timestamps: false,
            kernel_enabled: true,
            kernel_console_level: 7,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemLogConfigRsp {
    config: SystemLogConfig,
    local_log_file: &'static str,
    local_storage: &'static str,
    remote_protocol: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogQuery {
    kind: Option<String>,
    lines: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogRsp {
    kind: String,
    content: String,
    lines: usize,
    truncated: bool,
}

pub async fn get_config() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(SystemLogConfigRsp {
        config: read_config()?,
        local_log_file: LOG_FILE,
        local_storage: "tmpfs",
        remote_protocol: "udp",
    })))
}

pub async fn set_config(Json(req): Json<SystemLogConfig>) -> Result<impl IntoResponse> {
    let config = validate_config(req)?;

    fs::create_dir_all(LOG_DIR)?;
    write_config(&config)?;
    write_defaults(&config)?;
    apply_config(&config).await?;

    Ok(Json(ApiResponse::ok(SystemLogConfigRsp {
        config,
        local_log_file: LOG_FILE,
        local_storage: "tmpfs",
        remote_protocol: "udp",
    })))
}

pub async fn get_messages(Query(query): Query<LogQuery>) -> Result<impl IntoResponse> {
    let kind = query.kind.unwrap_or_else(|| "system".to_string());
    let lines = query.lines.unwrap_or(DEFAULT_LINES).clamp(1, MAX_LINES);

    let (content, truncated) = match kind.as_str() {
        "system" => read_system_log(lines)?,
        "kernel" => read_kernel_log(lines).await?,
        "backend" => read_backend_log(lines)?,
        _ => return Err(AppError::BadRequest("invalid log kind".to_string())),
    };

    Ok(Json(ApiResponse::ok(LogRsp {
        kind,
        content,
        lines,
        truncated,
    })))
}

pub async fn test_message(ConnectInfo(addr): ConnectInfo<ClientAddr>) -> Result<impl IntoResponse> {
    audit::test_message(&addr.0.ip().to_string());
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

fn read_config() -> Result<SystemLogConfig> {
    match fs::read_to_string(CONFIG_FILE) {
        Ok(content) => {
            let config: SystemLogConfig = serde_json::from_str(&content)
                .map_err(|err| AppError::Config(format!("invalid syslog config: {err}")))?;
            validate_config(config)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(SystemLogConfig::default()),
        Err(err) => Err(AppError::Io(err)),
    }
}

fn validate_config(mut config: SystemLogConfig) -> Result<SystemLogConfig> {
    config.remote_host = config.remote_host.trim().to_string();

    if config.remote_port == 0 {
        return Err(AppError::BadRequest("invalid syslog port".to_string()));
    }
    if !(1..=8).contains(&config.priority) {
        return Err(AppError::BadRequest("invalid syslog priority".to_string()));
    }
    if !(16..=1024).contains(&config.buffer_kb) {
        return Err(AppError::BadRequest(
            "log buffer must be between 16 and 1024 KiB".to_string(),
        ));
    }
    if config.rotations > 4 {
        return Err(AppError::BadRequest(
            "log rotations must be between 0 and 4".to_string(),
        ));
    }
    if !(1..=8).contains(&config.kernel_console_level) {
        return Err(AppError::BadRequest(
            "invalid kernel console level".to_string(),
        ));
    }
    if config.remote_enabled && !valid_remote_host(&config.remote_host) {
        return Err(AppError::BadRequest(
            "invalid syslog host; use an IPv4 address or hostname".to_string(),
        ));
    }

    Ok(config)
}

fn valid_remote_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('-') || host.ends_with('-') || host.contains("..") {
        return false;
    }

    host.chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' || ch == '_')
}

fn write_config(config: &SystemLogConfig) -> Result<()> {
    let content = serde_json::to_vec_pretty(config)
        .map_err(|err| AppError::Internal(format!("encode syslog config: {err}")))?;
    write_file_atomic(Path::new(CONFIG_FILE), &content, 0o644)
}

fn write_defaults(config: &SystemLogConfig) -> Result<()> {
    fs::create_dir_all("/etc/default")?;

    let syslog_args = build_syslogd_args(config);
    let syslog_default = format!("SYSLOGD_ARGS={}\n", shell_quote(&syslog_args));
    write_file_atomic(
        Path::new(SYSLOGD_DEFAULT_FILE),
        syslog_default.as_bytes(),
        0o644,
    )?;

    let klog_args = format!("-c {}", config.kernel_console_level);
    let klog_default = format!("KLOGD_ARGS={}\n", shell_quote(&klog_args));
    write_file_atomic(
        Path::new(KLOGD_DEFAULT_FILE),
        klog_default.as_bytes(),
        0o644,
    )
}

fn build_syslogd_args(config: &SystemLogConfig) -> String {
    let mut args = vec![
        "-O".to_string(),
        LOG_FILE.to_string(),
        "-s".to_string(),
        config.buffer_kb.to_string(),
        "-b".to_string(),
        config.rotations.to_string(),
        "-l".to_string(),
        config.priority.to_string(),
    ];

    if config.remote_enabled {
        args.push("-R".to_string());
        args.push(format!("{}:{}", config.remote_host, config.remote_port));
        args.push("-L".to_string());
    }
    if config.small_output {
        args.push("-S".to_string());
    }
    if config.strip_timestamps {
        args.push("-t".to_string());
    }

    args.join(" ")
}

async fn apply_config(config: &SystemLogConfig) -> Result<()> {
    restart_service(
        AllowedCommand::ServiceSyslogd,
        "restart",
        "failed to restart syslogd",
    )
    .await?;

    if config.kernel_enabled {
        restart_service(
            AllowedCommand::ServiceKlogd,
            "restart",
            "failed to restart klogd",
        )
        .await
    } else {
        restart_service(AllowedCommand::ServiceKlogd, "stop", "failed to stop klogd").await
    }
}

async fn restart_service(command: AllowedCommand, action: &str, message: &str) -> Result<()> {
    let output = run_allowed(command, [action], Duration::from_secs(8)).await?;
    if output.status != 0 {
        return Err(AppError::Internal(command_error(message, output)));
    }

    Ok(())
}

fn read_system_log(lines: usize) -> Result<(String, bool)> {
    for path in std::iter::once(LOG_FILE).chain(FALLBACK_LOG_FILES.iter().copied()) {
        if Path::new(path).exists() {
            return tail_file(path, lines);
        }
    }

    Ok((String::new(), false))
}

fn read_backend_log(lines: usize) -> Result<(String, bool)> {
    match tail_file(BACKEND_LOG_FILE, lines) {
        Ok(log) => Ok(log),
        Err(AppError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok((String::new(), false))
        }
        Err(err) => Err(err),
    }
}

async fn read_kernel_log(lines: usize) -> Result<(String, bool)> {
    let size = MAX_LOG_VIEW_BYTES.to_string();
    let output = run_allowed(
        AllowedCommand::Dmesg,
        ["-s", size.as_str()],
        Duration::from_secs(3),
    )
    .await?;
    if output.status != 0 {
        return Err(AppError::Internal(command_error(
            "failed to read kernel log",
            output,
        )));
    }

    let content = String::from_utf8_lossy(&output.stdout).to_string();
    Ok((
        tail_lines(&content, lines),
        content.len() >= MAX_LOG_VIEW_BYTES,
    ))
}

fn tail_file(path: &str, lines: usize) -> Result<(String, bool)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let read_len = len.min(MAX_LOG_VIEW_BYTES as u64) as usize;
    let start = len.saturating_sub(read_len as u64);
    let mut buf = vec![0_u8; read_len];

    file.seek(SeekFrom::Start(start))?;
    file.read_exact(&mut buf)?;

    let truncated = start > 0;
    let mut content = String::from_utf8_lossy(&buf).to_string();
    if truncated {
        if let Some(pos) = content.find('\n') {
            content = content[pos + 1..].to_string();
        }
    }

    Ok((tail_lines(&content, lines), truncated))
}

fn tail_lines(content: &str, lines: usize) -> String {
    let all_lines: Vec<&str> = content.lines().collect();
    let start = all_lines.len().saturating_sub(lines);
    let mut out = all_lines[start..].join("\n");
    if content.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    out
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

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn command_error(message: &str, output: CommandOutput) -> String {
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
    fn renders_local_syslogd_args_in_tmpfs() {
        let args = build_syslogd_args(&SystemLogConfig::default());

        assert!(args.contains("-O /tmp/hardened-syslog/messages"));
        assert!(args.contains("-s 200"));
        assert!(!args.contains("-R"));
    }

    #[test]
    fn renders_remote_syslogd_args_with_local_copy() {
        let config = SystemLogConfig {
            remote_enabled: true,
            remote_host: "10.0.87.5".to_string(),
            remote_port: 514,
            ..SystemLogConfig::default()
        };
        let args = build_syslogd_args(&config);

        assert!(args.contains("-R 10.0.87.5:514"));
        assert!(args.contains("-L"));
    }

    #[test]
    fn rejects_ambiguous_ipv6_remote_host_for_busybox() {
        let config = SystemLogConfig {
            remote_enabled: true,
            remote_host: "fd00::1".to_string(),
            ..SystemLogConfig::default()
        };

        assert!(validate_config(config).is_err());
    }

    #[test]
    fn tails_requested_line_count() {
        let content = "one\ntwo\nthree\nfour\n";

        assert_eq!(tail_lines(content, 2), "three\nfour\n");
    }
}
