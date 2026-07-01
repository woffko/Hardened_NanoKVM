use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Component, Path},
    time::Duration,
};

use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{
    AppError, Result,
    error::ApiResponse,
    system::command::{AllowedCommand, CommandOutput, run_allowed},
};

const CONFIG_FILE: &str = "/etc/kvm/time.json";
const NTP_CONF_FILE: &str = "/etc/ntp.conf";
const NTPD_DEFAULT_FILE: &str = "/etc/default/ntpd";
const LOCALTIME_FILE: &str = "/etc/localtime";
const ZONEINFO_DIR: &str = "/usr/share/zoneinfo";
const DEFAULT_TIMEZONE: &str = "Etc/UTC";
const DEFAULT_NTP_SERVERS: &[&str] = &[
    "0.pool.ntp.org",
    "1.pool.ntp.org",
    "2.pool.ntp.org",
    "3.pool.ntp.org",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TimeConfig {
    pub ntp_enabled: bool,
    pub timezone: String,
    pub servers: Vec<String>,
}

impl Default for TimeConfig {
    fn default() -> Self {
        Self {
            ntp_enabled: true,
            timezone: current_timezone().unwrap_or_else(|| DEFAULT_TIMEZONE.to_string()),
            servers: current_ntp_servers(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeConfigRsp {
    config: TimeConfig,
    current_time: String,
    gateway: String,
    default_servers: Vec<String>,
    timezone_options: Vec<String>,
}

pub async fn get_config() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(build_response().await?)))
}

pub async fn set_config(Json(req): Json<TimeConfig>) -> Result<impl IntoResponse> {
    let config = validate_config(req)?;

    write_config(&config)?;
    write_ntp_conf(&config.servers)?;
    write_ntpd_default()?;
    set_timezone(&config.timezone)?;
    apply_ntp_state(config.ntp_enabled).await?;

    Ok(Json(ApiResponse::ok(build_response().await?)))
}

pub async fn sync_now() -> Result<impl IntoResponse> {
    let config = read_config()?;
    if !config.ntp_enabled {
        return Err(AppError::BadRequest("NTP is disabled".to_string()));
    }

    let Some(server) = config.servers.first() else {
        return Err(AppError::BadRequest(
            "no NTP servers configured".to_string(),
        ));
    };

    let output = run_allowed(
        AllowedCommand::Ntpdate,
        ["-u", server.as_str()],
        Duration::from_secs(20),
    )
    .await?;
    if output.status != 0 {
        return Err(AppError::Internal(command_error(
            "failed to synchronize time",
            output,
        )));
    }

    apply_ntp_state(true).await?;
    Ok(Json(ApiResponse::ok(build_response().await?)))
}

async fn build_response() -> Result<TimeConfigRsp> {
    Ok(TimeConfigRsp {
        config: read_config()?,
        current_time: current_time().await.unwrap_or_default(),
        gateway: default_ipv4_gateway().unwrap_or_default(),
        default_servers: DEFAULT_NTP_SERVERS
            .iter()
            .map(|value| value.to_string())
            .collect(),
        timezone_options: timezone_options(),
    })
}

fn read_config() -> Result<TimeConfig> {
    match fs::read_to_string(CONFIG_FILE) {
        Ok(content) => {
            let config: TimeConfig = serde_json::from_str(&content)
                .map_err(|err| AppError::Config(format!("invalid time config: {err}")))?;
            validate_config(config)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(TimeConfig::default()),
        Err(err) => Err(AppError::Io(err)),
    }
}

fn validate_config(mut config: TimeConfig) -> Result<TimeConfig> {
    config.timezone = normalize_timezone(&config.timezone)?;
    config.servers = normalize_servers(config.servers.iter().map(String::as_str))?;
    if config.servers.is_empty() {
        config.servers = DEFAULT_NTP_SERVERS
            .iter()
            .map(|value| value.to_string())
            .collect();
    }

    Ok(config)
}

fn normalize_timezone(value: &str) -> Result<String> {
    let timezone = value.trim().trim_start_matches('/').to_string();
    if timezone.is_empty() || timezone.len() > 128 {
        return Err(AppError::BadRequest("invalid timezone".to_string()));
    }
    if timezone.starts_with("posix/") || timezone.starts_with("right/") {
        return Err(AppError::BadRequest("invalid timezone".to_string()));
    }
    if !timezone
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '_' | '-' | '+'))
    {
        return Err(AppError::BadRequest("invalid timezone".to_string()));
    }

    let path = Path::new(ZONEINFO_DIR).join(&timezone);
    ensure_subpath(Path::new(ZONEINFO_DIR), &path)?;
    if !path.is_file() {
        return Err(AppError::BadRequest("unknown timezone".to_string()));
    }

    Ok(timezone)
}

fn normalize_servers<'a, I>(servers: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();

    for server in servers {
        let server = server.trim();
        if server.is_empty() {
            continue;
        }
        if normalized.len() >= 6 {
            return Err(AppError::BadRequest(
                "no more than 6 NTP servers are allowed".to_string(),
            ));
        }
        if !valid_ntp_server(server) {
            return Err(AppError::BadRequest("invalid NTP server".to_string()));
        }
        if seen.insert(server.to_ascii_lowercase()) {
            normalized.push(server.to_string());
        }
    }

    Ok(normalized)
}

fn valid_ntp_server(server: &str) -> bool {
    if server.is_empty() || server.len() > 253 {
        return false;
    }
    if server.starts_with('-')
        || server.ends_with('-')
        || server.contains("..")
        || server.contains(':') && server.starts_with(':')
    {
        return false;
    }

    server
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | '_' | ':'))
}

fn current_ntp_servers() -> Vec<String> {
    let servers = parse_ntp_servers(&fs::read_to_string(NTP_CONF_FILE).unwrap_or_default())
        .unwrap_or_else(|_| Vec::new())
        .into_iter()
        .take(6)
        .collect::<Vec<_>>();
    if servers.is_empty() {
        DEFAULT_NTP_SERVERS
            .iter()
            .map(|value| value.to_string())
            .collect()
    } else {
        servers
    }
}

fn parse_ntp_servers(content: &str) -> Result<Vec<String>> {
    let mut servers = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        if matches!(fields[0], "server" | "pool") {
            servers.push(fields[1]);
        }
    }
    normalize_servers(servers)
}

fn current_timezone() -> Option<String> {
    if let Ok(target) = fs::read_link(LOCALTIME_FILE) {
        if let Some(zone) = zone_from_path(&target) {
            return Some(zone);
        }
        if let Ok(canonical) = Path::new("/etc").join(target).canonicalize() {
            if let Some(zone) = zone_from_path(&canonical) {
                return Some(zone);
            }
        }
    }

    None
}

fn zone_from_path(path: &Path) -> Option<String> {
    let path = path.to_string_lossy();
    let zone = path
        .strip_prefix("../usr/share/zoneinfo/")
        .or_else(|| path.strip_prefix("/usr/share/zoneinfo/"))?;
    if zone.starts_with("posix/") || zone.starts_with("right/") {
        return None;
    }
    Some(zone.to_string())
}

fn timezone_options() -> Vec<String> {
    let mut zones = BTreeSet::new();
    zones.insert(DEFAULT_TIMEZONE.to_string());

    for file in ["zone1970.tab", "zone.tab"] {
        let path = Path::new(ZONEINFO_DIR).join(file);
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }
                if let Some(zone) = line.split_whitespace().nth(2) {
                    zones.insert(zone.to_string());
                }
            }
        }
    }

    if zones.len() <= 1 {
        collect_zone_files(Path::new(ZONEINFO_DIR), "", &mut zones);
    }

    zones.into_iter().collect()
}

fn collect_zone_files(dir: &Path, prefix: &str, zones: &mut BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if should_skip_zone_entry(&name) {
            continue;
        }

        let next_prefix = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let path = entry.path();
        if path.is_dir() {
            collect_zone_files(&path, &next_prefix, zones);
        } else if path.is_file() {
            zones.insert(next_prefix);
        }
    }
}

fn should_skip_zone_entry(name: &str) -> bool {
    matches!(
        name,
        "posix"
            | "right"
            | "SystemV"
            | "localtime"
            | "posixrules"
            | "zone.tab"
            | "zone1970.tab"
            | "iso3166.tab"
            | "leapseconds"
            | "tzdata.zi"
    )
}

fn write_config(config: &TimeConfig) -> Result<()> {
    let content = serde_json::to_vec_pretty(config)
        .map_err(|err| AppError::Internal(format!("encode time config: {err}")))?;
    write_file_atomic(Path::new(CONFIG_FILE), &content, 0o644)
}

fn write_ntp_conf(servers: &[String]) -> Result<()> {
    let mut content = String::new();
    content.push_str("# Managed by Hardened NanoKVM.\n");
    content.push_str("driftfile /var/lib/ntp/ntp.drift\n\n");
    for server in servers {
        content.push_str("server ");
        content.push_str(server);
        content.push_str(" iburst\n");
    }
    content.push_str("\nrestrict default kod nomodify notrap nopeer noquery\n");
    content.push_str("restrict 127.0.0.1\n");
    content.push_str("restrict ::1\n");
    write_file_atomic(Path::new(NTP_CONF_FILE), content.as_bytes(), 0o644)
}

fn write_ntpd_default() -> Result<()> {
    write_file_atomic(Path::new(NTPD_DEFAULT_FILE), b"NTPD_ARGS=\" -g\"\n", 0o644)
}

fn set_timezone(timezone: &str) -> Result<()> {
    let timezone = normalize_timezone(timezone)?;
    let target = Path::new("../usr/share/zoneinfo").join(timezone);
    let tmp = Path::new("/etc/.localtime.tmp");
    let _ = fs::remove_file(tmp);
    symlink(&target, tmp)?;
    fs::rename(tmp, LOCALTIME_FILE)?;
    Ok(())
}

async fn apply_ntp_state(enabled: bool) -> Result<()> {
    let action = if enabled { "restart" } else { "stop" };
    let output = run_allowed(AllowedCommand::ServiceNtp, [action], Duration::from_secs(8)).await?;
    if output.status != 0 {
        return Err(AppError::Internal(command_error(
            "failed to apply NTP settings",
            output,
        )));
    }

    Ok(())
}

async fn current_time() -> Result<String> {
    let output = run_allowed(
        AllowedCommand::Date,
        ["+%Y-%m-%d %H:%M:%S %Z"],
        Duration::from_secs(3),
    )
    .await?;
    if output.status != 0 {
        return Err(AppError::Internal(command_error(
            "failed to read current time",
            output,
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn default_ipv4_gateway() -> Option<String> {
    let content = fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 || fields[1] != "00000000" {
            continue;
        }
        return parse_route_gateway(fields[2]);
    }
    None
}

fn parse_route_gateway(value: &str) -> Option<String> {
    let gateway = u32::from_str_radix(value, 16).ok()?;
    if gateway == 0 {
        return None;
    }

    Some(format!(
        "{}.{}.{}.{}",
        gateway & 0xff,
        (gateway >> 8) & 0xff,
        (gateway >> 16) & 0xff,
        (gateway >> 24) & 0xff
    ))
}

fn ensure_subpath(base: &Path, path: &Path) -> Result<()> {
    for component in path.strip_prefix(base).unwrap_or(path).components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(AppError::BadRequest("invalid timezone".to_string()));
        }
    }
    Ok(())
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
    fn parses_ntp_servers() {
        let servers = parse_ntp_servers(
            r#"
            # comment
            server 0.pool.ntp.org iburst
            pool time.cloudflare.com iburst
            "#,
        )
        .unwrap();

        assert_eq!(servers, vec!["0.pool.ntp.org", "time.cloudflare.com"]);
    }

    #[test]
    fn rejects_shell_like_ntp_servers() {
        assert!(!valid_ntp_server("-bad"));
        assert!(!valid_ntp_server("pool.ntp.org;reboot"));
        assert!(!valid_ntp_server("pool ntp org"));
    }

    #[test]
    fn parses_little_endian_route_gateway() {
        assert_eq!(
            parse_route_gateway("0557000A").as_deref(),
            Some("10.0.87.5")
        );
        assert_eq!(parse_route_gateway("00000000"), None);
    }

    #[test]
    fn extracts_timezone_from_link_target() {
        assert_eq!(
            zone_from_path(Path::new("../usr/share/zoneinfo/Europe/Tallinn")).as_deref(),
            Some("Europe/Tallinn")
        );
    }
}
