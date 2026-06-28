use axum::{Json, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{fs, time::Duration};

use crate::{
    AppError, Result,
    error::ApiResponse,
    system::command::{AllowedCommand, CommandOutput, run_allowed},
};

const SYSTEM_VERSION_FILE: &str = "/etc/kvm/system-version.json";
const BOOT_VERSION_FILE: &str = "/boot/ver";
const KERNEL_RELEASE_FILE: &str = "/proc/sys/kernel/osrelease";
const OS_RELEASE_FILE: &str = "/etc/os-release";
const DEVICE_MODEL_FILE: &str = "/proc/device-tree/model";
const HARDWARE_VERSION_FILE: &str = "/etc/kvm/hw";
const DEFAULT_SYSTEM_VERSION: &str = "0.0.0-stock";
const DEFAULT_SYSTEM_TARGET: &str = "sg2002-licheervnano-sd";
const GITHUB_SYSTEM_LATEST_JSON: &str = "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-stable/system-latest.json";
const GITHUB_SYSTEM_PREVIEW_JSON: &str = "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-preview/system-latest.json";
const GITHUB_SYSTEM_DOWNLOAD_PREFIX: &str =
    "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-";
const GITHUB_SYSTEM_CHANNEL_PREFIX: &str =
    "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-";
const MAX_SYSTEM_UPDATE_BYTES: u64 = 256 * 1024 * 1024;
const METADATA_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemVersion {
    pub version: String,
    pub target: String,
    pub base_version: String,
    pub kernel_version: String,
    pub rootfs_version: String,
    pub model: String,
    pub hardware_version: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemLatest {
    pub kind: String,
    pub format: u32,
    pub channel: String,
    pub version: String,
    pub target: String,
    pub name: String,
    pub sha256: String,
    pub sha512: String,
    pub size: u64,
    pub url: String,
    pub release_notes_url: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemVersionRsp {
    pub current: SystemVersion,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemCheckRsp {
    pub current: SystemVersion,
    pub latest: Option<SystemLatest>,
    pub update_available: bool,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedSystemVersion {
    version: Option<String>,
    target: Option<String>,
    base_version: Option<String>,
    kernel_version: Option<String>,
    rootfs_version: Option<String>,
}

pub async fn get_version() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(SystemVersionRsp {
        current: read_current_system_version(),
    })))
}

pub async fn check() -> Result<impl IntoResponse> {
    let current = read_current_system_version();

    match get_latest_system(false).await {
        Ok(latest) => {
            let update_available =
                latest.target == current.target && latest.version != current.version;
            Ok(Json(ApiResponse::ok(SystemCheckRsp {
                current,
                latest: Some(latest),
                update_available,
                error: None,
            })))
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to query latest system release");
            Ok(Json(ApiResponse::ok(SystemCheckRsp {
                current,
                latest: None,
                update_available: false,
                error: Some(err.to_string()),
            })))
        }
    }
}

async fn get_latest_system(preview: bool) -> Result<SystemLatest> {
    if preview {
        match fetch_latest_system(GITHUB_SYSTEM_PREVIEW_JSON).await {
            Ok(latest) => return Ok(latest),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to query preview system release metadata, falling back to stable"
                );
            }
        }
    }

    fetch_latest_system(GITHUB_SYSTEM_LATEST_JSON).await
}

async fn fetch_latest_system(url: &str) -> Result<SystemLatest> {
    validate_metadata_url(url)?;
    let output = run_allowed(
        AllowedCommand::Curl,
        [
            "-fsSL",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "-H",
            "Accept: application/json",
            url,
        ],
        METADATA_TIMEOUT,
    )
    .await?;
    ensure_success(&output, "query latest system release metadata")?;

    let latest: SystemLatest = serde_json::from_slice(&output.stdout)
        .map_err(|err| AppError::Internal(format!("invalid system-latest.json: {err}")))?;
    validate_latest_system(&latest)?;
    Ok(latest)
}

fn read_current_system_version() -> SystemVersion {
    let mut version = SystemVersion {
        version: DEFAULT_SYSTEM_VERSION.to_string(),
        target: DEFAULT_SYSTEM_TARGET.to_string(),
        base_version: read_trimmed(BOOT_VERSION_FILE).unwrap_or_default(),
        kernel_version: read_trimmed(KERNEL_RELEASE_FILE).unwrap_or_default(),
        rootfs_version: read_rootfs_version(),
        model: read_trimmed(DEVICE_MODEL_FILE).unwrap_or_default(),
        hardware_version: read_trimmed(HARDWARE_VERSION_FILE).unwrap_or_default(),
        source: "fallback".to_string(),
    };

    if let Ok(raw) = fs::read_to_string(SYSTEM_VERSION_FILE) {
        match serde_json::from_str::<PersistedSystemVersion>(&raw) {
            Ok(persisted) => {
                if let Some(value) = non_empty(persisted.version) {
                    version.version = value;
                }
                if let Some(value) = non_empty(persisted.target) {
                    version.target = value;
                }
                if let Some(value) = non_empty(persisted.base_version) {
                    version.base_version = value;
                }
                if let Some(value) = non_empty(persisted.kernel_version) {
                    version.kernel_version = value;
                }
                if let Some(value) = non_empty(persisted.rootfs_version) {
                    version.rootfs_version = value;
                }
                version.source = "persisted".to_string();
            }
            Err(err) => {
                tracing::warn!(error = %err, path = SYSTEM_VERSION_FILE, "invalid system version file");
            }
        }
    }

    version.model = version.model.trim_matches(char::from(0)).to_string();
    version
}

fn read_rootfs_version() -> String {
    let Some(raw) = read_trimmed(OS_RELEASE_FILE) else {
        return String::new();
    };

    let mut name = None;
    let mut version_id = None;
    let mut pretty = None;

    for line in raw.lines() {
        if let Some(value) = parse_os_release_value(line, "PRETTY_NAME") {
            pretty = Some(value);
        } else if let Some(value) = parse_os_release_value(line, "NAME") {
            name = Some(value);
        } else if let Some(value) = parse_os_release_value(line, "VERSION_ID") {
            version_id = Some(value);
        }
    }

    pretty
        .or_else(|| match (name, version_id) {
            (Some(name), Some(version)) => Some(format!("{name} {version}")),
            (Some(name), None) => Some(name),
            _ => None,
        })
        .unwrap_or_default()
}

fn parse_os_release_value(line: &str, key: &str) -> Option<String> {
    let value = line.strip_prefix(key)?.strip_prefix('=')?;
    Some(value.trim_matches('"').to_string())
}

fn validate_latest_system(latest: &SystemLatest) -> Result<()> {
    if latest.kind != "hardened-nanokvm-system-update" {
        return Err(AppError::BadRequest(
            "invalid system update kind".to_string(),
        ));
    }
    if latest.format != 1 {
        return Err(AppError::BadRequest(format!(
            "unsupported system update format: {}",
            latest.format
        )));
    }
    validate_token("version", &latest.version)?;
    validate_token("target", &latest.target)?;
    validate_token("channel", &latest.channel)?;
    validate_system_archive_name(&latest.name)?;
    validate_system_release_url(&latest.url)?;
    validate_release_notes_url(&latest.release_notes_url)?;

    if latest.size == 0 || latest.size > MAX_SYSTEM_UPDATE_BYTES {
        return Err(AppError::BadRequest(
            "invalid system update size".to_string(),
        ));
    }
    if !latest.sha256.chars().all(|ch| ch.is_ascii_hexdigit()) || latest.sha256.len() != 64 {
        return Err(AppError::BadRequest(
            "invalid system update sha256".to_string(),
        ));
    }
    STANDARD
        .decode(&latest.sha512)
        .map_err(|_| AppError::BadRequest("invalid system update sha512".to_string()))?;

    Ok(())
}

fn validate_metadata_url(url: &str) -> Result<()> {
    if !url.starts_with(GITHUB_SYSTEM_CHANNEL_PREFIX) || !url.ends_with("/system-latest.json") {
        return Err(AppError::Internal(
            "invalid system update metadata URL".to_string(),
        ));
    }
    Ok(())
}

fn validate_system_release_url(url: &str) -> Result<()> {
    if !url.starts_with(GITHUB_SYSTEM_DOWNLOAD_PREFIX)
        || !url.contains("/hardened-nanokvm-system-")
        || !url.ends_with(".tar.gz")
    {
        return Err(AppError::BadRequest(
            "untrusted system update URL".to_string(),
        ));
    }
    Ok(())
}

fn validate_release_notes_url(url: &str) -> Result<()> {
    if !url.starts_with("https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-")
    {
        return Err(AppError::BadRequest(
            "untrusted system release notes URL".to_string(),
        ));
    }
    Ok(())
}

fn validate_system_archive_name(name: &str) -> Result<()> {
    match name {
        name if name.starts_with("hardened-nanokvm-system-") && name.ends_with(".tar.gz") => {
            validate_filename(name)
        }
        _ => Err(AppError::BadRequest(
            "invalid system update archive name".to_string(),
        )),
    }
}

fn validate_filename(name: &str) -> Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+'))
    {
        return Err(AppError::BadRequest("invalid filename".to_string()));
    }
    Ok(())
}

fn validate_token(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+'))
    {
        return Err(AppError::BadRequest(format!("invalid {name}")));
    }
    Ok(())
}

fn ensure_success(output: &CommandOutput, action: &str) -> Result<()> {
    if output.status == 0 {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(AppError::Internal(format!("{action} failed: {stderr}")))
}

fn read_trimmed(path: &str) -> Option<String> {
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim().trim_matches(char::from(0)).to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_string();
        if value.is_empty() { None } else { Some(value) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_system_latest_metadata() {
        let latest = SystemLatest {
            kind: "hardened-nanokvm-system-update".to_string(),
            format: 1,
            channel: "stable".to_string(),
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            name: "hardened-nanokvm-system-0.1.0.tar.gz".to_string(),
            sha256: "a".repeat(64),
            sha512: STANDARD.encode([1_u8; 64]),
            size: 1024,
            url: "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-0.1.0/hardened-nanokvm-system-0.1.0.tar.gz".to_string(),
            release_notes_url: "https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.1.0".to_string(),
        };

        validate_latest_system(&latest).unwrap();
    }

    #[test]
    fn rejects_untrusted_system_update_url() {
        let latest = SystemLatest {
            kind: "hardened-nanokvm-system-update".to_string(),
            format: 1,
            channel: "stable".to_string(),
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            name: "hardened-nanokvm-system-0.1.0.tar.gz".to_string(),
            sha256: "a".repeat(64),
            sha512: STANDARD.encode([1_u8; 64]),
            size: 1024,
            url: "https://example.com/hardened-nanokvm-system-0.1.0.tar.gz".to_string(),
            release_notes_url:
                "https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.1.0"
                    .to_string(),
        };

        assert!(validate_latest_system(&latest).is_err());
    }
}
