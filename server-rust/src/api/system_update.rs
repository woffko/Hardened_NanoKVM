use axum::{Json, extract::State, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    AppError, Result,
    config::Config,
    error::ApiResponse,
    state::AppState,
    system::command::{AllowedCommand, CommandOutput, run_allowed},
    update::archive::extract_tar_gz_safe,
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
const SYSTEM_UPDATE_SIGNATURE_ALGORITHM: &str = "sha256-rsa-pkcs1-v1_5";
const SYSTEM_UPDATE_UNSIGNED_ALGORITHM: &str = "unsigned";
const MAX_SYSTEM_UPDATE_BYTES: u64 = 256 * 1024 * 1024;
const METADATA_TIMEOUT: Duration = Duration::from_secs(45);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const SYSTEM_STAGE_DIR_NAME: &str = "system-update";
const SYSTEM_EXTRACT_DIR_NAME: &str = "extract";
const SYSTEM_STAGE_RECORD: &str = "staged.json";
const SYSTEM_BACKUPS_DIR_NAME: &str = "backups";
const SYSTEM_BACKUP_RECORD: &str = "backup.json";
const SYSTEM_PENDING_FILE: &str = "/etc/kvm/system-update-pending.json";
const SYSTEM_LAST_BACKUP_FILE: &str = "/etc/kvm/system-update-last-backup.json";
const SYSTEM_BOOT_GOOD_FILE: &str = "/etc/kvm/system-update-boot-good.json";
const SYSTEM_ROLLBACK_SCRIPT_FILE: &str = "/etc/kvm/system-update-rollback.sh";
const SYSTEM_ROLLBACK_ATTEMPT_FILE: &str = "/etc/kvm/system-update-rollback-attempted";

static SYSTEM_UPDATE_LOCK: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));

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
    #[serde(alias = "release_notes_url")]
    pub release_notes_url: String,
    #[serde(alias = "signature_algorithm")]
    pub signature_algorithm: String,
    #[serde(alias = "signature_key_id")]
    pub signature_key_id: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStagedUpdate {
    pub version: String,
    pub target: String,
    pub channel: String,
    pub archive_name: String,
    pub size: u64,
    pub sha256: String,
    pub staged_at: u64,
    pub base_version: String,
    pub kernel_version: String,
    pub required_free_bytes: u64,
    pub requires_reboot: bool,
    pub file_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatusRsp {
    pub current: SystemVersion,
    pub staged: Option<SystemStagedUpdate>,
    pub pending: Option<SystemPendingUpdate>,
    pub boot_health: Option<SystemBootHealth>,
    pub rollback: Option<SystemRollbackInfo>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemDownloadRsp {
    pub current: SystemVersion,
    pub latest: SystemLatest,
    pub staged: SystemStagedUpdate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemPendingUpdate {
    pub version: String,
    pub target: String,
    pub backup_id: String,
    pub installed_at: u64,
    pub requires_reboot: bool,
    pub file_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemRollbackInfo {
    pub version: String,
    pub target: String,
    pub backup_id: String,
    pub installed_at: u64,
    pub file_count: usize,
    pub requires_reboot: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInstallRsp {
    pub current: SystemVersion,
    pub installed: SystemPendingUpdate,
    pub reboot_required: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemRollbackRsp {
    pub restored: SystemRollbackInfo,
    pub reboot_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemBootHealth {
    pub backend_running: bool,
    pub version_matches_pending: bool,
    pub boot_marker_present: bool,
    pub web_root_present: bool,
    pub healthy: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemConfirmRsp {
    pub confirmed: SystemPendingUpdate,
    pub health: SystemBootHealth,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemStageRecord {
    staged_at: u64,
    latest: SystemLatest,
    manifest: SystemManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemManifest {
    format: String,
    version: String,
    target: String,
    base_version: String,
    kernel_version: String,
    source_commit: String,
    created_utc: String,
    required_free_bytes: u64,
    requires_reboot: bool,
    operations: Vec<String>,
    files: Vec<SystemManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemManifestFile {
    payload: String,
    install: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemInstallRecord {
    version: String,
    target: String,
    backup_id: String,
    installed_at: u64,
    requires_reboot: bool,
    files: Vec<SystemBackupFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemBackupFile {
    install: String,
    backup: String,
    existed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstalledSystemVersion {
    version: String,
    target: String,
    base_version: String,
    kernel_version: String,
    rootfs_version: String,
}

#[derive(Debug)]
struct UpdateGuard;

#[derive(Debug)]
struct FileHashes {
    sha256: String,
    sha512: String,
}

impl Drop for UpdateGuard {
    fn drop(&mut self) {
        if let Ok(mut is_updating) = SYSTEM_UPDATE_LOCK.lock() {
            *is_updating = false;
        }
    }
}

pub async fn get_version() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(SystemVersionRsp {
        current: read_current_system_version(),
    })))
}

pub async fn check(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let current = read_current_system_version();

    match get_latest_system(false, &state.config).await {
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

pub async fn status(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let current = read_current_system_version();
    let stage_dir = system_stage_dir(&state.config.paths.update_cache_dir);
    let pending = read_pending_update().ok().flatten();
    let boot_health = pending
        .as_ref()
        .map(|pending| evaluate_boot_health(&current, pending, &state));
    let rollback = read_last_backup_record(&stage_dir)
        .ok()
        .flatten()
        .map(|record| rollback_info(&record));

    match read_staged_update(&stage_dir) {
        Ok(staged) => Ok(Json(ApiResponse::ok(SystemStatusRsp {
            current,
            staged,
            pending,
            boot_health,
            rollback,
            error: None,
        }))),
        Err(err) => {
            tracing::warn!(error = %err, "failed to read staged system update");
            Ok(Json(ApiResponse::ok(SystemStatusRsp {
                current,
                staged: None,
                pending,
                boot_health,
                rollback,
                error: Some(err.to_string()),
            })))
        }
    }
}

pub async fn download(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let _guard = acquire_update_lock()?;
    let current = read_current_system_version();
    let latest = get_latest_system(false, &state.config).await?;

    if latest.target != current.target {
        return Err(AppError::BadRequest(format!(
            "system update target mismatch: device {}, release {}",
            current.target, latest.target
        )));
    }

    let stage_dir = system_stage_dir(&state.config.paths.update_cache_dir);
    prepare_stage_dir(&stage_dir)?;

    let archive = stage_dir.join(&latest.name);
    download_system_asset(&latest, &archive).await?;
    verify_system_archive(&archive, &latest)?;

    let manifest = extract_and_verify_system_bundle(&archive, &stage_dir, &latest)?;
    let record = SystemStageRecord {
        staged_at: now_unix_seconds(),
        latest: latest.clone(),
        manifest,
    };
    write_stage_record(&stage_dir, &record)?;

    Ok(Json(ApiResponse::ok(SystemDownloadRsp {
        current,
        latest,
        staged: staged_summary(&record),
    })))
}

pub async fn install(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let _guard = acquire_update_lock()?;
    let stage_dir = system_stage_dir(&state.config.paths.update_cache_dir);
    let installed = install_staged_update(&stage_dir)?;

    Ok(Json(ApiResponse::ok(SystemInstallRsp {
        current: read_current_system_version(),
        reboot_required: installed.requires_reboot,
        installed,
    })))
}

pub async fn rollback(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let _guard = acquire_update_lock()?;
    let stage_dir = system_stage_dir(&state.config.paths.update_cache_dir);
    let restored = rollback_last_system_update(&stage_dir)?;

    Ok(Json(ApiResponse::ok(SystemRollbackRsp {
        reboot_required: restored.requires_reboot,
        restored,
    })))
}

pub async fn confirm(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let _guard = acquire_update_lock()?;
    let current = read_current_system_version();
    let pending = read_pending_update()?
        .ok_or_else(|| AppError::NotFound("no pending system update found".to_string()))?;
    let health = evaluate_boot_health(&current, &pending, &state);

    if !health.healthy {
        return Err(AppError::BadRequest(
            "system update boot health check failed".to_string(),
        ));
    }

    write_boot_good(&pending, &health)?;
    remove_file_if_exists(Path::new(SYSTEM_PENDING_FILE))?;

    Ok(Json(ApiResponse::ok(SystemConfirmRsp {
        confirmed: pending,
        health,
    })))
}

async fn get_latest_system(preview: bool, config: &Config) -> Result<SystemLatest> {
    if preview {
        match fetch_latest_system(GITHUB_SYSTEM_PREVIEW_JSON, config).await {
            Ok(latest) => return Ok(latest),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to query preview system release metadata, falling back to stable"
                );
            }
        }
    }

    fetch_latest_system(GITHUB_SYSTEM_LATEST_JSON, config).await
}

async fn fetch_latest_system(url: &str, config: &Config) -> Result<SystemLatest> {
    validate_metadata_url(url)?;
    let metadata = fetch_system_metadata(url).await?;

    let latest: SystemLatest = serde_json::from_slice(&metadata)
        .map_err(|err| AppError::Internal(format!("invalid system-latest.json: {err}")))?;
    validate_latest_system(&latest)?;
    enforce_system_metadata_signature(url, &metadata, &latest, config).await?;
    Ok(latest)
}

async fn fetch_system_metadata(url: &str) -> Result<Vec<u8>> {
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
    Ok(output.stdout)
}

async fn enforce_system_metadata_signature(
    metadata_url: &str,
    metadata: &[u8],
    latest: &SystemLatest,
    config: &Config,
) -> Result<()> {
    if system_metadata_is_unsigned(latest) {
        if config.security.allow_unsigned_updates {
            tracing::warn!(
                version = %latest.version,
                channel = %latest.channel,
                "accepting unsigned system update metadata because allow_unsigned_updates is enabled"
            );
            return Ok(());
        }
        return Err(AppError::BadRequest(
            "unsigned system update metadata is not allowed".to_string(),
        ));
    }

    if latest.signature_algorithm != SYSTEM_UPDATE_SIGNATURE_ALGORITHM {
        return Err(AppError::BadRequest(
            "unsupported system update metadata signature algorithm".to_string(),
        ));
    }
    if !config.paths.system_update_public_key.is_file() {
        return Err(AppError::Config(format!(
            "system update public key is not configured: {}",
            config.paths.system_update_public_key.display()
        )));
    }

    let signature_url = metadata_signature_url(metadata_url)?;
    let signature = fetch_system_metadata_signature(&signature_url).await?;
    verify_system_metadata_signature(metadata, &signature, &config.paths.system_update_public_key)
        .await
}

async fn fetch_system_metadata_signature(url: &str) -> Result<Vec<u8>> {
    let output = run_allowed(
        AllowedCommand::Curl,
        ["-fsSL", "--connect-timeout", "10", "--max-time", "30", url],
        METADATA_TIMEOUT,
    )
    .await?;
    ensure_success(&output, "download system update metadata signature")?;
    if output.stdout.is_empty() || output.stdout.len() > 16 * 1024 {
        return Err(AppError::BadRequest(
            "invalid system update metadata signature size".to_string(),
        ));
    }
    Ok(output.stdout)
}

async fn verify_system_metadata_signature(
    metadata: &[u8],
    signature: &[u8],
    public_key: &Path,
) -> Result<()> {
    let metadata_path = temp_verify_path("metadata")?;
    let signature_path = temp_verify_path("signature")?;

    let result = async {
        write_verify_temp_file(&metadata_path, metadata)?;
        write_verify_temp_file(&signature_path, signature)?;

        let output = run_allowed(
            AllowedCommand::OpenSsl,
            [
                "dgst",
                "-sha256",
                "-verify",
                path_arg(public_key)?,
                "-signature",
                path_arg(&signature_path)?,
                path_arg(&metadata_path)?,
            ],
            METADATA_TIMEOUT,
        )
        .await?;

        if output.status == 0 {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(error = %stderr, "system update metadata signature verification failed");
            Err(AppError::BadRequest(
                "system update metadata signature verification failed".to_string(),
            ))
        }
    }
    .await;

    let _ = remove_file_if_exists(&metadata_path);
    let _ = remove_file_if_exists(&signature_path);
    result
}

fn metadata_signature_url(metadata_url: &str) -> Result<String> {
    validate_metadata_url(metadata_url)?;
    Ok(format!("{metadata_url}.sig"))
}

fn system_metadata_is_unsigned(latest: &SystemLatest) -> bool {
    latest.signature_algorithm == SYSTEM_UPDATE_UNSIGNED_ALGORITHM
        && latest.signature_key_id == SYSTEM_UPDATE_UNSIGNED_ALGORITHM
}

async fn download_system_asset(latest: &SystemLatest, target: &Path) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }

    let output = run_allowed(
        AllowedCommand::Curl,
        [
            "-fL",
            "--retry",
            "3",
            "--connect-timeout",
            "10",
            "--max-time",
            "600",
            "--output",
            path_arg(target)?,
            latest.url.as_str(),
        ],
        DOWNLOAD_TIMEOUT,
    )
    .await?;
    ensure_success(&output, "download system update archive")?;

    let size = fs::metadata(target)?.len();
    if size == 0 || size > MAX_SYSTEM_UPDATE_BYTES {
        return Err(AppError::BadRequest(
            "invalid system update archive size".to_string(),
        ));
    }
    if size != latest.size {
        return Err(AppError::BadRequest(format!(
            "system update archive size mismatch: got {size}, expected {}",
            latest.size
        )));
    }

    Ok(())
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

fn read_staged_update(stage_dir: &Path) -> Result<Option<SystemStagedUpdate>> {
    let record_path = stage_dir.join(SYSTEM_STAGE_RECORD);
    if !record_path.exists() {
        return Ok(None);
    }

    let raw = fs::read(&record_path)?;
    let record: SystemStageRecord = serde_json::from_slice(&raw)
        .map_err(|err| AppError::Internal(format!("invalid staged system update: {err}")))?;
    validate_latest_system(&record.latest)?;
    validate_manifest_shape(&record.manifest, &record.latest)?;

    let archive = stage_dir.join(&record.latest.name);
    if !archive.is_file() {
        return Ok(None);
    }

    let archive_size = fs::metadata(&archive)?.len();
    if archive_size != record.latest.size {
        return Ok(None);
    }

    Ok(Some(staged_summary(&record)))
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
    if !latest.url.ends_with(&format!("/{}", latest.name)) {
        return Err(AppError::BadRequest(
            "system update URL does not match archive name".to_string(),
        ));
    }
    if !latest
        .release_notes_url
        .ends_with(&format!("/hardened-system-{}", latest.version))
    {
        return Err(AppError::BadRequest(
            "system release notes URL does not match version".to_string(),
        ));
    }
    validate_system_metadata_signature_fields(latest)?;

    if latest.size == 0 || latest.size > MAX_SYSTEM_UPDATE_BYTES {
        return Err(AppError::BadRequest(
            "invalid system update size".to_string(),
        ));
    }
    validate_sha256_hex(&latest.sha256)?;
    let sha512 = STANDARD
        .decode(&latest.sha512)
        .map_err(|_| AppError::BadRequest("invalid system update sha512".to_string()))?;
    if sha512.len() != 64 {
        return Err(AppError::BadRequest(
            "invalid system update sha512".to_string(),
        ));
    }

    Ok(())
}

fn validate_system_metadata_signature_fields(latest: &SystemLatest) -> Result<()> {
    if system_metadata_is_unsigned(latest) {
        return Ok(());
    }
    if latest.signature_algorithm == SYSTEM_UPDATE_UNSIGNED_ALGORITHM
        || latest.signature_key_id == SYSTEM_UPDATE_UNSIGNED_ALGORITHM
    {
        return Err(AppError::BadRequest(
            "invalid unsigned system update metadata marker".to_string(),
        ));
    }
    if latest.signature_algorithm != SYSTEM_UPDATE_SIGNATURE_ALGORITHM {
        return Err(AppError::BadRequest(
            "unsupported system update metadata signature algorithm".to_string(),
        ));
    }
    validate_token("signature_key_id", &latest.signature_key_id)?;
    Ok(())
}

fn verify_system_archive(path: &Path, latest: &SystemLatest) -> Result<()> {
    let hashes = hash_file(path)?;
    if !hashes.sha256.eq_ignore_ascii_case(&latest.sha256) {
        return Err(AppError::BadRequest(
            "system update sha256 mismatch".to_string(),
        ));
    }
    if hashes.sha512 != latest.sha512 {
        return Err(AppError::BadRequest(
            "system update sha512 mismatch".to_string(),
        ));
    }
    Ok(())
}

fn extract_and_verify_system_bundle(
    archive: &Path,
    stage_dir: &Path,
    latest: &SystemLatest,
) -> Result<SystemManifest> {
    let extract_dir = stage_dir.join(SYSTEM_EXTRACT_DIR_NAME);
    remove_dir_if_exists(&extract_dir)?;
    fs::create_dir_all(&extract_dir)?;
    extract_tar_gz_safe(archive, &extract_dir)?;

    validate_system_extract_root(&extract_dir)?;

    let manifest_path = extract_dir.join("manifest.json");
    let manifest: SystemManifest = serde_json::from_slice(&fs::read(&manifest_path)?)
        .map_err(|err| AppError::BadRequest(format!("invalid system update manifest: {err}")))?;
    let payload_dir = extract_dir.join("payload");
    validate_system_manifest(&manifest, latest, &payload_dir)?;

    Ok(manifest)
}

fn install_staged_update(stage_dir: &Path) -> Result<SystemPendingUpdate> {
    let record = read_stage_record(stage_dir)?
        .ok_or_else(|| AppError::BadRequest("no staged system update".to_string()))?;
    validate_latest_system(&record.latest)?;

    let archive = stage_dir.join(&record.latest.name);
    if !archive.is_file() {
        return Err(AppError::BadRequest(
            "staged system update archive is missing".to_string(),
        ));
    }
    verify_system_archive(&archive, &record.latest)?;
    let manifest = extract_and_verify_system_bundle(&archive, stage_dir, &record.latest)?;
    let payload_dir = stage_dir.join(SYSTEM_EXTRACT_DIR_NAME).join("payload");

    let backup_id = format!("{}-{}", manifest.version, now_unix_seconds());
    validate_filename(&backup_id)?;
    let backup_dir = backup_dir_for(stage_dir, &backup_id);
    remove_dir_if_exists(&backup_dir)?;
    fs::create_dir_all(&backup_dir)?;

    let mut install_record = SystemInstallRecord {
        version: manifest.version.clone(),
        target: manifest.target.clone(),
        backup_id,
        installed_at: now_unix_seconds(),
        requires_reboot: manifest.requires_reboot,
        files: Vec::new(),
    };

    let mut backed_up = BTreeSet::new();
    for file in &manifest.files {
        backup_install_target(
            &file.install,
            &backup_dir,
            &mut install_record,
            &mut backed_up,
        )?;
    }
    if !backed_up.contains(SYSTEM_VERSION_FILE) {
        backup_install_target(
            SYSTEM_VERSION_FILE,
            &backup_dir,
            &mut install_record,
            &mut backed_up,
        )?;
    }
    write_backup_record(&backup_dir, &install_record)?;

    let apply_result = (|| -> Result<()> {
        for file in &manifest.files {
            install_payload_file(&payload_dir, file)?;
        }
        write_installed_system_version(&manifest)?;
        write_last_backup_record(&install_record)?;
        write_rollback_script(stage_dir, &install_record)?;
        remove_file_if_exists(Path::new(SYSTEM_ROLLBACK_ATTEMPT_FILE))?;
        remove_file_if_exists(Path::new(SYSTEM_BOOT_GOOD_FILE))?;
        write_pending_update(&pending_update(&install_record))?;
        Ok(())
    })();

    if let Err(err) = apply_result {
        tracing::error!(error = %err, "system update install failed, rolling back applied files");
        if let Err(rollback_err) = rollback_from_record(stage_dir, &install_record) {
            tracing::error!(error = %rollback_err, "failed to rollback after system update install error");
        }
        return Err(err);
    }

    Ok(pending_update(&install_record))
}

fn rollback_last_system_update(stage_dir: &Path) -> Result<SystemRollbackInfo> {
    let record = read_last_backup_record(stage_dir)?
        .ok_or_else(|| AppError::NotFound("no system update backup found".to_string()))?;
    rollback_from_record(stage_dir, &record)?;
    remove_file_if_exists(Path::new(SYSTEM_PENDING_FILE))?;
    remove_file_if_exists(Path::new(SYSTEM_BOOT_GOOD_FILE))?;
    remove_file_if_exists(Path::new(SYSTEM_ROLLBACK_SCRIPT_FILE))?;
    remove_file_if_exists(Path::new(SYSTEM_ROLLBACK_ATTEMPT_FILE))?;
    Ok(rollback_info(&record))
}

fn rollback_from_record(stage_dir: &Path, record: &SystemInstallRecord) -> Result<()> {
    let backup_dir = backup_dir_for(stage_dir, &record.backup_id);
    if !backup_dir.is_dir() {
        return Err(AppError::Internal(format!(
            "system update backup directory is missing: {}",
            record.backup_id
        )));
    }

    for file in record.files.iter().rev() {
        let install = validate_absolute_install_path(&file.install)?;
        if file.existed {
            let backup = safe_backup_join(&backup_dir, &file.backup)?;
            if !backup.is_file() {
                return Err(AppError::Internal(format!(
                    "system update backup file is missing: {}",
                    file.backup
                )));
            }
            atomic_copy_file(&backup, &install, backup_file_mode(&backup)?)?;
        } else {
            remove_file_if_exists(&install)?;
        }
    }

    Ok(())
}

fn install_payload_file(payload_dir: &Path, file: &SystemManifestFile) -> Result<()> {
    validate_install_path(&file.install, &file.payload)?;
    let payload = safe_payload_join(payload_dir, &file.payload)?;
    let install = validate_absolute_install_path(&file.install)?;
    atomic_copy_file(&payload, &install, install_file_mode(&file.install))
}

fn write_installed_system_version(manifest: &SystemManifest) -> Result<()> {
    let version = InstalledSystemVersion {
        version: manifest.version.clone(),
        target: manifest.target.clone(),
        base_version: manifest.base_version.clone(),
        kernel_version: manifest.kernel_version.clone(),
        rootfs_version: read_rootfs_version(),
    };
    let data = serde_json::to_vec_pretty(&version)
        .map_err(|err| AppError::Internal(format!("encode system version: {err}")))?;
    atomic_write_file(Path::new(SYSTEM_VERSION_FILE), &data, 0o644)
}

fn backup_install_target(
    install: &str,
    backup_dir: &Path,
    record: &mut SystemInstallRecord,
    backed_up: &mut BTreeSet<String>,
) -> Result<()> {
    let install_path = validate_absolute_install_path(install)?;
    if !backed_up.insert(install.to_string()) {
        return Ok(());
    }

    let backup = backup_relative_for_install(install)?;
    let backup_path = safe_backup_join(backup_dir, &backup)?;
    let existed = install_path.exists();

    if existed {
        let metadata = fs::symlink_metadata(&install_path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AppError::BadRequest(format!(
                "system update can only backup regular files: {install}"
            )));
        }
        if let Some(parent) = backup_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&install_path, &backup_path)?;
        fs::set_permissions(&backup_path, metadata.permissions())?;
    }

    record.files.push(SystemBackupFile {
        install: install.to_string(),
        backup,
        existed,
    });
    Ok(())
}

fn atomic_write_file(target: &Path, data: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    reject_symlink_parents(target)?;
    if target
        .symlink_metadata()
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(AppError::BadRequest(format!(
            "refusing to replace symlink: {}",
            target.display()
        )));
    }

    let temp = temp_install_path(target)?;
    remove_file_if_exists(&temp)?;
    fs::write(&temp, data)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(mode))?;
    fs::rename(&temp, target)?;
    Ok(())
}

fn atomic_copy_file(source: &Path, target: &Path, mode: u32) -> Result<()> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    reject_symlink_parents(target)?;
    if target
        .symlink_metadata()
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(AppError::BadRequest(format!(
            "refusing to replace symlink: {}",
            target.display()
        )));
    }

    let temp = temp_install_path(target)?;
    remove_file_if_exists(&temp)?;
    fs::copy(source, &temp)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(mode))?;
    fs::rename(&temp, target)?;
    Ok(())
}

fn validate_system_extract_root(extract_dir: &Path) -> Result<()> {
    let manifest = extract_dir.join("manifest.json");
    let payload = extract_dir.join("payload");
    if !manifest.is_file() || !payload.is_dir() {
        return Err(AppError::BadRequest(
            "system update archive must contain manifest.json and payload/".to_string(),
        ));
    }

    for entry in fs::read_dir(extract_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let metadata = entry.metadata()?;
        match name.as_ref() {
            "manifest.json" if metadata.is_file() => {}
            "payload" if metadata.is_dir() => {}
            _ => {
                return Err(AppError::BadRequest(
                    "system update archive contains unsupported top-level entries".to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn validate_system_manifest(
    manifest: &SystemManifest,
    latest: &SystemLatest,
    payload_dir: &Path,
) -> Result<()> {
    validate_manifest_shape(manifest, latest)?;

    if !payload_dir.is_dir() {
        return Err(AppError::BadRequest(
            "system update payload directory is missing".to_string(),
        ));
    }

    let mut listed = BTreeSet::new();
    let mut total_size = 0_u64;
    for file in &manifest.files {
        validate_payload_path(&file.payload)?;
        validate_install_path(&file.install, &file.payload)?;
        validate_sha256_hex(&file.sha256)?;

        let payload_path = safe_payload_join(payload_dir, &file.payload)?;
        if !payload_path.is_file() {
            return Err(AppError::BadRequest(format!(
                "system update payload is missing {}",
                file.payload
            )));
        }

        let metadata = fs::metadata(&payload_path)?;
        if metadata.len() != file.size {
            return Err(AppError::BadRequest(format!(
                "system update payload size mismatch: {}",
                file.payload
            )));
        }
        let actual = hash_file(&payload_path)?.sha256;
        if !actual.eq_ignore_ascii_case(&file.sha256) {
            return Err(AppError::BadRequest(format!(
                "system update payload checksum mismatch: {}",
                file.payload
            )));
        }

        if !listed.insert(file.payload.clone()) {
            return Err(AppError::BadRequest(format!(
                "duplicate system update payload entry: {}",
                file.payload
            )));
        }
        total_size = total_size.saturating_add(file.size);
        if total_size > MAX_SYSTEM_UPDATE_BYTES {
            return Err(AppError::BadRequest(
                "system update payload is too large".to_string(),
            ));
        }
    }

    let actual_files = collect_regular_payload_files(payload_dir)?;
    if listed != actual_files {
        return Err(AppError::BadRequest(
            "system update manifest does not match payload contents".to_string(),
        ));
    }

    Ok(())
}

fn validate_manifest_shape(manifest: &SystemManifest, latest: &SystemLatest) -> Result<()> {
    if manifest.format != "hardened-nanokvm-system-update-v1" {
        return Err(AppError::BadRequest(
            "unsupported system update manifest format".to_string(),
        ));
    }
    if manifest.version != latest.version {
        return Err(AppError::BadRequest(
            "system update manifest version mismatch".to_string(),
        ));
    }
    if manifest.target != latest.target {
        return Err(AppError::BadRequest(
            "system update manifest target mismatch".to_string(),
        ));
    }
    validate_token("manifest version", &manifest.version)?;
    validate_token("manifest target", &manifest.target)?;
    validate_text_field("base_version", &manifest.base_version, 128)?;
    validate_text_field("kernel_version", &manifest.kernel_version, 128)?;
    validate_text_field("source_commit", &manifest.source_commit, 64)?;
    validate_text_field("created_utc", &manifest.created_utc, 64)?;

    if manifest.required_free_bytes > 8 * 1024 * 1024 * 1024 {
        return Err(AppError::BadRequest(
            "system update required_free_bytes is too large".to_string(),
        ));
    }
    if manifest.files.is_empty() {
        return Err(AppError::BadRequest(
            "system update manifest has no files".to_string(),
        ));
    }
    if manifest.operations.is_empty() {
        return Err(AppError::BadRequest(
            "system update manifest has no operations".to_string(),
        ));
    }

    Ok(())
}

fn system_stage_dir(cache_dir: &Path) -> PathBuf {
    cache_dir.join(SYSTEM_STAGE_DIR_NAME)
}

fn prepare_stage_dir(stage_dir: &Path) -> Result<()> {
    if stage_dir == Path::new("/") || stage_dir.as_os_str().is_empty() {
        return Err(AppError::Config(
            "invalid system update staging directory".to_string(),
        ));
    }
    remove_dir_if_exists(stage_dir)?;
    fs::create_dir_all(stage_dir)?;
    Ok(())
}

fn acquire_update_lock() -> Result<UpdateGuard> {
    let mut is_updating = SYSTEM_UPDATE_LOCK
        .lock()
        .map_err(|_| AppError::Internal("system update lock poisoned".to_string()))?;
    if *is_updating {
        return Err(AppError::Conflict(
            "system update already in progress".to_string(),
        ));
    }
    *is_updating = true;
    Ok(UpdateGuard)
}

fn write_stage_record(stage_dir: &Path, record: &SystemStageRecord) -> Result<()> {
    let data = serde_json::to_vec_pretty(record)
        .map_err(|err| AppError::Internal(format!("encode staged system update: {err}")))?;
    fs::write(stage_dir.join(SYSTEM_STAGE_RECORD), data)?;
    Ok(())
}

fn staged_summary(record: &SystemStageRecord) -> SystemStagedUpdate {
    SystemStagedUpdate {
        version: record.latest.version.clone(),
        target: record.latest.target.clone(),
        channel: record.latest.channel.clone(),
        archive_name: record.latest.name.clone(),
        size: record.latest.size,
        sha256: record.latest.sha256.clone(),
        staged_at: record.staged_at,
        base_version: record.manifest.base_version.clone(),
        kernel_version: record.manifest.kernel_version.clone(),
        required_free_bytes: record.manifest.required_free_bytes,
        requires_reboot: record.manifest.requires_reboot,
        file_count: record.manifest.files.len(),
    }
}

fn validate_payload_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path == "."
        || path == ".."
        || path.starts_with("../")
        || path.contains("/../")
        || path.contains("//")
        || path.ends_with('/')
        || path.ends_with("/..")
        || !(path.starts_with("boot/") || path.starts_with("rootfs/"))
        || !path.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | '/' | '@' | '=' | '-')
        })
    {
        return Err(AppError::BadRequest(
            "invalid system update payload path".to_string(),
        ));
    }
    Ok(())
}

fn validate_install_path(install: &str, payload: &str) -> Result<()> {
    let expected = install_path_for_payload(payload)?;
    if install != expected {
        return Err(AppError::BadRequest(format!(
            "system update install path mismatch for {payload}"
        )));
    }
    Ok(())
}

fn install_path_for_payload(payload: &str) -> Result<String> {
    if let Some(path) = payload.strip_prefix("boot/") {
        if path.is_empty() {
            return Err(AppError::BadRequest(
                "invalid system update payload path".to_string(),
            ));
        }
        Ok(format!("/boot/{path}"))
    } else if let Some(path) = payload.strip_prefix("rootfs/") {
        if path.is_empty() {
            return Err(AppError::BadRequest(
                "invalid system update payload path".to_string(),
            ));
        }
        Ok(format!("/{path}"))
    } else {
        Err(AppError::BadRequest(
            "invalid system update payload path".to_string(),
        ))
    }
}

fn safe_payload_join(payload_dir: &Path, relative: &str) -> Result<PathBuf> {
    validate_payload_path(relative)?;
    let target = payload_dir.join(relative);
    if !target.starts_with(payload_dir) {
        return Err(AppError::BadRequest(
            "system update payload path escapes staging directory".to_string(),
        ));
    }
    Ok(target)
}

fn collect_regular_payload_files(payload_dir: &Path) -> Result<BTreeSet<String>> {
    let mut files = BTreeSet::new();
    collect_regular_payload_files_inner(payload_dir, payload_dir, &mut files)?;
    Ok(files)
}

fn collect_regular_payload_files_inner(
    root: &Path,
    dir: &Path,
    files: &mut BTreeSet<String>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_regular_payload_files_inner(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| AppError::Internal("payload path escaped root".to_string()))?;
            let relative = relative
                .to_str()
                .ok_or_else(|| AppError::BadRequest("payload path is not UTF-8".to_string()))?
                .replace('\\', "/");
            validate_payload_path(&relative)?;
            files.insert(relative);
        } else {
            return Err(AppError::BadRequest(
                "unsupported file type in system update payload".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_sha256_hex(value: &str) -> Result<()> {
    if !value.chars().all(|ch| ch.is_ascii_hexdigit()) || value.len() != 64 {
        return Err(AppError::BadRequest(
            "invalid system update sha256".to_string(),
        ));
    }
    Ok(())
}

fn validate_text_field(name: &str, value: &str, max_len: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > max_len
        || value
            .chars()
            .any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
    {
        return Err(AppError::BadRequest(format!(
            "invalid system update manifest {name}"
        )));
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<FileHashes> {
    let mut file = fs::File::open(path)?;
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut buf = [0_u8; 64 * 1024];

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha256.update(&buf[..n]);
        sha512.update(&buf[..n]);
    }

    Ok(FileHashes {
        sha256: format!("{:x}", sha256.finalize()),
        sha512: STANDARD.encode(sha512.finalize()),
    })
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| AppError::BadRequest("path is not valid UTF-8".to_string()))
}

fn temp_verify_path(kind: &str) -> Result<PathBuf> {
    validate_token("temporary file kind", kind)?;
    Ok(PathBuf::from(format!(
        "/tmp/hardened-system-update-{}-{}-{kind}.tmp",
        std::process::id(),
        now_unix_nanos()
    )))
}

fn write_verify_temp_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn remove_dir_if_exists(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn read_stage_record(stage_dir: &Path) -> Result<Option<SystemStageRecord>> {
    let record_path = stage_dir.join(SYSTEM_STAGE_RECORD);
    if !record_path.exists() {
        return Ok(None);
    }
    let raw = fs::read(record_path)?;
    let record: SystemStageRecord = serde_json::from_slice(&raw)
        .map_err(|err| AppError::Internal(format!("invalid staged system update: {err}")))?;
    validate_latest_system(&record.latest)?;
    validate_manifest_shape(&record.manifest, &record.latest)?;
    Ok(Some(record))
}

fn read_pending_update() -> Result<Option<SystemPendingUpdate>> {
    let path = Path::new(SYSTEM_PENDING_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path)?;
    let pending: SystemPendingUpdate = serde_json::from_slice(&raw)
        .map_err(|err| AppError::Internal(format!("invalid pending system update: {err}")))?;
    validate_token("pending version", &pending.version)?;
    validate_token("pending target", &pending.target)?;
    validate_filename(&pending.backup_id)?;
    Ok(Some(pending))
}

fn read_last_backup_record(stage_dir: &Path) -> Result<Option<SystemInstallRecord>> {
    let marker = Path::new(SYSTEM_LAST_BACKUP_FILE);
    if !marker.exists() {
        return Ok(None);
    }

    let raw = fs::read(marker)?;
    let record: SystemInstallRecord = serde_json::from_slice(&raw)
        .map_err(|err| AppError::Internal(format!("invalid system update backup marker: {err}")))?;
    validate_install_record(&record)?;

    let backup_record = backup_dir_for(stage_dir, &record.backup_id).join(SYSTEM_BACKUP_RECORD);
    if !backup_record.is_file() {
        return Ok(None);
    }

    Ok(Some(record))
}

fn validate_install_record(record: &SystemInstallRecord) -> Result<()> {
    validate_token("backup version", &record.version)?;
    validate_token("backup target", &record.target)?;
    validate_filename(&record.backup_id)?;
    if record.files.is_empty() {
        return Err(AppError::BadRequest(
            "system update backup record has no files".to_string(),
        ));
    }
    for file in &record.files {
        validate_absolute_install_path(&file.install)?;
        validate_backup_relative(&file.backup)?;
    }
    Ok(())
}

fn write_pending_update(pending: &SystemPendingUpdate) -> Result<()> {
    let data = serde_json::to_vec_pretty(pending)
        .map_err(|err| AppError::Internal(format!("encode pending system update: {err}")))?;
    atomic_write_file(Path::new(SYSTEM_PENDING_FILE), &data, 0o644)
}

fn write_boot_good(pending: &SystemPendingUpdate, health: &SystemBootHealth) -> Result<()> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct BootGood<'a> {
        confirmed_at: u64,
        pending: &'a SystemPendingUpdate,
        health: &'a SystemBootHealth,
    }

    let data = serde_json::to_vec_pretty(&BootGood {
        confirmed_at: now_unix_seconds(),
        pending,
        health,
    })
    .map_err(|err| AppError::Internal(format!("encode system update boot-good marker: {err}")))?;
    atomic_write_file(Path::new(SYSTEM_BOOT_GOOD_FILE), &data, 0o644)
}

fn evaluate_boot_health(
    current: &SystemVersion,
    pending: &SystemPendingUpdate,
    state: &AppState,
) -> SystemBootHealth {
    let version_matches_pending =
        current.version == pending.version && current.target == pending.target;
    let boot_marker_present = Path::new(BOOT_VERSION_FILE).is_file();
    let web_root_present = state.config.paths.web_root.join("index.html").is_file();
    let backend_running = true;
    let healthy =
        backend_running && version_matches_pending && boot_marker_present && web_root_present;

    SystemBootHealth {
        backend_running,
        version_matches_pending,
        boot_marker_present,
        web_root_present,
        healthy,
    }
}

fn write_last_backup_record(record: &SystemInstallRecord) -> Result<()> {
    let data = serde_json::to_vec_pretty(record)
        .map_err(|err| AppError::Internal(format!("encode system update backup marker: {err}")))?;
    atomic_write_file(Path::new(SYSTEM_LAST_BACKUP_FILE), &data, 0o600)
}

fn write_rollback_script(stage_dir: &Path, record: &SystemInstallRecord) -> Result<()> {
    let script = rollback_script_for_record(stage_dir, record)?;
    atomic_write_file(
        Path::new(SYSTEM_ROLLBACK_SCRIPT_FILE),
        script.as_bytes(),
        0o700,
    )
}

fn rollback_script_for_record(stage_dir: &Path, record: &SystemInstallRecord) -> Result<String> {
    validate_install_record(record)?;
    let backup_dir = backup_dir_for(stage_dir, &record.backup_id);
    let mut script = String::from(
        "#!/bin/sh\n\
set -eu\n\
LOG=/tmp/system-update-watchdog.log\n\
echo \"$(date '+%Y-%m-%d %H:%M:%S') automatic system-update rollback started\" >> \"$LOG\"\n",
    );

    for file in record.files.iter().rev() {
        let install = validate_absolute_install_path(&file.install)?;
        let install_parent = install.parent().ok_or_else(|| {
            AppError::Internal("system update install path has no parent".to_string())
        })?;
        script.push_str(&format!("mkdir -p {}\n", shell_quote_path(install_parent)?));
        if file.existed {
            let backup = safe_backup_join(&backup_dir, &file.backup)?;
            if !backup.is_file() {
                return Err(AppError::Internal(format!(
                    "system update backup file is missing: {}",
                    file.backup
                )));
            }
            script.push_str(&format!(
                "cp -p {} {}\n",
                shell_quote_path(&backup)?,
                shell_quote_path(&install)?
            ));
        } else {
            script.push_str(&format!("rm -f {}\n", shell_quote_path(&install)?));
        }
    }

    script.push_str(&format!(
        "rm -f {} {} {}\n\
sync\n\
echo \"$(date '+%Y-%m-%d %H:%M:%S') automatic system-update rollback finished\" >> \"$LOG\"\n",
        shell_quote_path(Path::new(SYSTEM_PENDING_FILE))?,
        shell_quote_path(Path::new(SYSTEM_BOOT_GOOD_FILE))?,
        shell_quote_path(Path::new(SYSTEM_ROLLBACK_SCRIPT_FILE))?,
    ));

    Ok(script)
}

fn shell_quote_path(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| AppError::BadRequest("path is not valid UTF-8".to_string()))?;
    Ok(format!("'{}'", value.replace('\'', "'\"'\"'")))
}

fn write_backup_record(backup_dir: &Path, record: &SystemInstallRecord) -> Result<()> {
    let data = serde_json::to_vec_pretty(record)
        .map_err(|err| AppError::Internal(format!("encode system update backup: {err}")))?;
    fs::write(backup_dir.join(SYSTEM_BACKUP_RECORD), data)?;
    Ok(())
}

fn pending_update(record: &SystemInstallRecord) -> SystemPendingUpdate {
    SystemPendingUpdate {
        version: record.version.clone(),
        target: record.target.clone(),
        backup_id: record.backup_id.clone(),
        installed_at: record.installed_at,
        requires_reboot: record.requires_reboot,
        file_count: record.files.len(),
    }
}

fn rollback_info(record: &SystemInstallRecord) -> SystemRollbackInfo {
    SystemRollbackInfo {
        version: record.version.clone(),
        target: record.target.clone(),
        backup_id: record.backup_id.clone(),
        installed_at: record.installed_at,
        file_count: record.files.len(),
        requires_reboot: record.requires_reboot,
    }
}

fn backup_dir_for(stage_dir: &Path, backup_id: &str) -> PathBuf {
    stage_dir.join(SYSTEM_BACKUPS_DIR_NAME).join(backup_id)
}

fn validate_absolute_install_path(install: &str) -> Result<PathBuf> {
    if install.is_empty()
        || !install.starts_with('/')
        || install == "/"
        || install.contains('\\')
        || install.contains("//")
        || install.contains("/../")
        || install.ends_with("/..")
        || install.ends_with('/')
        || install.chars().any(|ch| ch.is_control())
        || install.starts_with("/proc/")
        || install.starts_with("/sys/")
        || install.starts_with("/dev/")
        || install.starts_with("/run/")
        || install.starts_with("/tmp/")
        || install.starts_with("/data/")
        || install.starts_with("/kvmapp/")
        || install.starts_with("/root/.kvmcache/")
    {
        return Err(AppError::BadRequest(format!(
            "invalid system update install path: {install}"
        )));
    }
    Ok(PathBuf::from(install))
}

fn backup_relative_for_install(install: &str) -> Result<String> {
    validate_absolute_install_path(install)?;
    Ok(install.trim_start_matches('/').to_string())
}

fn validate_backup_relative(path: &str) -> Result<()> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains("//")
        || path == "."
        || path == ".."
        || path.starts_with("../")
        || path.contains("/../")
        || path.ends_with("/..")
        || path.ends_with('/')
        || path.chars().any(|ch| ch.is_control())
    {
        return Err(AppError::BadRequest(
            "invalid system update backup path".to_string(),
        ));
    }
    Ok(())
}

fn safe_backup_join(backup_dir: &Path, relative: &str) -> Result<PathBuf> {
    validate_backup_relative(relative)?;
    let target = backup_dir.join(relative);
    if !target.starts_with(backup_dir) {
        return Err(AppError::BadRequest(
            "system update backup path escapes backup directory".to_string(),
        ));
    }
    Ok(target)
}

fn reject_symlink_parents(target: &Path) -> Result<()> {
    let mut current = target.parent();
    while let Some(path) = current {
        if path == Path::new("/") {
            return Ok(());
        }
        if fs::symlink_metadata(path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(AppError::BadRequest(format!(
                "refusing to install through symlink parent: {}",
                path.display()
            )));
        }
        current = path.parent();
    }
    Ok(())
}

fn temp_install_path(target: &Path) -> Result<PathBuf> {
    let parent = target
        .parent()
        .ok_or_else(|| AppError::BadRequest("install path has no parent".to_string()))?;
    let filename = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AppError::BadRequest("install filename is not UTF-8".to_string()))?;
    Ok(parent.join(format!(
        ".hardened-system-update.{}.{}.tmp",
        std::process::id(),
        filename
    )))
}

fn install_file_mode(install: &str) -> u32 {
    if install.starts_with("/etc/init.d/") || install.starts_with("/usr/bin/") {
        0o755
    } else {
        0o644
    }
}

fn backup_file_mode(path: &Path) -> Result<u32> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
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

    fn valid_latest() -> SystemLatest {
        SystemLatest {
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
            signature_algorithm: SYSTEM_UPDATE_SIGNATURE_ALGORITHM.to_string(),
            signature_key_id: "hardened-system-test".to_string(),
        }
    }

    fn valid_manifest(file: SystemManifestFile) -> SystemManifest {
        SystemManifest {
            format: "hardened-nanokvm-system-update-v1".to_string(),
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            base_version: "2025-02-17-19-08-3649fe.img".to_string(),
            kernel_version: "5.10.4-tag-".to_string(),
            source_commit: "abcdef1".to_string(),
            created_utc: "2026-06-28T00:00:00Z".to_string(),
            required_free_bytes: 67_108_864,
            requires_reboot: true,
            operations: vec![
                "backup".to_string(),
                "stage".to_string(),
                "install-known-paths".to_string(),
            ],
            files: vec![file],
        }
    }

    #[test]
    fn validates_system_latest_metadata() {
        let latest = valid_latest();

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
            signature_algorithm: SYSTEM_UPDATE_SIGNATURE_ALGORITHM.to_string(),
            signature_key_id: "hardened-system-test".to_string(),
        };

        assert!(validate_latest_system(&latest).is_err());
    }

    #[test]
    fn rejects_system_update_url_name_mismatch() {
        let mut latest = valid_latest();
        latest.url = "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-0.1.0/hardened-nanokvm-system-other.tar.gz".to_string();

        assert!(validate_latest_system(&latest).is_err());
    }

    #[test]
    fn accepts_unsigned_system_metadata_marker_shape() {
        let mut latest = valid_latest();
        latest.signature_algorithm = SYSTEM_UPDATE_UNSIGNED_ALGORITHM.to_string();
        latest.signature_key_id = SYSTEM_UPDATE_UNSIGNED_ALGORITHM.to_string();

        validate_latest_system(&latest).unwrap();
        assert!(system_metadata_is_unsigned(&latest));
    }

    #[test]
    fn rejects_partial_unsigned_system_metadata_marker() {
        let mut latest = valid_latest();
        latest.signature_algorithm = SYSTEM_UPDATE_UNSIGNED_ALGORITHM.to_string();
        latest.signature_key_id = "hardened-system-test".to_string();

        assert!(validate_latest_system(&latest).is_err());
    }

    #[test]
    fn builds_metadata_signature_url_from_metadata_url() {
        let url = "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-stable/system-latest.json";

        assert_eq!(
            metadata_signature_url(url).unwrap(),
            "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-stable/system-latest.json.sig"
        );
    }

    #[test]
    fn parses_script_generated_system_latest_metadata() {
        let raw = r#"{
  "kind": "hardened-nanokvm-system-update",
  "format": 1,
  "channel": "stable",
  "version": "0.1.0",
  "target": "sg2002-licheervnano-sd",
  "name": "hardened-nanokvm-system-0.1.0.tar.gz",
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "sha512": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ==",
  "size": 1024,
  "url": "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-0.1.0/hardened-nanokvm-system-0.1.0.tar.gz",
  "release_notes_url": "https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-0.1.0",
  "signature_algorithm": "sha256-rsa-pkcs1-v1_5",
  "signature_key_id": "hardened-system-test"
}"#;

        let latest: SystemLatest = serde_json::from_str(raw).unwrap();
        validate_latest_system(&latest).unwrap();
    }

    #[test]
    fn validates_manifest_payload_tree() {
        let temp = tempfile::tempdir().unwrap();
        let payload_dir = temp.path().join("payload");
        let file = payload_dir.join("boot/boot.sd");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"boot image").unwrap();
        let hashes = hash_file(&file).unwrap();

        let manifest = valid_manifest(SystemManifestFile {
            payload: "boot/boot.sd".to_string(),
            install: "/boot/boot.sd".to_string(),
            size: fs::metadata(&file).unwrap().len(),
            sha256: hashes.sha256,
        });

        validate_system_manifest(&manifest, &valid_latest(), &payload_dir).unwrap();
    }

    #[test]
    fn rejects_manifest_payload_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let payload_dir = temp.path().join("payload");
        let file = payload_dir.join("boot/boot.sd");
        let extra = payload_dir.join("rootfs/etc/system-version.json");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::create_dir_all(extra.parent().unwrap()).unwrap();
        fs::write(&file, b"boot image").unwrap();
        fs::write(extra, b"{}").unwrap();
        let hashes = hash_file(&file).unwrap();

        let manifest = valid_manifest(SystemManifestFile {
            payload: "boot/boot.sd".to_string(),
            install: "/boot/boot.sd".to_string(),
            size: fs::metadata(&file).unwrap().len(),
            sha256: hashes.sha256,
        });

        assert!(validate_system_manifest(&manifest, &valid_latest(), &payload_dir).is_err());
    }

    #[test]
    fn rejects_unsafe_install_paths() {
        assert!(validate_absolute_install_path("/boot/boot.sd").is_ok());
        assert!(validate_absolute_install_path("/etc/kvm/system-version.json").is_ok());
        assert!(validate_absolute_install_path("/proc/version").is_err());
        assert!(validate_absolute_install_path("/dev/null").is_err());
        assert!(validate_absolute_install_path("/kvmapp/server/NanoKVM-Server").is_err());
        assert!(
            validate_absolute_install_path("/root/.kvmcache/system-update/staged.json").is_err()
        );
        assert!(validate_absolute_install_path("/etc/../passwd").is_err());
    }

    #[test]
    fn rollback_script_restores_files_in_reverse_order() {
        let temp = tempfile::tempdir().unwrap();
        let stage_dir = temp.path().join("system-update");
        let backup_dir = stage_dir.join("backups/0.1.0-123/etc");
        fs::create_dir_all(&backup_dir).unwrap();
        fs::write(backup_dir.join("config"), b"old config").unwrap();

        let record = SystemInstallRecord {
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            backup_id: "0.1.0-123".to_string(),
            installed_at: 123,
            requires_reboot: true,
            files: vec![
                SystemBackupFile {
                    install: "/etc/config".to_string(),
                    backup: "etc/config".to_string(),
                    existed: true,
                },
                SystemBackupFile {
                    install: "/boot/new.bin".to_string(),
                    backup: "boot/new.bin".to_string(),
                    existed: false,
                },
            ],
        };

        let script = rollback_script_for_record(&stage_dir, &record).unwrap();
        let remove_new = script.find("rm -f '/boot/new.bin'").unwrap();
        let restore_config = script.find("cp -p ").unwrap();

        assert!(remove_new < restore_config);
        assert!(script.contains("'/etc/kvm/system-update-pending.json'"));
        assert!(script.contains("'/etc/kvm/system-update-rollback.sh'"));
    }

    #[test]
    fn rollback_script_rejects_missing_backup_file() {
        let temp = tempfile::tempdir().unwrap();
        let record = SystemInstallRecord {
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            backup_id: "0.1.0-123".to_string(),
            installed_at: 123,
            requires_reboot: true,
            files: vec![SystemBackupFile {
                install: "/etc/config".to_string(),
                backup: "etc/config".to_string(),
                existed: true,
            }],
        };

        assert!(rollback_script_for_record(temp.path(), &record).is_err());
    }
}
