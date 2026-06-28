use axum::{Json, extract::State, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    AppError, Result,
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
const MAX_SYSTEM_UPDATE_BYTES: u64 = 256 * 1024 * 1024;
const METADATA_TIMEOUT: Duration = Duration::from_secs(45);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const SYSTEM_STAGE_DIR_NAME: &str = "system-update";
const SYSTEM_EXTRACT_DIR_NAME: &str = "extract";
const SYSTEM_STAGE_RECORD: &str = "staged.json";

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
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemDownloadRsp {
    pub current: SystemVersion,
    pub latest: SystemLatest,
    pub staged: SystemStagedUpdate,
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

pub async fn status(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let current = read_current_system_version();
    let stage_dir = system_stage_dir(&state.config.paths.update_cache_dir);

    match read_staged_update(&stage_dir) {
        Ok(staged) => Ok(Json(ApiResponse::ok(SystemStatusRsp {
            current,
            staged,
            error: None,
        }))),
        Err(err) => {
            tracing::warn!(error = %err, "failed to read staged system update");
            Ok(Json(ApiResponse::ok(SystemStatusRsp {
                current,
                staged: None,
                error: Some(err.to_string()),
            })))
        }
    }
}

pub async fn download(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let _guard = acquire_update_lock()?;
    let current = read_current_system_version();
    let latest = get_latest_system(false).await?;

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
}
