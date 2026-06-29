use axum::{
    Json,
    extract::{Multipart, State},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::{
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{LazyLock, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{fs as tokio_fs, io::AsyncWriteExt, time};

use crate::{
    AppError, Result,
    error::ApiResponse,
    state::AppState,
    system::command::{AllowedCommand, CommandOutput, run_allowed},
    update::archive::extract_tar_gz_safe,
};

const APP_DIR: &str = "/kvmapp";
const BACKUP_DIR: &str = "/root/old";
const APP_VERSION_FILE: &str = "/kvmapp/version";
const DEFAULT_APP_VERSION: &str = "0.1.0";
const PREVIEW_UPDATES_FLAG: &str = "/etc/kvm/preview_updates";
const GITHUB_RELEASE_LATEST_JSON: &str =
    "https://github.com/woffko/Hardened_NanoKVM/releases/latest/download/latest.json";
const GITHUB_PREVIEW_LATEST_JSON: &str = "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-rust-preview/latest.json";
const GITHUB_RELEASE_DOWNLOAD_PREFIX: &str =
    "https://github.com/woffko/Hardened_NanoKVM/releases/download/";
const MAX_UPDATE_BYTES: u64 = 128 * 1024 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const METADATA_TIMEOUT: Duration = Duration::from_secs(45);
const APPLICATION_UPDATE_CACHE_DIR_NAME: &str = "application-update";
const APP_UPDATE_SIGNATURE_ALGORITHM: &str = "sha256-rsa-pkcs1-v1_5";
const APP_UPDATE_UNSIGNED_ALGORITHM: &str = "unsigned";

static UPDATE_LOCK: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(false));

#[derive(Debug, Serialize)]
pub struct VersionRsp {
    pub current: String,
    pub latest: String,
}

#[derive(Debug, Serialize)]
pub struct PreviewRsp {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetPreviewReq {
    pub enable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LatestRelease {
    version: String,
    name: String,
    sha512: String,
    size: u64,
    url: String,
    #[serde(default)]
    signature_algorithm: String,
    #[serde(default)]
    signature_key_id: String,
}

struct UpdateGuard;

impl Drop for UpdateGuard {
    fn drop(&mut self) {
        if let Ok(mut is_updating) = UPDATE_LOCK.lock() {
            *is_updating = false;
        }
    }
}

pub async fn get_version(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let latest = match get_latest(is_preview_enabled(), &state.config).await {
        Ok(latest) => latest.version,
        Err(err) => {
            tracing::warn!(error = %err, "failed to query latest application release");
            String::new()
        }
    };

    Ok(Json(ApiResponse::ok(VersionRsp {
        current: read_trimmed(APP_VERSION_FILE).unwrap_or_else(|| DEFAULT_APP_VERSION.to_string()),
        latest,
    })))
}

pub async fn get_preview() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(PreviewRsp {
        enabled: is_preview_enabled(),
    })))
}

pub async fn set_preview(Json(req): Json<SetPreviewReq>) -> Result<impl IntoResponse> {
    let is_enabled = is_preview_enabled();
    if req.enable == is_enabled {
        return Ok(Json(ApiResponse::<()>::ok_empty()));
    }

    if req.enable {
        fs::write(PREVIEW_UPDATES_FLAG, b"1")?;
    } else {
        match fs::remove_file(PREVIEW_UPDATES_FLAG) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn update(State(state): State<AppState>) -> Result<Json<ApiResponse<()>>> {
    let _guard = acquire_update_lock()?;
    let cache_dir = application_update_cache_dir(&state.config.paths.update_cache_dir);

    prepare_cache_dir(&cache_dir)?;
    let latest = get_latest(is_preview_enabled(), &state.config).await?;
    let archive = cache_dir.join(&latest.name);
    download_release_asset(&latest, &archive).await?;
    verify_sha512(&archive, &latest.sha512)?;

    install_package_blocking(archive, cache_dir.clone()).await?;
    let _ = remove_dir_if_exists(&cache_dir);
    restart_nanokvm_after_response();

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn offline_update(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<ApiResponse<()>>> {
    let _guard = acquire_update_lock()?;
    let cache_dir = application_update_cache_dir(&state.config.paths.update_cache_dir);

    prepare_cache_dir(&cache_dir)?;
    let archive = save_uploaded_update(&cache_dir, &mut multipart).await?;

    install_package_blocking(archive, cache_dir.clone()).await?;
    let _ = remove_dir_if_exists(&cache_dir);
    restart_nanokvm_after_response();

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

async fn get_latest(preview: bool, config: &crate::config::Config) -> Result<LatestRelease> {
    if preview {
        match fetch_latest(GITHUB_PREVIEW_LATEST_JSON, config).await {
            Ok(preview_latest) => match fetch_latest(GITHUB_RELEASE_LATEST_JSON, config).await {
                Ok(stable_latest) => return Ok(newer_release(preview_latest, stable_latest)),
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "failed to query stable release metadata, using preview"
                    );
                    return Ok(preview_latest);
                }
            },
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to query preview release metadata, falling back to stable"
                );
            }
        }
    }

    fetch_latest(GITHUB_RELEASE_LATEST_JSON, config).await
}

fn newer_release(left: LatestRelease, right: LatestRelease) -> LatestRelease {
    match compare_application_versions(&left.version, &right.version) {
        Some(std::cmp::Ordering::Less) => right,
        _ => left,
    }
}

fn compare_application_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    let left = parse_application_version(left)?;
    let right = parse_application_version(right)?;
    Some(left.cmp(&right))
}

fn parse_application_version(version: &str) -> Option<[u64; 3]> {
    let mut parts = version.split('.');
    let parsed = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    if parts.next().is_some() {
        return None;
    }
    Some(parsed)
}

async fn fetch_latest(url: &str, config: &crate::config::Config) -> Result<LatestRelease> {
    validate_metadata_url(url)?;
    let metadata = fetch_latest_metadata(url).await?;
    let latest: LatestRelease = serde_json::from_slice(&metadata)
        .map_err(|err| AppError::Internal(format!("invalid latest.json: {err}")))?;
    validate_latest_release(&latest)?;
    enforce_app_metadata_signature(url, &metadata, &latest, config).await?;
    Ok(latest)
}

async fn fetch_latest_metadata(url: &str) -> Result<Vec<u8>> {
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
    ensure_success(&output, "query latest release metadata")?;
    Ok(output.stdout)
}

async fn download_release_asset(latest: &LatestRelease, target: &Path) -> Result<()> {
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
    ensure_success(&output, "download update archive")?;

    let size = fs::metadata(target)?.len();
    if size == 0 || size > MAX_UPDATE_BYTES {
        return Err(AppError::BadRequest(
            "invalid update archive size".to_string(),
        ));
    }
    if latest.size != 0 && size != latest.size {
        return Err(AppError::BadRequest(format!(
            "update archive size mismatch: got {size}, expected {}",
            latest.size
        )));
    }

    Ok(())
}

async fn save_uploaded_update(cache_dir: &Path, multipart: &mut Multipart) -> Result<PathBuf> {
    let mut archive = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid multipart data: {err}")))?
    {
        if field.name() != Some("file") {
            continue;
        }

        let filename = field
            .file_name()
            .map(str::to_string)
            .ok_or_else(|| AppError::BadRequest("missing update filename".to_string()))?;
        validate_update_filename(&filename)?;

        let target = cache_dir.join(&filename);
        let mut file = tokio_fs::File::create(&target).await?;
        let mut written = 0_u64;

        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|err| AppError::BadRequest(format!("invalid multipart data: {err}")))?
        {
            written = written.saturating_add(chunk.len() as u64);
            if written > MAX_UPDATE_BYTES {
                return Err(AppError::BadRequest(
                    "update archive is too large".to_string(),
                ));
            }
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;

        if written == 0 {
            return Err(AppError::BadRequest("empty update archive".to_string()));
        }
        archive = Some(target);
    }

    archive.ok_or_else(|| AppError::BadRequest("no update file uploaded".to_string()))
}

async fn install_package_blocking(archive: PathBuf, cache_dir: PathBuf) -> Result<()> {
    tokio::task::spawn_blocking(move || install_package(&archive, &cache_dir))
        .await
        .map_err(|err| AppError::Internal(format!("update task failed: {err}")))?
}

fn install_package(source: &Path, cache_dir: &Path) -> Result<()> {
    let extract_dir = cache_dir.join("extract");
    remove_dir_if_exists(&extract_dir)?;
    fs::create_dir_all(&extract_dir)?;

    let extracted = extract_tar_gz_safe(source, &extract_dir)?;
    let update_root = resolve_update_root(&extracted)?;
    validate_update_root(&update_root)?;

    let app_dir = Path::new(APP_DIR);
    let backup_dir = Path::new(BACKUP_DIR);
    remove_dir_if_exists(backup_dir)?;
    if app_dir.exists() {
        move_path(app_dir, backup_dir)?;
    }

    if let Err(err) = move_path(&update_root, app_dir) {
        tracing::error!(error = %err, "failed to move update into place");
        if let Err(restore_err) = restore_backup(app_dir, backup_dir) {
            tracing::error!(error = %restore_err, "failed to restore old kvmapp after update error");
        }
        return Err(AppError::Internal(format!("failed to apply update: {err}")));
    }

    chmod_recursively(app_dir, 0o755)?;
    Ok(())
}

fn resolve_update_root(extracted: &Path) -> Result<PathBuf> {
    if extracted.file_name() == Some(OsStr::new("kvmapp")) {
        return Ok(extracted.to_path_buf());
    }

    let nested = extracted.join("kvmapp");
    if nested.is_dir() {
        return Ok(nested);
    }

    Err(AppError::BadRequest(
        "update archive does not contain kvmapp".to_string(),
    ))
}

fn validate_update_root(root: &Path) -> Result<()> {
    for relative in [
        "server/NanoKVM-Server",
        "system/init.d/S95nanokvm",
        "backends/NanoKVM-Server.rust",
    ] {
        let path = root.join(relative);
        if !path.is_file() {
            return Err(AppError::BadRequest(format!(
                "update archive is missing {relative}"
            )));
        }
    }
    for relative in [
        "backends/NanoKVM-Server.go",
        "server/NanoKVM-Server.go",
        "server/NanoKVM-Server.go.bak",
    ] {
        if root.join(relative).exists() {
            return Err(AppError::BadRequest(format!(
                "update archive contains forbidden legacy Go backend file: {relative}"
            )));
        }
    }
    validate_update_tree_has_no_symlinks(root)?;
    Ok(())
}

fn validate_latest_release(latest: &LatestRelease) -> Result<()> {
    validate_version(&latest.version)?;
    validate_update_filename(&latest.name)?;
    validate_sha512(&latest.sha512)?;

    if latest.size == 0 || latest.size > MAX_UPDATE_BYTES {
        return Err(AppError::BadRequest(
            "invalid release archive size".to_string(),
        ));
    }
    if !latest.url.starts_with(GITHUB_RELEASE_DOWNLOAD_PREFIX) {
        return Err(AppError::BadRequest(
            "release archive URL is not from Hardened_NanoKVM releases".to_string(),
        ));
    }
    if latest.url.contains(char::is_whitespace) {
        return Err(AppError::BadRequest(
            "release archive URL contains whitespace".to_string(),
        ));
    }
    validate_signature_fields(&latest.signature_algorithm, &latest.signature_key_id)?;

    Ok(())
}

async fn enforce_app_metadata_signature(
    metadata_url: &str,
    metadata: &[u8],
    latest: &LatestRelease,
    config: &crate::config::Config,
) -> Result<()> {
    if app_metadata_is_unsigned(latest) {
        if config.security.allow_unsigned_updates {
            tracing::warn!(
                version = %latest.version,
                "accepting unsigned application update metadata because allow_unsigned_updates is enabled"
            );
            return Ok(());
        }
        return Err(AppError::BadRequest(
            "unsigned application update metadata is not allowed".to_string(),
        ));
    }

    if latest.signature_algorithm != APP_UPDATE_SIGNATURE_ALGORITHM {
        return Err(AppError::BadRequest(
            "unsupported application update metadata signature algorithm".to_string(),
        ));
    }
    if !config.paths.system_update_public_key.is_file() {
        return Err(AppError::Config(format!(
            "application update public key is not configured: {}",
            config.paths.system_update_public_key.display()
        )));
    }

    let signature_url = metadata_signature_url(metadata_url)?;
    let signature = fetch_app_metadata_signature(&signature_url).await?;
    verify_app_metadata_signature(metadata, &signature, &config.paths.system_update_public_key)
        .await
}

fn app_metadata_is_unsigned(latest: &LatestRelease) -> bool {
    latest.signature_algorithm == APP_UPDATE_UNSIGNED_ALGORITHM
        && latest.signature_key_id == APP_UPDATE_UNSIGNED_ALGORITHM
}

fn validate_signature_fields(algorithm: &str, key_id: &str) -> Result<()> {
    match algorithm {
        APP_UPDATE_SIGNATURE_ALGORITHM | APP_UPDATE_UNSIGNED_ALGORITHM => {}
        _ => {
            return Err(AppError::BadRequest(
                "unsupported application update metadata signature algorithm".to_string(),
            ));
        }
    }
    if key_id.is_empty()
        || key_id.starts_with('.')
        || key_id.ends_with('.')
        || key_id.contains("..")
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(AppError::BadRequest(
            "invalid application update metadata signature key id".to_string(),
        ));
    }
    if (algorithm == APP_UPDATE_UNSIGNED_ALGORITHM) != (key_id == APP_UPDATE_UNSIGNED_ALGORITHM) {
        return Err(AppError::BadRequest(
            "invalid application update metadata signature marker".to_string(),
        ));
    }
    Ok(())
}

fn validate_metadata_url(url: &str) -> Result<()> {
    if url == GITHUB_RELEASE_LATEST_JSON || url == GITHUB_PREVIEW_LATEST_JSON {
        return Ok(());
    }
    Err(AppError::BadRequest(
        "invalid application update metadata URL".to_string(),
    ))
}

fn metadata_signature_url(metadata_url: &str) -> Result<String> {
    validate_metadata_url(metadata_url)?;
    Ok(format!("{metadata_url}.sig"))
}

async fn fetch_app_metadata_signature(url: &str) -> Result<Vec<u8>> {
    let output = run_allowed(
        AllowedCommand::Curl,
        ["-fsSL", "--connect-timeout", "10", "--max-time", "30", url],
        METADATA_TIMEOUT,
    )
    .await?;
    ensure_success(&output, "download application update metadata signature")?;
    if output.stdout.is_empty() || output.stdout.len() > 16 * 1024 {
        return Err(AppError::BadRequest(
            "invalid application update metadata signature size".to_string(),
        ));
    }
    Ok(output.stdout)
}

async fn verify_app_metadata_signature(
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
            tracing::warn!(error = %stderr, "application update metadata signature verification failed");
            Err(AppError::BadRequest(
                "application update metadata signature verification failed".to_string(),
            ))
        }
    }
    .await;

    let _ = remove_file_if_exists(&metadata_path);
    let _ = remove_file_if_exists(&signature_path);
    result
}

fn validate_update_filename(filename: &str) -> Result<()> {
    if Path::new(filename)
        .file_name()
        .and_then(|value| value.to_str())
        != Some(filename)
    {
        return Err(AppError::BadRequest("invalid update filename".to_string()));
    }
    if filename.contains("..")
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AppError::BadRequest("invalid update filename".to_string()));
    }
    if !filename.ends_with(".tar.gz") {
        return Err(AppError::BadRequest(
            "update archive must be a tar.gz file".to_string(),
        ));
    }
    if !(filename.starts_with("hardened-nanokvm-kvmapp-") || filename.starts_with("nanokvm_")) {
        return Err(AppError::BadRequest(
            "unsupported update archive name".to_string(),
        ));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<()> {
    let mut parts = version.split('.');
    let valid = (0..3).all(|_| {
        parts
            .next()
            .filter(|part| !part.is_empty())
            .is_some_and(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none();
    if !valid {
        return Err(AppError::BadRequest(
            "release version must be semver x.y.z".to_string(),
        ));
    }
    Ok(())
}

fn validate_sha512(value: &str) -> Result<()> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| AppError::BadRequest("invalid release sha512".to_string()))?;
    if decoded.len() != 64 {
        return Err(AppError::BadRequest("invalid release sha512".to_string()));
    }
    Ok(())
}

fn verify_sha512(path: &Path, expected: &str) -> Result<()> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha512::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let actual = STANDARD.encode(hasher.finalize());
    if actual != expected {
        return Err(AppError::BadRequest("update checksum mismatch".to_string()));
    }
    Ok(())
}

fn validate_update_tree_has_no_symlinks(root: &Path) -> Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            return Err(AppError::BadRequest(format!(
                "update archive contains unsupported symlink: {}",
                relative.display()
            )));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
        }
    }
    Ok(())
}

fn prepare_cache_dir(cache_dir: &Path) -> Result<()> {
    if cache_dir == Path::new("/") || cache_dir.as_os_str().is_empty() {
        return Err(AppError::Config(
            "invalid update cache directory".to_string(),
        ));
    }
    remove_dir_if_exists(cache_dir)?;
    fs::create_dir_all(cache_dir)?;
    Ok(())
}

fn application_update_cache_dir(cache_root: &Path) -> PathBuf {
    cache_root.join(APPLICATION_UPDATE_CACHE_DIR_NAME)
}

fn acquire_update_lock() -> Result<UpdateGuard> {
    let mut is_updating = UPDATE_LOCK
        .lock()
        .map_err(|_| AppError::Internal("update lock poisoned".to_string()))?;
    if *is_updating {
        return Err(AppError::Conflict("update already in progress".to_string()));
    }
    *is_updating = true;
    Ok(UpdateGuard)
}

fn ensure_success(output: &CommandOutput, action: &str) -> Result<()> {
    if output.status == 0 {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(AppError::Internal(format!(
        "{action} failed with status {}: {}",
        output.status,
        stderr.trim()
    )))
}

fn path_arg(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| AppError::BadRequest("path is not valid UTF-8".to_string()))
}

fn temp_verify_path(kind: &str) -> Result<PathBuf> {
    match kind {
        "metadata" | "signature" => {}
        _ => {
            return Err(AppError::BadRequest(
                "invalid temporary file kind".to_string(),
            ));
        }
    }
    Ok(PathBuf::from(format!(
        "/tmp/hardened-app-update-{}-{}-{kind}.tmp",
        std::process::id(),
        now_unix_nanos()
    )))
}

fn write_verify_temp_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
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

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn move_path(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        remove_dir_if_exists(dst)?;
    }
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(rename_err) => {
            tracing::warn!(
                source = %src.display(),
                target = %dst.display(),
                error = %rename_err,
                "rename failed, copying directory"
            );
            copy_path(src, dst)?;
            remove_dir_if_exists(src)
        }
    }
}

fn copy_path(src: &Path, dst: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(src)?;
    if metadata.file_type().is_symlink() {
        return Err(AppError::BadRequest(
            "unsupported symlink in update tree".to_string(),
        ));
    } else if metadata.is_dir() {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_path(&entry.path(), &dst.join(entry.file_name()))?;
        }
    } else if metadata.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(src, dst)?;
    } else {
        return Err(AppError::BadRequest(
            "unsupported file type in update tree".to_string(),
        ));
    }
    Ok(())
}

fn restore_backup(app_dir: &Path, backup_dir: &Path) -> Result<()> {
    remove_dir_if_exists(app_dir)?;
    if backup_dir.exists() {
        move_path(backup_dir, app_dir)?;
    }
    Ok(())
}

fn chmod_recursively(path: &Path, mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_symlink() {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            chmod_recursively(&entry?.path(), mode)?;
        }
    }
    Ok(())
}

fn restart_nanokvm_after_response() {
    tokio::spawn(async {
        time::sleep(Duration::from_secs(1)).await;
        if let Err(err) = run_allowed(
            AllowedCommand::ServiceNanokvmRestart,
            ["restart"],
            Duration::from_secs(20),
        )
        .await
        {
            tracing::error!(error = %err, "failed to restart NanoKVM after update");
        }
    });
}

pub(crate) fn is_preview_enabled() -> bool {
    Path::new(PREVIEW_UPDATES_FLAG).exists()
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn validates_hardened_update_filenames() {
        assert!(validate_update_filename("hardened-nanokvm-kvmapp-0.1.1.tar.gz").is_ok());
        assert!(validate_update_filename("nanokvm_1.2.3.tar.gz").is_ok());
        assert!(validate_update_filename("../hardened-nanokvm-kvmapp-0.1.1.tar.gz").is_err());
        assert!(validate_update_filename("hardened-nanokvm-kvmapp-0.1.1.zip").is_err());
        assert!(validate_update_filename("other-0.1.1.tar.gz").is_err());
    }

    #[test]
    fn validates_latest_release_metadata() {
        let sha512 = STANDARD.encode([42_u8; 64]);
        let latest = LatestRelease {
            version: "0.1.1".to_string(),
            name: "hardened-nanokvm-kvmapp-0.1.1.tar.gz".to_string(),
            sha512,
            size: 1024,
            url: "https://github.com/woffko/Hardened_NanoKVM/releases/download/test/hardened-nanokvm-kvmapp-0.1.1.tar.gz".to_string(),
            signature_algorithm: APP_UPDATE_SIGNATURE_ALGORITHM.to_string(),
            signature_key_id: "hardened-system-dev".to_string(),
        };
        assert!(validate_latest_release(&latest).is_ok());
    }

    #[test]
    fn chooses_newer_stable_when_preview_is_stale() {
        let sha512 = STANDARD.encode([42_u8; 64]);
        let preview = LatestRelease {
            version: "1.0.5".to_string(),
            name: "hardened-nanokvm-kvmapp-1.0.5.tar.gz".to_string(),
            sha512: sha512.clone(),
            size: 1024,
            url: "https://github.com/woffko/Hardened_NanoKVM/releases/download/preview/hardened-nanokvm-kvmapp-1.0.5.tar.gz".to_string(),
            signature_algorithm: APP_UPDATE_SIGNATURE_ALGORITHM.to_string(),
            signature_key_id: "hardened-system-dev".to_string(),
        };
        let stable = LatestRelease {
            version: "2.0.0".to_string(),
            name: "hardened-nanokvm-kvmapp-2.0.0.tar.gz".to_string(),
            sha512,
            size: 2048,
            url: "https://github.com/woffko/Hardened_NanoKVM/releases/download/stable/hardened-nanokvm-kvmapp-2.0.0.tar.gz".to_string(),
            signature_algorithm: APP_UPDATE_SIGNATURE_ALGORITHM.to_string(),
            signature_key_id: "hardened-system-dev".to_string(),
        };

        assert_eq!(newer_release(preview, stable).version, "2.0.0");
    }

    #[test]
    fn rejects_bad_application_signature_marker() {
        let sha512 = STANDARD.encode([42_u8; 64]);
        let latest = LatestRelease {
            version: "0.1.1".to_string(),
            name: "hardened-nanokvm-kvmapp-0.1.1.tar.gz".to_string(),
            sha512,
            size: 1024,
            url: "https://github.com/woffko/Hardened_NanoKVM/releases/download/test/hardened-nanokvm-kvmapp-0.1.1.tar.gz".to_string(),
            signature_algorithm: APP_UPDATE_UNSIGNED_ALGORITHM.to_string(),
            signature_key_id: "not-unsigned".to_string(),
        };
        assert!(validate_latest_release(&latest).is_err());
    }

    #[test]
    fn rejects_go_backend_in_update_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("server")).unwrap();
        fs::create_dir_all(root.join("system/init.d")).unwrap();
        fs::create_dir_all(root.join("backends")).unwrap();
        fs::write(root.join("server/NanoKVM-Server"), b"rust").unwrap();
        fs::write(root.join("system/init.d/S95nanokvm"), b"init").unwrap();
        fs::write(root.join("backends/NanoKVM-Server.rust"), b"rust").unwrap();
        fs::write(root.join("backends/NanoKVM-Server.go"), b"go").unwrap();

        let err = validate_update_root(root).unwrap_err();
        assert!(err.to_string().contains("legacy Go backend"));
    }

    #[test]
    fn rejects_symlink_in_update_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("server")).unwrap();
        fs::create_dir_all(root.join("system/init.d")).unwrap();
        fs::create_dir_all(root.join("backends")).unwrap();
        fs::write(root.join("server/NanoKVM-Server"), b"rust").unwrap();
        fs::write(root.join("system/init.d/S95nanokvm"), b"init").unwrap();
        fs::write(root.join("backends/NanoKVM-Server.rust"), b"rust").unwrap();
        symlink("/etc/shadow", root.join("server/web")).unwrap();

        let err = validate_update_root(root).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }
}
