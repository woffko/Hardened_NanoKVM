use axum::{
    Json,
    extract::{Multipart, State},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fs,
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time;

use crate::{
    AppError, Result,
    api::system_firewall,
    config::Config,
    error::ApiResponse,
    state::AppState,
    system::command::{AllowedCommand, CommandOutput, run_allowed},
    update::{
        app_stage::{AppArchive, AppDownload, AppStage, MAX_ARCHIVE_BYTES as MAX_UPDATE_BYTES},
        archive::extract_app_tar_gz,
        keys::resolve_update_public_key,
        operation::{Kind, Snapshot, UpdateOwner},
        staged_metadata::{MAX_METADATA, MAX_SIGNATURE},
    },
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
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const METADATA_TIMEOUT: Duration = Duration::from_secs(45);
const APP_UPDATE_SIGNATURE_ALGORITHM: &str = "sha256-rsa-pkcs1-v1_5";
const APP_UPDATE_UNSIGNED_ALGORITHM: &str = "unsigned";
const MAX_APP_VERSION_BYTES: u64 = 128;

#[derive(Debug, Serialize)]
pub struct VersionRsp {
    pub current: String,
    pub latest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CurrentVersionRsp {
    pub current: String,
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

// Exact signed bytes travel with the parsed view. Never reconstruct a receipt
// by serializing LatestRelease, or let version selection mix two receipts.
struct VerifiedAppMetadata {
    latest: LatestRelease,
    metadata: Vec<u8>,
    signature: Vec<u8>,
}

enum InstallAuthority {
    OnlineMetadata(VerifiedAppMetadata),
    ManualImport,
}

pub async fn update_status(State(state): State<AppState>) -> Result<Json<ApiResponse<Snapshot>>> {
    Ok(Json(ApiResponse::ok(state.updates.snapshot()?)))
}

pub async fn get_version(State(state): State<AppState>) -> Result<impl IntoResponse> {
    if system_firewall::paranoid_mode_enabled() {
        return Ok(Json(ApiResponse::ok(VersionRsp {
            current: current_app_version(),
            latest: String::new(),
            blocked: Some(true),
            error: Some(system_firewall::paranoid_blocked_message().to_string()),
        })));
    }

    let latest = match get_latest(is_preview_enabled(), &state.config).await {
        Ok(verified) => verified.latest.version,
        Err(err) => {
            tracing::warn!(error = %err, "failed to query latest application release");
            String::new()
        }
    };

    Ok(Json(ApiResponse::ok(VersionRsp {
        current: current_app_version(),
        latest,
        blocked: None,
        error: None,
    })))
}

pub async fn get_current_version() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(CurrentVersionRsp {
        current: current_app_version(),
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
    if system_firewall::paranoid_mode_enabled() {
        return Err(AppError::BadRequest(
            system_firewall::paranoid_blocked_message().to_string(),
        ));
    }

    let owner = state.updates.acquire(Kind::ApplicationOnline)?;
    owner
        .run(move |job| async move {
            let config = job.blocking("read app update policy", Config::read).await?;
            let verified = get_latest(is_preview_enabled(), &config).await?;
            let (stage, archive) = job
                .blocking("prepare private app staging", || {
                    let stage = AppStage::prepare()?;
                    let archive = stage.create_archive()?;
                    Ok((stage, archive))
                })
                .await?;
            let archive = download_release_asset(&verified.latest, archive, &job).await?;
            let config = job
                .blocking("reread app install policy", Config::read)
                .await?;
            let verified =
                authenticate_app_metadata(verified.metadata, verified.signature, &config).await?;
            job.blocking("verify and install app", move || {
                let archive = archive
                    .finish_online(
                        verified.latest.size,
                        &decode_sha512(&verified.latest.sha512)?,
                    )
                    .map_err(|error| {
                        if error.kind() == io::ErrorKind::InvalidData {
                            AppError::BadRequest("update archive size or checksum mismatch".into())
                        } else {
                            error.into()
                        }
                    })?;
                install_package(archive, stage, InstallAuthority::OnlineMetadata(verified))
            })
            .await?;
            restart_nanokvm_after_response(job);
            Ok(())
        })
        .await?;

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn offline_update(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<ApiResponse<()>>> {
    let owner = state.updates.acquire(Kind::ApplicationOffline)?;
    owner
        .run(move |job| async move {
            let (stage, archive) = job
                .blocking("prepare private offline app staging", || {
                    let stage = AppStage::prepare()?;
                    let archive = stage.create_archive()?;
                    Ok((stage, archive))
                })
                .await?;
            let archive = time::timeout(
                DOWNLOAD_TIMEOUT,
                save_uploaded_update(archive, &mut multipart, &job),
            )
            .await
            .map_err(|_| AppError::BadRequest("app upload timed out".into()))??;
            job.blocking("install offline app", move || {
                install_package(archive, stage, InstallAuthority::ManualImport)
            })
            .await?;
            restart_nanokvm_after_response(job);
            Ok(())
        })
        .await?;

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

async fn get_latest(preview: bool, config: &Config) -> Result<VerifiedAppMetadata> {
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

fn newer_release(left: VerifiedAppMetadata, right: VerifiedAppMetadata) -> VerifiedAppMetadata {
    match compare_application_versions(&left.latest.version, &right.latest.version) {
        Some(std::cmp::Ordering::Less) => right,
        _ => left,
    }
}

pub(crate) fn compare_application_versions(left: &str, right: &str) -> Option<std::cmp::Ordering> {
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

async fn fetch_latest(url: &str, config: &Config) -> Result<VerifiedAppMetadata> {
    validate_metadata_url(url)?;
    let metadata = fetch_latest_metadata(url).await?;
    let latest = parse_exact_app_metadata(&metadata)?;
    let signature = enforce_app_metadata_signature(url, &metadata, &latest, config).await?;
    Ok(VerifiedAppMetadata {
        latest,
        metadata,
        signature,
    })
}

fn parse_exact_app_metadata(metadata: &[u8]) -> Result<LatestRelease> {
    if metadata.is_empty() || metadata.len() > MAX_METADATA {
        return Err(AppError::BadRequest(
            "invalid application update metadata size".into(),
        ));
    }
    let latest = serde_json::from_slice(metadata)
        .map_err(|_| AppError::BadRequest("invalid application update metadata".into()))?;
    validate_latest_release(&latest)?;
    Ok(latest)
}

async fn authenticate_app_metadata(
    metadata: Vec<u8>,
    signature: Vec<u8>,
    config: &Config,
) -> Result<VerifiedAppMetadata> {
    let latest = parse_exact_app_metadata(&metadata)?;
    verify_app_metadata_with_policy(&metadata, &signature, &latest, config).await?;
    Ok(VerifiedAppMetadata {
        latest,
        metadata,
        signature,
    })
}

async fn fetch_latest_metadata(url: &str) -> Result<Vec<u8>> {
    let output = run_allowed(
        AllowedCommand::Curl,
        [
            "--disable",
            "-fsSL",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "-H",
            "Accept: application/json",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--",
            url,
        ],
        METADATA_TIMEOUT,
    )
    .await?;
    ensure_success(&output, "query latest release metadata")?;
    Ok(output.stdout)
}

async fn download_release_asset(
    latest: &LatestRelease,
    archive: AppDownload,
    owner: &UpdateOwner,
) -> Result<AppDownload> {
    let mut command = tokio::process::Command::new("/usr/bin/curl");
    // No output pathname, curlrc, stdin, retry append, or non-HTTPS redirect.
    command.args([
        "--disable",
        "-fsSL",
        "--connect-timeout",
        "10",
        "--max-time",
        "600",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--",
        &latest.url,
    ]);
    receive_app_archive(&mut command, latest.size, archive, owner, DOWNLOAD_TIMEOUT).await
}

async fn receive_app_archive(
    command: &mut tokio::process::Command,
    size: u64,
    mut archive: AppDownload,
    owner: &UpdateOwner,
    deadline: Duration,
) -> Result<AppDownload> {
    use tokio::io::AsyncReadExt;
    if size == 0 || size > MAX_UPDATE_BYTES {
        return Err(AppError::BadRequest("invalid app archive size".into()));
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let Some(mut source) = child.stdout.take() else {
        let _ = child.start_kill();
        child.wait().await?;
        return Err(AppError::Internal("missing app archive stream".into()));
    };
    let result = time::timeout(deadline, async {
        let mut remaining = size;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = source.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            if count as u64 > remaining {
                return Err(AppError::BadRequest(
                    "app archive exceeds signed size".into(),
                ));
            }
            let chunk = buffer[..count].to_vec();
            archive = owner
                .blocking("write online app archive", move || {
                    archive.append(&chunk)?;
                    Ok(archive)
                })
                .await?;
            remaining -= count as u64;
        }
        if remaining != 0 {
            return Err(AppError::BadRequest(
                "app archive is shorter than signed size".into(),
            ));
        }
        if !child.wait().await?.success() {
            return Err(AppError::BadRequest("download app archive failed".into()));
        }
        Ok(archive)
    })
    .await
    .unwrap_or_else(|_| Err(AppError::BadRequest("app download timed out".into())));
    if result.is_err() {
        let _ = child.start_kill();
        // Retain the registered job through direct-child reap, even when kill
        // races natural exit. No detached download owns a writable descriptor.
        child.wait().await?;
    }
    result
}

async fn save_uploaded_update(
    mut archive: AppDownload,
    multipart: &mut Multipart,
    owner: &UpdateOwner,
) -> Result<AppArchive> {
    let mut found = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid multipart data: {err}")))?
    {
        if field.name() != Some("file") {
            continue;
        }
        if found {
            return Err(AppError::BadRequest(
                "multiple update files uploaded".into(),
            ));
        }
        found = true;

        let filename = field
            .file_name()
            .map(str::to_string)
            .ok_or_else(|| AppError::BadRequest("missing update filename".to_string()))?;
        validate_update_filename(&filename)?;

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
            archive = owner
                .blocking("write offline app archive", move || {
                    archive.append(&chunk)?;
                    Ok(archive)
                })
                .await?;
        }

        if written == 0 {
            return Err(AppError::BadRequest("empty update archive".to_string()));
        }
    }

    if !found {
        return Err(AppError::BadRequest("no update file uploaded".into()));
    }
    owner
        .blocking("seal manual app import", move || {
            Ok(archive.finish_manual_import()?)
        })
        .await
}

fn prepare_app_candidate(
    source: AppArchive,
    stage: &AppStage,
    authority: &InstallAuthority,
) -> Result<PathBuf> {
    let extract_dir = stage.extraction_path()?;
    let extracted = extract_app_tar_gz(source, &extract_dir)?;
    let update_root = resolve_update_root(&extracted)?;
    let version = validate_update_root(&update_root)?;
    if let InstallAuthority::OnlineMetadata(verified) = authority
        && version != verified.latest.version
    {
        return Err(AppError::BadRequest(
            "app candidate version differs from authenticated metadata".into(),
        ));
    }
    Ok(update_root)
}

fn install_package(
    source: AppArchive,
    mut stage: AppStage,
    authority: InstallAuthority,
) -> Result<()> {
    let update_root = prepare_app_candidate(source, &stage, &authority)?;

    // Startup attempts a fixed independent bootstrap. Recheck its exact bytes
    // and absence of any journal while this job owns app/system admission.
    // This prerequisite does not make the remaining legacy swap crash-safe.
    #[cfg(all(target_arch = "riscv64", feature = "linked-libkvm"))]
    crate::update::app_bootstrap::check_before_legacy_install()?;

    // From the first live-slot/backup mutation onward, retain the candidate on
    // every error (including failed backup restore). No cleanup is recovery.
    stage.preserve_recovery();
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
    stage.discard_after_success();
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

fn validate_update_root(root: &Path) -> Result<String> {
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
    for relative in [
        "kvm_new_app",
        "kvm_new_img",
        "jpg_stream",
        "kvm_system/kvm_stream",
    ] {
        if root.join(relative).exists() {
            return Err(AppError::BadRequest(format!(
                "update archive contains forbidden legacy app migration artifact: {relative}"
            )));
        }
    }
    validate_update_tree_has_no_symlinks(root)?;
    read_candidate_version(root)
}

fn read_candidate_version(root: &Path) -> Result<String> {
    use std::io::Read;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(root.join("version"))
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                AppError::BadRequest("app candidate version is missing".into())
            } else {
                error.into()
            }
        })?;
    if !file.metadata()?.is_file() {
        return Err(AppError::BadRequest(
            "app candidate version is not a regular file".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(MAX_APP_VERSION_BYTES as usize + 1);
    file.take(MAX_APP_VERSION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_APP_VERSION_BYTES {
        return Err(AppError::BadRequest(
            "invalid app candidate version size".into(),
        ));
    }
    let version = std::str::from_utf8(&bytes)
        .map_err(|_| AppError::BadRequest("invalid app candidate version encoding".into()))?
        .trim();
    validate_version(version)?;
    Ok(version.to_string())
}

fn validate_latest_release(latest: &LatestRelease) -> Result<()> {
    validate_version(&latest.version)?;
    validate_update_filename(&latest.name)?;
    decode_sha512(&latest.sha512)?;

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
    config: &Config,
) -> Result<Vec<u8>> {
    let signature = if app_metadata_is_unsigned(latest) {
        Vec::new()
    } else {
        let signature_url = metadata_signature_url(metadata_url)?;
        fetch_app_metadata_signature(&signature_url).await?
    };
    verify_app_metadata_with_policy(metadata, &signature, latest, config).await?;
    Ok(signature)
}

async fn verify_app_metadata_with_policy(
    metadata: &[u8],
    signature: &[u8],
    latest: &LatestRelease,
    config: &Config,
) -> Result<()> {
    if app_metadata_is_unsigned(latest) {
        if !signature.is_empty() {
            return Err(AppError::BadRequest(
                "unsigned application metadata cannot carry a signature receipt".into(),
            ));
        }
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
    if signature.is_empty() || signature.len() > MAX_SIGNATURE {
        return Err(AppError::BadRequest(
            "invalid application update metadata signature size".into(),
        ));
    }
    let public_key = resolve_update_public_key(
        &config.paths.system_update_public_key,
        &latest.signature_key_id,
    )?;

    verify_app_metadata_signature(metadata, signature, &public_key).await
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
        [
            "--disable",
            "-fsSL",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--",
            url,
        ],
        METADATA_TIMEOUT,
    )
    .await?;
    ensure_success(&output, "download application update metadata signature")?;
    if output.stdout.is_empty() || output.stdout.len() > MAX_SIGNATURE {
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
    if version.len() as u64 > MAX_APP_VERSION_BYTES {
        return Err(AppError::BadRequest("release version is too long".into()));
    }
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

fn decode_sha512(value: &str) -> Result<[u8; 64]> {
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| AppError::BadRequest("invalid release sha512".to_string()))?;
    decoded
        .try_into()
        .map_err(|_| AppError::BadRequest("invalid release sha512".into()))
}

fn validate_update_tree_has_no_symlinks(root: &Path) -> Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        if matches!(
            path.file_name().and_then(OsStr::to_str),
            Some("switch-backend-go.sh" | "switch-backend-rust.sh")
        ) {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            return Err(AppError::BadRequest(format!(
                "update archive contains forbidden backend switch script: {}",
                relative.display()
            )));
        }
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

fn restart_nanokvm_after_response(owner: UpdateOwner) {
    tokio::spawn(async move {
        time::sleep(Duration::from_secs(1)).await;
        let result = run_allowed(
            AllowedCommand::ServiceNanokvmRestart,
            ["restart"],
            Duration::from_secs(20),
        )
        .await;
        if !matches!(result, Ok(ref output) if output.status == 0) {
            owner.record_outcome(false);
            tracing::error!("failed to restart NanoKVM after update");
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

pub(crate) fn current_app_version() -> String {
    read_trimmed(APP_VERSION_FILE).unwrap_or_else(|| DEFAULT_APP_VERSION.to_string())
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
    use std::io::Read;

    async fn upload_fixture(payload: &[u8], complete: bool) -> Multipart {
        use axum::{body::Body, extract::FromRequest, http::Request};
        let mut body = b"--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hardened-nanokvm-kvmapp-fixture.tar.gz\"\r\nContent-Type: application/gzip\r\n\r\n".to_vec();
        body.extend_from_slice(payload);
        if complete {
            body.extend_from_slice(b"\r\n--fixture--\r\n");
        }
        let request = Request::builder()
            .header("content-type", "multipart/form-data; boundary=fixture")
            .body(Body::from(body))
            .unwrap();
        Multipart::from_request(request, &()).await.unwrap()
    }

    #[tokio::test]
    async fn offline_upload_file_work_is_owned_and_exact() {
        use crate::update::operation::{Phase, UpdateCoordinator};
        use std::sync::Arc;
        let temporary = tempfile::tempdir().unwrap();
        let stage = AppStage::fixture(temporary.path()).unwrap();
        let download = stage.create_archive().unwrap();
        let coordinator = Arc::new(UpdateCoordinator::in_process_fixture());
        let owner = coordinator.acquire(Kind::ApplicationOffline).unwrap();
        let payload = b"synthetic archive bytes, not an installable archive";
        let mut multipart = upload_fixture(payload, true).await;
        let mut archive =
            owner
                .run(move |job| async move {
                    save_uploaded_update(download, &mut multipart, &job).await
                })
                .await
                .unwrap();
        let mut actual = Vec::new();
        archive.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, payload);
        let snapshot = coordinator.snapshot().unwrap();
        assert!(snapshot.active.is_none() && snapshot.last.unwrap().phase == Phase::Finished);
    }

    #[tokio::test]
    async fn interrupted_offline_body_never_returns_an_installable_upload() {
        use crate::update::operation::{Phase, UpdateCoordinator};
        use std::sync::Arc;
        let temporary = tempfile::tempdir().unwrap();
        let stage = AppStage::fixture(temporary.path()).unwrap();
        let download = stage.create_archive().unwrap();
        let coordinator = Arc::new(UpdateCoordinator::in_process_fixture());
        let owner = coordinator.acquire(Kind::ApplicationOffline).unwrap();
        let mut multipart = upload_fixture(b"synthetic truncated body", false).await;
        assert!(
            owner
                .run(move |job| async move {
                    save_uploaded_update(download, &mut multipart, &job).await
                })
                .await
                .is_err()
        );
        let snapshot = coordinator.snapshot().unwrap();
        assert!(snapshot.active.is_none() && snapshot.last.unwrap().phase == Phase::Failed);
    }

    #[tokio::test]
    async fn app_stream_is_exactly_bounded_and_does_not_use_archive_names() {
        use crate::update::operation::UpdateCoordinator;
        use sha2::{Digest, Sha512};
        use std::sync::Arc;
        let root = tempfile::tempdir().unwrap();
        let sentinel = root.path().join("sentinel");
        fs::write(&sentinel, b"untouched").unwrap();
        let stage = AppStage::fixture(root.path()).unwrap();
        let coordinator = Arc::new(UpdateCoordinator::in_process_fixture());
        for (program, args, size, success) in [
            ("/usr/bin/printf", vec!["%s", "exact"], 5, true),
            ("/usr/bin/printf", vec!["%s", "short"], 6, false),
            ("/usr/bin/printf", vec!["%s", "oversized"], 8, false),
            ("/usr/bin/false", vec![], 1, false),
            ("/usr/bin/true", vec![], 1, false),
        ] {
            let owner = coordinator.acquire(Kind::ApplicationOnline).unwrap();
            let archive = stage.create_archive().unwrap();
            let mut command = tokio::process::Command::new(program);
            command.args(args);
            let result = owner
                .run(move |job| async move {
                    receive_app_archive(&mut command, size, archive, &job, Duration::from_secs(5))
                        .await
                })
                .await;
            assert_eq!(result.is_ok(), success);
            if let Ok(download) = result {
                let mut archive = download
                    .finish_online(5, &Sha512::digest(b"exact").into())
                    .unwrap();
                let mut bytes = Vec::new();
                archive.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"exact");
            }
        }
        assert_eq!(fs::read(sentinel).unwrap(), b"untouched");
        assert_eq!(
            fs::read_dir(stage.extraction_path().unwrap().parent().unwrap())
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn app_stream_child_fixture() {
        let Ok(mode) = std::env::var("NANOKVM_APP_STREAM_TEST_MODE") else {
            return;
        };
        fs::write(
            std::env::var_os("NANOKVM_APP_STREAM_TEST_PID").unwrap(),
            std::process::id().to_string(),
        )
        .unwrap();
        match mode.as_str() {
            "hang" => std::thread::sleep(Duration::from_secs(30)),
            "failed-exit" => {
                std::io::stdout().write_all(b"bytes").unwrap();
                std::io::stdout().flush().unwrap();
                std::process::exit(1);
            }
            "oversized-hang" => {
                std::io::stdout().write_all(&[b'x'; 2048]).unwrap();
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            _ => panic!("unknown app stream test mode"),
        }
    }

    #[tokio::test]
    async fn app_stream_failure_and_deadline_reap_direct_child_before_releasing_admission() {
        use crate::update::operation::{Phase, UpdateCoordinator};
        use std::sync::Arc;
        let root = tempfile::tempdir().unwrap();
        let stage = AppStage::fixture(root.path()).unwrap();
        let coordinator = Arc::new(UpdateCoordinator::in_process_fixture());
        for mode in ["hang", "failed-exit", "oversized-hang"] {
            let pid_path = root.path().join(format!("{mode}.pid"));
            let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
            command
                .env_clear()
                .args([
                    "--exact",
                    "api::application::tests::app_stream_child_fixture",
                    "--nocapture",
                ])
                .env("NANOKVM_APP_STREAM_TEST_MODE", mode)
                .env("NANOKVM_APP_STREAM_TEST_PID", &pid_path);
            let size = if mode == "failed-exit" {
                let control = command.output().await.unwrap();
                assert_eq!(control.status.code(), Some(1));
                fs::remove_file(&pid_path).unwrap();
                control.stdout.len() as u64
            } else {
                1024
            };
            let archive = stage.create_archive().unwrap();
            let owner = coordinator.acquire(Kind::ApplicationOnline).unwrap();
            let error = owner
                .run(move |job| async move {
                    receive_app_archive(
                        &mut command,
                        size,
                        archive,
                        &job,
                        Duration::from_millis(500),
                    )
                    .await
                })
                .await
                .err()
                .unwrap();
            let expected = match mode {
                "hang" => "app download timed out",
                "failed-exit" => "download app archive failed",
                "oversized-hang" => "app archive exceeds signed size",
                _ => unreachable!(),
            };
            assert!(error.to_string().contains(expected), "{error}");
            let pid = fs::read_to_string(pid_path)
                .unwrap()
                .parse::<u32>()
                .unwrap();
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "direct child not reaped"
            );
            let status = coordinator.snapshot().unwrap();
            assert!(status.active.is_none() && status.last.unwrap().phase == Phase::Failed);
        }
    }

    #[tokio::test]
    async fn multiple_offline_files_are_rejected_without_selecting_the_last_one() {
        use crate::update::operation::UpdateCoordinator;
        use axum::{body::Body, extract::FromRequest, http::Request};
        use std::sync::Arc;
        let root = tempfile::tempdir().unwrap();
        let stage = AppStage::fixture(root.path()).unwrap();
        let download = stage.create_archive().unwrap();
        let part = "--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"nanokvm_fixture.tar.gz\"\r\n\r\nbytes\r\n";
        let request = Request::builder()
            .header("content-type", "multipart/form-data; boundary=fixture")
            .body(Body::from(format!("{part}{part}--fixture--\r\n")))
            .unwrap();
        let mut multipart = Multipart::from_request(request, &()).await.unwrap();
        let owner = Arc::new(UpdateCoordinator::in_process_fixture())
            .acquire(Kind::ApplicationOffline)
            .unwrap();
        assert!(
            owner
                .run(move |job| async move {
                    save_uploaded_update(download, &mut multipart, &job).await
                })
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("multiple update files")
        );
    }

    #[tokio::test]
    async fn lost_app_stream_reply_retains_stage_and_admission_until_child_cleanup() {
        use crate::update::operation::{Phase, UpdateCoordinator};
        use std::sync::Arc;
        let root = tempfile::tempdir().unwrap();
        let stage = AppStage::fixture(root.path()).unwrap();
        let stage_path = stage
            .extraction_path()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let archive = stage.create_archive().unwrap();
        let pid_path = root.path().join("pid");
        let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
        command
            .env_clear()
            .args([
                "--exact",
                "api::application::tests::app_stream_child_fixture",
                "--nocapture",
            ])
            .env("NANOKVM_APP_STREAM_TEST_MODE", "hang")
            .env("NANOKVM_APP_STREAM_TEST_PID", &pid_path);
        let coordinator = Arc::new(UpdateCoordinator::in_process_fixture());
        let owner = coordinator.acquire(Kind::ApplicationOnline).unwrap();
        let reply = tokio::spawn(owner.run(move |job| async move {
            let result = receive_app_archive(
                &mut command,
                1024,
                archive,
                &job,
                Duration::from_millis(800),
            )
            .await;
            drop(stage);
            result.map(|_| ())
        }));
        time::timeout(Duration::from_secs(3), async {
            while !pid_path.exists() {
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let pid = fs::read_to_string(pid_path)
            .unwrap()
            .parse::<u32>()
            .unwrap();
        reply.abort();
        assert!(reply.await.unwrap_err().is_cancelled());
        assert!(stage_path.is_dir());
        assert!(coordinator.acquire(Kind::ApplicationOffline).is_err());
        time::timeout(Duration::from_secs(5), async {
            while coordinator.snapshot().unwrap().active.is_some() {
                time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(!stage_path.exists());
        assert_eq!(
            coordinator.snapshot().unwrap().last.unwrap().phase,
            Phase::Failed
        );
    }

    #[test]
    #[ignore = "requires retained historical public app archives"]
    fn historical_bridge_package_extracts_in_private_stage_without_installing() {
        use sha2::{Digest, Sha256};
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for (path, hash, version) in [
            (
                "build/release/combined-rc11-3cca4d8/hardened-nanokvm-kvmapp-2.0.40.tar.gz",
                "85e6aa195ccf7274203462a0488c9e251c567a523519fd50d4973eb60ddd65d5",
                "2.0.40",
            ),
            (
                "build/key-transition-2.0.42-bootstrap/legacy-inputs/hardened-nanokvm-kvmapp-2.0.41.tar.gz",
                "c8520306d70b3c6998a486e84faf82f1a8509f7a97f621d14dfc34af368ae18d",
                "2.0.41",
            ),
            (
                "build/key-transition-2.0.42-bootstrap/app-a/out/hardened-nanokvm-kvmapp-2.0.42.tar.gz",
                "aa0cd78c1b2e9951f216826c44b4b7ff2fb211fc1980540366f8f5b1f7e0dd20",
                "2.0.42",
            ),
        ] {
            let root = tempfile::tempdir().unwrap();
            let stage = AppStage::fixture(root.path()).unwrap();
            let mut download = stage.create_archive().unwrap();
            let mut source = fs::File::open(project.join(path)).unwrap();
            assert!(source.metadata().unwrap().len() <= MAX_UPDATE_BYTES);
            let mut actual = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = source.read(&mut buffer).unwrap();
                if count == 0 {
                    break;
                }
                actual.update(&buffer[..count]);
                download.append(&buffer[..count]).unwrap();
            }
            assert_eq!(format!("{:x}", actual.finalize()), hash);
            let archive = download.finish_manual_import().unwrap();
            let extracted = extract_app_tar_gz(archive, &stage.extraction_path().unwrap()).unwrap();
            let app = resolve_update_root(&extracted).unwrap();
            validate_update_root(&app).unwrap();
            assert_eq!(
                fs::read_to_string(app.join("version")).unwrap().trim(),
                version
            );
        }
    }
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

        // Selection must move the matching exact bytes/signature, not only the
        // parsed version. These placeholders are NOT signature verification.
        let stable_bytes = serde_json::to_vec(&stable).unwrap();
        let chosen = newer_release(
            VerifiedAppMetadata {
                metadata: serde_json::to_vec(&preview).unwrap(),
                latest: preview,
                signature: vec![1; 256],
            },
            VerifiedAppMetadata {
                metadata: stable_bytes.clone(),
                latest: stable,
                signature: vec![2; 256],
            },
        );
        assert_eq!(chosen.latest.version, "2.0.0");
        assert_eq!(chosen.metadata, stable_bytes);
        assert_eq!(chosen.signature, vec![2; 256]);
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
    fn rejects_legacy_app_migration_artifacts_in_update_root() {
        for relative in [
            "kvm_new_app",
            "kvm_new_img",
            "jpg_stream",
            "kvm_system/kvm_stream",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            fs::create_dir_all(root.join("server")).unwrap();
            fs::create_dir_all(root.join("system/init.d")).unwrap();
            fs::create_dir_all(root.join("backends")).unwrap();
            fs::write(root.join("server/NanoKVM-Server"), b"rust").unwrap();
            fs::write(root.join("system/init.d/S95nanokvm"), b"init").unwrap();
            fs::write(root.join("backends/NanoKVM-Server.rust"), b"rust").unwrap();
            if relative == "jpg_stream" {
                fs::create_dir(root.join(relative)).unwrap();
            } else {
                let path = root.join(relative);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"legacy").unwrap();
            }

            let err = validate_update_root(root).unwrap_err();
            assert!(err.to_string().contains("legacy app migration artifact"));
        }
    }

    #[test]
    fn rejects_backend_switch_script_in_update_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("server")).unwrap();
        fs::create_dir_all(root.join("system/init.d")).unwrap();
        fs::create_dir_all(root.join("backends")).unwrap();
        fs::create_dir_all(root.join("system/scripts")).unwrap();
        fs::write(root.join("server/NanoKVM-Server"), b"rust").unwrap();
        fs::write(root.join("system/init.d/S95nanokvm"), b"init").unwrap();
        fs::write(root.join("backends/NanoKVM-Server.rust"), b"rust").unwrap();
        fs::write(
            root.join("system/scripts/switch-backend-rust.sh"),
            b"switch",
        )
        .unwrap();

        let err = validate_update_root(root).unwrap_err();
        assert!(err.to_string().contains("backend switch"));
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

#[cfg(test)]
#[path = "application_trust_tests.rs"]
mod trust_tests;
