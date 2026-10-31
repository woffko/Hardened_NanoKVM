use crate::{
    AppError, Result,
    api::application::{compare_application_versions, current_app_version, is_preview_enabled},
    api::system_firewall,
    config::Config,
    error::ApiResponse,
    state::AppState,
    system::command::{AllowedCommand, CommandOutput, run_allowed},
    update::{
        archive::extract_tar_gz_reader,
        keys::verify_metadata_signature,
        operation::{Kind, Snapshot as OperationSnapshot, UpdateOwner},
        raw_capture::{self, CaptureRequest, TargetImage},
        raw_install_lease::{RawImages, RawSender},
        raw_restore,
        raw_transport::TransferContext,
        restore_capsule::ticket::{BootId, Phase, RestoreTicket, Store},
        restore_job::PinnedSshHelper,
        staged_archive::{StageDirectory, StagedDownload},
        staged_metadata::{MAX_METADATA, MAX_SIGNATURE, MetadataReceipt, MetadataStore},
        staged_snapshot::PublicSnapshot,
    },
};
use axum::{Json, extract::State, response::IntoResponse};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    cmp::Ordering,
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Read, Seek},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::AtomicBool,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[path = "system_update_bundle.rs"]
mod bundle;

const SYSTEM_VERSION_FILE: &str = "/etc/kvm/system-version.json";
const BOOT_VERSION_FILE: &str = "/boot/ver";
const BOOT_ID_FILE: &str = "/proc/sys/kernel/random/boot_id";
const PROC_STAT_FILE: &str = "/proc/stat";
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
const SYSTEM_UPDATE_METADATA_FORMAT_V1: u32 = 1;
const SYSTEM_UPDATE_METADATA_FORMAT_V2: u32 = 2;
const SYSTEM_UPDATE_MANIFEST_FORMAT_V1: &str = "hardened-nanokvm-system-update-v1";
const SYSTEM_UPDATE_MANIFEST_FORMAT_V2: &str = "hardened-nanokvm-system-update-v2";
const MAX_SYSTEM_UPDATE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_SYSTEM_UPDATE_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const METADATA_TIMEOUT: Duration = Duration::from_secs(45);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const SYSTEM_STAGE_DIR_NAME: &str = "system-update";
const SYSTEM_EXTRACT_DIR_NAME: &str = "extract";
const SYSTEM_STAGE_RECORD: &str = "staged.json";
const SYSTEM_PROGRESS_RECORD: &str = "progress.json";
const SYSTEM_BACKUPS_DIR_NAME: &str = "backups";
const SYSTEM_BACKUP_RECORD: &str = "backup.json";
const SYSTEM_PENDING_FILE: &str = "/etc/kvm/system-update-pending.json";
const MAX_PENDING_UPDATE_BYTES: u64 = 4096;
const SYSTEM_LAST_BACKUP_FILE: &str = "/etc/kvm/system-update-last-backup.json";
const SYSTEM_BOOT_GOOD_FILE: &str = "/etc/kvm/system-update-boot-good.json";
const SYSTEM_ROLLBACK_SCRIPT_FILE: &str = "/etc/kvm/system-update-rollback.sh";
const SYSTEM_ROLLBACK_ATTEMPT_FILE: &str = "/etc/kvm/system-update-rollback-attempted";
const SYSTEM_RAW_INSTALL_MARKER: &str = "/data/hardened-system-raw-update-pending.json";
const SYSTEM_RAW_INSTALL_RUN_DIR: &str = "/tmp/hardened-system-raw-update";
#[cfg(test)]
const SYSTEM_RAW_INSTALL_LOG: &str = "/data/hardened-system-raw-update.log";
#[cfg(test)]
const SYSTEM_RAW_RUNTIME_LOADER: &str = "ld-musl-system-update.so.1";
const RAW_BOOT_DEVICE: &str = "/dev/mmcblk0p1";
const RAW_ROOTFS_DEVICE: &str = "/dev/mmcblk0p2";
const RAW_PRIVATE_STAGING: &str = "/etc/kvm/.raw-capture";
const RAW_CAPSULE_DIR: &str = "/data/.nanokvm-restore";
const WRITER_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemVersion {
    pub version: String,
    pub target: String,
    pub base_version: String,
    pub kernel_version: String,
    pub rootfs_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_patch_level: Option<String>,
    pub model: String,
    pub hardware_version: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[serde(default, alias = "security_patch_level")]
    pub security_patch_level: Option<String>,
    #[serde(default, alias = "required_app_version")]
    pub required_app_version: Option<String>,
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
    pub app_update_required: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_patch_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_app_version: Option<String>,
    pub required_free_bytes: u64,
    pub requires_reboot: bool,
    pub file_count: usize,
    pub image_count: usize,
    pub destructive: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatusRsp {
    pub update_operation: OperationSnapshot,
    pub current: SystemVersion,
    pub staged: Option<SystemStagedUpdate>,
    pub pending: Option<SystemPendingUpdate>,
    pub boot_health: Option<SystemBootHealth>,
    pub rollback: Option<SystemRollbackInfo>,
    pub progress: Option<SystemUpdateProgress>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RawUpdateEnabledRsp {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetRawUpdateEnabledReq {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemUpdateProgress {
    pub operation: String,
    pub phase: String,
    pub version: Option<String>,
    pub started_at: u64,
    pub updated_at: u64,
    pub message: Option<String>,
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
    /// Kernel boot ID at install. An update that requires a reboot is
    /// confirmed only in a later boot; older backends recorded none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_boot_id: Option<String>,
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
    #[serde(default)]
    pub rebooted: bool,
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
struct PersistedSystemVersion {
    version: Option<String>,
    target: Option<String>,
    #[serde(alias = "baseVersion")]
    base_version: Option<String>,
    #[serde(alias = "kernelVersion")]
    kernel_version: Option<String>,
    #[serde(alias = "rootfsVersion")]
    rootfs_version: Option<String>,
    #[serde(alias = "securityPatchLevel")]
    security_patch_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemStageRecord {
    staged_at: u64,
    latest: SystemLatest,
    manifest: SystemManifest,
}

// Constructed only after exact metadata/signature verification. Do not derive
// Deserialize or build it from the mutable stage receipt.
struct VerifiedSystemMetadata {
    latest: SystemLatest,
    metadata: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SystemManifest {
    format: String,
    version: String,
    target: String,
    base_version: String,
    kernel_version: String,
    #[serde(default)]
    security_patch_level: Option<String>,
    #[serde(default)]
    required_app_version: Option<String>,
    source_commit: String,
    created_utc: String,
    required_free_bytes: u64,
    requires_reboot: bool,
    operations: Vec<String>,
    files: Vec<SystemManifestFile>,
    #[serde(default)]
    raw_images: Vec<SystemManifestRawImage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SystemManifestFile {
    payload: String,
    install: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SystemManifestRawImage {
    payload: String,
    device: String,
    label: String,
    size: u64,
    sha256: String,
    #[serde(default)]
    compression: Option<String>,
    #[serde(default, alias = "compressed_size")]
    compressed_size: Option<u64>,
    #[serde(default, alias = "compressed_sha256")]
    compressed_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemInstallRecord {
    version: String,
    target: String,
    backup_id: String,
    installed_at: u64,
    requires_reboot: bool,
    files: Vec<SystemBackupFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    install_boot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SystemBackupFile {
    install: String,
    backup: String,
    existed: bool,
}

#[derive(Debug, Serialize)]
struct InstalledSystemVersion {
    version: String,
    target: String,
    base_version: String,
    kernel_version: String,
    rootfs_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_patch_level: Option<String>,
}

#[derive(Debug)]
struct FileHashes {
    sha256: String,
    sha512: String,
}

impl SystemUpdateProgress {
    fn new(
        operation: impl Into<String>,
        phase: impl Into<String>,
        version: Option<String>,
        message: Option<String>,
    ) -> Self {
        let now = now_unix_seconds();
        Self {
            operation: operation.into(),
            phase: phase.into(),
            version,
            started_at: now,
            updated_at: now,
            message,
        }
    }

    fn is_active(&self) -> bool {
        !matches!(self.phase.as_str(), "failed" | "done")
    }
}

pub async fn get_version() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(SystemVersionRsp {
        current: read_current_system_version(),
    })))
}

pub async fn get_raw_enabled() -> Result<impl IntoResponse> {
    let config = Config::read()?;
    Ok(Json(ApiResponse::ok(RawUpdateEnabledRsp {
        enabled: config.security.allow_raw_system_updates,
    })))
}

pub async fn set_raw_enabled(
    State(state): State<AppState>,
    Json(req): Json<SetRawUpdateEnabledReq>,
) -> Result<impl IntoResponse> {
    let permit = state.writers.configuration()?;
    permit
        .run(move |writer| async move {
            writer
                .blocking(move |permit| {
                    let mut config = Config::read_for(permit)?;
                    config.security.allow_raw_system_updates = req.enabled;
                    config.write(permit)
                })
                .await
        })
        .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn check(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let current = read_current_system_version();
    if system_firewall::paranoid_mode_enabled() {
        return Ok(Json(ApiResponse::ok(SystemCheckRsp {
            current,
            latest: None,
            update_available: false,
            app_update_required: false,
            error: Some(system_firewall::paranoid_blocked_message().to_string()),
        })));
    }

    match get_latest_system(is_preview_enabled(), &state.config).await {
        Ok(latest) => {
            let app_requirement_error = application_requirement_error(&latest);
            let update_available =
                app_requirement_error.is_none() && system_update_is_newer(&current, &latest);
            Ok(Json(ApiResponse::ok(SystemCheckRsp {
                current,
                latest: Some(latest),
                update_available,
                app_update_required: app_requirement_error.is_some(),
                error: app_requirement_error,
            })))
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to query latest system release");
            Ok(Json(ApiResponse::ok(SystemCheckRsp {
                current,
                latest: None,
                update_available: false,
                app_update_required: false,
                error: Some(err.to_string()),
            })))
        }
    }
}

pub async fn status(State(state): State<AppState>) -> Result<impl IntoResponse> {
    let update_operation = state.updates.snapshot()?;
    let operation_active = update_operation
        .active
        .is_some_and(|active| active.kind.is_system());
    let current = read_current_system_version();
    let stage_dir = system_stage_dir(&state.config.paths.update_cache_dir);
    let (pending, pending_error) = read_pending_status(
        Path::new(SYSTEM_PENDING_FILE),
        Path::new(SYSTEM_RAW_INSTALL_MARKER),
    );
    let progress =
        read_normalized_update_progress(&stage_dir, &current, pending.as_ref(), operation_active);
    let boot_health = pending
        .as_ref()
        .map(|pending| evaluate_boot_health(&current, pending, &state));
    let rollback = read_last_backup_record(&stage_dir)
        .ok()
        .flatten()
        .map(|record| rollback_info(&record));

    match read_staged_update(&stage_dir) {
        Ok(mut staged) => {
            if pending.is_none()
                && progress.is_none()
                && staged
                    .as_ref()
                    .map(|staged| staged_matches_current_system(staged, &current))
                    .unwrap_or(false)
            {
                staged = None;
            }

            Ok(Json(ApiResponse::ok(SystemStatusRsp {
                update_operation,
                current,
                staged,
                pending,
                boot_health,
                rollback,
                progress,
                error: pending_error,
            })))
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to read staged system update");
            Ok(Json(ApiResponse::ok(SystemStatusRsp {
                update_operation,
                current,
                staged: None,
                pending,
                boot_health,
                rollback,
                progress,
                error: Some(match pending_error {
                    Some(pending_error) => format!("{pending_error}; {err}"),
                    None => err.to_string(),
                }),
            })))
        }
    }
}

pub async fn download(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<SystemDownloadRsp>>> {
    if system_firewall::paranoid_mode_enabled() {
        return Err(AppError::BadRequest(
            system_firewall::paranoid_blocked_message().to_string(),
        ));
    }

    let owner = state.updates.acquire(Kind::SystemDownload)?;
    owner.run(move |job| download_owned(state, job)).await
}

async fn download_owned(
    state: AppState,
    owner: UpdateOwner,
) -> Result<Json<ApiResponse<SystemDownloadRsp>>> {
    ensure_no_pending_system_update()?;
    let current = read_current_system_version();
    let verified = get_verified_latest_system(is_preview_enabled(), &state.config).await?;
    let latest = verified.latest.clone();
    enforce_required_application_version(&latest)?;

    if latest.target != current.target {
        return Err(AppError::BadRequest(format!(
            "system update target mismatch: device {}, release {}",
            current.target, latest.target
        )));
    }
    if !system_update_is_newer(&current, &latest) {
        return Err(AppError::BadRequest(format!(
            "no newer system update available: current {}, release {}",
            current.version, latest.version
        )));
    }

    let stage_dir = system_stage_dir(&state.config.paths.update_cache_dir);
    let cache_stage_dir = stage_dir.clone();
    let cache_latest = latest.clone();
    if let Some(staged) = owner
        .blocking("check cached system update staging", move || {
            read_cached_staged_update(&cache_stage_dir, &cache_latest)
        })
        .await?
    {
        let receipt_stage_dir = stage_dir.clone();
        owner
            .blocking("commit cached system metadata", move || {
                ensure_no_pending_system_update()?;
                let mut archive = StageDirectory::open(&receipt_stage_dir)?
                    .open_archive(&verified.latest.name)?;
                let mut snapshot =
                    freeze_system_archive(&mut archive, &receipt_stage_dir, &verified.latest)?;
                let _checked = bundle::capture(
                    &mut snapshot,
                    &StageDirectory::open(&receipt_stage_dir)?,
                    &verified.latest,
                )?;
                persist_verified_system_metadata(&verified)
            })
            .await?;
        remove_update_progress(&stage_dir)?;
        return Ok(Json(ApiResponse::ok(SystemDownloadRsp {
            current,
            latest,
            staged,
        })));
    }

    let prepare_dir = stage_dir.clone();
    owner
        .blocking("prepare system update staging", move || {
            prepare_stage_dir(&prepare_dir)
        })
        .await?;

    write_update_progress(
        &stage_dir,
        SystemUpdateProgress::new(
            "download",
            "downloading",
            Some(latest.version.clone()),
            None,
        ),
    )?;

    let mut downloaded = match download_system_asset(&latest, &stage_dir).await {
        Ok(downloaded) => downloaded,
        Err(err) => {
            let _ = write_update_progress(
                &stage_dir,
                SystemUpdateProgress::new(
                    "download",
                    "failed",
                    Some(latest.version.clone()),
                    Some("download failed".to_string()),
                ),
            );
            return Err(err);
        }
    };

    write_update_progress(
        &stage_dir,
        SystemUpdateProgress::new("download", "verifying", Some(latest.version.clone()), None),
    )?;

    let stage_dir_for_verify = stage_dir.clone();
    let staged = match owner
        .blocking("verify and stage system update", move || {
            ensure_no_pending_system_update()?;
            let mut snapshot = freeze_system_archive(
                downloaded.file_mut(),
                &stage_dir_for_verify,
                &verified.latest,
            )?;
            downloaded.publish(&verified.latest.name)?;

            let (manifest, _raw_images) = extract_and_verify_system_bundle(
                &mut snapshot,
                &stage_dir_for_verify,
                &verified.latest,
            )?;
            let record = SystemStageRecord {
                staged_at: now_unix_seconds(),
                latest: verified.latest.clone(),
                manifest,
            };
            write_stage_record(&stage_dir_for_verify, &record)?;
            // Publish authority last, after archive/manifest checks. A crash
            // with mismatched generations fails closed and requires re-download.
            persist_verified_system_metadata(&verified)?;
            Ok(staged_summary(&record))
        })
        .await
    {
        Ok(staged) => staged,
        Err(err) => {
            let _ = write_update_progress(
                &stage_dir,
                SystemUpdateProgress::new(
                    "download",
                    "failed",
                    Some(latest.version.clone()),
                    Some("verification failed".to_string()),
                ),
            );
            return Err(err);
        }
    };

    remove_update_progress(&stage_dir)?;

    Ok(Json(ApiResponse::ok(SystemDownloadRsp {
        current,
        latest,
        staged,
    })))
}

pub async fn install(State(state): State<AppState>) -> Result<Json<ApiResponse<SystemInstallRsp>>> {
    let owner = state.updates.acquire(Kind::SystemInstall)?;
    owner.run(move |job| install_owned(state, job)).await
}

async fn install_owned(
    state: AppState,
    owner: UpdateOwner,
) -> Result<Json<ApiResponse<SystemInstallRsp>>> {
    ensure_no_pending_system_update()?;
    let stage_dir = system_stage_dir(&state.config.paths.update_cache_dir);
    let progress_stage_dir = stage_dir.clone();
    let staged_version = read_staged_update(&stage_dir)
        .ok()
        .flatten()
        .map(|staged| staged.version);
    // Use the running identity, not a fresh YAML read: Config::read() does not
    // materialize a session secret from session_secret_file. Raw capture
    // compares the running secret with the on-disk identity and otherwise
    // refuses an update on a valid installation whose YAML secret is empty.
    let config = state.config.clone();
    let receipt = {
        let store =
            MetadataStore::open().map_err(|error| AppError::BadRequest(error.to_string()))?;
        required_system_metadata_receipt(&store)?
    };
    let verified = authenticate_stored_system_metadata(receipt, &config).await?;
    if verified.latest.target != read_current_system_version().target {
        return Err(AppError::BadRequest(
            "system update target no longer matches the device".to_string(),
        ));
    }
    write_update_progress(
        &stage_dir,
        SystemUpdateProgress::new(
            "install",
            "starting",
            staged_version.clone(),
            Some("starting system update install".to_string()),
        ),
    )?;
    let install_error_version = staged_version.clone();
    let staged = read_stage_record(&stage_dir)?
        .ok_or_else(|| AppError::BadRequest("no staged system update".to_string()))?;
    let raw = if staged.manifest.raw_images.is_empty() {
        None
    } else {
        Some((
            owner.clone_for_work(),
            state.drain_writers(WRITER_DRAIN_TIMEOUT).await?,
        ))
    };
    let installed = match owner
        .blocking(
            "install staged system update",
            move || match install_staged_update(&stage_dir, &config, verified, raw) {
                Ok(installed) => Ok(installed),
                Err(err) => {
                    let _ = write_update_progress(
                        &stage_dir,
                        SystemUpdateProgress::new(
                            "install",
                            "failed",
                            install_error_version,
                            Some(err.to_string()),
                        ),
                    );
                    Err(err)
                }
            },
        )
        .await
    {
        Ok(installed) => installed,
        Err(err) => {
            let _ = write_update_progress(
                &progress_stage_dir,
                SystemUpdateProgress::new(
                    "install",
                    "failed",
                    staged_version,
                    Some(err.to_string()),
                ),
            );
            return Err(err);
        }
    };

    Ok(Json(ApiResponse::ok(SystemInstallRsp {
        current: read_current_system_version(),
        reboot_required: installed.requires_reboot,
        installed,
    })))
}

pub async fn rollback(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<SystemRollbackRsp>>> {
    let owner = state.updates.acquire(Kind::SystemRollback)?;
    let stage_dir = system_stage_dir(&state.config.paths.update_cache_dir);
    owner
        .run(move |job| async move {
            let restored = job
                .blocking("rollback system update", move || {
                    rollback_last_system_update(&stage_dir)
                })
                .await?;
            Ok(Json(ApiResponse::ok(SystemRollbackRsp {
                reboot_required: restored.requires_reboot,
                restored,
            })))
        })
        .await
}

pub async fn confirm(State(state): State<AppState>) -> Result<Json<ApiResponse<SystemConfirmRsp>>> {
    let owner = state.updates.acquire(Kind::SystemConfirm)?;
    owner
        .run(move |job| async move {
            job.blocking("confirm system update", move || {
                let current = read_current_system_version();
                let pending =
                    read_pending_update(Path::new(SYSTEM_PENDING_FILE))?.ok_or_else(|| {
                        AppError::NotFound("no pending system update found".to_string())
                    })?;
                let health = evaluate_boot_health(&current, &pending, &state);

                if !health.healthy {
                    return Err(AppError::BadRequest(
                        if pending.requires_reboot && !health.rebooted {
                            "reboot the device before confirming the system update"
                        } else {
                            "system update boot health check failed"
                        }
                        .to_string(),
                    ));
                }

                write_boot_good(&pending, &health)?;
                remove_file_if_exists(Path::new(SYSTEM_PENDING_FILE))?;
                remove_update_progress(&system_stage_dir(&state.config.paths.update_cache_dir))?;

                Ok(Json(ApiResponse::ok(SystemConfirmRsp {
                    confirmed: pending,
                    health,
                })))
            })
            .await
        })
        .await
}

async fn get_latest_system(preview: bool, config: &Config) -> Result<SystemLatest> {
    Ok(get_verified_latest_system(preview, config).await?.latest)
}

async fn get_verified_latest_system(
    preview: bool,
    config: &Config,
) -> Result<VerifiedSystemMetadata> {
    if preview {
        match fetch_latest_system(GITHUB_SYSTEM_PREVIEW_JSON, config).await {
            Ok(preview_latest) => {
                match fetch_latest_system(GITHUB_SYSTEM_LATEST_JSON, config).await {
                    Ok(stable_latest) => {
                        return Ok(newer_system_release(preview_latest, stable_latest));
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "failed to query stable system release metadata, using preview"
                        );
                        return Ok(preview_latest);
                    }
                }
            }
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

fn newer_system_release(
    left: VerifiedSystemMetadata,
    right: VerifiedSystemMetadata,
) -> VerifiedSystemMetadata {
    match compare_system_versions(&left.latest.version, &right.latest.version) {
        Some(Ordering::Less) => right,
        _ => left,
    }
}

async fn fetch_latest_system(url: &str, config: &Config) -> Result<VerifiedSystemMetadata> {
    validate_metadata_url(url)?;
    let metadata = fetch_system_metadata(url).await?;

    let latest = parse_exact_system_metadata(&metadata)?;
    let signature = enforce_system_metadata_signature(url, &metadata, &latest, config).await?;
    Ok(VerifiedSystemMetadata {
        latest,
        metadata,
        signature,
    })
}

fn parse_exact_system_metadata(metadata: &[u8]) -> Result<SystemLatest> {
    if metadata.is_empty() || metadata.len() > MAX_METADATA {
        return Err(AppError::BadRequest(
            "invalid system update metadata size".to_string(),
        ));
    }
    let latest = serde_json::from_slice(metadata)
        .map_err(|_| AppError::BadRequest("invalid system update metadata".to_string()))?;
    validate_latest_system(&latest)?;
    Ok(latest)
}

fn persist_verified_system_metadata(verified: &VerifiedSystemMetadata) -> Result<()> {
    let store = MetadataStore::open().map_err(|error| AppError::BadRequest(error.to_string()))?;
    store
        .replace(&verified.metadata, &verified.signature)
        .map_err(|error| AppError::BadRequest(error.to_string()))
}

fn required_system_metadata_receipt(store: &MetadataStore) -> Result<MetadataReceipt> {
    store
        .read()
        .map_err(|error| AppError::BadRequest(error.to_string()))?
        .ok_or_else(|| {
            AppError::BadRequest(
                "no protected system update metadata; run Download and Verify again".to_string(),
            )
        })
}

async fn authenticate_stored_system_metadata(
    receipt: MetadataReceipt,
    config: &Config,
) -> Result<VerifiedSystemMetadata> {
    let latest = parse_exact_system_metadata(&receipt.metadata)?;
    verify_system_metadata_with_policy(&receipt.metadata, &receipt.signature, &latest, config)
        .await?;
    Ok(VerifiedSystemMetadata {
        latest,
        metadata: receipt.metadata,
        signature: receipt.signature,
    })
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
) -> Result<Vec<u8>> {
    let signature = if system_metadata_is_unsigned(latest) {
        Vec::new()
    } else {
        let signature_url = metadata_signature_url(metadata_url)?;
        fetch_system_metadata_signature(&signature_url).await?
    };
    verify_system_metadata_with_policy(metadata, &signature, latest, config).await?;
    Ok(signature)
}

async fn verify_system_metadata_with_policy(
    metadata: &[u8],
    signature: &[u8],
    latest: &SystemLatest,
    config: &Config,
) -> Result<()> {
    if system_metadata_is_unsigned(latest) {
        if !signature.is_empty() {
            return Err(AppError::BadRequest(
                "unsigned system metadata cannot carry a signature receipt".to_string(),
            ));
        }
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
    if signature.is_empty() || signature.len() > MAX_SIGNATURE {
        return Err(AppError::BadRequest(
            "invalid system update metadata signature size".to_string(),
        ));
    }
    verify_metadata_signature(
        metadata,
        signature,
        &config.paths.system_update_public_key,
        &latest.signature_key_id,
        METADATA_TIMEOUT,
    )
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

fn metadata_signature_url(metadata_url: &str) -> Result<String> {
    validate_metadata_url(metadata_url)?;
    Ok(format!("{metadata_url}.sig"))
}

fn system_metadata_is_unsigned(latest: &SystemLatest) -> bool {
    latest.signature_algorithm == SYSTEM_UPDATE_UNSIGNED_ALGORITHM
        && latest.signature_key_id == SYSTEM_UPDATE_UNSIGNED_ALGORITHM
}

async fn download_system_asset(latest: &SystemLatest, stage: &Path) -> Result<StagedDownload> {
    if latest.size == 0 || latest.size > MAX_SYSTEM_UPDATE_BYTES {
        return Err(AppError::BadRequest(
            "invalid system update archive size".to_string(),
        ));
    }
    let downloaded = StageDirectory::open(stage)?.create_download()?;
    // No output pathname, curlrc, shell or inherited stdin. Curl cannot follow
    // an archive-name symlink. Retries require a fresh descriptor/empty file;
    // never let a stdout retry append a second response to the same archive.
    let mut command = tokio::process::Command::new("/usr/bin/curl");
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
        latest.url.as_str(),
    ]);
    receive_system_archive(&mut command, latest.size, &downloaded, DOWNLOAD_TIMEOUT).await?;
    Ok(downloaded)
}

async fn receive_system_archive(
    command: &mut tokio::process::Command,
    size: u64,
    downloaded: &StagedDownload,
    deadline: Duration,
) -> Result<()> {
    let mut destination = tokio::fs::File::from_std(downloaded.writer()?);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut source = child
        .stdout
        .take()
        .ok_or_else(|| AppError::Internal("missing archive stream".into()))?;
    let result = tokio::time::timeout(deadline, async {
        let (_, status) = tokio::try_join!(
            copy_system_archive(&mut source, &mut destination, size),
            async { child.wait().await.map_err(AppError::from) },
        )?;
        if !status.success() {
            return Err(AppError::BadRequest(
                "download system update archive failed".into(),
            ));
        }
        Ok(())
    })
    .await
    .unwrap_or_else(|_| {
        Err(AppError::Internal(
            "system archive download timed out".into(),
        ))
    });
    if result.is_err() {
        // Stop/reap the one fixed direct child, including size-limit failures.
        // Cancellation also drops kill_on_drop. No detached transfer task or
        // external child owns the destination; Tokio may finish one in-flight
        // bounded filesystem write to the now-unlinked owned temporary inode.
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

async fn copy_system_archive(
    source: &mut (impl tokio::io::AsyncRead + Unpin),
    destination: &mut (impl tokio::io::AsyncWrite + Unpin),
    size: u64,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        if count as u64 > remaining {
            return Err(AppError::BadRequest(
                "system update archive exceeds signed size".into(),
            ));
        }
        destination.write_all(&buffer[..count]).await?;
        remaining -= count as u64;
    }
    if remaining != 0 {
        return Err(AppError::BadRequest(
            "system update archive is shorter than signed size".into(),
        ));
    }
    destination.flush().await?;
    Ok(())
}

fn read_current_system_version() -> SystemVersion {
    let mut version = SystemVersion {
        version: DEFAULT_SYSTEM_VERSION.to_string(),
        target: DEFAULT_SYSTEM_TARGET.to_string(),
        base_version: read_trimmed(BOOT_VERSION_FILE).unwrap_or_default(),
        kernel_version: read_trimmed(KERNEL_RELEASE_FILE).unwrap_or_default(),
        rootfs_version: read_rootfs_version(),
        security_patch_level: None,
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
                version.security_patch_level = non_empty(persisted.security_patch_level);
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

fn read_cached_staged_update(
    stage_dir: &Path,
    latest: &SystemLatest,
) -> Result<Option<SystemStagedUpdate>> {
    let record = match read_stage_record(stage_dir) {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(None),
        Err(_) => {
            // A legacy/malformed p3 receipt is not authority and cannot prevent
            // a fresh authenticated download. Do not delete its recovery data.
            tracing::warn!("invalid cached system staging cannot be reused");
            return Ok(None);
        }
    };
    if record.latest != *latest {
        return Ok(None);
    }
    let Some(staged) = read_staged_update(stage_dir)? else {
        return Ok(None);
    };

    let reusable = (|| {
        let mut archive = StageDirectory::open(stage_dir)?.open_archive(&latest.name)?;
        verify_system_archive(&mut archive, latest)?;
        validate_cached_system_extract(stage_dir, &record)
    })();
    match reusable {
        Ok(()) => Ok(Some(staged)),
        Err(err) => {
            tracing::warn!(error = %err, "cached staged system update is not reusable");
            Ok(None)
        }
    }
}

fn validate_cached_system_extract(stage_dir: &Path, record: &SystemStageRecord) -> Result<()> {
    let extract_dir = stage_dir.join(SYSTEM_EXTRACT_DIR_NAME);
    validate_system_extract_root(&extract_dir)?;

    let manifest_path = extract_dir.join("manifest.json");
    let manifest: SystemManifest = serde_json::from_slice(&fs::read(&manifest_path)?)
        .map_err(|err| AppError::BadRequest(format!("invalid system update manifest: {err}")))?;
    if manifest != record.manifest {
        return Err(AppError::BadRequest(
            "cached system update manifest does not match staged record".to_string(),
        ));
    }

    let payload_dir = extract_dir.join("payload");
    validate_system_manifest(&record.manifest, &record.latest, &payload_dir)
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
    match latest.format {
        SYSTEM_UPDATE_METADATA_FORMAT_V1 => {
            if latest.required_app_version.is_some() {
                return Err(AppError::BadRequest(
                    "system update metadata v1 cannot require an application version".to_string(),
                ));
            }
        }
        SYSTEM_UPDATE_METADATA_FORMAT_V2 => {
            let required = latest.required_app_version.as_deref().ok_or_else(|| {
                AppError::BadRequest(
                    "system update metadata v2 requires required_app_version".to_string(),
                )
            })?;
            validate_application_version("required_app_version", required)?;
        }
        _ => {
            return Err(AppError::BadRequest(format!(
                "unsupported system update format: {}",
                latest.format
            )));
        }
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

fn validate_application_version(name: &str, version: &str) -> Result<()> {
    validate_token(name, version)?;
    if compare_application_versions(version, version).is_none() {
        return Err(AppError::BadRequest(format!("{name} must be semver x.y.z")));
    }
    Ok(())
}

fn application_requirement_error(latest: &SystemLatest) -> Option<String> {
    let current = current_app_version();
    application_requirement_error_for(&current, latest)
}

fn application_requirement_error_for(current: &str, latest: &SystemLatest) -> Option<String> {
    let required = latest.required_app_version.as_deref()?;
    match compare_application_versions(current, required) {
        Some(Ordering::Less) => Some(format!(
            "application update required: current {current}, required {required}"
        )),
        Some(_) => None,
        None => Some(format!(
            "cannot compare application versions: current {current}, required {required}"
        )),
    }
}

fn enforce_required_application_version(latest: &SystemLatest) -> Result<()> {
    if let Some(error) = application_requirement_error(latest) {
        return Err(AppError::BadRequest(error));
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

fn verify_system_archive(file: &mut fs::File, latest: &SystemLatest) -> Result<()> {
    if file.metadata()?.len() != latest.size
        || latest.size == 0
        || latest.size > MAX_SYSTEM_UPDATE_BYTES
    {
        return Err(AppError::BadRequest(
            "system update archive size mismatch".into(),
        ));
    }
    file.rewind()?;
    let hashes = hash_reader(&mut (&mut *file).take(latest.size + 1))?;
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
    file.rewind()?;
    Ok(())
}

fn freeze_system_archive(
    source: &mut fs::File,
    stage_dir: &Path,
    latest: &SystemLatest,
) -> Result<PublicSnapshot> {
    if source.metadata()?.len() != latest.size {
        return Err(AppError::BadRequest(
            "system update archive size mismatch".into(),
        ));
    }
    validate_sha256_hex(&latest.sha256)?;
    let mut sha256 = [0_u8; 32];
    for (byte, hex) in sha256
        .iter_mut()
        .zip(latest.sha256.as_bytes().as_chunks::<2>().0)
    {
        let hex = std::str::from_utf8(hex)
            .map_err(|_| AppError::BadRequest("invalid system update sha256".into()))?;
        *byte = u8::from_str_radix(hex, 16)
            .map_err(|_| AppError::BadRequest("invalid system update sha256".into()))?;
    }
    let sha512: [u8; 64] = STANDARD
        .decode(&latest.sha512)
        .map_err(|_| AppError::BadRequest("invalid system update sha512".into()))?
        .try_into()
        .map_err(|_| AppError::BadRequest("invalid system update sha512".into()))?;
    source.rewind()?;
    PublicSnapshot::capture(
        &StageDirectory::open(stage_dir)?,
        source,
        latest.size,
        &sha256,
        &sha512,
    )
    .map_err(|error| AppError::BadRequest(error.to_string()))
}

fn extract_and_verify_system_bundle(
    archive: &mut PublicSnapshot,
    stage_dir: &Path,
    latest: &SystemLatest,
) -> Result<(SystemManifest, Option<[PublicSnapshot; 2]>)> {
    let bundle::BundlePreflight {
        manifest,
        raw_images,
    } = bundle::capture(archive, &StageDirectory::open(stage_dir)?, latest)?;
    // Raw images stay as the authenticated anonymous descriptors the writer
    // consumes. File updates do not retain the unused snapshots.
    archive.rewind()?;
    let extract_dir = stage_dir.join(SYSTEM_EXTRACT_DIR_NAME);
    remove_dir_if_exists(&extract_dir)?;
    fs::create_dir_all(&extract_dir)?;
    extract_tar_gz_reader(archive, &extract_dir)?;

    validate_system_extract_root(&extract_dir)?;

    // The extracted manifest is not input: the only manifest parsed above
    // came directly from the authenticated, bounded anonymous snapshot.
    let payload_dir = extract_dir.join("payload");
    validate_system_manifest(&manifest, latest, &payload_dir)?;

    Ok((manifest, raw_images))
}

fn install_staged_update(
    stage_dir: &Path,
    config: &Config,
    verified: VerifiedSystemMetadata,
    raw: Option<(UpdateOwner, crate::update::state_writers::WriterDrain)>,
) -> Result<SystemPendingUpdate> {
    let record = read_stage_record(stage_dir)?
        .ok_or_else(|| AppError::BadRequest("no staged system update".to_string()))?;
    if record.latest != verified.latest {
        return Err(AppError::BadRequest("staged system update differs from authenticated metadata; run Download and Verify again".to_string()));
    }
    ensure_no_pending_system_update()?;
    let latest = verified.latest;
    enforce_required_application_version(&latest)?;

    let mut source = StageDirectory::open(stage_dir)?.open_archive(&latest.name)?;
    write_update_progress(
        stage_dir,
        SystemUpdateProgress::new(
            "install",
            "verifying",
            Some(record.latest.version.clone()),
            Some("verifying staged system update archive".to_string()),
        ),
    )?;
    let mut archive = freeze_system_archive(&mut source, stage_dir, &latest)?;
    drop(source);
    write_update_progress(
        stage_dir,
        SystemUpdateProgress::new(
            "install",
            "extracting",
            Some(record.latest.version.clone()),
            Some("extracting staged system update payload".to_string()),
        ),
    )?;
    let (manifest, raw_images) =
        extract_and_verify_system_bundle(&mut archive, stage_dir, &latest)?;
    let payload_dir = stage_dir.join(SYSTEM_EXTRACT_DIR_NAME).join("payload");

    write_update_progress(
        stage_dir,
        SystemUpdateProgress::new("install", "preparing", Some(manifest.version.clone()), None),
    )?;

    if !manifest.raw_images.is_empty() {
        let images = raw_images.ok_or_else(|| {
            AppError::Internal("authenticated raw images were not retained".into())
        })?;
        let (owner, writers) = raw.ok_or_else(|| {
            AppError::Internal("raw install requires retained owner and writer drain".into())
        })?;
        return install_raw_image_update(
            stage_dir,
            &manifest,
            &payload_dir,
            config,
            images,
            owner,
            writers,
        );
    }

    let install_boot_id = current_boot_id()?;
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
        install_boot_id: Some(install_boot_id),
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
        let _ = write_update_progress(
            stage_dir,
            SystemUpdateProgress::new(
                "install",
                "failed",
                Some(manifest.version.clone()),
                Some(err.to_string()),
            ),
        );
        return Err(err);
    }

    remove_update_progress(stage_dir)?;
    Ok(pending_update(&install_record))
}

fn install_raw_image_update(
    _stage_dir: &Path,
    manifest: &SystemManifest,
    _payload_dir: &Path,
    config: &Config,
    images: [PublicSnapshot; 2],
    owner: UpdateOwner,
    writers: crate::update::state_writers::WriterDrain,
) -> Result<SystemPendingUpdate> {
    validate_raw_install(config, manifest)?;

    let staging = Path::new(RAW_PRIVATE_STAGING);
    let mountpoint = staging.join("mount");
    let ssh_roots = staging.join("ssh");
    ensure_private_directory(staging, true)?;
    ensure_private_directory(&mountpoint, true)?;
    ensure_private_directory(&ssh_roots, true)?;
    if fs::read_dir(&mountpoint)?.next().is_some() || fs::read_dir(&ssh_roots)?.next().is_some() {
        return Err(AppError::Conflict(
            "raw capture staging is not empty; recovery evidence was retained".into(),
        ));
    }
    let capsules = ensure_private_directory(Path::new(RAW_CAPSULE_DIR), false)?;

    let boot = raw_image(manifest, "BOOT")?;
    let rootfs = raw_image(manifest, "ROOTFS")?;
    let sizes = [boot.size, rootfs.size];
    let sha256 = [decode_sha256(&boot.sha256)?, decode_sha256(&rootfs.sha256)?];
    let image_files = [images[0].file().try_clone()?, images[1].file().try_clone()?];
    let raw_images = RawImages {
        files: [images[0].file().try_clone()?, images[1].file().try_clone()?],
        sizes,
        sha256,
    };

    let helper = PinnedSshHelper::embedded(staging)
        .map_err(|error| AppError::Internal(format!("pinned SSH helper unavailable: {error}")))?;
    let mut seed = [0_u8; 16];
    OsRng.fill_bytes(&mut seed);
    if seed == [0; 16] {
        seed[0] = 1;
    }
    let transfer = TransferContext::new(seed, &manifest.version, sizes)
        .map_err(|error| AppError::Internal(format!("raw transfer context invalid: {error}")))?;
    let hostname = fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "nanokvm".to_string());
    let mut image = raw_capture::SandboxImage {
        helper: &helper,
        images: &image_files,
        transfer: &transfer,
        mountpoint: &mountpoint,
        ssh_roots: &ssh_roots,
        hostname: &hostname,
    };
    let target_app = manifest
        .required_app_version
        .clone()
        .unwrap_or_else(current_app_version);
    let request = CaptureRequest {
        source_root: Path::new("/"),
        private_staging: staging,
        capsule_directory: &capsules,
        config,
        working_dir: Path::new("/etc/kvm"),
        config_path: Path::new("/etc/kvm/server.yaml"),
        target_version: &manifest.version,
        target_app_version: &target_app,
        target: &manifest.target,
        boot_image_sha256: sha256[0],
        rootfs_image_sha256: sha256[1],
        source_boot: BootId::parse(&current_boot_id()?)
            .map_err(|_| AppError::Internal("invalid kernel boot ID".into()))?,
        device_id: crate::update::restore_capsule::ticket::device_id()
            .map_err(|error| AppError::Internal(format!("device identity unavailable: {error}")))?,
    };
    let publish = |ticket: &RestoreTicket| -> Result<()> {
        let mut store = Store::open_boot().map_err(|error| {
            AppError::Internal(format!("raw ticket store unavailable: {error}"))
        })?;
        publish_outgoing_ticket(
            Path::new("/"),
            &mut store,
            Path::new(RAW_CAPSULE_DIR),
            ticket,
        )
    };
    let send = move |transaction: [u8; 16], images: RawImages| -> Result<()> {
        let handoff = owner.prepare_raw_handoff(transaction, images, writers)?;
        RawSender::connect_broker()
            .map_err(|error| AppError::Conflict(format!("raw installer is not available: {error}")))?
            .send(handoff)
            .map_err(|error| {
                AppError::Internal(format!(
                    "the raw installer did not take update {:032x} ({error}); check its state, do not resubmit",
                    u128::from_be_bytes(transaction)
                ))
            })
    };
    let ticket = submit_raw_capture(&request, &mut image, raw_images, publish, send)?;
    Ok(SystemPendingUpdate {
        version: ticket.target_version().to_string(),
        target: manifest.target.clone(),
        backup_id: format!("raw-{:032x}", u128::from_be_bytes(ticket.transaction_id())),
        installed_at: now_unix_seconds(),
        requires_reboot: true,
        file_count: 0,
        install_boot_id: Some(current_boot_id()?),
    })
}

fn validate_raw_install(config: &Config, manifest: &SystemManifest) -> Result<()> {
    if !config.security.allow_raw_system_updates {
        return Err(AppError::Forbidden(
            "raw partition system updates are disabled".to_string(),
        ));
    }
    if !manifest.files.is_empty() {
        return Err(AppError::BadRequest(
            "raw partition system updates cannot mix file installs".to_string(),
        ));
    }
    Ok(())
}

/// The last local step before the handoff, reached only after every capture
/// refusal. The running system first stops needing the boot ticket, so an
/// attempt that never reaches the writer cannot keep it from booting; only then
/// is an older attempt retired and this one published in its place.
fn publish_outgoing_ticket(
    root: &Path,
    store: &mut Store,
    capsule_directory: &Path,
    ticket: &RestoreTicket,
) -> Result<()> {
    raw_restore::retire_required(root).map_err(|error| {
        AppError::Internal(format!("raw restore requirement was not retired: {error}"))
    })?;
    retire_prepared_ticket(store, capsule_directory)?;
    store
        .publish_prepared(ticket)
        .map_err(|error| AppError::Internal(format!("prepared ticket was not published: {error}")))
}

fn retire_prepared_ticket(store: &mut Store, capsule_directory: &Path) -> Result<()> {
    let Some(ticket) = store
        .load()
        .map_err(|error| AppError::Internal(format!("raw ticket state is unreadable: {error}")))?
    else {
        return Ok(());
    };
    if ticket.phase() != Phase::Prepared {
        return Ok(());
    }
    store.abandon_prepared(&ticket).map_err(|error| {
        AppError::Internal(format!("stale raw ticket was not retired: {error}"))
    })?;
    let capsule = capsule_directory.join(format!(
        "{:032x}.capsule",
        u128::from_be_bytes(ticket.transaction_id())
    ));
    match fs::remove_file(&capsule) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(path = %capsule.display(), %error, "stale raw capsule was not removed");
        }
    }
    Ok(())
}

fn submit_raw_capture(
    request: &CaptureRequest<'_>,
    image: &mut impl TargetImage,
    raw_images: RawImages,
    publish: impl FnOnce(&RestoreTicket) -> Result<()>,
    send: impl FnOnce([u8; 16], RawImages) -> Result<()>,
) -> Result<RestoreTicket> {
    let cancel = AtomicBool::new(false);
    let captured = raw_capture::capture(request, image, &cancel)
        .map_err(|error| AppError::Internal(format!("raw capture failed: {error}")))?;
    let ticket = captured.into_ticket();
    publish(&ticket)?;
    send(ticket.transaction_id(), raw_images)?;
    Ok(ticket)
}

fn raw_image<'a>(manifest: &'a SystemManifest, label: &str) -> Result<&'a SystemManifestRawImage> {
    manifest
        .raw_images
        .iter()
        .find(|image| image.label == label)
        .ok_or_else(|| AppError::BadRequest("raw manifest is missing an image label".into()))
}

fn ensure_private_directory(path: &Path, on_root: bool) -> Result<fs::File> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o700
        || (on_root && metadata.dev() != fs::metadata("/")?.dev())
    {
        return Err(AppError::Internal(
            "raw capture directory is not private protected storage".into(),
        ));
    }
    Ok(fs::File::open(path)?)
}

#[cfg(test)]
fn raw_images_install_order(images: &[SystemManifestRawImage]) -> Vec<&SystemManifestRawImage> {
    let mut ordered: Vec<_> = images.iter().collect();
    ordered.sort_by_key(|image| match image.device.as_str() {
        RAW_ROOTFS_DEVICE => 0,
        RAW_BOOT_DEVICE => 1,
        _ => 2,
    });
    ordered
}

// Historical generator retained only to document/test the removed unsafe
// engine. No launcher exists and this code is absent from production builds.
#[cfg(test)]
fn raw_image_updater_script(
    stage_dir: &Path,
    manifest: &SystemManifest,
    payload_dir: &Path,
    pending: &SystemPendingUpdate,
) -> Result<String> {
    let busybox_path = Path::new(SYSTEM_RAW_INSTALL_RUN_DIR).join("busybox");
    let loader_path = Path::new(SYSTEM_RAW_INSTALL_RUN_DIR).join(SYSTEM_RAW_RUNTIME_LOADER);
    let busybox = shell_quote(&format!(
        "{} --library-path {} {}",
        path_arg(&loader_path)?,
        SYSTEM_RAW_INSTALL_RUN_DIR,
        path_arg(&busybox_path)?
    ));
    let log = shell_quote_path(Path::new(SYSTEM_RAW_INSTALL_LOG))?;
    let progress = shell_quote_path(&stage_dir.join(SYSTEM_PROGRESS_RECORD))?;
    let progress_dir = shell_quote_path(stage_dir)?;
    let version = shell_quote(&manifest.version);
    let boot_device = shell_quote_path(Path::new(RAW_BOOT_DEVICE))?;
    let root_device = shell_quote_path(Path::new(RAW_ROOTFS_DEVICE))?;
    let raw_marker = shell_quote_path(Path::new(SYSTEM_RAW_INSTALL_MARKER))?;
    let pending_file = shell_quote_path(Path::new(SYSTEM_PENDING_FILE))?;
    let started_at = pending.installed_at;

    let mut script = format!(
        "#!/bin/sh\n\
set -u\n\
BB={busybox}\n\
LOG={log}\n\
PROGRESS={progress}\n\
PROGRESS_DIR={progress_dir}\n\
VERSION={version}\n\
BOOT_DEVICE={boot_device}\n\
ROOT_DEVICE={root_device}\n\
STARTED_AT={started_at}\n\
RAW_WRITE_STARTED=0\n\
SERVICES_STOPPED=0\n\
RAW_PRESERVE_DIR=\"$PROGRESS_DIR/preserve\"\n\
BOOT_PRESERVE_DIR=\"$RAW_PRESERVE_DIR/boot\"\n\
BOOT_TMP_MOUNT=/tmp/hardened-boot-preserve-mount\n\
ROOT_PRESERVE_DIR=\"$RAW_PRESERVE_DIR/root\"\n\
ROOT_RESTORE_DONE=\"$PROGRESS_DIR/root-restore-done\"\n\
ROOT_TMP_MOUNT=/tmp/hardened-root-preserve-mount\n\
kmsg() {{\n\
  [ -w /dev/kmsg ] && $BB printf 'hardened-system-update: %s\\n' \"$1\" > /dev/kmsg || true\n\
}}\n\
log() {{\n\
  NOW=$($BB date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || $BB echo unknown)\n\
  $BB printf '%s %s\\n' \"$NOW\" \"$1\" >> \"$LOG\" || kmsg \"$1\"\n\
}}\n\
progress() {{\n\
  NOW=$($BB date +%s 2>/dev/null || $BB echo 0)\n\
  $BB mkdir -p \"$PROGRESS_DIR\" >/dev/null 2>&1 || true\n\
  $BB printf '{{\"operation\":\"install\",\"phase\":\"%s\",\"version\":\"%s\",\"startedAt\":%s,\"updatedAt\":%s,\"message\":\"%s\"}}\\n' \"$1\" \"$VERSION\" \"$STARTED_AT\" \"$NOW\" \"$2\" > \"$PROGRESS\" || true\n\
}}\n\
fail() {{\n\
  progress failed \"$1\"\n\
  log \"failed: $1\"\n\
  if [ \"$RAW_WRITE_STARTED\" = \"1\" ]; then\n\
    log 'raw write had started; rebooting instead of restarting services'\n\
    force_reboot_now\n\
    exit 1\n\
  fi\n\
  $BB rm -f {raw_marker} {pending_file} >/dev/null 2>&1 || true\n\
  if [ \"$SERVICES_STOPPED\" = \"1\" ]; then\n\
    log 'runtime services were stopped; rebooting to recover cleanly'\n\
    force_reboot_now\n\
    exit 1\n\
  fi\n\
  $BB mount -o remount,rw / >/dev/null 2>&1 || true\n\
  /etc/init.d/S95nanokvm start >/dev/null 2>&1 || true\n\
  exit 1\n\
}}\n\
force_reboot_now() {{\n\
  # After raw partition writes the current rootfs has been overwritten under\n\
  # the running kernel. Avoid execing /bin/busybox or /sbin/reboot from that\n\
  # filesystem; use shell builtins and kernel sysrq instead.\n\
  if [ -w /proc/sysrq-trigger ]; then\n\
    echo s > /proc/sysrq-trigger 2>/dev/null || true\n\
    echo u > /proc/sysrq-trigger 2>/dev/null || true\n\
    echo b > /proc/sysrq-trigger 2>/dev/null || true\n\
  fi\n\
  $BB sync >/dev/null 2>&1 || true\n\
  $BB reboot -f >/dev/null 2>&1 || $BB reboot >/dev/null 2>&1 || true\n\
}}\n\
root_is_ro() {{\n\
  while read DEV MNT TYPE OPTS REST; do\n\
    [ \"$MNT\" = '/' ] || continue\n\
    case \",$OPTS,\" in\n\
      *,ro,*) return 0 ;;\n\
      *) return 1 ;;\n\
    esac\n\
  done < /proc/mounts\n\
  return 1\n\
}}\n\
stop_update_runtime() {{\n\
  log 'stopping NanoKVM runtime'\n\
  SERVICES_STOPPED=1\n\
  for INIT in \\\n\
    /etc/init.d/S98tailscaled \\\n\
    /etc/init.d/S96picoclaw \\\n\
    /etc/init.d/S95nanokvm \\\n\
    /etc/init.d/S80dnsmasq \\\n\
    /etc/init.d/S50sshd \\\n\
    /etc/init.d/S50ssdpd \\\n\
    /etc/init.d/S50ser2net \\\n\
    /etc/init.d/S50avahi-daemon \\\n\
    /etc/init.d/S49ntp \\\n\
    /etc/init.d/S40bluetoothd \\\n\
    /etc/init.d/S30dbus \\\n\
    /etc/init.d/S21haveged \\\n\
    /etc/init.d/S10udev \\\n\
    /etc/init.d/S02klogd \\\n\
    /etc/init.d/S01syslogd; do\n\
    [ -x \"$INIT\" ] && \"$INIT\" stop >> \"$LOG\" 2>&1 || true\n\
  done\n\
  /etc/init.d/S95nanokvm stop >> \"$LOG\" 2>&1 || true\n\
  for PID_FILE in /tmp/nanokvm-watchdog.pid /tmp/system-update-watchdog.pid; do\n\
    if [ -f \"$PID_FILE\" ]; then\n\
      PID=$($BB cat \"$PID_FILE\" 2>/dev/null || true)\n\
      [ -n \"$PID\" ] && $BB kill \"$PID\" >/dev/null 2>&1 || true\n\
      $BB rm -f \"$PID_FILE\" >/dev/null 2>&1 || true\n\
    fi\n\
  done\n\
  for NAME in NanoKVM-Server kvm_system tailscaled picoclaw dnsmasq sshd ssdpd avahi-daemon ntpd bluetoothd dbus-daemon haveged input-event-daemon udevd syslogd klogd; do\n\
    $BB killall \"$NAME\" >/dev/null 2>&1 || true\n\
  done\n\
  $BB sleep 1\n\
  for NAME in NanoKVM-Server kvm_system tailscaled picoclaw dnsmasq sshd ssdpd avahi-daemon ntpd bluetoothd dbus-daemon haveged input-event-daemon udevd syslogd klogd; do\n\
    $BB killall -9 \"$NAME\" >/dev/null 2>&1 || true\n\
  done\n\
  for PROC in /proc/[0-9]*; do\n\
    PID=${{PROC##*/}}\n\
    CMD=$($BB tr '\\0' ' ' < \"$PROC/cmdline\" 2>/dev/null || true)\n\
    case \"$CMD\" in\n\
      *'/etc/init.d/S95nanokvm start'*) $BB kill -9 \"$PID\" >/dev/null 2>&1 || true ;;\n\
    esac\n\
  done\n\
  $BB rm -rf /tmp/kvm_system /tmp/server >/dev/null 2>&1 || true\n\
}}\n\
copy_boot_preserve_files() {{\n\
  SRC_DIR=\"$1\"\n\
  $BB mkdir -p \"$BOOT_PRESERVE_DIR\" >/dev/null 2>&1 || return\n\
  for NAME in eth.nodhcp resolv.conf resolv.conf.manual.bak eth.mac eth.ipv6.mode eth.ipv6 hostname hostname.prefix usb.vid usb.pid usb.wakeup usb.notwakeup usb.ncm usb.rndis0 usb.disk0 usb.disk0.ro disable_hid BIOS wifi.ssid wifi.pass wifi.nodhcp start_ssh_once logo.ico; do\n\
    [ -e \"$SRC_DIR/$NAME\" ] || continue\n\
    $BB cp -p \"$SRC_DIR/$NAME\" \"$BOOT_PRESERVE_DIR/$NAME\" >> \"$LOG\" 2>&1 || log \"failed to preserve boot file $NAME\"\n\
  done\n\
}}\n\
preserve_boot_config() {{\n\
  progress writing 'preserving boot configuration'\n\
  log 'preserving boot configuration files'\n\
  $BB rm -rf \"$BOOT_PRESERVE_DIR\" \"$BOOT_TMP_MOUNT\" >/dev/null 2>&1 || true\n\
  if $BB grep -q ' /boot ' /proc/mounts >/dev/null 2>&1; then\n\
    copy_boot_preserve_files /boot\n\
    return\n\
  fi\n\
  $BB mkdir -p \"$BOOT_TMP_MOUNT\" >/dev/null 2>&1 || {{ log 'failed to create temporary boot mount'; return; }}\n\
  if $BB mount -t vfat \"$BOOT_DEVICE\" \"$BOOT_TMP_MOUNT\" >> \"$LOG\" 2>&1; then\n\
    copy_boot_preserve_files \"$BOOT_TMP_MOUNT\"\n\
    $BB umount \"$BOOT_TMP_MOUNT\" >> \"$LOG\" 2>&1 || true\n\
  else\n\
    log 'boot partition was not mounted; no boot configuration could be preserved'\n\
  fi\n\
}}\n\
restore_boot_config() {{\n\
  [ -d \"$BOOT_PRESERVE_DIR\" ] || return\n\
  $BB ls \"$BOOT_PRESERVE_DIR\" >/dev/null 2>&1 || return\n\
  progress writing 'restoring boot configuration'\n\
  log 'restoring boot configuration files'\n\
  $BB rm -rf \"$BOOT_TMP_MOUNT\" >/dev/null 2>&1 || true\n\
  $BB mkdir -p \"$BOOT_TMP_MOUNT\" >/dev/null 2>&1 || {{ log 'failed to create temporary boot restore mount'; return; }}\n\
  if $BB mount -t vfat \"$BOOT_DEVICE\" \"$BOOT_TMP_MOUNT\" >> \"$LOG\" 2>&1; then\n\
    for SRC in \"$BOOT_PRESERVE_DIR\"/*; do\n\
      [ -e \"$SRC\" ] || continue\n\
      NAME=$($BB basename \"$SRC\" 2>/dev/null || $BB echo '')\n\
      [ -n \"$NAME\" ] || continue\n\
      $BB cp -p \"$SRC\" \"$BOOT_TMP_MOUNT/$NAME\" >> \"$LOG\" 2>&1 || log \"failed to restore boot file $NAME\"\n\
    done\n\
    $BB sync\n\
    $BB umount \"$BOOT_TMP_MOUNT\" >> \"$LOG\" 2>&1 || true\n\
  else\n\
    log 'new boot partition could not be mounted for restoring preserved config'\n\
  fi\n\
}}\n\
preserve_path() {{\n\
  SRC=\"$1\"\n\
  DEST_ROOT=\"$2\"\n\
  [ -e \"$SRC\" ] || return\n\
  REL=${{SRC#/}}\n\
  DEST=\"$DEST_ROOT/$REL\"\n\
  DEST_DIR=${{DEST%/*}}\n\
  $BB mkdir -p \"$DEST_DIR\" >/dev/null 2>&1 || {{ log \"failed to create preserve directory for $SRC\"; return; }}\n\
  if [ -d \"$SRC\" ]; then\n\
    $BB rm -rf \"$DEST\" >/dev/null 2>&1 || true\n\
    $BB cp -a \"$SRC\" \"$DEST\" >> \"$LOG\" 2>&1 || log \"failed to preserve $SRC\"\n\
  else\n\
    $BB cp -p \"$SRC\" \"$DEST\" >> \"$LOG\" 2>&1 || log \"failed to preserve $SRC\"\n\
  fi\n\
}}\n\
restore_path() {{\n\
  REL=\"$1\"\n\
  SRC=\"$ROOT_PRESERVE_DIR/$REL\"\n\
  DEST=\"$ROOT_TMP_MOUNT/$REL\"\n\
  [ -e \"$SRC\" ] || return\n\
  DEST_DIR=${{DEST%/*}}\n\
  $BB mkdir -p \"$DEST_DIR\" >/dev/null 2>&1 || {{ log \"failed to create restore directory for $REL\"; return; }}\n\
  if [ -d \"$SRC\" ]; then\n\
    $BB mkdir -p \"$DEST\" >/dev/null 2>&1 || {{ log \"failed to create restore directory /$REL\"; return; }}\n\
    $BB cp -a \"$SRC/.\" \"$DEST/\" >> \"$LOG\" 2>&1 || log \"failed to restore /$REL\"\n\
  else\n\
    $BB rm -f \"$DEST\" >/dev/null 2>&1 || true\n\
    $BB cp -p \"$SRC\" \"$DEST\" >> \"$LOG\" 2>&1 || log \"failed to restore /$REL\"\n\
  fi\n\
}}\n\
drop_unsafe_preserved_kvm_state() {{\n\
  KVM_DIR=\"$ROOT_PRESERVE_DIR/etc/kvm\"\n\
  [ -d \"$KVM_DIR\" ] || return\n\
  $BB rm -f \\\n\
    \"$KVM_DIR/system-version.json\" \\\n\
    \"$KVM_DIR/system-update-pending.json\" \\\n\
    \"$KVM_DIR/system-update-last-backup.json\" \\\n\
    \"$KVM_DIR/system-update-boot-good.json\" \\\n\
    \"$KVM_DIR/system-update-rollback.sh\" \\\n\
    \"$KVM_DIR/system-update-rollback-attempted\" \\\n\
    \"$KVM_DIR/system-update-signing.pub.pem\" \\\n\
    >/dev/null 2>&1 || true\n\
}}\n\
preserve_root_config() {{\n\
  progress writing 'preserving rootfs configuration'\n\
  log 'preserving rootfs configuration files'\n\
  $BB rm -f \"$ROOT_RESTORE_DONE\" >/dev/null 2>&1 || true\n\
  $BB rm -rf \"$ROOT_PRESERVE_DIR\" \"$ROOT_TMP_MOUNT\" >/dev/null 2>&1 || true\n\
  for PATH_NAME in \\\n\
    /etc/kvm \\\n\
    /etc/default/syslogd \\\n\
    /etc/default/klogd \\\n\
    /etc/ssh \\\n\
    /etc/dropbear \\\n\
    /etc/passwd \\\n\
    /etc/shadow \\\n\
    /etc/group \\\n\
    /etc/gshadow \\\n\
    /etc/kvm.disk0 \\\n\
    /etc/hostname \\\n\
    /etc/machine-id \\\n\
    /etc/resolv.conf \\\n\
    /device_key \\\n\
    /root/.tailscale \\\n\
    /root/.picoclaw \\\n\
    /root/.picoclaw-cache \\\n\
    /var/lib/tailscale \\\n\
    /usr/bin/tailscale \\\n\
    /usr/sbin/tailscaled \\\n\
    /usr/bin/picoclaw \\\n\
    /etc/init.d/S96picoclaw \\\n\
    /etc/init.d/S98tailscaled \\\n\
    /etc/GOMEMLIMIT; do\n\
    preserve_path \"$PATH_NAME\" \"$ROOT_PRESERVE_DIR\"\n\
  done\n\
  drop_unsafe_preserved_kvm_state\n\
}}\n\
restore_root_config() {{\n\
  [ -d \"$ROOT_PRESERVE_DIR\" ] || return\n\
  $BB ls \"$ROOT_PRESERVE_DIR\" >/dev/null 2>&1 || return\n\
  progress writing 'restoring rootfs configuration'\n\
  log 'restoring rootfs configuration files'\n\
  $BB rm -rf \"$ROOT_TMP_MOUNT\" >/dev/null 2>&1 || true\n\
  $BB mkdir -p \"$ROOT_TMP_MOUNT\" >/dev/null 2>&1 || {{ log 'failed to create temporary rootfs restore mount'; return; }}\n\
  if $BB mount -t ext4 \"$ROOT_DEVICE\" \"$ROOT_TMP_MOUNT\" >> \"$LOG\" 2>&1; then\n\
    for REL in \\\n\
      etc/kvm \\\n\
      etc/default/syslogd \\\n\
      etc/default/klogd \\\n\
      etc/ssh \\\n\
      etc/dropbear \\\n\
      etc/passwd \\\n\
      etc/shadow \\\n\
      etc/group \\\n\
      etc/gshadow \\\n\
      etc/kvm.disk0 \\\n\
      etc/hostname \\\n\
      etc/machine-id \\\n\
      etc/resolv.conf \\\n\
      device_key \\\n\
      root/.tailscale \\\n\
      root/.picoclaw \\\n\
      root/.picoclaw-cache \\\n\
      var/lib/tailscale \\\n\
      usr/bin/tailscale \\\n\
      usr/sbin/tailscaled \\\n\
      usr/bin/picoclaw \\\n\
      etc/init.d/S96picoclaw \\\n\
      etc/init.d/S98tailscaled \\\n\
      etc/GOMEMLIMIT; do\n\
      restore_path \"$REL\"\n\
    done\n\
    $BB sync\n\
    $BB umount \"$ROOT_TMP_MOUNT\" >> \"$LOG\" 2>&1 || true\n\
  else\n\
    log 'new rootfs partition could not be mounted for restoring preserved config'\n\
  fi\n\
}}\n\
prepare_boot_readonly() {{\n\
  if $BB grep -q ' /boot ' /proc/mounts >/dev/null 2>&1; then\n\
    log 'preparing /boot read-only'\n\
    $BB umount /boot >> \"$LOG\" 2>&1 || $BB mount -o remount,ro /boot >> \"$LOG\" 2>&1 || true\n\
  fi\n\
}}\n\
force_root_readonly() {{\n\
  progress writing 'remounting rootfs read-only'\n\
  log 'attempting rootfs read-only remount'\n\
  REMOUNT_ERR=$($BB mount -o remount,ro / 2>&1)\n\
  REMOUNT_RC=$?\n\
  if [ \"$REMOUNT_RC\" = '0' ] || root_is_ro; then\n\
    log 'rootfs is read-only after normal remount'\n\
    return 0\n\
  fi\n\
  log \"normal rootfs read-only remount failed rc=$REMOUNT_RC: $REMOUNT_ERR\"\n\
  log 'rootfs users after failed remount:'\n\
  $BB fuser -m / >> \"$LOG\" 2>&1 || true\n\
  $BB lsof / >> \"$LOG\" 2>&1 || true\n\
  if [ -w /proc/sysrq-trigger ]; then\n\
    progress writing 'forcing read-only remount with sysrq'\n\
    log 'forcing read-only remount through sysrq u'\n\
    $BB sync\n\
    $BB echo u > /proc/sysrq-trigger\n\
    $BB sleep 3\n\
    if root_is_ro; then\n\
      log 'rootfs is read-only after sysrq remount'\n\
      return 0\n\
    fi\n\
    log 'sysrq remount did not make rootfs read-only'\n\
  else\n\
    log 'sysrq-trigger is unavailable'\n\
  fi\n\
  fail 'failed to remount rootfs read-only'\n\
}}\n\
cd /tmp || exit 1\n\
progress writing 'raw image write in progress'\n\
log 'raw system image update started'\n\
$BB sleep 2\n\
stop_update_runtime\n\
$BB sync\n\
preserve_boot_config\n\
preserve_root_config\n\
prepare_boot_readonly\n\
force_root_readonly\n"
    );

    for image in raw_images_install_order(&manifest.raw_images) {
        let payload = safe_payload_join(payload_dir, &image.payload)?;
        let payload = shell_quote_path(&payload)?;
        let device = shell_quote_path(Path::new(&image.device))?;
        let message = format!("writing {}", image.label);
        if raw_image_is_gzip(image) {
            script.push_str(&format!(
                "progress writing {}\n\
log 'testing compressed {} payload'\n\
$BB gzip -t {} >> \"$LOG\" 2>&1 || fail 'failed to verify compressed {}'\n\
log 'streaming compressed {} to {}'\n\
RAW_WRITE_STARTED=1\n\
$BB gzip -dc {} > {} || fail 'failed to write {}'\n\
$BB sync\n",
                shell_quote(&message),
                image.label,
                payload,
                image.label,
                image.label,
                image.device,
                payload,
                device,
                image.label
            ));
        } else {
            script.push_str(&format!(
                "progress writing {}\n\
log 'writing {} to {}'\n\
RAW_WRITE_STARTED=1\n\
$BB dd if={} of={} bs=4M conv=fsync >/dev/null 2>&1 || fail 'failed to write {}'\n",
                shell_quote(&message),
                image.label,
                image.device,
                payload,
                device,
                image.label
            ));
        }
        script.push_str(&format!("log '{} image write finished'\n", image.label));
    }

    script.push_str(
        "log 'rootfs configuration restore is deferred until first boot'\n\
restore_boot_config\n\
progress rebooting 'raw image write finished; rebooting'\n\
log 'raw system image update finished; rebooting'\n\
force_reboot_now\n",
    );

    Ok(script)
}

fn rollback_last_system_update(stage_dir: &Path) -> Result<SystemRollbackInfo> {
    write_update_progress(
        stage_dir,
        SystemUpdateProgress::new("rollback", "preparing", None, None),
    )?;
    let record = read_last_backup_record(stage_dir)?
        .ok_or_else(|| AppError::NotFound("no system update backup found".to_string()))?;
    if let Err(err) = rollback_from_record(stage_dir, &record) {
        let _ = write_update_progress(
            stage_dir,
            SystemUpdateProgress::new(
                "rollback",
                "failed",
                Some(record.version.clone()),
                Some(err.to_string()),
            ),
        );
        return Err(err);
    }
    remove_file_if_exists(Path::new(SYSTEM_PENDING_FILE))?;
    remove_file_if_exists(Path::new(SYSTEM_BOOT_GOOD_FILE))?;
    remove_file_if_exists(Path::new(SYSTEM_ROLLBACK_SCRIPT_FILE))?;
    remove_file_if_exists(Path::new(SYSTEM_ROLLBACK_ATTEMPT_FILE))?;
    remove_update_progress(stage_dir)?;
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
        security_patch_level: non_empty(manifest.security_patch_level.clone()),
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
        if total_size > MAX_SYSTEM_UPDATE_PAYLOAD_BYTES {
            return Err(AppError::BadRequest(
                "system update payload is too large".to_string(),
            ));
        }
    }

    for image in &manifest.raw_images {
        validate_raw_image_manifest(image)?;
        let payload_path = safe_payload_join(payload_dir, &image.payload)?;
        if !payload_path.is_file() {
            return Err(AppError::BadRequest(format!(
                "system update raw image is missing {}",
                image.payload
            )));
        }

        let metadata = fs::metadata(&payload_path)?;
        let expected_size = raw_image_payload_stored_size(image)?;
        if metadata.len() != expected_size {
            return Err(AppError::BadRequest(format!(
                "system update raw image size mismatch: {}",
                image.payload
            )));
        }
        // The outer archive is already verified against signed release metadata
        // before extraction. Re-hashing multi-GB raw images on SG2002 makes GUI
        // staging impractically slow, so raw payload validation is limited to
        // manifest shape, exact payload tree, and declared sizes.

        if !listed.insert(image.payload.clone()) {
            return Err(AppError::BadRequest(format!(
                "duplicate system update payload entry: {}",
                image.payload
            )));
        }
        total_size = total_size.saturating_add(image.size);
        if total_size > MAX_SYSTEM_UPDATE_PAYLOAD_BYTES {
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
    let expected_format = match latest.format {
        SYSTEM_UPDATE_METADATA_FORMAT_V1 => SYSTEM_UPDATE_MANIFEST_FORMAT_V1,
        SYSTEM_UPDATE_METADATA_FORMAT_V2 => SYSTEM_UPDATE_MANIFEST_FORMAT_V2,
        _ => {
            return Err(AppError::BadRequest(
                "unsupported system update metadata format".to_string(),
            ));
        }
    };
    if manifest.format != expected_format {
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
    if manifest.required_app_version != latest.required_app_version {
        return Err(AppError::BadRequest(
            "system update manifest required application version mismatch".to_string(),
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
    if manifest.files.is_empty() && manifest.raw_images.is_empty() {
        return Err(AppError::BadRequest(
            "system update manifest has no payload entries".to_string(),
        ));
    }
    if manifest.operations.is_empty() {
        return Err(AppError::BadRequest(
            "system update manifest has no operations".to_string(),
        ));
    }
    if !manifest.raw_images.is_empty() {
        if !manifest.requires_reboot {
            return Err(AppError::BadRequest(
                "raw system update images require reboot".to_string(),
            ));
        }
        if !manifest
            .operations
            .iter()
            .any(|operation| operation == "write-raw-devices")
        {
            return Err(AppError::BadRequest(
                "raw system update manifest must include write-raw-devices".to_string(),
            ));
        }
    }

    Ok(())
}

fn system_stage_dir(cache_dir: &Path) -> PathBuf {
    cache_dir.join(SYSTEM_STAGE_DIR_NAME)
}

fn system_update_is_newer(current: &SystemVersion, latest: &SystemLatest) -> bool {
    latest.target == current.target
        && compare_system_versions(&latest.version, &current.version) == Some(Ordering::Greater)
}

fn compare_system_versions(left: &str, right: &str) -> Option<Ordering> {
    let left = ParsedSystemVersion::parse(left)?;
    let right = ParsedSystemVersion::parse(right)?;
    Some(left.cmp(&right))
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedSystemVersion<'a> {
    core: Vec<u64>,
    suffix: Option<&'a str>,
}

impl<'a> ParsedSystemVersion<'a> {
    fn parse(version: &'a str) -> Option<Self> {
        let (core, suffix) = version
            .split_once('-')
            .map(|(core, suffix)| (core, Some(suffix)))
            .unwrap_or((version, None));
        let core = core
            .split('.')
            .map(|part| part.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()?;
        if core.is_empty() {
            return None;
        }
        Some(Self { core, suffix })
    }
}

impl Ord for ParsedSystemVersion<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        let segment_count = self.core.len().max(other.core.len());
        for index in 0..segment_count {
            let ordering = self
                .core
                .get(index)
                .copied()
                .unwrap_or_default()
                .cmp(&other.core.get(index).copied().unwrap_or_default());
            if ordering != Ordering::Equal {
                return ordering;
            }
        }

        match (self.suffix, other.suffix) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(left), Some(right)) => compare_version_suffix(left, right),
        }
    }
}

impl PartialOrd for ParsedSystemVersion<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_version_suffix(left: &str, right: &str) -> Ordering {
    let mut left_parts = left.split('.');
    let mut right_parts = right.split('.');

    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left), Some(right)) => {
                let ordering = compare_version_suffix_part(left, right);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
        }
    }
}

fn compare_version_suffix_part(left: &str, right: &str) -> Ordering {
    match (left.parse::<u64>(), right.parse::<u64>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => left.cmp(right),
    }
}

fn prepare_stage_dir(stage_dir: &Path) -> Result<()> {
    if stage_dir == Path::new("/") || stage_dir.as_os_str().is_empty() {
        return Err(AppError::Config(
            "invalid system update staging directory".to_string(),
        ));
    }
    // Old backups/preserve/unknown recovery material are not disposable cache.
    // New verified extraction replaces only its exact generated extract member.
    StageDirectory::prepare(stage_dir)?;
    Ok(())
}

fn ensure_no_pending_system_update() -> Result<()> {
    reject_pending_system_paths(&[
        Path::new(SYSTEM_PENDING_FILE),
        Path::new(SYSTEM_RAW_INSTALL_MARKER),
    ])
}

fn reject_pending_system_paths(paths: &[&Path]) -> Result<()> {
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(AppError::Conflict("unfinished system update or legacy raw state exists; inspect recovery status before another download/install".to_string())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_stage_record(stage_dir: &Path, record: &SystemStageRecord) -> Result<()> {
    let data = serde_json::to_vec_pretty(record)
        .map_err(|err| AppError::Internal(format!("encode staged system update: {err}")))?;
    StageDirectory::prepare(stage_dir)?.replace_generated(SYSTEM_STAGE_RECORD, &data)?;
    Ok(())
}

fn staged_summary(record: &SystemStageRecord) -> SystemStagedUpdate {
    let image_count = record.manifest.raw_images.len();
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
        security_patch_level: non_empty(record.manifest.security_patch_level.clone()),
        required_app_version: record.latest.required_app_version.clone(),
        required_free_bytes: record.manifest.required_free_bytes,
        requires_reboot: record.manifest.requires_reboot,
        file_count: record.manifest.files.len() + image_count,
        image_count,
        destructive: image_count > 0,
    }
}

fn staged_matches_current_system(staged: &SystemStagedUpdate, current: &SystemVersion) -> bool {
    staged.version == current.version && staged.target == current.target
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
        || !(path.starts_with("boot/")
            || path.starts_with("rootfs/")
            || path.starts_with("images/"))
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
    validate_absolute_install_path(install)?;
    Ok(())
}

fn validate_raw_image_manifest(image: &SystemManifestRawImage) -> Result<()> {
    validate_payload_path(&image.payload)?;
    validate_sha256_hex(&image.sha256)?;
    validate_text_field("raw_image_label", &image.label, 32)?;
    if image.size == 0 || image.size > MAX_SYSTEM_UPDATE_PAYLOAD_BYTES {
        return Err(AppError::BadRequest(
            "invalid system update raw image size".to_string(),
        ));
    }

    match image.compression.as_deref() {
        None => {
            if image.compressed_size.is_some() || image.compressed_sha256.is_some() {
                return Err(AppError::BadRequest(
                    "compressed raw image fields require compression".to_string(),
                ));
            }
        }
        Some("gzip") => {
            if !image.payload.ends_with(".gz") {
                return Err(AppError::BadRequest(
                    "gzip raw image payload must end with .gz".to_string(),
                ));
            }
            let compressed_size = image.compressed_size.ok_or_else(|| {
                AppError::BadRequest("missing compressed raw image size".to_string())
            })?;
            if compressed_size == 0 || compressed_size > MAX_SYSTEM_UPDATE_BYTES {
                return Err(AppError::BadRequest(
                    "invalid compressed raw image size".to_string(),
                ));
            }
            let compressed_sha256 = image.compressed_sha256.as_deref().ok_or_else(|| {
                AppError::BadRequest("missing compressed raw image sha256".to_string())
            })?;
            validate_sha256_hex(compressed_sha256)?;
        }
        Some(_) => {
            return Err(AppError::BadRequest(
                "unsupported raw image compression".to_string(),
            ));
        }
    }

    match (
        image.label.as_str(),
        image.payload.as_str(),
        image.device.as_str(),
    ) {
        ("BOOT", "images/boot.vfat", RAW_BOOT_DEVICE) => Ok(()),
        ("BOOT", "images/boot.vfat.gz", RAW_BOOT_DEVICE) => Ok(()),
        ("ROOTFS", "images/rootfs.sd", RAW_ROOTFS_DEVICE) => Ok(()),
        ("ROOTFS", "images/rootfs.sd.gz", RAW_ROOTFS_DEVICE) => Ok(()),
        _ => Err(AppError::BadRequest(
            "unsupported system update raw image target".to_string(),
        )),
    }
}

fn raw_image_payload_stored_size(image: &SystemManifestRawImage) -> Result<u64> {
    if image.compression.as_deref() == Some("gzip") {
        image
            .compressed_size
            .ok_or_else(|| AppError::BadRequest("missing compressed raw image size".to_string()))
    } else {
        Ok(image.size)
    }
}

#[cfg(test)]
fn raw_image_is_gzip(image: &SystemManifestRawImage) -> bool {
    image.compression.as_deref() == Some("gzip")
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

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    validate_sha256_hex(value)?;
    let mut result = [0_u8; 32];
    for (byte, pair) in result.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| AppError::BadRequest("invalid system update sha256".into()))?;
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| AppError::BadRequest("invalid system update sha256".into()))?;
    }
    Ok(result)
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
    hash_reader(&mut file)
}

fn hash_reader(file: &mut impl Read) -> Result<FileHashes> {
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

#[cfg(test)]
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

fn read_normalized_update_progress(
    stage_dir: &Path,
    current: &SystemVersion,
    pending: Option<&SystemPendingUpdate>,
    operation_active: bool,
) -> Option<SystemUpdateProgress> {
    let mut progress = match read_update_progress(stage_dir) {
        Ok(progress) => progress?,
        Err(err) => {
            tracing::warn!(error = %err, "failed to read system update progress");
            return None;
        }
    };

    if progress.operation == "install"
        && matches!(
            progress.phase.as_str(),
            "rebooting" | "writing" | "launching"
        )
        && pending
            .map(|pending| current.version == pending.version && current.target == pending.target)
            .unwrap_or(false)
    {
        return None;
    }

    if progress.operation == "install" && progress.phase == "failed" && progress.version.is_none() {
        return None;
    }

    let now = now_unix_seconds();
    let raw_install_stopped = progress.operation == "install"
        && progress.is_active()
        && pending
            .map(|pending| {
                pending.backup_id.starts_with("raw-")
                    && !(current.version == pending.version && current.target == pending.target)
            })
            .unwrap_or(false)
        && !raw_writer_active();
    if raw_install_stopped && !operation_active {
        progress.phase = "failed".to_string();
        progress.updated_at = now;
        progress.message = Some("raw system update writer stopped before reboot".to_string());
        return Some(progress);
    }

    let stale = progress
        .updated_at
        .checked_add(60 * 60)
        .map(|expires| expires < now)
        .unwrap_or(false);
    if progress.is_active() && !operation_active && (stale || progress.operation != "install") {
        progress.phase = "failed".to_string();
        progress.updated_at = now;
        progress.message = Some("system update operation did not complete".to_string());
    }

    Some(progress)
}

fn read_update_progress(stage_dir: &Path) -> Result<Option<SystemUpdateProgress>> {
    let path = stage_dir.join(SYSTEM_PROGRESS_RECORD);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path)?;
    let progress: SystemUpdateProgress = serde_json::from_slice(&raw)
        .map_err(|err| AppError::Internal(format!("invalid system update progress: {err}")))?;
    validate_update_progress(&progress)?;
    Ok(Some(progress))
}

fn write_update_progress(stage_dir: &Path, progress: SystemUpdateProgress) -> Result<()> {
    validate_update_progress(&progress)?;
    let data = serde_json::to_vec_pretty(&progress)
        .map_err(|err| AppError::Internal(format!("encode system update progress: {err}")))?;
    StageDirectory::prepare(stage_dir)?.replace_generated(SYSTEM_PROGRESS_RECORD, &data)?;
    Ok(())
}

fn remove_update_progress(stage_dir: &Path) -> Result<()> {
    match StageDirectory::open(stage_dir) {
        Ok(stage) => Ok(stage.remove_generated(SYSTEM_PROGRESS_RECORD)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_update_progress(progress: &SystemUpdateProgress) -> Result<()> {
    validate_token("system update progress operation", &progress.operation)?;
    validate_token("system update progress phase", &progress.phase)?;
    if let Some(version) = &progress.version {
        validate_token("system update progress version", version)?;
    }
    if let Some(message) = &progress.message {
        validate_text_field("system update progress message", message, 256)?;
    }
    Ok(())
}

fn raw_writer_active() -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }

        let cmdline_path = entry.path().join("cmdline");
        let Ok(cmdline) = fs::read(cmdline_path) else {
            continue;
        };
        if cmdline
            .windows(SYSTEM_RAW_INSTALL_RUN_DIR.len())
            .any(|window| window == SYSTEM_RAW_INSTALL_RUN_DIR.as_bytes())
        {
            return true;
        }
    }

    false
}

fn read_pending_status(
    pending_path: &Path,
    legacy_marker: &Path,
) -> (Option<SystemPendingUpdate>, Option<String>) {
    let (pending, pending_error) = match read_pending_update(pending_path) {
        Ok(pending) => (pending, None),
        Err(error) => (None, Some(error.to_string())),
    };
    // Any legacy p3 object is evidence to inspect, never pending/boot-good
    // authority. Do not open its contents, follow its target, or remove it.
    let legacy_error = reject_pending_system_paths(&[legacy_marker])
        .err()
        .map(|error| error.to_string());
    (pending, pending_error.or(legacy_error))
}

fn read_pending_update(path: &Path) -> Result<Option<SystemPendingUpdate>> {
    // Production callers pass only SYSTEM_PENDING_FILE on rootfs. There is no
    // p3 fallback. This bounded legacy file reader is NOT the future raw ticket
    // or app journal protocol, nor proof of provenance after a compromised boot.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_PENDING_UPDATE_BYTES {
        return Err(AppError::BadRequest(
            "pending system update is not a bounded regular record".into(),
        ));
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_PENDING_UPDATE_BYTES + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_PENDING_UPDATE_BYTES {
        return Err(AppError::BadRequest(
            "pending system update exceeds its size limit".into(),
        ));
    }
    let pending: SystemPendingUpdate = serde_json::from_slice(&raw)
        .map_err(|err| AppError::Internal(format!("invalid pending system update: {err}")))?;
    validate_pending_update(&pending)?;
    Ok(Some(pending))
}

fn validate_pending_update(pending: &SystemPendingUpdate) -> Result<()> {
    validate_token("pending version", &pending.version)?;
    validate_token("pending target", &pending.target)?;
    validate_filename(&pending.backup_id)?;
    Ok(())
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
    boot_health(
        current,
        pending,
        &CurrentBoot::read(),
        Path::new(BOOT_VERSION_FILE).is_file(),
        state.config.paths.web_root.join("index.html").is_file(),
    )
}

fn boot_health(
    current: &SystemVersion,
    pending: &SystemPendingUpdate,
    boot: &CurrentBoot,
    boot_marker_present: bool,
    web_root_present: bool,
) -> SystemBootHealth {
    // The install writes the new version file, so the version matches before
    // the reboot too. Only a later boot shows that the update came up.
    let version_matches_pending =
        current.version == pending.version && current.target == pending.target;
    let rebooted = booted_since_install(pending, boot);
    // This runs in the backend that serves the request.
    let backend_running = true;
    let healthy = backend_running
        && (rebooted || !pending.requires_reboot)
        && version_matches_pending
        && boot_marker_present
        && web_root_present;

    SystemBootHealth {
        backend_running,
        rebooted,
        version_matches_pending,
        boot_marker_present,
        web_root_present,
        healthy,
    }
}

/// The current boot, as needed to tell whether an install was followed by one.
struct CurrentBoot {
    id: Option<String>,
    started_at: Option<u64>,
}

impl CurrentBoot {
    fn read() -> Self {
        Self {
            id: current_boot_id().ok(),
            started_at: boot_started_at(),
        }
    }
}

fn booted_since_install(pending: &SystemPendingUpdate, boot: &CurrentBoot) -> bool {
    match (&pending.install_boot_id, &boot.id) {
        (Some(installed), Some(current)) => installed != current,
        (Some(_), None) => false,
        // Older backends recorded no boot ID: compare the install time with
        // the start of this boot instead.
        (None, _) => boot
            .started_at
            .is_some_and(|started| started > pending.installed_at),
    }
}

fn current_boot_id() -> Result<String> {
    let raw = fs::read_to_string(BOOT_ID_FILE)?;
    let id = raw.strip_suffix('\n').unwrap_or(&raw);
    BootId::parse(id).map_err(|_| AppError::Internal("invalid kernel boot ID".into()))?;
    Ok(id.to_ascii_lowercase())
}

fn boot_started_at() -> Option<u64> {
    fs::read_to_string(PROC_STAT_FILE)
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("btime ")?.trim().parse().ok())
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
    Ok(shell_quote(value))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
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
        install_boot_id: record.install_boot_id.clone(),
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
        || blocked_system_update_install_root(install)
    {
        return Err(AppError::BadRequest(format!(
            "invalid system update install path: {install}"
        )));
    }
    Ok(PathBuf::from(install))
}

fn blocked_system_update_install_root(install: &str) -> bool {
    const BLOCKED_ROOTS: &[&str] = &[
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/tmp",
        "/data",
        "/kvmapp",
        "/root/.kvmcache",
    ];

    BLOCKED_ROOTS.iter().any(|root| {
        install == *root
            || install
                .strip_prefix(root)
                .map(|rest| rest.starts_with('/'))
                .unwrap_or(false)
    })
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
#[path = "system_update_trust_tests.rs"]
mod trust_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_normalization_never_mutates_live_or_stale_progress() {
        let temporary = tempfile::tempdir().unwrap();
        let stage = temporary.path().join("stage");
        let mut progress =
            SystemUpdateProgress::new("download", "verifying", Some("0.1.0".into()), None);
        progress.updated_at = 0; // a clock jump never fails registered live work
        write_update_progress(&stage, progress).unwrap();
        let path = stage.join(SYSTEM_PROGRESS_RECORD);
        let before = fs::read(&path).unwrap();
        let current = read_current_system_version();
        let active = read_normalized_update_progress(&stage, &current, None, true).unwrap();
        assert_eq!(active.phase, "verifying");
        assert_eq!(fs::read(&path).unwrap(), before);
        let stale = read_normalized_update_progress(&stage, &current, None, false).unwrap();
        assert_eq!(stale.phase, "failed");
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn status_normalization_does_not_delete_completed_progress() {
        let temporary = tempfile::tempdir().unwrap();
        let stage = temporary.path().join("stage");
        let progress = SystemUpdateProgress::new("install", "failed", None, None);
        write_update_progress(&stage, progress).unwrap();
        let path = stage.join(SYSTEM_PROGRESS_RECORD);
        let before = fs::read(&path).unwrap();
        assert!(
            read_normalized_update_progress(&stage, &read_current_system_version(), None, false)
                .is_none()
        );
        assert_eq!(fs::read(path).unwrap(), before);
    }

    pub(super) fn valid_latest() -> SystemLatest {
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
            security_patch_level: None,
            required_app_version: None,
            signature_algorithm: SYSTEM_UPDATE_SIGNATURE_ALGORITHM.to_string(),
            signature_key_id: "hardened-system-test".to_string(),
        }
    }

    pub(super) fn valid_manifest(file: SystemManifestFile) -> SystemManifest {
        SystemManifest {
            format: "hardened-nanokvm-system-update-v1".to_string(),
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            base_version: "2025-02-17-19-08-3649fe.img".to_string(),
            kernel_version: "5.10.4-tag-".to_string(),
            security_patch_level: None,
            required_app_version: None,
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
            raw_images: Vec::new(),
        }
    }

    pub(super) fn valid_raw_manifest() -> SystemManifest {
        SystemManifest {
            format: "hardened-nanokvm-system-update-v1".to_string(),
            version: "0.1.0-raw.1".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            base_version: "2025-02-17-19-08-3649fe.img".to_string(),
            kernel_version: "5.10.4-tag-hardened.1".to_string(),
            security_patch_level: None,
            required_app_version: None,
            source_commit: "abcdef1".to_string(),
            created_utc: "2026-06-28T00:00:00Z".to_string(),
            required_free_bytes: 2_147_483_648,
            requires_reboot: true,
            operations: vec![
                "stage".to_string(),
                "write-raw-devices".to_string(),
                "reboot".to_string(),
            ],
            files: Vec::new(),
            raw_images: vec![
                SystemManifestRawImage {
                    payload: "images/rootfs.sd".to_string(),
                    device: RAW_ROOTFS_DEVICE.to_string(),
                    label: "ROOTFS".to_string(),
                    size: 1024,
                    sha256: "a".repeat(64),
                    compression: None,
                    compressed_size: None,
                    compressed_sha256: None,
                },
                SystemManifestRawImage {
                    payload: "images/boot.vfat".to_string(),
                    device: RAW_BOOT_DEVICE.to_string(),
                    label: "BOOT".to_string(),
                    size: 1024,
                    sha256: "b".repeat(64),
                    compression: None,
                    compressed_size: None,
                    compressed_sha256: None,
                },
            ],
        }
    }

    #[test]
    fn validates_system_latest_metadata() {
        let latest = valid_latest();

        validate_latest_system(&latest).unwrap();
    }

    #[test]
    fn validates_system_metadata_v2_with_required_application_version() {
        let mut latest = valid_latest();
        latest.format = SYSTEM_UPDATE_METADATA_FORMAT_V2;
        latest.required_app_version = Some("2.0.41".to_string());
        let mut manifest = valid_raw_manifest();
        latest.version = manifest.version.clone();
        latest.name = format!("hardened-nanokvm-system-{}.tar.gz", latest.version);
        latest.url = format!(
            "https://github.com/woffko/Hardened_NanoKVM/releases/download/hardened-system-{0}/hardened-nanokvm-system-{0}.tar.gz",
            latest.version
        );
        latest.release_notes_url = format!(
            "https://github.com/woffko/Hardened_NanoKVM/releases/tag/hardened-system-{}",
            latest.version
        );
        manifest.format = SYSTEM_UPDATE_MANIFEST_FORMAT_V2.to_string();
        manifest.required_app_version = latest.required_app_version.clone();

        validate_latest_system(&latest).unwrap();
        validate_manifest_shape(&manifest, &latest).unwrap();
        assert!(application_requirement_error_for("2.0.40", &latest).is_some());
        assert!(application_requirement_error_for("2.0.41", &latest).is_none());
        assert!(application_requirement_error_for("2.1.0", &latest).is_none());
    }

    #[test]
    fn rejects_ambiguous_or_invalid_required_application_versions() {
        let mut latest = valid_latest();
        latest.format = SYSTEM_UPDATE_METADATA_FORMAT_V2;
        assert!(validate_latest_system(&latest).is_err());

        latest.required_app_version = Some("2.0".to_string());
        assert!(validate_latest_system(&latest).is_err());

        latest.format = SYSTEM_UPDATE_METADATA_FORMAT_V1;
        latest.required_app_version = Some("2.0.41".to_string());
        assert!(validate_latest_system(&latest).is_err());
    }

    #[test]
    fn rejects_manifest_required_application_version_mismatch() {
        let mut latest = valid_latest();
        latest.format = SYSTEM_UPDATE_METADATA_FORMAT_V2;
        latest.required_app_version = Some("2.0.41".to_string());
        let mut manifest = valid_raw_manifest();
        latest.version = manifest.version.clone();
        manifest.format = SYSTEM_UPDATE_MANIFEST_FORMAT_V2.to_string();
        manifest.required_app_version = Some("2.0.42".to_string());

        assert!(validate_manifest_shape(&manifest, &latest).is_err());
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
            security_patch_level: None,
            required_app_version: None,
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
    fn parses_persisted_system_version_in_snake_and_camel_case() {
        let snake: PersistedSystemVersion = serde_json::from_str(
            r#"{
  "version": "0.1.2-raw.1",
  "target": "sg2002-licheervnano-sd",
  "base_version": "2026-01-05-1_4_1.img",
  "kernel_version": "5.10.4-tag-",
  "rootfs_version": "Buildroot 2023.11.2",
  "security_patch_level": "Buildroot 2023.11.3 package backports"
}"#,
        )
        .unwrap();
        assert_eq!(snake.version.as_deref(), Some("0.1.2-raw.1"));
        assert_eq!(snake.base_version.as_deref(), Some("2026-01-05-1_4_1.img"));
        assert_eq!(snake.kernel_version.as_deref(), Some("5.10.4-tag-"));
        assert_eq!(snake.rootfs_version.as_deref(), Some("Buildroot 2023.11.2"));
        assert_eq!(
            snake.security_patch_level.as_deref(),
            Some("Buildroot 2023.11.3 package backports")
        );

        let camel: PersistedSystemVersion = serde_json::from_str(
            r#"{
  "version": "0.1.2-raw.1",
  "target": "sg2002-licheervnano-sd",
  "baseVersion": "2026-01-05-1_4_1.img",
  "kernelVersion": "5.10.4-tag-",
  "rootfsVersion": "Buildroot 2023.11.2",
  "securityPatchLevel": "Buildroot 2023.11.3 package backports"
}"#,
        )
        .unwrap();
        assert_eq!(camel.version.as_deref(), Some("0.1.2-raw.1"));
        assert_eq!(camel.base_version.as_deref(), Some("2026-01-05-1_4_1.img"));
        assert_eq!(camel.kernel_version.as_deref(), Some("5.10.4-tag-"));
        assert_eq!(camel.rootfs_version.as_deref(), Some("Buildroot 2023.11.2"));
        assert_eq!(
            camel.security_patch_level.as_deref(),
            Some("Buildroot 2023.11.3 package backports")
        );
    }

    #[test]
    fn compares_system_update_versions_numerically() {
        assert_eq!(
            compare_system_versions("0.1.2-raw.1", "0.1.0-raw.1"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_system_versions("0.1.0-raw.1", "0.1.2-raw.1"),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_system_versions("0.1.10-raw.1", "0.1.2-raw.1"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_system_versions("0.1.2-raw.2", "0.1.2-raw.1"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_system_versions("0.1.2", "0.1.2-raw.1"),
            Some(Ordering::Greater)
        );
    }

    #[test]
    fn only_reports_newer_system_release_as_update_available() {
        let current = SystemVersion {
            version: "0.1.2-raw.1".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            base_version: String::new(),
            kernel_version: String::new(),
            rootfs_version: String::new(),
            security_patch_level: None,
            model: String::new(),
            hardware_version: String::new(),
            source: "test".to_string(),
        };

        let mut latest = valid_latest();
        latest.version = "0.1.0-raw.1".to_string();
        assert!(!system_update_is_newer(&current, &latest));

        latest.version = "0.1.2-raw.2".to_string();
        assert!(system_update_is_newer(&current, &latest));

        latest.target = "other-target".to_string();
        assert!(!system_update_is_newer(&current, &latest));
    }

    #[test]
    fn chooses_newer_stable_system_release_when_preview_is_stale() {
        let mut preview = valid_latest();
        preview.version = "0.1.3-raw.1".to_string();

        let mut stable = valid_latest();
        stable.version = "0.2.0-raw.1".to_string();

        // Selection must retain each candidate's exact signed bytes, not
        // serialize a new JSON representation after choosing its version.
        let selected = newer_system_release(
            VerifiedSystemMetadata {
                latest: preview,
                metadata: b"preview exact".to_vec(),
                signature: b"preview signature".to_vec(),
            },
            VerifiedSystemMetadata {
                latest: stable,
                metadata: b"stable exact".to_vec(),
                signature: b"stable signature".to_vec(),
            },
        );
        assert_eq!(selected.latest.version, "0.2.0-raw.1");
        assert_eq!(selected.metadata, b"stable exact");
        assert_eq!(selected.signature, b"stable signature");
    }

    #[test]
    fn raw_install_barrier_keeps_existing_configuration_permission_gate() {
        let mut config = Config::default();
        config.security.allow_raw_system_updates = false;
        assert!(matches!(
            validate_raw_install(&config, &valid_raw_manifest()),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn raw_install_barrier_still_rejects_mixed_file_and_raw_operations() {
        let mut config = Config::default();
        config.security.allow_raw_system_updates = true;
        let mut manifest = valid_raw_manifest();
        manifest.files.push(SystemManifestFile {
            payload: "images/file".into(),
            install: "/etc/hostname".into(),
            size: 1,
            sha256: "a".repeat(64),
        });
        assert!(matches!(
            validate_raw_install(&config, &manifest),
            Err(AppError::BadRequest(_))
        ));
    }
    #[test]
    fn a_stale_prepared_ticket_is_abandoned_and_its_exact_capsule_removed() {
        use crate::update::restore_capsule::{
            prepare_capsule,
            ticket::{Binding, BootId, Phase, RestoreTicket, Store},
        };
        use std::io::Cursor;

        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let capsules = tempfile::tempdir().unwrap();
        let mut store = Store::open_fixture(root.path()).unwrap();
        let plaintext = b"fixture".repeat(128);
        let mut encrypted = Vec::new();
        let secret = prepare_capsule(
            "0.3.0-raw.13",
            plaintext.len() as u64,
            &mut Cursor::new(&plaintext),
            &mut encrypted,
        )
        .unwrap();
        let ticket = RestoreTicket::prepared(
            secret,
            Binding {
                source_boot: BootId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                device_id: [1; 32],
                capsule_sha256: Sha256::digest(&encrypted).into(),
                boot_image_sha256: [2; 32],
                rootfs_image_sha256: [3; 32],
                target_app_version: "2.0.43".into(),
                target: "sg2002-licheervnano-sd".into(),
            },
        )
        .unwrap();
        store.publish_prepared(&ticket).unwrap();
        let capsule = capsules.path().join(format!(
            "{:032x}.capsule",
            u128::from_be_bytes(ticket.transaction_id())
        ));
        std::fs::write(&capsule, b"stale ciphertext").unwrap();
        retire_prepared_ticket(&mut store, capsules.path()).unwrap();
        assert_eq!(store.load().unwrap().unwrap().phase(), Phase::Abandoned);
        assert!(!capsule.exists());
    }

    fn outgoing_ticket(version: &str) -> crate::update::restore_capsule::ticket::RestoreTicket {
        use crate::update::restore_capsule::{
            prepare_capsule,
            ticket::{Binding, BootId, RestoreTicket},
        };
        use std::io::Cursor;

        let plaintext = b"fixture".repeat(128);
        let mut encrypted = Vec::new();
        let secret = prepare_capsule(
            version,
            plaintext.len() as u64,
            &mut Cursor::new(&plaintext),
            &mut encrypted,
        )
        .unwrap();
        RestoreTicket::prepared(
            secret,
            Binding {
                source_boot: BootId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
                device_id: [1; 32],
                capsule_sha256: Sha256::digest(&encrypted).into(),
                boot_image_sha256: [2; 32],
                rootfs_image_sha256: [3; 32],
                target_app_version: "2.1.0".into(),
                target: "sg2002-licheervnano-sd".into(),
            },
        )
        .unwrap()
    }

    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn restored_system_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/kvm")).unwrap();
        let requirement = root.path().join(raw_restore::REQUIRED_PATH);
        std::fs::write(&requirement, raw_restore::REQUIRED_BYTES).unwrap();
        std::fs::set_permissions(&requirement, std::fs::Permissions::from_mode(0o644)).unwrap();
        root
    }

    fn source_boot_outcome(
        root: &Path,
        store: &mut crate::update::restore_capsule::ticket::Store,
        capsules: &Path,
    ) -> (
        std::result::Result<raw_restore::Outcome, raw_restore::Error>,
        bool,
    ) {
        use crate::update::restore_capsule::ticket::BootId;

        let staging = private_directory();
        let marker_directory = tempfile::tempdir().unwrap();
        let marker = marker_directory.path().join("blocked");
        let outcome = raw_restore::run_observed(
            root,
            store,
            capsules,
            staging.path(),
            &marker,
            &raw_restore::Observation {
                boot_id: BootId::parse("22222222-2222-4222-8222-222222222222").unwrap(),
                device_id: [1; 32],
                system_version: "0.3.0-raw.13".into(),
                app_version: "2.0.45".into(),
                target: "sg2002-licheervnano-sd".into(),
            },
        );
        (outcome, marker.exists())
    }

    #[test]
    fn an_attempt_that_never_reaches_the_writer_leaves_the_source_system_bootable() {
        use crate::update::restore_capsule::ticket::{Phase, Store};

        let root = restored_system_root();
        let store_root = private_directory();
        let capsules = private_directory();
        let mut store = Store::open_fixture(store_root.path()).unwrap();
        let ticket = outgoing_ticket("0.4.0-raw.1");
        publish_outgoing_ticket(root.path(), &mut store, capsules.path(), &ticket).unwrap();
        assert_eq!(store.load().unwrap().unwrap().phase(), Phase::Prepared);
        let (outcome, blocked) = source_boot_outcome(root.path(), &mut store, capsules.path());
        assert!(matches!(outcome, Ok(raw_restore::Outcome::NotRequired)));
        assert!(!blocked, "the source system must keep its network and SSH");
    }

    #[test]
    fn a_retired_attempt_leaves_the_source_system_bootable_too() {
        use crate::update::restore_capsule::ticket::{Phase, Store};

        let root = restored_system_root();
        let store_root = private_directory();
        let capsules = private_directory();
        let mut store = Store::open_fixture(store_root.path()).unwrap();
        let first = outgoing_ticket("0.4.0-raw.1");
        publish_outgoing_ticket(root.path(), &mut store, capsules.path(), &first).unwrap();
        retire_prepared_ticket(&mut store, capsules.path()).unwrap();
        assert_eq!(store.load().unwrap().unwrap().phase(), Phase::Abandoned);
        let (outcome, blocked) = source_boot_outcome(root.path(), &mut store, capsules.path());
        assert!(matches!(outcome, Ok(raw_restore::Outcome::NotRequired)));
        assert!(!blocked);
    }

    #[test]
    fn publishing_replaces_a_stale_attempt_and_its_capsule() {
        use crate::update::restore_capsule::ticket::{Phase, Store};

        let root = restored_system_root();
        let store_root = private_directory();
        let capsules = private_directory();
        let mut store = Store::open_fixture(store_root.path()).unwrap();
        let stale = outgoing_ticket("0.4.0-raw.1");
        store.publish_prepared(&stale).unwrap();
        let capsule = capsules.path().join(format!(
            "{:032x}.capsule",
            u128::from_be_bytes(stale.transaction_id())
        ));
        std::fs::write(&capsule, b"stale ciphertext").unwrap();
        let next = outgoing_ticket("0.4.0-raw.2");
        publish_outgoing_ticket(root.path(), &mut store, capsules.path(), &next).unwrap();
        let current = store.load().unwrap().unwrap();
        assert_eq!(current.phase(), Phase::Prepared);
        assert_eq!(current.transaction_id(), next.transaction_id());
        assert!(!capsule.exists());
    }

    #[test]
    fn a_requirement_that_cannot_be_retired_stops_before_any_ticket_changes() {
        use crate::update::restore_capsule::ticket::{Phase, Store};

        let root = tempfile::tempdir().unwrap();
        // A directory at the marker path cannot be removed as a file.
        std::fs::create_dir_all(root.path().join(raw_restore::REQUIRED_PATH).join("x")).unwrap();
        let store_root = private_directory();
        let capsules = private_directory();
        let mut store = Store::open_fixture(store_root.path()).unwrap();
        let stale = outgoing_ticket("0.4.0-raw.1");
        store.publish_prepared(&stale).unwrap();
        let next = outgoing_ticket("0.4.0-raw.2");
        assert!(publish_outgoing_ticket(root.path(), &mut store, capsules.path(), &next).is_err());
        let current = store.load().unwrap().unwrap();
        assert_eq!(current.phase(), Phase::Prepared);
        assert_eq!(current.transaction_id(), stale.transaction_id());
    }

    #[test]
    fn raw_capture_publishes_one_prepared_ticket_then_sends_the_same_transaction_and_images() {
        use crate::update::{
            raw_capture::{self, CaptureRequest, TargetImage},
            raw_install_lease::RawImages,
            restore_accounts,
            restore_capsule::ticket::{BootId, Phase},
            restore_identity::{
                IdentityCheckedRestore,
                tests::{CONFIG_PATH, CWD, fixture, signed_accounts},
            },
        };
        use std::{
            cell::RefCell, fs::File, io::Write, os::unix::fs::PermissionsExt, path::Path,
            sync::atomic::AtomicBool,
        };

        #[derive(Default)]
        struct Image;
        impl TargetImage for Image {
            fn signed_accounts(
                &mut self,
                _: &AtomicBool,
            ) -> std::result::Result<restore_accounts::SignedAccounts, raw_capture::CaptureError>
            {
                let encoded = restore_accounts::encode(&signed_accounts()).unwrap();
                Ok(restore_accounts::decode(&encoded).unwrap())
            }
            fn check_ssh(
                &mut self,
                _: &mut IdentityCheckedRestore,
                _: &AtomicBool,
            ) -> std::result::Result<(), raw_capture::CaptureError> {
                Ok(())
            }
        }

        let (source, config) = fixture();
        let private = tempfile::tempdir().unwrap();
        let capsules = tempfile::tempdir().unwrap();
        std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(capsules.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = File::open(capsules.path()).unwrap();
        let mut first = tempfile::tempfile().unwrap();
        first.write_all(b"boot image").unwrap();
        let mut second = tempfile::tempfile().unwrap();
        second.write_all(b"rootfs image").unwrap();
        let raw_images = RawImages {
            files: [first, second],
            sizes: [10, 12],
            sha256: [[1; 32], [2; 32]],
        };
        let published = RefCell::new(None);
        let sent = RefCell::new(None);
        let target_app = "2.0.43";
        let request = CaptureRequest {
            source_root: source.path(),
            private_staging: private.path(),
            capsule_directory: &directory,
            config: &config,
            working_dir: Path::new(CWD),
            config_path: Path::new(CONFIG_PATH),
            target_version: "0.3.0-raw.13",
            target_app_version: target_app,
            target: "sg2002-licheervnano-sd",
            boot_image_sha256: [2; 32],
            rootfs_image_sha256: [3; 32],
            source_boot: BootId::parse("11111111-1111-4111-8111-111111111111").unwrap(),
            device_id: [1; 32],
        };
        let ticket = submit_raw_capture(
            &request,
            &mut Image,
            raw_images,
            |ticket| {
                *published.borrow_mut() = Some((
                    ticket.transaction_id(),
                    ticket.target_version().to_string(),
                    ticket.phase(),
                ));
                Ok(())
            },
            |transaction, images| {
                *sent.borrow_mut() = Some((transaction, images.sizes, images.sha256));
                Ok(())
            },
        )
        .unwrap();
        let (transaction, version, phase) = published.borrow().clone().unwrap();
        assert_eq!(transaction, ticket.transaction_id());
        assert_eq!(version, "0.3.0-raw.13");
        assert_eq!(phase, Phase::Prepared);
        let (sent_transaction, sizes, sha256) = (*sent.borrow()).unwrap();
        assert_eq!(sent_transaction, transaction);
        assert_eq!(sizes, [10, 12]);
        assert_eq!(sha256, [[1; 32], [2; 32]]);
        assert_eq!(
            std::fs::read_dir(capsules.path()).unwrap().count(),
            1,
            "the sealed capsule stays on the data partition"
        );
        assert_eq!(std::fs::read_dir(private.path()).unwrap().count(), 0);
    }

    #[test]
    fn historical_only_raw_generator_documents_removed_unsafe_preserve() {
        let temp = tempfile::tempdir().unwrap();
        let stage_dir = temp.path().join("system-update");
        let payload_dir = temp.path().join("payload");
        let manifest = valid_raw_manifest();
        let pending = SystemPendingUpdate {
            version: manifest.version.clone(),
            target: manifest.target.clone(),
            backup_id: "raw-123".to_string(),
            installed_at: 123,
            requires_reboot: true,
            file_count: manifest.raw_images.len(),
            install_boot_id: None,
        };

        let script = raw_image_updater_script(&stage_dir, &manifest, &payload_dir, &pending)
            .expect("raw updater script");

        assert!(script.contains("ld-musl-system-update.so.1 --library-path"));
        assert!(script.contains("RAW_PRESERVE_DIR=\"$PROGRESS_DIR/preserve\""));
        assert!(script.contains("BOOT_PRESERVE_DIR=\"$RAW_PRESERVE_DIR/boot\""));
        assert!(script.contains("ROOT_PRESERVE_DIR=\"$RAW_PRESERVE_DIR/root\""));
        assert!(script.contains("ROOT_RESTORE_DONE=\"$PROGRESS_DIR/root-restore-done\""));
        assert!(script.contains("$BB rm -f \"$ROOT_RESTORE_DONE\""));
        assert!(!script.contains("BOOT_PRESERVE_DIR=/tmp/hardened-boot-preserve"));
        assert!(!script.contains("ROOT_PRESERVE_DIR=/tmp/hardened-root-preserve"));
        assert!(
            script.contains("preserve_boot_config\npreserve_root_config\nprepare_boot_readonly")
        );
        assert!(script.contains(
            "log 'rootfs configuration restore is deferred until first boot'\nrestore_boot_config\nprogress rebooting"
        ));
        assert!(!script.contains("restore_root_config\nrestore_boot_config"));
        assert!(script.contains("eth.nodhcp"));
        assert!(script.contains("eth.ipv6.mode"));
        assert!(script.contains("/etc/kvm"));
        assert!(script.contains("/etc/default/syslogd"));
        assert!(script.contains("/etc/default/klogd"));
        assert!(script.contains("etc/default/syslogd"));
        assert!(script.contains("etc/default/klogd"));
        assert!(script.contains("/etc/passwd"));
        assert!(script.contains("/etc/shadow"));
        assert!(script.contains("/etc/ssh"));
        assert!(script.contains("/etc/kvm.disk0"));
        assert!(script.contains("etc/kvm.disk0"));
        assert!(script.contains("/root/.tailscale"));
        assert!(script.contains("/root/.picoclaw"));
        assert!(script.contains("drop_unsafe_preserved_kvm_state"));
        assert!(script.contains("$BB rm -f"));
        assert!(script.contains("/data/hardened-system-raw-update-pending.json"));
        assert!(script.contains("/etc/kvm/system-update-pending.json"));
        assert!(script.contains("$BB cp -a \"$SRC/.\" \"$DEST/\""));
        assert!(!script.contains("$ROOT_TMP_MOUNT/etc/kvm/system-version.json"));
    }

    #[test]
    fn staged_update_matches_current_system_when_same_version_and_target() {
        let record = SystemStageRecord {
            staged_at: 123,
            latest: valid_latest(),
            manifest: valid_raw_manifest(),
        };
        let staged = staged_summary(&record);
        let mut current = SystemVersion {
            version: staged.version.clone(),
            target: staged.target.clone(),
            base_version: String::new(),
            kernel_version: String::new(),
            rootfs_version: String::new(),
            security_patch_level: None,
            model: String::new(),
            hardware_version: String::new(),
            source: "test".to_string(),
        };

        assert!(staged_matches_current_system(&staged, &current));
        current.version = "0.0.0-stock".to_string();
        assert!(!staged_matches_current_system(&staged, &current));
    }

    #[test]
    fn historical_only_raw_generator_documents_removed_mutable_gzip_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let stage_dir = temp.path().join("system-update");
        let payload_dir = temp.path().join("payload");
        let mut manifest = valid_raw_manifest();
        manifest.raw_images[0].payload = "images/rootfs.sd.gz".to_string();
        manifest.raw_images[0].compression = Some("gzip".to_string());
        manifest.raw_images[0].compressed_size = Some(512);
        manifest.raw_images[0].compressed_sha256 = Some("c".repeat(64));
        manifest.raw_images[1].payload = "images/boot.vfat.gz".to_string();
        manifest.raw_images[1].compression = Some("gzip".to_string());
        manifest.raw_images[1].compressed_size = Some(256);
        manifest.raw_images[1].compressed_sha256 = Some("d".repeat(64));
        let pending = SystemPendingUpdate {
            version: manifest.version.clone(),
            target: manifest.target.clone(),
            backup_id: "raw-123".to_string(),
            installed_at: 123,
            requires_reboot: true,
            file_count: manifest.raw_images.len(),
            install_boot_id: None,
        };

        let script = raw_image_updater_script(&stage_dir, &manifest, &payload_dir, &pending)
            .expect("raw updater script");

        assert!(script.contains("$BB gzip -t"));
        assert!(script.contains("$BB gzip -dc"));
        assert!(script.contains("images/rootfs.sd.gz"));
        assert!(script.contains("images/boot.vfat.gz"));
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
        assert!(validate_absolute_install_path("/proc").is_err());
        assert!(validate_absolute_install_path("/proc/version").is_err());
        assert!(validate_absolute_install_path("/sys").is_err());
        assert!(validate_absolute_install_path("/dev").is_err());
        assert!(validate_absolute_install_path("/dev/null").is_err());
        assert!(validate_absolute_install_path("/run").is_err());
        assert!(validate_absolute_install_path("/tmp").is_err());
        assert!(validate_absolute_install_path("/data").is_err());
        assert!(validate_absolute_install_path("/kvmapp").is_err());
        assert!(validate_absolute_install_path("/kvmapp/server/NanoKVM-Server").is_err());
        assert!(validate_absolute_install_path("/root/.kvmcache").is_err());
        assert!(
            validate_absolute_install_path("/root/.kvmcache/system-update/staged.json").is_err()
        );
        assert!(validate_absolute_install_path("/etc/../passwd").is_err());
    }

    #[test]
    fn rejects_manifest_installing_to_blocked_roots() {
        let temp = tempfile::tempdir().unwrap();
        let payload_dir = temp.path().join("payload");
        let file = payload_dir.join("rootfs/dev");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"not a device").unwrap();
        let hashes = hash_file(&file).unwrap();

        let manifest = valid_manifest(SystemManifestFile {
            payload: "rootfs/dev".to_string(),
            install: "/dev".to_string(),
            size: fs::metadata(&file).unwrap().len(),
            sha256: hashes.sha256,
        });

        assert!(validate_system_manifest(&manifest, &valid_latest(), &payload_dir).is_err());
    }

    #[test]
    fn validates_raw_image_manifest_payload_tree() {
        let temp = tempfile::tempdir().unwrap();
        let payload_dir = temp.path().join("payload");
        let file = payload_dir.join("images/rootfs.sd");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"rootfs image").unwrap();
        let hashes = hash_file(&file).unwrap();

        let manifest = SystemManifest {
            format: "hardened-nanokvm-system-update-v1".to_string(),
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            base_version: "2025-02-17-19-08-3649fe.img".to_string(),
            kernel_version: "5.10.4-tag-hardened.1".to_string(),
            security_patch_level: None,
            required_app_version: None,
            source_commit: "abcdef1".to_string(),
            created_utc: "2026-06-28T00:00:00Z".to_string(),
            required_free_bytes: 2_147_483_648,
            requires_reboot: true,
            operations: vec![
                "stage".to_string(),
                "write-raw-devices".to_string(),
                "reboot".to_string(),
            ],
            files: Vec::new(),
            raw_images: vec![SystemManifestRawImage {
                payload: "images/rootfs.sd".to_string(),
                device: RAW_ROOTFS_DEVICE.to_string(),
                label: "ROOTFS".to_string(),
                size: fs::metadata(&file).unwrap().len(),
                sha256: hashes.sha256,
                compression: None,
                compressed_size: None,
                compressed_sha256: None,
            }],
        };

        validate_system_manifest(&manifest, &valid_latest(), &payload_dir).unwrap();
    }

    #[test]
    fn validates_compressed_raw_image_manifest_payload_tree() {
        let temp = tempfile::tempdir().unwrap();
        let payload_dir = temp.path().join("payload");
        let raw_file = temp.path().join("rootfs.sd");
        let file = payload_dir.join("images/rootfs.sd.gz");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&raw_file, vec![1_u8; 1024]).unwrap();
        fs::write(&file, b"compressed rootfs image").unwrap();
        let raw_hashes = hash_file(&raw_file).unwrap();
        let stored_hashes = hash_file(&file).unwrap();

        let manifest = SystemManifest {
            format: "hardened-nanokvm-system-update-v1".to_string(),
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            base_version: "2025-02-17-19-08-3649fe.img".to_string(),
            kernel_version: "5.10.4-tag-hardened.1".to_string(),
            security_patch_level: None,
            required_app_version: None,
            source_commit: "abcdef1".to_string(),
            created_utc: "2026-06-28T00:00:00Z".to_string(),
            required_free_bytes: 805_306_368,
            requires_reboot: true,
            operations: vec![
                "stage".to_string(),
                "write-raw-devices".to_string(),
                "reboot".to_string(),
            ],
            files: Vec::new(),
            raw_images: vec![SystemManifestRawImage {
                payload: "images/rootfs.sd.gz".to_string(),
                device: RAW_ROOTFS_DEVICE.to_string(),
                label: "ROOTFS".to_string(),
                size: fs::metadata(&raw_file).unwrap().len(),
                sha256: raw_hashes.sha256,
                compression: Some("gzip".to_string()),
                compressed_size: Some(fs::metadata(&file).unwrap().len()),
                compressed_sha256: Some(stored_hashes.sha256),
            }],
        };

        validate_system_manifest(&manifest, &valid_latest(), &payload_dir).unwrap();
    }

    #[test]
    fn rejects_raw_image_unknown_device() {
        let temp = tempfile::tempdir().unwrap();
        let payload_dir = temp.path().join("payload");
        let file = payload_dir.join("images/rootfs.sd");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"rootfs image").unwrap();
        let hashes = hash_file(&file).unwrap();

        let manifest = SystemManifest {
            format: "hardened-nanokvm-system-update-v1".to_string(),
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            base_version: "2025-02-17-19-08-3649fe.img".to_string(),
            kernel_version: "5.10.4-tag-hardened.1".to_string(),
            security_patch_level: None,
            required_app_version: None,
            source_commit: "abcdef1".to_string(),
            created_utc: "2026-06-28T00:00:00Z".to_string(),
            required_free_bytes: 2_147_483_648,
            requires_reboot: true,
            operations: vec![
                "stage".to_string(),
                "write-raw-devices".to_string(),
                "reboot".to_string(),
            ],
            files: Vec::new(),
            raw_images: vec![SystemManifestRawImage {
                payload: "images/rootfs.sd".to_string(),
                device: "/dev/sda1".to_string(),
                label: "ROOTFS".to_string(),
                size: fs::metadata(&file).unwrap().len(),
                sha256: hashes.sha256,
                compression: None,
                compressed_size: None,
                compressed_sha256: None,
            }],
        };

        assert!(validate_system_manifest(&manifest, &valid_latest(), &payload_dir).is_err());
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
            install_boot_id: None,
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
            install_boot_id: None,
        };

        assert!(rollback_script_for_record(temp.path(), &record).is_err());
    }

    const INSTALL_BOOT: &str = "0f8c6f4e-6b9b-4f0e-9a51-6c1f0d6f7a10";
    const LATER_BOOT: &str = "6e1b5b9d-1a2c-4c7e-8d3f-2a9b0c4d5e6f";

    fn pending_installed(boot_id: Option<&str>, requires_reboot: bool) -> SystemPendingUpdate {
        SystemPendingUpdate {
            version: "0.1.0".into(),
            target: DEFAULT_SYSTEM_TARGET.into(),
            backup_id: "0.1.0-100".into(),
            installed_at: 100,
            requires_reboot,
            file_count: 1,
            install_boot_id: boot_id.map(str::to_string),
        }
    }

    fn running(version: &str) -> SystemVersion {
        SystemVersion {
            version: version.into(),
            target: DEFAULT_SYSTEM_TARGET.into(),
            base_version: String::new(),
            kernel_version: String::new(),
            rootfs_version: String::new(),
            security_patch_level: None,
            model: String::new(),
            hardware_version: String::new(),
            source: "test".into(),
        }
    }

    fn boot(id: Option<&str>, started_at: Option<u64>) -> CurrentBoot {
        CurrentBoot {
            id: id.map(str::to_string),
            started_at,
        }
    }

    #[test]
    fn an_update_that_needs_a_reboot_is_healthy_only_in_a_later_boot() {
        let pending = pending_installed(Some(INSTALL_BOOT), true);
        let current = running("0.1.0");
        let same = boot_health(
            &current,
            &pending,
            &boot(Some(INSTALL_BOOT), Some(200)),
            true,
            true,
        );
        assert!(
            !same.rebooted && !same.healthy,
            "confirmed before the reboot"
        );
        let later = boot_health(
            &current,
            &pending,
            &boot(Some(LATER_BOOT), Some(200)),
            true,
            true,
        );
        assert!(later.rebooted && later.healthy);
        // A later boot does not excuse a failed check.
        let later_boot = boot(Some(LATER_BOOT), Some(200));
        assert!(!boot_health(&running("0.0.9"), &pending, &later_boot, true, true).healthy);
        assert!(!boot_health(&current, &pending, &later_boot, false, true).healthy);
        assert!(!boot_health(&current, &pending, &later_boot, true, false).healthy);
        // An unreadable boot ID never counts as a new boot.
        assert!(!boot_health(&current, &pending, &boot(None, Some(200)), true, true).healthy);
    }

    #[test]
    fn an_update_without_a_reboot_is_healthy_in_the_install_boot() {
        let pending = pending_installed(Some(INSTALL_BOOT), false);
        let health = boot_health(
            &running("0.1.0"),
            &pending,
            &boot(Some(INSTALL_BOOT), Some(50)),
            true,
            true,
        );
        assert!(!health.rebooted && health.healthy);
    }

    #[test]
    fn records_without_a_boot_id_compare_the_install_time_with_the_boot_start() {
        let pending = pending_installed(None, true);
        assert!(!booted_since_install(
            &pending,
            &boot(Some(LATER_BOOT), Some(99))
        ));
        assert!(!booted_since_install(
            &pending,
            &boot(Some(LATER_BOOT), Some(100))
        ));
        assert!(booted_since_install(
            &pending,
            &boot(Some(LATER_BOOT), Some(101))
        ));
        assert!(!booted_since_install(&pending, &boot(None, None)));
    }

    #[test]
    fn pending_records_carry_the_install_boot_id_and_old_ones_still_parse() {
        let old = br#"{"version":"0.1.0","target":"t","backupId":"b","installedAt":1,"requiresReboot":true,"fileCount":1}"#;
        let parsed: SystemPendingUpdate = serde_json::from_slice(old).unwrap();
        assert_eq!(parsed.install_boot_id, None);
        let json = serde_json::to_string(&pending_installed(Some(INSTALL_BOOT), true)).unwrap();
        assert!(
            json.contains(&format!("\"installBootId\":\"{INSTALL_BOOT}\"")),
            "{json}"
        );
        let record = SystemInstallRecord {
            version: "0.1.0".to_string(),
            target: DEFAULT_SYSTEM_TARGET.to_string(),
            backup_id: "0.1.0-123".to_string(),
            installed_at: 123,
            requires_reboot: true,
            files: Vec::new(),
            install_boot_id: Some(INSTALL_BOOT.to_string()),
        };
        assert_eq!(
            pending_update(&record).install_boot_id.as_deref(),
            Some(INSTALL_BOOT)
        );
        let health: SystemBootHealth = serde_json::from_slice(
            br#"{"backendRunning":true,"versionMatchesPending":true,"bootMarkerPresent":true,"webRootPresent":true,"healthy":true}"#,
        )
        .unwrap();
        assert!(!health.rebooted);
    }

    #[test]
    fn this_hosts_boot_id_and_boot_start_are_read() {
        let id = current_boot_id().unwrap();
        assert!(BootId::parse(&id).is_ok());
        assert_eq!(current_boot_id().unwrap(), id);
        assert!(boot_started_at().is_some_and(|started| started > 0));
        assert!(!booted_since_install(
            &pending_installed(Some(&id), true),
            &CurrentBoot::read()
        ));
    }
}
