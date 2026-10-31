use axum::{
    Json,
    extract::{Multipart, State},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fs, io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
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
        app_install_lease::{Answer, Handoff, Sender},
        app_slot::{self, SlotError},
        app_stage::{AppArchive, AppDownload, AppStage, MAX_ARCHIVE_BYTES as MAX_UPDATE_BYTES},
        keys::verify_metadata_signature,
        operation::{Kind, Snapshot, UpdateOwner},
        staged_metadata::{MAX_METADATA, MAX_SIGNATURE},
    },
};

#[path = "application_job.rs"]
mod job;
pub use job::status as job_status;

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
const WRITER_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const APP_UPDATE_SIGNATURE_ALGORITHM: &str = "sha256-rsa-pkcs1-v1_5";
const APP_UPDATE_UNSIGNED_ALGORITHM: &str = "unsigned";
const MAX_APP_VERSION_BYTES: u64 = 128;

/// The installer's transaction for an accepted handoff, observed at
/// `/api/application/update/jobs/{transactionId}`. Not an installation result.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSubmittedRsp {
    pub transaction_id: String,
}

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
    /// Size, digest and version come from metadata the trust set signed.
    SignedMetadata(VerifiedAppMetadata),
    #[cfg(test)]
    ManualImport,
}

/// Opaque result of private, bounded extraction and current-policy admission.
/// There is no pathname/import-mode constructor or deserializer. The slot
/// issuer consumes this result, not arbitrary caller-selected directories.
pub struct AppCandidate {
    input: crate::update::app_slot::CandidateInput,
}
impl AppCandidate {
    pub(crate) fn into_slot(self) -> crate::update::app_slot::CandidateInput {
        self.input
    }

    #[cfg(test)]
    pub(crate) fn fixture_root(&self) -> &Path {
        &self.input.root
    }
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

pub async fn update(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<UpdateSubmittedRsp>>> {
    if system_firewall::paranoid_mode_enabled() {
        return Err(AppError::BadRequest(
            system_firewall::paranoid_blocked_message().to_string(),
        ));
    }

    let owner = state.updates.acquire(Kind::ApplicationOnline)?;
    let transaction = owner
        .run(move |job| async move {
            let config = job.blocking("read app update policy", Config::read).await?;
            let verified = get_latest(is_preview_enabled(), &config).await?;
            // Refuse before the download, and again for the reauthenticated metadata.
            check_forward(&current_app_version(), &verified.latest.version)?;
            let (stage, archive) = job
                .blocking("prepare private app staging", || {
                    let stage = AppStage::prepare()?;
                    let archive = stage.create_archive()?;
                    Ok((stage, archive))
                })
                .await?;
            let archive = download_release_asset(&verified.latest, archive, &job).await?;
            // Do not freeze settings during the network download. Settle the
            // enrolled firewall owner and all enrolled writers BEFORE rereading
            // policy; keep that same barrier through reauthentication and swap.
            let writers = state.drain_writers(WRITER_DRAIN_TIMEOUT).await?;
            let (config, writers) = writers
                .blocking(&job, "reread app install policy", Config::read_frozen)
                .await?;
            let verified =
                authenticate_app_metadata(verified.metadata, verified.signature, &config).await?;
            check_forward(&current_app_version(), &verified.latest.version)?;
            let handoff = job.prepare_install_handoff(writers)?;
            job.blocking("verify and hand over app", move || {
                let archive = seal_signed(archive, &verified)?;
                submit_package(
                    archive,
                    stage,
                    InstallAuthority::SignedMetadata(verified),
                    handoff,
                )
            })
            .await
        })
        .await?;

    Ok(Json(ApiResponse::ok(submitted(transaction))))
}

pub async fn offline_update(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<ApiResponse<UpdateSubmittedRsp>>> {
    let owner = state.updates.acquire(Kind::ApplicationOffline)?;
    let transaction = owner
        .run(move |job| async move {
            let (stage, archive) = job
                .blocking("prepare private offline app staging", || {
                    let stage = AppStage::prepare()?;
                    let archive = stage.create_archive()?;
                    Ok((stage, archive))
                })
                .await?;
            let package = time::timeout(
                DOWNLOAD_TIMEOUT,
                save_uploaded_update(archive, &mut multipart, &job),
            )
            .await
            .map_err(|_| AppError::BadRequest("app upload timed out".into()))??;
            // A session alone must not be enough to install code as root, so
            // an upload passes what a download passes. Any signed version is
            // accepted: this is how a device goes back to an earlier release.
            let writers = state.drain_writers(WRITER_DRAIN_TIMEOUT).await?;
            let (config, writers) = writers
                .blocking(&job, "reread app install policy", Config::read_frozen)
                .await?;
            let OfflinePackage {
                archive,
                metadata,
                signature,
            } = package;
            let verified = authenticate_offline_metadata(metadata, signature, &config).await?;
            let handoff = job.prepare_install_handoff(writers)?;
            job.blocking("verify and hand over offline app", move || {
                let archive = seal_signed(archive, &verified)?;
                submit_package(
                    archive,
                    stage,
                    InstallAuthority::SignedMetadata(verified),
                    handoff,
                )
            })
            .await
        })
        .await?;

    Ok(Json(ApiResponse::ok(submitted(transaction))))
}

fn submitted(transaction: [u8; 16]) -> UpdateSubmittedRsp {
    UpdateSubmittedRsp {
        transaction_id: format!("{:032x}", u128::from_be_bytes(transaction)),
    }
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

/// An online update only moves forward. Signed metadata for an older release,
/// or for the installed version with another archive, is refused: it would roll
/// the device back to known bugs. A manual import stays the explicit way to
/// install an older release.
fn check_forward(installed: &str, offered: &str) -> Result<()> {
    match compare_application_versions(offered, installed) {
        Some(std::cmp::Ordering::Greater) => Ok(()),
        Some(_) => Err(AppError::Conflict(format!(
            "the offered app {offered} is not newer than the installed app {installed}"
        ))),
        None => Err(AppError::BadRequest(
            "the installed and offered app versions cannot be compared".to_string(),
        )),
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

/// An upload in the form a release publishes it, not yet trusted in any part.
struct OfflinePackage {
    archive: AppDownload,
    metadata: Vec<u8>,
    signature: Vec<u8>,
}

async fn read_field(
    field: &mut axum::extract::multipart::Field<'_>,
    limit: usize,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid multipart data: {err}")))?
    {
        if chunk.len() > limit - bytes.len() {
            return Err(AppError::BadRequest("update metadata is too large".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn save_uploaded_update(
    mut archive: AppDownload,
    multipart: &mut Multipart,
    owner: &UpdateOwner,
) -> Result<OfflinePackage> {
    let mut found = false;
    let mut metadata = None;
    let mut signature = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid multipart data: {err}")))?
    {
        match field.name() {
            Some("metadata") => {
                let bytes = read_field(&mut field, MAX_METADATA).await?;
                if metadata.replace(bytes).is_some() {
                    return Err(AppError::BadRequest(
                        "multiple update metadata files".into(),
                    ));
                }
                continue;
            }
            Some("signature") => {
                let bytes = read_field(&mut field, MAX_SIGNATURE).await?;
                if signature.replace(bytes).is_some() {
                    return Err(AppError::BadRequest("multiple update signatures".into()));
                }
                continue;
            }
            Some("file") => {}
            _ => continue,
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
    let (Some(metadata), Some(signature)) = (metadata, signature) else {
        return Err(AppError::BadRequest(
            "an offline update needs the release's latest.json and latest.json.sig".into(),
        ));
    };
    Ok(OfflinePackage {
        archive,
        metadata,
        signature,
    })
}

/// The lab setting for unsigned metadata covers downloads only.
async fn authenticate_offline_metadata(
    metadata: Vec<u8>,
    signature: Vec<u8>,
    config: &Config,
) -> Result<VerifiedAppMetadata> {
    if app_metadata_is_unsigned(&parse_exact_app_metadata(&metadata)?) {
        return Err(AppError::BadRequest(
            "an offline update must carry a release signature".into(),
        ));
    }
    authenticate_app_metadata(metadata, signature, config).await
}

fn seal_signed(archive: AppDownload, verified: &VerifiedAppMetadata) -> Result<AppArchive> {
    archive
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
        })
}

fn prepare_app_candidate(
    mut source: AppArchive,
    stage: AppStage,
    authority: &InstallAuthority,
) -> Result<AppCandidate> {
    use crate::update::app_slot::Import;
    use sha2::{Digest, Sha256};
    let (size, archive_sha512) = source.fingerprint()?;
    let (import, metadata_sha256, signature_sha256) = match authority {
        #[cfg(test)]
        InstallAuthority::ManualImport => (Import::Manual, [0; 32], [0; 32]),
        InstallAuthority::SignedMetadata(verified) => {
            if size != verified.latest.size
                || archive_sha512 != decode_sha512(&verified.latest.sha512)?
            {
                return Err(AppError::BadRequest(
                    "app candidate differs from authenticated archive metadata".into(),
                ));
            }
            let metadata = Sha256::digest(&verified.metadata).into();
            if app_metadata_is_unsigned(&verified.latest) {
                (Import::UnsignedLab, metadata, [0; 32])
            } else {
                (
                    Import::Signed,
                    metadata,
                    Sha256::digest(&verified.signature).into(),
                )
            }
        }
    };
    let extracted = stage.extract(source)?;
    let update_root = resolve_update_root(&extracted)?;
    let version = validate_update_root(&update_root)?;
    if let InstallAuthority::SignedMetadata(verified) = authority
        && version != verified.latest.version
    {
        return Err(AppError::BadRequest(
            "app candidate version differs from authenticated metadata".into(),
        ));
    }
    crate::update::helper_family::check_candidate(&update_root).map_err(|_| {
        AppError::BadRequest("app candidate helper family is incomplete or inconsistent".into())
    })?;
    Ok(AppCandidate {
        input: crate::update::app_slot::CandidateInput {
            root: update_root,
            stage,
            version,
            import,
            archive_sha512,
            metadata_sha256,
            signature_sha256,
        },
    })
}

/// Hands a verified candidate to the independent installer in the native
/// broker. The prepared record is durable before the handoff, and the installer
/// answers before it stops this backend for its frozen trial. Nothing here waits
/// for an outcome: observe the returned transaction instead of submitting again.
fn submit_package(
    source: AppArchive,
    stage: AppStage,
    authority: InstallAuthority,
    handoff: Handoff,
) -> Result<[u8; 16]> {
    let candidate = prepare_app_candidate(source, stage, &authority)?;
    // This backend still runs: past the installer's stop a refusal would cost
    // the management path until a reboot.
    app_slot::check_candidate(&candidate.input.root).map_err(|_| {
        AppError::Conflict(
            "this device cannot take that package by an application update; nothing changed".into(),
        )
    })?;
    // A prepared record that no installer accepts blocks further updates until
    // boot recovery retires it, so refuse first when nobody is listening.
    drop(connect_installer()?);
    let prepared = app_slot::prepare(candidate, handoff).map_err(slot_error)?;
    let transaction = prepared.transaction();
    let handoff = prepared.into_handoff();
    // Connect again: the installer drops an idle offer after five seconds,
    // and preparation syncs the whole candidate first.
    let installer = match connect_installer() {
        Ok(installer) => installer,
        Err(error) => {
            withdraw_refused(transaction);
            return Err(error);
        }
    };
    match installer.offer(handoff) {
        Ok(Answer::Refused(handoff)) => {
            withdraw_refused(transaction);
            drop(handoff);
            Err(AppError::Conflict(
                "the installer did not take this update; nothing changed, try again".into(),
            ))
        }
        Ok(_) => Ok(transaction),
        Err(error) => Err(AppError::Internal(format!(
            "the installer did not take update {:032x} ({error}); check its job status, \
             do not submit it again",
            u128::from_be_bytes(transaction)
        ))),
    }
}

/// Otherwise the record stops further updates until boot recovery retires it.
fn withdraw_refused(transaction: [u8; 16]) {
    if let Err(error) = app_slot::withdraw(transaction) {
        tracing::warn!(%error, "the refused update stays recorded until the next boot");
    }
}

fn connect_installer() -> Result<Sender> {
    Sender::connect_broker()
        .map_err(|error| AppError::Conflict(format!("the app installer is not available: {error}")))
}

fn slot_error(error: SlotError) -> AppError {
    match error {
        SlotError::Busy => AppError::Conflict(
            "another app update transaction is recorded; check its job status".into(),
        ),
        other => AppError::Internal(format!("app update preparation failed: {other}")),
    }
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
    verify_metadata_signature(
        metadata,
        signature,
        &config.paths.system_update_public_key,
        &latest.signature_key_id,
        METADATA_TIMEOUT,
    )
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

/// The offline API's handoff for fixture archive bytes: the same verified
/// candidate preparation and installer submission as `offline_update`.
#[cfg(all(test, feature = "sandbox-test-fixture"))]
pub(crate) fn submit_manual_fixture(
    stage: AppStage,
    bytes: &[u8],
    handoff: Handoff,
) -> Result<[u8; 16]> {
    let mut download = stage.create_archive()?;
    download.append(bytes)?;
    submit_package(
        download.finish_manual_import()?,
        stage,
        InstallAuthority::ManualImport,
        handoff,
    )
}

#[cfg(test)]
pub(crate) fn manual_candidate_fixture(stage: AppStage, bytes: &[u8]) -> Result<AppCandidate> {
    let mut download = stage.create_archive()?;
    download.append(bytes)?;
    prepare_app_candidate(
        download.finish_manual_import()?,
        stage,
        &InstallAuthority::ManualImport,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn an_online_update_only_moves_forward() {
        check_forward("2.0.42", "2.0.43").unwrap();
        check_forward("2.0.42", "2.1.0").unwrap();
        check_forward("2.0.9", "2.0.10").unwrap();
        for offered in ["2.0.42", "2.0.41", "1.9.99"] {
            assert!(
                matches!(check_forward("2.0.42", offered), Err(AppError::Conflict(_))),
                "{offered}"
            );
        }
        for (installed, offered) in [("2.0.42", "2.0.43-rc1"), ("unknown", "2.0.43")] {
            assert!(matches!(
                check_forward(installed, offered),
                Err(AppError::BadRequest(_))
            ));
        }
    }

    async fn multipart_fixture(body: Vec<u8>) -> Multipart {
        use axum::{body::Body, extract::FromRequest, http::Request};
        let request = Request::builder()
            .header("content-type", "multipart/form-data; boundary=fixture")
            .body(Body::from(body))
            .unwrap();
        Multipart::from_request(request, &()).await.unwrap()
    }

    fn signed_parts() -> Vec<u8> {
        let mut body = Vec::new();
        for (name, bytes) in [("metadata", "{}"), ("signature", "synthetic signature")] {
            body.extend_from_slice(
                format!(
                    "--fixture\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{bytes}\r\n"
                )
                .as_bytes(),
            );
        }
        body
    }

    async fn upload_fixture(payload: &[u8], complete: bool) -> Multipart {
        let mut body = signed_parts();
        body.extend_from_slice(b"--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hardened-nanokvm-kvmapp-2.0.43.tar.gz\"\r\n\r\n");
        body.extend_from_slice(payload);
        if complete {
            body.extend_from_slice(b"\r\n--fixture--\r\n");
        }
        multipart_fixture(body).await
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
        let package =
            owner
                .run(move |job| async move {
                    save_uploaded_update(download, &mut multipart, &job).await
                })
                .await
                .unwrap();
        assert_eq!(package.metadata, b"{}");
        assert_eq!(package.signature, b"synthetic signature");
        let mut archive = package.archive.finish_manual_import().unwrap();
        let mut actual = Vec::new();
        archive.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, payload);
        let snapshot = coordinator.snapshot().unwrap();
        assert!(snapshot.active.is_none() && snapshot.last.unwrap().phase == Phase::Finished);
    }

    #[tokio::test]
    async fn an_upload_needs_the_metadata_and_the_signature_of_its_release() {
        use crate::update::operation::UpdateCoordinator;
        use std::sync::Arc;
        let file = b"--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\"hardened-nanokvm-kvmapp-2.0.43.tar.gz\"\r\n\r\nsynthetic archive\r\n";
        let signature =
            b"--fixture\r\nContent-Disposition: form-data; name=\"signature\"\r\n\r\nsynthetic\r\n";
        let metadata =
            b"--fixture\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{}\r\n";
        for parts in [
            vec![&file[..]],
            vec![&file[..], &signature[..]],
            vec![&file[..], &metadata[..]],
        ] {
            let mut body = parts.concat();
            body.extend_from_slice(b"--fixture--\r\n");
            let mut multipart = multipart_fixture(body).await;
            let temporary = tempfile::tempdir().unwrap();
            let stage = AppStage::fixture(temporary.path()).unwrap();
            let download = stage.create_archive().unwrap();
            let owner = Arc::new(UpdateCoordinator::in_process_fixture())
                .acquire(Kind::ApplicationOffline)
                .unwrap();
            let error = owner
                .run(move |job| async move {
                    save_uploaded_update(download, &mut multipart, &job).await
                })
                .await
                .err()
                .unwrap();
            assert!(error.to_string().contains("latest.json"), "{error}");
        }
    }

    #[tokio::test]
    async fn repeated_or_oversized_release_files_are_refused() {
        use crate::update::operation::UpdateCoordinator;
        use std::sync::Arc;
        let part = |name: &str, bytes: &str| {
            format!(
                "--fixture\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{bytes}\r\n"
            )
        };
        let oversized = "x".repeat(MAX_METADATA + 1);
        for (body, expected) in [
            (
                part("metadata", "{}") + &part("metadata", "{}"),
                "multiple update metadata",
            ),
            (
                part("signature", "a") + &part("signature", "b"),
                "multiple update signatures",
            ),
            (part("metadata", &oversized), "too large"),
        ] {
            let mut multipart = multipart_fixture((body + "--fixture--\r\n").into_bytes()).await;
            let temporary = tempfile::tempdir().unwrap();
            let stage = AppStage::fixture(temporary.path()).unwrap();
            let download = stage.create_archive().unwrap();
            let owner = Arc::new(UpdateCoordinator::in_process_fixture())
                .acquire(Kind::ApplicationOffline)
                .unwrap();
            let error = owner
                .run(move |job| async move {
                    save_uploaded_update(download, &mut multipart, &job).await
                })
                .await
                .err()
                .unwrap();
            assert!(error.to_string().contains(expected), "{error}");
        }
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
            let extracted = stage.extract(archive).unwrap();
            let app = resolve_update_root(&extracted).unwrap();
            validate_update_root(&app).unwrap();
            assert_eq!(
                fs::read_to_string(app.join("version")).unwrap().trim(),
                version
            );
        }
    }
    fn retained_manual_app_archive(stage: &AppStage, path: &Path, expected: &str) -> AppArchive {
        use sha2::{Digest, Sha256};
        let mut download = stage.create_archive().unwrap();
        let mut source = fs::File::open(path).unwrap();
        assert!(source.metadata().unwrap().len() <= MAX_UPDATE_BYTES);
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = source.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            download.append(&buffer[..count]).unwrap();
        }
        assert_eq!(format!("{:x}", hash.finalize()), expected);
        download.finish_manual_import().unwrap()
    }

    fn assert_legacy_app_boot_profile(app: &Path, private_root: &Path) {
        use sha2::{Digest, Sha256};
        assert_eq!(read_candidate_version(app).unwrap(), "0.0.0");
        for name in ["S02apprecover", "S30eth", "S30wifi"] {
            assert!(!app.join("system/init.d").join(name).exists());
        }
        let s95 = fs::read(app.join("system/init.d/S95nanokvm")).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&s95)),
            "8030d0f81581a417eca91e3db7e0c3d96cba197b519022d7c73c3c5caca05365"
        );
        assert!(!private_root.join("kvmapp").exists());
        assert!(!private_root.join("application-slot").exists());
        assert!(!private_root.join("etc/init.d").exists());
        assert!(!private_root.join("usr/libexec").exists());
    }

    #[test]
    #[ignore = "requires retained pre-native-family development app archives"]
    fn historical_boot_delivery_packages_are_readable_but_not_full_family_candidates() {
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for side in ["a", "b"] {
            let path = project.join(format!(
                "build/audit/remediation-2026-10-17/host/app-boot-delivery-valid-{side}/out/boot-delivery-fixture.tar.gz"
            ));
            let root = tempfile::tempdir().unwrap();
            let stage = AppStage::fixture(root.path()).unwrap();
            let archive = retained_manual_app_archive(
                &stage,
                &path,
                "c347842bb1fbbabd645a4feefcc5d9c50f4b38a3f798bdf8a153ffaddcafcbd0",
            );
            let extracted = stage.extract(archive).unwrap();
            let app = resolve_update_root(&extracted).unwrap();
            validate_update_root(&app).unwrap();
            assert_legacy_app_boot_profile(&app, root.path());
            assert!(app.join("system/bin/nanokvm-app-recovery").is_file());
            for role in &crate::update::helper_family::ROLES[1..] {
                assert!(!app.join("system/bin").join(role.filename()).exists());
            }
            // Preserve historical readability/boot-profile evidence without
            // promoting a pre-family fixture into a current install candidate.
            let candidate_stage = AppStage::fixture(root.path()).unwrap();
            let archive = retained_manual_app_archive(
                &candidate_stage,
                &path,
                "c347842bb1fbbabd645a4feefcc5d9c50f4b38a3f798bdf8a153ffaddcafcbd0",
            );
            let error =
                prepare_app_candidate(archive, candidate_stage, &InstallAuthority::ManualImport)
                    .err()
                    .unwrap();
            assert_eq!(
                error.to_string(),
                "bad request: app candidate helper family is incomplete or inconsistent"
            );
            assert_legacy_app_boot_profile(&app, root.path());
        }
    }

    #[test]
    #[ignore = "requires retained current complete-family development app archives"]
    fn current_boot_delivery_packages_use_private_production_preflight_without_installing() {
        let project = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        for side in ["a", "b"] {
            let path = project.join(format!(
                "build/audit/remediation-2026-10-17/host/helper-family-candidate-valid-{side}/out/helper-family-fixture.tar.gz"
            ));
            let root = tempfile::tempdir().unwrap();
            let stage = AppStage::fixture(root.path()).unwrap();
            let archive = retained_manual_app_archive(
                &stage,
                &path,
                "ab9ce7e0bf07299a09083584bac0754d8da780b82c69a75ed4ec27267dc30a3c",
            );
            let app =
                prepare_app_candidate(archive, stage, &InstallAuthority::ManualImport).unwrap();
            let app = &app.input.root;
            assert_legacy_app_boot_profile(app, root.path());
            for role in crate::update::helper_family::ROLES {
                assert!(app.join("system/bin").join(role.filename()).is_file());
            }
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
