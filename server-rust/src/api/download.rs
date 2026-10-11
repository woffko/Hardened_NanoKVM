use axum::{
    Json,
    extract::{Multipart, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::{
    AppError, Result,
    config::Config,
    error::ApiResponse,
    state::AppState,
    system::command::{AllowedCommand, run_allowed},
};

pub const MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024 * 1024;

const SENTINEL_PATH: &str = "/tmp/.download_in_progress";
const ISO9660_MAGIC_OFFSET: u64 = 0x8001;
const ISO9660_MAGIC: &[u8; 5] = b"CD001";
const SECTOR_SIZE: usize = 512;
const MASS_STORAGE_HEADER_BYTES: usize = 128 * 1024;
const GPT_HEADER_OFFSET: usize = SECTOR_SIZE;
const GPT_MAGIC: &[u8; 8] = b"EFI PART";
const EXT_SUPERBLOCK_MAGIC_OFFSET: usize = 1024 + 56;
const BTRFS_SUPERBLOCK_MAGIC_OFFSET: usize = 0x10040;
const BTRFS_MAGIC: &[u8; 8] = b"_BHRfS_M";
const REMOTE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const UPLOAD_STATUS_STALE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const REMOTE_STATUS_STALE_TIMEOUT: Duration = Duration::from_secs((2 * 60 * 60) + (5 * 60));
const SHA256_HEADER: &str = "x-sha256-sum";
const CHECKSUM_QUEUE_CHUNKS: usize = 8;
const SHA256_MISMATCH: &str = "sha256 mismatch";

/// Image whose remote download failed the checksum; reported once by the status
/// endpoint, because the background task has no other way to tell the UI.
static CHECKSUM_FAILURE: Mutex<Option<String>> = Mutex::new(None);

#[derive(Debug, Deserialize)]
pub struct DownloadImageReq {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub sha256sum: String,
}

#[derive(Debug, Serialize)]
pub struct ImageEnabledRsp {
    pub enabled: bool,
    #[serde(rename = "remoteEnabled")]
    pub remote_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct SetRemoteImageDownloadReq {
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct StatusImageRsp {
    pub status: String,
    pub file: String,
    pub percentage: String,
}

pub async fn image_enabled(State(state): State<AppState>) -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(ImageEnabledRsp {
        enabled: storage_writable(&state.config.paths.image_directory),
        remote_enabled: state.remote_image_download_enabled(),
    })))
}

pub async fn get_remote_image_download_enabled(
    State(state): State<AppState>,
) -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(ImageEnabledRsp {
        enabled: storage_writable(&state.config.paths.image_directory),
        remote_enabled: state.remote_image_download_enabled(),
    })))
}

pub async fn set_remote_image_download_enabled(
    State(state): State<AppState>,
    Json(req): Json<SetRemoteImageDownloadReq>,
) -> Result<impl IntoResponse> {
    let mut config = Config::read()?;
    config.security.allow_remote_image_download = req.enabled;
    config.write()?;
    state.set_remote_image_download_enabled(req.enabled);

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

/// Whether an image download or upload is running.
pub fn transfer_in_progress() -> bool {
    read_status_image(Path::new(SENTINEL_PATH))
        .map(|status| status.status == "in_progress")
        .unwrap_or(false)
}

pub async fn status_image() -> Result<impl IntoResponse> {
    let status = read_status_image(Path::new(SENTINEL_PATH))?;
    if status.status == "idle"
        && let Some(file) = take_checksum_failure()
    {
        return Ok(Json(ApiResponse::ok(StatusImageRsp::checksum_failed(file))));
    }
    Ok(Json(ApiResponse::ok(status)))
}

pub async fn download_image(
    State(state): State<AppState>,
    Json(req): Json<DownloadImageReq>,
) -> Result<Json<ApiResponse<StatusImageRsp>>> {
    if !state.remote_image_download_enabled() {
        return Err(AppError::Api {
            code: -403,
            msg: "remote image download is disabled".to_string(),
        });
    }

    crate::api::storage::ensure_writable(&state.config.paths.image_directory)?;
    let expected_sha256 = parse_sha256(&req.sha256sum)?;
    let remote = validate_remote_iso_url(&req.file)?;
    let target = safe_upload_target(&state.config.paths.image_directory, &remote.filename)?;
    ensure_not_mounted(&target)?;
    let guard = DownloadGuard::acquire(&remote.url)?;
    let root = state.config.paths.image_directory.clone();

    tokio::spawn(async move {
        if let Err(err) = download_remote_iso(remote, root, target, expected_sha256, guard).await {
            tracing::error!(error = %err, "remote ISO download failed");
        }
    });

    Ok(Json(ApiResponse::ok(StatusImageRsp {
        status: "in_progress".to_string(),
        file: req.file,
        percentage: String::new(),
    })))
}

pub async fn upload_image_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<impl IntoResponse> {
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if content_length
        .map(|len| len as usize > MAX_UPLOAD_BYTES + 1024 * 1024)
        .unwrap_or(false)
    {
        return Err(AppError::BadRequest("upload is too large".to_string()));
    }

    crate::api::storage::ensure_writable(&state.config.paths.image_directory)?;
    let expected_sha256 = parse_sha256(
        headers
            .get(SHA256_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
    )?;
    let guard = DownloadGuard::acquire("upload")?;
    let mut uploaded = false;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid multipart data: {err}")))?
    {
        if field.name() != Some("file") {
            continue;
        }
        if uploaded {
            return Err(AppError::BadRequest(
                "only one file upload is allowed".to_string(),
            ));
        }

        let filename = valid_upload_filename(field.file_name().unwrap_or_default())?;
        guard.update(&filename, 0, content_length)?;

        let target = safe_upload_target(&state.config.paths.image_directory, &filename)?;
        ensure_not_mounted(&target)?;
        let mut temp = TempUpload::create(&state.config.paths.image_directory, &filename)?;
        let mut file = temp.open()?;
        let mut total = 0_usize;
        let checksum = expected_sha256.map(|_| ChecksumWorker::spawn());
        let mut field = field;

        while let Some(chunk) = field
            .chunk()
            .await
            .map_err(|err| AppError::BadRequest(format!("invalid multipart chunk: {err}")))?
        {
            total = total.saturating_add(chunk.len());
            if total > MAX_UPLOAD_BYTES {
                return Err(AppError::BadRequest("upload is too large".to_string()));
            }
            if let Some(worker) = &checksum {
                worker.feed(chunk.clone()).await?;
            }
            file.write_all(&chunk).await?;
            guard.update(&filename, total as u64, content_length)?;
        }
        file.flush().await?;
        drop(file);

        if let (Some(expected), Some(worker)) = (expected_sha256, checksum)
            && worker.finish().await? != expected
        {
            return Err(AppError::BadRequest(SHA256_MISMATCH.to_string()));
        }

        validate_uploaded_image(temp.path(), &filename)?;

        // The image may have been mounted while it uploaded.
        ensure_not_mounted(&target)?;
        fs::rename(temp.path(), &target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))?;
        temp.keep();
        uploaded = true;
    }

    if !uploaded {
        return Err(AppError::BadRequest("no file part found".to_string()));
    }

    drop(guard);
    Ok(Json(ApiResponse::ok(StatusImageRsp::idle())))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum UploadImageKind {
    Iso,
    MassStorage,
}

#[derive(Debug)]
struct RemoteIso {
    url: String,
    filename: String,
}

async fn download_remote_iso(
    remote: RemoteIso,
    root: PathBuf,
    target: PathBuf,
    expected_sha256: Option<[u8; 32]>,
    _guard: DownloadGuard,
) -> Result<()> {
    let mut temp = TempUpload::create(&root, &remote.filename)?;
    let output = download_remote_with_curl(&remote.url, temp.path()).await?;
    if output.status != 0 {
        return Err(AppError::Internal(command_error(
            "download remote ISO failed",
            output,
        )));
    }

    let size = fs::metadata(temp.path())?.len();
    if size == 0 || size > MAX_UPLOAD_BYTES as u64 {
        return Err(AppError::BadRequest(
            "invalid downloaded ISO size".to_string(),
        ));
    }

    if let Some(expected) = expected_sha256 {
        let path = temp.path().to_path_buf();
        let actual = tokio::task::spawn_blocking(move || sha256_file(&path))
            .await
            .map_err(|err| AppError::Internal(format!("checksum task failed: {err}")))??;
        if actual != expected {
            record_checksum_failure(&remote.filename);
            return Err(AppError::BadRequest(SHA256_MISMATCH.to_string()));
        }
    }

    if !is_iso9660(temp.path())? {
        return Err(AppError::BadRequest(
            "file is not a valid ISO image".to_string(),
        ));
    }

    ensure_not_mounted(&target)?;
    fs::rename(temp.path(), &target)?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644))?;
    temp.keep();
    Ok(())
}

async fn download_remote_with_curl(
    url: &str,
    target: &Path,
) -> Result<crate::system::command::CommandOutput> {
    let args = vec![
        OsString::from("--fail"),
        OsString::from("--location"),
        OsString::from("--proto"),
        OsString::from("=http,https"),
        OsString::from("--proto-redir"),
        OsString::from("=http,https"),
        OsString::from("--max-redirs"),
        OsString::from("5"),
        OsString::from("--connect-timeout"),
        OsString::from("20"),
        OsString::from("--max-time"),
        OsString::from(REMOTE_DOWNLOAD_TIMEOUT.as_secs().to_string()),
        OsString::from("--speed-limit"),
        OsString::from("1024"),
        OsString::from("--speed-time"),
        OsString::from("120"),
        OsString::from("--max-filesize"),
        OsString::from(MAX_UPLOAD_BYTES.to_string()),
        OsString::from("--output"),
        target.as_os_str().to_os_string(),
        OsString::from(url),
    ];
    run_allowed(AllowedCommand::Curl, args, REMOTE_DOWNLOAD_TIMEOUT).await
}

/// Parses an optional SHA-256 checksum given as 64 hexadecimal characters.
/// Hashes an upload as it streams in, on its own thread, so the async worker
/// stays free and no read-back is needed once the last byte has arrived.
struct ChecksumWorker {
    tx: tokio::sync::mpsc::Sender<Bytes>,
    task: tokio::task::JoinHandle<[u8; 32]>,
}

impl ChecksumWorker {
    fn spawn() -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(CHECKSUM_QUEUE_CHUNKS);
        let task = tokio::task::spawn_blocking(move || {
            let mut hasher = Sha256::new();
            while let Some(chunk) = rx.blocking_recv() {
                hasher.update(&chunk);
            }
            hasher.finalize().into()
        });
        Self { tx, task }
    }

    /// Waits when the hasher is behind, which slows the upload to its pace.
    async fn feed(&self, chunk: Bytes) -> Result<()> {
        self.tx
            .send(chunk)
            .await
            .map_err(|_| AppError::Internal("checksum task stopped".to_string()))
    }

    async fn finish(self) -> Result<[u8; 32]> {
        drop(self.tx);
        self.task
            .await
            .map_err(|err| AppError::Internal(format!("checksum task failed: {err}")))
    }
}

fn parse_sha256(value: &str) -> Result<Option<[u8; 32]>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }

    let invalid = || AppError::BadRequest("invalid sha256sum".to_string());
    if value.len() != 64 || !value.is_ascii() {
        return Err(invalid());
    }

    let mut sum = [0_u8; 32];
    for (byte, pair) in sum.iter_mut().zip(value.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
    }
    Ok(Some(sum))
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn record_checksum_failure(file: &str) {
    if let Ok(mut failure) = CHECKSUM_FAILURE.lock() {
        *failure = Some(file.to_string());
    }
}

fn take_checksum_failure() -> Option<String> {
    CHECKSUM_FAILURE.lock().ok()?.take()
}

fn validate_remote_iso_url(raw: &str) -> Result<RemoteIso> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 2048 || raw.chars().any(char::is_control) {
        return Err(AppError::BadRequest("invalid url".to_string()));
    }

    let parsed = Url::parse(raw).map_err(|_| AppError::BadRequest("invalid url".to_string()))?;
    match parsed.scheme() {
        "http" | "https" => {}
        _ => {
            return Err(AppError::BadRequest(
                "only http and https URLs are allowed".to_string(),
            ));
        }
    }
    if parsed.host_str().is_none() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::BadRequest("invalid url".to_string()));
    }

    let filename = parsed
        .path_segments()
        .and_then(|segments| segments.filter(|segment| !segment.is_empty()).next_back())
        .ok_or_else(|| AppError::BadRequest("url must end with an ISO filename".to_string()))?;
    let filename = valid_upload_filename(filename)?;
    if upload_image_kind(&filename) != Some(UploadImageKind::Iso) {
        return Err(AppError::BadRequest(
            "url must end with an ISO filename".to_string(),
        ));
    }

    Ok(RemoteIso {
        url: parsed.to_string(),
        filename,
    })
}

impl StatusImageRsp {
    fn idle() -> Self {
        Self {
            status: "idle".to_string(),
            file: String::new(),
            percentage: String::new(),
        }
    }

    fn in_progress(file: String, percentage: String) -> Self {
        Self {
            status: "in_progress".to_string(),
            file,
            percentage,
        }
    }

    fn checksum_failed(file: String) -> Self {
        Self {
            status: "checksum_failed".to_string(),
            file,
            percentage: String::new(),
        }
    }

    fn failed(file: String, percentage: String) -> Self {
        Self {
            status: "failed".to_string(),
            file,
            percentage,
        }
    }
}

fn read_status_image(path: &Path) -> Result<StatusImageRsp> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(StatusImageRsp::idle()),
        Err(err) => return Err(err.into()),
    };

    let mut parts = content.splitn(2, ';');
    let file = parts.next().unwrap_or_default().to_string();
    let percentage = parts.next().unwrap_or_default().to_string();

    if status_sentinel_is_stale(path, &file)? {
        let _ = fs::remove_file(path);
        return Ok(StatusImageRsp::failed(file, percentage));
    }

    Ok(StatusImageRsp::in_progress(file, percentage))
}

fn status_sentinel_is_stale(path: &Path, label: &str) -> Result<bool> {
    let modified = fs::metadata(path)?.modified()?;
    let Some(age) = modified.elapsed().ok() else {
        return Ok(false);
    };

    Ok(status_label_is_stale(label, age))
}

fn status_label_is_stale(label: &str, age: Duration) -> bool {
    let timeout = if is_remote_status_label(label) {
        REMOTE_STATUS_STALE_TIMEOUT
    } else {
        UPLOAD_STATUS_STALE_TIMEOUT
    };

    age > timeout
}

fn is_remote_status_label(label: &str) -> bool {
    label.starts_with("http://") || label.starts_with("https://")
}

struct DownloadGuard;

impl DownloadGuard {
    fn acquire(initial: &str) -> Result<Self> {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(SENTINEL_PATH)?
            .write_all(initial.as_bytes())?;
        // A new transfer supersedes an unreported checksum failure.
        let _ = take_checksum_failure();
        Ok(Self)
    }

    fn update(&self, label: &str, written: u64, total: Option<u64>) -> Result<()> {
        let percentage = total
            .filter(|total| *total > 0)
            .map(|total| format!("{:.2}%", (written as f64 / total as f64) * 100.0))
            .unwrap_or_default();
        let content = if percentage.is_empty() {
            label.to_string()
        } else {
            format!("{label};{percentage}")
        };
        fs::write(SENTINEL_PATH, content.as_bytes())?;
        Ok(())
    }
}

impl Drop for DownloadGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(SENTINEL_PATH);
    }
}

struct TempUpload {
    path: PathBuf,
    keep: bool,
}

impl TempUpload {
    fn create(root: &Path, filename: &str) -> Result<Self> {
        let path = root.join(format!(".{filename}.{}.upload", random_suffix()));
        Ok(Self { path, keep: false })
    }

    fn open(&self) -> Result<tokio::fs::File> {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.path)?;
        Ok(tokio::fs::File::from_std(file))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for TempUpload {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn storage_writable(root: &Path) -> bool {
    let path = root.join(format!(".nanokvm-write-test-{}", random_suffix()));
    let result = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path);
    let ok = result.is_ok();
    drop(result);
    let _ = fs::remove_file(path);
    ok
}

fn valid_upload_filename(filename: &str) -> Result<String> {
    let path = Path::new(filename);
    if filename.is_empty()
        || path.file_name().and_then(|name| name.to_str()) != Some(filename)
        || filename.contains("..")
        || upload_image_kind(filename).is_none()
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AppError::BadRequest("invalid filename".to_string()));
    }
    Ok(filename.to_string())
}

fn upload_image_kind(filename: &str) -> Option<UploadImageKind> {
    match Path::new(filename)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some(extension) if extension.eq_ignore_ascii_case("iso") => Some(UploadImageKind::Iso),
        Some(extension) if extension.eq_ignore_ascii_case("img") => {
            Some(UploadImageKind::MassStorage)
        }
        _ => None,
    }
}

/// Replacing a mounted image would leave the host serving the old, unlinked copy
/// and keep /data from going read-only.
fn ensure_not_mounted(target: &Path) -> Result<()> {
    if crate::api::storage::mounted_image_matches(target) {
        return Err(AppError::Conflict(
            "this image is mounted; unmount it before replacing it".to_string(),
        ));
    }
    Ok(())
}

fn safe_upload_target(root: &Path, filename: &str) -> Result<PathBuf> {
    let root = fs::canonicalize(root)?;
    let target = root.join(filename);

    if let Ok(metadata) = fs::symlink_metadata(&target) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AppError::BadRequest("invalid destination file".to_string()));
        }
    }

    Ok(target)
}

fn is_iso9660(path: &Path) -> Result<bool> {
    let mut file = fs::File::open(path)?;
    file.seek(SeekFrom::Start(ISO9660_MAGIC_OFFSET))?;
    let mut magic = [0_u8; 5];
    if let Err(err) = file.read_exact(&mut magic) {
        if err.kind() == ErrorKind::UnexpectedEof {
            return Ok(false);
        }
        return Err(err.into());
    }
    Ok(&magic == ISO9660_MAGIC)
}

fn validate_uploaded_image(path: &Path, filename: &str) -> Result<()> {
    let valid = match upload_image_kind(filename) {
        Some(UploadImageKind::Iso) => is_iso9660(path)?,
        Some(UploadImageKind::MassStorage) => is_mass_storage_image(path)?,
        None => false,
    };

    if !valid {
        return Err(AppError::BadRequest(
            "file is not a valid ISO or mass storage image".to_string(),
        ));
    }

    Ok(())
}

fn is_mass_storage_image(path: &Path) -> Result<bool> {
    let size = fs::metadata(path)?.len();
    if size < SECTOR_SIZE as u64 || size > MAX_UPLOAD_BYTES as u64 {
        return Ok(false);
    }

    let mut file = fs::File::open(path)?;
    let mut header = vec![0_u8; MASS_STORAGE_HEADER_BYTES.min(size as usize)];
    let read = file.read(&mut header)?;
    header.truncate(read);

    Ok(has_partition_table(&header)
        || has_superfloppy_filesystem(&header)
        || has_raw_filesystem(&header))
}

fn has_partition_table(header: &[u8]) -> bool {
    has_gpt_header(header)
        || header
            .get(..SECTOR_SIZE)
            .is_some_and(has_mbr_partition_table)
}

fn has_gpt_header(header: &[u8]) -> bool {
    header
        .get(GPT_HEADER_OFFSET..GPT_HEADER_OFFSET + GPT_MAGIC.len())
        .is_some_and(|magic| magic == GPT_MAGIC)
}

fn has_mbr_partition_table(sector: &[u8]) -> bool {
    has_boot_signature(sector)
        && sector[446..510].chunks_exact(16).any(|entry| {
            let boot_flag = entry[0];
            let partition_type = entry[4];
            let start_lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
            let sectors = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);

            matches!(boot_flag, 0x00 | 0x80)
                && partition_type != 0
                && start_lba != 0
                && sectors != 0
        })
}

fn has_superfloppy_filesystem(header: &[u8]) -> bool {
    let Some(sector) = header.get(..SECTOR_SIZE) else {
        return false;
    };
    if !has_boot_signature(sector) {
        return false;
    }

    if sector.get(3..11) == Some(b"EXFAT   ") {
        return true;
    }

    let jump = sector[0];
    if !matches!(jump, 0xeb | 0xe9) {
        return false;
    }

    let bytes_per_sector = u16::from_le_bytes([sector[11], sector[12]]);
    let sectors_per_cluster = sector[13];
    let reserved_sectors = u16::from_le_bytes([sector[14], sector[15]]);
    let fat_count = sector[16];
    let total_sectors_16 = u16::from_le_bytes([sector[19], sector[20]]);
    let total_sectors_32 = u32::from_le_bytes([sector[32], sector[33], sector[34], sector[35]]);
    let has_fat_label = sector
        .get(54..62)
        .is_some_and(|label| label.starts_with(b"FAT"))
        || sector
            .get(82..90)
            .is_some_and(|label| label.starts_with(b"FAT"));

    matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096)
        && sectors_per_cluster != 0
        && sectors_per_cluster.is_power_of_two()
        && reserved_sectors != 0
        && fat_count != 0
        && (total_sectors_16 != 0 || total_sectors_32 != 0)
        && has_fat_label
}

fn has_raw_filesystem(header: &[u8]) -> bool {
    header.starts_with(b"XFSB")
        || header
            .get(EXT_SUPERBLOCK_MAGIC_OFFSET..EXT_SUPERBLOCK_MAGIC_OFFSET + 2)
            .is_some_and(|magic| magic == [0x53, 0xef])
        || header
            .get(BTRFS_SUPERBLOCK_MAGIC_OFFSET..BTRFS_SUPERBLOCK_MAGIC_OFFSET + BTRFS_MAGIC.len())
            .is_some_and(|magic| magic == BTRFS_MAGIC)
}

fn has_boot_signature(sector: &[u8]) -> bool {
    sector.len() >= SECTOR_SIZE && sector[510] == 0x55 && sector[511] == 0xaa
}

fn random_suffix() -> String {
    let mut bytes = [0_u8; 9];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn command_error(message: &str, output: crate::system::command::CommandOutput) -> String {
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
    use std::{fs::File, io::Write, os::unix::fs as unix_fs};
    use tempfile::tempdir;

    #[test]
    fn upload_filename_accepts_simple_image_names() {
        assert_eq!(
            valid_upload_filename("rescue-1.0_x86.iso").unwrap(),
            "rescue-1.0_x86.iso"
        );
        assert_eq!(
            valid_upload_filename("usb-stick_2026.IMG").unwrap(),
            "usb-stick_2026.IMG"
        );
    }

    #[test]
    fn upload_filename_rejects_paths_and_non_image_files() {
        for name in [
            "../evil.iso",
            "nested/evil.iso",
            "evil.raw",
            "evil iso.iso",
            "",
        ] {
            let err = valid_upload_filename(name).unwrap_err();
            assert!(matches!(err, AppError::BadRequest(_)));
        }
    }

    #[test]
    fn remote_iso_url_accepts_http_and_https_iso_files() {
        let https =
            validate_remote_iso_url("https://example.com/images/rescue.iso?token=abc").unwrap();
        assert_eq!(https.filename, "rescue.iso");
        assert!(
            https
                .url
                .starts_with("https://example.com/images/rescue.iso")
        );

        let http = validate_remote_iso_url("http://example.com/rescue.iso").unwrap();
        assert_eq!(http.filename, "rescue.iso");
    }

    #[test]
    fn remote_iso_url_rejects_unsafe_or_non_iso_urls() {
        for url in [
            "file:///tmp/rescue.iso",
            "https://example.com/",
            "https://example.com/rescue.img",
            "https://user:pass@example.com/rescue.iso",
            "https://example.com/rescue iso.iso",
            "not a url",
        ] {
            assert!(validate_remote_iso_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn stale_status_detects_orphaned_upload_marker() {
        assert!(!status_label_is_stale(
            "debian.iso",
            UPLOAD_STATUS_STALE_TIMEOUT - Duration::from_secs(1)
        ));
        assert!(status_label_is_stale(
            "debian.iso",
            UPLOAD_STATUS_STALE_TIMEOUT + Duration::from_secs(1)
        ));
    }

    #[test]
    fn stale_status_allows_long_remote_download_marker() {
        assert!(!status_label_is_stale(
            "https://example.com/debian.iso",
            UPLOAD_STATUS_STALE_TIMEOUT + Duration::from_secs(1)
        ));
        assert!(status_label_is_stale(
            "https://example.com/debian.iso",
            REMOTE_STATUS_STALE_TIMEOUT + Duration::from_secs(1)
        ));
    }

    #[test]
    fn safe_upload_target_rejects_symlink_destination() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real.iso");
        let link = dir.path().join("link.iso");
        File::create(&real).unwrap();
        unix_fs::symlink(&real, &link).unwrap();

        let err = safe_upload_target(dir.path(), "link.iso").unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn iso_magic_is_checked_at_primary_volume_descriptor_offset() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("valid.iso");
        let mut file = File::create(&path).unwrap();
        file.write_all(&vec![0_u8; ISO9660_MAGIC_OFFSET as usize])
            .unwrap();
        file.write_all(ISO9660_MAGIC).unwrap();

        assert!(is_iso9660(&path).unwrap());
    }

    #[test]
    fn iso_magic_rejects_short_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("short.iso");
        File::create(&path).unwrap();

        assert!(!is_iso9660(&path).unwrap());
    }

    #[test]
    fn mass_storage_image_accepts_mbr_partition_table() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("usb.img");
        let mut sector = [0_u8; SECTOR_SIZE];
        sector[446] = 0x00;
        sector[446 + 4] = 0x0c;
        sector[446 + 8..446 + 12].copy_from_slice(&2048_u32.to_le_bytes());
        sector[446 + 12..446 + 16].copy_from_slice(&4096_u32.to_le_bytes());
        sector[510] = 0x55;
        sector[511] = 0xaa;
        File::create(&path).unwrap().write_all(&sector).unwrap();

        assert!(is_mass_storage_image(&path).unwrap());
        validate_uploaded_image(&path, "usb.img").unwrap();
    }

    #[test]
    fn mass_storage_image_accepts_gpt_header() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("usb.img");
        let mut image = vec![0_u8; SECTOR_SIZE * 2];
        image[GPT_HEADER_OFFSET..GPT_HEADER_OFFSET + GPT_MAGIC.len()].copy_from_slice(GPT_MAGIC);
        File::create(&path).unwrap().write_all(&image).unwrap();

        assert!(is_mass_storage_image(&path).unwrap());
    }

    #[test]
    fn mass_storage_image_accepts_fat_superfloppy() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("usb.img");
        let mut sector = [0_u8; SECTOR_SIZE];
        sector[0] = 0xeb;
        sector[1] = 0x3c;
        sector[2] = 0x90;
        sector[3..11].copy_from_slice(b"MSDOS5.0");
        sector[11..13].copy_from_slice(&512_u16.to_le_bytes());
        sector[13] = 1;
        sector[14..16].copy_from_slice(&1_u16.to_le_bytes());
        sector[16] = 2;
        sector[19..21].copy_from_slice(&2880_u16.to_le_bytes());
        sector[54..62].copy_from_slice(b"FAT16   ");
        sector[510] = 0x55;
        sector[511] = 0xaa;
        File::create(&path).unwrap().write_all(&sector).unwrap();

        assert!(is_mass_storage_image(&path).unwrap());
    }

    #[test]
    fn mass_storage_image_accepts_raw_ext_filesystem() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("usb.img");
        let mut image = vec![0_u8; EXT_SUPERBLOCK_MAGIC_OFFSET + 2];
        image[EXT_SUPERBLOCK_MAGIC_OFFSET..EXT_SUPERBLOCK_MAGIC_OFFSET + 2]
            .copy_from_slice(&[0x53, 0xef]);
        File::create(&path).unwrap().write_all(&image).unwrap();

        assert!(is_mass_storage_image(&path).unwrap());
    }

    #[test]
    fn mass_storage_image_rejects_random_data() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("random.img");
        File::create(&path)
            .unwrap()
            .write_all(&vec![0x42_u8; SECTOR_SIZE * 2])
            .unwrap();

        assert!(!is_mass_storage_image(&path).unwrap());
        let err = validate_uploaded_image(&path, "random.img").unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn parses_sha256_in_either_case() {
        let lower = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let upper = lower.to_ascii_uppercase();
        let expected = parse_sha256(lower).unwrap().unwrap();
        assert_eq!(expected[0], 0xba);
        assert_eq!(expected[31], 0xad);
        assert_eq!(
            parse_sha256(&format!("  {upper}\n")).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn empty_sha256_means_no_check() {
        assert_eq!(parse_sha256("").unwrap(), None);
        assert_eq!(parse_sha256("   ").unwrap(), None);
    }

    #[test]
    fn rejects_malformed_sha256() {
        for value in [
            "abc",
            &"a".repeat(63),
            &"a".repeat(65),
            &"g".repeat(64),
            &"é".repeat(32),
        ] {
            let err = parse_sha256(value).unwrap_err();
            assert!(matches!(err, AppError::BadRequest(_)), "{value}");
        }
    }

    #[test]
    fn hashes_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abc.iso");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            parse_sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()
                .unwrap()
        );
    }

    #[test]
    fn checksum_failure_is_reported_once() {
        record_checksum_failure("broken.iso");
        assert_eq!(take_checksum_failure().as_deref(), Some("broken.iso"));
        assert_eq!(take_checksum_failure(), None);
    }
    #[tokio::test]
    async fn checksum_worker_hashes_streamed_chunks() {
        let worker = ChecksumWorker::spawn();
        for part in [&b"a"[..], &b"b"[..], &b"c"[..]] {
            worker.feed(Bytes::copy_from_slice(part)).await.unwrap();
        }
        let expected =
            parse_sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()
                .unwrap();
        assert_eq!(worker.finish().await.unwrap(), expected);
    }
}
