use axum::{
    Json,
    extract::{Multipart, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
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
const REMOTE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

#[derive(Debug, Deserialize)]
pub struct DownloadImageReq {
    #[serde(default)]
    pub file: String,
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

pub async fn status_image() -> Result<impl IntoResponse> {
    let Ok(content) = fs::read_to_string(SENTINEL_PATH) else {
        return Ok(Json(ApiResponse::ok(StatusImageRsp::idle())));
    };

    let mut parts = content.splitn(2, ';');
    Ok(Json(ApiResponse::ok(StatusImageRsp {
        status: "in_progress".to_string(),
        file: parts.next().unwrap_or_default().to_string(),
        percentage: parts.next().unwrap_or_default().to_string(),
    })))
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

    let remote = validate_remote_iso_url(&req.file)?;
    let target = safe_upload_target(&state.config.paths.image_directory, &remote.filename)?;
    let guard = DownloadGuard::acquire(&remote.url)?;
    let root = state.config.paths.image_directory.clone();

    tokio::spawn(async move {
        if let Err(err) = download_remote_iso(remote, root, target, guard).await {
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
        let mut temp = TempUpload::create(&state.config.paths.image_directory, &filename)?;
        let mut file = temp.open()?;
        let mut total = 0_usize;
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
            file.write_all(&chunk).await?;
            guard.update(&filename, total as u64, content_length)?;
        }
        file.flush().await?;
        drop(file);

        if !is_iso9660(temp.path())? {
            return Err(AppError::BadRequest(
                "file is not a valid ISO image".to_string(),
            ));
        }

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

#[derive(Debug)]
struct RemoteIso {
    url: String,
    filename: String,
}

async fn download_remote_iso(
    remote: RemoteIso,
    root: PathBuf,
    target: PathBuf,
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

    if !is_iso9660(temp.path())? {
        return Err(AppError::BadRequest(
            "file is not a valid ISO image".to_string(),
        ));
    }

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
        || !filename.ends_with(".iso")
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AppError::BadRequest("invalid filename".to_string()));
    }
    Ok(filename.to_string())
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
    file.read_exact(&mut magic)?;
    Ok(&magic == ISO9660_MAGIC)
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
    fn upload_filename_accepts_simple_iso_names() {
        assert_eq!(
            valid_upload_filename("rescue-1.0_x86.iso").unwrap(),
            "rescue-1.0_x86.iso"
        );
    }

    #[test]
    fn upload_filename_rejects_paths_and_non_iso_files() {
        for name in [
            "../evil.iso",
            "nested/evil.iso",
            "evil.img",
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
}
