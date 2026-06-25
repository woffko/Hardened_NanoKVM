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
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::io::AsyncWriteExt;

use crate::{AppError, Result, error::ApiResponse, state::AppState};

pub const MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024 * 1024;

const SENTINEL_PATH: &str = "/tmp/.download_in_progress";
const ISO9660_MAGIC_OFFSET: u64 = 0x8001;
const ISO9660_MAGIC: &[u8; 5] = b"CD001";

#[derive(Debug, Deserialize)]
pub struct DownloadImageReq {
    #[serde(default)]
    pub file: String,
}

#[derive(Debug, Serialize)]
pub struct ImageEnabledRsp {
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
    })))
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

pub async fn download_image(Json(_req): Json<DownloadImageReq>) -> Result<Json<ApiResponse<()>>> {
    Err(AppError::Unsupported(
        "remote image download is disabled in the Rust backend; upload an ISO file instead"
            .to_string(),
    ))
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
