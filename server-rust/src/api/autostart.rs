use axum::{
    Json,
    extract::Path as AxumPath,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{AppError, Result, error::ApiResponse};

pub const MAX_AUTOSTART_BYTES: usize = 256 * 1024;
const AUTOSTART_DIRECTORY: &str = "/etc/kvm/autostart";

#[derive(Debug, Serialize)]
pub struct GetAutostartRsp {
    pub files: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UploadAutostartReq {
    pub content: String,
}

pub async fn get_autostart() -> Result<impl IntoResponse> {
    let mut files = Vec::new();
    let dir = Path::new(AUTOSTART_DIRECTORY);
    if dir.exists() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if is_autostart_name(&name) {
                files.push(name);
            }
        }
    }
    files.sort();

    Ok(Json(ApiResponse::ok(GetAutostartRsp { files })))
}

pub async fn get_autostart_content(AxumPath(name): AxumPath<String>) -> Result<Response> {
    let path = checked_autostart_path(&name)?;
    let metadata = fs::metadata(&path)?;
    if metadata.len() as usize > MAX_AUTOSTART_BYTES {
        return Err(AppError::BadRequest(
            "autostart file is too large".to_string(),
        ));
    }

    let content = fs::read(&path)?;
    Ok(Json(ApiResponse::ok(
        String::from_utf8_lossy(&content).to_string(),
    ))
    .into_response())
}

pub async fn upload_autostart(
    AxumPath(name): AxumPath<String>,
    Json(req): Json<UploadAutostartReq>,
) -> Result<Response> {
    let name = validate_autostart_name(&name)?;
    if req.content.len() > MAX_AUTOSTART_BYTES {
        return Err(AppError::BadRequest(
            "autostart content is too large".to_string(),
        ));
    }

    write_autostart_file(&name, req.content.as_bytes())?;
    Ok(Json(ApiResponse::ok(name)).into_response())
}

pub async fn delete_autostart(AxumPath(name): AxumPath<String>) -> Result<impl IntoResponse> {
    let path = checked_autostart_path(&name)?;
    fs::remove_file(path)?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

fn validate_autostart_name(name: &str) -> Result<String> {
    let name = name.trim();
    if !is_autostart_name(name) {
        return Err(AppError::BadRequest(
            "invalid autostart filename".to_string(),
        ));
    }
    Ok(name.to_string())
}

fn is_autostart_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn autostart_path(name: &str) -> Result<PathBuf> {
    Ok(Path::new(AUTOSTART_DIRECTORY).join(validate_autostart_name(name)?))
}

fn checked_autostart_path(name: &str) -> Result<PathBuf> {
    let path = autostart_path(name)?;
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::BadRequest("invalid autostart file".to_string()));
    }
    Ok(path)
}

fn write_autostart_file(name: &str, data: &[u8]) -> Result<()> {
    fs::create_dir_all(AUTOSTART_DIRECTORY)?;
    let path = autostart_path(name)?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() {
            return Err(AppError::BadRequest("invalid autostart file".to_string()));
        }
    }

    let tmp = temporary_path(name)?;
    let result = write_temp_file(&tmp, data).and_then(|_| fs::rename(&tmp, &path));
    if let Err(err) = result {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    Ok(())
}

fn write_temp_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(data)?;
    file.flush()?;
    Ok(())
}

fn temporary_path(name: &str) -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| AppError::Internal(format!("system clock error: {err}")))?
        .as_nanos();
    Ok(Path::new(AUTOSTART_DIRECTORY).join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        timestamp
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_autostart_names() {
        assert_eq!(validate_autostart_name("S99custom").unwrap(), "S99custom");
        assert_eq!(
            validate_autostart_name("boot-hook_1.sh").unwrap(),
            "boot-hook_1.sh"
        );
    }

    #[test]
    fn rejects_unsafe_autostart_names() {
        assert!(validate_autostart_name("../S99custom").is_err());
        assert!(validate_autostart_name("bad name").is_err());
        assert!(validate_autostart_name("x/y").is_err());
        assert!(validate_autostart_name("").is_err());
    }
}
