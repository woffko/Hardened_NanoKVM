use axum::{Json, extract::Multipart, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command, time};

use crate::{AppError, Result, error::ApiResponse};

pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;
const MAX_SCRIPT_OUTPUT_BYTES: usize = 64 * 1024;
const SCRIPT_DIRECTORY: &str = "/etc/kvm/scripts";
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Serialize)]
pub struct GetScriptsRsp {
    pub files: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UploadScriptRsp {
    pub file: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteScriptReq {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct RunScriptReq {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Serialize)]
pub struct RunScriptRsp {
    pub log: String,
}

pub async fn get_scripts() -> Result<impl IntoResponse> {
    let mut files = Vec::new();
    let dir = Path::new(SCRIPT_DIRECTORY);
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
            if is_script_name(&name) {
                files.push(name);
            }
        }
    }
    files.sort();

    Ok(Json(ApiResponse::ok(GetScriptsRsp { files })))
}

pub async fn upload_script(mut multipart: Multipart) -> Result<impl IntoResponse> {
    let mut uploaded = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::BadRequest(format!("invalid multipart script upload: {err}")))?
    {
        if field.name() != Some("file") {
            continue;
        }
        let filename = field
            .file_name()
            .ok_or_else(|| AppError::BadRequest("missing script filename".to_string()))?
            .to_string();
        let filename = validate_script_name(&filename)?;
        let data = field
            .bytes()
            .await
            .map_err(|err| AppError::BadRequest(format!("read script upload failed: {err}")))?;
        if data.len() > MAX_SCRIPT_BYTES {
            return Err(AppError::BadRequest("script file is too large".to_string()));
        }
        if data.is_empty() {
            return Err(AppError::BadRequest("script file is empty".to_string()));
        }

        write_script_file(&filename, &data)?;
        uploaded = Some(filename);
        break;
    }

    let file = uploaded.ok_or_else(|| AppError::BadRequest("missing script file".to_string()))?;
    Ok(Json(ApiResponse::ok(UploadScriptRsp { file })))
}

pub async fn delete_script(Json(req): Json<DeleteScriptReq>) -> Result<impl IntoResponse> {
    let path = checked_script_path(&req.name)?;
    remove_script_file(&path)?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn run_script(Json(req): Json<RunScriptReq>) -> Result<impl IntoResponse> {
    let path = checked_script_path(&req.name)?;
    match req.kind.as_str() {
        "foreground" => {
            let log = run_script_foreground(&path).await?;
            Ok(Json(ApiResponse::ok(RunScriptRsp { log })))
        }
        "background" => {
            run_script_background(&path)?;
            Ok(Json(ApiResponse::ok(RunScriptRsp { log: String::new() })))
        }
        _ => Err(AppError::BadRequest("invalid script run type".to_string())),
    }
}

fn validate_script_name(name: &str) -> Result<String> {
    let name = name.trim();
    if !is_script_name(name) {
        return Err(AppError::BadRequest("invalid script filename".to_string()));
    }
    if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
        return Err(AppError::BadRequest("invalid script filename".to_string()));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(AppError::BadRequest("invalid script filename".to_string()));
    }
    Ok(name.to_string())
}

fn is_script_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.ends_with(".sh") || lower.ends_with(".py")) && name.len() <= 128 && name.len() > 3
}

fn script_path(name: &str) -> Result<PathBuf> {
    Ok(Path::new(SCRIPT_DIRECTORY).join(validate_script_name(name)?))
}

fn checked_script_path(name: &str) -> Result<PathBuf> {
    let path = script_path(name)?;
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::BadRequest("invalid script file".to_string()));
    }
    Ok(path)
}

fn write_script_file(name: &str, data: &[u8]) -> Result<()> {
    fs::create_dir_all(SCRIPT_DIRECTORY)?;
    let path = script_path(name)?;
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() {
            return Err(AppError::BadRequest("invalid script file".to_string()));
        }
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)?;
    file.write_all(data)?;
    file.flush()?;
    Ok(())
}

fn remove_script_file(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
    Ok(())
}

async fn run_script_foreground(path: &Path) -> Result<String> {
    let mut child = script_command(path)?
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");
    let stdout_task = tokio::spawn(async move { read_limited(&mut stdout).await });
    let stderr_task = tokio::spawn(async move { read_limited(&mut stderr).await });
    let status = time::timeout(SCRIPT_TIMEOUT, child.wait())
        .await
        .map_err(|_| AppError::Internal("script timed out".to_string()))??;
    let stdout = stdout_task
        .await
        .map_err(|err| AppError::Internal(format!("script stdout task failed: {err}")))??;
    let stderr = stderr_task
        .await
        .map_err(|err| AppError::Internal(format!("script stderr task failed: {err}")))??;

    let mut output = stdout;
    output.extend_from_slice(&stderr);
    if !status.success() {
        return Err(AppError::Internal("run script failed".to_string()));
    }
    Ok(String::from_utf8_lossy(&output).to_string())
}

fn run_script_background(path: &Path) -> Result<()> {
    script_command(path)?
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}

fn script_command(path: &Path) -> Result<Command> {
    let extension = path
        .extension()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if extension == "py" {
        let mut command = Command::new("python");
        command.arg(path);
        Ok(command)
    } else if extension == "sh" {
        Ok(Command::new(path))
    } else {
        Err(AppError::BadRequest("invalid script filename".to_string()))
    }
}

async fn read_limited<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        let remaining = MAX_SCRIPT_OUTPUT_BYTES.saturating_sub(out.len());
        if remaining == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n.min(remaining)]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_script_names() {
        assert_eq!(validate_script_name("test.sh").unwrap(), "test.sh");
        assert_eq!(
            validate_script_name("hello_world-1.py").unwrap(),
            "hello_world-1.py"
        );
    }

    #[test]
    fn rejects_unsafe_script_names() {
        assert!(validate_script_name("../x.sh").is_err());
        assert!(validate_script_name("x.txt").is_err());
        assert!(validate_script_name("bad name.sh").is_err());
        assert!(validate_script_name("x.sh/evil").is_err());
    }
}
