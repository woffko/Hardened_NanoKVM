use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::{Result, error::ApiResponse};

const APP_VERSION_FILE: &str = "/kvmapp/version";
const PREVIEW_UPDATES_FLAG: &str = "/etc/kvm/preview_updates";

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

pub async fn get_version() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(VersionRsp {
        current: read_trimmed(APP_VERSION_FILE).unwrap_or_else(|| "1.0.0".to_string()),
        latest: String::new(),
    })))
}

pub async fn get_preview() -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(PreviewRsp {
        enabled: Path::new(PREVIEW_UPDATES_FLAG).exists(),
    })))
}

pub async fn set_preview(Json(req): Json<SetPreviewReq>) -> Result<impl IntoResponse> {
    let is_enabled = Path::new(PREVIEW_UPDATES_FLAG).exists();
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

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
