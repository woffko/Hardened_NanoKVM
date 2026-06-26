use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("rate limited: {0}")]
    RateLimited(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub code: i32,
    pub msg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            code: 0,
            msg: "success".to_string(),
            data: Some(data),
        }
    }

    pub fn ok_empty() -> ApiResponse<()> {
        ApiResponse {
            code: 0,
            msg: "success".to_string(),
            data: None,
        }
    }

    pub fn err(code: i32, msg: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            code,
            msg: msg.into(),
            data: None,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, code, msg) = match self {
            AppError::BadRequest(msg) => (StatusCode::OK, -1, msg),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, -401, "unauthorized".into()),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, -403, msg),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, -404, msg),
            AppError::Conflict(msg) => (StatusCode::OK, -409, msg),
            AppError::InvalidCredentials => (
                StatusCode::OK,
                -2,
                "invalid username or password".to_string(),
            ),
            AppError::RateLimited(msg) => (StatusCode::OK, -5, msg),
            AppError::Unsupported(msg) => (StatusCode::OK, -501, msg),
            AppError::Io(err) => (StatusCode::OK, -500, err.to_string()),
            AppError::Config(msg) => (StatusCode::OK, -500, msg),
            AppError::Internal(msg) => (StatusCode::OK, -500, msg),
        };
        (status, Json(ApiResponse::<()>::err(code, msg))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::to_bytes, http::StatusCode};
    use serde_json::Value;

    use super::*;

    #[tokio::test]
    async fn invalid_credentials_use_go_compatible_code() {
        let response = AppError::InvalidCredentials.into_response();

        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], -2);
        assert_eq!(body["msg"], "invalid username or password");
    }
}
