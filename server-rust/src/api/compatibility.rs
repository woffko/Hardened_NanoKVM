use axum::{Json, response::IntoResponse};
use serde_json::json;

use crate::error::ApiResponse;

pub async fn not_implemented() -> impl IntoResponse {
    Json(ApiResponse::ok(json!({
        "implemented": false,
        "message": "Rust backend compatibility route is not implemented in this phase"
    })))
}

pub async fn health() -> impl IntoResponse {
    Json(ApiResponse::ok(json!({
        "status": "ok",
        "backend": "rust",
        "phase": "skeleton"
    })))
}
