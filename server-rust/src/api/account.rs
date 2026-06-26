use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderValue, header},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::{
    AppError, Result,
    auth::compat_crypto::decode_frontend_password,
    error::ApiResponse,
    http::{middleware::CurrentSession, tls::ClientAddr},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginRsp {
    pub token: String,
    #[serde(rename = "csrfToken")]
    pub csrf_token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordReq {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AccountRsp {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordUpdatedRsp {
    #[serde(rename = "isUpdated")]
    pub is_updated: bool,
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<ClientAddr>,
    Json(req): Json<LoginReq>,
) -> Result<impl IntoResponse> {
    if !state.accounts.exists() {
        return Err(AppError::Conflict(
            "password setup required; default admin/admin is disabled by config".to_string(),
        ));
    }

    let source_ip = addr.0.ip().to_string();
    {
        let mut limiter = state.login_limiter.write().await;
        if limiter.check(&source_ip, &req.username) {
            return Err(AppError::RateLimited(
                "account locked due to too many failed attempts".to_string(),
            ));
        }
    }

    let password = decode_frontend_password(&req.password)?;
    if !state.accounts.verify(&req.username, &password)? {
        let mut limiter = state.login_limiter.write().await;
        let locked = limiter.record_failure(&source_ip, &req.username);
        if locked {
            tracing::warn!(source_ip, username = %req.username, "login lockout threshold reached");
        }
        return Err(AppError::BadRequest(
            "invalid username or password".to_string(),
        ));
    }

    state
        .login_limiter
        .write()
        .await
        .record_success(&source_ip, &req.username);
    let session = state
        .sessions
        .issue(&req.username, state.config.security.access_token_duration)
        .await;

    let mut headers = HeaderMap::new();
    headers.insert(header::SET_COOKIE, secure_cookie(&session.token)?);
    let body = Json(ApiResponse::ok(LoginRsp {
        token: session.token,
        csrf_token: session.csrf_token,
        expires_at: session.expires_at_unix,
    }));
    Ok((headers, body))
}

pub async fn setup_first_account(
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordReq>,
) -> Result<impl IntoResponse> {
    if state.accounts.exists() {
        return Err(AppError::Conflict(
            "account already initialized".to_string(),
        ));
    }
    let password = decode_frontend_password(&req.password)?;
    state.accounts.set_account(&req.username, &password)?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn logout(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
) -> Result<impl IntoResponse> {
    state.sessions.revoke(&session.token).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_static("nano-kvm-token=; Path=/; Max-Age=0; SameSite=Lax"),
    );
    Ok((headers, Json(ApiResponse::<()>::ok_empty())))
}

pub async fn get_account(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
) -> Result<impl IntoResponse> {
    let account = state
        .accounts
        .load()?
        .ok_or_else(|| AppError::NotFound("account not initialized".to_string()))?;
    if account.username != session.username {
        return Err(AppError::Forbidden("session/account mismatch".to_string()));
    }
    Ok(Json(ApiResponse::ok(AccountRsp {
        username: account.username,
    })))
}

pub async fn is_password_updated(State(state): State<AppState>) -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(PasswordUpdatedRsp {
        is_updated: state.accounts.exists(),
    })))
}

pub async fn change_password(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    Json(req): Json<ChangePasswordReq>,
) -> Result<impl IntoResponse> {
    if req.username != session.username {
        return Err(AppError::Forbidden(
            "cannot change another account password".to_string(),
        ));
    }
    let password = decode_frontend_password(&req.password)?;
    state.accounts.set_account(&req.username, &password)?;
    if state.config.security.revoke_tokens_on_password_change {
        state.sessions.revoke_user(&req.username).await;
    }
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

fn secure_cookie(token: &str) -> Result<HeaderValue> {
    let value = format!("nano-kvm-token={token}; Path=/; Max-Age=900; SameSite=Lax");
    HeaderValue::from_str(&value)
        .map_err(|err| AppError::Internal(format!("failed to build cookie: {err}")))
}
