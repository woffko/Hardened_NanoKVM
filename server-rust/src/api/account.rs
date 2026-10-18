use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::{
    AppError, Result,
    auth::{compat_crypto::decode_frontend_password, password::validate_account_credentials},
    error::ApiResponse,
    http::{
        cookie::{expired_session_cookie, session_cookie, session_cookie_secure},
        middleware::CurrentSession,
        tls::ClientAddr,
    },
    state::AppState,
    system::{audit, command::AllowedCommand},
    update::state_writers::WriterPermit,
};

const ROOT_PASSWORD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginRsp {
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
    #[serde(rename = "csrfToken")]
    pub csrf_token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
}

#[derive(Debug, Serialize)]
pub struct PasswordUpdatedRsp {
    #[serde(rename = "isUpdated")]
    pub is_updated: bool,
}

#[derive(Debug, Serialize)]
pub struct SetupStateRsp {
    pub required: bool,
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
            audit::login_failure(&req.username, &source_ip, "locked");
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
            audit::login_failure(&req.username, &source_ip, "lockout");
        } else {
            audit::login_failure(&req.username, &source_ip, "invalid_credentials");
        }
        return Err(AppError::InvalidCredentials);
    }

    audit::login_success(&req.username, &source_ip);
    state
        .login_limiter
        .write()
        .await
        .record_success(&source_ip, &req.username);
    let session_lock_duration = state.session_lock_duration();
    let session = state
        .sessions
        .issue(&req.username, session_lock_duration)
        .await;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        session_cookie(
            &session.token,
            session_lock_duration,
            session_cookie_secure(&state.config.proto),
        )?,
    );
    let body = Json(ApiResponse::ok(LoginRsp {
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
    let permit = state.writers.account()?;
    let ChangePasswordReq {
        username,
        password: encoded,
    } = req;
    let encoded = Zeroizing::new(encoded);
    let password = Zeroizing::new(decode_frontend_password(&encoded)?);
    validate_account_credentials(&username, &password)?;
    permit
        .run(move |writer| async move {
            // Recheck under the serialized permit; two first-setup requests must
            // not each change native identity and then overwrite the web account.
            if state.accounts.exists() {
                return Err(AppError::Conflict("account already initialized".into()));
            }
            change_root_password(&password, &writer).await?;
            let accounts = state.accounts;
            writer
                .blocking(move |permit| accounts.set_account(permit, &username, &password))
                .await?;
            Ok(())
        })
        .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

pub async fn get_setup_state(State(state): State<AppState>) -> Result<impl IntoResponse> {
    Ok(Json(ApiResponse::ok(SetupStateRsp {
        required: !state.accounts.exists(),
    })))
}

pub async fn logout(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
) -> Result<impl IntoResponse> {
    state.sessions.revoke(&session.token).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        expired_session_cookie(session_cookie_secure(&state.config.proto))?,
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
        csrf_token: session.csrf_token,
        expires_at: session.expires_at_unix,
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
    let permit = state.writers.account()?;
    let ChangePasswordReq {
        username,
        password: encoded,
    } = req;
    let encoded = Zeroizing::new(encoded);
    let password = Zeroizing::new(decode_frontend_password(&encoded)?);
    validate_account_credentials(&username, &password)?;
    permit
        .run(move |writer| async move {
            change_root_password(&password, &writer).await?;
            let revoke_user = username.clone();
            let accounts = state.accounts;
            writer
                .blocking(move |permit| accounts.set_account(permit, &username, &password))
                .await?;
            if state.config.security.revoke_tokens_on_password_change {
                state.sessions.revoke_user(&revoke_user).await;
            }
            Ok(())
        })
        .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

async fn change_root_password(password: &str, writer: &WriterPermit) -> Result<()> {
    let input = Zeroizing::new(format!("{password}\n{password}\n"));
    let output = writer
        .command_with_stdin(
            AllowedCommand::Passwd,
            ["root"],
            input.as_bytes(),
            ROOT_PASSWORD_TIMEOUT,
        )
        .await?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(AppError::Internal("failed to change root password".into()))
    }
}
