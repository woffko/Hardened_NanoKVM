//! Enrolment and management of the TOTP second factor.
//!
//! All of these require an authenticated session; the login-time half lives in
//! [`crate::api::account`].

use axum::{Extension, Json, extract::State, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{
    AppError, Result,
    auth::{
        clock,
        compat_crypto::decode_frontend_password,
        password::{BACKUP_CODE_COUNT, TotpConfig, generate_backup_codes},
        totp,
    },
    config::Config,
    error::ApiResponse,
    http::middleware::CurrentSession,
    state::AppState,
    system::audit,
};

/// Issuer shown in the authenticator app's account list.
const TOTP_ISSUER: &str = "Hardened NanoKVM";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpStatusRsp {
    enabled: bool,
    /// False while the board still reports its pre-NTP epoch clock. Enrolment
    /// is refused in that state, because a code generated against a 1970 clock
    /// could never be confirmed.
    clock_synced: bool,
    backup_codes_remaining: usize,
    enrolled_at: u64,
    /// Whether configuration requires a second factor for this device.
    required: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpEnrollRsp {
    secret: String,
    otpauth_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpEnrollReq {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct TotpConfirmReq {
    pub code: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpConfirmRsp {
    /// Shown to the user exactly once; only hashes are kept.
    backup_codes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TotpDisableReq {
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SetRequiredReq {
    pub required: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupCodesRsp {
    backup_codes: Vec<String>,
}

pub async fn get_status(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
) -> Result<impl IntoResponse> {
    let config = state.accounts.totp_config(&session.username)?;
    Ok(Json(ApiResponse::ok(TotpStatusRsp {
        enabled: config.is_some(),
        clock_synced: clock::is_synced(),
        backup_codes_remaining: config
            .as_ref()
            .map(|totp| totp.backup_codes.len())
            .unwrap_or(0),
        enrolled_at: config.as_ref().map(|totp| totp.enrolled_at).unwrap_or(0),
        required: state.require_totp(),
    })))
}

/// Start enrolment: generate a secret and hold it pending confirmation.
///
/// Nothing is persisted here, so an abandoned enrolment leaves no trace and
/// cannot lock anyone out.
pub async fn enroll(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    Json(req): Json<TotpEnrollReq>,
) -> Result<impl IntoResponse> {
    ensure_clock_synced()?;
    // Like disable and regenerate: a stolen session alone must not be able to
    // bind its own authenticator.
    verify_password(&state, &session.username, &req.password)?;

    let secret = totp::generate_secret();
    let uri = totp::otpauth_uri(TOTP_ISSUER, &session.username, &secret);
    state
        .pending_enrolment
        .put(&session.username, &secret)
        .await;

    Ok(Json(ApiResponse::ok(TotpEnrollRsp {
        secret,
        otpauth_uri: uri,
    })))
}

/// Finish enrolment by proving the authenticator produces matching codes.
///
/// Activating without this step would lock the user out the moment their
/// authenticator was misconfigured.
pub async fn confirm(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    Json(req): Json<TotpConfirmReq>,
) -> Result<impl IntoResponse> {
    ensure_clock_synced()?;

    let secret = state
        .pending_enrolment
        .get(&session.username)
        .await
        .ok_or_else(|| AppError::BadRequest("no enrolment in progress; start again".to_string()))?;
    let decoded = totp::decode_secret(&secret)
        .ok_or_else(|| AppError::Internal("generated an invalid TOTP secret".to_string()))?;

    let now = clock::now_unix();
    let Some(step) = totp::verify(&decoded, req.code.trim(), now, None) else {
        return Err(AppError::BadRequest(
            "that code does not match; check the device clock and try the next one".to_string(),
        ));
    };

    let (codes, hashes) = generate_backup_codes();
    state.accounts.set_totp(
        &session.username,
        TotpConfig {
            secret,
            backup_codes: hashes,
            enrolled_at: now,
        },
    )?;
    state.pending_enrolment.clear(&session.username).await;

    // The confirming code must not also work as a login code.
    state.totp_replay.try_use(&session.username, step).await;

    // Any other session predates the second factor; this one is doing the
    // enrolling and would be pointless to drop.
    state
        .sessions
        .revoke_user_except(&session.username, &session.token)
        .await;

    audit::totp_enrolled(&session.username);
    Ok(Json(ApiResponse::ok(TotpConfirmRsp {
        backup_codes: codes,
    })))
}

/// Issue a fresh set of backup codes, invalidating the old ones.
pub async fn regenerate_backup_codes(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    Json(req): Json<TotpDisableReq>,
) -> Result<impl IntoResponse> {
    verify_password(&state, &session.username, &req.password)?;

    let mut config = state
        .accounts
        .totp_config(&session.username)?
        .ok_or_else(|| AppError::BadRequest("two-factor auth is not enabled".to_string()))?;

    let (codes, hashes) = generate_backup_codes();
    config.backup_codes = hashes;
    state.accounts.set_totp(&session.username, config)?;

    audit::totp_backup_codes_regenerated(&session.username);
    Ok(Json(ApiResponse::ok(BackupCodesRsp {
        backup_codes: codes,
    })))
}

/// Turn the second factor off. Requires the account password.
pub async fn disable(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    Json(req): Json<TotpDisableReq>,
) -> Result<impl IntoResponse> {
    // Refusing here would leave the UI unable to undo a setting it offers, so
    // this only blocks while the policy flag is on -- the flag itself has to
    // be cleared first.
    if state.require_totp() {
        return Err(AppError::Conflict(
            "configuration requires two-factor auth; clear security.require_totp first".to_string(),
        ));
    }
    verify_password(&state, &session.username, &req.password)?;

    state.accounts.clear_totp(&session.username)?;
    state.pending_enrolment.clear(&session.username).await;
    state.totp_replay.forget(&session.username).await;
    state
        .sessions
        .revoke_user_except(&session.username, &session.token)
        .await;

    audit::totp_disabled(&session.username);
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

/// Turn the "a second factor is required" policy on or off.
///
/// Mirrors `ensure_https_mode_can_be_enabled` in
/// [`crate::api::system_firewall`]: a setting whose prerequisite is not met is
/// refused up front rather than accepted and left to fail later. Here the
/// prerequisite is that the account can actually satisfy the requirement.
pub async fn set_required(
    State(state): State<AppState>,
    Extension(CurrentSession(session)): Extension<CurrentSession>,
    Json(req): Json<SetRequiredReq>,
) -> Result<impl IntoResponse> {
    if req.required && !state.accounts.totp_enabled(&session.username)? {
        return Err(AppError::Conflict(
            "enrol in two-factor auth before requiring it".to_string(),
        ));
    }

    let mut config = Config::read()?;
    config.security.require_totp = req.required;
    config.write()?;
    state.set_require_totp(req.required);

    Ok(Json(ApiResponse::<()>::ok_empty()))
}

fn ensure_clock_synced() -> Result<()> {
    if clock::is_synced() {
        return Ok(());
    }
    Err(AppError::Conflict(
        "device clock is not synchronized; synchronize time before enrolling".to_string(),
    ))
}

fn verify_password(state: &AppState, username: &str, password: &str) -> Result<()> {
    let password = decode_frontend_password(password)?;
    if !state.accounts.verify(username, &password)? {
        return Err(AppError::InvalidCredentials);
    }
    Ok(())
}

/// Number of backup codes a fresh enrolment issues, for the UI to announce.
pub const ENROLMENT_BACKUP_CODE_COUNT: usize = BACKUP_CODE_COUNT;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::Session;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const PASSWORD: &str = "correct horse battery";

    async fn state_and_session() -> (tempfile::TempDir, AppState, Session) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.paths.account_file = dir.path().canonicalize().unwrap().join("pwd");
        let state = AppState::new(config).await.unwrap();
        state.accounts.set_account("operator", PASSWORD).unwrap();
        let session = state.sessions.issue("operator", 900).await;
        (dir, state, session)
    }

    async fn try_enroll(state: &AppState, session: &Session, password: &str) -> Result<()> {
        enroll(
            State(state.clone()),
            Extension(CurrentSession(session.clone())),
            Json(TotpEnrollReq {
                password: password.to_string(),
            }),
        )
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn enrolment_requires_the_password() {
        let (_dir, state, session) = state_and_session().await;

        let refused = try_enroll(&state, &session, "not the password").await;
        assert!(matches!(refused, Err(AppError::InvalidCredentials)));
        assert!(state.pending_enrolment.get("operator").await.is_none());

        try_enroll(&state, &session, PASSWORD).await.unwrap();
        assert!(state.pending_enrolment.get("operator").await.is_some());
    }

    #[tokio::test]
    async fn a_session_cannot_replace_an_enrolment_without_the_password() {
        // A stolen session must not be able to rebind the factor: doing so
        // would replace the secret, void the owner's backup codes and, on
        // confirm, log the owner out.
        let (_dir, state, session) = state_and_session().await;
        state
            .accounts
            .set_totp(
                "operator",
                TotpConfig {
                    secret: SECRET.to_string(),
                    backup_codes: vec![],
                    enrolled_at: 0,
                },
            )
            .unwrap();

        let refused = try_enroll(&state, &session, "not the password").await;

        assert!(matches!(refused, Err(AppError::InvalidCredentials)));
        assert!(state.pending_enrolment.get("operator").await.is_none());
        let stored = state.accounts.totp_config("operator").unwrap().unwrap();
        assert_eq!(stored.secret, SECRET);
    }
}
