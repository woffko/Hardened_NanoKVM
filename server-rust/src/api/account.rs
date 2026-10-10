use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::{
    AppError, Result,
    auth::{
        clock,
        compat_crypto::decode_frontend_password,
        password::{AccountStore, TotpConfig, validate_account_credentials},
        pending_totp::PENDING_TTL_SECS,
        totp::{self, ReplayGuard},
    },
    error::ApiResponse,
    http::{
        cookie::{
            PENDING_TOTP_COOKIE_NAME, expired_pending_totp_cookie, expired_session_cookie,
            pending_totp_cookie, session_cookie, session_cookie_secure,
        },
        middleware::CurrentSession,
        tls::ClientAddr,
    },
    state::AppState,
    system::{
        audit,
        command::{AllowedCommand, CommandOutput, run_allowed_with_stdin},
    },
};

const ROOT_PASSWORD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Deserialize)]
pub struct LoginReq {
    pub username: String,
    pub password: String,
}

/// Outcome of the first login step.
///
/// The frontend contract forces the shape: `web/src/lib/http.ts` unwraps
/// `data` and the login page treats any nonzero `code` as a hard failure, so
/// "a second factor is needed" has to be a successful response with a
/// discriminator inside `data` rather than a new error code.
#[derive(Debug, Default, Serialize)]
pub struct LoginRsp {
    #[serde(rename = "csrfToken", skip_serializing_if = "String::is_empty")]
    pub csrf_token: String,
    #[serde(rename = "expiresAt", skip_serializing_if = "is_zero")]
    pub expires_at: u64,
    /// Set when the password was accepted but a TOTP code is still required.
    /// No session is issued alongside it.
    #[serde(rename = "totpRequired", skip_serializing_if = "is_false")]
    pub totp_required: bool,
    /// Set when policy requires a second factor that this account has not
    /// enrolled yet. A session *is* issued, and the UI must force enrolment.
    #[serde(rename = "totpEnrollmentRequired", skip_serializing_if = "is_false")]
    pub totp_enrollment_required: bool,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Deserialize)]
pub struct TotpLoginReq {
    /// A 6-digit TOTP code, or one of the account's backup codes.
    pub code: String,
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

    state
        .login_limiter
        .write()
        .await
        .record_success(&source_ip, &req.username);

    // The password is right. Decide whether a second factor stands between
    // this and a session.
    if state.accounts.totp_enabled(&req.username)? {
        let ticket = state.pending_totp.issue(&req.username, &source_ip).await;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SET_COOKIE,
            pending_totp_cookie(
                &ticket,
                PENDING_TTL_SECS,
                session_cookie_secure(&state.config.proto),
            )?,
        );
        return Ok((
            headers,
            Json(ApiResponse::ok(LoginRsp {
                totp_required: true,
                ..Default::default()
            })),
        ));
    }

    // Policy wants a second factor but this account has none. Refusing would
    // brick a headless device whose account file was reset or whose config was
    // restored, so issue the session and make the UI force enrolment instead.
    let enrollment_required = state.require_totp();
    if enrollment_required {
        tracing::warn!(
            username = %req.username,
            "security.require_totp is set but the account has no enrolment; \
             allowing login to enrol"
        );
    }

    audit::login_success(&req.username, &source_ip);
    issue_session_response(&state, &req.username, enrollment_required).await
}

/// Second login step: exchange the pending ticket plus a code for a session.
pub async fn login_totp(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<ClientAddr>,
    headers: HeaderMap,
    Json(req): Json<TotpLoginReq>,
) -> Result<impl IntoResponse> {
    let source_ip = addr.0.ip().to_string();
    let ticket = pending_totp_from_cookie(&headers).ok_or(AppError::InvalidCredentials)?;

    // Resolve without spending: a mistyped digit should cost a retry, not the
    // whole login.
    let username = state
        .pending_totp
        .peek(&ticket, &source_ip)
        .await
        .ok_or(AppError::InvalidCredentials)?;

    // Share the login lockout budget under a distinct key, so hammering the
    // second step cannot be used to lock out the first, or vice versa.
    let limiter_key = format!("totp:{username}");
    {
        let mut limiter = state.login_limiter.write().await;
        if limiter.check(&source_ip, &limiter_key) {
            audit::login_failure(&username, &source_ip, "locked");
            return Err(AppError::RateLimited(
                "account locked due to too many failed attempts".to_string(),
            ));
        }
    }

    let Some(totp) = state.accounts.totp_config(&username)? else {
        // Enrolment was removed between the two steps.
        state.pending_totp.discard(&ticket).await;
        return Err(AppError::InvalidCredentials);
    };

    let accepted = verify_second_factor(
        &state.accounts,
        &state.totp_replay,
        &username,
        &source_ip,
        &totp,
        req.code.trim(),
        clock::read(),
    )
    .await?;
    if !accepted {
        let mut limiter = state.login_limiter.write().await;
        if limiter.record_failure(&source_ip, &limiter_key) {
            tracing::warn!(source_ip, %username, "TOTP lockout threshold reached");
            audit::login_failure(&username, &source_ip, "lockout");
        } else {
            audit::login_failure(&username, &source_ip, "invalid_totp");
        }
        return Err(AppError::InvalidCredentials);
    }

    // Only now is the ticket spent.
    if state
        .pending_totp
        .consume(&ticket, &source_ip)
        .await
        .is_none()
    {
        return Err(AppError::InvalidCredentials);
    }
    state
        .login_limiter
        .write()
        .await
        .record_success(&source_ip, &limiter_key);
    audit::login_success(&username, &source_ip);

    let (mut headers, body) = issue_session_response(&state, &username, false).await?;
    headers.append(
        header::SET_COOKIE,
        expired_pending_totp_cookie(session_cookie_secure(&state.config.proto))?,
    );
    Ok((headers, body))
}

/// Whether a submitted second factor is a TOTP code rather than a backup code.
///
/// Six digits is the TOTP shape; backup codes are letters and digits in two
/// groups, so they can never be mistaken for one.
fn looks_like_totp_code(code: &str) -> bool {
    code.len() == totp::DIGITS && code.bytes().all(|b| b.is_ascii_digit())
}

/// Check a submitted code against the account's TOTP secret, then its backup
/// codes.
///
/// Takes its dependencies explicitly rather than reaching into [`AppState`] so
/// the clock-gate behaviour can be tested directly.
async fn verify_second_factor(
    accounts: &AccountStore,
    replay: &ReplayGuard,
    username: &str,
    source_ip: &str,
    totp_config: &TotpConfig,
    code: &str,
    time: clock::Reading,
) -> Result<bool> {
    // Backup codes are checked whatever the clock says. They are the recovery
    // path *for* an unsynchronized clock, so gating them on the clock would
    // make them unreachable in exactly the situation they exist for.
    if !looks_like_totp_code(code) {
        return accounts.consume_backup_code(username, code);
    }

    if !time.synced {
        audit::login_failure(username, source_ip, "clock_unsynced");
        return Err(AppError::BadRequest(
            "device clock is not synchronized, so time-based codes cannot be \
             checked; use a backup code or synchronize time first"
                .to_string(),
        ));
    }

    let Some(secret) = totp::decode_secret(&totp_config.secret) else {
        return Err(AppError::Config(
            "stored TOTP secret is invalid".to_string(),
        ));
    };

    let last_step = replay.last_step(username).await;
    let Some(step) = totp::verify(&secret, code, time.now_unix, last_step) else {
        return Ok(false);
    };

    // Authoritative check: claims the step under a single lock, so two
    // requests racing with the same code cannot both succeed.
    Ok(replay.try_use(username, step).await)
}

async fn issue_session_response(
    state: &AppState,
    username: &str,
    totp_enrollment_required: bool,
) -> Result<(HeaderMap, Json<ApiResponse<LoginRsp>>)> {
    let session_lock_duration = state.session_lock_duration();
    let session = state.sessions.issue(username, session_lock_duration).await;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        session_cookie(
            &session.token,
            session_lock_duration,
            session_cookie_secure(&state.config.proto),
        )?,
    );
    Ok((
        headers,
        Json(ApiResponse::ok(LoginRsp {
            csrf_token: session.csrf_token,
            expires_at: session.expires_at_unix,
            totp_required: false,
            totp_enrollment_required,
        })),
    ))
}

fn pending_totp_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|item| {
        item.trim()
            .strip_prefix(&format!("{PENDING_TOTP_COOKIE_NAME}="))
            .filter(|token| !token.is_empty())
            .map(str::to_string)
    })
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
    validate_account_credentials(&req.username, &password)?;
    change_root_password(&password).await?;
    state.accounts.set_account(&req.username, &password)?;
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
    let password = decode_frontend_password(&req.password)?;
    validate_account_credentials(&req.username, &password)?;
    change_root_password(&password).await?;
    state.accounts.set_account(&req.username, &password)?;
    if state.config.security.revoke_tokens_on_password_change {
        state.sessions.revoke_user(&req.username).await;
    }
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

async fn change_root_password(password: &str) -> Result<()> {
    let input = format!("{password}\n{password}\n");
    let output = run_allowed_with_stdin(
        AllowedCommand::Passwd,
        ["root"],
        input.as_bytes(),
        ROOT_PASSWORD_TIMEOUT,
    )
    .await?;
    if output.status == 0 {
        Ok(())
    } else {
        Err(AppError::Internal(command_error(
            "failed to change root password",
            output,
        )))
    }
}

fn command_error(message: &str, output: CommandOutput) -> String {
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
    use crate::auth::password::generate_backup_codes;

    /// A clock reading well after the plausibility floor.
    const SYNCED_NOW: u64 = 1_800_000_000;
    /// What the board actually reports before NTP succeeds.
    const EPOCH_NOW: u64 = 0;
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    /// Client address for audit events; these tests do not depend on it.
    const SOURCE_IP: &str = "10.0.0.5";

    fn accounts_with_totp(backup_hashes: Vec<String>) -> (tempfile::TempDir, AccountStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = AccountStore::new(dir.path().canonicalize().unwrap().join("pwd"));
        store
            .set_account("operator", "correct horse battery")
            .unwrap();
        store
            .set_totp(
                "operator",
                TotpConfig {
                    secret: SECRET.to_string(),
                    backup_codes: backup_hashes,
                    enrolled_at: SYNCED_NOW,
                },
            )
            .unwrap();
        (dir, store)
    }

    fn config() -> TotpConfig {
        TotpConfig {
            secret: SECRET.to_string(),
            backup_codes: Vec::new(),
            enrolled_at: SYNCED_NOW,
        }
    }

    fn synced() -> clock::Reading {
        clock::Reading {
            now_unix: SYNCED_NOW,
            synced: true,
        }
    }

    fn unsynced() -> clock::Reading {
        clock::Reading {
            now_unix: EPOCH_NOW,
            synced: false,
        }
    }

    fn code_for(now: u64) -> String {
        let secret = totp::decode_secret(SECRET).unwrap();
        format!("{:06}", totp::code_at(&secret, totp::current_step(now)))
    }

    #[test]
    fn totp_codes_are_told_apart_from_backup_codes() {
        assert!(looks_like_totp_code("123456"));
        assert!(!looks_like_totp_code("12345"));
        assert!(!looks_like_totp_code("1234567"));

        // Every generated backup code must fall on the backup side, or it
        // would be routed into the clock-gated branch.
        let (codes, _) = generate_backup_codes();
        for code in codes {
            assert!(
                !looks_like_totp_code(&code),
                "{code} looks like a TOTP code"
            );
        }
    }

    #[tokio::test]
    async fn accepts_a_valid_totp_code_when_the_clock_is_synced() {
        let (_dir, accounts) = accounts_with_totp(Vec::new());
        let replay = ReplayGuard::new();

        let accepted = verify_second_factor(
            &accounts,
            &replay,
            "operator",
            SOURCE_IP,
            &config(),
            &code_for(SYNCED_NOW),
            synced(),
        )
        .await
        .unwrap();

        assert!(accepted);
    }

    #[tokio::test]
    async fn rejects_a_reused_totp_code() {
        let (_dir, accounts) = accounts_with_totp(Vec::new());
        let replay = ReplayGuard::new();
        let code = code_for(SYNCED_NOW);

        let first = verify_second_factor(
            &accounts,
            &replay,
            "operator",
            SOURCE_IP,
            &config(),
            &code,
            synced(),
        )
        .await
        .unwrap();
        let second = verify_second_factor(
            &accounts,
            &replay,
            "operator",
            SOURCE_IP,
            &config(),
            &code,
            synced(),
        )
        .await
        .unwrap();

        assert!(first);
        assert!(!second, "a code must not work twice");
    }

    #[tokio::test]
    async fn refuses_totp_codes_while_the_clock_is_unsynced() {
        let (_dir, accounts) = accounts_with_totp(Vec::new());
        let replay = ReplayGuard::new();

        let result = verify_second_factor(
            &accounts,
            &replay,
            "operator",
            SOURCE_IP,
            &config(),
            "123456",
            unsynced(),
        )
        .await;

        // An explicit error, not a plain rejection: "wrong code" would send
        // the user hunting for a fault in their authenticator.
        match result {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("not synchronized"), "{message}");
                assert!(message.contains("backup code"), "{message}");
            }
            other => panic!("expected a clock error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn backup_codes_work_while_the_clock_is_unsynced() {
        // The rule this whole design turns on: the clock gate must not reach
        // the recovery path, or recovery is unavailable in exactly the
        // situation that calls for it -- a device rebooted without a network.
        let (codes, hashes) = generate_backup_codes();
        let (_dir, accounts) = accounts_with_totp(hashes);
        let replay = ReplayGuard::new();

        let accepted = verify_second_factor(
            &accounts,
            &replay,
            "operator",
            SOURCE_IP,
            &config(),
            &codes[0],
            unsynced(),
        )
        .await
        .unwrap();

        assert!(accepted);
    }

    #[tokio::test]
    async fn backup_codes_are_spent_on_use() {
        let (codes, hashes) = generate_backup_codes();
        let (_dir, accounts) = accounts_with_totp(hashes);
        let replay = ReplayGuard::new();

        for expected in [true, false] {
            let accepted = verify_second_factor(
                &accounts,
                &replay,
                "operator",
                SOURCE_IP,
                &config(),
                &codes[0],
                unsynced(),
            )
            .await
            .unwrap();
            assert_eq!(accepted, expected);
        }
    }

    #[tokio::test]
    async fn rejects_an_unknown_backup_code_without_erroring() {
        let (_codes, hashes) = generate_backup_codes();
        let (_dir, accounts) = accounts_with_totp(hashes);
        let replay = ReplayGuard::new();

        let accepted = verify_second_factor(
            &accounts,
            &replay,
            "operator",
            SOURCE_IP,
            &config(),
            "ZZZZZ-ZZZZZ",
            synced(),
        )
        .await
        .unwrap();

        assert!(!accepted);
    }

    #[test]
    fn reads_the_pending_ticket_from_its_own_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "nano-kvm-token=session; nano-kvm-totp=ticket"
                .parse()
                .unwrap(),
        );

        assert_eq!(
            pending_totp_from_cookie(&headers).as_deref(),
            Some("ticket")
        );
    }

    #[test]
    fn ignores_a_missing_or_empty_pending_cookie() {
        assert_eq!(pending_totp_from_cookie(&HeaderMap::new()), None);

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "nano-kvm-token=session".parse().unwrap());
        assert_eq!(pending_totp_from_cookie(&headers), None);

        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "nano-kvm-totp=".parse().unwrap());
        assert_eq!(pending_totp_from_cookie(&headers), None);
    }

    #[test]
    fn login_response_omits_absent_fields() {
        let pending = serde_json::to_value(LoginRsp {
            totp_required: true,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(pending["totpRequired"], serde_json::json!(true));
        assert!(
            pending.get("csrfToken").is_none(),
            "no session is issued yet"
        );
        assert!(pending.get("expiresAt").is_none());

        let issued = serde_json::to_value(LoginRsp {
            csrf_token: "csrf".to_string(),
            expires_at: 42,
            totp_required: false,
            totp_enrollment_required: true,
        })
        .unwrap();
        assert_eq!(issued["csrfToken"], serde_json::json!("csrf"));
        assert_eq!(issued["totpEnrollmentRequired"], serde_json::json!(true));
        assert!(issued.get("totpRequired").is_none());
    }
}
