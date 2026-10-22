use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::{
    AppError, Result,
    auth::credential_txn::{self, Change},
    auth::password::AccountStore,
    auth::{compat_crypto::decode_frontend_password, password::validate_account_credentials},
    error::ApiResponse,
    http::{
        cookie::{expired_session_cookie, session_cookie, session_cookie_secure},
        middleware::CurrentSession,
        tls::ClientAddr,
    },
    state::AppState,
    system::audit,
    update::state_writers::AccountPermit,
};

const ROOT_HASH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a verification waits for the single hashing slot.
const VERIFY_WAIT: Duration = Duration::from_secs(2);

/// Verify a password on a blocking thread, one at a time. Inline Argon2 on the
/// single-core SoC stalls HID, video and every other request; concurrent
/// attempts wait briefly for the one slot, then are refused rather than queued.
pub(crate) async fn verify_bounded(
    hashing: &Arc<Semaphore>,
    accounts: &Arc<AccountStore>,
    username: &str,
    password: Zeroizing<String>,
) -> Result<bool> {
    let permit = tokio::time::timeout(VERIFY_WAIT, Arc::clone(hashing).acquire_owned())
        .await
        .map_err(|_| AppError::RateLimited("login is busy; retry shortly".to_string()))?
        .map_err(|_| AppError::Internal("password verification unavailable".to_string()))?;
    let accounts = Arc::clone(accounts);
    let username = username.to_string();
    tokio::task::spawn_blocking(move || {
        // Held until the hash finishes, even if the request is dropped.
        let _permit = permit;
        accounts.verify(&username, &password)
    })
    .await
    .map_err(|_| AppError::Internal("password verification failed".to_string()))?
}

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
    /// The current password, encoded like `password`. A change requires it;
    /// first setup has none.
    #[serde(rename = "currentPassword", default)]
    pub current_password: Option<String>,
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

    let source = addr.0.ip();
    let source_ip = source.to_string();
    {
        let mut limiter = state.login_limiter.write().await;
        if limiter.check(source, &req.username) {
            audit::login_failure(&req.username, &source_ip, "locked");
            return Err(AppError::RateLimited(
                "account locked due to too many failed attempts".to_string(),
            ));
        }
    }

    let password = Zeroizing::new(decode_frontend_password(&req.password)?);
    if !verify_bounded(
        &state.login_hashing,
        &state.accounts,
        &req.username,
        password,
    )
    .await?
    {
        let mut limiter = state.login_limiter.write().await;
        let locked = limiter.record_failure(source, &req.username);
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
        .record_success(source, &req.username);
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
        ..
    } = req;
    let encoded = Zeroizing::new(encoded);
    let password = Zeroizing::new(decode_frontend_password(&encoded)?);
    validate_account_credentials(&username, &password)?;
    permit
        .run(move |writer| async move {
            // Recheck under the serialized permit; two first-setup requests must
            // not each change native identity and then overwrite the web account.
            // The credential journal checks absence once more as it writes.
            if state.accounts.exists() {
                return Err(AppError::Conflict("account already initialized".into()));
            }
            replace_credentials(&state.accounts, &writer, Change::Setup, username, password).await
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
    ConnectInfo(addr): ConnectInfo<ClientAddr>,
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
        current_password,
    } = req;
    let current = Zeroizing::new(current_password.unwrap_or_default());
    reauthenticate(&state, addr.0.ip(), &username, &current).await?;
    let encoded = Zeroizing::new(encoded);
    let password = Zeroizing::new(decode_frontend_password(&encoded)?);
    validate_account_credentials(&username, &password)?;
    permit
        .run(move |writer| async move {
            let revoke_user = username.clone();
            replace_credentials(
                &state.accounts,
                &writer,
                Change::Replace,
                username,
                password,
            )
            .await?;
            if state.config.security.revoke_tokens_on_password_change {
                state.sessions.revoke_user(&revoke_user).await;
            }
            Ok(())
        })
        .await?;
    Ok(Json(ApiResponse::<()>::ok_empty()))
}

/// A change needs the current password, counted by the login lockout: a stolen
/// session must not become a password-guessing oracle.
async fn reauthenticate(
    state: &AppState,
    source: IpAddr,
    username: &str,
    encoded: &str,
) -> Result<()> {
    if encoded.is_empty() {
        return Err(AppError::BadRequest(
            "the current password is required".to_string(),
        ));
    }
    if state.login_limiter.write().await.check(source, username) {
        return Err(AppError::RateLimited(
            "account locked due to too many failed attempts".to_string(),
        ));
    }
    let current = Zeroizing::new(decode_frontend_password(encoded)?);
    if verify_bounded(&state.login_hashing, &state.accounts, username, current).await? {
        state
            .login_limiter
            .write()
            .await
            .record_success(source, username);
        return Ok(());
    }
    state
        .login_limiter
        .write()
        .await
        .record_failure(source, username);
    audit::login_failure(username, &source.to_string(), "password_change_reauth");
    Err(AppError::InvalidCredentials)
}

/// Hash both passwords, then publish root's hash and the web account through
/// one credential journal under the account permit.
async fn replace_credentials(
    accounts: &Arc<AccountStore>,
    writer: &AccountPermit,
    change: Change,
    username: String,
    password: Zeroizing<String>,
) -> Result<()> {
    let root_hash = root_password_hash(accounts, &password, writer).await?;
    let accounts = Arc::clone(accounts);
    writer
        .blocking(move |permit| {
            accounts.replace_credentials(permit, change, &username, &password, &root_hash)
        })
        .await
}

/// Root's SHA-512 crypt(3) hash from BusyBox `mkpasswd`, which reads the
/// password from stdin and writes no file. Only the credential journal
/// publishes the hash.
async fn root_password_hash(
    accounts: &AccountStore,
    password: &str,
    writer: &AccountPermit,
) -> Result<String> {
    let salt = credential_txn::root_salt()?;
    let input = Zeroizing::new(format!("{password}\n"));
    let output = writer
        .command_with_stdin(
            accounts.root_hasher(),
            ["-m", "sha512", "-S", salt.as_str()],
            input.as_bytes(),
            ROOT_HASH_TIMEOUT,
        )
        .await?;
    if output.status != 0 {
        return Err(AppError::Internal(
            "failed to hash the root password".into(),
        ));
    }
    credential_txn::parse_root_hash(&output.stdout, &salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "synthetic right password";

    fn store(dir: &tempfile::TempDir) -> Arc<AccountStore> {
        let path = dir.path().join("pwd");
        let hash = crate::auth::password::hash_password(PASSWORD).unwrap();
        let account = serde_json::json!({"username": "operator", "password": hash});
        std::fs::write(&path, account.to_string()).unwrap();
        Arc::new(AccountStore::new(path))
    }

    fn password() -> Zeroizing<String> {
        Zeroizing::new(PASSWORD.to_string())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verification_runs_off_the_runtime_one_at_a_time_and_refuses_after_its_wait() {
        let dir = tempfile::tempdir().unwrap();
        let accounts = store(&dir);
        let hashing = Arc::new(Semaphore::new(1));
        assert!(
            verify_bounded(&hashing, &accounts, "operator", password())
                .await
                .unwrap()
        );
        assert!(
            !verify_bounded(&hashing, &accounts, "intruder", password())
                .await
                .unwrap()
        );
        // The only thread of this runtime keeps serving while a hash runs.
        let verification = tokio::spawn({
            let (hashing, accounts) = (Arc::clone(&hashing), Arc::clone(&accounts));
            async move { verify_bounded(&hashing, &accounts, "operator", password()).await }
        });
        let mut ticks = 0;
        while !verification.is_finished() {
            tokio::time::sleep(Duration::from_millis(1)).await;
            ticks += 1;
        }
        assert!(verification.await.unwrap().unwrap());
        assert!(
            ticks >= 3,
            "the runtime was blocked by the hash: {ticks} ticks"
        );
        // With the one slot taken, another verification waits its bound and is
        // then refused, instead of queueing more hashing.
        let held = Arc::clone(&hashing).acquire_owned().await.unwrap();
        let started = std::time::Instant::now();
        let refused = verify_bounded(&hashing, &accounts, "operator", password()).await;
        assert!(matches!(refused, Err(AppError::RateLimited(_))));
        assert!(started.elapsed() >= VERIFY_WAIT);
        drop(held);
        assert!(
            verify_bounded(&hashing, &accounts, "operator", password())
                .await
                .unwrap()
        );
    }

    /// The image's BusyBox `mkpasswd -m sha512 -S Fx1./abcdEFGH234` output for
    /// a synthetic password; the fixture prints it for any salt it is given.
    const FIXTURE_DIGEST: &str =
        "2qHO9tMVYA0mOOe16irs2YWy6hEOtOydJUoBSmIWuKej9klY2b3zcJ9B4Z.PnBDbsCrinnVBtfhfxJS6DU2vx.";
    const NEW_PASSWORD: &str = "synthetic new password";

    async fn change_fixture(
        dir: &tempfile::TempDir,
    ) -> (AppState, crate::auth::session::Session, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let mut config = crate::config::Config::default();
        config.paths.account_file = dir.path().join("pwd");
        let mut state = AppState::new(config).await.unwrap();
        state.writers = Arc::new(crate::update::state_writers::StateWriters::for_test_parent(
            std::fs::File::open(dir.path()).unwrap(),
        ));
        let shadow = dir.path().join("shadow");
        std::fs::write(&shadow, b"root:$5$synthetic$old:19000:0:99999:7:::\n").unwrap();
        let hasher = dir.path().join("mkpasswd");
        let script = format!(
            "#!/bin/sh\n[ \"$#\" -eq 4 ] && [ \"$1\" = -m ] && [ \"$2\" = sha512 ] && [ \"$3\" = -S ] || exit 2\n\
             IFS= read -r password || exit 3\nprintf '%s' \"$password\" > \"${{0%/*}}/mkpasswd.stdin\"\n\
             printf '$6$%s$%s\\n' \"$4\" '{FIXTURE_DIGEST}'\n"
        );
        std::fs::write(&hasher, script).unwrap();
        std::fs::set_permissions(&hasher, std::fs::Permissions::from_mode(0o700)).unwrap();
        let accounts = AccountStore::fixture(dir.path().join("pwd"), shadow.clone(), hasher);
        let hash = crate::auth::password::hash_password(PASSWORD).unwrap();
        let account = serde_json::json!({"username": "operator", "password": hash});
        std::fs::write(dir.path().join("pwd"), account.to_string()).unwrap();
        state.accounts = Arc::new(accounts);
        state.login_limiter = Arc::new(tokio::sync::RwLock::new(
            crate::security::rate_limit::LoginRateLimiter::new(2, 600),
        ));
        let session = state.sessions.issue("operator", 900).await;
        (state, session, shadow)
    }

    fn change(current: Option<&str>) -> Json<ChangePasswordReq> {
        Json(ChangePasswordReq {
            username: "operator".into(),
            password: NEW_PASSWORD.into(),
            current_password: current.map(str::to_string),
        })
    }

    fn client() -> ConnectInfo<ClientAddr> {
        ConnectInfo(ClientAddr("192.0.2.10:40000".parse().unwrap()))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_password_change_needs_the_current_password_under_the_login_lockout() {
        let dir = tempfile::tempdir().unwrap();
        let (state, session, shadow) = change_fixture(&dir).await;
        let attempt = |current: Option<&'static str>| {
            let state = state.clone();
            let session = session.clone();
            async move {
                change_password(
                    State(state),
                    client(),
                    Extension(CurrentSession(session)),
                    change(current),
                )
                .await
                .map(|_| ())
            }
        };
        let unchanged = |state: &AppState| {
            assert!(state.accounts.verify("operator", PASSWORD).unwrap());
            assert!(
                std::fs::read_to_string(&shadow)
                    .unwrap()
                    .contains("$5$synthetic$old")
            );
            assert!(!dir.path().join("mkpasswd.stdin").exists());
        };

        assert!(matches!(attempt(None).await, Err(AppError::BadRequest(_))));
        assert!(matches!(
            attempt(Some("")).await,
            Err(AppError::BadRequest(_))
        ));
        unchanged(&state);
        // Wrong current passwords count toward the same lockout as logins.
        for _ in 0..2 {
            assert!(matches!(
                attempt(Some("synthetic wrong password")).await,
                Err(AppError::InvalidCredentials)
            ));
        }
        assert!(matches!(
            attempt(Some(PASSWORD)).await,
            Err(AppError::RateLimited(_))
        ));
        unchanged(&state);

        state
            .login_limiter
            .write()
            .await
            .record_success(client().0.0.ip(), "operator");
        attempt(Some(PASSWORD)).await.unwrap();
        assert!(state.accounts.verify("operator", NEW_PASSWORD).unwrap());
        assert!(!state.accounts.verify("operator", PASSWORD).unwrap());
        let root = std::fs::read_to_string(&shadow).unwrap();
        assert!(root.starts_with("root:$6$"), "{root}");
        assert!(root.contains(FIXTURE_DIGEST));
        // The password reached mkpasswd on stdin, never as an argument.
        assert_eq!(
            std::fs::read_to_string(dir.path().join("mkpasswd.stdin")).unwrap(),
            NEW_PASSWORD
        );
        assert!(!state.accounts.credential_recovery_pending());
        // Revocation ends the session that made the change.
        assert!(state.sessions.validate(&session.token).await.is_none());
    }
}
