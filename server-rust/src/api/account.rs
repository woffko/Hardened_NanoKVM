use axum::{
    Extension, Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc, time::Duration};
use zeroize::Zeroizing;

/// Above any name an account can have.
const MAX_LOGIN_USERNAME_BYTES: usize = 256;

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
    state: &AppState,
    source: IpAddr,
    limiter_username: &str,
    username: &str,
    password: Zeroizing<String>,
) -> Result<bool> {
    let permit = tokio::time::timeout(
        VERIFY_WAIT,
        Arc::clone(&state.login_hashing).acquire_owned(),
    )
    .await
    .map_err(|_| AppError::RateLimited("login is busy; retry shortly".to_string()))?
    .map_err(|_| AppError::Internal("password verification unavailable".to_string()))?;
    let accounts = Arc::clone(&state.accounts);
    let limiter = Arc::clone(&state.login_limiter);
    let username = username.to_string();
    let limiter_username = limiter_username.to_string();
    tokio::task::spawn_blocking(move || {
        // Keep check, hash and result accounting inside the same slot. The
        // blocking task completes accounting even if its HTTP request is dropped.
        let _permit = permit;
        if limiter.blocking_write().check(source, &limiter_username) {
            return Err(AppError::RateLimited(
                "account locked due to too many failed attempts".into(),
            ));
        }
        let valid = accounts.verify(&username, &password)?;
        let mut limiter = limiter.blocking_write();
        if valid {
            limiter.record_success(source, &limiter_username);
        } else {
            limiter.record_failure(source, &limiter_username);
        }
        Ok(valid)
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
    #[serde(default)]
    pub claim: Option<String>,
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

    // An oversized name costs neither a hash nor a lockout entry, which keeps
    // its name for the lockout period. Only the size is checked: an account an
    // older version created may have a name today's rules refuse.
    if req.username.is_empty() || req.username.len() > MAX_LOGIN_USERNAME_BYTES {
        return Err(AppError::BadRequest("invalid username".to_string()));
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
    if !verify_bounded(&state, source, &req.username, &req.username, password).await? {
        let mut limiter = state.login_limiter.write().await;
        let locked = limiter.check(source, &req.username);
        if locked {
            tracing::warn!(source_ip, username = ?req.username, "login lockout threshold reached");
            audit::login_failure(&req.username, &source_ip, "lockout");
        } else {
            audit::login_failure(&req.username, &source_ip, "invalid_credentials");
        }
        return Err(AppError::InvalidCredentials);
    }

    audit::login_success(&req.username, &source_ip);
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
        claim,
        ..
    } = req;
    let claim = Zeroizing::new(
        claim.ok_or_else(|| AppError::Forbidden("first-boot claim token required".to_string()))?,
    );
    crate::auth::claim::check(&state.config.paths.account_file, claim.as_str())?;
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
            crate::auth::claim::check(&state.config.paths.account_file, claim.as_str())?;
            replace_credentials(&state.accounts, &writer, Change::Setup, username, password)
                .await?;
            crate::auth::claim::consume(&state.config.paths.account_file)?;
            state.accounts.refresh_ssh(&writer).await.map_err(|_| {
                AppError::Internal("credentials changed, but SSH protection refresh failed".into())
            })
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
        claim: _,
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
            state.accounts.refresh_ssh(&writer).await.map_err(|_| {
                AppError::Internal("credentials changed, but SSH protection refresh failed".into())
            })
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
    if verify_bounded(state, source, username, username, current).await? {
        return Ok(());
    }
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
    // Install key-only barriers before the first hash can make crypt()'s error
    // marker exploitable. Refresh again after commit to enable root's new hash.
    accounts.refresh_ssh(writer).await?;
    let changed_accounts = Arc::clone(accounts);
    writer
        .blocking(move |permit| {
            changed_accounts.replace_credentials(permit, change, &username, &password, &root_hash)
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

    fn password() -> Zeroizing<String> {
        Zeroizing::new(PASSWORD.to_string())
    }

    #[tokio::test]
    async fn queued_verification_rechecks_name_and_source_lockouts() {
        use std::{future::Future, task::Poll};
        let dir = tempfile::tempdir().unwrap();
        let (state, _, _) = change_fixture(&dir).await;
        let source = "192.0.2.10".parse().unwrap();
        for key in ["operator", "terminal:operator"] {
            let held = Arc::clone(&state.login_hashing)
                .acquire_owned()
                .await
                .unwrap();
            let mut queued = Box::pin(verify_bounded(&state, source, key, "operator", password()));
            std::future::poll_fn(|cx| {
                assert!(queued.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            {
                let mut limiter = state.login_limiter.write().await;
                limiter.record_failure(source, key);
                limiter.record_failure(source, key);
            }
            drop(held);
            assert!(
                matches!(queued.await, Err(AppError::RateLimited(message)) if message.contains("account locked"))
            );
            assert!(state.login_limiter.write().await.check(source, key));
            state
                .login_limiter
                .write()
                .await
                .record_success(source, key);
        }
        let held = Arc::clone(&state.login_hashing)
            .acquire_owned()
            .await
            .unwrap();
        let mut queued = Box::pin(verify_bounded(
            &state,
            source,
            "operator",
            "operator",
            password(),
        ));
        std::future::poll_fn(|cx| {
            assert!(queued.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        for n in 0..8 {
            state
                .login_limiter
                .write()
                .await
                .record_failure(source, &format!("guess{n}"));
        }
        drop(held);
        assert!(
            matches!(queued.await, Err(AppError::RateLimited(message)) if message.contains("account locked"))
        );
        assert!(state.login_limiter.write().await.check(source, "operator"));
        assert!(
            !state
                .login_limiter
                .write()
                .await
                .check("192.0.2.11".parse().unwrap(), "operator")
        );
    }

    #[tokio::test]
    async fn dropped_request_records_failure_before_releasing_hash_slot() {
        use std::{future::Future, task::Poll};
        let dir = tempfile::tempdir().unwrap();
        let (state, _, _) = change_fixture(&dir).await;
        let source = "192.0.2.10".parse().unwrap();
        let mut limiter = state.login_limiter.write().await;
        // One more failure locks this name. Hold the limiter so the detached
        // blocking task cannot finish before its request future is dropped.
        limiter.record_failure(source, "operator");
        let mut cancelled = Box::pin(verify_bounded(
            &state,
            source,
            "operator",
            "nonexistent",
            password(),
        ));
        std::future::poll_fn(|cx| {
            assert!(cancelled.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(state.login_hashing.available_permits(), 0);
        drop(cancelled);
        drop(limiter);
        let next = verify_bounded(&state, source, "operator", "operator", password()).await;
        assert!(
            matches!(next, Err(AppError::RateLimited(message)) if message.contains("account locked"))
        );
        assert!(state.login_limiter.write().await.check(source, "operator"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verification_runs_off_the_runtime_one_at_a_time_and_refuses_after_its_wait() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, _) = change_fixture(&dir).await;
        let source = "192.0.2.10".parse().unwrap();
        let hashing = Arc::clone(&state.login_hashing);
        assert!(
            verify_bounded(&state, source, "operator", "operator", password())
                .await
                .unwrap()
        );
        assert!(
            !verify_bounded(&state, source, "intruder", "intruder", password())
                .await
                .unwrap()
        );
        // The only thread of this runtime keeps serving while a hash runs.
        let verification = tokio::spawn({
            let state = state.clone();
            async move { verify_bounded(&state, source, "operator", "operator", password()).await }
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
        let refused = verify_bounded(&state, source, "operator", "operator", password()).await;
        assert!(matches!(refused, Err(AppError::RateLimited(_))));
        assert!(started.elapsed() >= VERIFY_WAIT);
        drop(held);
        assert!(
            verify_bounded(&state, source, "operator", "operator", password())
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
        let ssh_service = dir.path().join("ssh-service");
        std::fs::write(&ssh_service, "#!/bin/sh\n[ \"$1\" = refresh ] || exit 2\ncat \"${0%/*}/shadow\" >> \"${0%/*}/ssh-refresh.snapshots\"\n").unwrap();
        std::fs::set_permissions(&ssh_service, std::fs::Permissions::from_mode(0o700)).unwrap();
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
            claim: None,
        })
    }

    fn client() -> ConnectInfo<ClientAddr> {
        ConnectInfo(ClientAddr("192.0.2.10:40000".parse().unwrap(), None))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_logins_cost_neither_a_hash_nor_a_lockout() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _session, _shadow) = change_fixture(&dir).await;
        let login_as = |username: String, password: String| {
            let state = state.clone();
            async move {
                login(
                    State(state),
                    client(),
                    Json(LoginReq { username, password }),
                )
                .await
                .map(|_| ())
            }
        };
        // With the only hashing slot taken, a request that reached Argon2
        // would wait and then be refused as busy, not as malformed.
        let held = Arc::clone(&state.login_hashing)
            .acquire_owned()
            .await
            .unwrap();
        for _ in 0..3 {
            assert!(matches!(
                login_as("x".repeat(100 * 1024), PASSWORD.into()).await,
                Err(AppError::BadRequest(_))
            ));
            assert!(matches!(
                login_as(String::new(), PASSWORD.into()).await,
                Err(AppError::BadRequest(_))
            ));
            assert!(matches!(
                login_as("operator".into(), "p".repeat(5000)).await,
                Err(AppError::BadRequest(_))
            ));
        }
        drop(held);
        // The limiter (two failures lock) counted none of them.
        login_as("operator".into(), PASSWORD.into()).await.unwrap();
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
        let snapshots = std::fs::read_to_string(dir.path().join("ssh-refresh.snapshots")).unwrap();
        let snapshots: Vec<_> = snapshots.lines().collect();
        assert_eq!(snapshots.len(), 2);
        assert!(snapshots[0].starts_with("root:$5$"));
        assert!(snapshots[1].starts_with("root:$6$"));
    }

    #[tokio::test]
    async fn first_setup_refreshes_before_and_after_the_first_hash() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (state, _, shadow) = change_fixture(&dir).await;
        std::fs::remove_file(dir.path().join("pwd")).unwrap();
        std::fs::write(&shadow, "root:*:19000:0:99999:7:::\n").unwrap();
        // A private fixture record in the real claim format; no console or
        // production claim state is touched.
        let claim = "synthetic-setup-claim";
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let uptime = std::fs::read_to_string("/proc/uptime").unwrap();
        let seconds = uptime.split('.').next().unwrap();
        let claim_path = dir.path().join("first-boot-claim");
        std::fs::write(&claim_path, format!("{claim}\n{} {seconds}\n", boot.trim())).unwrap();
        std::fs::set_permissions(&claim_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        setup_first_account(
            State(state.clone()),
            Json(ChangePasswordReq {
                username: "operator".into(),
                password: NEW_PASSWORD.into(),
                current_password: None,
                claim: Some(claim.into()),
            }),
        )
        .await
        .unwrap();
        assert!(state.accounts.verify("operator", NEW_PASSWORD).unwrap());
        assert!(!claim_path.exists());
        let snapshots = std::fs::read_to_string(dir.path().join("ssh-refresh.snapshots")).unwrap();
        let snapshots: Vec<_> = snapshots.lines().collect();
        assert_eq!(snapshots.len(), 2);
        assert!(snapshots[0].starts_with("root:*:"));
        assert!(snapshots[1].starts_with("root:$6$"));
        assert!(!state.accounts.credential_recovery_pending());
    }

    #[tokio::test]
    async fn startup_applies_service_locks_before_refreshing_ssh() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _, shadow) = change_fixture(&dir).await;
        std::fs::write(
            dir.path().join("passwd"),
            "root:x:0:0::/root:/bin/sh\ndaemon:x:1:1::/:/bin/false\n",
        )
        .unwrap();
        std::fs::write(
            &shadow,
            "root:*:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n",
        )
        .unwrap();
        state.lock_service_accounts().await;
        let snapshots = std::fs::read_to_string(dir.path().join("ssh-refresh.snapshots")).unwrap();
        assert!(snapshots.starts_with("root:*:"));
        assert!(snapshots.contains("\ndaemon:!*:"));
        assert_eq!(snapshots.lines().count(), 2);
        assert_eq!(std::fs::read_to_string(shadow).unwrap(), snapshots);
    }

    #[tokio::test]
    async fn failed_ssh_preparation_leaves_credentials_and_session_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let (state, session, shadow) = change_fixture(&dir).await;
        let before = std::fs::read(&shadow).unwrap();
        std::fs::write(dir.path().join("ssh-service"), "#!/bin/sh\nexit 1\n").unwrap();
        assert!(
            change_password(
                State(state.clone()),
                client(),
                Extension(CurrentSession(session.clone())),
                change(Some(PASSWORD))
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(shadow).unwrap(), before);
        assert!(state.accounts.verify("operator", PASSWORD).unwrap());
        assert!(state.sessions.validate(&session.token).await.is_some());
        assert!(!state.accounts.credential_recovery_pending());
    }

    #[tokio::test]
    async fn failed_ssh_refresh_after_commit_still_revokes_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let (state, session, shadow) = change_fixture(&dir).await;
        std::fs::write(
            dir.path().join("ssh-service"),
            r#"#!/bin/sh
case "$(cat "${0%/*}/shadow")" in 'root:$6$'*) exit 1 ;; esac
exit 0
"#,
        )
        .unwrap();
        let result = change_password(
            State(state.clone()),
            client(),
            Extension(CurrentSession(session.clone())),
            change(Some(PASSWORD)),
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Internal(message)) if message.contains("credentials changed"))
        );
        assert!(
            std::fs::read_to_string(shadow)
                .unwrap()
                .starts_with("root:$6$")
        );
        assert!(state.accounts.verify("operator", NEW_PASSWORD).unwrap());
        assert!(state.sessions.validate(&session.token).await.is_none());
        assert!(!state.accounts.credential_recovery_pending());
    }
}
