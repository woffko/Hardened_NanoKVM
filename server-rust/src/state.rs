use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use tokio::sync::RwLock;

use crate::{
    Result,
    auth::{password::AccountStore, session::SessionStore},
    config::Config,
    security::rate_limit::LoginRateLimiter,
};

pub const DEFAULT_SESSION_LOCK_DURATION_SECS: u64 = 900;
pub const SESSION_LOCK_DURATION_OPTIONS: [u64; 4] = [300, 900, 1800, 3600];

pub fn is_allowed_session_lock_duration(seconds: u64) -> bool {
    SESSION_LOCK_DURATION_OPTIONS.contains(&seconds)
}

pub fn normalize_session_lock_duration(seconds: u64) -> u64 {
    if is_allowed_session_lock_duration(seconds) {
        seconds
    } else {
        DEFAULT_SESSION_LOCK_DURATION_SECS
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub accounts: Arc<AccountStore>,
    pub sessions: Arc<SessionStore>,
    pub login_limiter: Arc<RwLock<LoginRateLimiter>>,
    pub terminal_enabled: Arc<AtomicBool>,
    pub remote_image_download_enabled: Arc<AtomicBool>,
    pub session_lock_duration: Arc<AtomicU64>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        let accounts = AccountStore::new(config.paths.account_file.clone());
        if config.security.allow_default_admin && accounts.seed_legacy_default_account()? {
            tracing::warn!("seeded legacy default web account admin/admin");
        }

        let sessions = SessionStore::new();
        let login_limiter = LoginRateLimiter::new(
            config.security.login_max_failures,
            config.security.login_lockout_duration,
        );

        let terminal_enabled = config.security.allow_terminal;
        let remote_image_download_enabled = config.security.allow_remote_image_download;
        let session_lock_duration =
            normalize_session_lock_duration(config.security.access_token_duration);

        Ok(Self {
            config: Arc::new(config),
            accounts: Arc::new(accounts),
            sessions: Arc::new(sessions),
            login_limiter: Arc::new(RwLock::new(login_limiter)),
            terminal_enabled: Arc::new(AtomicBool::new(terminal_enabled)),
            remote_image_download_enabled: Arc::new(AtomicBool::new(remote_image_download_enabled)),
            session_lock_duration: Arc::new(AtomicU64::new(session_lock_duration)),
        })
    }

    pub fn set_terminal_enabled(&self, enabled: bool) {
        self.terminal_enabled.store(enabled, Ordering::Release);
    }

    pub fn terminal_enabled(&self) -> bool {
        self.terminal_enabled.load(Ordering::Acquire)
    }

    pub fn set_remote_image_download_enabled(&self, enabled: bool) {
        self.remote_image_download_enabled
            .store(enabled, Ordering::Release);
    }

    pub fn remote_image_download_enabled(&self) -> bool {
        self.remote_image_download_enabled.load(Ordering::Acquire)
    }

    pub fn set_session_lock_duration(&self, seconds: u64) {
        self.session_lock_duration
            .store(normalize_session_lock_duration(seconds), Ordering::Release);
    }

    pub fn session_lock_duration(&self) -> u64 {
        self.session_lock_duration.load(Ordering::Acquire)
    }
}
