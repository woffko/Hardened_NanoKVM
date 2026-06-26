use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::RwLock;

use crate::{
    Result,
    auth::{password::AccountStore, session::SessionStore},
    config::Config,
    security::rate_limit::LoginRateLimiter,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub accounts: Arc<AccountStore>,
    pub sessions: Arc<SessionStore>,
    pub login_limiter: Arc<RwLock<LoginRateLimiter>>,
    pub terminal_enabled: Arc<AtomicBool>,
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

        Ok(Self {
            config: Arc::new(config),
            accounts: Arc::new(accounts),
            sessions: Arc::new(sessions),
            login_limiter: Arc::new(RwLock::new(login_limiter)),
            terminal_enabled: Arc::new(AtomicBool::new(terminal_enabled)),
        })
    }

    pub fn set_terminal_enabled(&self, enabled: bool) {
        self.terminal_enabled.store(enabled, Ordering::Release);
    }

    pub fn terminal_enabled(&self) -> bool {
        self.terminal_enabled.load(Ordering::Acquire)
    }
}
