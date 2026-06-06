use std::sync::Arc;

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
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        let accounts = AccountStore::new(config.paths.account_file.clone());
        let sessions = SessionStore::new();
        let login_limiter = LoginRateLimiter::new(
            config.security.login_max_failures,
            config.security.login_lockout_duration,
        );

        Ok(Self {
            config: Arc::new(config),
            accounts: Arc::new(accounts),
            sessions: Arc::new(sessions),
            login_limiter: Arc::new(RwLock::new(login_limiter)),
        })
    }
}
