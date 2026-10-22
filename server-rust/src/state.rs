use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use tokio::sync::{RwLock, Semaphore};

use crate::{
    AppError, Result,
    api::system_firewall::FirewallController,
    auth::{password::AccountStore, session::SessionStore, terminal_ticket::TerminalTicketStore},
    config::Config,
    security::rate_limit::LoginRateLimiter,
    update::operation::UpdateCoordinator,
    update::state_writers::{StateWriters, WriterDrain},
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
    pub updates: Arc<UpdateCoordinator>,
    pub(crate) app_job_reads: Arc<Semaphore>,
    /// One password verification at a time, off the async runtime.
    pub(crate) login_hashing: Arc<Semaphore>,
    pub(crate) picoclaw_worker: Arc<crate::api::picoclaw::worker::Worker>,
    pub(crate) webrtc: Arc<crate::api::webrtc_stream::WebRtcManager>,
    #[cfg(test)]
    pub(crate) app_job_test_root: Option<Arc<std::path::PathBuf>>,
    pub writers: Arc<StateWriters>,
    pub firewall: Arc<FirewallController>,
    pub config: Arc<Config>,
    pub accounts: Arc<AccountStore>,
    pub sessions: Arc<SessionStore>,
    pub terminal_tickets: Arc<TerminalTicketStore>,
    pub login_limiter: Arc<RwLock<LoginRateLimiter>>,
    pub(crate) ap_key_limiter: Arc<RwLock<crate::security::rate_limit::ApKeyLimiter>>,
    pub terminal_enabled: Arc<AtomicBool>,
    pub remote_image_download_enabled: Arc<AtomicBool>,
    pub session_lock_duration: Arc<AtomicU64>,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        config.webrtc_limits()?;
        let writers = Arc::new(StateWriters::default());
        let accounts = AccountStore::new(config.paths.account_file.clone());
        // An interrupted credential change is undone before anything reads the
        // stores. Failure keeps its journal, which refuses further changes
        // until a later start succeeds; login keeps working meanwhile.
        if accounts.credential_recovery_pending() {
            match writers
                .account()
                .and_then(|permit| accounts.recover_credentials(&permit))
            {
                Ok(true) => tracing::warn!("restored the credentials of an interrupted change"),
                Ok(false) => {}
                Err(error) => tracing::error!(%error, "credential recovery failed"),
            }
        }
        if config.security.allow_default_admin {
            let permit = writers.account()?;
            if accounts.seed_legacy_default_account(&permit)? {
                tracing::warn!("seeded legacy default web account admin/admin");
            }
        }

        Self::with_identity(config, writers, accounts)
    }

    /// Frozen trial never enrolls a writer or creates a default account. A
    /// pending credential journal waits for the next ordinary start.
    pub fn new_trial(config: Config, startup: &crate::update::app_trial::Startup) -> Result<Self> {
        let account = startup.read_state(&config.paths.account_file, 64 * 1024)?;
        if let Some(bytes) = account {
            let _ = serde_json::from_slice::<crate::auth::password::Account>(&bytes)
                .map_err(|_| AppError::Config("invalid trial account state".into()))?;
        } else if config.security.allow_default_admin {
            return Err(AppError::Config(
                "trial requires existing account identity, not default seeding".into(),
            ));
        }
        let accounts = AccountStore::new(config.paths.account_file.clone());
        Self::with_identity(config, Arc::new(StateWriters::default()), accounts)
    }

    fn with_identity(
        config: Config,
        writers: Arc<StateWriters>,
        accounts: AccountStore,
    ) -> Result<Self> {
        let webrtc = crate::api::webrtc_stream::WebRtcManager::new(config.webrtc_limits()?);
        let sessions = SessionStore::new();
        let terminal_tickets = TerminalTicketStore::new();
        let login_limiter = LoginRateLimiter::new(
            config.security.login_max_failures,
            config.security.login_lockout_duration,
        );

        let terminal_enabled = config.security.allow_terminal;
        let remote_image_download_enabled = config.security.allow_remote_image_download;
        let session_lock_duration =
            normalize_session_lock_duration(config.security.access_token_duration);

        Ok(Self {
            updates: Arc::new(UpdateCoordinator::default()),
            app_job_reads: Arc::new(Semaphore::new(4)),
            login_hashing: Arc::new(Semaphore::new(1)),
            picoclaw_worker: Arc::new(crate::api::picoclaw::worker::Worker::default()),
            webrtc: Arc::new(webrtc),
            #[cfg(test)]
            app_job_test_root: None,
            writers,
            firewall: Arc::new(FirewallController::default()),
            config: Arc::new(config),
            accounts: Arc::new(accounts),
            sessions: Arc::new(sessions),
            terminal_tickets: Arc::new(terminal_tickets),
            login_limiter: Arc::new(RwLock::new(login_limiter)),
            ap_key_limiter: Arc::new(RwLock::new(Default::default())),
            terminal_enabled: Arc::new(AtomicBool::new(terminal_enabled)),
            remote_image_download_enabled: Arc::new(AtomicBool::new(remote_image_download_enabled)),
            session_lock_duration: Arc::new(AtomicU64::new(session_lock_duration)),
        })
    }

    /// A cooperative boundary for the enrolled APIs/timer only. External
    /// services, privileged sessions and other settings are still NOT covered.
    pub async fn drain_writers(&self, timeout: std::time::Duration) -> Result<WriterDrain> {
        let deadline = tokio::time::Instant::now() + timeout;
        let pause = self.writers.pause()?;
        tokio::time::timeout_at(deadline, self.firewall.stop_and_join())
            .await
            .map_err(|_| AppError::Conflict("firewall writer did not stop".into()))??;
        pause
            .drain(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .await
    }

    /// Only WebRTC owners are drained here. This is not the complete backend,
    /// capture/native, privileged-job or delegated-task shutdown boundary.
    pub async fn stop_webrtc(&self) -> Result<()> {
        self.webrtc.stop_and_join().await
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
