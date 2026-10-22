use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::sync::RwLock;

use crate::auth::token::random_token;

#[path = "session_lifetime.rs"]
mod lifetime;
pub(crate) use lifetime::SessionLifetime;

#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    pub username: String,
    pub csrf_token: String,
    pub expires_at: Instant,
    pub expires_at_unix: u64,
    lifetime: SessionLifetime,
}

impl Session {
    // Transports capture liveness without retaining the bearer/CSRF credentials.
    pub(crate) fn lifetime(&self) -> SessionLifetime {
        self.lifetime.clone()
    }
}

/// Live sessions kept at once. At the cap the session closest to expiry is
/// revoked, so repeated logins cannot grow the store without bound.
const MAX_SESSIONS: usize = 32;

#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: RwLock<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn issue(&self, username: &str, ttl_secs: u64) -> Session {
        let token = random_token(32);
        let csrf_token = random_token(32);
        let ttl = Duration::from_secs(ttl_secs);
        let expires_at = Instant::now() + ttl;
        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .saturating_add(ttl)
            .as_secs();
        let session = Session {
            token: token.clone(),
            username: username.to_string(),
            csrf_token,
            expires_at,
            expires_at_unix,
            lifetime: SessionLifetime::new(expires_at),
        };
        let mut sessions = self.sessions.write().await;
        // Expired sessions go here as well, not only when presented again;
        // `is_active` ends each one's lifetime and every transport it captured.
        sessions.retain(|_, session| session.lifetime.is_active());
        if sessions.len() >= MAX_SESSIONS
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.expires_at)
                .map(|(token, _)| token.clone())
            && let Some(evicted) = sessions.remove(&oldest)
        {
            evicted.lifetime.revoke();
        }
        if let Some(previous) = sessions.insert(token, session.clone()) {
            previous.lifetime.revoke();
        }
        drop(sessions);
        session
    }

    pub async fn validate(&self, token: &str) -> Option<Session> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get(token).cloned()?;
        if !session.lifetime.is_active() {
            sessions.remove(token);
            return None;
        }
        Some(session)
    }

    pub async fn retime(&self, token: &str, ttl_secs: u64) -> Option<Session> {
        let ttl = Duration::from_secs(ttl_secs);
        let expires_at = Instant::now() + ttl;
        let expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .saturating_add(ttl)
            .as_secs();
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(token)?;
        if !session.lifetime.retime(expires_at) {
            sessions.remove(token);
            return None;
        }
        session.expires_at = expires_at;
        session.expires_at_unix = expires_at_unix;
        Some(session.clone())
    }

    pub async fn revoke(&self, token: &str) {
        if let Some(session) = self.sessions.write().await.remove(token) {
            session.lifetime.revoke();
        }
    }

    pub async fn revoke_user(&self, username: &str) {
        self.sessions.write().await.retain(|_, session| {
            if session.username == username {
                session.lifetime.revoke();
                false
            } else {
                true
            }
        });
    }
}

impl Drop for SessionStore {
    fn drop(&mut self) {
        for session in self.sessions.get_mut().values() {
            session.lifetime.revoke();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lifetime::SessionEnd;

    #[tokio::test]
    async fn logout_revokes_old_captures_but_not_a_same_name_login() {
        let store = SessionStore::new();
        let old = store.issue("admin", 60).await;
        let capture = store.validate(&old.token).await.unwrap().lifetime();
        let next = store.issue("admin", 60).await;
        store.revoke(&old.token).await;
        assert_eq!(capture.ended().await, SessionEnd::Revoked);
        assert!(store.validate(&old.token).await.is_none());
        assert!(store.retime(&old.token, 300).await.is_none());
        assert!(next.lifetime().is_active());
        assert!(store.validate(&next.token).await.is_some());
    }

    #[tokio::test]
    async fn user_revocation_ends_all_of_that_users_handles_only() {
        let store = SessionStore::new();
        let first = store.issue("admin", 60).await;
        let second = store.issue("admin", 60).await;
        let unrelated = store.issue("other", 60).await;
        store.revoke_user("admin").await;
        assert_eq!(first.lifetime().ended().await, SessionEnd::Revoked);
        assert_eq!(second.lifetime().ended().await, SessionEnd::Revoked);
        assert!(unrelated.lifetime().is_active());
        assert!(store.validate(&first.token).await.is_none());
        assert!(store.validate(&second.token).await.is_none());
        assert!(store.validate(&unrelated.token).await.is_some());
    }

    #[tokio::test]
    async fn retime_of_an_expired_store_entry_does_not_resurrect_captures() {
        let store = SessionStore::new();
        let session = store.issue("admin", 0).await;
        assert!(store.retime(&session.token, 300).await.is_none());
        assert_eq!(session.lifetime().ended().await, SessionEnd::Expired);
        assert!(store.validate(&session.token).await.is_none());
        let next = store.issue("admin", 60).await;
        assert!(next.lifetime().is_active());
        assert_eq!(session.lifetime().ended().await, SessionEnd::Expired);
    }

    #[tokio::test]
    async fn retime_updates_a_capture_and_zero_ttl_ends_it_without_validate() {
        let store = SessionStore::new();
        let session = store.issue("admin", 60).await;
        let capture = session.lifetime();
        let renewed = store.retime(&session.token, 300).await.unwrap();
        assert!(renewed.expires_at > session.expires_at);
        assert!(capture.is_active());
        store.retime(&session.token, 0).await.unwrap();
        assert_eq!(capture.ended().await, SessionEnd::Expired);
        assert!(store.retime(&session.token, 300).await.is_none());
    }

    #[tokio::test]
    async fn revoke_and_retime_in_either_order_cannot_renew_a_revoked_login() {
        for renew_first in [false, true] {
            let store = SessionStore::new();
            let session = store.issue("admin", 60).await;
            if renew_first {
                store.retime(&session.token, 300).await.unwrap();
            }
            store.revoke(&session.token).await;
            assert_eq!(session.lifetime().ended().await, SessionEnd::Revoked);
            assert!(store.retime(&session.token, 300).await.is_none());
            assert!(store.issue("admin", 60).await.lifetime().is_active());
            assert_eq!(session.lifetime().ended().await, SessionEnd::Revoked);
        }
    }

    #[tokio::test]
    async fn losing_the_store_revokes_captures_without_a_reference_cycle() {
        let captured = {
            let store = SessionStore::new();
            store.issue("admin", 60).await.lifetime()
        };
        assert_eq!(captured.ended().await, SessionEnd::Revoked);
    }

    #[tokio::test]
    async fn an_expired_session_is_pruned_at_the_next_login_and_its_lifetime_ends() {
        let store = SessionStore::new();
        let expired = store.issue("admin", 0).await;
        let capture = expired.lifetime.clone();
        let live = store.issue("admin", 60).await;
        assert_eq!(store.sessions.read().await.len(), 1);
        assert!(!capture.is_active());
        assert!(store.validate(&expired.token).await.is_none());
        assert!(store.validate(&live.token).await.is_some());
    }

    #[tokio::test]
    async fn the_store_is_capped_and_revokes_the_session_closest_to_expiry() {
        let store = SessionStore::new();
        let first = store.issue("admin", 60).await;
        let capture = store.validate(&first.token).await.unwrap().lifetime();
        let mut later = Vec::new();
        for offset in 1..MAX_SESSIONS {
            later.push(store.issue("admin", 60 + offset as u64).await);
        }
        assert_eq!(store.sessions.read().await.len(), MAX_SESSIONS);
        let newest = store.issue("admin", 600).await;
        assert_eq!(store.sessions.read().await.len(), MAX_SESSIONS);
        assert!(store.validate(&first.token).await.is_none());
        assert!(!capture.is_active(), "the evicted session's transports end");
        for session in later.iter().chain([&newest]) {
            assert!(store.validate(&session.token).await.is_some());
        }
    }
}
