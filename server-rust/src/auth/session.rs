use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::sync::RwLock;

use crate::auth::token::random_token;

#[derive(Debug, Clone)]
pub struct Session {
    pub token: String,
    pub username: String,
    pub csrf_token: String,
    pub expires_at: Instant,
    pub expires_at_unix: u64,
}

fn deadline(ttl_secs: u64) -> (Instant, u64) {
    let ttl = Duration::from_secs(ttl_secs);
    let expires_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(ttl)
        .as_secs();
    (Instant::now() + ttl, expires_at_unix)
}

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
        let (expires_at, expires_at_unix) = deadline(ttl_secs);
        let session = Session {
            token: token.clone(),
            username: username.to_string(),
            csrf_token,
            expires_at,
            expires_at_unix,
        };
        self.sessions.write().await.insert(token, session.clone());
        session
    }

    pub async fn validate(&self, token: &str) -> Option<Session> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get(token).cloned()?;
        if Instant::now() >= session.expires_at {
            sessions.remove(token);
            return None;
        }
        Some(session)
    }

    pub async fn retime(&self, token: &str, ttl_secs: u64) -> Option<Session> {
        let (expires_at, expires_at_unix) = deadline(ttl_secs);
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(token)?;
        session.expires_at = expires_at;
        session.expires_at_unix = expires_at_unix;
        Some(session.clone())
    }

    /// Slide a live session to a full `ttl_secs` from now. Unlike `retime`, this never
    /// revives a session that has already run out.
    pub async fn touch(&self, token: &str, ttl_secs: u64) -> Option<Session> {
        let mut sessions = self.sessions.write().await;
        let session = sessions.get_mut(token)?;
        if Instant::now() >= session.expires_at {
            sessions.remove(token);
            return None;
        }
        let (expires_at, expires_at_unix) = deadline(ttl_secs);
        session.expires_at = expires_at;
        session.expires_at_unix = expires_at_unix;
        Some(session.clone())
    }

    pub async fn revoke(&self, token: &str) {
        self.sessions.write().await.remove(token);
    }

    pub async fn revoke_user(&self, username: &str) {
        self.sessions
            .write()
            .await
            .retain(|_, session| session.username != username);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn touching_a_live_session_slides_its_deadline() {
        let store = SessionStore::new();
        let session = store.issue("admin", 2).await;

        let touched = store.touch(&session.token, 3600).await.unwrap();
        assert!(touched.expires_at > session.expires_at + Duration::from_secs(3000));
        assert!(touched.expires_at_unix >= session.expires_at_unix + 3000);
        assert_eq!(touched.token, session.token);
        assert_eq!(touched.csrf_token, session.csrf_token);

        let valid = store.validate(&session.token).await.unwrap();
        assert_eq!(valid.expires_at, touched.expires_at);
    }

    #[tokio::test]
    async fn touching_an_expired_session_does_not_revive_it() {
        let store = SessionStore::new();
        let session = store.issue("admin", 0).await;

        assert!(store.touch(&session.token, 3600).await.is_none());
        assert!(store.validate(&session.token).await.is_none());
    }

    #[tokio::test]
    async fn touching_an_unknown_token_does_nothing() {
        let store = SessionStore::new();
        assert!(store.touch("missing", 3600).await.is_none());
    }
}
