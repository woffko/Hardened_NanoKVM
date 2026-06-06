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
