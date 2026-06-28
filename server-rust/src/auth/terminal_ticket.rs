use std::{
    collections::HashMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use tokio::sync::RwLock;

use crate::auth::{session::Session, token::random_token};

#[derive(Debug, Clone)]
pub struct TerminalTicket {
    pub token: String,
    pub expires_at: Instant,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone)]
struct StoredTerminalTicket {
    username: String,
    session_token: String,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct TerminalTicketStore {
    tickets: RwLock<HashMap<String, StoredTerminalTicket>>,
}

impl TerminalTicketStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn issue(&self, session: &Session, ttl_secs: u64) -> TerminalTicket {
        let now = Instant::now();
        let requested_expires_at = now + Duration::from_secs(ttl_secs);
        let expires_at = requested_expires_at.min(session.expires_at);
        let expires_at_unix = unix_deadline_from_now(now, expires_at);
        let token = random_token(32);
        let ticket = StoredTerminalTicket {
            username: session.username.clone(),
            session_token: session.token.clone(),
            expires_at,
        };
        let mut tickets = self.tickets.write().await;
        prune_expired(&mut tickets, now);
        tickets.insert(token.clone(), ticket);
        TerminalTicket {
            token,
            expires_at,
            expires_at_unix,
        }
    }

    pub async fn consume(&self, token: &str, session: &Session) -> bool {
        let now = Instant::now();
        let mut tickets = self.tickets.write().await;
        prune_expired(&mut tickets, now);
        let Some(ticket) = tickets.remove(token) else {
            return false;
        };
        ticket.expires_at > now
            && ticket.username == session.username
            && ticket.session_token == session.token
    }
}

fn prune_expired(tickets: &mut HashMap<String, StoredTerminalTicket>, now: Instant) {
    tickets.retain(|_, ticket| ticket.expires_at > now);
}

fn unix_deadline_from_now(now: Instant, deadline: Instant) -> u64 {
    let duration = deadline.saturating_duration_since(now);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_add(duration)
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(username: &str, token: &str, ttl_secs: u64) -> Session {
        let ttl = Duration::from_secs(ttl_secs);
        Session {
            token: token.to_string(),
            username: username.to_string(),
            csrf_token: "csrf".to_string(),
            expires_at: Instant::now() + ttl,
            expires_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .saturating_add(ttl)
                .as_secs(),
        }
    }

    #[tokio::test]
    async fn consumes_ticket_once_for_same_session() {
        let store = TerminalTicketStore::new();
        let session = session("admin", "session-token", 300);
        let ticket = store.issue(&session, 120).await;

        assert!(store.consume(&ticket.token, &session).await);
        assert!(!store.consume(&ticket.token, &session).await);
    }

    #[tokio::test]
    async fn rejects_ticket_for_different_session() {
        let store = TerminalTicketStore::new();
        let session_a = session("admin", "session-a", 300);
        let session_b = session("admin", "session-b", 300);
        let ticket = store.issue(&session_a, 120).await;

        assert!(!store.consume(&ticket.token, &session_b).await);
    }

    #[tokio::test]
    async fn ticket_deadline_does_not_exceed_session_deadline() {
        let store = TerminalTicketStore::new();
        let session = session("admin", "session-token", 1);
        let ticket = store.issue(&session, 120).await;

        assert!(ticket.expires_at <= session.expires_at);
    }
}
