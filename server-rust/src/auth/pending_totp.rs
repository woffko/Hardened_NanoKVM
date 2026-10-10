//! Short-lived tickets bridging the two halves of a two-factor login.
//!
//! A ticket is issued once the password has been verified and exchanged for a
//! real session once the second factor has been. It is deliberately *not* a
//! [`Session`](crate::auth::session::Session) and carries no authority of its
//! own: [`PendingTotpStore::consume`] hands back only a username, so no route
//! can mistake a half-finished login for an authenticated one.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use tokio::sync::RwLock;

use crate::auth::token::random_token;

/// How long the second step stays available. Long enough to open an
/// authenticator app and read a code, short enough that an abandoned login
/// does not linger.
pub const PENDING_TTL_SECS: u64 = 300;

#[derive(Debug, Clone)]
struct PendingLogin {
    username: String,
    source_ip: String,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct PendingTotpStore {
    entries: RwLock<HashMap<String, PendingLogin>>,
}

impl PendingTotpStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a ticket for an account that has passed the password check.
    pub async fn issue(&self, username: &str, source_ip: &str) -> String {
        let now = Instant::now();
        let token = random_token(32);
        let pending = PendingLogin {
            username: username.to_string(),
            source_ip: source_ip.to_string(),
            expires_at: now + Duration::from_secs(PENDING_TTL_SECS),
        };

        let mut entries = self.entries.write().await;
        prune_expired(&mut entries, now);
        entries.insert(token.clone(), pending);
        token
    }

    /// Resolve a ticket without spending it, for use when the submitted code
    /// turns out to be wrong. A mistyped digit should cost the user a retry,
    /// not the whole login.
    pub async fn peek(&self, token: &str, source_ip: &str) -> Option<String> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        prune_expired(&mut entries, now);
        let pending = entries.get(token)?;
        matches(pending, source_ip, now).then(|| pending.username.clone())
    }

    /// Spend a ticket, returning the account it authorizes.
    pub async fn consume(&self, token: &str, source_ip: &str) -> Option<String> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        prune_expired(&mut entries, now);
        let pending = entries.remove(token)?;
        matches(&pending, source_ip, now).then_some(pending.username)
    }

    /// Drop a ticket, for an abandoned or superseded login.
    pub async fn discard(&self, token: &str) {
        self.entries.write().await.remove(token);
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.entries.read().await.len()
    }
}

/// How long an unconfirmed enrolment secret is held.
pub const PENDING_ENROLMENT_TTL_SECS: u64 = 600;

#[derive(Debug, Clone)]
struct PendingEnrolment {
    secret: String,
    expires_at: Instant,
}

/// Secrets generated for enrolment but not yet confirmed with a code.
///
/// Held here rather than written to the account file so that an abandoned
/// enrolment leaves nothing behind, and so a secret can never be active
/// without the user having proven their authenticator produces matching codes.
#[derive(Debug, Default)]
pub struct PendingEnrolmentStore {
    entries: RwLock<HashMap<String, PendingEnrolment>>,
}

impl PendingEnrolmentStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a freshly generated secret, replacing any earlier attempt.
    pub async fn put(&self, username: &str, secret: &str) {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        entries.retain(|_, entry| entry.expires_at > now);
        entries.insert(
            username.to_string(),
            PendingEnrolment {
                secret: secret.to_string(),
                expires_at: now + Duration::from_secs(PENDING_ENROLMENT_TTL_SECS),
            },
        );
    }

    pub async fn get(&self, username: &str) -> Option<String> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        entries.retain(|_, entry| entry.expires_at > now);
        entries.get(username).map(|entry| entry.secret.clone())
    }

    pub async fn take(&self, username: &str) -> Option<String> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;
        entries.retain(|_, entry| entry.expires_at > now);
        entries.remove(username).map(|entry| entry.secret)
    }

    pub async fn clear(&self, username: &str) {
        self.entries.write().await.remove(username);
    }
}

/// A ticket is only usable from the address that obtained it, so a leaked
/// token is not enough on its own.
fn matches(pending: &PendingLogin, source_ip: &str, now: Instant) -> bool {
    pending.expires_at > now && pending.source_ip == source_ip
}

fn prune_expired(entries: &mut HashMap<String, PendingLogin>, now: Instant) {
    entries.retain(|_, pending| pending.expires_at > now);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address the ticket is issued to.
    const SOURCE_IP: &str = "10.0.0.5";
    /// Any other address; a ticket must not be usable from it.
    const OTHER_SOURCE_IP: &str = "10.0.0.9";

    #[tokio::test]
    async fn consumes_a_ticket_exactly_once() {
        let store = PendingTotpStore::new();
        let token = store.issue("operator", SOURCE_IP).await;

        assert_eq!(
            store.consume(&token, SOURCE_IP).await.as_deref(),
            Some("operator")
        );
        assert_eq!(store.consume(&token, SOURCE_IP).await, None);
    }

    #[tokio::test]
    async fn peeking_leaves_the_ticket_usable() {
        let store = PendingTotpStore::new();
        let token = store.issue("operator", SOURCE_IP).await;

        // A wrong code peeks repeatedly; the ticket must survive.
        for _ in 0..3 {
            assert_eq!(
                store.peek(&token, SOURCE_IP).await.as_deref(),
                Some("operator")
            );
        }
        assert_eq!(
            store.consume(&token, SOURCE_IP).await.as_deref(),
            Some("operator")
        );
    }

    #[tokio::test]
    async fn rejects_a_ticket_replayed_from_another_address() {
        let store = PendingTotpStore::new();
        let token = store.issue("operator", SOURCE_IP).await;

        assert_eq!(store.peek(&token, OTHER_SOURCE_IP).await, None);
        assert_eq!(store.consume(&token, OTHER_SOURCE_IP).await, None);
    }

    #[tokio::test]
    async fn rejects_an_unknown_ticket() {
        let store = PendingTotpStore::new();
        assert_eq!(store.consume("nonexistent", SOURCE_IP).await, None);
    }

    #[tokio::test]
    async fn discards_an_abandoned_ticket() {
        let store = PendingTotpStore::new();
        let token = store.issue("operator", SOURCE_IP).await;

        store.discard(&token).await;

        assert_eq!(store.consume(&token, SOURCE_IP).await, None);
    }

    #[tokio::test]
    async fn enrolment_secret_is_taken_once() {
        let store = PendingEnrolmentStore::new();
        store.put("operator", "SECRET").await;

        assert_eq!(store.get("operator").await.as_deref(), Some("SECRET"));
        assert_eq!(store.take("operator").await.as_deref(), Some("SECRET"));
        assert_eq!(store.get("operator").await, None);
    }

    #[tokio::test]
    async fn restarting_enrolment_replaces_the_secret() {
        let store = PendingEnrolmentStore::new();
        store.put("operator", "FIRST").await;
        store.put("operator", "SECOND").await;

        assert_eq!(store.take("operator").await.as_deref(), Some("SECOND"));
    }

    #[tokio::test]
    async fn abandoned_enrolment_can_be_cleared() {
        let store = PendingEnrolmentStore::new();
        store.put("operator", "SECRET").await;

        store.clear("operator").await;

        assert_eq!(store.get("operator").await, None);
    }

    #[tokio::test]
    async fn expired_tickets_are_pruned_on_write() {
        let store = PendingTotpStore::new();
        let token = store.issue("operator", SOURCE_IP).await;

        // Expire it without waiting out the real TTL.
        store
            .entries
            .write()
            .await
            .get_mut(&token)
            .unwrap()
            .expires_at = Instant::now() - Duration::from_secs(1);

        assert_eq!(store.peek(&token, SOURCE_IP).await, None);
        assert_eq!(store.len().await, 0);
    }
}
