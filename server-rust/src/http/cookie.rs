use axum::http::HeaderValue;

use crate::{AppError, Result};

const SESSION_COOKIE_NAME: &str = "nano-kvm-token";
pub const PENDING_TOTP_COOKIE_NAME: &str = "nano-kvm-totp";

pub fn session_cookie(token: &str, max_age_secs: u64, secure: bool) -> Result<HeaderValue> {
    build_session_cookie(Some(token), max_age_secs, secure)
}

pub fn expired_session_cookie(secure: bool) -> Result<HeaderValue> {
    build_session_cookie(None, 0, secure)
}

pub fn session_cookie_secure(proto: &str) -> bool {
    proto.eq_ignore_ascii_case("https")
}

/// Cookie carrying the half-finished login between the two steps.
///
/// HttpOnly like the session cookie, so the ticket is never readable from JS.
pub fn pending_totp_cookie(token: &str, max_age_secs: u64, secure: bool) -> Result<HeaderValue> {
    build_cookie(PENDING_TOTP_COOKIE_NAME, Some(token), max_age_secs, secure)
}

pub fn expired_pending_totp_cookie(secure: bool) -> Result<HeaderValue> {
    build_cookie(PENDING_TOTP_COOKIE_NAME, None, 0, secure)
}

fn build_session_cookie(
    token: Option<&str>,
    max_age_secs: u64,
    secure: bool,
) -> Result<HeaderValue> {
    build_cookie(SESSION_COOKIE_NAME, token, max_age_secs, secure)
}

fn build_cookie(
    name: &str,
    token: Option<&str>,
    max_age_secs: u64,
    secure: bool,
) -> Result<HeaderValue> {
    let mut value = format!(
        "{name}={}; Path=/; Max-Age={max_age_secs}; HttpOnly; SameSite=Lax",
        token.unwrap_or_default()
    );
    if secure {
        value.push_str("; Secure");
    }

    HeaderValue::from_str(&value)
        .map_err(|err| AppError::Internal(format!("failed to build cookie: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_is_httponly_and_lax() {
        let cookie = session_cookie("abc", 900, false).unwrap();
        let value = cookie.to_str().unwrap();
        assert!(value.contains("nano-kvm-token=abc"));
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(!value.contains("Secure"));
    }

    #[test]
    fn secure_session_cookie_sets_secure_attribute() {
        let cookie = session_cookie("abc", 900, true).unwrap();
        assert!(cookie.to_str().unwrap().contains("Secure"));
    }

    #[test]
    fn pending_totp_cookie_is_httponly_and_separate_from_the_session() {
        let cookie = pending_totp_cookie("pending", 300, true).unwrap();
        let value = cookie.to_str().unwrap();
        assert!(value.contains("nano-kvm-totp=pending"));
        assert!(!value.contains("nano-kvm-token="));
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Lax"));
        assert!(value.contains("Secure"));
    }

    #[test]
    fn expired_pending_totp_cookie_clears_the_ticket() {
        let cookie = expired_pending_totp_cookie(false).unwrap();
        let value = cookie.to_str().unwrap();
        assert!(value.contains("nano-kvm-totp="));
        assert!(value.contains("Max-Age=0"));
    }

    #[test]
    fn expired_session_cookie_clears_the_token() {
        let cookie = expired_session_cookie(true).unwrap();
        let value = cookie.to_str().unwrap();
        assert!(value.contains("nano-kvm-token="));
        assert!(value.contains("Max-Age=0"));
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("Secure"));
    }
}
