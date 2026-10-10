//! RFC 6238 TOTP over RFC 4226 HOTP, SHA-1, 6 digits, 30-second steps.
//!
//! Those parameters are not configurable on purpose: they are what every
//! authenticator app implements, and an `otpauth://` URI carrying anything else
//! is silently mis-imported by a good number of them.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::auth::token::random_bytes;

type HmacSha1 = Hmac<Sha1>;

/// Seconds per TOTP step.
pub const TIME_STEP_SECS: u64 = 30;
/// Digits in a generated code.
pub const DIGITS: usize = 6;
/// Steps of clock drift tolerated either side of the current one.
const DRIFT_STEPS: u64 = 1;
/// Length of a generated shared secret. RFC 4226 §4 R6 requires at least 128
/// bits and recommends 160, which is also the SHA-1 block output size.
const SECRET_BYTES: usize = 20;

/// A fresh base32 shared secret, in the form shown to the user for manual entry.
pub fn generate_secret() -> String {
    BASE32_NOPAD.encode(&random_bytes(SECRET_BYTES))
}

/// Decode a base32 secret. Tolerant of what users actually paste: lowercase,
/// embedded spaces (authenticator apps display secrets in groups of four) and
/// trailing `=` padding.
pub fn decode_secret(secret: &str) -> Option<Vec<u8>> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    let normalized = normalized.trim_end_matches('=');
    if normalized.is_empty() {
        return None;
    }
    BASE32_NOPAD.decode(normalized.as_bytes()).ok()
}

/// The step counter covering `now_unix`.
pub fn current_step(now_unix: u64) -> u64 {
    now_unix / TIME_STEP_SECS
}

/// HOTP value for `step` (RFC 4226 §5.3 dynamic truncation).
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts keys of any length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // The low nibble of the last byte selects a 4-byte window; masking the top
    // bit of the first one keeps the result positive across signed languages.
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    binary % 10_u32.pow(DIGITS as u32)
}

/// Render a code the way it is typed: zero-padded to [`DIGITS`].
fn format_code(code: u32) -> String {
    format!("{code:0DIGITS$}")
}

/// Verify `code` against `secret` at `now_unix`, allowing ±[`DRIFT_STEPS`].
///
/// Returns the step that matched, so the caller can record it and refuse a
/// replay of the same code inside its validity window. A `last_used_step` at or
/// above the match is rejected for that reason.
pub fn verify(
    secret: &[u8],
    code: &str,
    now_unix: u64,
    last_used_step: Option<u64>,
) -> Option<u64> {
    let code = code.trim();
    if code.len() != DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let current = current_step(now_unix);
    let mut matched = None;
    // Every candidate step is evaluated even after a hit, so the time taken
    // does not reveal which step matched.
    for step in current.saturating_sub(DRIFT_STEPS)..=current.saturating_add(DRIFT_STEPS) {
        let expected = format_code(code_at(secret, step));
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            matched = Some(step);
        }
    }

    let matched = matched?;
    match last_used_step {
        Some(last) if matched <= last => None,
        _ => Some(matched),
    }
}

/// The `otpauth://` URI encoded into the enrolment QR code (Key Uri Format).
pub fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> String {
    let issuer_enc = urlencoding::encode(issuer);
    let label = urlencoding::encode(account);
    format!(
        "otpauth://totp/{issuer_enc}:{label}?secret={secret}&issuer={issuer_enc}\
         &algorithm=SHA1&digits={DIGITS}&period={TIME_STEP_SECS}"
    )
}

/// Remembers the most recent step accepted for each account, so a code cannot
/// be used twice inside its validity window.
///
/// Held in memory rather than in `/etc/kvm/pwd` on purpose: persisting it would
/// mean a flash write on every single login. Sessions are in-memory already, so
/// a reboot clears no more than it otherwise would, and replaying a captured
/// code across a power cycle means beating a boot that takes far longer than
/// the 30-second window.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    last_step: tokio::sync::RwLock<std::collections::HashMap<String, u64>>,
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// The last step spent by `username`, if any.
    pub async fn last_step(&self, username: &str) -> Option<u64> {
        self.last_step.read().await.get(username).copied()
    }

    /// Claim `step` for `username`, returning false if it has already been
    /// used. Check and record happen under one lock, so two requests racing
    /// with the same code cannot both succeed.
    pub async fn try_use(&self, username: &str, step: u64) -> bool {
        let mut guard = self.last_step.write().await;
        match guard.get(username) {
            Some(last) if *last >= step => false,
            _ => {
                guard.insert(username.to_string(), step);
                true
            }
        }
    }

    /// Forget an account's replay state, on disenrolment.
    pub async fn forget(&self, username: &str) {
        self.last_step.write().await.remove(username);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ASCII secret "12345678901234567890" used by both RFC test suites.
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    fn rfc_secret_base32() -> String {
        BASE32_NOPAD.encode(RFC_SECRET)
    }

    #[test]
    fn matches_rfc4226_appendix_d_hotp_vectors() {
        // RFC 4226 Appendix D, counters 0..=9.
        let expected = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(
                code_at(RFC_SECRET, counter as u64),
                *want,
                "counter {counter}"
            );
        }
    }

    #[test]
    fn matches_rfc6238_appendix_b_sha1_vectors() {
        // RFC 6238 Appendix B. Only the SHA-1 rows apply: the SHA-256 and
        // SHA-512 rows in that table use different, longer seeds.
        let vectors = [
            (59_u64, 94287082_u32),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ];
        for (time, eight_digit) in vectors {
            // The RFC prints 8 digits; this implementation emits 6.
            let want = eight_digit % 1_000_000;
            assert_eq!(code_at(RFC_SECRET, current_step(time)), want, "T={time}");
        }
    }

    #[test]
    fn accepts_one_step_of_drift_but_not_two() {
        let now = 1_767_225_600_u64;
        let step = current_step(now);

        for offset in [-1_i64, 0, 1] {
            let candidate = (step as i64 + offset) as u64;
            let code = format_code(code_at(RFC_SECRET, candidate));
            assert_eq!(
                verify(RFC_SECRET, &code, now, None),
                Some(candidate),
                "offset {offset} should be accepted"
            );
        }

        for offset in [-2_i64, 2] {
            let candidate = (step as i64 + offset) as u64;
            let code = format_code(code_at(RFC_SECRET, candidate));
            assert_eq!(
                verify(RFC_SECRET, &code, now, None),
                None,
                "offset {offset} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_replayed_code() {
        let now = 1_767_225_600_u64;
        let code = format_code(code_at(RFC_SECRET, current_step(now)));

        let step = verify(RFC_SECRET, &code, now, None).expect("first use succeeds");
        assert_eq!(verify(RFC_SECRET, &code, now, Some(step)), None);
    }

    #[test]
    fn replay_guard_still_allows_the_next_step() {
        let now = 1_767_225_600_u64;
        let used = current_step(now);
        let next_now = now + TIME_STEP_SECS;
        let code = format_code(code_at(RFC_SECRET, current_step(next_now)));

        assert_eq!(
            verify(RFC_SECRET, &code, next_now, Some(used)),
            Some(used + 1)
        );
    }

    #[test]
    fn rejects_malformed_codes() {
        let now = 1_767_225_600_u64;
        for bad in ["", "12345", "1234567", "abcdef", "12 456", "-12345"] {
            assert_eq!(verify(RFC_SECRET, bad, now, None), None, "input {bad:?}");
        }
    }

    #[test]
    fn codes_are_zero_padded_to_six_digits() {
        // RFC 6238 T=1111111111 truncates to 050471 -- a leading zero that a
        // naive integer comparison would drop.
        let code = format_code(code_at(RFC_SECRET, current_step(1111111111)));
        assert_eq!(code, "050471");
        assert_eq!(
            verify(RFC_SECRET, "050471", 1111111111, None),
            Some(37037037)
        );
    }

    #[test]
    fn generated_secrets_round_trip_and_differ() {
        let a = generate_secret();
        let b = generate_secret();
        assert_ne!(a, b);
        assert_eq!(decode_secret(&a).unwrap().len(), SECRET_BYTES);
    }

    #[test]
    fn decodes_secrets_as_users_paste_them() {
        let canonical = rfc_secret_base32();
        let spaced = canonical
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" ");

        assert_eq!(decode_secret(&canonical).unwrap(), RFC_SECRET);
        assert_eq!(decode_secret(&spaced).unwrap(), RFC_SECRET);
        assert_eq!(
            decode_secret(&canonical.to_ascii_lowercase()).unwrap(),
            RFC_SECRET
        );
        assert_eq!(
            decode_secret(&format!("{canonical}==")).unwrap(),
            RFC_SECRET
        );
        assert_eq!(decode_secret(""), None);
        assert_eq!(decode_secret("not!base32"), None);
    }

    #[tokio::test]
    async fn replay_guard_accepts_a_step_once() {
        let guard = ReplayGuard::new();

        assert!(guard.try_use("operator", 100).await);
        assert!(!guard.try_use("operator", 100).await);
        assert!(!guard.try_use("operator", 99).await, "older steps rejected");
        assert!(guard.try_use("operator", 101).await);
        assert_eq!(guard.last_step("operator").await, Some(101));
    }

    #[tokio::test]
    async fn replay_guard_is_per_account() {
        let guard = ReplayGuard::new();

        assert!(guard.try_use("operator", 100).await);
        assert!(guard.try_use("someone-else", 100).await);
    }

    #[tokio::test]
    async fn replay_guard_forgets_on_request() {
        let guard = ReplayGuard::new();
        assert!(guard.try_use("operator", 100).await);

        guard.forget("operator").await;

        assert_eq!(guard.last_step("operator").await, None);
        assert!(guard.try_use("operator", 100).await);
    }

    #[test]
    fn otpauth_uri_escapes_the_label() {
        let uri = otpauth_uri("Hardened NanoKVM", "admin@kvm", "ABCD");
        assert!(uri.starts_with("otpauth://totp/Hardened%20NanoKVM:admin%40kvm?"));
        assert!(uri.contains("secret=ABCD"));
        assert!(uri.contains("issuer=Hardened%20NanoKVM"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }
}
