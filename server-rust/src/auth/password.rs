use std::{fs, path::PathBuf};

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{AppError, Result, auth::token::random_bytes, fsutil::write_0600_atomic};

pub const LEGACY_DEFAULT_USERNAME: &str = "admin";
pub const LEGACY_DEFAULT_PASSWORD: &str = "admin";

/// Number of single-use recovery codes issued at enrolment.
pub const BACKUP_CODE_COUNT: usize = 9;
/// Characters per backup code. 10 characters over a 32-symbol alphabet is 50
/// bits of entropy.
const BACKUP_CODE_LEN: usize = 10;
/// Crockford-style alphabet with `I`, `O`, `0` and `1` removed so a code read
/// off a screen and typed back cannot be ambiguous. Exactly 32 symbols, which
/// divides 256 evenly and so indexes a random byte without modulo bias.
const BACKUP_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpConfig {
    /// Base32 shared secret.
    pub secret: String,
    /// SHA-256 hashes of the unused backup codes, hex-encoded.
    ///
    /// Deliberately *not* Argon2, unlike the account password. Argon2's cost
    /// exists to make offline brute force of a guessable, human-chosen secret
    /// expensive; these codes are server-generated with 50 bits of entropy, so
    /// plain preimage resistance is already sufficient. The cost matters here:
    /// one Argon2 verification takes seconds on this board, and checking a
    /// backup code has to compare against every remaining hash.
    #[serde(default)]
    pub backup_codes: Vec<String>,
    /// When enrolment was confirmed, for display only.
    #[serde(default)]
    pub enrolled_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<TotpConfig>,
}

#[derive(Debug)]
pub struct AccountStore {
    path: PathBuf,
}

impl AccountStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn load(&self) -> Result<Option<Account>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&self.path)?;
        let account = serde_json::from_str::<Account>(&data)
            .map_err(|err| AppError::Config(format!("invalid account file: {err}")))?;
        Ok(Some(account))
    }

    pub fn set_account(&self, username: &str, password: &str) -> Result<()> {
        validate_username(username)?;
        validate_password(password)?;
        let hash = hash_password(password)?;
        self.write_account(username, &hash)
    }

    pub fn seed_legacy_default_account(&self) -> Result<bool> {
        if self.exists() {
            return Ok(false);
        }
        let hash = hash_password_unchecked(LEGACY_DEFAULT_PASSWORD)?;
        self.write_account(LEGACY_DEFAULT_USERNAME, &hash)?;
        Ok(true)
    }

    fn write_account(&self, username: &str, hash: &str) -> Result<()> {
        // A password change must not silently disable two-factor auth, so
        // carry any existing enrolment across. A rename is treated as a
        // different account and starts clean.
        let totp = self
            .load()?
            .filter(|existing| existing.username == username)
            .and_then(|existing| existing.totp);

        self.store(&Account {
            username: username.to_string(),
            password: hash.to_string(),
            totp,
        })
    }

    fn store(&self, account: &Account) -> Result<()> {
        let data = serde_json::to_vec(account)
            .map_err(|err| AppError::Internal(format!("account serialization failed: {err}")))?;
        write_0600_atomic(&self.path, &data)
    }

    /// The stored account, if the username matches the one on file.
    fn load_matching(&self, username: &str) -> Result<Account> {
        let account = self
            .load()?
            .filter(|account| account.username == username)
            .ok_or_else(|| AppError::BadRequest("unknown account".to_string()))?;
        Ok(account)
    }

    pub fn totp_config(&self, username: &str) -> Result<Option<TotpConfig>> {
        Ok(self
            .load()?
            .filter(|account| account.username == username)
            .and_then(|account| account.totp))
    }

    pub fn totp_enabled(&self, username: &str) -> Result<bool> {
        Ok(self.totp_config(username)?.is_some())
    }

    pub fn set_totp(&self, username: &str, totp: TotpConfig) -> Result<()> {
        let mut account = self.load_matching(username)?;
        account.totp = Some(totp);
        self.store(&account)
    }

    pub fn clear_totp(&self, username: &str) -> Result<()> {
        let mut account = self.load_matching(username)?;
        account.totp = None;
        self.store(&account)
    }

    /// Spend one backup code. Returns false when it does not match any unused
    /// code; on success the code is removed so it cannot be reused.
    pub fn consume_backup_code(&self, username: &str, code: &str) -> Result<bool> {
        let mut account = self.load_matching(username)?;
        let Some(totp) = account.totp.as_mut() else {
            return Ok(false);
        };
        let Some(index) = find_backup_code(&totp.backup_codes, code) else {
            return Ok(false);
        };

        totp.backup_codes.remove(index);
        self.store(&account)?;
        Ok(true)
    }

    pub fn verify(&self, username: &str, password: &str) -> Result<bool> {
        let Some(account) = self.load()? else {
            return Ok(false);
        };
        if account.username != username {
            return Ok(false);
        }
        verify_password(&account.password, password)
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    validate_password(password)?;
    hash_password_unchecked(password)
}

pub fn validate_account_credentials(username: &str, password: &str) -> Result<()> {
    validate_username(username)?;
    validate_password(password)
}

fn hash_password_unchecked(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| AppError::Internal(format!("password hashing failed: {err}")))?;
    Ok(hash.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
    if is_bcrypt_hash(hash) {
        return bcrypt::verify(password, hash)
            .map_err(|err| AppError::Config(format!("invalid bcrypt password hash: {err}")));
    }

    let parsed = PasswordHash::new(hash)
        .map_err(|err| AppError::Config(format!("invalid password hash: {err}")))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

fn is_bcrypt_hash(hash: &str) -> bool {
    matches!(
        hash.as_bytes().get(..4),
        Some(b"$2a$" | b"$2b$" | b"$2x$" | b"$2y$")
    )
}

fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() || username.len() > 64 {
        return Err(AppError::BadRequest("invalid username".to_string()));
    }
    if username.contains(['\'', '"', '\\', '/']) {
        return Err(AppError::BadRequest("invalid username".to_string()));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    if password.len() < 8 || password.len() > 256 {
        return Err(AppError::BadRequest(
            "password must be between 8 and 256 characters".to_string(),
        ));
    }
    Ok(())
}

/// Generate a fresh set of backup codes.
///
/// Returns the codes in the form shown to the user exactly once, paired with
/// the hashes to persist.
pub fn generate_backup_codes() -> (Vec<String>, Vec<String>) {
    let mut plaintext = Vec::with_capacity(BACKUP_CODE_COUNT);
    let mut hashes = Vec::with_capacity(BACKUP_CODE_COUNT);

    for _ in 0..BACKUP_CODE_COUNT {
        let code: String = random_bytes(BACKUP_CODE_LEN)
            .into_iter()
            .map(|byte| BACKUP_CODE_ALPHABET[byte as usize % BACKUP_CODE_ALPHABET.len()] as char)
            .collect();
        hashes.push(hash_backup_code(&code));
        // Grouped for legibility; normalization strips the separator again.
        plaintext.push(format!("{}-{}", &code[..5], &code[5..]));
    }

    (plaintext, hashes)
}

/// Strip formatting so a code matches however the user types it back.
fn normalize_backup_code(code: &str) -> String {
    code.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}

fn hash_backup_code(code: &str) -> String {
    let digest = Sha256::digest(normalize_backup_code(code).as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Index of the stored hash matching `code`, if any.
///
/// Every candidate is compared even after a match so the time taken does not
/// reveal which code was used or how many remain.
fn find_backup_code(hashes: &[String], code: &str) -> Option<usize> {
    let candidate = hash_backup_code(code);
    let mut found = None;
    for (index, stored) in hashes.iter().enumerate() {
        if bool::from(stored.as_bytes().ct_eq(candidate.as_bytes())) {
            found = Some(index);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_hash_verifies() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password(&hash, "correct horse battery staple").unwrap());
        assert!(!verify_password(&hash, "wrong password").unwrap());
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn bcrypt_hash_verifies_for_legacy_go_accounts() {
        let hash = bcrypt::hash("legacy password", 10).unwrap();
        assert!(verify_password(&hash, "legacy password").unwrap());
        assert!(!verify_password(&hash, "wrong password").unwrap());
    }

    fn store_with_account() -> (tempfile::TempDir, AccountStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = AccountStore::new(dir.path().canonicalize().unwrap().join("pwd"));
        store
            .set_account("operator", "correct horse battery")
            .unwrap();
        (dir, store)
    }

    fn totp_with(hashes: Vec<String>) -> TotpConfig {
        TotpConfig {
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            backup_codes: hashes,
            enrolled_at: 1_767_225_600,
        }
    }

    #[test]
    fn account_file_without_totp_still_loads() {
        // The on-disk format predating two-factor support.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("pwd");
        fs::write(
            &path,
            br#"{"username":"admin","password":"$argon2id$v=19$x"}"#,
        )
        .unwrap();

        let account = AccountStore::new(path).load().unwrap().unwrap();
        assert_eq!(account.username, "admin");
        assert!(account.totp.is_none());
    }

    #[test]
    fn enrolment_survives_a_password_change() {
        // Otherwise changing the password would silently drop the second
        // factor, which is the opposite of what the user intends.
        let (_dir, store) = store_with_account();
        store.set_totp("operator", totp_with(vec![])).unwrap();

        store
            .set_account("operator", "a different password")
            .unwrap();

        assert!(store.totp_enabled("operator").unwrap());
        assert!(store.verify("operator", "a different password").unwrap());
    }

    #[test]
    fn renaming_the_account_does_not_inherit_enrolment() {
        let (_dir, store) = store_with_account();
        store.set_totp("operator", totp_with(vec![])).unwrap();

        store
            .set_account("someone-else", "correct horse battery")
            .unwrap();

        assert!(!store.totp_enabled("someone-else").unwrap());
    }

    #[test]
    fn totp_config_is_scoped_to_the_stored_username() {
        let (_dir, store) = store_with_account();
        store.set_totp("operator", totp_with(vec![])).unwrap();

        assert!(store.totp_config("operator").unwrap().is_some());
        assert!(store.totp_config("intruder").unwrap().is_none());
        assert!(store.set_totp("intruder", totp_with(vec![])).is_err());
    }

    #[test]
    fn clearing_totp_leaves_the_password_intact() {
        let (_dir, store) = store_with_account();
        store.set_totp("operator", totp_with(vec![])).unwrap();

        store.clear_totp("operator").unwrap();

        assert!(!store.totp_enabled("operator").unwrap());
        assert!(store.verify("operator", "correct horse battery").unwrap());
    }

    #[test]
    fn backup_codes_are_single_use() {
        let (_dir, store) = store_with_account();
        let (codes, hashes) = generate_backup_codes();
        store.set_totp("operator", totp_with(hashes)).unwrap();

        assert!(store.consume_backup_code("operator", &codes[2]).unwrap());
        assert!(!store.consume_backup_code("operator", &codes[2]).unwrap());
        assert_eq!(
            store
                .totp_config("operator")
                .unwrap()
                .unwrap()
                .backup_codes
                .len(),
            BACKUP_CODE_COUNT - 1
        );
        // The others still work.
        assert!(store.consume_backup_code("operator", &codes[0]).unwrap());
    }

    #[test]
    fn backup_codes_tolerate_how_users_retype_them() {
        let (_dir, store) = store_with_account();
        let (codes, hashes) = generate_backup_codes();
        store.set_totp("operator", totp_with(hashes)).unwrap();

        let typed = codes[1].to_ascii_lowercase().replace('-', " ");
        assert!(store.consume_backup_code("operator", &typed).unwrap());
    }

    #[test]
    fn unknown_backup_codes_are_rejected() {
        let (_dir, store) = store_with_account();
        let (_codes, hashes) = generate_backup_codes();
        store.set_totp("operator", totp_with(hashes)).unwrap();

        for wrong in ["", "AAAAA-AAAAA", "not a code"] {
            assert!(!store.consume_backup_code("operator", wrong).unwrap());
        }
    }

    #[test]
    fn backup_codes_are_not_stored_in_the_clear() {
        let (_dir, store) = store_with_account();
        let (codes, hashes) = generate_backup_codes();
        store.set_totp("operator", totp_with(hashes)).unwrap();

        let on_disk = fs::read_to_string(&store.path).unwrap();
        for code in &codes {
            assert!(!on_disk.contains(code), "{code} leaked to disk");
            assert!(!on_disk.contains(&normalize_backup_code(code)));
        }
    }

    #[test]
    fn generated_backup_codes_are_distinct_and_well_formed() {
        let (codes, hashes) = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        assert_eq!(hashes.len(), BACKUP_CODE_COUNT);

        let unique: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), BACKUP_CODE_COUNT);

        for code in &codes {
            assert_eq!(code.len(), BACKUP_CODE_LEN + 1, "expected grouped {code}");
            assert!(
                normalize_backup_code(code)
                    .bytes()
                    .all(|b| BACKUP_CODE_ALPHABET.contains(&b)),
                "unexpected character in {code}"
            );
        }
    }

    #[test]
    fn consuming_a_backup_code_without_enrolment_is_not_an_error() {
        let (_dir, store) = store_with_account();
        assert!(
            !store
                .consume_backup_code("operator", "AAAAA-AAAAA")
                .unwrap()
        );
    }

    #[test]
    fn legacy_default_seed_allows_admin_admin() {
        let dir = tempfile::tempdir().unwrap();
        let store = AccountStore::new(dir.path().canonicalize().unwrap().join("pwd"));

        assert!(store.seed_legacy_default_account().unwrap());
        assert!(!store.seed_legacy_default_account().unwrap());
        assert!(store.verify("admin", "admin").unwrap());
        assert!(!store.verify("admin", "wrong").unwrap());
    }
}
