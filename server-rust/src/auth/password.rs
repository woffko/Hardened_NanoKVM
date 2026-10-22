use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use serde::{Deserialize, Serialize};

use crate::{AppError, Result, update::state_writers::AccountPermit};

pub const LEGACY_DEFAULT_USERNAME: &str = "admin";
pub const LEGACY_DEFAULT_PASSWORD: &str = "admin";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub username: String,
    pub password: String,
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

    pub(crate) fn set_account(
        &self,
        _permit: &AccountPermit,
        username: &str,
        password: &str,
    ) -> Result<()> {
        validate_username(username)?;
        validate_password(password)?;
        let hash = hash_password(password)?;
        self.write_account(username, &hash)
    }

    pub(crate) fn seed_legacy_default_account(&self, _permit: &AccountPermit) -> Result<bool> {
        if self.exists() {
            return Ok(false);
        }
        let hash = hash_password_unchecked(LEGACY_DEFAULT_PASSWORD)?;
        self.write_account(LEGACY_DEFAULT_USERNAME, &hash)?;
        Ok(true)
    }

    fn write_account(&self, username: &str, hash: &str) -> Result<()> {
        let account = Account {
            username: username.to_string(),
            password: hash.to_string(),
        };
        let data = serde_json::to_vec(&account)
            .map_err(|err| AppError::Internal(format!("account serialization failed: {err}")))?;
        write_account_0600(&self.path, &data)
    }

    /// The stored hash is checked even for a wrong username, so the reply
    /// time does not reveal whether the username exists.
    pub fn verify(&self, username: &str, password: &str) -> Result<bool> {
        let Some(account) = self.load()? else {
            return Ok(false);
        };
        let password_matches = verify_password(&account.password, password)?;
        Ok(password_matches && account.username == username)
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
    if username.contains(['\'', '"', '\\', '/']) || username.chars().any(char::is_control) {
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
    if password.contains(['\0', '\r', '\n']) {
        return Err(AppError::BadRequest(
            "password must not contain NUL, CR, or LF".to_string(),
        ));
    }
    Ok(())
}

fn write_account_0600(path: &PathBuf, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_preflight_rejects_password_protocol_delimiters_after_decoding() {
        let encoded = [
            "synthetic%0Apassword",
            "synthetic%0Dpassword",
            "synthetic%00password",
            "synthetic%0D%0Apassword",
        ];
        let rejected = encoded
            .iter()
            .filter(|value| {
                let password = crate::auth::compat_crypto::decode_frontend_password(value).unwrap();
                matches!(
                    validate_account_credentials("operator", &password),
                    Err(AppError::BadRequest(_))
                )
            })
            .count();
        assert_eq!(rejected, encoded.len());
    }

    #[test]
    fn credential_preflight_rejects_username_control_characters() {
        let controls = ['\0', '\n', '\r', '\t', '\x1b', '\x7f', '\u{85}'];
        let rejected = controls
            .iter()
            .filter(|control| {
                let username = format!("oper{control}ator");
                matches!(
                    validate_account_credentials(&username, "synthetic password"),
                    Err(AppError::BadRequest(_))
                )
            })
            .count();
        assert_eq!(rejected, controls.len());
    }

    #[test]
    fn credential_preflight_preserves_supported_passwords_and_byte_limits() {
        for username in ["operator", "оператор", "操作员"] {
            for password in [
                "synthetic password with spaces",
                r#"synthetic "quotes" 'spaces' \ ;$()&| password"#,
                "синтетический пароль",
                "synthetic\tpassword",
            ] {
                validate_account_credentials(username, password).unwrap();
            }
        }
        validate_account_credentials(&"a".repeat(64), &"é".repeat(128)).unwrap();
        for (username, password) in [
            ("".to_string(), "synthetic password".to_string()),
            ("a".repeat(65), "synthetic password".to_string()),
            ("operator".to_string(), "a".repeat(7)),
            ("operator".to_string(), "é".repeat(129)),
        ] {
            assert!(validate_account_credentials(&username, &password).is_err());
        }
    }

    #[test]
    fn credential_preflight_does_not_reject_existing_legacy_password_verification() {
        let dir = tempfile::tempdir().unwrap();
        let store = AccountStore::new(dir.path().join("pwd"));
        let password = "synthetic\nlegacy password";
        let hash = hash_password_unchecked(password).unwrap();
        store.write_account("operator", &hash).unwrap();
        assert!(store.verify("operator", password).unwrap());
        assert!(
            !store
                .verify("operator", "synthetic wrong password")
                .unwrap()
        );
    }

    #[test]
    fn a_wrong_username_still_costs_a_full_verification() {
        let dir = tempfile::tempdir().unwrap();
        let store = AccountStore::new(dir.path().join("pwd"));
        let hash = hash_password_unchecked("synthetic right password").unwrap();
        store.write_account("operator", &hash).unwrap();
        assert!(
            store
                .verify("operator", "synthetic right password")
                .unwrap()
        );
        assert!(
            !store
                .verify("intruder", "synthetic right password")
                .unwrap()
        );
        assert!(
            !store
                .verify("operator", "synthetic wrong password")
                .unwrap()
        );
        // An unusable stored hash fails for any username: the hash is always
        // read and verified, never skipped after a username mismatch.
        store
            .write_account("operator", "not-a-password-hash")
            .unwrap();
        assert!(
            store
                .verify("intruder", "synthetic right password")
                .is_err()
        );
    }

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

    #[test]
    fn legacy_default_seed_allows_admin_admin() {
        let dir = tempfile::tempdir().unwrap();
        let store = AccountStore::new(dir.path().join("pwd"));

        let writers = crate::update::state_writers::StateWriters::for_test_parent(
            std::fs::File::open(dir.path()).unwrap(),
        );
        let permit = writers.account().unwrap();
        assert!(store.seed_legacy_default_account(&permit).unwrap());
        assert!(!store.seed_legacy_default_account(&permit).unwrap());
        assert!(store.verify("admin", "admin").unwrap());
        assert!(!store.verify("admin", "wrong").unwrap());
    }
}
