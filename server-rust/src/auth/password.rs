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

use crate::{AppError, Result};

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
        let account = Account {
            username: username.to_string(),
            password: hash.to_string(),
        };
        let data = serde_json::to_vec(&account)
            .map_err(|err| AppError::Internal(format!("account serialization failed: {err}")))?;
        write_account_0600(&self.path, &data)
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

        assert!(store.seed_legacy_default_account().unwrap());
        assert!(!store.seed_legacy_default_account().unwrap());
        assert!(store.verify("admin", "admin").unwrap());
        assert!(!store.verify("admin", "wrong").unwrap());
    }
}
