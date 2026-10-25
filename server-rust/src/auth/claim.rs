use crate::{AppError, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

const NAME: &str = "first-boot-claim";
const MAX: u64 = 256;
const TTL: Duration = Duration::from_secs(24 * 60 * 60);

pub fn ensure(account_file: &Path) -> Result<Option<String>> {
    let path = path(account_file);
    if account_file.exists() {
        let _ = fs::remove_file(&path);
        return Ok(None);
    }
    if let Some(token) = read(&path)? {
        announce(&token);
        return Ok(Some(token));
    }
    let token = crate::auth::token::random_token(9);
    write(&path, &token)?;
    announce(&token);
    Ok(Some(token))
}

pub fn check(account_file: &Path, supplied: &str) -> Result<()> {
    let token = read(&path(account_file))?
        .ok_or_else(|| AppError::Forbidden("first-boot claim token required".to_string()))?;
    if token.as_bytes() != supplied.as_bytes() {
        return Err(AppError::Forbidden(
            "invalid first-boot claim token".to_string(),
        ));
    }
    Ok(())
}

pub fn consume(account_file: &Path) -> Result<()> {
    let path = path(account_file);
    match fs::remove_file(&path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn path(account_file: &Path) -> PathBuf {
    account_file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("/etc/kvm"))
        .join(NAME)
}

fn read(path: &Path) -> Result<Option<String>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > MAX
    {
        return Err(AppError::Config(
            "first-boot claim state is not private".to_string(),
        ));
    }
    let modified = metadata
        .modified()
        .map_err(|_| AppError::Config("first-boot claim state has no timestamp".to_string()))?;
    if SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age > TTL)
    {
        let _ = fs::remove_file(path);
        return Ok(None);
    }
    let token = fs::read_to_string(path)?;
    let token = token.trim();
    if token.len() < 8
        || token.len() > 64
        || token
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    {
        return Err(AppError::Config(
            "first-boot claim state is malformed".to_string(),
        ));
    }
    Ok(Some(token.to_string()))
}

fn write(path: &Path, token: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(token.as_bytes())?;
    file.write_all(b"\n")?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn announce(token: &str) {
    if let Ok(mut kmsg) = OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = writeln!(kmsg, "NanoKVM first-boot claim token: {token}");
    }
}

#[cfg(test)]
#[path = "claim_tests.rs"]
mod tests;
