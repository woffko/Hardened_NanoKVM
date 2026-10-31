use crate::{AppError, Result, api::network::constant_time_eq, system::files};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const NAME: &str = "first-boot-claim";
const MAX: u64 = 256;
const TTL_SECONDS: u64 = 24 * 60 * 60;
const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";
const UPTIME: &str = "/proc/uptime";
/// The serial console alone: the kernel log goes on to syslog and to a remote
/// server, and whoever reads either could claim the device. Root reads the token
/// from the file beside the account store.
const CONSOLE: &str = "/dev/console";

/// A device without a real-time clock starts in the past, so the age of a token
/// counts in this boot's uptime and a token ends with its boot.
struct Moment {
    boot: String,
    seconds: u64,
}

fn now() -> Result<Moment> {
    let uptime = fs::read_to_string(UPTIME)?;
    Ok(Moment {
        boot: fs::read_to_string(BOOT_ID)?.trim().to_string(),
        seconds: uptime
            .split('.')
            .next()
            .and_then(|whole| whole.parse().ok())
            .ok_or_else(|| AppError::Config("the system uptime is unreadable".to_string()))?,
    })
}

pub fn ensure(account_file: &Path) -> Result<Option<String>> {
    ensure_at(account_file, &now()?, Path::new(CONSOLE))
}

fn ensure_at(account_file: &Path, now: &Moment, console: &Path) -> Result<Option<String>> {
    let path = path(account_file);
    if account_file.exists() {
        let _ = fs::remove_file(&path);
        return Ok(None);
    }
    // Damaged, unsafe, expired or from an earlier boot, the old file only stands
    // in the way of a device that nobody can set up.
    if let Ok(Some(token)) = read(&path, now) {
        announce(console, &token);
        return Ok(Some(token));
    }
    let token = crate::auth::token::random_token(9);
    let record = format!("{token}\n{} {}\n", now.boot, now.seconds);
    files::write_atomic(&path, record.as_bytes(), 0o600)?;
    announce(console, &token);
    Ok(Some(token))
}

pub fn check(account_file: &Path, supplied: &str) -> Result<()> {
    let token = read(&path(account_file), &now()?)?
        .ok_or_else(|| AppError::Forbidden("first-boot claim token required".to_string()))?;
    if !constant_time_eq(&token, supplied) {
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

fn read(path: &Path, now: &Moment) -> Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
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
    let record = fs::read_to_string(path)?;
    let malformed = || AppError::Config("first-boot claim state is malformed".to_string());
    let (token, issued) = record.split_once('\n').ok_or_else(malformed)?;
    let (boot, seconds) = issued.trim().split_once(' ').ok_or_else(malformed)?;
    let seconds: u64 = seconds.parse().map_err(|_| malformed())?;
    if token.len() < 8
        || token.len() > 64
        || token
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    {
        return Err(malformed());
    }
    if boot != now.boot || now.seconds.saturating_sub(seconds) > TTL_SECONDS {
        return Ok(None);
    }
    Ok(Some(token.to_string()))
}

/// A port that nobody drains must not hold up the start of the backend.
fn announce(console: &Path, token: &str) {
    if let Ok(mut console) = OpenOptions::new()
        .append(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open(console)
    {
        let _ = writeln!(console, "NanoKVM first-boot claim token: {token}");
    }
}

#[cfg(test)]
#[path = "claim_tests.rs"]
mod tests;
