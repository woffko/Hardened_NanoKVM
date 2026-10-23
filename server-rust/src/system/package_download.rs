//! HTTPS downloads of optional packages whose exact bytes this source pins.
//! The digest ships inside the signed app. A hash served next to the package
//! comes from the same origin and proves nothing about it.

use sha2::{Digest, Sha256};
use std::{ffi::OsString, fs, io, path::Path, time::Duration};
use tokio::task;

use crate::{
    AppError, Result,
    system::command::{self, AllowedCommand},
};

/// One release file: where it is served, its size and its SHA-256.
pub(crate) struct Pinned {
    pub(crate) url: &'static str,
    pub(crate) size: u64,
    /// Lowercase hex.
    pub(crate) sha256: &'static str,
}

/// Downloads `package` into `target` and keeps the file only when its SHA-256
/// equals the pin. Any failure, including a failed transfer, leaves no file.
pub(crate) async fn fetch(package: &Pinned, target: &Path, timeout: Duration) -> Result<()> {
    let args = curl_args(package, target, timeout);
    match command::run_allowed(AllowedCommand::Curl, args, timeout).await {
        Ok(output) if output.status == 0 => {}
        Ok(output) => {
            let _ = fs::remove_file(target);
            return Err(AppError::Internal(format!(
                "download {} failed (curl exit {}): {}",
                package.url,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Err(err) => {
            let _ = fs::remove_file(target);
            return Err(err);
        }
    }
    let target = target.to_path_buf();
    let expected = package.sha256;
    task::spawn_blocking(move || keep_if_pinned(&target, expected))
        .await
        .map_err(|err| AppError::Internal(format!("package digest task failed: {err}")))?
}

fn curl_args(package: &Pinned, target: &Path, timeout: Duration) -> Vec<OsString> {
    // HTTPS only, also after a redirect, and never more than the pinned size.
    // There is no fallback to another client or transport.
    vec![
        OsString::from("-f"),
        OsString::from("-L"),
        OsString::from("-sS"),
        OsString::from("--proto"),
        OsString::from("=https"),
        OsString::from("--proto-redir"),
        OsString::from("=https"),
        OsString::from("--max-filesize"),
        OsString::from(package.size.to_string()),
        OsString::from("--connect-timeout"),
        OsString::from("20"),
        OsString::from("--max-time"),
        OsString::from(timeout.as_secs().to_string()),
        OsString::from("--output"),
        target.as_os_str().to_os_string(),
        OsString::from(package.url),
    ]
}

fn keep_if_pinned(path: &Path, expected: &str) -> Result<()> {
    match sha256_file(path) {
        Ok(actual) if actual == expected => Ok(()),
        Ok(actual) => {
            let _ = fs::remove_file(path);
            Err(AppError::Internal(format!(
                "downloaded package has SHA-256 {actual}, expected {expected}"
            )))
        }
        Err(err) => {
            let _ = fs::remove_file(path);
            Err(err)
        }
    }
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    io::copy(&mut file, &mut hash)?;
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
#[path = "package_download_tests.rs"]
mod tests;
