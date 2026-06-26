use std::{ffi::OsStr, path::PathBuf, process::Stdio, time::Duration};

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
    time,
};

use crate::{AppError, Result};

const MAX_CAPTURE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub enum AllowedCommand {
    Reboot,
    Hostname,
    ServiceNanokvmRestart,
    ServiceSshd,
    ServiceAvahiDaemon,
    ServiceUsbDev,
    ServiceWifi,
    ServiceTailscaled,
    ServicePicoclawEtc,
    ServicePicoclawKvmapp,
    EtherWake,
    Fallocate,
    Mkswap,
    Swapon,
    Swapoff,
    Tailscale,
    Tailscaled,
    Curl,
    Wget,
    Pidof,
    Kill,
    CustomForTest(PathBuf),
}

#[derive(Debug)]
pub struct CommandOutput {
    pub status: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl AllowedCommand {
    fn program(&self) -> &OsStr {
        match self {
            AllowedCommand::Reboot => OsStr::new("reboot"),
            AllowedCommand::Hostname => OsStr::new("hostname"),
            AllowedCommand::ServiceNanokvmRestart => OsStr::new("/etc/init.d/S95nanokvm"),
            AllowedCommand::ServiceSshd => OsStr::new("/etc/init.d/S50sshd"),
            AllowedCommand::ServiceAvahiDaemon => OsStr::new("/etc/init.d/S50avahi-daemon"),
            AllowedCommand::ServiceUsbDev => OsStr::new("/etc/init.d/S03usbdev"),
            AllowedCommand::ServiceWifi => OsStr::new("/etc/init.d/S30wifi"),
            AllowedCommand::ServiceTailscaled => OsStr::new("/etc/init.d/S98tailscaled"),
            AllowedCommand::ServicePicoclawEtc => OsStr::new("/etc/init.d/S96picoclaw"),
            AllowedCommand::ServicePicoclawKvmapp => {
                OsStr::new("/kvmapp/system/init.d/S96picoclaw")
            }
            AllowedCommand::EtherWake => OsStr::new("ether-wake"),
            AllowedCommand::Fallocate => OsStr::new("fallocate"),
            AllowedCommand::Mkswap => OsStr::new("mkswap"),
            AllowedCommand::Swapon => OsStr::new("swapon"),
            AllowedCommand::Swapoff => OsStr::new("swapoff"),
            AllowedCommand::Tailscale => OsStr::new("/usr/bin/tailscale"),
            AllowedCommand::Tailscaled => OsStr::new("/usr/sbin/tailscaled"),
            AllowedCommand::Curl => OsStr::new("/usr/bin/curl"),
            AllowedCommand::Wget => OsStr::new("/usr/bin/wget"),
            AllowedCommand::Pidof => OsStr::new("pidof"),
            AllowedCommand::Kill => OsStr::new("kill"),
            AllowedCommand::CustomForTest(path) => path.as_os_str(),
        }
    }
}

pub async fn run_allowed<I, S>(
    command: AllowedCommand,
    args: I,
    timeout: Duration,
) -> Result<CommandOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut child = Command::new(command.program())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");

    let stdout_task = tokio::spawn(async move { read_limited(&mut stdout).await });
    let stderr_task = tokio::spawn(async move { read_limited(&mut stderr).await });
    let status = time::timeout(timeout, child.wait())
        .await
        .map_err(|_| AppError::Internal("command timed out".to_string()))??;

    let stdout = stdout_task
        .await
        .map_err(|err| AppError::Internal(format!("stdout task failed: {err}")))??;
    let stderr = stderr_task
        .await
        .map_err(|err| AppError::Internal(format!("stderr task failed: {err}")))??;

    Ok(CommandOutput {
        status: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

pub async fn read_allowed_stderr_until<I, S, F>(
    command: AllowedCommand,
    args: I,
    timeout: Duration,
    mut matcher: F,
) -> Result<Option<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
    F: FnMut(&str) -> Option<String>,
{
    let mut child = Command::new(command.program())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    let stderr = child.stderr.take().expect("stderr piped");
    let mut lines = BufReader::new(stderr).lines();

    let matched = time::timeout(timeout, async {
        while let Some(line) = lines.next_line().await? {
            if let Some(value) = matcher(&line) {
                return Ok::<_, std::io::Error>(Some(value));
            }
        }
        Ok(None)
    })
    .await
    .map_err(|_| AppError::Internal("command timed out".to_string()))??;

    if matched.is_some() {
        let _ = child.kill().await;
    }
    let _ = time::timeout(Duration::from_secs(1), child.wait()).await;

    Ok(matched)
}

async fn read_limited<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(out.len());
        if remaining == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n.min(remaining)]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_allowlisted_command_with_argv() {
        let out = run_allowed(
            AllowedCommand::CustomForTest(PathBuf::from("/bin/echo")),
            ["hello"],
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(out.status, 0);
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hello\n");
    }
}
