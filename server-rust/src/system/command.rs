use std::{ffi::OsStr, path::PathBuf, process::Stdio, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::oneshot,
    time,
};
use zeroize::Zeroizing;

use crate::{AppError, Result};

const MAX_CAPTURE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub enum AllowedCommand {
    Reboot,
    Mount,
    Umount,
    Hostname,
    Passwd,
    ServiceFirewall,
    ServiceNanokvmRestart,
    ServiceNtp,
    ServiceSshd,
    ServiceSyslogd,
    ServiceKlogd,
    ServiceAvahiDaemon,
    ServiceUsbDev,
    ServiceEth,
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
    OpenSsl,
    Ip,
    IptablesSave,
    Ip6tablesSave,
    Nft,
    Dmesg,
    Date,
    Ntpdate,
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
            AllowedCommand::Mount => OsStr::new("/bin/mount"),
            AllowedCommand::Umount => OsStr::new("/bin/umount"),
            AllowedCommand::Hostname => OsStr::new("hostname"),
            AllowedCommand::Passwd => OsStr::new("passwd"),
            AllowedCommand::ServiceFirewall => OsStr::new("/etc/init.d/S40firewall"),
            AllowedCommand::ServiceNanokvmRestart => OsStr::new("/etc/init.d/S95nanokvm"),
            AllowedCommand::ServiceNtp => OsStr::new("/etc/init.d/S49ntp"),
            AllowedCommand::ServiceSshd => OsStr::new("/etc/init.d/S50sshd"),
            AllowedCommand::ServiceSyslogd => OsStr::new("/etc/init.d/S01syslogd"),
            AllowedCommand::ServiceKlogd => OsStr::new("/etc/init.d/S02klogd"),
            AllowedCommand::ServiceAvahiDaemon => OsStr::new("/etc/init.d/S50avahi-daemon"),
            AllowedCommand::ServiceUsbDev => OsStr::new("/etc/init.d/S03usbdev"),
            AllowedCommand::ServiceEth => OsStr::new("/etc/init.d/S30eth"),
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
            AllowedCommand::OpenSsl => OsStr::new("/usr/bin/openssl"),
            AllowedCommand::Ip => OsStr::new("/usr/sbin/ip"),
            AllowedCommand::IptablesSave => OsStr::new("/usr/sbin/iptables-save"),
            AllowedCommand::Ip6tablesSave => OsStr::new("/usr/sbin/ip6tables-save"),
            AllowedCommand::Nft => OsStr::new("/usr/sbin/nft"),
            AllowedCommand::Dmesg => OsStr::new("dmesg"),
            AllowedCommand::Date => OsStr::new("date"),
            AllowedCommand::Ntpdate => OsStr::new("/usr/bin/ntpdate"),
            AllowedCommand::Pidof => OsStr::new("pidof"),
            AllowedCommand::Kill => OsStr::new("kill"),
            AllowedCommand::CustomForTest(path) => path.as_os_str(),
        }
    }
}

pub async fn run_allowed_with_stdin<I, S>(
    command: AllowedCommand,
    args: I,
    stdin: &[u8],
    timeout: Duration,
) -> Result<CommandOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_allowed_with_stdin_owned(command, args, stdin, timeout, ()).await
}

/// Retains caller-issued work ownership through pipe cleanup and child reap.
/// This is lifetime ownership, not authorization for an arbitrary command.
pub(crate) async fn run_allowed_with_stdin_owned<I, S, G>(
    command: AllowedCommand,
    args: I,
    stdin: &[u8],
    timeout: Duration,
    ownership: G,
) -> Result<CommandOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
    G: Send + 'static,
{
    let mut process = Command::new(command.program());
    process
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    run_captured(
        process,
        Some(Zeroizing::new(stdin.to_vec())),
        timeout,
        ownership,
    )
    .await
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
    run_allowed_owned(command, args, timeout, ()).await
}

/// Owns caller-issued work through capture, cancellation and direct-child reap.
pub(crate) async fn run_allowed_owned<I, S, G>(
    command: AllowedCommand,
    args: I,
    timeout: Duration,
    ownership: G,
) -> Result<CommandOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
    G: Send + 'static,
{
    let mut process = Command::new(command.program());
    process
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    run_captured(process, None, timeout, ownership).await
}

/// A runtime task owns the direct child through cancellation/timeout cleanup.
/// No separate pipe tasks outlive it. A lost receiver signals cancellation; it
/// is not a synchronous join API or a process-tree/quiescence guarantee.
async fn run_captured<G: Send + 'static>(
    mut command: Command,
    input: Option<Zeroizing<Vec<u8>>>,
    timeout: Duration,
    ownership: G,
) -> Result<CommandOutput> {
    let (mut reply, receive) = oneshot::channel();
    tokio::spawn(async move {
        if reply.is_closed() {
            return;
        }
        let result = match command.spawn() {
            Ok(mut child) => {
                drop(command);
                supervise_capture(&mut child, input, timeout, &mut reply).await
            }
            Err(error) => Err(error.into()),
        };
        drop(reply.send(result));
        drop(ownership);
    });
    receive
        .await
        .map_err(|_| AppError::Internal("command owner ended without a result".into()))?
}

async fn supervise_capture(
    child: &mut Child,
    input: Option<Zeroizing<Vec<u8>>>,
    timeout: Duration,
    reply: &mut oneshot::Sender<Result<CommandOutput>>,
) -> Result<CommandOutput> {
    let result = tokio::select! {
        biased;
        _ = reply.closed() => Err(AppError::Internal("command cancelled".into())),
        result = time::timeout(timeout, capture(child, input)) => {
            result.map_err(|_| AppError::Internal("command timed out".into()))
                .and_then(|result| result)
        }
    };
    if result.is_err() {
        stop_and_reap(child).await?;
    }
    result
}

async fn capture(child: &mut Child, input: Option<Zeroizing<Vec<u8>>>) -> Result<CommandOutput> {
    let mut stdout = child.stdout.take().ok_or_else(missing_pipe)?;
    let mut stderr = child.stderr.take().ok_or_else(missing_pipe)?;
    let stdin = child.stdin.take();
    let write_input = async move {
        let result = async move {
            if let Some(input) = input {
                let mut stdin =
                    stdin.ok_or_else(|| std::io::Error::other("command stdin unavailable"))?;
                stdin.write_all(&input).await?;
                stdin.shutdown().await?;
            }
            Ok::<_, std::io::Error>(())
        }
        .await;
        // passwd may exit nonzero before reading input. Preserve its status and
        // stderr; only a successful process makes a stdin failure authoritative.
        Ok::<_, std::io::Error>(result)
    };
    let (status, stdout, stderr, stdin_result) = tokio::try_join!(
        child.wait(),
        read_limited(&mut stdout),
        read_limited(&mut stderr),
        write_input,
    )?;
    if status.success() {
        stdin_result?;
    }
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
    matcher: F,
) -> Result<Option<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
    F: FnMut(&str) -> Option<String> + Send + 'static,
{
    let mut process = Command::new(command.program());
    process
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let (mut reply, receive) = oneshot::channel();
    tokio::spawn(async move {
        if reply.is_closed() {
            return;
        }
        let result = match process.spawn() {
            Ok(mut child) => {
                drop(process);
                let result = tokio::select! {
                    biased;
                    _ = reply.closed() => Err(AppError::Internal("command cancelled".into())),
                    result = time::timeout(timeout, match_stderr(&mut child, matcher)) => {
                        result.map_err(|_| AppError::Internal("command timed out".into()))
                            .and_then(|result| result)
                    }
                };
                // Match intentionally stops the login CLI, not its daemon.
                // No deadline abandons a direct child before wait/reap.
                match stop_and_reap(&mut child).await {
                    Ok(()) => result,
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error.into()),
        };
        drop(reply.send(result));
    });
    receive
        .await
        .map_err(|_| AppError::Internal("command owner ended without a result".into()))?
}

async fn match_stderr<F>(child: &mut Child, mut matcher: F) -> Result<Option<String>>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut stderr = child.stderr.take().ok_or_else(missing_pipe)?;
    let mut line = Vec::with_capacity(MAX_CAPTURE_BYTES);
    let mut chunk = [0; 4096];
    loop {
        let count = stderr.read(&mut chunk).await?;
        for byte in &chunk[..count] {
            if *byte != b'\n' {
                if line.len() == MAX_CAPTURE_BYTES {
                    return Err(AppError::Internal("command stderr line too long".into()));
                }
                line.push(*byte);
                continue;
            }
            if let Some(value) = match_line(&line, &mut matcher)? {
                return Ok(Some(value));
            }
            line.clear();
        }
        if count == 0 {
            if !line.is_empty()
                && let Some(value) = match_line(&line, &mut matcher)?
            {
                return Ok(Some(value));
            }
            child.wait().await?;
            return Ok(None);
        }
    }
}

fn match_line<F>(line: &[u8], matcher: &mut F) -> Result<Option<String>>
where
    F: FnMut(&str) -> Option<String>,
{
    let line = std::str::from_utf8(line)
        .map_err(|_| AppError::Internal("command stderr is not UTF-8".into()))?;
    Ok(matcher(line.strip_suffix('\r').unwrap_or(line)))
}

async fn stop_and_reap(child: &mut Child) -> Result<()> {
    // Even if SIGKILL races normal exit or fails, always attempt wait/reap.
    // No process-group kill: init scripts intentionally daemonize services.
    let kill_result = child.start_kill();
    child.wait().await.map_err(|_| {
        AppError::Internal(if kill_result.is_err() {
            "command kill and reap failed".into()
        } else {
            "command reap failed".into()
        })
    })?;
    Ok(())
}

fn missing_pipe() -> AppError {
    AppError::Internal("command pipe unavailable".into())
}

async fn read_limited<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut out = Vec::with_capacity(MAX_CAPTURE_BYTES);
    let mut chunk = [0_u8; 4096];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if out.len() < MAX_CAPTURE_BYTES {
            let remaining = MAX_CAPTURE_BYTES - out.len();
            out.extend_from_slice(&chunk[..n.min(remaining)]);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod tests;
