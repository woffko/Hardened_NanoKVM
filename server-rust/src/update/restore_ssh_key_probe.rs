//! Host-native possession diagnostic through parent proc-fds, not the isolated
//! signed-image target gate. Production preflight uses restore_job HostKeys.
//! No configured helper, agent, shell or provider is invoked here.

use super::{Result, SshRestoreError};
use crate::update::restore_capsule::create_private_spool;
pub(super) use crate::update::restore_key::MAX_PUBLIC;
use crate::update::restore_key::{HostKey as Algorithm, NAMESPACE, PRINCIPAL, parse_public};
#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand_core::{OsRng, RngCore};
use std::{fs::File, io::Write, os::fd::AsRawFd, path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::timeout,
};
use zeroize::Zeroizing;

const DEADLINE: Duration = Duration::from_secs(8);
const REAP_DEADLINE: Duration = Duration::from_secs(2);

pub(super) async fn check_pair(
    private: &File,
    public: Option<&[u8]>,
    algorithm: Algorithm,
    private_staging: &Path,
) -> Result<()> {
    // These are paths to this live process's anonymous protected descriptors,
    // not key bytes or caller-selected filesystem paths. Each descriptor stays
    // alive until all associated children have finished or been killed.
    let key_path = format!("/proc/{}/fd/{}", std::process::id(), private.as_raw_fd());
    let derived = keygen(&["-y", "-P", "", "-f", &key_path], &[]).await?;
    let identity = parse_public(&derived, algorithm)?;
    if let Some(public) = public {
        let companion = parse_public(public, algorithm)?;
        if companion.kind != identity.kind || companion.blob != identity.blob {
            return Err(SshRestoreError::InvalidKey);
        }
    }
    // -y and sshd -t compare stored public components; neither proves that
    // those components agree mathematically with the secret. Sign + verify
    // through an explicit allowed-signers file proves possession for this key.
    let mut challenge = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut challenge)
        .map_err(|_| SshRestoreError::ProbeRuntime)?;
    let signature = keygen(
        &[
            "-Y", "sign", "-q", "-n", NAMESPACE, "-P", "", "-f", &key_path,
        ],
        &challenge,
    )
    .await?;
    if signature.is_empty() {
        return Err(SshRestoreError::InvalidKey);
    }
    let mut signature_file =
        create_private_spool(private_staging).map_err(|_| SshRestoreError::ProbeRuntime)?;
    signature_file
        .write_all(&signature)
        .map_err(|_| SshRestoreError::ProbeRuntime)?;
    let mut allowed =
        create_private_spool(private_staging).map_err(|_| SshRestoreError::ProbeRuntime)?;
    allowed
        .write_all(identity.allowed_signers().as_bytes())
        .map_err(|_| SshRestoreError::ProbeRuntime)?;
    let signature_path = format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        signature_file.as_raw_fd()
    );
    let allowed_path = format!("/proc/{}/fd/{}", std::process::id(), allowed.as_raw_fd());
    keygen(
        &[
            "-Y",
            "verify",
            "-q",
            "-n",
            NAMESPACE,
            "-I",
            PRINCIPAL,
            "-f",
            &allowed_path,
            "-s",
            &signature_path,
        ],
        &challenge,
    )
    .await?;
    Ok(())
}

async fn keygen(args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut command = Command::new("/usr/bin/ssh-keygen");
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .current_dir("/");
    run_child(command, input, DEADLINE).await
}

async fn run_child(
    mut command: Command,
    input: &[u8],
    deadline: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| SshRestoreError::ProbeRuntime)?;
    let mut stdin = child.stdin.take().ok_or(SshRestoreError::ProbeRuntime)?;
    let mut stdout = child.stdout.take().ok_or(SshRestoreError::ProbeRuntime)?;
    // No detached reader/writer tasks: one timeout covers input, bounded output
    // and process exit, including a child that exits but leaves a pipe open.
    let result = timeout(deadline, async {
        let send = async {
            stdin
                .write_all(input)
                .await
                .map_err(|_| SshRestoreError::ProbeRuntime)?;
            stdin
                .shutdown()
                .await
                .map_err(|_| SshRestoreError::ProbeRuntime)?;
            drop(stdin);
            Ok(())
        };
        let wait = async {
            child
                .wait()
                .await
                .map_err(|_| SshRestoreError::ProbeRuntime)
        };
        let (_, output, status) = tokio::try_join!(send, read_output(&mut stdout), wait)?;
        if !status.success() {
            return Err(SshRestoreError::InvalidKey);
        }
        Ok(output)
    })
    .await
    .unwrap_or(Err(SshRestoreError::ProbeTimeout));
    if result.is_err() {
        let _ = child.start_kill();
        if !matches!(timeout(REAP_DEADLINE, child.wait()).await, Ok(Ok(_))) {
            return Err(SshRestoreError::ProbeRuntime);
        }
    }
    result
}

async fn read_output(reader: &mut (impl AsyncRead + Unpin)) -> Result<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(Vec::with_capacity(MAX_PUBLIC));
    let mut chunk = Zeroizing::new([0_u8; 1024]);
    loop {
        let length = reader
            .read(&mut *chunk)
            .await
            .map_err(|_| SshRestoreError::ProbeRuntime)?;
        if length == 0 {
            return Ok(output);
        }
        if length > MAX_PUBLIC - output.len() {
            return Err(SshRestoreError::Limit);
        }
        output.extend_from_slice(&chunk[..length]);
    }
}

#[cfg(test)]
#[path = "restore_ssh_key_probe_tests.rs"]
mod tests;
