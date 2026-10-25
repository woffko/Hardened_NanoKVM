//! Blocking, owned SSH preflight supervisor, never raw-write authorization.
//!
//! Run on the transaction's dedicated blocking owner, retaining its lock and
//! writer quiescence. Dropping a spawn_blocking JoinHandle is NOT cancellation:
//! signal the supplied AtomicBool and join that owner. No detached tasks here.

use super::{
    raw_transport::{TransferContext, channel},
    restore_accounts::{self, SignedAccounts},
    restore_effective::{self, RootContext, RootEffectivePolicy},
    restore_key::{KeyOperation, KeyStage, MAX_PUBLIC, parse_public},
    restore_preflight::PreparedSshRoot,
};
use rand_core::{OsRng, RngCore};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[path = "restore_job_helper.rs"]
mod helper;
pub use helper::PinnedSshHelper;

const DEADLINE: Duration = Duration::from_secs(15);
const CANCEL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("SSH preflight helper does not match the trusted static runtime")]
    Helper,
    #[error("SSH preflight process or descriptor I/O failed")]
    Process,
    #[error("SSH preflight was cancelled")]
    Cancelled,
    #[error("SSH preflight exceeded its wall deadline")]
    Timeout,
    #[error("SSH preflight failed native validation or private output policy")]
    Native,
    #[error("SSH preflight private staging cleanup failed")]
    Cleanup,
}
type Result<T> = std::result::Result<T, JobError>;

pub enum Check {
    Syntax,
    Effective(RootContext),
    HostKeys,
}

// No Debug/serde/raw output. Neither outcome grants an install/restore ticket.
pub enum Outcome {
    Syntax,
    Effective(RootEffectivePolicy),
    HostKeys(HostKeyProof),
}

/// Count only, not raw public keys/signatures or a restore authorization.
pub struct HostKeyProof {
    count: u8,
}
impl HostKeyProof {
    pub fn keys_checked(&self) -> u8 {
        self.count
    }
}

enum Request<'a> {
    Syntax,
    Effective(&'a RootContext),
    Key(KeyOperation),
}
impl Request<'_> {
    fn append(&self, command: &mut Command) {
        match self {
            Self::Syntax => {}
            Self::Effective(context) => {
                command.arg("--effective-root").arg(context.as_argument());
            }
            Self::Key(operation) => {
                command.arg("--host-key-proof").arg(operation.as_argument());
            }
        }
    }
    fn output_limit(&self) -> usize {
        match self {
            Self::Syntax => 0,
            Self::Effective(_) => restore_effective::MAX_OUTPUT,
            Self::Key(operation) if operation.stage == KeyStage::Verify => 0,
            Self::Key(_) => MAX_PUBLIC,
        }
    }
}

enum Backend<'a> {
    Image {
        helper: &'a PinnedSshHelper,
        images: &'a [File; 2],
        transfer: &'a TransferContext,
        mountpoint: &'a Path,
    },
    #[cfg(feature = "sandbox-test-fixture")]
    Fixture { helper: &'a Path, image: &'a Path },
}
impl Backend<'_> {
    fn run(
        &self,
        identity: &mut PreparedSshRoot,
        request: Request<'_>,
        cancel: &AtomicBool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        cancelled(cancel)?;
        identity
            .check_runtime_slots_before_child()
            .map_err(|_| JobError::Cleanup)?;
        let root = identity.checked_path().map_err(|_| JobError::Process)?;
        let mut command = match self {
            Self::Image {
                helper,
                images,
                transfer,
                mountpoint,
            } => {
                let (sender, receiver) = channel().map_err(|_| JobError::Process)?;
                // Only readonly CLOEXEC aliases cross each one-shot pair;
                // originals stay owned for subsequent proof stages.
                sender
                    .send(
                        transfer,
                        [
                            images[0].try_clone().map_err(|_| JobError::Process)?,
                            images[1].try_clone().map_err(|_| JobError::Process)?,
                        ],
                    )
                    .map_err(|_| JobError::Process)?;
                cancelled(cancel)?;
                let mut command = helper.command()?;
                command
                    .arg("--root")
                    .arg(root)
                    .arg("--parent-pid")
                    .arg(std::process::id().to_string())
                    .arg("--image-root")
                    .arg(mountpoint);
                transfer.append_helper_arguments(&mut command);
                command.stdin(receiver.into_stdio());
                command
            }
            #[cfg(feature = "sandbox-test-fixture")]
            Self::Fixture { helper, image } => {
                // Explicit host-only signed-image/helper-provenance bypass.
                let mut command = Command::new(helper);
                command
                    .arg(root)
                    .arg(image)
                    .arg(std::process::id().to_string())
                    .env_clear()
                    .stdin(Stdio::null());
                command
            }
        };
        request.append(&mut command);
        let result = supervise(command, cancel, DEADLINE, request.output_limit());
        // Namespace teardown removes mounts, not placeholder inodes. Record
        // only fixed empty slots AFTER reap, including partial mount failure.
        identity
            .record_runtime_slots()
            .map_err(|_| JobError::Cleanup)?;
        result
    }
}

/// Consumes identity staging and both already authenticated readonly snapshots.
/// Context/hash/modes do NOT verify their signatures or authorize partition I/O.
/// The caller must protect the outer directories and own the common lock.
pub struct SshPreflightJob<'a> {
    pub helper: &'a PinnedSshHelper,
    pub identity: PreparedSshRoot,
    pub images: [File; 2],
    pub transfer: TransferContext,
    pub image_mountpoint: PathBuf,
    pub check: Check,
}

impl SshPreflightJob<'_> {
    /// Synchronous by design: cancellation is a signal, not dropping a future.
    /// Child ownership never escapes; kill/reap precedes checked cleanup on
    /// success/error and best-effort root Drop on unwind. Uninterruptible kernel I/O can delay reap;
    /// never abandon ownership/cleanup early to manufacture a finite timeout.
    pub fn run(self, cancel: &AtomicBool) -> Result<Outcome> {
        let Self {
            helper,
            mut identity,
            images,
            transfer,
            image_mountpoint,
            check,
        } = self;
        let backend = Backend::Image {
            helper,
            images: &images,
            transfer: &transfer,
            mountpoint: &image_mountpoint,
        };
        let result = execute(&backend, &mut identity, check, cancel);
        // supervise's guard has already reaped, including every error path.
        // Cleanup failure wins: never return a successful proof with residue.
        identity.cleanup().map_err(|_| JobError::Cleanup)?;
        cancelled(cancel)?;
        result
    }
}

/// Reads the account tables of the authenticated ROOTFS image through the
/// pinned sandbox, which mounts it read-only in its own namespaces and runs
/// nothing from it. The tables feed `capture_effective`; this proves neither
/// the image nor a restore authorization. `image_mountpoint` must be an empty
/// private directory; the images are lent as read-only aliases.
pub fn export_signed_accounts(
    helper: &PinnedSshHelper,
    images: &[File; 2],
    transfer: &TransferContext,
    image_mountpoint: &Path,
    cancel: &AtomicBool,
) -> Result<SignedAccounts> {
    cancelled(cancel)?;
    let (sender, receiver) = channel().map_err(|_| JobError::Process)?;
    sender
        .send(
            transfer,
            [
                images[0].try_clone().map_err(|_| JobError::Process)?,
                images[1].try_clone().map_err(|_| JobError::Process)?,
            ],
        )
        .map_err(|_| JobError::Process)?;
    cancelled(cancel)?;
    let mut command = helper.command()?;
    command
        .arg("--export-accounts")
        .arg("--parent-pid")
        .arg(std::process::id().to_string())
        .arg("--image-root")
        .arg(image_mountpoint);
    transfer.append_helper_arguments(&mut command);
    command.stdin(receiver.into_stdio());
    collect_accounts(command, cancel)
}

fn collect_accounts(command: Command, cancel: &AtomicBool) -> Result<SignedAccounts> {
    let encoded = supervise(command, cancel, DEADLINE, restore_accounts::MAX_ENCODED)?;
    restore_accounts::decode(&encoded).map_err(|_| JobError::Native)
}

fn execute(
    backend: &Backend<'_>,
    identity: &mut PreparedSshRoot,
    check: Check,
    cancel: &AtomicBool,
) -> Result<Outcome> {
    cancelled(cancel)?;
    match check {
        Check::Syntax => {
            backend.run(identity, Request::Syntax, cancel)?;
            Ok(Outcome::Syntax)
        }
        Check::Effective(context) => {
            let raw = backend.run(identity, Request::Effective(&context), cancel)?;
            restore_effective::read_policy(&mut &raw[..], &context)
                .map(Outcome::Effective)
                .map_err(|_| JobError::Native)
        }
        Check::HostKeys => {
            let keys = identity.host_keys();
            let mut challenge = [0; 32];
            OsRng
                .try_fill_bytes(&mut challenge)
                .map_err(|_| JobError::Process)?;
            identity
                .stage_challenge(&challenge)
                .map_err(|_| JobError::Process)?;
            for &key in &keys {
                let public = backend.run(
                    identity,
                    Request::Key(KeyOperation {
                        key,
                        stage: KeyStage::Public,
                    }),
                    cancel,
                )?;
                let public = parse_public(&public, key).map_err(|_| JobError::Native)?;
                if let Some(companion) = identity
                    .public_companion(key)
                    .map_err(|_| JobError::Native)?
                {
                    let companion = parse_public(&companion, key).map_err(|_| JobError::Native)?;
                    if public.kind != companion.kind || public.blob != companion.blob {
                        return Err(JobError::Native);
                    }
                }
                let signature = backend.run(
                    identity,
                    Request::Key(KeyOperation {
                        key,
                        stage: KeyStage::Sign,
                    }),
                    cancel,
                )?;
                identity
                    .stage_key_proof(key, &signature, public.allowed_signers().as_bytes())
                    .map_err(|_| JobError::Process)?;
                backend.run(
                    identity,
                    Request::Key(KeyOperation {
                        key,
                        stage: KeyStage::Verify,
                    }),
                    cancel,
                )?;
            }
            Ok(Outcome::HostKeys(HostKeyProof {
                count: keys.len() as u8,
            }))
        }
    }
}

#[doc(hidden)]
#[cfg(feature = "sandbox-test-fixture")]
pub fn run_host_ssh_job_fixture(
    mut identity: PreparedSshRoot,
    helper: &Path,
    image: &Path,
    check: Check,
    cancel: &AtomicBool,
) -> Result<Outcome> {
    let backend = Backend::Fixture { helper, image };
    let result = execute(&backend, &mut identity, check, cancel);
    identity.cleanup().map_err(|_| JobError::Cleanup)?;
    cancelled(cancel)?;
    result
}

fn cancelled(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::SeqCst) {
        Err(JobError::Cancelled)
    } else {
        Ok(())
    }
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // wait caches a previously collected status. Even if kill fails, do
        // not release the caller's identity root while the direct child lives.
        let _ = self.0.kill();
        loop {
            match self.0.wait() {
                Ok(_) => break,
                // A collected child is no longer a reader of the identity.
                Err(e) if e.raw_os_error() == Some(nix::libc::ECHILD) => break,
                Err(_) => std::thread::sleep(CANCEL_INTERVAL),
            }
        }
    }
}

fn supervise(
    mut command: Command,
    cancel: &AtomicBool,
    deadline: Duration,
    output_limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let started = Instant::now();
    cancelled(cancel)?;
    command.stdout(Stdio::piped()).stderr(Stdio::inherit());
    let child = OwnedChild(command.spawn().map_err(|_| JobError::Process)?);
    // Crucial: Command can own stdin/other aliases even after successful spawn.
    drop(command);
    collect(child, cancel, started, deadline, output_limit)
}

fn collect(
    mut child: OwnedChild,
    cancel: &AtomicBool,
    started: Instant,
    deadline: Duration,
    output_limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut stdout = child.0.stdout.take().ok_or(JobError::Process)?;
    let flags = fcntl_getfl(&stdout).map_err(|_| JobError::Process)?;
    fcntl_setfl(&stdout, flags | OFlags::NONBLOCK).map_err(|_| JobError::Process)?;
    let mut output = Zeroizing::new(Vec::with_capacity(output_limit));
    let mut chunk = Zeroizing::new([0; 4096]);
    let mut eof = false;
    let mut status: Option<ExitStatus> = None;
    loop {
        cancelled(cancel)?;
        if started.elapsed() >= deadline {
            return Err(JobError::Timeout);
        }
        if !eof {
            // At most one bounded read before rechecking cancellation/time.
            match stdout.read(&mut *chunk) {
                Ok(0) => eof = true,
                Ok(n) => {
                    if n > output_limit - output.len() {
                        return Err(JobError::Native);
                    }
                    output.extend_from_slice(&chunk[..n]);
                    // Drain an already full pipe without a 20-ms delay per
                    // chunk, while still checking wall time on every iteration.
                    continue;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(JobError::Process),
            }
        }
        if status.is_none() {
            status = child.0.try_wait().map_err(|_| JobError::Process)?;
        }
        if let Some(status) = status {
            if !status.success() {
                return Err(JobError::Native);
            }
            if eof {
                return Ok(output);
            }
        }
        let wait = CANCEL_INTERVAL.min(deadline.saturating_sub(started.elapsed()));
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: wait.as_nanos() as _,
        };
        // No stdout after EOF: an empty poll sleeps rather than spinning on HUP.
        let mut descriptors = [PollFd::new(&stdout, PollFlags::IN)];
        let descriptors = if eof {
            &mut [][..]
        } else {
            &mut descriptors[..]
        };
        match poll(descriptors, Some(&timeout)) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(JobError::Process),
        }
    }
}

#[cfg(test)]
#[path = "restore_job_tests.rs"]
mod tests;
