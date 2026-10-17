//! Blocking, owned SSH preflight supervisor, never raw-write authorization.
//!
//! Run on the transaction's dedicated blocking owner, retaining its lock and
//! writer quiescence. Dropping a spawn_blocking JoinHandle is NOT cancellation:
//! signal the supplied AtomicBool and join that owner. No detached tasks here.

use super::{
    raw_transport::{TransferContext, channel},
    restore_effective::{self, RootContext, RootEffectivePolicy},
    restore_preflight::PreparedSshRoot,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
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
}

// No Debug/serde/raw output. Neither outcome grants an install/restore ticket.
pub enum Outcome {
    Syntax,
    Effective(RootEffectivePolicy),
}

/// Consumes identity staging and both already authenticated readonly snapshots.
/// Context/hash/modes do NOT verify their signatures or authorize partition I/O.
/// The caller must protect the outer directories and own the common lock.
pub struct SshPreflightJob {
    pub helper: PinnedSshHelper,
    pub identity: PreparedSshRoot,
    pub images: [File; 2],
    pub transfer: TransferContext,
    pub image_mountpoint: PathBuf,
    pub check: Check,
}

impl SshPreflightJob {
    /// Synchronous by design: cancellation is a signal, not dropping a future.
    /// Child ownership never escapes; kill/reap precedes checked cleanup on
    /// success/error and best-effort root Drop on unwind. Uninterruptible kernel I/O can delay reap;
    /// never abandon ownership/cleanup early to manufacture a finite timeout.
    pub fn run(self, cancel: &AtomicBool) -> Result<Outcome> {
        let Self {
            helper,
            identity,
            images,
            transfer,
            image_mountpoint,
            check,
        } = self;
        let result = (|| {
            cancelled(cancel)?;
            let root = identity.checked_path().map_err(|_| JobError::Process)?;
            let (sender, receiver) = channel().map_err(|_| JobError::Process)?;
            // One small packet fits the fresh socket. Queue before fork so no
            // blocking transport task or writable/sender alias can outlive us.
            // Successful send is NOT child acceptance. Failed spawn drops the
            // Command's receiver and therefore queued descriptor references.
            sender
                .send(&transfer, images)
                .map_err(|_| JobError::Process)?;
            cancelled(cancel)?;
            let mut command = helper.command()?;
            command
                .arg("--root")
                .arg(root)
                .arg("--parent-pid")
                .arg(std::process::id().to_string())
                .arg("--image-root")
                .arg(&image_mountpoint);
            transfer.append_helper_arguments(&mut command);
            if let Check::Effective(context) = &check {
                command.arg("--effective-root").arg(context.as_argument());
            }
            command.stdin(receiver.into_stdio());
            let raw = supervise(
                command,
                cancel,
                DEADLINE,
                matches!(check, Check::Effective(_)),
            )?;
            // Exact pinned helper stays owned until native exit + EOF. The
            // readonly image view has then died with the fresh child namespace.
            match check {
                Check::Syntax => Ok(Outcome::Syntax),
                Check::Effective(context) => {
                    restore_effective::read_policy(&mut &raw[..], &context)
                        .map(Outcome::Effective)
                        .map_err(|_| JobError::Native)
                }
            }
        })();
        // supervise's guard has already reaped, including every error path.
        // Cleanup failure wins: never return a successful proof with residue.
        identity.cleanup().map_err(|_| JobError::Cleanup)?;
        cancelled(cancel)?;
        result
    }
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
    effective: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let started = Instant::now();
    cancelled(cancel)?;
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let child = OwnedChild(command.spawn().map_err(|_| JobError::Process)?);
    // Crucial: Command can own stdin/other aliases even after successful spawn.
    drop(command);
    collect(child, cancel, started, deadline, effective)
}

fn collect(
    mut child: OwnedChild,
    cancel: &AtomicBool,
    started: Instant,
    deadline: Duration,
    effective: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut stdout = child.0.stdout.take().ok_or(JobError::Process)?;
    let flags = fcntl_getfl(&stdout).map_err(|_| JobError::Process)?;
    fcntl_setfl(&stdout, flags | OFlags::NONBLOCK).map_err(|_| JobError::Process)?;
    let mut output = Zeroizing::new(Vec::with_capacity(if effective {
        restore_effective::MAX_OUTPUT
    } else {
        0
    }));
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
                    if !effective || n > restore_effective::MAX_OUTPUT - output.len() {
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
