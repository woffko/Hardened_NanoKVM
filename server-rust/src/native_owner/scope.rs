//! Dedicated, single-threaded process only. Never include in the async backend.
//! Owns one fresh trusted process tree, not arbitrary existing device services.

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::{Errno, FdFlags, fcntl_setfd},
    process::{
        Pid, PidfdFlags, Signal, WaitId, WaitIdOptions, WaitOptions, child_subreaper, getpid,
        pidfd_open, wait, waitid,
    },
};
use std::{
    fs,
    io::{Read, Write},
    os::fd::{AsFd, AsRawFd},
    os::unix::net::UnixStream,
    process::Command,
    time::{Duration, Instant},
};

#[path = "../system/proc_tree.rs"]
mod proc_tree;
#[path = "scope_trial.rs"]
mod trial;
pub use crate::app_trial_wire as trial_wire;

const STEP: Duration = Duration::from_millis(20);
const GRACE: Duration = Duration::from_secs(2);
const CHILD_BATCH: usize = 4096;
// Linux __WALL includes clone children whose exit signal is not SIGCHLD.
const REAP: WaitOptions =
    WaitOptions::NOHANG.union(WaitOptions::from_bits_retain(nix::libc::__WALL as u32));
const PEEK: WaitIdOptions = WaitIdOptions::EXITED
    .union(WaitIdOptions::NOHANG)
    .union(WaitIdOptions::NOWAIT)
    .union(WaitIdOptions::from_bits_retain(nix::libc::__WALL as u32));

#[derive(Debug)]
pub(super) enum Error {
    Process,
    Control,
    Setup,
    Spawn,
    Runtime,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Stopped,
    Exited(bool),
}

fn initialize(control: &UnixStream) -> Result<(), Error> {
    if !control
        .local_addr()
        .map_err(|_| Error::Control)?
        .is_unnamed()
        || !control
            .peer_addr()
            .map_err(|_| Error::Control)?
            .is_unnamed()
    {
        return Err(Error::Control);
    }
    control.set_nonblocking(true).map_err(|_| Error::Control)?;
    fcntl_setfd(control, FdFlags::CLOEXEC).map_err(|_| Error::Control)?;
    // No other thread may create children/descriptors or reap these children.
    let mut tasks = 0;
    for entry in fs::read_dir("/proc/self/task").map_err(|_| Error::Process)? {
        entry.map_err(|_| Error::Process)?;
        tasks += 1;
        if tasks > 1 {
            return Err(Error::Process);
        }
    }
    if tasks != 1 {
        return Err(Error::Process);
    }
    let mut descriptors = fs::read_dir("/proc/self/fd").map_err(|_| Error::Process)?;
    let mut standard = [false; 3];
    let mut owned = false;
    let mut other = 0;
    for entry in &mut descriptors {
        let fd = entry
            .map_err(|_| Error::Process)?
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .ok_or(Error::Process)?;
        match fd {
            0..=2 => standard[fd as usize] = true,
            fd if fd == control.as_raw_fd() => owned = true,
            _ => other += 1,
        }
    }
    // Exactly one other descriptor belongs to this live read_dir iterator.
    if standard != [true; 3] || !owned || other != 1 {
        return Err(Error::Process);
    }
    drop(descriptors);
    let status = fs::read_to_string("/proc/self/status").map_err(|_| Error::Process)?;
    for field in ["SigIgn:", "SigCgt:"] {
        let mask = status
            .lines()
            .find_map(|s| s.strip_prefix(field))
            .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
            .ok_or(Error::Process)?;
        if mask & (1 << (nix::libc::SIGCHLD - 1)) != 0 {
            return Err(Error::Process);
        }
    }
    if !matches!(waitid(WaitId::All, PEEK), Err(Errno::CHILD)) {
        return Err(Error::Process);
    }
    // Require actual pidfd and P_PIDFD support before launching any work.
    let own = pidfd_open(getpid(), PidfdFlags::empty()).map_err(|_| Error::Setup)?;
    if !matches!(waitid(WaitId::PidFd(own.as_fd()), PEEK), Err(Errno::CHILD)) {
        return Err(Error::Setup);
    }
    drop(own);
    nix::sys::prctl::set_child_subreaper(true).map_err(|_| Error::Setup)?;
    if child_subreaper().map_err(|_| Error::Setup)?.is_none() {
        return Err(Error::Setup);
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Control {
    Idle,
    Stop,
    Lost,
}

fn control_event(control: &mut UnixStream) -> Result<Control, Error> {
    let mut byte = [0];
    match control.read(&mut byte) {
        Ok(0) => Ok(Control::Lost),
        Ok(_) if byte == *b"S" => Ok(Control::Stop),
        Ok(_) => Err(Error::Control),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(Control::Idle)
        }
        Err(_) => Err(Error::Control),
    }
}

// PID numbers from proc only nominate candidates. The kernel must confirm the
// pidfd names OUR unreaped child before any signal. No PID-file or integer kill.
pub(super) fn signal_child(pid: Pid, signal: Signal) -> Result<(), Error> {
    proc_tree::signal_child(pid, signal).map_err(|_| Error::Runtime)
}

pub(super) fn run(command: Command, control: UnixStream) -> Result<Outcome, Error> {
    run_guarded(command, control, || Some(()))
}

/// Backend loss must not kill an update owned by the still-live backend.
/// Callback obtains fixed update exclusion after controller/leader loss.
/// Explicit Stop has the broker's update permit and durable stopping fence.
pub(super) fn run_guarded<G>(
    command: Command,
    control: UnixStream,
    orphan_admission: impl FnMut() -> Option<G>,
) -> Result<Outcome, Error> {
    run_owned(command, control, orphan_admission, false)
}

pub(super) fn run_trial_guarded<G>(
    command: Command,
    control: UnixStream,
    orphan_admission: impl FnMut() -> Option<G>,
) -> Result<Outcome, Error> {
    run_owned(command, control, orphan_admission, true)
}

fn run_owned<G>(
    mut command: Command,
    mut control: UnixStream,
    mut orphan_admission: impl FnMut() -> Option<G>,
    is_trial: bool,
) -> Result<Outcome, Error> {
    initialize(&control)?;
    let mut trial = if is_trial {
        match trial::Trial::prepare(&mut control)? {
            Some(trial) => Some(trial),
            None => {
                let _ = control.write_all(b"D\0");
                return Ok(Outcome::Stopped);
            }
        }
    } else {
        if control_event(&mut control)? != Control::Idle {
            let _ = control.write_all(b"D\0");
            return Ok(Outcome::Stopped);
        }
        None
    };
    if let Some(trial) = &mut trial
        && trial.control(&mut control)? != Control::Idle
    {
        let _ = control.write_all(b"D\0");
        return Ok(Outcome::Stopped);
    }
    // The child cannot inherit a control alias, even if the original fd0 is the
    // socket. All other inherited fds were rejected above; stdio is explicit.
    if let Some(trial) = &mut trial {
        trial.configure(&mut command)?;
    } else {
        command.stdin(std::process::Stdio::null());
    }
    let mut term_seen = Vec::with_capacity(CHILD_BATCH);
    let leader = command.spawn().map_err(|_| Error::Spawn)?;
    // Command retains configured Stdio FDs after spawn. Drop its child-side
    // startup socket alias now, otherwise backend EOF can never be observed.
    drop(command);
    let leader_pid = Pid::from_child(&leader);
    // Child is deliberately reaped only by the single owner below, not Child::wait.
    let _leader = leader;
    let mut failed = !is_trial && control.write_all(b"R").is_err();
    let mut stop_pending = failed;
    let mut lost = failed;
    let mut orphan_guard = None;
    let mut stopping = None;
    let mut leader_success = None;
    loop {
        // Only a successful kernel ECHILD after all waitable exits is closure.
        let mut no_children = false;
        for _ in 0..CHILD_BATCH {
            match wait(REAP) {
                Ok(Some((pid, status))) => {
                    if pid == leader_pid {
                        if stopping.is_none() {
                            leader_success = Some(status.exit_status() == Some(0));
                        }
                        stop_pending = true;
                    }
                }
                Ok(None) => break,
                Err(Errno::CHILD) => {
                    no_children = true;
                    break;
                }
                Err(Errno::INTR) => {}
                Err(_) => {
                    failed = true;
                    stop_pending = true;
                    lost = true;
                    break;
                }
            }
        }
        if leader_success.is_some() && trial.as_ref().is_some_and(|t| !t.committed()) {
            failed = true;
            if let Some(trial) = &mut trial {
                trial.fail(&mut control);
            }
        }
        if no_children {
            let result = if failed {
                Err(Error::Runtime)
            } else if let Some(success) = leader_success {
                Ok(Outcome::Exited(success))
            } else {
                Ok(Outcome::Stopped)
            };
            let code = match &result {
                Ok(Outcome::Stopped) => 0,
                Ok(Outcome::Exited(true)) => 1,
                Ok(Outcome::Exited(false)) => 2,
                Err(_) => 3,
            };
            let _ = control.write_all(&[b'D', code]);
            return result;
        }
        if stopping.is_none()
            && let Some(trial) = &mut trial
            && trial.tick(&mut control).is_err()
        {
            failed = true;
            stop_pending = true;
            // Keep reading the live controller. The admitted broker can send
            // explicit Stop even while orphan admission is held by that broker.
            trial.fail(&mut control);
        }
        if stopping.is_none() && !lost {
            let event = match &mut trial {
                Some(trial) => trial.control(&mut control),
                None => control_event(&mut control),
            };
            match event {
                Ok(Control::Stop) => {
                    stopping = Some(Instant::now());
                }
                Ok(Control::Lost) => {
                    stop_pending = true;
                    lost = true;
                }
                Ok(Control::Idle) => {}
                Err(_) => {
                    failed = true;
                    stop_pending = true;
                    lost = true;
                }
            }
        }
        if stopping.is_none() && stop_pending && orphan_guard.is_none() {
            orphan_guard = orphan_admission();
            if orphan_guard.is_some() {
                stopping = Some(Instant::now());
            }
        }
        if let Some(started) = stopping {
            let kill = started.elapsed() >= GRACE;
            match proc_tree::direct_children(std::path::Path::new("/proc"), getpid()) {
                Ok(children) => {
                    for pid in children.into_iter().take(CHILD_BATCH) {
                        if !kill && term_seen.contains(&pid) {
                            continue;
                        }
                        if signal_child(pid, if kill { Signal::KILL } else { Signal::TERM })
                            .is_err()
                        {
                            failed = true;
                        }
                        if !kill && term_seen.len() < CHILD_BATCH {
                            term_seen.push(pid);
                        }
                    }
                }
                Err(_) => {
                    failed = true;
                }
            }
        }
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: STEP.as_nanos() as _,
        };
        let mut fds = [PollFd::new(&control, PollFlags::IN)];
        let fds = if stopping.is_some() || lost {
            &mut [][..]
        } else {
            &mut fds[..]
        };
        if !matches!(poll(fds, Some(&timeout)), Ok(_) | Err(Errno::INTR)) {
            failed = true;
            stop_pending = true;
            lost = true;
        }
        // No teardown timeout returns while children still exist. A controller
        // deadline/disconnect cannot manufacture a completed scope receipt.
    }
}
