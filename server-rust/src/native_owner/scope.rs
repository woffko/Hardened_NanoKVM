//! Dedicated, single-threaded process only. Never include in the async backend.
//! Owns one fresh trusted process tree, not arbitrary existing device services.

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::{Errno, FdFlags, fcntl_setfd},
    process::{
        Pid, PidfdFlags, Signal, WaitId, WaitIdOptions, WaitOptions, child_subreaper, getpid,
        pidfd_open, pidfd_send_signal, wait, waitid,
    },
};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::fd::{AsFd, AsRawFd},
    os::unix::net::UnixStream,
    process::Command,
    time::{Duration, Instant},
};

const STEP: Duration = Duration::from_millis(20);
const GRACE: Duration = Duration::from_secs(2);
const CHILDREN_BYTES: usize = 64 * 1024;
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

fn control_event(control: &mut UnixStream) -> Result<bool, Error> {
    let mut byte = [0];
    match control.read(&mut byte) {
        Ok(0) => Ok(true), // Parent disconnect is Stop, never abandonment.
        Ok(_) if byte == *b"S" => Ok(true),
        Ok(_) => Err(Error::Control),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(_) => Err(Error::Control),
    }
}

// PID numbers from proc only nominate candidates. The kernel must confirm the
// pidfd names OUR unreaped child before any signal. No PID-file or integer kill.
pub(super) fn signal_child(pid: Pid, signal: Signal) -> Result<(), Error> {
    let fd = match pidfd_open(pid, PidfdFlags::empty()) {
        Ok(fd) => fd,
        Err(Errno::SRCH) => return Ok(()),
        Err(_) => return Err(Error::Runtime),
    };
    match waitid(WaitId::PidFd(fd.as_fd()), PEEK) {
        Ok(None) => {}
        Ok(Some(_)) | Err(Errno::CHILD) => return Ok(()),
        Err(_) => return Err(Error::Runtime),
    }
    match pidfd_send_signal(&fd, signal) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(_) => Err(Error::Runtime),
    }
}

pub(super) fn run(mut command: Command, mut control: UnixStream) -> Result<Outcome, Error> {
    initialize(&control)?;
    if control_event(&mut control)? {
        let _ = control.write_all(b"D\0");
        return Ok(Outcome::Stopped);
    }
    // The child cannot inherit a control alias, even if the original fd0 is the
    // socket. All other inherited fds were rejected above; stdio is explicit.
    command.stdin(std::process::Stdio::null());
    let children_path = format!("/proc/self/task/{}/children", getpid().as_raw_nonzero());
    let mut buffer = vec![0_u8; CHILDREN_BYTES];
    let mut term_seen = Vec::with_capacity(CHILD_BATCH);
    let leader = command.spawn().map_err(|_| Error::Spawn)?;
    let leader_pid = Pid::from_child(&leader);
    // Child is deliberately reaped only by the single owner below, not Child::wait.
    let _leader = leader;
    let mut failed = control.write_all(b"R").is_err();
    let mut stopping = failed.then(Instant::now);
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
                        stopping.get_or_insert_with(Instant::now);
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
                    stopping.get_or_insert_with(Instant::now);
                    break;
                }
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
        if stopping.is_none() {
            match control_event(&mut control) {
                Ok(true) => {
                    stopping = Some(Instant::now());
                }
                Ok(false) => {}
                Err(_) => {
                    failed = true;
                    stopping = Some(Instant::now());
                }
            }
        }
        if let Some(started) = stopping {
            let kill = started.elapsed() >= GRACE;
            let children = File::open(&children_path);
            match children.and_then(|mut file| file.read(&mut buffer)) {
                Ok(size) => {
                    if size == buffer.len() {
                        failed = true;
                    }
                    for token in buffer[..size]
                        .split(|b| b.is_ascii_whitespace())
                        .take(CHILD_BATCH)
                    {
                        if token.is_empty() {
                            continue;
                        }
                        let pid = std::str::from_utf8(token)
                            .ok()
                            .and_then(|s| s.parse::<i32>().ok())
                            .and_then(Pid::from_raw);
                        let Some(pid) = pid else {
                            failed = true;
                            continue;
                        };
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
        let fds = if stopping.is_some() {
            &mut [][..]
        } else {
            &mut fds[..]
        };
        if !matches!(poll(fds, Some(&timeout)), Ok(_) | Err(Errno::INTR)) {
            failed = true;
            stopping.get_or_insert_with(Instant::now);
        }
        // No teardown timeout returns while children still exist. A controller
        // deadline/disconnect cannot manufacture a completed scope receipt.
    }
}
