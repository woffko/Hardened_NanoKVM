use nix::{
    sys::{
        prctl,
        signal::{Signal, kill, killpg},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use rustix::process::{Pid as ChildPid, Signal as ChildSignal};
use std::{
    ffi::OsString,
    io,
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

#[path = "proc_tree.rs"]
mod proc_tree;

const CHILD_DRAIN: Duration = Duration::from_secs(1);
/// The script ended and processes it started could not be stopped. Not one of
/// the codes that timeout, env or a shell use for themselves.
pub const LEFT_BEHIND: i32 = 199;

pub fn run(args: &[OsString]) -> i32 {
    let Some((timeout, grace, program, script_args)) = parse(args) else {
        return 64;
    };
    if prctl::set_child_subreaper(true).is_err() {
        return 70;
    }
    let mut command = Command::new(program);
    command
        .args(script_args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0);
    let Ok(mut child) = command.spawn() else {
        return 71;
    };
    let started = Instant::now();
    let mut timed_out = false;
    let mut code = 1;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                code = status.code().unwrap_or(1);
                break;
            }
            Ok(None) if started.elapsed() >= timeout => {
                timed_out = true;
                break;
            }
            Ok(None) => sleep(Duration::from_millis(20)),
            Err(_) => {
                timed_out = true;
                break;
            }
        }
    }
    if timed_out {
        let pid = i32::try_from(child.id()).ok();
        if let Some(pid) = pid {
            let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            let _ = killpg(Pid::from_raw(pid), Signal::SIGTERM);
        }
        sleep(grace);
        if let Some(pid) = pid {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            sleep(Duration::from_millis(10));
        }
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
        code = 124;
    }
    exit_code(code, drain(CHILD_DRAIN, children))
}

fn exit_code(code: i32, children_gone: bool) -> i32 {
    if children_gone { code } else { LEFT_BEHIND }
}

fn parse(args: &[OsString]) -> Option<(Duration, Duration, &OsString, &[OsString])> {
    if args.len() < 4 || args[2] != "--" {
        return None;
    }
    let timeout = args[0].to_str()?.parse::<u64>().ok()?;
    let grace = args[1].to_str()?.parse::<u64>().ok()?;
    Some((
        Duration::from_secs(timeout),
        Duration::from_millis(grace),
        &args[3],
        &args[4..],
    ))
}

/// Whether everything the script started is gone. An enumeration that keeps
/// failing proves nothing, so it does not count as gone.
fn drain(limit: Duration, mut children: impl FnMut() -> io::Result<Vec<ChildPid>>) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        match children() {
            Ok(children) if children.is_empty() => {
                reap();
                return true;
            }
            Ok(children) => {
                for pid in children {
                    let _ = proc_tree::signal_child(pid, ChildSignal::KILL);
                }
                reap();
            }
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(10));
    }
}

fn children() -> io::Result<Vec<ChildPid>> {
    let raw = i32::try_from(std::process::id())
        .map_err(|_| io::Error::other("script supervisor PID does not fit in i32"))?;
    let parent = ChildPid::from_raw(raw)
        .ok_or_else(|| io::Error::other("script supervisor has an invalid PID"))?;
    proc_tree::direct_children(Path::new("/proc"), parent)
}

fn reap() {
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: Duration = Duration::from_millis(30);

    #[test]
    fn a_child_left_behind_outranks_the_exit_code_of_the_script() {
        assert_eq!(exit_code(0, true), 0);
        assert_eq!(exit_code(124, true), 124);
        assert_eq!(exit_code(0, false), LEFT_BEHIND);
        assert_eq!(exit_code(124, false), LEFT_BEHIND);
    }

    #[test]
    fn only_an_empty_listing_proves_the_children_are_gone() {
        assert!(drain(LIMIT, || Ok(Vec::new())));
        let mut listings = 0;
        assert!(drain(LIMIT, || {
            listings += 1;
            Ok(if listings == 1 {
                vec![ChildPid::from_raw(i32::MAX).unwrap()]
            } else {
                Vec::new()
            })
        }));
    }

    #[test]
    fn a_child_that_stays_or_a_listing_that_fails_is_not_gone() {
        assert!(!drain(LIMIT, || Ok(vec![
            ChildPid::from_raw(i32::MAX).unwrap()
        ])));
        assert!(!drain(LIMIT, || Err(io::Error::other("no listing"))));
    }
}
