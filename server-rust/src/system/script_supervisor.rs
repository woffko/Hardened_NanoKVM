use nix::{
    sys::{
        prctl,
        signal::{Signal, kill, killpg},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use std::{
    ffi::OsString,
    fs,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

const CHILD_DRAIN: Duration = Duration::from_secs(1);

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
    kill_remaining_children();
    code
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

fn kill_remaining_children() {
    let deadline = Instant::now() + CHILD_DRAIN;
    loop {
        let children = children();
        if children.is_empty() {
            reap();
            return;
        }
        for pid in children {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
        reap();
        if Instant::now() >= deadline {
            return;
        }
        sleep(Duration::from_millis(10));
    }
}

fn children() -> Vec<i32> {
    let path = format!("/proc/self/task/{}/children", std::process::id());
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    text.split_whitespace()
        .filter_map(|value| value.parse::<i32>().ok())
        .collect()
}

fn reap() {
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(_) => break,
            Ok(_) => {}
        }
    }
}
