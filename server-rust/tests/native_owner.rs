#![cfg(feature = "sandbox-test-fixture")]

use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const LIMIT: Duration = Duration::from_secs(8);

struct Running {
    child: Child,
    control: UnixStream,
    root: tempfile::TempDir,
}

fn start(mode: &str) -> Running {
    let root = tempfile::tempdir().unwrap();
    start_at(mode, "scope", root)
}

fn start_at(mode: &str, kind: &str, root: tempfile::TempDir) -> Running {
    let (control, owner) = UnixStream::pair().unwrap();
    control.set_read_timeout(Some(LIMIT)).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nanokvm-native-owner-fixture"))
        .args([kind, mode])
        .arg(root.path())
        .env_clear()
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(owner)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    Running {
        child,
        control,
        root,
    }
}

impl Running {
    fn ready(&mut self) {
        let mut byte = [0];
        self.control.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'R']);
    }

    fn done(&mut self, code: u8) {
        let mut bytes = [0; 2];
        self.control.read_exact(&mut bytes).unwrap();
        assert_eq!(bytes, [b'D', code]);
    }

    fn wait(&mut self) -> std::process::ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                started.elapsed() < LIMIT,
                "owner did not exit after scope closure"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        // Normal Stop/EOF, not kill(owner): the owner must keep reaping its tree.
        let _ = self.control.shutdown(std::net::Shutdown::Both);
        let start = Instant::now();
        while start.elapsed() < LIMIT {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_pid(root: &Path, name: &str) -> rustix::process::Pid {
    let started = Instant::now();
    loop {
        if let Ok(raw) = fs::read_to_string(root.join(name))
            && let Ok(raw) = raw.parse()
        {
            return rustix::process::Pid::from_raw(raw).unwrap();
        }
        assert!(started.elapsed() < LIMIT, "fixture did not publish PID");
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct FixtureProcess(std::os::fd::OwnedFd);

impl std::ops::Deref for FixtureProcess {
    type Target = std::os::fd::OwnedFd;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        // Emergency cleanup for a failing assertion, including a SIGSTOP fixture.
        // This descriptor pins only a process created inside our private fixture.
        let _ = rustix::process::pidfd_send_signal(&self.0, rustix::process::Signal::KILL);
    }
}

fn pin(pid: rustix::process::Pid) -> FixtureProcess {
    FixtureProcess(rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap())
}

fn assert_exited(fd: &std::os::fd::OwnedFd) {
    let mut fds = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
    let zero = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(rustix::event::poll(&mut fds, Some(&zero)).unwrap(), 1);
    assert!(fds[0].revents().contains(rustix::event::PollFlags::IN));
}

fn wait_file(root: &Path, name: &str) {
    let started = Instant::now();
    while !root.join(name).exists() {
        assert!(started.elapsed() < LIMIT, "fixture did not publish {name}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn guarded_fixture() -> (tempfile::TempDir, fs::File) {
    let root = tempfile::tempdir().unwrap();
    let lock = fs::File::create(root.path().join("update-lock")).unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    (root, lock)
}

#[test]
fn backend_disconnect_waits_for_update_and_retains_lock_until_tree_join() {
    let (root, update) = guarded_fixture();
    let mut run = start_at("tree", "scope-guarded", root);
    run.ready();
    let leader = pin(wait_pid(run.root.path(), "leader.pid"));
    let leaf = pin(wait_pid(run.root.path(), "leaf.pid"));
    run.control.shutdown(std::net::Shutdown::Both).unwrap();
    wait_file(run.root.path(), "orphan-attempt");
    assert!(!run.root.path().join("orphan-acquired").exists());
    assert!(run.child.try_wait().unwrap().is_none());
    let mut fds = [rustix::event::PollFd::new(
        &leader.0,
        rustix::event::PollFlags::IN,
    )];
    let timeout = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    assert_eq!(rustix::event::poll(&mut fds, Some(&timeout)).unwrap(), 0);
    drop(update);
    wait_file(run.root.path(), "orphan-acquired");
    let contender = fs::File::open(run.root.path().join("update-lock")).unwrap();
    assert_eq!(
        rustix::fs::flock(
            &contender,
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        ),
        Err(rustix::io::Errno::WOULDBLOCK)
    );
    assert!(run.wait().success());
    assert_exited(&leader);
    assert_exited(&leaf);
    rustix::fs::flock(
        &contender,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
}

#[test]
fn backend_explicit_stop_uses_controllers_existing_update_exclusion() {
    let (root, _update) = guarded_fixture();
    let mut run = start_at("tree", "scope-guarded", root);
    run.ready();
    let leaf = pin(wait_pid(run.root.path(), "leaf.pid"));
    run.control.write_all(b"S").unwrap();
    run.done(0);
    assert!(run.wait().success());
    assert_exited(&leaf);
    assert!(!run.root.path().join("orphan-attempt").exists());
}

#[test]
fn backend_natural_leader_exit_cannot_kill_update_descendants_without_admission() {
    let (root, update) = guarded_fixture();
    let mut run = start_at("parent-exit", "scope-guarded", root);
    run.ready();
    let leaf = pin(wait_pid(run.root.path(), "leaf.pid"));
    wait_file(run.root.path(), "orphan-attempt");
    assert!(!run.root.path().join("orphan-acquired").exists());
    assert!(run.child.try_wait().unwrap().is_none());
    drop(update);
    run.done(1);
    assert!(run.wait().success());
    assert_exited(&leaf);
}

#[test]
fn explicit_stop_joins_direct_child_and_does_not_signal_unrelated_process() {
    let mut unrelated = Command::new("/bin/sleep")
        .arg("20")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut run = start("hold");
    run.ready();
    let leader = pin(wait_pid(run.root.path(), "leader.pid"));
    run.control.write_all(b"S").unwrap();
    run.done(0);
    assert!(run.wait().success());
    assert_exited(&leader);
    let alive = unrelated.try_wait().unwrap().is_none();
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
    assert!(alive);
}

#[test]
fn stop_reaps_setsid_grandchild_after_its_parent_is_gone() {
    let mut run = start("tree");
    run.ready();
    let leaf = pin(wait_pid(run.root.path(), "leaf.pid"));
    let started = Instant::now();
    run.control.write_all(b"S").unwrap();
    run.done(0);
    assert!(run.wait().success());
    assert_exited(&leaf);
    // TERM is ignored by the daemon. No completion before escalation/reap.
    assert!(started.elapsed() >= Duration::from_millis(1800));
}

#[test]
fn natural_leader_exit_still_cleans_and_reaps_its_daemon() {
    let mut run = start("parent-exit");
    run.ready();
    let leaf = pin(wait_pid(run.root.path(), "leaf.pid"));
    run.done(1);
    assert!(run.wait().success());
    assert_exited(&leaf);
}

#[test]
fn controller_disconnect_does_not_abandon_the_tree() {
    let mut run = start("tree");
    run.ready();
    let leaf = pin(wait_pid(run.root.path(), "leaf.pid"));
    run.control.shutdown(std::net::Shutdown::Both).unwrap();
    assert!(run.wait().success());
    assert_exited(&leaf);
}

#[test]
fn invalid_control_is_failure_only_after_tree_cleanup() {
    let mut run = start("tree");
    run.ready();
    let leaf = pin(wait_pid(run.root.path(), "leaf.pid"));
    run.control.write_all(b"X").unwrap();
    run.done(3);
    assert_eq!(run.wait().code(), Some(72));
    assert_exited(&leaf);
}

#[test]
fn preclosed_control_never_launches_native_work() {
    let root = tempfile::tempdir().unwrap();
    let (control, owner) = UnixStream::pair().unwrap();
    control.shutdown(std::net::Shutdown::Both).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nanokvm-native-owner-fixture"))
        .args(["scope", "hold"])
        .arg(root.path())
        .env_clear()
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(owner)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut run = Running {
        child,
        control,
        root,
    };
    assert!(run.wait().success());
    assert!(!run.root.path().join("leader.pid").exists());
}

#[test]
fn command_exec_cannot_inherit_the_private_control_descriptor() {
    let mut run = start("fd-check");
    run.ready();
    run.done(1);
    assert!(run.wait().success());
}

#[test]
fn named_socket_is_not_an_anonymous_parent_control_capability() {
    let root = tempfile::tempdir().unwrap();
    let listener =
        std::os::unix::net::UnixListener::bind(root.path().join("control.sock")).unwrap();
    let control = UnixStream::connect(root.path().join("control.sock")).unwrap();
    let (owner, _) = listener.accept().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nanokvm-native-owner-fixture"))
        .args(["scope", "hold"])
        .arg(root.path())
        .env_clear()
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(owner)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut run = Running {
        child,
        control,
        root,
    };
    assert_eq!(run.wait().code(), Some(72));
    assert!(!run.root.path().join("leader.pid").exists());
}

#[test]
fn natural_success_and_failure_keep_distinct_outcomes() {
    for (mode, receipt, exit) in [("zero", 1, 0), ("failure", 2, 71)] {
        let mut run = start(mode);
        run.ready();
        run.done(receipt);
        assert_eq!(run.wait().code(), Some(exit));
    }
}

#[test]
fn stopped_child_is_killed_and_reaped_before_acknowledgement() {
    let mut run = start("stopped");
    run.ready();
    let pid = wait_pid(run.root.path(), "leader.pid");
    let leader = pin(pid);
    let started = Instant::now();
    while !fs::read_to_string(format!("/proc/{}/status", pid.as_raw_nonzero()))
        .unwrap()
        .lines()
        .any(|line| line.starts_with("State:") && line.contains('T'))
    {
        assert!(started.elapsed() < LIMIT);
        std::thread::sleep(Duration::from_millis(5));
    }
    run.control.write_all(b"S").unwrap();
    run.done(0);
    assert!(run.wait().success());
    assert_exited(&leader);
}

#[test]
fn unsafe_startup_contexts_are_rejected_without_touching_existing_children() {
    for mode in ["existing-child", "extra-fd", "multithread"] {
        let mut run = start(mode);
        assert!(
            run.wait().success(),
            "context was not safely rejected: {mode}"
        );
        assert!(!run.root.path().join("leader.pid").exists());
    }
}

#[test]
fn pidfd_waitid_rejects_a_live_process_that_is_not_this_owners_child() {
    let mut unrelated = Command::new("/bin/sleep")
        .arg("20")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_nanokvm-native-owner-fixture"))
        .args(["foreign", &unrelated.id().to_string()])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    let alive = unrelated.try_wait().unwrap().is_none();
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
    assert!(status.success() && alive);
}

#[test]
fn production_binary_has_no_generic_command_or_fixture_fallback() {
    for args in [
        vec!["--scope", "/bin/sh"],
        vec!["--scope", "watchdog"],
        vec!["--fixture"],
        vec!["--scope", "hwmon"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_nanokvm-native-owner"))
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}
