use super::*;
use std::{
    fs,
    os::fd::{AsFd, OwnedFd},
    path::Path,
    time::{Duration, Instant},
};

fn until(mut ready: impl FnMut() -> bool) {
    let start = Instant::now();
    while !ready() {
        assert!(start.elapsed() < Duration::from_secs(8));
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn command(root: &Path, mode: &str) -> Command {
    let test = std::env::current_exe().unwrap();
    let mut command = Command::new(
        test.parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("nanokvm-native-owner-fixture"),
    );
    command
        .args(["scope", mode])
        .arg(root)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    command
}

struct Leaf(OwnedFd);
impl Drop for Leaf {
    fn drop(&mut self) {
        let _ = rustix::process::pidfd_send_signal(&self.0, rustix::process::Signal::KILL);
    }
}

fn leaf(root: &Path) -> Leaf {
    let mut pid = None;
    until(|| {
        pid = fs::read_to_string(root.join("leaf.pid"))
            .ok()
            .and_then(|text| text.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw);
        pid.is_some()
    });
    Leaf(rustix::process::pidfd_open(pid.unwrap(), rustix::process::PidfdFlags::empty()).unwrap())
}

fn exited(leaf: &Leaf) -> bool {
    let mut fds = [rustix::event::PollFd::new(
        &leaf.0,
        rustix::event::PollFlags::IN,
    )];
    rustix::event::poll(
        &mut fds,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )
    .unwrap()
        == 1
}

#[test]
fn maintenance_joins_optional_pico_descendants_without_stopping_backend() {
    let root = tempfile::tempdir().unwrap();
    let backend = root.path().join("backend");
    let pico = root.path().join("pico");
    fs::create_dir(&backend).unwrap();
    fs::create_dir(&pico).unwrap();
    let mut group = Group::default();
    group
        .start_command(Role::Backend, command(&backend, "tree"))
        .unwrap();
    group
        .start_command(Role::Picoclaw, command(&pico, "tree"))
        .unwrap();
    until(|| {
        let status = group.poll();
        status[2] == Some(Status::Running) && status[3] == Some(Status::Running)
    });
    let backend_leaf = leaf(&backend);
    let pico_leaf = leaf(&pico);
    let owner = group.cells[3].as_ref().unwrap().child.id();
    struct Paused(OwnedFd);
    impl Drop for Paused {
        fn drop(&mut self) {
            let _ = rustix::process::pidfd_send_signal(&self.0, rustix::process::Signal::CONT);
        }
    }
    let paused = Paused(
        rustix::process::pidfd_open(
            rustix::process::Pid::from_raw(owner as i32).unwrap(),
            rustix::process::PidfdFlags::empty(),
        )
        .unwrap(),
    );
    rustix::process::pidfd_send_signal(&paused.0, rustix::process::Signal::STOP).unwrap();
    until(|| {
        rustix::process::waitid(
            rustix::process::WaitId::PidFd(paused.0.as_fd()),
            rustix::process::WaitIdOptions::STOPPED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        )
        .unwrap()
        .is_some()
    });
    let mut drain = group.begin_native_drain();
    assert_eq!(
        drain.poll(),
        DrainStatus::Pending,
        "a stopped Pico owner has not joined its native tree"
    );
    assert_eq!(drain.backend_status(), Some(Status::Running));
    assert!(!exited(&pico_leaf) && !exited(&backend_leaf));
    drop(paused);
    until(|| drain.poll() == DrainStatus::Drained);
    assert!(exited(&pico_leaf));
    assert!(!exited(&backend_leaf));
    assert_eq!(drain.backend_status(), Some(Status::Running));
    let Resume::Running(group) = drain.try_resume() else {
        panic!("joined native drain must resume")
    };
    let mut all = group.begin_drain();
    until(|| all.poll() == DrainStatus::Drained);
    assert!(exited(&backend_leaf));
    assert!(all.all_owner_processes_reaped());
}

#[test]
fn optional_pico_loss_latches_uncertainty_and_never_becomes_an_empty_drain() {
    // A child that is not an owner exits without the mandatory D receipt.
    let command = Command::new("/bin/true");
    let mut group = Group::default();
    group.start_command(Role::Picoclaw, command).unwrap();
    until(|| group.poll()[3] == Some(Status::Uncertain));
    assert!(matches!(
        group.start_command(Role::Hwmon, Command::new("/bin/true")),
        Err(StartError::UncertainOwnership)
    ));
    let mut drain = group.begin_native_drain();
    assert_eq!(drain.poll(), DrainStatus::Uncertain);
    assert!(drain.all_owner_processes_reaped());
    assert!(matches!(drain.try_resume(), Resume::Retained(_)));
}
