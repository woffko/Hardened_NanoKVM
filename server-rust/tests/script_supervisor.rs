use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    thread::sleep,
    time::{Duration, Instant},
};

fn script(root: &Path, name: &str, body: &str) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn pid_file(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

fn read_pid(path: &Path) -> i32 {
    fs::read_to_string(path).unwrap().trim().parse().unwrap()
}

fn alive(pid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(") ")
            .is_some_and(|(_, rest)| !rest.starts_with('Z'))
    })
}

fn dead(pid: i32) -> bool {
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if !alive(pid) {
            return true;
        }
        sleep(Duration::from_millis(20));
    }
    false
}

fn supervisor() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nanokvm-rust-server"));
    command.arg("--script-supervisor");
    command
}

#[test]
fn a_timed_out_setsid_escapee_is_killed_with_the_script() {
    let root = tempfile::tempdir().unwrap();
    let pids = pid_file(root.path(), "pids");
    let body = format!(
        "setsid sh -c 'trap \"\" TERM; exec sleep 300' &\necho $! > {}\nexec sleep 300\n",
        pids.display()
    );
    let path = script(root.path(), "stuck.sh", &body);
    let status = supervisor()
        .args(["1", "100", "--", "/bin/sh"])
        .arg(&path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(124));
    assert!(dead(read_pid(&pids)), "setsid child survived the timeout");
}

#[test]
fn a_setsid_escapee_is_killed_after_a_successful_script_exit() {
    let root = tempfile::tempdir().unwrap();
    let pids = pid_file(root.path(), "pids");
    let body = format!(
        "setsid sh -c 'trap \"\" TERM; exec sleep 300' &\necho $! > {}\nexit 0\n",
        pids.display()
    );
    let path = script(root.path(), "daemon.sh", &body);
    let status = supervisor()
        .args(["5", "100", "--", "/bin/sh"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success(), "{status:?}");
    assert!(dead(read_pid(&pids)), "setsid child survived a normal exit");
}

/// A device runs `loader --library-path ... program`. The host's loader takes the
/// same form, so this is the shape the option has to survive.
#[test]
fn the_supervisor_option_reaches_the_program_through_its_loader() {
    let loader = Path::new("/lib64/ld-linux-x86-64.so.2");
    assert!(loader.exists(), "this test needs the host's dynamic loader");
    let status = Command::new(loader)
        .args(["--library-path", "/lib/x86_64-linux-gnu"])
        .arg(env!("CARGO_BIN_EXE_nanokvm-rust-server"))
        .args(["--script-supervisor", "5", "100", "--"])
        .args(["/bin/sh", "-c", "exit 7"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(7));
}
