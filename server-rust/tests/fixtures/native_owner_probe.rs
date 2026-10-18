#[path = "../../src/native_owner/scope.rs"]
mod scope;

use std::{
    fs::{self, File},
    os::unix::{net::UnixStream, process::CommandExt},
    path::Path,
    process::{Command, ExitCode, Stdio},
    time::Duration,
};

fn child(mode: &str, root: &Path) -> ! {
    if mode != "leaf" {
        fs::write(root.join("leader.pid"), std::process::id().to_string()).unwrap();
    }
    if mode == "fd-check" {
        let count = fs::read_dir("/proc/self/fd").unwrap().count();
        std::process::exit(if count == 4 { 0 } else { 12 });
    }
    if mode == "zero" {
        std::process::exit(0);
    }
    if mode == "failure" {
        std::process::exit(9);
    }
    if mode == "leaf" {
        nix::unistd::setsid().unwrap();
        let error = Command::new("/bin/sh")
            .args([
                "-c",
                "trap '' TERM; printf '%s' \"$$\" > \"$1\"; i=0; while [ \"$i\" -lt 10 ]; do sleep 1; i=$((i+1)); done",
                "fixture-leaf",
            ])
            .arg(root.join("leaf.pid"))
            .env_clear()
            .exec();
        panic!("fixture exec failed: {error}");
    }
    if mode == "tree" || mode == "parent-exit" {
        let mut leaf = Command::new(std::env::current_exe().unwrap());
        leaf.args(["child", "leaf"])
            .arg(root)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut leaf = leaf.spawn().unwrap();
        while !root.join("leaf.pid").exists() {
            std::thread::sleep(Duration::from_millis(2));
        }
        if mode == "parent-exit" {
            // Deliberately orphan the daemon to test the dedicated subreaper.
            std::process::exit(0);
        }
        let _ = leaf.wait();
        std::process::exit(17);
    }
    if mode == "stopped" {
        let error = Command::new("/bin/sh")
            .args(["-c", "kill -STOP $$; while :; do sleep 1; done"])
            .env_clear()
            .exec();
        panic!("fixture exec failed: {error}");
    }
    for _ in 0..150 {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::process::exit(18)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("foreign") {
        let pid = args[2]
            .parse()
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .unwrap();
        return if scope::signal_child(pid, rustix::process::Signal::KILL).is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    let mode = &args[2];
    let root = Path::new(&args[3]);
    if args[1] == "child" {
        child(mode, root);
    }
    let fd = rustix::io::dup(std::io::stdin()).unwrap();
    let control = UnixStream::from(fd);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["child", mode])
        .arg(root)
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if mode == "existing-child" {
        let mut existing = Command::new("/bin/sleep")
            .arg("20")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let rejected = scope::run(command, control).is_err();
        let alive = existing.try_wait().unwrap().is_none();
        existing.kill().unwrap();
        existing.wait().unwrap();
        return if rejected && alive {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    if mode == "extra-fd" {
        let extra = File::open("/dev/null").unwrap();
        let rejected = scope::run(command, control).is_err();
        extra.metadata().unwrap();
        return if rejected {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    if mode == "multithread" {
        let (send, recv) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || recv.recv().unwrap());
        let rejected = scope::run(command, control).is_err();
        send.send(()).unwrap();
        thread.join().unwrap();
        return if rejected {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    match scope::run(command, control) {
        Ok(scope::Outcome::Stopped | scope::Outcome::Exited(true)) => ExitCode::SUCCESS,
        Ok(scope::Outcome::Exited(false)) => ExitCode::from(71),
        Err(_) => ExitCode::from(72),
    }
}
