#[path = "../../src/update/app_trial_wire.rs"]
pub mod app_trial_wire;
#[path = "../../src/native_owner/scope.rs"]
mod scope;

use std::{
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::CommandExt},
    },
    path::Path,
    process::{Command, ExitCode, Stdio},
    time::Duration,
};

fn child(mode: &str, root: &Path) -> ! {
    if !matches!(mode, "leaf" | "owned-leaf") {
        fs::write(root.join("leader.pid"), std::process::id().to_string()).unwrap();
    }
    if mode == "fd-check" {
        let count = fs::read_dir("/proc/self/fd").unwrap().count();
        std::process::exit(if count == 4 { 0 } else { 12 });
    }
    if mode.starts_with("trial-") {
        use scope::trial_wire as wire;
        let mut startup = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
        rustix::io::fcntl_setfd(&startup, rustix::io::FdFlags::CLOEXEC).unwrap();
        let null = File::open("/dev/null").unwrap();
        nix::unistd::dup2(null.as_raw_fd(), 0).unwrap();
        drop(null);
        startup
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let mut begin = [0; wire::BYTES];
        startup.read_exact(&mut begin).unwrap();
        let transaction = wire::parse(&begin, wire::Event::Begin).unwrap();
        fs::write(root.join("trial-begin"), begin).unwrap();
        if mode == "trial-orphan" {
            let mut leaf = Command::new(std::env::current_exe().unwrap())
                .args(["child", "leaf"])
                .arg(root)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            while !root.join("leaf.pid").exists() {
                std::thread::sleep(Duration::from_millis(2));
            }
            // Retain the orphan until the independent scope receives Stop.
            let _ = leaf.try_wait();
            std::process::exit(0);
        }
        if mode == "trial-delayed" {
            let start = std::time::Instant::now();
            while !root.join("release-ready").exists() {
                assert!(start.elapsed() < Duration::from_secs(8));
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let ready = wire::frame(
            wire::Event::Ready,
            if mode == "trial-wrong" {
                [9; 16]
            } else {
                transaction
            },
        )
        .unwrap();
        if mode == "trial-truncated" {
            startup.write_all(&ready[..8]).unwrap();
            drop(startup);
        } else if mode == "trial-eof" {
            drop(startup);
        } else {
            startup.write_all(&ready).unwrap();
            if mode != "trial-wrong" {
                let mut commit = [0; wire::BYTES];
                startup.read_exact(&mut commit).unwrap();
                assert_eq!(
                    wire::parse(&commit, wire::Event::Commit).unwrap(),
                    transaction
                );
                fs::write(root.join("trial-committed"), commit).unwrap();
            }
        }
        // No implicit commit/exit when the startup channel has closed.
        for _ in 0..150 {
            std::thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(18);
    }
    if mode == "zero" {
        std::process::exit(0);
    }
    if mode == "failure" {
        std::process::exit(9);
    }
    if mode == "leaf" || mode == "owned-leaf" {
        nix::unistd::setsid().unwrap();
        let script = if mode == "owned-leaf" {
            // Lifetime belongs to the test/real scope Stop, not a competing
            // wall-clock expiry while the test is still preparing its input.
            "trap '' TERM; printf '%s' \"$$\" > \"$1\"; while [ ! -e \"$2\" ]; do sleep 1; done"
        } else {
            "trap '' TERM; printf '%s' \"$$\" > \"$1\"; i=0; while [ \"$i\" -lt 10 ]; do sleep 1; i=$((i+1)); done"
        };
        let error = Command::new("/bin/sh")
            .args(["-c", script, "fixture-leaf"])
            .arg(root.join("leaf.pid"))
            .arg(root.join("release-leaf"))
            .env_clear()
            .exec();
        panic!("fixture exec failed: {error}");
    }
    if matches!(mode, "tree" | "owned-tree" | "parent-exit") {
        let mut leaf = Command::new(std::env::current_exe().unwrap());
        leaf.args([
            "child",
            if mode == "owned-tree" {
                "owned-leaf"
            } else {
                "leaf"
            },
        ])
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
    if args.len() == 2 && args[1] == "gateway" {
        fs::write(
            "picoclaw-runtime.fixture",
            serde_json::to_vec(&serde_json::json!({
                "home": std::env::var("PICOCLAW_HOME").unwrap(),
                "cwd": std::env::current_dir().unwrap(),
                "user_home": std::env::var("HOME").unwrap(),
            }))
            .unwrap(),
        )
        .unwrap();
        return ExitCode::SUCCESS;
    }
    if args.get(1).map(String::as_str) == Some("wire") {
        let root = Path::new(&args[3]);
        fs::write(root.join("owner.pid"), std::process::id().to_string()).unwrap();
        let mut control = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
        control
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        control.write_all(b"R").unwrap();
        match args[2].as_str() {
            "missing" => return ExitCode::SUCCESS,
            "malformed" => control.write_all(b"X").unwrap(),
            "malformed-record" => {
                control.write_all(b"X").unwrap();
                let mut stop = [0];
                let count = control.read(&mut stop).unwrap();
                fs::write(root.join("received-control"), &stop[..count]).unwrap();
                return ExitCode::SUCCESS;
            }
            "duplicate" => control.write_all(b"R").unwrap(),
            "killed" => {
                let mut stop = [0];
                let _ = control.read(&mut stop);
                return ExitCode::from(72);
            }
            "receipt-before-exit" => {
                control.write_all(b"D\x01").unwrap();
                let mut stop = [0];
                let _ = control.read(&mut stop);
                return ExitCode::SUCCESS;
            }
            "wrong-exit" => {
                control.write_all(b"D\x01").unwrap();
                return ExitCode::from(71);
            }
            "truncated" => {
                control.write_all(b"D").unwrap();
                return ExitCode::SUCCESS;
            }
            _ => return ExitCode::from(64),
        }
        let mut stop = [0];
        let _ = control.read(&mut stop);
        control.write_all(b"D\0").unwrap();
        return ExitCode::SUCCESS;
    }
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
    fs::write(root.join("owner.pid"), std::process::id().to_string()).unwrap();
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
    let admission = || {
        fs::write(root.join("orphan-attempt"), b"attempt").unwrap();
        let file = File::open(root.join("update-lock")).unwrap();
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                fs::write(root.join("orphan-acquired"), b"acquired").unwrap();
                Some(file)
            }
            Err(rustix::io::Errno::WOULDBLOCK) => None,
            Err(error) => panic!("fixture lock failed: {error}"),
        }
    };
    let result = if args[1] == "scope-trial" {
        scope::run_trial_guarded(command, control, admission)
    } else if args[1] == "scope-guarded" {
        scope::run_guarded(command, control, admission)
    } else {
        scope::run(command, control)
    };
    match result {
        Ok(scope::Outcome::Stopped | scope::Outcome::Exited(true)) => ExitCode::SUCCESS,
        Ok(scope::Outcome::Exited(false)) => ExitCode::from(71),
        Err(_) => ExitCode::from(72),
    }
}
