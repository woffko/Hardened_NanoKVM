//! Fresh-process kernel owner. Not yet a device-wide maintenance/capture API.

#[path = "../update/app_trial_wire.rs"]
pub mod app_trial_wire;

#[path = "../native_owner/scope.rs"]
mod scope;

use std::{
    os::unix::net::UnixStream,
    process::{Command, ExitCode, Stdio},
};

fn command(role: &str) -> Option<Command> {
    if matches!(role, "picoclaw" | "picoclaw-onboard") {
        let home = nanokvm_rust_server::native_owner::picoclaw_home::resolve().ok()?;
        let onboard = role == "picoclaw-onboard";
        let runtime_home = if onboard {
            home.join(nanokvm_rust_server::native_owner::picoclaw_home::ONBOARD_DIRECTORY)
        } else {
            home
        };
        let mut command = Command::new("/usr/bin/picoclaw");
        command
            .arg(if onboard { "onboard" } else { "gateway" })
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env(
                "HOME",
                if onboard {
                    runtime_home.as_path()
                } else {
                    std::path::Path::new("/root")
                },
            )
            .env("LANG", "C")
            .env("PICOCLAW_HOME", &runtime_home)
            .current_dir(&runtime_home);
        if onboard {
            command.env("PICOCLAW_CONFIG", runtime_home.join("config.json"));
        }
        return Some(command);
    }
    let (loader, program) = match role {
        "kvm-system" => (
            "/lib/ld-musl-riscv64v0p7_xthead.so.1",
            "/kvmapp/kvm_system/kvm_system",
        ),
        "hwmon" => (
            "/lib/ld-musl-riscv64xthead.so.1",
            "/kvmapp/hwmon/nanokvm-hwmon",
        ),
        "backend" | "backend-trial" => (
            "/lib/ld-musl-riscv64xthead.so.1",
            "/kvmapp/server/NanoKVM-Server",
        ),
        _ => return None,
    };
    let mut command = Command::new(loader);
    command
        .args([
            "--library-path",
            "/kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd",
            program,
        ])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C");
    if role == "backend-trial" {
        command.arg("--app-trial");
    }
    if matches!(role, "backend" | "backend-trial") {
        command.env(
            "PICOCLAW_HOME",
            nanokvm_rust_server::native_owner::picoclaw_home::resolve().ok()?,
        );
    }
    Some(command)
}

fn main() -> ExitCode {
    let _ = std::hint::black_box(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/support-abi-nanokvm-native-owner.binding"
    )));
    let args: Vec<_> = std::env::args_os().collect();
    let Some(mut command) = (args.len() == 3 && args[1] == "--scope")
        .then(|| args[2].to_str().and_then(command))
        .flatten()
    else {
        eprintln!(
            "usage: nanokvm-native-owner --scope {{kvm-system|hwmon|backend|backend-trial|picoclaw|picoclaw-onboard}}"
        );
        return ExitCode::from(64);
    };
    // Only a root direct parent over its anonymous socketpair may launch a
    // production role. No pathname/PID marker, shell string or environment API.
    let Ok(fd) = rustix::io::dup(std::io::stdin()) else {
        return ExitCode::from(70);
    };
    let control = UnixStream::from(fd);
    let authorized = rustix::net::sockopt::socket_peercred(&control).is_ok_and(|peer| {
        nix::unistd::geteuid().is_root()
            && peer.uid.is_root()
            && peer.pid.as_raw_nonzero().get() == nix::unistd::getppid().as_raw()
    });
    if !authorized {
        return ExitCode::from(70);
    }
    // Dedicated single-threaded process; upstream's new files stay private.
    if args[2] == "picoclaw-onboard" {
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    }
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let result = if args[2] == "backend-trial" {
        scope::run_trial_guarded(command, control, || {
            nanokvm_rust_server::native_owner::broker::BackendOrphanPermit::try_acquire()
                .ok()
                .flatten()
        })
    } else if args[2] == "backend" {
        scope::run_guarded(command, control, || {
            nanokvm_rust_server::native_owner::broker::BackendOrphanPermit::try_acquire()
                .ok()
                .flatten()
        })
    } else {
        scope::run(command, control)
    };
    match result {
        Ok(scope::Outcome::Stopped | scope::Outcome::Exited(true)) => ExitCode::SUCCESS,
        Ok(scope::Outcome::Exited(false)) => ExitCode::from(71),
        Err(_) => {
            eprintln!("native owner did not complete successfully");
            ExitCode::from(72)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_select_only_fixed_programs_and_share_the_absolute_pico_home() {
        assert!(command("kvm-system").is_some());
        assert!(command("hwmon").is_some());
        assert!(command("backend").is_some());
        assert!(command("picoclaw").is_some());
        let kvm = command("kvm-system").unwrap();
        assert_eq!(kvm.get_program(), "/lib/ld-musl-riscv64v0p7_xthead.so.1");
        assert_eq!(
            kvm.get_args().collect::<Vec<_>>(),
            [
                "--library-path",
                "/kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd",
                "/kvmapp/kvm_system/kvm_system"
            ]
        );
        let backend = command("backend").unwrap();
        assert_eq!(backend.get_program(), "/lib/ld-musl-riscv64xthead.so.1");
        assert_eq!(
            backend.get_args().collect::<Vec<_>>(),
            [
                "--library-path",
                "/kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd",
                "/kvmapp/server/NanoKVM-Server"
            ]
        );
        assert_eq!(backend.get_envs().count(), 4);
        let pico = command("picoclaw").unwrap();
        assert_eq!(pico.get_program(), "/usr/bin/picoclaw");
        assert_eq!(pico.get_args().collect::<Vec<_>>(), ["gateway"]);
        let home = nanokvm_rust_server::native_owner::picoclaw_home::resolve().unwrap();
        assert_eq!(pico.get_current_dir(), Some(home.as_path()));
        for process in [&backend, &pico] {
            assert!(process.get_envs().any(|(name, value)| name == "PICOCLAW_HOME" && value == Some(home.as_os_str())));
        }
        let onboard = command("picoclaw-onboard").unwrap();
        let scratch =
            home.join(nanokvm_rust_server::native_owner::picoclaw_home::ONBOARD_DIRECTORY);
        assert_eq!(onboard.get_program(), "/usr/bin/picoclaw");
        assert_eq!(onboard.get_args().collect::<Vec<_>>(), ["onboard"]);
        assert_eq!(onboard.get_current_dir(), Some(scratch.as_path()));
        for key in ["HOME", "PICOCLAW_HOME"] {
            assert!(
                onboard
                    .get_envs()
                    .any(|(name, value)| name == key && value == Some(scratch.as_os_str()))
            );
        }
        assert!(
            onboard
                .get_envs()
                .any(|(name, value)| name == "PICOCLAW_CONFIG"
                    && value == Some(scratch.join("config.json").as_os_str()))
        );
        assert_eq!(onboard.get_envs().count(), 5);
        let trial = command("backend-trial").unwrap();
        assert_eq!(trial.get_program(), backend.get_program());
        assert_eq!(trial.get_args().last().unwrap(), "--app-trial");
        assert_eq!(trial.get_args().count(), backend.get_args().count() + 1);
        for role in [
            "",
            "/bin/sh",
            "watchdog",
            "../../other",
            "hwmon;reboot",
            "picoclaw onboard",
            "picoclaw;sh",
        ] {
            assert!(command(role).is_none());
        }
    }
}
