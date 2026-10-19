//! Fresh-process kernel owner. Not yet a device-wide maintenance/capture API.

#[path = "../native_owner/scope.rs"]
mod scope;

use std::{
    os::unix::net::UnixStream,
    process::{Command, ExitCode, Stdio},
};

fn command(role: &str) -> Option<Command> {
    let (loader, program) = match role {
        "kvm-system" => (
            "/lib/ld-musl-riscv64v0p7_xthead.so.1",
            "/kvmapp/kvm_system/kvm_system",
        ),
        "hwmon" => (
            "/lib/ld-musl-riscv64xthead.so.1",
            "/kvmapp/hwmon/nanokvm-hwmon",
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
    Some(command)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let Some(mut command) = (args.len() == 3 && args[1] == "--scope")
        .then(|| args[2].to_str().and_then(command))
        .flatten()
    else {
        eprintln!("usage: nanokvm-native-owner --scope {{kvm-system|hwmon}}");
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
    command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    match scope::run(command, control) {
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
    fn roles_select_only_the_two_fixed_native_programs() {
        assert!(command("kvm-system").is_some());
        assert!(command("hwmon").is_some());
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
        for role in ["", "/bin/sh", "watchdog", "../../other", "hwmon;reboot"] {
            assert!(command(role).is_none());
        }
    }
}
