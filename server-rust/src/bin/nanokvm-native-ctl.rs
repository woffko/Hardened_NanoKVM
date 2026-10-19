use nanokvm_rust_server::native_owner::broker::ipc::{Channel, Code, Mode, Operation};
use nanokvm_rust_server::native_owner::broker::{Broker, JournalError, boot};
use std::{
    process::ExitCode,
    time::{Duration, Instant},
};
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 {
        let result = match args[0].to_str() {
            Some("activate-boot") => Some(boot::activate_early()),
            Some("boot-ready") => Some(boot::require_ready().map(drop)),
            _ => None,
        };
        if let Some(result) = result {
            return match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("native boot: {error}");
                    ExitCode::from(78)
                }
            };
        }
    }
    let query = args.len() == 1 && args[0] == "kvm-running";
    let running_query = args.len() == 1 && args[0] == "running";
    let op = if args.len() == 1 {
        match args[0].to_str() {
            Some("status" | "running" | "kvm-running") => Some(Operation::Observe),
            Some("ensure-kvm") => Some(Operation::EnsureKvm),
            Some("ensure-hwmon") => Some(Operation::EnsureHwmon),
            Some("shutdown") => Some(Operation::Shutdown),
            Some("ensure-backend") => Some(Operation::EnsureBackend),
            Some("backend-running") => Some(Operation::BackendRunning),
            Some("restart-backend") => Some(Operation::RestartBackend),
            Some("restart-backend-safe") => Some(Operation::RestartBackendSafe),
            Some("retry-app-retirement") => Some(Operation::RetryAppRetirement),
            _ => None,
        }
    } else {
        None
    };
    let Some(op) = op else {
        eprintln!(
            "usage: nanokvm-native-ctl {{activate-boot|boot-ready|status|running|kvm-running|backend-running|ensure-kvm|ensure-hwmon|ensure-backend|restart-backend|restart-backend-safe|retry-app-retirement|shutdown}}"
        );
        return ExitCode::from(64);
    };
    let Ok(mut channel) = Channel::connect() else {
        if op == Operation::Shutdown && Broker::verify_stopped().is_ok() {
            return ExitCode::SUCCESS;
        }
        eprintln!("cannot connect to protected native broker");
        return ExitCode::from(70);
    };
    if channel.begin(op).is_err() {
        return ExitCode::from(71);
    }
    let start = Instant::now();
    let backend_control = matches!(
        op,
        Operation::EnsureBackend | Operation::RestartBackend | Operation::RestartBackendSafe
    );
    let mut backend_wait = false;
    while start.elapsed() < Duration::from_secs(15) {
        match channel.poll() {
            Ok(Some(reply)) => {
                if op == Operation::BackendRunning && reply.code == Code::Unavailable {
                    return ExitCode::from(1);
                }
                if reply.code != Code::Ok && !(backend_wait && reply.code == Code::Unavailable) {
                    eprintln!("broker: {:?} {:?}", reply.code, reply.mode);
                    return ExitCode::from(71);
                }
                if backend_control {
                    if backend_wait && reply.code == Code::Ok {
                        return ExitCode::SUCCESS;
                    }
                    backend_wait = true;
                    if channel.begin(Operation::BackendRunning).is_err() {
                        return ExitCode::from(71);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                if op == Operation::Shutdown && reply.mode == Mode::Stopped {
                    // The reply precedes daemon return. Do not let S95 replace
                    // app files until the singleton lease really is released.
                    drop(channel);
                    while start.elapsed() < Duration::from_secs(15) {
                        match Broker::verify_stopped() {
                            Ok(()) => return ExitCode::SUCCESS,
                            Err(JournalError::Busy) => {
                                std::thread::sleep(Duration::from_millis(20))
                            }
                            Err(_) => return ExitCode::from(71),
                        }
                    }
                    return ExitCode::from(71);
                }
                let running = reply.mode == Mode::Running;
                let complete = match op {
                    Operation::EnsureKvm => running && reply.roles[0] == 2,
                    Operation::EnsureHwmon => running && reply.roles[1] == 2,
                    Operation::Observe => true,
                    Operation::BackendRunning => true,
                    Operation::RetryAppRetirement => running,
                    _ => false,
                };
                if complete {
                    if running_query && !running {
                        return ExitCode::from(1);
                    }
                    if query && (!running || reply.roles[0] != 2) {
                        return ExitCode::from(1);
                    }
                    println!("admission={:?} scopes={:?}", reply.mode, reply.roles);
                    return ExitCode::SUCCESS;
                }
                if channel.begin(Operation::Observe).is_err() {
                    return ExitCode::from(71);
                }
            }
            Ok(None) => {}
            Err(_) => {
                eprintln!("broker response lost; completion is unknown");
                return ExitCode::from(71);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!("broker deadline elapsed; ownership was not declared closed");
    ExitCode::from(71)
}
