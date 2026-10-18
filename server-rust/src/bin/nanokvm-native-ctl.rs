use nanokvm_rust_server::native_owner::broker::ipc::{Channel, Code, Mode, Operation};
use std::{
    process::ExitCode,
    time::{Duration, Instant},
};
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let op = if args.len() == 1 {
        match args[0].to_str() {
            Some("status") => Some(Operation::Observe),
            Some("ensure-kvm") => Some(Operation::EnsureKvm),
            Some("ensure-hwmon") => Some(Operation::EnsureHwmon),
            Some("shutdown") => Some(Operation::Shutdown),
            _ => None,
        }
    } else {
        None
    };
    let Some(op) = op else {
        eprintln!("usage: nanokvm-native-ctl {{status|ensure-kvm|ensure-hwmon|shutdown}}");
        return ExitCode::from(64);
    };
    let Ok(mut channel) = Channel::connect() else {
        eprintln!("cannot connect to protected native broker");
        return ExitCode::from(70);
    };
    if channel.begin(op).is_err() {
        return ExitCode::from(71);
    }
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        match channel.poll() {
            Ok(Some(reply)) => {
                if reply.code != Code::Ok {
                    eprintln!("broker: {:?} {:?}", reply.code, reply.mode);
                    return ExitCode::from(71);
                }
                if op != Operation::Shutdown || reply.mode == Mode::Stopped {
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
