use nanokvm_rust_server::update::app_slot;
use std::{ffi::OsString, process::ExitCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Status,
    Recover,
    Gate,
}

fn parse(args: &[OsString]) -> Option<Mode> {
    if args.len() != 2 {
        return None;
    }
    match args[1].to_str()? {
        "status" => Some(Mode::Status),
        "recover" => Some(Mode::Recover),
        "gate" => Some(Mode::Gate),
        _ => None,
    }
}

fn main() -> ExitCode {
    let _ = std::hint::black_box(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/support-abi-nanokvm-app-recovery.binding"
    )));
    let args: Vec<_> = std::env::args_os().take(3).collect();
    let Some(mode) = parse(&args) else {
        eprintln!("usage: nanokvm-app-recovery status|recover|gate");
        return ExitCode::from(64);
    };
    let result = match mode {
        Mode::Status => app_slot::status(),
        Mode::Recover => app_slot::recover(),
        Mode::Gate => app_slot::boot_gate(),
    };
    match result {
        Ok(status) => {
            println!("nanokvm-app-slot-v1 {}", status.label());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(match error {
                app_slot::SlotError::Busy => 75,
                app_slot::SlotError::Unsafe | app_slot::SlotError::Invalid => 78,
                app_slot::SlotError::Io(_) => 74,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fixed_status_recover_and_gate_modes_are_accepted() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(parse(&args(&["helper", "status"])), Some(Mode::Status));
        assert_eq!(parse(&args(&["helper", "recover"])), Some(Mode::Recover));
        assert_eq!(parse(&args(&["helper", "gate"])), Some(Mode::Gate));
        for values in [
            vec!["helper"],
            vec!["helper", "commit"],
            vec!["helper", "prepare"],
            vec!["helper", "recover", "/tmp/root"],
            vec!["helper", "--force"],
            vec!["helper", "--root=/data"],
            vec!["helper", "--journal=/data/forged"],
        ] {
            assert!(parse(&args(&values)).is_none());
        }
    }
}
