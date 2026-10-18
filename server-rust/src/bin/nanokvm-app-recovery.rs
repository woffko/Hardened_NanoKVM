use nanokvm_rust_server::update::app_slot;
use std::{ffi::OsString, process::ExitCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Status,
    Recover,
}

fn parse(args: &[OsString]) -> Option<Mode> {
    if args.len() != 2 {
        return None;
    }
    match args[1].to_str()? {
        "status" => Some(Mode::Status),
        "recover" => Some(Mode::Recover),
        _ => None,
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().take(3).collect();
    let Some(mode) = parse(&args) else {
        eprintln!("usage: nanokvm-app-recovery status|recover");
        return ExitCode::from(64);
    };
    let result = match mode {
        Mode::Status => app_slot::status(),
        Mode::Recover => app_slot::recover(),
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
    fn only_fixed_status_and_recover_modes_are_accepted() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(parse(&args(&["helper", "status"])), Some(Mode::Status));
        assert_eq!(parse(&args(&["helper", "recover"])), Some(Mode::Recover));
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
