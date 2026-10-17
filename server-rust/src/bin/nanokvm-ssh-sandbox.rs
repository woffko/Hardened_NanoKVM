use nanokvm_rust_server::update::restore_runtime::exec_sshd_syntax;
use std::{path::Path, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 || args[1] != "--root" || args[3] != "--parent-pid" {
        eprintln!("usage: nanokvm-ssh-sandbox --root PRIVATE_PREPARED_ROOT --parent-pid PID");
        return ExitCode::from(64);
    }
    let Some(parent) = args[4].to_str().and_then(|s| s.parse::<u32>().ok()) else {
        return ExitCode::from(64);
    };
    match exec_sshd_syntax(Path::new(&args[2]), parent) {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}
