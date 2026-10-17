use nanokvm_rust_server::update::restore_runtime::exec_sshd_syntax_image_fixture;
use std::{path::Path, process::ExitCode};

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 4 {
        return ExitCode::from(64);
    }
    let Some(parent) = arguments[3].to_str().and_then(|s| s.parse().ok()) else {
        return ExitCode::from(64);
    };
    match exec_sshd_syntax_image_fixture(Path::new(&arguments[1]), parent, Path::new(&arguments[2]))
    {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}
