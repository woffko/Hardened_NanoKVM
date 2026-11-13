use nanokvm_rust_server::update::raw_restore;
use std::process::ExitCode;

fn main() -> ExitCode {
    match raw_restore::run_early() {
        Ok(outcome) => {
            println!("raw early restore: {outcome:?}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("raw early restore blocked: {error}");
            ExitCode::from(78)
        }
    }
}
