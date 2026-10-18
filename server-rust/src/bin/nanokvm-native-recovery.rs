use nanokvm_rust_server::native_owner::broker::recovery;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let operation = if args.len() == 1 {
        args[0].to_str()
    } else {
        None
    };
    let result = match operation {
        Some("status") => recovery::inspect(),
        Some("prepare") => recovery::prepare(),
        Some("complete") => match recovery::complete() {
            Ok(()) => {
                println!(
                    "native admission recovered; raw/restore state was not accepted or changed"
                );
                return ExitCode::SUCCESS;
            }
            Err(error) => Err(error),
        },
        _ => {
            eprintln!("usage: nanokvm-native-recovery {{status|prepare|complete}}");
            return ExitCode::from(64);
        }
    };
    match result {
        Ok(status) => {
            println!("native recovery: {status:?}; not a raw/restore completion receipt");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("native recovery refused: {error}; preserve recovery evidence");
            ExitCode::from(72)
        }
    }
}
