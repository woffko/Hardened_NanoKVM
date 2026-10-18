use std::process::ExitCode;
fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--serve")) || args.next().is_some() {
        eprintln!("usage: nanokvm-native-broker --serve");
        return ExitCode::from(64);
    }
    match nanokvm_rust_server::native_owner::broker::ipc::run_daemon() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("native broker did not complete; ownership may remain unresolved");
            ExitCode::from(72)
        }
    }
}
