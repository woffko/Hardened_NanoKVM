use std::process::ExitCode;
fn main() -> ExitCode {
    let _ = std::hint::black_box(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/support-abi-nanokvm-native-broker.binding"
    )));
    let args: Vec<_> = std::env::args_os().skip(1).take(14).collect();
    if args.first().is_some_and(|first| first == "--raw-writer") {
        use nanokvm_rust_server::update::raw_writer;
        let Some(arguments) = raw_writer::parse_writer_arguments(&args[1..]) else {
            eprintln!("usage: nanokvm-native-broker --serve");
            return ExitCode::from(64);
        };
        // Returns only when it refused before touching anything.
        let error = raw_writer::run_device_writer(arguments);
        eprintln!("raw writer refused: {error}");
        return ExitCode::from(65);
    }
    if args.len() != 1 || args[0] != "--serve" {
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
