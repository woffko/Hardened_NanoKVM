use nanokvm_rust_server::native_owner::broker::ipc::{
    Channel, Code, JobChannel, JobCode, Mode, Operation, run_onboard_job, run_startup_job,
};
use nanokvm_rust_server::native_owner::broker::{Broker, JournalError, boot};
use std::{
    process::ExitCode,
    time::{Duration, Instant},
};

/// The job store's Onboard and Startup kinds.
const ONBOARD: u8 = 1;
const STARTUP: u8 = 3;

// Startup defaults, with the local tool policy, as one broker-owned job before
// S96 ensures the runtime: the broker never launches a pair without them.
fn startup_picoclaw() -> Result<(), ExitCode> {
    if JobChannel::connect().is_err() {
        eprintln!("cannot connect to the protected job transport; nothing was submitted");
        return Err(ExitCode::from(70));
    }
    match run_startup_job(Duration::from_secs(60)) {
        Ok(reply) => match (reply.code, reply.receipt) {
            (JobCode::Ok, [STARTUP, 8, 1 | 2, _]) => Ok(()),
            (code, receipt) => {
                eprintln!("picoclaw startup defaults: {code:?} {receipt:?}");
                Err(ExitCode::from(71))
            }
        },
        Err(_) => {
            eprintln!("job reply lost; completion is unknown");
            Err(ExitCode::from(71))
        }
    }
}

// S96 first configuration: one broker-owned Onboard job over the private job
// transport, never the service frame. Only its durable Changed or Noop
// receipt is success.
fn onboard_picoclaw() -> ExitCode {
    if nanokvm_rust_server::native_owner::picoclaw_home::Home::resolve().is_err() {
        eprintln!("invalid picoclaw home; no runtime action taken");
        return ExitCode::from(64);
    }
    let _pico_boot = match boot::require_ready() {
        Ok(permit) => permit,
        Err(error) => {
            eprintln!("picoclaw native boot: {error}");
            return ExitCode::from(78);
        }
    };
    if JobChannel::connect().is_err() {
        eprintln!("cannot connect to the protected job transport; nothing was submitted");
        return ExitCode::from(70);
    }
    // The broker bounds the one-shot at 60 s; import and retirement follow.
    match run_onboard_job(Duration::from_secs(90)) {
        Ok(reply) => match (reply.code, reply.receipt) {
            (JobCode::Ok, [ONBOARD, 8, 1 | 2, _]) => ExitCode::SUCCESS,
            (JobCode::Ok, [ONBOARD, 8, 3, _]) => {
                eprintln!("picoclaw onboarding did not complete; nothing was changed");
                ExitCode::from(71)
            }
            (code, _) => {
                eprintln!("picoclaw onboarding job: {code:?}");
                ExitCode::from(71)
            }
        },
        Err(_) => {
            eprintln!("job reply lost; completion is unknown");
            ExitCode::from(71)
        }
    }
}

fn main() -> ExitCode {
    let _ = std::hint::black_box(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/support-abi-nanokvm-native-ctl.binding"
    )));
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    // The backend's script runs. They are here because this program is static:
    // the backend's own binary would load the vendor libraries.
    if args.first().is_some_and(|arg| arg == "--script-supervisor") {
        std::process::exit(nanokvm_rust_server::system::script_supervisor::run(
            &args[1..],
        ));
    }
    if args.len() == 1 && args[0] == "picoclaw-home" {
        return match nanokvm_rust_server::native_owner::picoclaw_home::resolve() {
            Ok(home) => {
                println!("{}", home.display());
                ExitCode::SUCCESS
            }
            Err(_) => {
                eprintln!("invalid picoclaw home; no runtime action taken");
                ExitCode::from(64)
            }
        };
    }
    if args.len() == 1 && args[0] == "onboard-picoclaw" {
        return onboard_picoclaw();
    }
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
    let control_ready = args.len() == 1 && args[0] == "picoclaw-control-ready";
    let home_check = args.len() == 1
        && matches!(
            args[0].to_str(),
            Some("picoclaw-home-check" | "picoclaw-control-ready")
        );
    let pico_service = args.len() == 1
        && matches!(
            args[0].to_str(),
            Some("ensure-picoclaw" | "picoclaw-running" | "stop-picoclaw" | "picoclaw-stopped")
        );
    let selected_home = if home_check || pico_service {
        match nanokvm_rust_server::native_owner::picoclaw_home::Home::resolve() {
            Ok(home) => Some(home),
            Err(_) => {
                eprintln!("invalid picoclaw home; no runtime action taken");
                return ExitCode::from(64);
            }
        }
    } else {
        None
    };
    // The new S96 probes this entrypoint so an older ctl that understands only
    // the original service verbs cannot report an empty scope as legacy Stop.
    // Each actual operation also rechecks/retains the current boot profile;
    // this separate probe is not a lease for a later connection.
    let _pico_boot = if pico_service || control_ready {
        match boot::require_ready() {
            Ok(permit) => Some(permit),
            Err(error) => {
                eprintln!("picoclaw native boot: {error}");
                return ExitCode::from(78);
            }
        }
    } else {
        None
    };
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
            Some("picoclaw-home-check" | "picoclaw-control-ready") => {
                Some(Operation::CheckPicoclawHome)
            }
            Some("ensure-picoclaw") => Some(Operation::EnsurePicoclaw),
            Some("picoclaw-running") => Some(Operation::PicoclawRunning),
            Some("stop-picoclaw") => Some(Operation::StopPicoclaw),
            Some("picoclaw-stopped") => Some(Operation::PicoclawStopped),
            _ => None,
        }
    } else {
        None
    };
    let Some(op) = op else {
        eprintln!(
            "usage: nanokvm-native-ctl {{activate-boot|boot-ready|status|running|kvm-running|backend-running|ensure-kvm|ensure-hwmon|ensure-backend|restart-backend|restart-backend-safe|retry-app-retirement|picoclaw-home|picoclaw-home-check|picoclaw-control-ready|ensure-picoclaw|picoclaw-running|stop-picoclaw|picoclaw-stopped|onboard-picoclaw|shutdown}}"
        );
        return ExitCode::from(64);
    };
    if op == Operation::EnsurePicoclaw
        && let Err(code) = startup_picoclaw()
    {
        return code;
    }
    let Ok(mut channel) = Channel::connect() else {
        if op == Operation::Shutdown && Broker::verify_stopped().is_ok() {
            return ExitCode::SUCCESS;
        }
        eprintln!("cannot connect to protected native broker");
        return ExitCode::from(70);
    };
    let begin = if let Some(home) = &selected_home {
        if pico_service {
            channel.picoclaw_service(op, home)
        } else {
            channel.check_picoclaw_home(home)
        }
    } else {
        channel.begin(op)
    };
    if begin.is_err() {
        return ExitCode::from(71);
    }
    let start = Instant::now();
    let backend_control = matches!(
        op,
        Operation::EnsureBackend | Operation::RestartBackend | Operation::RestartBackendSafe
    );
    let mut backend_wait = false;
    let mut pico_wait = false;
    while start.elapsed() < Duration::from_secs(15) {
        match channel.poll() {
            Ok(Some(reply)) => {
                if matches!(
                    op,
                    Operation::BackendRunning
                        | Operation::PicoclawRunning
                        | Operation::PicoclawStopped
                ) && reply.code == Code::Unavailable
                {
                    return ExitCode::from(1);
                }
                if reply.code != Code::Ok
                    && !((backend_wait || pico_wait) && reply.code == Code::Unavailable)
                {
                    eprintln!("broker: {:?} {:?}", reply.code, reply.mode);
                    return ExitCode::from(71);
                }
                if pico_service {
                    if matches!(op, Operation::PicoclawRunning | Operation::PicoclawStopped)
                        || (pico_wait && reply.code == Code::Ok)
                    {
                        return ExitCode::SUCCESS;
                    }
                    let query = match op {
                        Operation::StopPicoclaw => Operation::PicoclawStopped,
                        _ => Operation::PicoclawRunning,
                    };
                    let Some(home) = &selected_home else {
                        return ExitCode::from(71);
                    };
                    pico_wait = true;
                    if channel.picoclaw_service(query, home).is_err() {
                        return ExitCode::from(71);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                if let Some(home) = &selected_home {
                    if !control_ready {
                        println!("{}", home.path().display());
                    }
                    return ExitCode::SUCCESS;
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
