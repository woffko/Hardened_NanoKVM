use super::*;
use crate::native_owner::broker::ipc::picoclaw::work::Fixture as ImportFixture;
use crate::update::{operation_lock::ProcessLock, state_writers::StateWriters};

const OPS: [Operation; 6] = [
    Operation::EnsurePicoclaw,
    Operation::PicoclawRunning,
    Operation::StopPicoclaw,
    Operation::PicoclawStopped,
    Operation::OnboardPicoclaw,
    Operation::PicoclawOnboardComplete,
];

fn frame(op: Operation, home: &Home, serial: u64) -> [u8; FRAME] {
    let mut frame = request(op, serial);
    frame[16..].copy_from_slice(&home.fingerprint());
    frame
}

fn call(engine: &mut Engine, op: Operation) -> Reply {
    engine.request_frame(7, op, &frame(op, &Home::default(), 1))
}

fn configured(root: &Path) -> Engine {
    fs::write(root.join("pico-generation"), [1; 32]).unwrap();
    engine(root)
}

fn ready(engine: &mut Engine) {
    until(|| {
        engine.tick();
        call(engine, Operation::PicoclawRunning).code == Code::Ok
    });
}

fn close(mut engine: Engine) {
    assert_eq!(engine.request(7, Operation::Shutdown).code, Code::Ok);
    until(|| {
        engine.tick();
        engine.mode == Mode::Stopped
    });
}

#[test]
fn each_fixed_service_operation_requires_a_full_home_bound_frame() {
    for (op, byte) in OPS.into_iter().zip([14, 15, 16, 17, 18, 19]) {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut channel = Channel::verified(stream, nix::unistd::geteuid().as_raw()).unwrap();
        assert_eq!(
            channel.begin(op).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(channel.flight.is_none());
        channel.picoclaw_service(op, &Home::default()).unwrap();
        let bytes = channel.flight.as_ref().unwrap().bytes;
        let mut prefix = *b"NKC2\0\0\0\0\0\0\0\0\0\0\0\x01";
        prefix[4] = byte;
        assert_eq!(&bytes[..16], &prefix);
        assert_eq!(&bytes[16..], &Home::default().fingerprint());
        assert_eq!(parse_request(&bytes), Some((op, 1)));
        assert_eq!(
            channel
                .picoclaw_service(op, &Home::default())
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn onboard_probe() {
    let Some(root) = std::env::var_os("NANOKVM_NATIVE_ONBOARD_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    fs::write(root.join("onboard-pid"), std::process::id().to_string()).unwrap();
    let mut control = UnixStream::from(rustix::io::dup(std::io::stdin()).unwrap());
    control.set_nonblocking(true).unwrap();
    control.write_all(b"R").unwrap();
    let mut stopped = false;
    until(|| {
        let mut byte = [0];
        match control.read(&mut byte) {
            Ok(1) => {
                assert_eq!(byte, *b"S");
                stopped = true;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!("onboard control lost: {other:?}"),
        }
        if stopped {
            fs::write(root.join("onboard-stopping"), b"stopping").unwrap();
        }
        (stopped && !root.join("onboard-stop-hold").exists())
            || root.join("onboard-release").exists()
    });
    if root.join("onboard-missing-receipt").exists() {
        return;
    }
    if stopped {
        control.write_all(b"D\0").unwrap();
    } else if root.join("onboard-fail").exists() {
        control.write_all(b"D\x02").unwrap();
        std::process::exit(71);
    } else {
        control.write_all(b"D\x01").unwrap();
    }
}

#[test]
fn onboard_retains_both_admissions_after_caller_loss_until_successful_closure() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    assert_eq!(call(&mut engine, Operation::OnboardPicoclaw).code, Code::Ok);
    until(|| {
        engine.tick();
        root.path().join("onboard-pid").exists()
    });
    engine.disconnected(7);
    assert!(engine.picoclaw_onboard.is_some());
    let parent = File::open(root.path()).unwrap();
    assert!(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).is_err());
    assert!(
        StateWriters::for_test_parent(parent.try_clone().unwrap())
            .configuration()
            .is_err()
    );
    assert_eq!(
        call(&mut engine, Operation::PicoclawRunning).code,
        Code::Unavailable
    );
    assert_eq!(
        call(&mut engine, Operation::PicoclawOnboardComplete).code,
        Code::Unavailable
    );
    for op in [Operation::OnboardPicoclaw, Operation::EnsurePicoclaw] {
        assert_eq!(call(&mut engine, op).code, Code::Busy);
    }
    for op in [
        Operation::Pause,
        Operation::RestartBackend,
        Operation::Shutdown,
    ] {
        assert_eq!(engine.request(7, op).code, Code::Busy);
    }
    fs::write(root.path().join("onboard-release"), b"release").unwrap();
    until(|| {
        engine.tick();
        engine.picoclaw_onboard.is_none()
    });
    assert_eq!(
        call(&mut engine, Operation::PicoclawOnboardComplete).code,
        Code::Ok
    );
    drop(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap());
    drop(
        StateWriters::for_test_parent(parent)
            .configuration()
            .unwrap(),
    );
    close(engine);
}

#[test]
fn onboard_import_runs_off_loop_and_stop_cannot_abandon_its_owner() {
    for stop_during_import in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut engine = configured(root.path());
        let (entered, observed) = std::sync::mpsc::channel();
        // Declared after Engine: disconnect this gate before joined teardown
        // even if an assertion fails while the import worker is held.
        let (resume, resumed) = std::sync::mpsc::channel();
        assert_eq!(call(&mut engine, Operation::OnboardPicoclaw).code, Code::Ok);
        engine
            .picoclaw_onboard
            .as_mut()
            .unwrap()
            .work
            .set_fixture(ImportFixture::Block {
                entered,
                resume: resumed,
            });
        fs::write(root.path().join("onboard-release"), b"release").unwrap();
        until(|| {
            engine.tick();
            observed.try_recv().is_ok()
        });
        engine.disconnected(7);
        let parent = File::open(root.path()).unwrap();
        for _ in 0..20 {
            let start = Instant::now();
            assert_eq!(engine.request(8, Operation::Observe).code, Code::Ok);
            assert!(start.elapsed() < Duration::from_millis(250));
            assert!(engine.picoclaw_onboard.is_some());
            assert!(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).is_err());
            assert!(
                StateWriters::for_test_parent(parent.try_clone().unwrap())
                    .configuration()
                    .is_err()
            );
            assert_eq!(
                call(&mut engine, Operation::EnsurePicoclaw).code,
                Code::Busy
            );
        }
        if stop_during_import {
            assert_eq!(call(&mut engine, Operation::StopPicoclaw).code, Code::Ok);
            let start = Instant::now();
            engine.tick();
            assert!(start.elapsed() < Duration::from_millis(250));
            assert!(engine.picoclaw_onboard.is_some());
        }
        assert_eq!(
            call(&mut engine, Operation::PicoclawStopped).code,
            Code::Unavailable
        );
        resume.send(()).unwrap();
        until(|| {
            engine.tick();
            engine.picoclaw_onboard.is_none()
        });
        assert_eq!(
            call(&mut engine, Operation::PicoclawOnboardComplete).code,
            if stop_during_import {
                Code::Invalid
            } else {
                Code::Ok
            }
        );
        assert_eq!(call(&mut engine, Operation::PicoclawStopped).code, Code::Ok);
        drop(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap());
        drop(
            StateWriters::for_test_parent(parent)
                .configuration()
                .unwrap(),
        );
        close(engine);
    }
}

#[test]
fn onboard_import_error_panic_and_spawn_failure_retain_admissions_without_retry() {
    for fixture in [
        ImportFixture::Fail,
        ImportFixture::Panic,
        ImportFixture::SpawnFailure,
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut engine = configured(root.path());
        assert_eq!(call(&mut engine, Operation::OnboardPicoclaw).code, Code::Ok);
        engine
            .picoclaw_onboard
            .as_mut()
            .unwrap()
            .work
            .set_fixture(fixture);
        fs::write(root.path().join("onboard-release"), b"release").unwrap();
        until(|| {
            engine.tick();
            engine.mode == Mode::Uncertain
        });
        assert!(matches!(
            engine.picoclaw_status,
            Some(Status::Closed(Completion::SuccessfulExit))
        ));
        let parent = File::open(root.path()).unwrap();
        for _ in 0..3 {
            engine.disconnected(7);
            engine.tick();
            assert!(engine.picoclaw_onboard.is_some());
            assert!(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).is_err());
            assert!(
                StateWriters::for_test_parent(parent.try_clone().unwrap())
                    .configuration()
                    .is_err()
            );
            for operation in OPS {
                assert_eq!(call(&mut engine, operation).code, Code::Uncertain);
            }
            assert_eq!(engine.request(8, Operation::Shutdown).code, Code::Uncertain);
        }
        // Explicit test teardown is not recovery or a successful receipt.
        drop(engine);
        drop(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap());
        drop(
            StateWriters::for_test_parent(parent)
                .configuration()
                .unwrap(),
        );
    }
}

#[test]
fn onboard_late_success_cannot_release_a_preexisting_uncertain_broker() {
    for before_import in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut engine = configured(root.path());
        let (entered, observed) = std::sync::mpsc::channel();
        let (resume, resumed) = std::sync::mpsc::channel();
        assert_eq!(call(&mut engine, Operation::OnboardPicoclaw).code, Code::Ok);
        engine
            .picoclaw_onboard
            .as_mut()
            .unwrap()
            .work
            .set_fixture(ImportFixture::Block {
                entered,
                resume: resumed,
            });
        if before_import {
            engine.mode = Mode::Uncertain;
        }
        fs::write(root.path().join("onboard-release"), b"release").unwrap();
        if before_import {
            until(|| {
                engine.tick();
                matches!(
                    engine.picoclaw_status,
                    Some(Status::Closed(Completion::SuccessfulExit))
                )
            });
            assert!(matches!(
                observed.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
        } else {
            until(|| {
                engine.tick();
                observed.try_recv().is_ok()
            });
            // Test the Engine-level uncertainty fence independently of Group's
            // existing sticky native ownership latch.
            engine.mode = Mode::Uncertain;
            resume.send(()).unwrap();
            until(|| {
                engine
                    .picoclaw_onboard
                    .as_ref()
                    .unwrap()
                    .work
                    .worker_finished_fixture()
            });
        }
        let parent = File::open(root.path()).unwrap();
        for _ in 0..3 {
            engine.tick();
            assert!(engine.picoclaw_onboard.is_some());
            assert_eq!(engine.picoclaw_onboard_result, None);
            assert_eq!(
                call(&mut engine, Operation::PicoclawOnboardComplete).code,
                Code::Uncertain
            );
            assert!(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).is_err());
            assert!(
                StateWriters::for_test_parent(parent.try_clone().unwrap())
                    .configuration()
                    .is_err()
            );
        }
        drop(engine);
    }
}

#[test]
fn onboard_actual_partial_import_retains_engine_and_both_admissions() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("root/.picoclaw")).unwrap();
    fs::set_permissions(root.path().join("root"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        root.path().join("root/.picoclaw"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let child = std::process::Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_owner::broker::ipc::tests::picoclaw::onboard_partial_import_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_ONBOARD_IMPORT_ROOT", root.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    struct OwnedChild(Option<std::process::Child>);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let mut owned = OwnedChild(Some(child));
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if owned.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "partial-import namespace fixture timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = owned.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success(), "partial import: {output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("actual-partial-import-retained")
    );
}

#[test]
fn onboard_engine_teardown_joins_import_before_releasing_native_singleton() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    assert_eq!(call(&mut engine, Operation::OnboardPicoclaw).code, Code::Ok);
    std::thread::scope(|scope| {
        let (entered, observed) = std::sync::mpsc::channel();
        // Scoped closure drops this gate before scope joins on assertion panic.
        let (resume, resumed) = std::sync::mpsc::channel();
        engine
            .picoclaw_onboard
            .as_mut()
            .unwrap()
            .work
            .set_fixture(ImportFixture::Block {
                entered,
                resume: resumed,
            });
        fs::write(root.path().join("onboard-release"), b"release").unwrap();
        until(|| {
            engine.tick();
            observed.try_recv().is_ok()
        });
        let (dropping, drop_entered) = std::sync::mpsc::channel();
        let (finished, complete) = std::sync::mpsc::channel();
        let teardown = scope.spawn(move || {
            dropping.send(()).unwrap();
            drop(engine);
            finished.send(()).unwrap();
        });
        drop_entered.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            complete.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        let parent = File::open(root.path()).unwrap();
        assert!(matches!(
            journal::Store::fixture(&parent, nix::unistd::geteuid().as_raw(), BOOT),
            Err(crate::native_owner::broker::JournalError::Busy)
        ));
        assert!(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).is_err());
        assert!(
            StateWriters::for_test_parent(parent.try_clone().unwrap())
                .configuration()
                .is_err()
        );
        resume.send(()).unwrap();
        teardown.join().unwrap();
        complete.recv_timeout(Duration::from_secs(1)).unwrap();
    });
}

#[test]
fn onboard_partial_import_child() {
    use std::os::unix::fs::PermissionsExt;
    let Some(root) = std::env::var_os("NANOKVM_ONBOARD_IMPORT_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    // Launch the synthetic fixed native one-shot before chroot so its executable
    // remains available. Controller fds/reap and actual import run afterward.
    let mut engine = configured(root);
    assert_eq!(call(&mut engine, Operation::OnboardPicoclaw).code, Code::Ok);
    until(|| root.join("onboard-pid").exists());
    fs::write(root.join("onboard-release"), b"release").unwrap();
    nix::unistd::chroot(root).unwrap();
    std::env::set_current_dir("/").unwrap();
    let home = Path::new("/root/.picoclaw");
    engine
        .picoclaw_onboard
        .as_mut()
        .unwrap()
        .work
        .prepare_stage_fixture(&home.join("config.json"), 1);
    let stage = home.join(crate::native_owner::picoclaw_home::ONBOARD_DIRECTORY);
    fs::create_dir(stage.join("workspace")).unwrap();
    for (path, bytes) in [
        (
            stage.join("config.json"),
            serde_json::to_vec(&serde_json::json!({
                "agents": {"defaults": {"workspace": stage.join("workspace")}},
                "model_list": []
            }))
            .unwrap(),
        ),
        (stage.join(".security.yml"), b"model_list: []\n".to_vec()),
        (
            stage.join("workspace/first"),
            b"first synthetic member".to_vec(),
        ),
        (
            stage.join("workspace/second"),
            b"second synthetic member".to_vec(),
        ),
    ] {
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    assert!(matches!(
        engine.picoclaw_status,
        Some(Status::Closed(Completion::SuccessfulExit))
    ));
    assert_eq!(
        fs::read(home.join("workspace/first")).unwrap(),
        b"first synthetic member"
    );
    assert!(!home.join("workspace/second").exists());
    assert!(!home.join("config.json").exists());
    assert!(!home.join(".security.yml").exists());
    assert!(stage.join("workspace/second").is_file());
    let parent = File::open("/").unwrap();
    for _ in 0..3 {
        engine.disconnected(7);
        engine.tick();
        assert!(engine.picoclaw_onboard.is_some());
        assert!(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).is_err());
        assert!(
            StateWriters::for_test_parent(parent.try_clone().unwrap())
                .configuration()
                .is_err()
        );
        assert_eq!(
            call(&mut engine, Operation::EnsurePicoclaw).code,
            Code::Uncertain
        );
    }
    let home_file = File::open(home).unwrap();
    assert_eq!(
        rustix::fs::flock(
            &home_file,
            rustix::fs::FlockOperation::NonBlockingLockExclusive
        ),
        Err(rustix::io::Errno::WOULDBLOCK)
    );
    drop(engine);
    assert!(stage.join("workspace/second").is_file());
    println!("actual-partial-import-retained");
}

#[test]
fn onboard_stop_and_deadline_never_report_a_successful_import() {
    for deadline in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut engine = configured(root.path());
        fs::write(root.path().join("onboard-stop-hold"), b"hold").unwrap();
        assert_eq!(call(&mut engine, Operation::OnboardPicoclaw).code, Code::Ok);
        until(|| {
            engine.tick();
            engine.picoclaw_status == Some(Status::Running)
        });
        if deadline {
            engine.picoclaw_onboard.as_mut().unwrap().deadline = Instant::now();
            engine.tick();
        } else {
            assert_eq!(call(&mut engine, Operation::StopPicoclaw).code, Code::Ok);
        }
        until(|| root.path().join("onboard-stopping").exists());
        engine.tick();
        assert!(engine.picoclaw_onboard.is_some());
        assert_eq!(
            call(&mut engine, Operation::PicoclawStopped).code,
            Code::Unavailable
        );
        fs::remove_file(root.path().join("onboard-stop-hold")).unwrap();
        until(|| {
            engine.tick();
            engine.picoclaw_onboard.is_none()
        });
        assert_eq!(
            call(&mut engine, Operation::PicoclawOnboardComplete).code,
            Code::Invalid
        );
        assert_eq!(call(&mut engine, Operation::PicoclawStopped).code, Code::Ok);
        close(engine);
    }
}

#[test]
fn onboard_failed_exit_and_missing_receipt_are_not_completion() {
    for missing in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut engine = configured(root.path());
        fs::write(
            root.path().join(if missing {
                "onboard-missing-receipt"
            } else {
                "onboard-fail"
            }),
            b"fixture",
        )
        .unwrap();
        assert_eq!(call(&mut engine, Operation::OnboardPicoclaw).code, Code::Ok);
        until(|| root.path().join("onboard-pid").exists());
        let pid = fs::read_to_string(root.path().join("onboard-pid")).unwrap();
        fs::write(root.path().join("onboard-release"), b"release").unwrap();
        until(|| {
            engine.tick();
            if missing {
                engine.mode == Mode::Uncertain
            } else {
                engine.picoclaw_onboard.is_none()
            }
        });
        if missing {
            until(|| {
                engine.tick();
                !Path::new(&format!("/proc/{pid}")).exists()
            });
            assert!(engine.picoclaw_onboard.is_some());
            assert_eq!(
                call(&mut engine, Operation::PicoclawOnboardComplete).code,
                Code::Uncertain
            );
            assert!(
                StateWriters::for_test_parent(File::open(root.path()).unwrap())
                    .configuration()
                    .is_err()
            );
            drop(engine); // Known childless/reaped fixture only, no closure claim.
        } else {
            assert_eq!(
                call(&mut engine, Operation::PicoclawOnboardComplete).code,
                Code::Invalid
            );
            close(engine);
        }
    }
}

#[test]
fn onboard_refuses_live_gateway_and_admission_contention_before_starting_a_writer() {
    for conflict in ["gateway", "update", "config"] {
        let root = tempfile::tempdir().unwrap();
        let mut engine = configured(root.path());
        if conflict == "gateway" {
            assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
            ready(&mut engine);
        }
        let parent = File::open(root.path()).unwrap();
        let update = (conflict == "update")
            .then(|| ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap());
        let config = (conflict == "config").then(|| {
            StateWriters::for_test_parent(parent.try_clone().unwrap())
                .configuration()
                .unwrap()
        });
        assert_eq!(
            call(&mut engine, Operation::OnboardPicoclaw).code,
            Code::Busy
        );
        assert!(!root.path().join("onboard-pid").exists());
        assert!(engine.picoclaw_onboard.is_none());
        if conflict == "gateway" {
            assert_eq!(call(&mut engine, Operation::PicoclawRunning).code, Code::Ok);
        }
        drop(config);
        drop(update);
        close(engine);
    }
}

#[test]
fn real_endpoint_onboard_survives_disconnected_client_and_releases_config_only_after_completion() {
    let root = tempfile::tempdir().unwrap();
    serve(root.path(), nix::unistd::geteuid().as_raw(), || {
        let mut channel = connect(root.path());
        assert_eq!(
            exchange_service(&mut channel, Operation::OnboardPicoclaw).code,
            Code::Ok
        );
        until(|| root.path().join("onboard-pid").exists());
        drop(channel);
        let parent = File::open(root.path()).unwrap();
        assert!(
            StateWriters::for_test_parent(parent.try_clone().unwrap())
                .configuration()
                .is_err()
        );
        let mut observer = connect(root.path());
        assert_eq!(
            exchange_service(&mut observer, Operation::PicoclawOnboardComplete).code,
            Code::Unavailable
        );
        fs::write(root.path().join("onboard-release"), b"release").unwrap();
        until(|| {
            exchange_service(&mut observer, Operation::PicoclawOnboardComplete).code == Code::Ok
        });
        drop(
            StateWriters::for_test_parent(parent)
                .configuration()
                .unwrap(),
        );
    });
}

#[test]
fn a_wrong_home_refuses_even_mutating_commands_before_any_lifecycle_tick() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    engine.wanted = [true; 2];
    engine.backend_wanted = true;
    for op in OPS {
        let mut bytes = frame(op, &Home::default(), 1);
        bytes[FRAME - 1] ^= 1;
        assert_eq!(engine.request_frame(7, op, &bytes).code, Code::Invalid);
    }
    for name in [
        "picoclaw",
        "backend",
        "kvm",
        "hwmon",
        "native-runtime-owner/state",
    ] {
        assert!(!root.path().join(name).exists());
    }
    assert_eq!(
        call(&mut engine, Operation::PicoclawRunning).code,
        Code::Unavailable
    );
    assert_eq!(call(&mut engine, Operation::PicoclawStopped).code, Code::Ok);
    assert!(
        !root.path().join("backend").exists(),
        "queries do not tick wanted work"
    );
    engine.wanted = [false; 2];
    engine.backend_wanted = false;
    close(engine);
}

#[test]
fn fixed_ensure_binds_generation_without_adoption_or_implicit_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    ready(&mut engine);
    let first = fs::read(root.path().join("picoclaw")).unwrap();
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), first);
    fs::write(root.path().join("pico-generation"), [2; 32]).unwrap();
    assert_eq!(
        call(&mut engine, Operation::EnsurePicoclaw).code,
        Code::Invalid
    );
    assert_eq!(engine.picoclaw_status, Some(Status::Running));
    assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), first);
    assert_eq!(call(&mut engine, Operation::StopPicoclaw).code, Code::Ok);
    until(|| {
        engine.tick();
        call(&mut engine, Operation::PicoclawStopped).code == Code::Ok
    });
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    ready(&mut engine);
    assert_ne!(fs::read(root.path().join("picoclaw")).unwrap(), first);
    close(engine);
}

#[test]
fn owned_stop_joins_with_config_held_and_retains_update_after_caller_loss() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    for op in [
        Operation::EnsureKvm,
        Operation::EnsureHwmon,
        Operation::EnsureBackend,
    ] {
        assert_eq!(engine.request(7, op).code, Code::Ok);
    }
    until(|| {
        engine.tick();
        engine.roles == [2; 2] && engine.backend_status == Some(Status::Running)
    });
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    ready(&mut engine);
    let backend = fs::read(root.path().join("backend")).unwrap();
    let kvm = fs::read(root.path().join("kvm")).unwrap();
    let writers = StateWriters::for_test_parent(File::open(root.path()).unwrap());
    let config = writers.configuration().unwrap();
    fs::write(root.path().join("picoclaw-stop-hold"), b"hold").unwrap();
    assert_eq!(call(&mut engine, Operation::StopPicoclaw).code, Code::Ok);
    until(|| root.path().join("picoclaw-stopping").exists());
    engine.tick();
    assert_eq!(
        call(&mut engine, Operation::PicoclawStopped).code,
        Code::Unavailable
    );
    assert!(engine.picoclaw_stop.is_some());
    assert!(
        ProcessLock::from_parent(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw()
        )
        .is_err()
    );
    assert_eq!(
        call(&mut engine, Operation::EnsurePicoclaw).code,
        Code::Busy
    );
    for op in [
        Operation::Pause,
        Operation::RestartBackend,
        Operation::Shutdown,
    ] {
        assert_eq!(engine.request(7, op).code, Code::Busy);
    }
    engine.disconnected(7);
    assert!(!engine.abandoned);
    assert!(engine.picoclaw_stop.is_some());
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    fs::remove_file(root.path().join("picoclaw-stop-hold")).unwrap();
    until(|| {
        engine.tick();
        engine.picoclaw_stop.is_none()
    });
    assert_eq!(call(&mut engine, Operation::PicoclawStopped).code, Code::Ok);
    assert_eq!(engine.backend_status, Some(Status::Running));
    assert_eq!(engine.roles, [2; 2]);
    assert_eq!(fs::read(root.path().join("backend")).unwrap(), backend);
    assert_eq!(fs::read(root.path().join("kvm")).unwrap(), kvm);
    drop(
        ProcessLock::from_parent(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw(),
        )
        .unwrap(),
    );
    drop(config);
    close(engine);
}

#[test]
fn start_contention_and_missing_generation_never_publish_native_intent() {
    for conflict in ["config", "update", "generation"] {
        let root = tempfile::tempdir().unwrap();
        let mut engine = configured(root.path());
        let writers = StateWriters::for_test_parent(File::open(root.path()).unwrap());
        let config = (conflict == "config").then(|| writers.configuration().unwrap());
        let update = (conflict == "update").then(|| {
            ProcessLock::from_parent(
                &File::open(root.path()).unwrap(),
                nix::unistd::geteuid().as_raw(),
            )
            .unwrap()
        });
        if conflict == "generation" {
            fs::remove_file(root.path().join("pico-generation")).unwrap();
        }
        assert_eq!(
            call(&mut engine, Operation::EnsurePicoclaw).code,
            if conflict == "generation" {
                Code::Unavailable
            } else {
                Code::Busy
            }
        );
        assert!(!root.path().join("picoclaw").exists());
        assert!(!root.path().join("native-runtime-owner/state").exists());
        drop(update);
        drop(config);
        close(engine);
    }
}

fn exchange_service(channel: &mut Channel, op: Operation) -> Reply {
    channel.picoclaw_service(op, &Home::default()).unwrap();
    let mut reply = None;
    until(|| {
        reply = channel.poll().unwrap();
        reply.is_some()
    });
    reply.unwrap()
}

#[test]
fn real_endpoint_stop_survives_its_client_and_does_not_stop_the_backend() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("pico-generation"), [3; 32]).unwrap();
    serve(root.path(), nix::unistd::geteuid().as_raw(), || {
        let mut channel = connect(root.path());
        assert_eq!(
            exchange(&mut channel, Operation::EnsureBackend).code,
            Code::Ok
        );
        until(|| exchange(&mut channel, Operation::BackendRunning).code == Code::Ok);
        assert_eq!(
            exchange_service(&mut channel, Operation::EnsurePicoclaw).code,
            Code::Ok
        );
        until(|| exchange_service(&mut channel, Operation::PicoclawRunning).code == Code::Ok);
        let backend = fs::read(root.path().join("backend")).unwrap();
        fs::write(root.path().join("picoclaw-stop-hold"), b"hold").unwrap();
        assert_eq!(
            exchange_service(&mut channel, Operation::StopPicoclaw).code,
            Code::Ok
        );
        until(|| root.path().join("picoclaw-stopping").exists());
        drop(channel);
        let mut observer = connect(root.path());
        assert_eq!(
            exchange_service(&mut observer, Operation::PicoclawStopped).code,
            Code::Unavailable
        );
        fs::remove_file(root.path().join("picoclaw-stop-hold")).unwrap();
        until(|| exchange_service(&mut observer, Operation::PicoclawStopped).code == Code::Ok);
        assert_eq!(
            exchange(&mut observer, Operation::BackendRunning).code,
            Code::Ok
        );
        assert_eq!(fs::read(root.path().join("backend")).unwrap(), backend);
    });
}

#[test]
fn missing_stop_receipt_pins_uncertainty_even_after_the_childless_owner_exits() {
    let root = tempfile::tempdir().unwrap();
    let mut engine = configured(root.path());
    assert_eq!(call(&mut engine, Operation::EnsurePicoclaw).code, Code::Ok);
    ready(&mut engine);
    let pid: u32 = fs::read_to_string(root.path().join("picoclaw"))
        .unwrap()
        .parse()
        .unwrap();
    let process = std::path::PathBuf::from(format!("/proc/{pid}"));
    fs::write(
        root.path().join("picoclaw-missing-receipt"),
        b"fixture only",
    )
    .unwrap();
    assert_eq!(call(&mut engine, Operation::StopPicoclaw).code, Code::Ok);
    until(|| {
        engine.tick();
        engine.mode == Mode::Uncertain
    });
    // Test-only observation of this exact known fixture child: keep polling
    // the retained controller until try_wait has also reaped it. This is not
    // a production PID-based closure/adoption mechanism.
    until(|| {
        engine.tick();
        !process.exists()
    });
    assert_eq!(
        call(&mut engine, Operation::PicoclawStopped).code,
        Code::Uncertain
    );
    assert_eq!(
        call(&mut engine, Operation::EnsurePicoclaw).code,
        Code::Uncertain
    );
    assert!(engine.picoclaw_stop.is_some());
    assert!(
        ProcessLock::from_parent(
            &File::open(root.path()).unwrap(),
            nix::unistd::geteuid().as_raw()
        )
        .is_err()
    );
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
    // This fixture owner is childless and reaped. Dropping it is not a closure
    // claim, a production recovery path, or permission to relaunch a native tree.
    drop(engine);
    assert_eq!(
        fs::read(root.path().join("native-runtime-owner/state")).unwrap()[44],
        1
    );
}

#[test]
fn cached_service_replay_never_restarts_or_stops_a_later_owned_generation() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("pico-generation"), [1; 32]).unwrap();
    serve(root.path(), nix::unistd::geteuid().as_raw(), || {
        let mut raw = connect(root.path());
        raw.stream.set_nonblocking(false).unwrap();
        raw.stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let start = frame(Operation::EnsurePicoclaw, &Home::default(), 1);
        raw.stream.write_all(&start).unwrap();
        let first = raw_reply(&mut raw.stream).unwrap();
        assert_eq!(Reply::parse(&first, 1).unwrap().code, Code::Ok);
        let mut observer = connect(root.path());
        until(|| exchange_service(&mut observer, Operation::PicoclawRunning).code == Code::Ok);
        let old = fs::read(root.path().join("picoclaw")).unwrap();
        fs::write(root.path().join("pico-generation"), [2; 32]).unwrap();
        raw.stream.write_all(&start).unwrap();
        assert_eq!(raw_reply(&mut raw.stream).unwrap(), first);
        let changed = frame(Operation::EnsurePicoclaw, &Home::default(), 2);
        raw.stream.write_all(&changed).unwrap();
        assert_eq!(
            Reply::parse(&raw_reply(&mut raw.stream).unwrap(), 2)
                .unwrap()
                .code,
            Code::Invalid
        );
        assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), old);
        let stop = frame(Operation::StopPicoclaw, &Home::default(), 3);
        raw.stream.write_all(&stop).unwrap();
        let stopped = raw_reply(&mut raw.stream).unwrap();
        assert_eq!(Reply::parse(&stopped, 3).unwrap().code, Code::Ok);
        until(|| exchange_service(&mut observer, Operation::PicoclawStopped).code == Code::Ok);
        assert_eq!(
            exchange_service(&mut observer, Operation::EnsurePicoclaw).code,
            Code::Ok
        );
        until(|| exchange_service(&mut observer, Operation::PicoclawRunning).code == Code::Ok);
        let new = fs::read(root.path().join("picoclaw")).unwrap();
        assert_ne!(new, old);
        // Last-request replay returns the old admission receipt, not another
        // Stop against a different process created after that request finished.
        raw.stream.write_all(&stop).unwrap();
        assert_eq!(raw_reply(&mut raw.stream).unwrap(), stopped);
        assert_eq!(
            exchange_service(&mut observer, Operation::PicoclawRunning).code,
            Code::Ok
        );
        assert_eq!(fs::read(root.path().join("picoclaw")).unwrap(), new);
        assert_eq!(
            exchange_service(&mut observer, Operation::StopPicoclaw).code,
            Code::Ok
        );
        until(|| exchange_service(&mut observer, Operation::PicoclawStopped).code == Code::Ok);
    });
}
