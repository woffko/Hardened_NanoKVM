use super::*;
#[cfg(feature = "sandbox-test-fixture")]
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    process::{Child, Command, Stdio},
};
const ID: [u8; 16] = [7; 16];

#[test]
fn trial_frames_require_exact_event_identity_and_reserved_bytes() {
    assert!(wire::frame(wire::Event::Begin, [0; 16]).is_err());
    let frame = wire::frame(wire::Event::Begin, ID).unwrap();
    assert_eq!(wire::parse(&frame, wire::Event::Begin).unwrap(), ID);
    for offset in [0, 8, 9, 15] {
        let mut bad = frame;
        bad[offset] ^= 0x40;
        assert!(wire::parse(&bad, wire::Event::Begin).is_err());
    }
    assert!(wire::parse(&frame, wire::Event::Ready).is_err());
    let mut zero = frame;
    zero[16..].fill(0);
    assert!(wire::parse(&zero, wire::Event::Begin).is_err());
}

#[test]
fn readiness_needs_matching_commit_and_disconnect_or_wrong_frames_fail() {
    for kind in [0, 1, 2, 3] {
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        parent
            .write_all(&wire::frame(wire::Event::Begin, ID).unwrap())
            .unwrap();
        std::thread::scope(|scope| {
            let thread =
                scope.spawn(move || Startup::receive(child).unwrap().ready_and_wait_commit());
            let mut ready = [0; wire::BYTES];
            parent.read_exact(&mut ready).unwrap();
            assert_eq!(wire::parse(&ready, wire::Event::Ready).unwrap(), ID);
            match kind {
                0 => parent
                    .write_all(&wire::frame(wire::Event::Commit, ID).unwrap())
                    .unwrap(),
                1 => parent
                    .write_all(&wire::frame(wire::Event::Commit, [9; 16]).unwrap())
                    .unwrap(),
                2 => parent
                    .write_all(&wire::frame(wire::Event::Ready, ID).unwrap())
                    .unwrap(),
                _ => parent.write_all(b"truncated").unwrap(),
            }
            drop(parent);
            assert_eq!(thread.join().unwrap().is_ok(), kind == 0);
        });
    }
}

#[test]
fn commit_cannot_replace_the_initial_begin_frame() {
    let (mut parent, child) = UnixStream::pair().unwrap();
    parent
        .write_all(&wire::frame(wire::Event::Commit, ID).unwrap())
        .unwrap();
    assert!(Startup::receive(child).is_err());
}

#[cfg(feature = "sandbox-test-fixture")]
struct OwnedChild(Child);
#[cfg(feature = "sandbox-test-fixture")]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn fixed_root_trial_child() {
    use crate::{
        state::AppState,
        update::{
            operation_lock::{LockError, ProcessLock},
            state_writers::StateWriters,
        },
    };
    use nix::mount::{MsFlags, mount};
    let Some(root) = std::env::var_os("NANOKVM_TRIAL_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    if std::env::var("NANOKVM_TRIAL_ROLE").unwrap() == "reader" {
        let startup = Startup::adopt_stdin().unwrap();
        nix::unistd::chroot(&root).unwrap();
        std::env::set_current_dir("/").unwrap();
        // The parent still owns actual WriterAdmission/Activity EX: a normal
        // startup would fail here, and frozen reads must not release them.
        assert!(StateWriters::default().configuration().is_err());
        let config = startup.configuration();
        let case = std::env::var("NANOKVM_TRIAL_CASE").unwrap();
        if matches!(
            case.as_str(),
            "missing-secret" | "symlink" | "hardlink" | "fifo" | "oversize"
        ) {
            assert!(config.is_err());
            return;
        }
        let config = config.unwrap();
        assert_eq!(config.jwt.secret_key, "synthetic-session-identity");
        assert!(matches!(
            crate::update::app_slot::status(),
            Err(crate::update::app_slot::SlotError::Busy)
        ));
        #[cfg(feature = "app-bootstrap-bound-test-fixture")]
        crate::update::app_bootstrap::check_trial_support(&startup).unwrap();
        let state = AppState::new_trial(config, &startup);
        if case == "missing-account" {
            assert!(state.is_err());
            return;
        }
        let state = state.unwrap();
        assert_eq!(
            state.accounts.load().unwrap().unwrap().username,
            "synthetic-user"
        );
        assert!(read_state(Path::new("/proc/self/cmdline"), 4096).is_err());
        assert!(StateWriters::default().configuration().is_err());
        startup.ready_and_wait_commit().unwrap();
        return;
    }
    assert!(nix::unistd::geteuid().is_root());
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    fs::create_dir_all(root.join("etc/kvm")).unwrap();
    let store_path = root.join("etc/kvm/application-slot");
    fs::create_dir(&store_path).unwrap();
    fs::set_permissions(&store_path, fs::Permissions::from_mode(0o700)).unwrap();
    let store = File::open(store_path).unwrap();
    rustix::fs::flock(&store, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    #[cfg(feature = "app-bootstrap-bound-test-fixture")]
    {
        use crate::{
            native_owner::embedded,
            update::{app_bootstrap, restore_binding},
        };
        fs::create_dir_all(root.join("usr/libexec")).unwrap();
        fs::create_dir(root.join("etc/init.d")).unwrap();
        for &(name, bytes) in app_bootstrap::BOOT_SCRIPTS {
            let path = root.join("etc/init.d").join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let recovery = root.join("usr/libexec/nanokvm-app-recovery");
        fs::write(&recovery, app_bootstrap::embedded_recovery().unwrap()).unwrap();
        fs::set_permissions(recovery, fs::Permissions::from_mode(0o755)).unwrap();
        for runtime in restore_binding::NATIVE_RUNTIMES {
            let path = root.join("usr/libexec").join(runtime.filename());
            fs::write(&path, embedded::image(runtime).unwrap()).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    fs::create_dir(root.join("proc")).unwrap();
    mount(
        Some("proc"),
        &root.join("proc"),
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .unwrap();
    let parent = File::open(root.join("etc/kvm")).unwrap();
    let _update = ProcessLock::from_parent(&parent, 0).unwrap();
    let writers = StateWriters::for_test_parent(parent.try_clone().unwrap());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let _drain = runtime
        .block_on(writers.drain(Duration::from_secs(2)))
        .unwrap();
    let mut config = Config::default();
    config.security.allow_default_admin = true;
    let yaml = root.join("etc/kvm/server.yaml");
    fs::write(&yaml, serde_yaml::to_string(&config).unwrap()).unwrap();
    fs::set_permissions(&yaml, fs::Permissions::from_mode(0o600)).unwrap();
    let secret = root.join("etc/kvm/session_secret");
    let account = root.join(config.paths.account_file.strip_prefix("/").unwrap());
    for case in [
        "valid",
        "missing-secret",
        "missing-account",
        "symlink",
        "hardlink",
        "fifo",
        "oversize",
    ] {
        for path in [&secret, &account, &root.join("etc/kvm/alias")] {
            let _ = fs::remove_file(path);
        }
        fs::write(&secret, b"synthetic-session-identity\n").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &account,
            br#"{"username":"synthetic-user","password":"synthetic-inactive-hash"}"#,
        )
        .unwrap();
        fs::set_permissions(&account, fs::Permissions::from_mode(0o600)).unwrap();
        match case {
            "missing-secret" => fs::remove_file(&secret).unwrap(),
            "missing-account" => fs::remove_file(&account).unwrap(),
            "symlink" => {
                fs::rename(&secret, root.join("etc/kvm/alias")).unwrap();
                symlink("alias", &secret).unwrap();
            }
            "hardlink" => fs::hard_link(&secret, root.join("etc/kvm/alias")).unwrap(),
            "fifo" => {
                fs::remove_file(&secret).unwrap();
                rustix::fs::mknodat(
                    rustix::fs::CWD,
                    &secret,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap();
            }
            "oversize" => fs::write(&secret, vec![0; 4097]).unwrap(),
            _ => {}
        }
        let yaml_before = fs::read(&yaml).unwrap();
        let account_before = fs::read(&account).ok();
        let secret_before = fs::symlink_metadata(&secret)
            .ok()
            .map(|m| (m.ino(), m.mode(), m.len()));
        let (mut control, child) = UnixStream::pair().unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut worker = OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "update::app_trial::tests::fixed_root_trial_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_clear()
                .env("NANOKVM_TRIAL_ROOT", &root)
                .env("NANOKVM_TRIAL_ROLE", "reader")
                .env("NANOKVM_TRIAL_CASE", case)
                .stdin(Stdio::from(std::os::fd::OwnedFd::from(child)))
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        control
            .write_all(&wire::frame(wire::Event::Begin, ID).unwrap())
            .unwrap();
        let mut ready = [0; wire::BYTES];
        if case == "valid" {
            control.read_exact(&mut ready).unwrap();
            assert_eq!(wire::parse(&ready, wire::Event::Ready).unwrap(), ID);
            control
                .write_all(&wire::frame(wire::Event::Commit, ID).unwrap())
                .unwrap();
        } else {
            assert_eq!(control.read(&mut ready).unwrap(), 0);
        }
        assert!(worker.0.wait().unwrap().success(), "case {case}");
        assert_eq!(fs::read(&yaml).unwrap(), yaml_before);
        assert_eq!(fs::read(&account).ok(), account_before);
        assert_eq!(
            fs::symlink_metadata(&secret)
                .ok()
                .map(|m| (m.ino(), m.mode(), m.len())),
            secret_before
        );
        assert!(matches!(
            ProcessLock::from_parent(&parent, 0),
            Err(LockError::Busy)
        ));
        assert!(writers.configuration().is_err());
        let other = File::open(root.join("etc/kvm/application-slot")).unwrap();
        assert_eq!(
            rustix::fs::flock(&other, rustix::fs::FlockOperation::NonBlockingLockExclusive),
            Err(rustix::io::Errno::WOULDBLOCK)
        );
    }
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn actual_frozen_startup_keeps_identity_and_refuses_generation_under_real_parent_exclusions() {
    let root = tempfile::tempdir().unwrap();
    let mut child = OwnedChild(
        Command::new("/usr/bin/unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--pid",
                "--fork",
                "--kill-child=KILL",
                "--",
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_trial::tests::fixed_root_trial_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_TRIAL_ROOT", root.path())
            .env("NANOKVM_TRIAL_ROLE", "parent")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "frozen startup deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
