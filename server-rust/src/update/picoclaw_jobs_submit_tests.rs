use super::*;
use crate::{native_owner::broker::Broker, update::state_writers::StateWriters};
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{
        fs::{PermissionsExt, symlink},
        process::ExitStatusExt,
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn request(kind: &str) -> Request {
    match kind {
        "onboard" => Request::Onboard,
        "model" => Request::Model {
            model: Zeroizing::new("vendor/model".into()),
            api_base: Zeroizing::new("https://fixture.invalid/v1".into()),
            api_key: Zeroizing::new("synthetic-private-model-value".into()),
        },
        "startup" => Request::Startup,
        "profile" => Request::Profile(Profile::Kvm),
        "install" => Request::Install,
        "remove" => Request::Remove,
        _ => panic!("unknown fixture kind"),
    }
}

fn terminal(submission: &mut Submission) -> Acceptance {
    let start = Instant::now();
    loop {
        let result = submission.poll();
        if result != Acceptance::Pending {
            return result;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "acceptance fixture watchdog"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn root_command(root: &Path, case: &str) -> Command {
    let mut command = Command::new("/usr/bin/unshare");
    command
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::picoclaw_config::jobs::submit::tests::private_submit_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_PICO_SUBMIT_ROOT", root)
        .env("NANOKVM_PICO_SUBMIT_CASE", case)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(point) = case.strip_prefix("fail:") {
        command.env("NANOKVM_PICO_ACCEPT_FAIL", point);
    }
    if case.contains(":custom:") {
        command.env("PICOCLAW_HOME", "/root/custom/deep/pico");
    }
    command
}

fn root_fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for directory in ["etc/kvm", "etc/init.d", "proc", "kvmapp", "root"] {
        fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    root
}

fn run_case(case: &str) {
    let root = root_fixture();
    let child = root_command(root.path(), case).spawn().unwrap();
    let mut child = super::super::tests::OwnedChild(Some(child));
    let start = Instant::now();
    while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
        assert!(
            start.elapsed() < Duration::from_secs(45),
            "private acceptance fixture watchdog: {case}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success(), "{case}: {output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("fixed-pico-acceptance-checked")
    );
}

#[test]
fn fixed_payload_encoding_is_bounded_and_distinguishes_credentials_without_debugging_them() {
    for kind in [
        "onboard", "model", "startup", "profile", "install", "remove",
    ] {
        let encoded = request(kind).encode().unwrap();
        assert_eq!(&encoded[..8], b"NKPREQ01");
        assert_eq!(encoded[8], request(kind).kind() as u8);
        assert!(encoded.as_slice() == request(kind).encode().unwrap().as_slice());
    }
    assert!(
        Request::Model {
            model: Zeroizing::new(" ".into()),
            api_base: Zeroizing::new(String::new()),
            api_key: Zeroizing::new(String::new())
        }
        .encode()
        .is_err()
    );
    assert!(
        Request::Model {
            model: Zeroizing::new("x".into()),
            api_base: Zeroizing::new(String::new()),
            api_key: Zeroizing::new("x".repeat(super::super::super::MAX_FILE_BYTES))
        }
        .encode()
        .is_err()
    );
}

#[test]
fn all_six_fixed_requests_persist_before_ack_and_owner_drop_keeps_durable_fence() {
    for kind in [
        "onboard", "model", "startup", "profile", "install", "remove",
    ] {
        for home in ["absent", "present"] {
            run_case(&format!("accept:{kind}:{home}"));
        }
    }
    run_case("accept:onboard:orphan-yaml");
    run_case("accept:model:custom:absent");
    run_case("accept:model:custom:present");
}

#[test]
fn exact_retained_replay_expiry_changed_payload_nonce_and_overflow_never_publish_new_work() {
    for case in [
        "replay",
        "changed",
        "changed-payload",
        "changed-home",
        "reused",
        "expired",
        "epoch",
        "future",
        "overflow",
        "zero-nonce",
        "legacy",
    ] {
        run_case(case);
    }
}

#[test]
fn source_and_store_rejections_preserve_evidence_without_acceptance_or_reset() {
    for case in [
        "reject:home-symlink",
        "reject:home-mode",
        "reject:config-symlink",
        "reject:config-hardlink",
        "reject:config-mode",
        "reject:config-oversize",
        "reject:pair-corrupt",
        "reject:store-active",
        "reject:store-payload",
        "reject:store-source",
        "reject:store-foreign",
        "reject:store-next",
        "reject:store-mode",
        "reject:store-state-missing",
        "reject:store-state-corrupt",
        "reject:anchor-missing",
        "reject:anchor-corrupt",
        "reject:anchor-next",
    ] {
        run_case(case);
    }
}

#[test]
fn worker_errors_spawn_failure_and_host_unwind_keep_admissions_without_retry() {
    for case in ["fail", "panic", "spawn", "block"] {
        run_case(case);
    }
}

#[test]
fn every_private_publication_error_is_sticky_and_preserves_partial_evidence() {
    for point in [
        "active-written",
        "active-durable",
        "payload-written",
        "payload-durable",
        "source-written",
        "source-durable",
        ".state.next-written",
        ".state.next-durable",
        "state-renamed",
        "state-durable",
    ] {
        run_case(&format!("fail:{point}"));
    }
}

#[test]
fn actual_sigkill_before_and_after_journal_rename_never_reopens_writer_admission() {
    for point in [
        "active-durable",
        "payload-written",
        "source-durable",
        "state-renamed",
        "state-durable",
    ] {
        let root = root_fixture();
        let mut command = root_command(root.path(), "kill");
        command.env("NANOKVM_PICO_ACCEPT_POINT", point);
        let child = command.spawn().unwrap();
        let mut child = super::super::tests::OwnedChild(Some(child));
        let stdout = child.0.as_mut().unwrap().stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.unwrap().contains("pico-accept-checkpoint-ready") {
                    let _ = send.send(());
                    break;
                }
            }
        });
        let reached = receive.recv_timeout(Duration::from_secs(30));
        let _ = child.0.as_mut().unwrap().kill();
        let status = child.0.as_mut().unwrap().wait().unwrap();
        child.0 = None;
        reader.join().unwrap();
        reached.unwrap();
        assert_eq!(status.signal(), Some(9));
        let parent = File::open(root.path().join("etc/kvm")).unwrap();
        drop(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap());
        let writers = StateWriters::for_test_parent(parent);
        assert!(writers.configuration().is_err());
        assert!(writers.try_drain().is_err());
        assert!(
            root.path()
                .join("etc/kvm")
                .join(DIRECTORY)
                .join("active")
                .is_file()
        );
        let state = Snapshot::decode(
            &fs::read(root.path().join("etc/kvm").join(DIRECTORY).join(STATE)).unwrap(),
        )
        .unwrap();
        assert_eq!(state.sequence, u64::from(point.starts_with("state-")));
    }
}

fn setup() {
    for (name, bytes) in crate::update::app_bootstrap::BOOT_SCRIPTS {
        let path = Path::new("/etc/init.d").join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let native = Path::new("/etc/kvm/native-runtime-boot");
    fs::create_dir(native).unwrap();
    fs::set_permissions(native, fs::Permissions::from_mode(0o700)).unwrap();
    let mut boot = [0; 112];
    boot[..8].copy_from_slice(b"NKBOOT02");
    boot[44] = 1;
    let hash = Sha256::digest(&boot[..80]);
    boot[80..].copy_from_slice(&hash);
    fs::write(native.join("state"), boot).unwrap();
    fs::set_permissions(native.join("state"), fs::Permissions::from_mode(0o600)).unwrap();
    let mut anchor = [0; 96];
    anchor[..8].copy_from_slice(b"NKPENR01");
    anchor[8] = 1;
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM Pico enrollment v1\0");
    hash.update(&anchor[..64]);
    anchor[64..].copy_from_slice(&hash.finalize());
    fs::write("/etc/kvm/picoclaw-enrollment", anchor).unwrap();
    fs::set_permissions(
        "/etc/kvm/picoclaw-enrollment",
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    crate::native_owner::broker::boot::activate_early().unwrap();
}

fn state() -> Snapshot {
    Snapshot::decode(&fs::read(Path::new("/etc/kvm").join(DIRECTORY).join(STATE)).unwrap()).unwrap()
}

fn submission(broker: &mut Broker) -> Submission {
    let mut submission = broker.prepare_picoclaw_submission().unwrap();
    // The public broker path pinned the real kernel executable/epoch. Its host
    // test executable need not fit the target-image budget. Substitute protected
    // synthetic image DATA only inside this private test owner, never execute it.
    let payload = Arc::get_mut(&mut submission.payload)
        .unwrap()
        .get_mut()
        .unwrap();
    assert!(payload.facts.boot != [0; 16] && payload.facts.image.metadata().unwrap().len() > 0);
    fs::write("/fixture-producer-image", b"synthetic executing image data").unwrap();
    fs::set_permissions("/fixture-producer-image", fs::Permissions::from_mode(0o600)).unwrap();
    payload.facts.image = File::open("/fixture-producer-image").unwrap();
    submission
}

fn assert_owned() {
    assert!(StateWriters::default().configuration().is_err());
    assert!(ProcessLock::acquire().is_err());
    assert!(Broker::acquire().is_err());
}

fn seed_terminal(head: u64, epoch: [u8; 16], home: [u8; 32]) {
    let mut receipts = [None; RETAINED];
    for offset in 0..head.min(RETAINED as u64) {
        let seq = head - offset;
        let mut record = super::super::tests::record(seq, Phase::Completed);
        record.home = home;
        record.nonce = if offset == 0 { [251; 16] } else { [7; 16] };
        if offset == 0 {
            let mut hash = Sha256::new();
            hash.update(b"NanoKVM Pico request v1\0");
            hash.update(request("model").encode().unwrap().as_slice());
            record.request = hash.finalize().into();
        }
        receipts[((seq - 1) % RETAINED as u64) as usize] = Some(record);
    }
    let snapshot = Snapshot {
        epoch,
        sequence: head,
        active: None,
        receipts,
    };
    fs::write(
        Path::new("/etc/kvm").join(DIRECTORY).join(STATE),
        snapshot.encode().unwrap().as_slice(),
    )
    .unwrap();
}

fn reject_fixture(case: &str) {
    fn private_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Path::new("/etc/kvm").join(DIRECTORY);
    let home = Path::new("/root/.picoclaw");
    match case {
        "reject:home-symlink" => {
            fs::create_dir("/fixture-home").unwrap();
            symlink("/fixture-home", home).unwrap();
        }
        "reject:home-mode" => {
            fs::create_dir(home).unwrap();
            fs::set_permissions(home, fs::Permissions::from_mode(0o777)).unwrap();
        }
        "reject:config-symlink"
        | "reject:config-hardlink"
        | "reject:config-mode"
        | "reject:config-oversize"
        | "reject:pair-corrupt" => {
            fs::create_dir(home).unwrap();
            fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
            let config = home.join("config.json");
            private_file(&config, b"synthetic-private-source");
            match case {
                "reject:config-symlink" => {
                    fs::rename(&config, "/fixture-config").unwrap();
                    symlink("/fixture-config", config).unwrap();
                }
                "reject:config-hardlink" => fs::hard_link(config, "/fixture-config").unwrap(),
                "reject:config-mode" => {
                    fs::set_permissions(config, fs::Permissions::from_mode(0o644)).unwrap();
                }
                "reject:config-oversize" => File::options()
                    .write(true)
                    .open(config)
                    .unwrap()
                    .set_len((super::super::super::MAX_FILE_BYTES + 1) as u64)
                    .unwrap(),
                "reject:pair-corrupt" => {
                    private_file(&home.join(".picoclaw-config-pair"), b"unknown pair intent");
                }
                _ => unreachable!(),
            }
        }
        "reject:store-state-missing" => fs::remove_file(store.join(STATE)).unwrap(),
        "reject:store-state-corrupt" => private_file(&store.join(STATE), b"unknown state"),
        "reject:store-mode" => {
            fs::set_permissions(store, fs::Permissions::from_mode(0o755)).unwrap();
        }
        "reject:anchor-missing" => fs::remove_file("/etc/kvm/picoclaw-enrollment").unwrap(),
        "reject:anchor-corrupt" => {
            private_file(Path::new("/etc/kvm/picoclaw-enrollment"), b"unknown anchor");
        }
        "reject:anchor-next" => {
            private_file(
                Path::new("/etc/kvm/.picoclaw-enrollment.next"),
                b"unknown next",
            );
        }
        _ => {
            let name = match case {
                "reject:store-active" => "active",
                "reject:store-payload" => "payload",
                "reject:store-source" => "source",
                "reject:store-foreign" => "unknown",
                "reject:store-next" => ".state.next",
                _ => panic!("unknown rejection fixture"),
            };
            private_file(&store.join(name), b"unknown private member");
        }
    }
}

#[test]
fn private_submit_child() {
    let Some(root) = std::env::var_os("NANOKVM_PICO_SUBMIT_ROOT") else {
        return;
    };
    let case = std::env::var("NANOKVM_PICO_SUBMIT_CASE").unwrap();
    nix::mount::mount(
        Some("/proc"),
        Path::new(&root).join("proc").as_path(),
        None::<&str>,
        nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    nix::unistd::chroot(Path::new(&root)).unwrap();
    std::env::set_current_dir("/").unwrap();
    setup();
    let initial = state();
    let mut cursor = Cursor {
        epoch: initial.epoch,
        sequence: 0,
    };
    let mut nonce = [251; 16];
    let mut broker = Broker::acquire().unwrap();
    let selected = case
        .split(':')
        .nth(1)
        .filter(|_| case.starts_with("accept:"))
        .unwrap_or("model");
    let selected_home = Home::resolve().unwrap();
    let home_path = selected_home.path();
    if case.starts_with("accept:") && !case.ends_with(":absent") {
        fs::create_dir_all(home_path).unwrap();
        fs::set_permissions(home_path, fs::Permissions::from_mode(0o700)).unwrap();
        if !case.ends_with("orphan-yaml") {
            fs::write(
                home_path.join("config.json"),
                b"{\"fixture\":\"synthetic-private-config\"}",
            )
            .unwrap();
            fs::set_permissions(
                home_path.join("config.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        fs::write(
            home_path.join(".security.yml"),
            b"fixture: synthetic-private-yaml\n",
        )
        .unwrap();
        fs::set_permissions(
            home_path.join(".security.yml"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let home = selected_home.fingerprint();
    if [
        "replay",
        "changed",
        "changed-payload",
        "changed-home",
        "reused",
        "expired",
        "overflow",
    ]
    .contains(&case.as_str())
    {
        let head = if case == "overflow" { u64::MAX } else { 40 };
        let mut receipt_home = home;
        if case == "changed-home" {
            receipt_home[0] ^= 1;
        }
        seed_terminal(head, cursor.epoch, receipt_home);
        cursor.sequence =
            if ["replay", "changed", "changed-payload", "changed-home"].contains(&case.as_str()) {
                39
            } else if case == "expired" {
                1
            } else {
                head
            };
        if ["expired", "overflow"].contains(&case.as_str()) {
            nonce = [252; 16];
        }
    }
    if case == "epoch" {
        cursor.epoch[0] ^= 1;
    }
    if case == "future" {
        cursor.sequence = 1;
    }
    if case == "zero-nonce" {
        nonce = [0; 16];
    }
    if case == "legacy" {
        fs::remove_file("/etc/kvm/picoclaw-enrollment").unwrap();
        fs::remove_file(Path::new("/etc/kvm").join(DIRECTORY).join(STATE)).unwrap();
        fs::remove_dir(Path::new("/etc/kvm").join(DIRECTORY)).unwrap();
    }
    let mut submission = submission(&mut broker);
    if case.starts_with("reject:") {
        // Prepare through the actual broker first, then inject evidence before
        // the worker reopens the store/source. No admission check is bypassed.
        reject_fixture(&case);
    }
    let before = fs::read(Path::new("/etc/kvm").join(DIRECTORY).join(STATE)).ok();
    let input = if case == "changed" {
        Request::Startup
    } else if case == "changed-payload" {
        Request::Model {
            model: Zeroizing::new("vendor/model".into()),
            api_base: Zeroizing::new("https://fixture.invalid/v1".into()),
            api_key: Zeroizing::new("different-synthetic-private-value".into()),
        }
    } else {
        request(selected)
    };
    match case.as_str() {
        "fail" => submission.fixture = Some(Fixture::Fail),
        "panic" => submission.fixture = Some(Fixture::Panic),
        "spawn" => submission.fixture = Some(Fixture::SpawnFailure),
        "block" => {
            let (entered, receive) = std::sync::mpsc::channel();
            let (resume, wait) = std::sync::mpsc::channel();
            submission.fixture = Some(Fixture::Block(entered, wait));
            submission.submit(cursor, nonce, input).unwrap();
            receive.recv_timeout(Duration::from_secs(30)).unwrap();
            let start = Instant::now();
            assert_eq!(submission.poll(), Acceptance::Pending);
            assert!(start.elapsed() < Duration::from_millis(250));
            assert_owned();
            let (done, received) = std::sync::mpsc::channel();
            let dropping = std::thread::spawn(move || {
                drop(submission);
                done.send(()).unwrap();
            });
            assert!(received.recv_timeout(Duration::from_millis(50)).is_err());
            assert_owned();
            resume.send(()).unwrap();
            received.recv_timeout(Duration::from_secs(30)).unwrap();
            dropping.join().unwrap();
            drop(ProcessLock::acquire().unwrap());
            assert!(StateWriters::default().configuration().is_err());
            println!("fixed-pico-acceptance-checked");
            return;
        }
        _ => {}
    }
    let result = submission.submit(cursor, nonce, input);
    assert_eq!(result.is_err(), case == "spawn");
    let status = terminal(&mut submission);
    assert_owned();
    assert!(submission.submit(cursor, nonce, request("model")).is_err());
    if case.starts_with("accept:") {
        assert_eq!(
            status,
            Acceptance::Accepted(JobId {
                epoch: cursor.epoch,
                sequence: 1,
                nonce
            })
        );
        let state = state();
        let record = state.active.unwrap();
        assert!(record.kind == request(selected).kind());
        for member in [STATE, "active", "payload", "source"] {
            let m = fs::metadata(Path::new("/etc/kvm").join(DIRECTORY).join(member)).unwrap();
            assert_eq!(m.mode() & 0o7777, 0o600);
            assert_eq!(m.nlink(), 1);
        }
        let payload = fs::read(Path::new("/etc/kvm").join(DIRECTORY).join("payload")).unwrap();
        assert!(payload.as_slice() == request(selected).encode().unwrap().as_slice());
        let public = format!("{status:?}");
        assert!(!public.contains("synthetic-private"));
        assert_eq!(
            record.resume_allowed,
            record.was_running && record.kind != Kind::Remove
        );
        let source = fs::read(Path::new("/etc/kvm").join(DIRECTORY).join("source")).unwrap();
        assert_eq!(source[8], u8::from(!case.ends_with(":absent")));
        assert_eq!(
            &source[128..128 + home_path.as_os_str().len()],
            home_path.as_os_str().as_encoded_bytes()
        );
        if case.ends_with(":absent") {
            assert!(!home_path.exists());
            if case.contains(":custom:") {
                assert!(!Path::new("/root/custom").exists());
            }
        }
    } else if case == "replay" {
        assert_eq!(
            status,
            Acceptance::Existing(JobId {
                epoch: cursor.epoch,
                sequence: 40,
                nonce
            })
        );
    } else if ["expired", "epoch"].contains(&case.as_str()) {
        assert_eq!(status, Acceptance::Expired);
    } else if case.starts_with("fail:") || case == "panic" {
        assert_eq!(status, Acceptance::RecoveryRequired);
    } else {
        assert_eq!(status, Acceptance::Rejected);
    }
    drop(submission);
    drop(ProcessLock::acquire().unwrap());
    if case.starts_with("accept:") || case.starts_with("fail:") {
        assert!(StateWriters::default().configuration().is_err());
        assert!(
            Path::new("/etc/kvm")
                .join(DIRECTORY)
                .join("active")
                .exists()
        );
    } else {
        let fenced_store = case.starts_with("reject:store-") || case.starts_with("reject:anchor-");
        if fenced_store {
            assert!(StateWriters::default().configuration().is_err());
        } else {
            drop(StateWriters::default().configuration().unwrap());
        }
        if let Some(before) = before {
            assert!(fs::read(Path::new("/etc/kvm").join(DIRECTORY).join(STATE)).unwrap() == before);
        } else if case == "legacy" {
            assert!(!Path::new("/etc/kvm").join(DIRECTORY).exists());
        } else {
            assert!(!Path::new("/etc/kvm").join(DIRECTORY).join(STATE).exists());
        }
        if case.starts_with("reject:") && !case.starts_with("reject:store-") {
            assert!(
                !Path::new("/etc/kvm")
                    .join(DIRECTORY)
                    .join("active")
                    .exists()
            );
        }
    }
    println!("fixed-pico-acceptance-checked");
}
