use super::*;
use crate::{
    native_owner::controller::{Completion, Group, Role},
    update::{operation_lock::ProcessLock, picoclaw_config::jobs, state_writers::StateWriters},
};
use rustix::process::{Pid, Signal};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::PermissionsExt,
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn until(mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "mutation fixture watchdog"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn command(root: &Path, case: &str) -> Command {
    let mut command = Command::new("/usr/bin/unshare");
    command
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "native_owner::broker::picoclaw_mutation::tests::mutation_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_PICO_MUTATION_ROOT", root)
        .env("NANOKVM_PICO_MUTATION_CASE", case)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(point) = case.strip_prefix("fail:") {
        command.env("NANOKVM_PICO_ACCEPT_FAIL", point);
    }
    if let Some(point) = case.strip_prefix("kill:") {
        command.env("NANOKVM_PICO_ACCEPT_POINT", point);
    }
    if let Some(point) = case.strip_prefix("settle-fail:") {
        command.env("NANOKVM_PICO_ACCEPT_FAIL", point);
    }
    command
}

fn root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for name in [
        "etc/kvm",
        "etc/init.d",
        "proc",
        "kvmapp",
        "root",
        "pico",
        "backend",
    ] {
        fs::create_dir_all(root.path().join(name)).unwrap();
    }
    root
}

struct Child(Option<std::process::Child>);
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// Parent-side last resort after the test child is reaped. Never participates
// in a Closed assertion: success already joined its tree inside the child.
struct FixtureLeaves<'a>(&'a Path);
impl Drop for FixtureLeaves<'_> {
    fn drop(&mut self) {
        for role in ["pico", "backend"] {
            if let Some(fd) = verified_fixture_leaf(&self.0.join(role)) {
                let _ = rustix::process::pidfd_send_signal(fd, Signal::KILL);
            }
        }
    }
}

fn verified_fixture_leaf(root: &Path) -> Option<OwnedFd> {
    let pid = fs::read_to_string(root.join("leaf.pid")).ok()?;
    let pid = Pid::from_raw(pid.parse().ok()?)?;
    let path = format!("/proc/{}/cmdline", pid.as_raw_nonzero());
    let before = fs::read(&path).ok()?;
    let mut args = before.split(|byte| *byte == 0);
    if args.next() != Some(b"/bin/sh".as_slice()) || args.next() != Some(b"-c".as_slice()) {
        return None;
    }
    args.next()?;
    let leaf = root.join("leaf.pid");
    let release = root.join("release-leaf");
    if args.next() != Some(b"fixture-leaf".as_slice())
        || args.next() != Some(leaf.as_os_str().as_encoded_bytes())
        || args.next() != Some(release.as_os_str().as_encoded_bytes())
        || args.next() != Some(b"".as_slice())
        || args.next().is_some()
    {
        return None;
    }
    let fd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()?;
    if fs::read(path).ok()? != before {
        return None;
    }
    Some(fd)
}

fn run(case: &str) {
    let root = root();
    let _cleanup = FixtureLeaves(root.path());
    let mut child = Child(Some(command(root.path(), case).spawn().unwrap()));
    until(|| child.0.as_mut().unwrap().try_wait().unwrap().is_some());
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success(), "{case}: {output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("pico-mutation-checked")
    );
}

#[test]
fn explicit_stop_is_durable_before_native_stop_and_only_matching_closure_publishes_closed() {
    for case in [
        "absent",
        "tree",
        "paused",
        "accepted-live",
        "refused",
        "stop-during-accept",
    ] {
        run(case);
    }
}

#[test]
fn failed_and_runtime_error_receipts_prove_closure_without_claiming_task_success() {
    for case in ["failed-exit", "runtime-error"] {
        run(case);
    }
}

#[test]
fn running_scope_without_owned_launch_generation_refuses_mutation_without_stop_or_publication() {
    run("unbound");
}

#[test]
fn blocked_or_failed_stop_work_retains_broker_and_late_success_cannot_clear_uncertainty() {
    for case in [
        "blocked-stop",
        "blocked-drop",
        "stopping-drop",
        "late-uncertain",
        "phase-fail",
        "phase-panic",
        "phase-spawn",
    ] {
        run(case);
    }
}

#[test]
fn malformed_completion_or_modified_private_input_never_becomes_a_closed_job() {
    for case in [
        "bad-receipt",
        "changed-payload",
        "changed-source",
        "changed-active",
        "changed-state",
    ] {
        run(case);
    }
}

#[test]
fn startup_noop_settlement_publishes_a_terminal_receipt_and_returns_the_same_broker() {
    for case in ["settle-noop-absent", "settle-noop-live"] {
        run(case);
    }
}

#[test]
fn startup_settlement_that_needs_work_or_cannot_run_changes_nothing() {
    for case in [
        "settle-change-absent",
        "settle-internal-absent",
        "settle-refused-absent",
        "settle-change-live",
    ] {
        run(case);
    }
}

#[test]
fn startup_settlement_publication_and_retirement_errors_keep_the_fence() {
    for point in [
        "completed-begin",
        "completed-renamed",
        "payload-retired",
        "active-retired",
    ] {
        run(&format!("settle-fail:{point}"));
    }
}

#[test]
fn parent_fixture_cleanup_rejects_foreign_pid_file_and_reaps_only_its_owned_orphan() {
    let root = root();
    let cleanup = FixtureLeaves(root.path());
    let mut child = Child(Some(
        command(root.path(), "parent-cleanup").spawn().unwrap(),
    ));
    until(|| child.0.as_mut().unwrap().try_wait().unwrap().is_some());
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("fixture-parent-cleanup")
    );
    let leaf = pidfd(&root.path().join("pico/leaf.pid"));
    let exited = || {
        let mut events = [rustix::event::PollFd::new(
            &leaf,
            rustix::event::PollFlags::IN,
        )];
        rustix::event::poll(
            &mut events,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .unwrap()
            == 1
    };
    assert!(
        !exited(),
        "killed subreaper's leaf needs explicit test cleanup"
    );
    let foreign = root.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    fs::copy(root.path().join("pico/leaf.pid"), foreign.join("leaf.pid")).unwrap();
    assert!(verified_fixture_leaf(&foreign).is_none());
    assert!(!exited(), "a PID file alone is not cleanup authority");
    drop(cleanup);
    until(exited);
}

#[test]
fn stop_publication_failures_never_send_native_stop_or_clear_the_fence() {
    for point in [
        "stop-begin",
        "stop-renamed",
        "stop-durable",
        "closed-begin",
        "closed-renamed",
        "closed-durable",
    ] {
        run(&format!("fail:{point}"));
    }
}

#[test]
fn real_sigkill_during_stop_publication_keeps_the_job_fenced_without_native_authority() {
    for point in ["stop-begin", "stop-renamed", "stop-durable"] {
        let root = root();
        let mut child = Child(Some(
            command(root.path(), &format!("kill:{point}"))
                .spawn()
                .unwrap(),
        ));
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
        let leaves =
            ["pico/leaf.pid", "backend/leaf.pid"].map(|name| pidfd(&root.path().join(name)));
        let owners =
            ["pico/owner.pid", "backend/owner.pid"].map(|name| pidfd(&root.path().join(name)));
        let _ = child.0.as_mut().unwrap().kill();
        child.0.as_mut().unwrap().wait().unwrap();
        child.0 = None;
        reader.join().unwrap();
        reached.unwrap();
        let parent = File::open(root.path().join("etc/kvm")).unwrap();
        let writers = StateWriters::for_test_parent(parent);
        assert!(writers.configuration().is_err());
        assert!(writers.try_drain().is_err());
        assert!(
            root.path()
                .join("etc/kvm/picoclaw-operations/active")
                .is_file()
        );
        // Exact pidfds avoid PID reuse while surviving owners reap their tree.
        // These are private process-death fixtures, not target power cuts.
        settle_fixture(leaves.map(Some), owners.map(Some));
    }
}

fn scope_command(root: &Path, role: &str, mode: &str) -> Command {
    let test = std::env::current_exe().unwrap();
    let mut command = Command::new(
        test.parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("nanokvm-native-owner-fixture"),
    );
    command
        .args(["scope", mode])
        .arg(root.join(role))
        .env_clear()
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn pidfd(path: &Path) -> OwnedFd {
    let pid = fs::read_to_string(path).unwrap().parse::<i32>().unwrap();
    rustix::process::pidfd_open(
        Pid::from_raw(pid).unwrap(),
        rustix::process::PidfdFlags::empty(),
    )
    .unwrap()
}

fn settle_fixture(leaves: [Option<OwnedFd>; 2], owners: [Option<OwnedFd>; 2]) {
    for fd in leaves.iter().chain(owners.iter()).flatten() {
        until(|| {
            let mut events = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
            rustix::event::poll(
                &mut events,
                Some(&rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )
            .unwrap()
                == 1
        });
    }
    for fd in owners.into_iter().flatten() {
        match rustix::process::waitid(
            rustix::process::WaitId::PidFd(fd.as_fd()),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
        ) {
            Ok(Some(_)) | Err(rustix::io::Errno::CHILD) => {}
            result => panic!("fixture owner not reaped after exit: {result:?}"),
        }
    }
}

struct Paused(OwnedFd);
impl Drop for Paused {
    fn drop(&mut self) {
        let _ = rustix::process::pidfd_send_signal(&self.0, Signal::CONT);
    }
}

fn record() -> Vec<u8> {
    fs::read("/etc/kvm/picoclaw-operations/state").unwrap()
}

fn closed(mutation: &mut Mutation) -> bool {
    matches!(mutation.poll(), MutationStatus::Closed(_))
}

#[test]
fn mutation_child() {
    let Some(root) = std::env::var_os("NANOKVM_PICO_MUTATION_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let case = std::env::var("NANOKVM_PICO_MUTATION_CASE").unwrap();
    let mut group = Group::default();
    let live = case != "absent" && !case.ends_with("-absent") && !case.starts_with("settle-fail:");
    // Fixture binaries/real descendant tree start before chroot so the host
    // interpreter is available. This tests closure, not production launch order.
    if live {
        group
            .start_command(Role::Backend, scope_command(root, "backend", "owned-tree"))
            .unwrap();
        if case == "unbound" {
            group
                .start_command(Role::Picoclaw, scope_command(root, "pico", "owned-tree"))
                .unwrap();
        } else {
            group
                .start_picoclaw(
                    scope_command(root, "pico", "owned-tree"),
                    crate::update::picoclaw_config::Generation::fixture([0x31; 32]),
                )
                .unwrap();
        }
        until(|| {
            let status = group.poll();
            status[2] == Some(Status::Running)
                && status[3] == Some(Status::Running)
                && root.join("pico/leaf.pid").exists()
                && root.join("backend/leaf.pid").exists()
        });
    }
    let pico_leaf = live.then(|| pidfd(&root.join("pico/leaf.pid")));
    let backend_leaf = live.then(|| pidfd(&root.join("backend/leaf.pid")));
    let pico_owner = live.then(|| pidfd(&root.join("pico/owner.pid")));
    let backend_owner = live.then(|| pidfd(&root.join("backend/owner.pid")));
    nix::mount::mount(
        Some("/proc"),
        root.join("proc").as_path(),
        None::<&str>,
        nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    nix::unistd::chroot(root).unwrap();
    std::env::set_current_dir("/").unwrap();
    jobs::prepare_factory_fixture();
    let settle_pair = case.starts_with("settle-").then(|| settle_home(&case));
    let initial = record();
    let epoch = initial[8..24].try_into().unwrap();
    let mut broker = Broker::acquire().unwrap();
    if live {
        broker.journal.begin().unwrap();
        broker.group = group;
    }
    if case == "unbound" {
        broker = match broker.begin_picoclaw_mutation() {
            MutationAdmission::Refused(broker) => broker,
            MutationAdmission::Owned(_) => panic!("unbound live scope must not authorize mutation"),
        };
        assert_eq!(broker.group.poll()[3], Some(Status::Running));
        assert!(broker.group.picoclaw_generation().is_none());
        assert!(record() == initial);
        assert!(!Path::new("/etc/kvm/picoclaw-operations/source").exists());
        drop(ProcessLock::acquire().unwrap());
        drop(StateWriters::default().configuration().unwrap());
        let admission = broker.runtime_permit().unwrap();
        let crate::native_owner::broker::Shutdown::Draining(mut drain) = broker.shutdown(admission)
        else {
            panic!("owned test cleanup was refused");
        };
        until(|| drain.poll().unwrap() == crate::native_owner::controller::DrainStatus::Drained);
        settle_fixture([pico_leaf, backend_leaf], [pico_owner, backend_owner]);
        println!("pico-mutation-checked");
        return;
    }
    if case == "refused" {
        let held = ProcessLock::acquire().unwrap();
        broker = match broker.begin_picoclaw_mutation() {
            MutationAdmission::Refused(broker) => broker,
            MutationAdmission::Owned(_) => panic!("busy admission must return the unchanged owner"),
        };
        assert_eq!(broker.group.poll()[3], Some(Status::Running));
        assert!(record() == initial);
        drop(held);
    }
    let mut mutation = match broker.begin_picoclaw_mutation() {
        MutationAdmission::Owned(mutation) => mutation,
        MutationAdmission::Refused(_) => panic!("actual root broker rejected mutation fixture"),
    };
    fs::write("/producer-image", b"synthetic private producer image data").unwrap();
    fs::set_permissions("/producer-image", fs::Permissions::from_mode(0o600)).unwrap();
    let acceptance_gate = if case == "stop-during-accept" {
        let (entered, receive) = std::sync::mpsc::channel();
        let (resume, wait) = std::sync::mpsc::channel();
        mutation
            .submission
            .fixture_work(jobs::WorkFixture::Block(entered, wait));
        Some((receive, resume))
    } else {
        None
    };
    mutation
        .submission
        .fixture_image(File::open("/producer-image").unwrap());
    mutation
        .submit(
            PicoCursor { epoch, sequence: 0 },
            [67; 16],
            PicoRequest::Startup,
        )
        .unwrap();
    if let Some((entered, resume)) = acceptance_gate {
        entered.recv_timeout(Duration::from_secs(30)).unwrap();
        mutation.request_stop();
        assert_eq!(mutation.poll(), MutationStatus::Accepting);
        assert!(record() == initial);
        assert_eq!(mutation.broker.group.poll()[3], Some(Status::Running));
        resume.send(()).unwrap();
        until(|| closed(&mut mutation));
    } else {
        until(|| matches!(mutation.poll(), MutationStatus::Accepted(_)));
    }
    let before = record();
    let source = fs::read("/etc/kvm/picoclaw-operations/source").unwrap();
    assert_eq!(&source[..8], b"NKPSRC02");
    assert_eq!(source[11], u8::from(live));
    assert_eq!(&source[96..128], if live { &[0x31; 32] } else { &[0; 32] });
    let mut digest = sha2::Sha256::new();
    use sha2::Digest as _;
    digest.update(b"NanoKVM Pico source v2\0");
    digest.update(&source);
    assert_eq!(&before[128 + 136..128 + 168], digest.finalize().as_slice());
    assert_eq!(
        before[128 + 169],
        if case == "stop-during-accept" { 3 } else { 1 }
    );
    assert_eq!(
        before[128 + 174],
        u8::from(live && case != "stop-during-accept")
    );
    assert!(Broker::acquire().is_err() && ProcessLock::acquire().is_err());
    if case == "accepted-live" {
        for _ in 0..4 {
            assert!(matches!(mutation.poll(), MutationStatus::Accepted(_)));
        }
        assert_eq!(mutation.broker.group.poll()[3], Some(Status::Running));
        assert!(record() == before);
    }
    if let Some(pair) = settle_pair {
        settle_case(&case, mutation, live, &pair, &before);
        settle_fixture([pico_leaf, backend_leaf], [pico_owner, backend_owner]);
        println!("pico-mutation-checked");
        return;
    }
    if case == "parent-cleanup" {
        rustix::process::pidfd_send_signal(pico_owner.as_ref().unwrap(), Signal::KILL).unwrap();
        until(|| mutation.poll() == MutationStatus::RecoveryRequired);
        panic!("fixture-parent-cleanup");
    }
    let mut blocked = None;
    if ["blocked-stop", "blocked-drop", "late-uncertain"].contains(&case.as_str()) {
        let (entered, receive) = std::sync::mpsc::channel();
        let (resume, wait) = std::sync::mpsc::channel();
        mutation
            .submission
            .fixture_work(jobs::WorkFixture::Block(entered, wait));
        mutation.request_stop();
        assert!(matches!(mutation.poll(), MutationStatus::StopPending(_)));
        receive.recv_timeout(Duration::from_secs(30)).unwrap();
        let start = Instant::now();
        assert!(matches!(mutation.poll(), MutationStatus::StopPending(_)));
        assert!(start.elapsed() < Duration::from_millis(250));
        assert!(record() == before);
        assert_eq!(mutation.broker.group.poll()[3], Some(Status::Running));
        if case == "blocked-drop" {
            let (done, finished) = std::sync::mpsc::channel();
            let dropping = std::thread::spawn(move || {
                drop(mutation);
                done.send(()).unwrap();
            });
            assert!(finished.recv_timeout(Duration::from_millis(50)).is_err());
            assert!(Broker::acquire().is_err() && ProcessLock::acquire().is_err());
            assert!(StateWriters::default().configuration().is_err());
            assert!(record() == before);
            resume.send(()).unwrap();
            finished.recv_timeout(Duration::from_secs(30)).unwrap();
            dropping.join().unwrap();
            assert_eq!(
                record()[128 + 169],
                2,
                "teardown cannot publish a closure proof"
            );
            assert_eq!(record()[128 + 174], 0);
            drop(ProcessLock::acquire().unwrap());
            assert!(StateWriters::default().configuration().is_err());
            settle_fixture([pico_leaf, backend_leaf], [pico_owner, backend_owner]);
            println!("pico-mutation-checked");
            return;
        }
        if case == "late-uncertain" {
            rustix::process::pidfd_send_signal(pico_owner.as_ref().unwrap(), Signal::KILL).unwrap();
            until(|| mutation.poll() == MutationStatus::RecoveryRequired);
        }
        blocked = Some(resume);
    }
    match case.as_str() {
        "phase-fail" => mutation.submission.fixture_work(jobs::WorkFixture::Fail),
        "phase-panic" => mutation.submission.fixture_work(jobs::WorkFixture::Panic),
        "phase-spawn" => mutation
            .submission
            .fixture_work(jobs::WorkFixture::SpawnFailure),
        _ => {}
    }
    if case.starts_with("changed-") {
        let name = match case.as_str() {
            "changed-payload" => "payload",
            "changed-source" => "source",
            "changed-active" => "active",
            _ => "state",
        };
        let path = Path::new("/etc/kvm/picoclaw-operations").join(name);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(path, bytes).unwrap();
    }
    if case == "bad-receipt" {
        // Killing only this real owner forfeits its receipt. The pidfd is an
        // exact test child, never a PID guess or closure substitute.
        rustix::process::pidfd_send_signal(pico_owner.as_ref().unwrap(), Signal::KILL).unwrap();
    }
    if case == "failed-exit" || case == "runtime-error" {
        let completion = if case == "failed-exit" {
            // Kill only the fixture leader. Its independent subreaper must
            // still join the TERM-resistant orphan before issuing D2.
            rustix::process::pidfd_send_signal(pidfd(Path::new("/pico/leader.pid")), Signal::KILL)
                .unwrap();
            Completion::FailedExit
        } else {
            mutation.broker.group.fail_picoclaw_control_for_test();
            Completion::RuntimeError
        };
        until(|| mutation.broker.group.poll()[3] == Some(Status::Closed(completion)));
        assert!(
            record() == before,
            "native closure alone cannot publish a job phase"
        );
        assert!(matches!(mutation.poll(), MutationStatus::Accepted(_)));
    }
    let paused = (case == "paused" || case == "stopping-drop").then(|| {
        let fd = pico_owner.as_ref().unwrap();
        rustix::process::pidfd_send_signal(fd, Signal::STOP).unwrap();
        Paused(rustix::io::dup(fd).unwrap())
    });
    mutation.request_stop();
    if let Some(resume) = blocked {
        resume.send(()).unwrap();
    }
    if case.starts_with("fail:")
        || case.starts_with("changed-")
        || case.starts_with("phase-")
        || case == "bad-receipt"
        || case == "late-uncertain"
    {
        until(|| mutation.poll() == MutationStatus::RecoveryRequired);
        assert!(StateWriters::default().configuration().is_err());
        assert!(ProcessLock::acquire().is_err() && Broker::acquire().is_err());
        assert!(Path::new("/etc/kvm/picoclaw-operations/active").is_file());
        if case.starts_with("fail:stop-")
            || case.starts_with("changed-")
            || case.starts_with("phase-")
        {
            assert_eq!(mutation.broker.group.poll()[3], Some(Status::Running));
        }
        for _ in 0..3 {
            assert_eq!(mutation.poll(), MutationStatus::RecoveryRequired);
        }
        drop(mutation);
        if case == "bad-receipt" || case == "late-uncertain" {
            // This test deliberately killed the native subreaper, forfeiting
            // its closure proof. Clean only our exact orphan leaf afterwards;
            // this signal cannot manufacture the already-asserted result.
            let _ = rustix::process::pidfd_send_signal(pico_leaf.as_ref().unwrap(), Signal::KILL);
        }
    } else {
        if paused.is_some() {
            until(|| matches!(mutation.poll(), MutationStatus::Stopping(_)));
            let persisted = record();
            assert_eq!(persisted[128 + 169], 2);
            assert_eq!(persisted[128 + 174], 0);
            for _ in 0..3 {
                assert!(matches!(mutation.poll(), MutationStatus::Stopping(_)));
            }
            assert_eq!(mutation.broker.group.poll()[3], Some(Status::Stopping));
            drop(paused);
            if case == "stopping-drop" {
                // The native Stop was sent, but dropping the owner cannot turn
                // its later receipt into a durable/public Closed job phase.
                drop(mutation);
                assert_eq!(record()[128 + 169], 2);
                assert_eq!(record()[128 + 174], 0);
                drop(ProcessLock::acquire().unwrap());
                assert!(StateWriters::default().configuration().is_err());
                settle_fixture([pico_leaf, backend_leaf], [pico_owner, backend_owner]);
                assert!(record() == persisted);
                println!("pico-mutation-checked");
                return;
            }
        }
        until(|| closed(&mut mutation));
        let state = record();
        assert_eq!(state[128 + 169], 3);
        assert_eq!(state[128 + 174], 0);
        if live {
            let completion = match case.as_str() {
                "failed-exit" => Completion::FailedExit,
                "runtime-error" => Completion::RuntimeError,
                _ => Completion::Stopped,
            };
            assert_eq!(
                mutation.broker.group.poll()[3],
                Some(Status::Closed(completion))
            );
            assert_eq!(mutation.broker.group.poll()[2], Some(Status::Running));
        }
        assert!(StateWriters::default().configuration().is_err());
        assert!(ProcessLock::acquire().is_err() && Broker::acquire().is_err());
        assert!(Path::new("/etc/kvm/picoclaw-operations/active").is_file());
        mutation.request_stop();
        assert!(closed(&mut mutation));
        assert!(record() == state);
        drop(mutation);
    }
    drop(ProcessLock::acquire().unwrap());
    assert!(StateWriters::default().configuration().is_err());
    settle_fixture([pico_leaf, backend_leaf], [pico_owner, backend_owner]);
    println!("pico-mutation-checked");
}

const HOME: &str = "/root/.picoclaw";

struct SettlePair {
    config: (Vec<u8>, u64),
    security: Option<(Vec<u8>, u64)>,
}

fn private_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

// Synthetic credential-free pair: canonical defaults for the noop cases,
// one drifted default or a missing token/config for the others.
fn settle_home(case: &str) -> SettlePair {
    use crate::update::picoclaw_startup as startup;
    use std::os::unix::fs::MetadataExt;
    if case != "settle-internal-absent" {
        private_write(
            Path::new("/etc/kvm/.picoclaw_internal_token"),
            b"synthetic-internal-fixture\n",
        );
    }
    if case == "settle-refused-absent" {
        return SettlePair {
            config: (Vec::new(), 0),
            security: None,
        };
    }
    fs::create_dir_all(HOME).unwrap();
    fs::set_permissions(HOME, fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = serde_json::json!({"agents": {"defaults": {"model": "fixture"}}});
    let mut security = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    startup::apply(
        &mut config,
        &mut security,
        "synthetic-gateway-fixture",
        "synthetic-internal-fixture",
    )
    .unwrap();
    if case.starts_with("settle-change-") {
        config["gateway"]["port"] = serde_json::json!(1);
    }
    let encoded = startup::encode(&config, &security).unwrap();
    // Original formatting/comments differ from canonical bytes on purpose: a
    // no-op must keep them exactly as found.
    let config_bytes = serde_json::to_vec(&config).unwrap();
    let security_bytes = format!("# synthetic fixture comment\n{}", encoded.security.as_str());
    private_write(&Path::new(HOME).join("config.json"), &config_bytes);
    private_write(
        &Path::new(HOME).join(".security.yml"),
        security_bytes.as_bytes(),
    );
    let inode = |name: &str| fs::metadata(Path::new(HOME).join(name)).unwrap().ino();
    SettlePair {
        config: (config_bytes, inode("config.json")),
        security: Some((security_bytes.into_bytes(), inode(".security.yml"))),
    }
}

fn assert_pair_unchanged(pair: &SettlePair) {
    use std::os::unix::fs::MetadataExt;
    if pair.config.0.is_empty() {
        assert!(!Path::new(HOME).exists());
        return;
    }
    let config = Path::new(HOME).join("config.json");
    assert!(fs::read(&config).unwrap() == pair.config.0);
    assert_eq!(fs::metadata(&config).unwrap().ino(), pair.config.1);
    let security = Path::new(HOME).join(".security.yml");
    let (bytes, inode) = pair.security.as_ref().unwrap();
    assert!(fs::read(&security).unwrap() == *bytes);
    assert_eq!(fs::metadata(&security).unwrap().ino(), *inode);
    assert!(!Path::new(HOME).join(".picoclaw-config-pair").exists());
}

fn members_present() -> [bool; 3] {
    ["active", "payload", "source"].map(|name| {
        Path::new("/etc/kvm/picoclaw-operations")
            .join(name)
            .exists()
    })
}

fn settle_until(mutation: &mut Mutation) -> MutationStatus {
    let mut status = MutationStatus::Idle;
    until(|| {
        status = mutation.poll();
        !matches!(
            status,
            MutationStatus::Settling(_) | MutationStatus::Accepted(_)
        )
    });
    status
}

fn settle_case(case: &str, mut mutation: Mutation, live: bool, pair: &SettlePair, accepted: &[u8]) {
    const RECEIPT: usize = 128 + 256;
    mutation.request_settlement();
    let status = settle_until(&mut mutation);
    assert_pair_unchanged(pair);
    if live {
        assert_eq!(mutation.broker.group.poll()[3], Some(Status::Running));
    }
    if let Some(point) = case.strip_prefix("settle-fail:") {
        assert_eq!(status, MutationStatus::RecoveryRequired);
        for _ in 0..3 {
            assert_eq!(mutation.poll(), MutationStatus::RecoveryRequired);
        }
        let state = record();
        match point {
            "completed-begin" => {
                assert!(state == accepted);
                assert_eq!(members_present(), [true; 3]);
            }
            _ => {
                // Terminal receipt is durable; the job stays fenced until
                // checked recovery retires what remains, never re-runs it.
                assert!(state[128..RECEIPT].iter().all(|byte| *byte == 0));
                assert_eq!(state[RECEIPT + 169], 8);
                assert_eq!(state[RECEIPT + 172], 2);
                let expected = match point {
                    "completed-renamed" => [true; 3],
                    "payload-retired" => [true, false, true],
                    _ => [false; 3],
                };
                assert_eq!(members_present(), expected);
            }
        }
        let mutation = match mutation.into_broker() {
            Ok(_) => panic!("uncertain settlement returned its broker"),
            Err(mutation) => *mutation,
        };
        drop(mutation);
        drop(ProcessLock::acquire().unwrap());
        if point != "active-retired" {
            assert!(StateWriters::default().configuration().is_err());
        }
        return;
    }
    match case {
        "settle-noop-absent" | "settle-noop-live" => {
            let MutationStatus::Completed(id) = status else {
                panic!("{case}: {status:?}");
            };
            assert_eq!(id.sequence, 1);
            for _ in 0..3 {
                assert_eq!(mutation.poll(), MutationStatus::Completed(id));
            }
            let state = record();
            assert!(state[128..RECEIPT].iter().all(|byte| *byte == 0));
            assert_eq!(state[RECEIPT + 169], 8, "Completed");
            assert_eq!(state[RECEIPT + 172], 2, "Noop");
            assert_eq!(state[RECEIPT + 173], 1, "runtime Unchanged");
            assert_eq!(state[RECEIPT + 170], u8::from(live));
            assert_eq!(members_present(), [false; 3]);
            let mut broker = match mutation.into_broker() {
                Ok(broker) => broker,
                Err(_) => panic!("completed settlement kept its broker"),
            };
            // The same owned scope keeps running with its launch generation.
            if live {
                assert_eq!(broker.group.poll()[3], Some(Status::Running));
                assert!(
                    broker.group.picoclaw_generation()
                        == Some(crate::update::picoclaw_config::Generation::fixture(
                            [0x31; 32]
                        ))
                );
            }
            // Admissions are free again and the store accepts new work.
            drop(broker.prepare_picoclaw_submission().unwrap());
            drop(ProcessLock::acquire().unwrap());
            drop(StateWriters::default().configuration().unwrap());
            assert_pair_unchanged(pair);
            if live {
                let admission = broker.runtime_permit().unwrap();
                let crate::native_owner::broker::Shutdown::Draining(mut drain) =
                    broker.shutdown(admission)
                else {
                    panic!("owned test cleanup was refused");
                };
                until(|| {
                    drain.poll().unwrap() == crate::native_owner::controller::DrainStatus::Drained
                });
            }
        }
        _ => {
            let expected = if case == "settle-refused-absent" {
                MutationStatus::SettlementRefused
            } else {
                MutationStatus::ChangeRequired
            };
            let (MutationStatus::ChangeRequired(id) | MutationStatus::SettlementRefused(id)) =
                status
            else {
                panic!("{case}: {status:?}");
            };
            assert_eq!(status, expected(id));
            assert!(record() == accepted, "nothing was published");
            assert_eq!(members_present(), [true; 3]);
            let mut mutation = match mutation.into_broker() {
                Ok(_) => panic!("unfinished job returned its broker"),
                Err(mutation) => *mutation,
            };
            assert!(StateWriters::default().configuration().is_err());
            // The accepted job can still take the explicit Stop path.
            mutation.request_stop();
            until(|| closed(&mut mutation));
            assert_eq!(record()[128 + 169], 3);
            assert_pair_unchanged(pair);
            drop(mutation);
            drop(ProcessLock::acquire().unwrap());
            assert!(StateWriters::default().configuration().is_err());
        }
    }
}
