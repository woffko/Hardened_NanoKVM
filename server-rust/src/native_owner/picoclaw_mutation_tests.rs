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

pub(crate) fn until(condition: impl FnMut() -> bool) {
    until_within(Duration::from_secs(30), condition)
}

/// A fixture child re-executes this whole debug test binary. Under heavy host
/// IO its start alone has taken over 30 s, so its exit gets a longer bound.
fn until_child_exits(child: &mut Child) {
    until_within(Duration::from_secs(120), || {
        child.0.as_mut().unwrap().try_wait().unwrap().is_some()
    })
}

fn until_within(limit: Duration, mut condition: impl FnMut() -> bool) {
    let start = Instant::now();
    while !condition() {
        assert!(start.elapsed() < limit, "mutation fixture watchdog");
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
    if case == "settle-assets-changed-absent" {
        command.env("NANOKVM_PICO_ACCEPT_WRITE", "closed-renamed");
        command.env("NANOKVM_PICO_ACCEPT_TARGET", Path::new(HOME).join(SKILL));
    }
    if let Some(point) = case.strip_prefix("kill:") {
        command.env("NANOKVM_PICO_ACCEPT_POINT", point);
    }
    if let Some(point) = case
        .strip_prefix("settle-fail:")
        .or_else(|| change_failure(case))
        .or_else(|| case.strip_prefix("settle-remove-fail:"))
        .or_else(|| case.strip_prefix("settle-profile-fail:"))
        .or_else(|| case.strip_prefix("settle-install-fail:"))
        .or_else(|| case.strip_prefix("settle-onboard-fail:"))
        .or_else(|| case.strip_prefix("settle-onboard-foreign-fail:"))
    {
        command.env("NANOKVM_PICO_ACCEPT_FAIL", point);
    }
    command
}

// A Startup change interrupted at one fixed point: absent runtime, absent
// internal credential, or a live runtime quiesced for the change.
fn change_failure(case: &str) -> Option<&str> {
    [
        "settle-change-fail:",
        "settle-assets-fail:",
        "settle-assets-foreign-fail:",
        "settle-assets-edited-fail:",
        "settle-assets-parent-fail:",
        "settle-internal-fail:",
        "settle-change-live-fail:",
        "settle-model-change-fail:",
    ]
    .into_iter()
    .find_map(|prefix| case.strip_prefix(prefix))
}

pub(crate) fn root() -> tempfile::TempDir {
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
    until_child_exits(&mut child);
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
fn startup_change_settlement_applies_once_and_records_the_exact_runtime_result() {
    for case in [
        "settle-change-absent",
        "settle-internal-absent",
        "settle-change-live",
        "settle-change-stop-live",
    ] {
        run(case);
    }
}

#[test]
fn startup_asset_refresh_restores_missing_generated_files_without_rewriting_the_pair() {
    run("settle-assets-absent");
    run("settle-assets-fail:applying-renamed");
    run("settle-assets-fail:bridge-staged");
    run("settle-assets-fail:bridge-published");
}

#[test]
fn startup_asset_refresh_keeps_the_default_profile_the_user_selected() {
    run("settle-assets-default-absent");
}

#[test]
fn an_object_at_an_asset_path_stays_and_blocks_no_startup_job() {
    run("settle-assets-foreign-absent");
    run("settle-assets-foreign-fail:applying-renamed");
    run("settle-assets-parent-fail:applying-renamed");
    run("settle-assets-edited-fail:applying-renamed");
}

#[test]
fn a_document_changed_after_the_plan_ends_the_job_before_applying() {
    run("settle-assets-changed-absent");
}

#[test]
fn model_settlement_shares_the_executor_with_its_own_change_before_the_defaults() {
    for case in [
        "settle-model-noop-absent",
        "settle-model-change-absent",
        "settle-model-change-live",
        "settle-model-refused-absent",
    ] {
        run(case);
    }
    for point in ["applying-renamed", "pair-published", "committed-renamed"] {
        run(&format!("settle-model-change-fail:{point}"));
    }
}

#[test]
fn onboarding_imports_a_successful_one_shot_and_retires_its_own_stage() {
    for case in [
        "settle-onboard-noop-absent",
        "settle-onboard-refused-absent",
        "settle-onboard-orphan-absent",
        "settle-onboard-absent",
        "settle-onboard-failed-absent",
        "settle-onboard-stop-absent",
        "settle-onboard-deadline-absent",
        "settle-onboard-missing-receipt-absent",
    ] {
        run(case);
    }
    for point in [
        "side-created",
        "side-marked",
        "stage-created",
        "pair-imported",
        "committed-renamed",
        "stage-renamed",
        "side-emptied",
        "stage-retired",
    ] {
        run(&format!("settle-onboard-fail:{point}"));
    }
    run("settle-onboard-foreign-fail:side-marked");
}

#[test]
fn install_puts_exactly_the_verified_staged_executable_in_place() {
    for case in [
        "settle-install-absent",
        "settle-install-unconfigured-absent",
        "settle-install-noop-absent",
        "settle-install-refused-absent",
        "settle-install-replace-live",
        "settle-install-legacy-live",
    ] {
        run(case);
    }
    for point in [
        "plan-durable",
        "closed-renamed",
        "applying-renamed",
        "binary-installed",
        "committed-renamed",
    ] {
        run(&format!("settle-install-fail:{point}"));
    }
}

#[test]
fn profile_replaces_only_an_absent_or_shipped_agent_document() {
    for case in [
        "settle-profile-noop-absent",
        "settle-profile-change-absent",
        "settle-profile-create-absent",
        "settle-profile-custom-absent",
        "settle-profile-change-live",
        "settle-profile-legacy-live",
    ] {
        run(case);
    }
    for point in [
        "plan-durable",
        "closed-renamed",
        "applying-renamed",
        "profile-published",
        "committed-renamed",
    ] {
        run(&format!("settle-profile-fail:{point}"));
    }
}

#[test]
fn removal_deletes_exactly_the_managed_files_and_keeps_the_workspace() {
    for case in [
        "settle-remove-noop-absent",
        "settle-remove-absent",
        "settle-remove-live",
        "settle-remove-refused-absent",
    ] {
        run(case);
    }
    for point in [
        "plan-durable",
        "closed-renamed",
        "applying-renamed",
        "pair-removed",
        "internal-removed",
        "binary-removed",
        "committed-renamed",
    ] {
        run(&format!("settle-remove-fail:{point}"));
    }
}

#[test]
fn startup_settlement_refuses_or_supersedes_without_changing_the_pair() {
    for case in [
        "settle-refused-absent",
        "settle-refused-live",
        "settle-superseded-absent",
    ] {
        run(case);
    }
}

#[test]
fn startup_settlement_errors_stay_fenced_in_their_boot_and_settle_exactly_later() {
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
fn startup_change_errors_keep_an_exact_fenced_state_until_a_later_boot_settles_it() {
    for point in [
        "plan-durable",
        "closed-renamed",
        "applying-renamed",
        "internal-installed",
        "pair-published",
        "committed-renamed",
    ] {
        run(&format!("settle-change-fail:{point}"));
    }
    for point in ["applying-renamed", "internal-installed"] {
        run(&format!("settle-internal-fail:{point}"));
    }
    for point in ["committed-renamed", "activating-renamed"] {
        run(&format!("settle-change-live-fail:{point}"));
    }
}

#[test]
fn parent_fixture_cleanup_rejects_foreign_pid_file_and_reaps_only_its_owned_orphan() {
    let root = root();
    let cleanup = FixtureLeaves(root.path());
    let mut child = Child(Some(
        command(root.path(), "parent-cleanup").spawn().unwrap(),
    ));
    until_child_exits(&mut child);
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

pub(crate) const RECEIPT: usize = 128 + 256;

pub(crate) fn record() -> Vec<u8> {
    fs::read("/etc/kvm/picoclaw-operations/state").unwrap()
}

// Early S02 of the SAME kernel boot: an active job stays with its native
// owner, so nothing is settled and the fence remains.
fn activate_same_boot_fenced(state: &[u8]) {
    assert!(matches!(
        crate::native_owner::broker::boot::activate_early(),
        Err(crate::native_owner::broker::JournalError::Busy)
    ));
    assert!(
        record() == state,
        "the same boot never settles an active job"
    );
}

// Early S02 of an emulated later kernel boot: the job settles exactly once
// and every private member is retired.
fn activate_later_boot() -> Vec<u8> {
    jobs::TEST_BOOT.with(|boot| boot.set(Some([0x5a; 16])));
    crate::native_owner::broker::boot::activate_early().unwrap();
    let settled = record();
    assert_eq!(members_present(), [false; 3]);
    assert!(!plan_present());
    crate::native_owner::broker::boot::activate_early().unwrap();
    assert!(record() == settled, "a repeated early boot changes nothing");
    drop(StateWriters::default().configuration().unwrap());
    jobs::TEST_BOOT.with(|boot| boot.set(None));
    settled
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
    let live = case != "absent"
        && !case.ends_with("-absent")
        && !case.starts_with("settle-fail:")
        && !case.starts_with("settle-change-fail:")
        && !case.starts_with("settle-internal-fail:")
        && !case.starts_with("settle-model-change-fail:")
        && !case.starts_with("settle-remove-fail:")
        && !case.starts_with("settle-profile-fail:")
        && !case.starts_with("settle-install-fail:")
        && !case.starts_with("settle-onboard-fail:")
        && !case.starts_with("settle-onboard-foreign-fail:");
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
    let fixture = (relaunched(&case) || onboard_spawns(&case)).then(|| host_runtime(root));
    // The onboarding one-shot fixture is this test binary at its host path.
    let test_exe = std::env::current_exe().unwrap();
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
            MutationAdmission::Refused(broker) => *broker,
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
            MutationAdmission::Refused(broker) => *broker,
            MutationAdmission::Owned(_) => panic!("busy admission must return the unchanged owner"),
        };
        assert_eq!(broker.group.poll()[3], Some(Status::Running));
        assert!(record() == initial);
        drop(held);
    }
    let mut mutation = match broker.begin_picoclaw_mutation() {
        MutationAdmission::Owned(mutation) => *mutation,
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
        .submit(PicoCursor { epoch, sequence: 0 }, [67; 16], request(&case))
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
    // Resume permission starts from the running state, except for removal.
    assert_eq!(
        before[128 + 174],
        u8::from(live && case != "stop-during-accept" && !case.starts_with("settle-remove-"))
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
        if onboard_spawns(&case) {
            mutation.onboard_fixture = Some((
                test_exe.clone(),
                [
                    "--exact",
                    "native_owner::broker::ipc::tests::picoclaw::onboard_probe",
                    "--nocapture",
                ]
                .map(Into::into)
                .to_vec(),
                vec![("NANOKVM_NATIVE_ONBOARD_FIXTURE".into(), "/".into())],
            ));
        }
        settle_case(&case, mutation, live, &pair, &before, fixture.as_ref());
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
    if case.starts_with("fail:") {
        // Its processes gone as after a power cut, the same boot still keeps
        // the job fenced; a later boot cancels it with nothing applied.
        let state = record();
        activate_same_boot_fenced(&state);
        let settled = activate_later_boot();
        assert!(settled[128..RECEIPT].iter().all(|byte| *byte == 0));
        assert_eq!(settled[RECEIPT + 169], 8, "Completed");
        assert_eq!(settled[RECEIPT + 170], 1, "was running");
        assert_eq!(settled[RECEIPT + 172], 4, "Cancelled");
        assert_eq!(settled[RECEIPT + 173], 2, "runtime NotRequested");
        assert_eq!(settled[RECEIPT + 174], 0, "no resume");
    }
    println!("pico-mutation-checked");
}

pub(crate) const HOME: &str = "/root/.picoclaw";
const MODEL: &str = "synthetic-vendor/synthetic-model";
const API_BASE: &str = "https://synthetic.invalid/v1";
const API_KEY: &str = "synthetic-model-key-fixture";

// The fixed synthetic Model request, as the job transport carries it.
pub(crate) fn model_kind() -> crate::native_owner::broker::ipc::JobKind {
    crate::native_owner::broker::ipc::JobKind::Model {
        model: zeroize::Zeroizing::new(MODEL.into()),
        api_base: zeroize::Zeroizing::new(API_BASE.into()),
        api_key: zeroize::Zeroizing::new(API_KEY.into()),
    }
}

// Startup jobs, or a Model job selecting the fixed synthetic model.
fn request(case: &str) -> PicoRequest {
    if case.starts_with("settle-remove-") {
        return PicoRequest::Remove;
    }
    if case.starts_with("settle-profile-") {
        return PicoRequest::Profile(crate::native_owner::broker::PicoProfile::Kvm);
    }
    if case.starts_with("settle-onboard") {
        return PicoRequest::Onboard;
    }
    if case.starts_with("settle-install-") {
        let mut digest = staged_digest();
        if case == "settle-install-refused-absent" {
            digest[0] ^= 1;
        }
        return PicoRequest::Install { digest };
    }
    if case.starts_with("settle-model-") {
        PicoRequest::Model {
            model: zeroize::Zeroizing::new(MODEL.into()),
            api_base: zeroize::Zeroizing::new(API_BASE.into()),
            api_key: zeroize::Zeroizing::new(API_KEY.into()),
        }
    } else {
        PicoRequest::Startup
    }
}

// Cases whose change relaunches a real fixture scope.
fn relaunched(case: &str) -> bool {
    matches!(
        case,
        "settle-change-live" | "settle-model-change-live" | "settle-profile-change-live"
    )
}
const GATEWAY: &str = "synthetic-gateway-fixture";
pub(crate) const INTERNAL: &str = "synthetic-internal-fixture";

// The relaunched fixture runs inside the chroot: provide the host loader,
// libraries, /dev/null and the fixture's own build directory (it re-executes
// itself by its real path) by bind mounts in this private mount namespace.
fn host_runtime(root: &Path) -> std::path::PathBuf {
    let test = std::env::current_exe().unwrap();
    let build = test.parent().unwrap().parent().unwrap().to_path_buf();
    for host in ["/usr", "/lib", "/lib64", "/bin", "/dev"]
        .into_iter()
        .map(std::path::PathBuf::from)
        .chain([build.clone()])
    {
        let Ok(metadata) = fs::symlink_metadata(&host) else {
            continue;
        };
        let target = root.join(host.strip_prefix("/").unwrap());
        if metadata.file_type().is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(&host).unwrap(), &target).unwrap();
        } else {
            fs::create_dir_all(&target).unwrap();
            nix::mount::mount(
                Some(host.as_path()),
                target.as_path(),
                None::<&str>,
                nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
                None::<&str>,
            )
            .unwrap();
        }
    }
    build.join("nanokvm-native-owner-fixture")
}

pub(crate) struct SettlePair {
    config: (Vec<u8>, u64),
    security: Option<(Vec<u8>, u64)>,
    /// A Model job: its model selection precedes the defaults.
    model: bool,
}

fn managed_workspace() {
    use std::os::unix::fs::PermissionsExt as _;
    let workspace = Path::new(HOME).join("workspace");
    for (name, bytes, executable) in crate::update::picoclaw_config::GENERATED {
        let path = workspace.join(name);
        if path.exists() {
            continue;
        }
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if executable { 0o755 } else { 0o600 }),
        )
        .unwrap();
    }
}

fn private_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

// Synthetic credential-free pair: canonical defaults for the noop cases,
// one drifted default or a missing token/config for the others.
pub(crate) fn settle_home(case: &str) -> SettlePair {
    use crate::update::picoclaw_startup as startup;
    use std::os::unix::fs::MetadataExt;
    if case != "settle-internal-absent"
        && !case.starts_with("settle-internal-fail:")
        && case != "settle-remove-noop-absent"
    {
        private_write(
            Path::new("/etc/kvm/.picoclaw_internal_token"),
            format!("{INTERNAL}\n").as_bytes(),
        );
    }
    if case.starts_with("settle-install-") {
        install_fixture(case);
    }
    if let Some(early) = onboard_fixture(case) {
        return early;
    }
    if case.starts_with("settle-refused-")
        || case == "settle-model-refused-absent"
        || case == "settle-remove-noop-absent"
        || case == "settle-install-unconfigured-absent"
    {
        return SettlePair {
            config: (Vec::new(), 0),
            security: None,
            model: case.starts_with("settle-model-"),
        };
    }
    fs::create_dir_all(HOME).unwrap();
    fs::set_permissions(HOME, fs::Permissions::from_mode(0o700)).unwrap();
    if !case.starts_with("settle-profile-") {
        managed_workspace();
    }
    if case.starts_with("settle-assets-") {
        fs::write(Path::new(HOME).join("workspace/AGENT.md"), AGENT).unwrap();
        fs::remove_file(Path::new(HOME).join(SKILL)).unwrap();
        fs::remove_file(Path::new(HOME).join(BRIDGE)).unwrap();
    }
    if case == "settle-assets-default-absent" {
        fs::write(
            Path::new(HOME).join("workspace/AGENT.md"),
            crate::update::picoclaw_profile::SHIPPED_AGENT,
        )
        .unwrap();
    }
    if case == "settle-assets-foreign-absent" {
        fs::create_dir(Path::new(HOME).join(SKILL)).unwrap();
    }
    let mut config = serde_json::json!({"agents": {"defaults": {"model": "fixture"}}});
    let mut security = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
    if case == "settle-model-noop-absent" {
        // Already selected with the same endpoint and key.
        crate::update::picoclaw_model::apply(&mut config, &mut security, MODEL, API_BASE, API_KEY)
            .unwrap();
    }
    startup::apply(
        &mut config,
        &mut security,
        GATEWAY,
        INTERNAL,
        Path::new(HOME),
    )
    .unwrap();
    if case.starts_with("settle-change-") || case == "settle-superseded-absent" {
        config["gateway"]["port"] = serde_json::json!(1);
    }
    if case.ends_with("-legacy-live") {
        // As RC12 left it: a pair without the local tool policy.
        config["agents"]["defaults"]["restrict_to_workspace"] = serde_json::json!(false);
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
    if case.starts_with("settle-remove-") {
        remove_fixture(case);
    }
    if case.starts_with("settle-profile-") {
        profile_fixture(case);
    }
    let inode = |name: &str| fs::metadata(Path::new(HOME).join(name)).unwrap().ino();
    SettlePair {
        config: (config_bytes, inode("config.json")),
        security: Some((security_bytes.into_bytes(), inode(".security.yml"))),
        model: case.starts_with("settle-model-"),
    }
}

pub(crate) fn assert_pair_unchanged(pair: &SettlePair) {
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

const BINARY: &str = "/usr/bin/picoclaw";
const AGENT: &[u8] = b"synthetic custom agent profile, kept by removal\n";
const EDIT: &[u8] = b"synthetic concurrent edit\n";
const SKILL: &str = "workspace/skills/kvm-control/SKILL.md";
const BRIDGE: &str = "workspace/skills/kvm-control/scripts/nanokvm-bridge.sh";

// The managed executable (or a link in its place) and a user workspace file.
fn remove_fixture(case: &str) {
    fs::create_dir_all("/usr/bin").unwrap();
    fs::set_permissions("/usr/bin", fs::Permissions::from_mode(0o755)).unwrap();
    if case == "settle-remove-refused-absent" {
        std::os::unix::fs::symlink("/producer-image", BINARY).unwrap();
    } else {
        fs::write(BINARY, b"synthetic runtime executable, never run\n").unwrap();
        fs::set_permissions(BINARY, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let workspace = Path::new(HOME).join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    private_write(&workspace.join("AGENT.md"), AGENT);
}

// Onboarding cases whose job runs the one-shot fixture.
fn onboard_spawns(case: &str) -> bool {
    matches!(
        case,
        "settle-onboard-absent"
            | "settle-onboard-failed-absent"
            | "settle-onboard-stop-absent"
            | "settle-onboard-deadline-absent"
            | "settle-onboard-missing-receipt-absent"
            | "settle-onboard-fail:pair-imported"
            | "settle-onboard-fail:committed-renamed"
            | "settle-onboard-fail:stage-renamed"
            | "settle-onboard-fail:side-emptied"
            | "settle-onboard-fail:stage-retired"
    )
}

// Trees under a job's side name: present only while a stage is created or
// retired, never after a settlement.
fn onboard_sides() -> usize {
    let prefix = format!("{}-", crate::native_owner::picoclaw_home::ONBOARD_DIRECTORY);
    fs::read_dir(HOME).map_or(0, |entries| {
        entries
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(&prefix))
            })
            .count()
    })
}

fn onboard_stage() -> std::path::PathBuf {
    Path::new(HOME).join(crate::native_owner::picoclaw_home::ONBOARD_DIRECTORY)
}

// What an onboarding case starts from: no Home at all, except an existing
// configuration (no-op), a security file alone (refused) or a leftover stage.
fn onboard_fixture(case: &str) -> Option<SettlePair> {
    if !case.starts_with("settle-onboard") || case == "settle-onboard-noop-absent" {
        return None;
    }
    let empty = || SettlePair {
        config: (Vec::new(), 0),
        security: None,
        model: false,
    };
    match case {
        "settle-onboard-refused-absent" => {
            fs::create_dir_all(HOME).unwrap();
            fs::set_permissions(HOME, fs::Permissions::from_mode(0o700)).unwrap();
            private_write(&Path::new(HOME).join(".security.yml"), b"kept: true\n");
        }
        "settle-onboard-orphan-absent" => {
            fs::create_dir_all(onboard_stage().join("workspace")).unwrap();
            fs::set_permissions(HOME, fs::Permissions::from_mode(0o700)).unwrap();
            private_write(&onboard_stage().join("leftover"), b"older evidence\n");
        }
        _ => {}
    }
    Some(empty())
}

// The output a successful upstream one-shot leaves in the stage.
fn write_onboard_stage() {
    let stage = onboard_stage();
    fs::create_dir(stage.join("workspace")).unwrap();
    let config = serde_json::json!({
        "agents": {"defaults": {"workspace": stage.join("workspace")}},
        "model_list": []
    });
    private_write(
        &stage.join("config.json"),
        &serde_json::to_vec(&config).unwrap(),
    );
    private_write(&stage.join(".security.yml"), b"model_list: {}\n");
    private_write(
        &stage.join("workspace/notes.md"),
        b"synthetic onboarding notes\n",
    );
}

// The imported Home: rewritten workspace, the stage's own file, the generated
// assets and the security document; the stage itself is gone.
fn assert_onboarded() {
    let home = Path::new(HOME);
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(home.join("config.json")).unwrap()).unwrap();
    assert_eq!(
        config["agents"]["defaults"]["workspace"],
        home.join("workspace").to_str().unwrap()
    );
    assert_eq!(config["agents"]["defaults"]["restrict_to_workspace"], true);
    assert_eq!(
        fs::read(home.join(".security.yml")).unwrap(),
        b"model_list: {}\n"
    );
    assert_eq!(
        fs::read(home.join("workspace/notes.md")).unwrap(),
        b"synthetic onboarding notes\n"
    );
    assert!(
        fs::read(home.join("workspace/AGENT.md")).unwrap()
            == include_bytes!("../../../kvmapp/picoclaw/AGENT_KVM.md")
    );
    assert!(home.join("workspace/skills/kvm-control/SKILL.md").is_file());
}

fn onboard_case(case: &str, mut mutation: Mutation, pair: &SettlePair) {
    let marker = onboard_stage().join(".nanokvm-onboard-job");
    match case {
        "settle-onboard-failed-absent" => fs::write("/onboard-fail", b"fail").unwrap(),
        "settle-onboard-deadline-absent" => {
            mutation.onboard_bound = Some(std::time::Duration::from_millis(300));
        }
        "settle-onboard-missing-receipt-absent" => {
            fs::write("/onboard-missing-receipt", b"fixture").unwrap();
        }
        _ => {}
    }
    mutation.request_settlement();
    if onboard_spawns(case) {
        // The marker is durable before the one-shot runs.
        until(|| {
            mutation.poll();
            Path::new("/onboard-pid").exists()
        });
        assert!(marker.is_file());
        match case {
            "settle-onboard-stop-absent" => mutation.request_stop(),
            // Only the bound stops this one-shot; nothing releases it.
            "settle-onboard-deadline-absent" => {}
            _ => {
                write_onboard_stage();
                fs::write("/onboard-release", b"release").unwrap();
            }
        }
    }
    let status = settle_until(&mut mutation);
    if case == "settle-onboard-missing-receipt-absent" {
        // A complete stage without the one-shot's receipt is never imported:
        // the job stays fenced, and a later boot fails it.
        assert_eq!(status, MutationStatus::RecoveryRequired);
        let state = record();
        assert_eq!(state[128 + 169], 4, "Applying");
        assert!(marker.is_file());
        assert!(!Path::new(HOME).join("config.json").exists());
        let mutation = match mutation.into_broker() {
            Ok(_) => panic!("an unreceipted one-shot returned its broker"),
            Err(mutation) => *mutation,
        };
        drop(mutation);
        assert!(StateWriters::default().configuration().is_err());
        activate_same_boot_fenced(&state);
        let settled = activate_later_boot();
        assert_eq!(settled[RECEIPT + 169], 8, "Completed");
        assert_eq!(settled[RECEIPT + 172], 3, "Failed");
        assert_eq!(settled[RECEIPT + 173], 2, "runtime NotRequested");
        assert!(!onboard_stage().exists());
        assert_eq!(onboard_sides(), 0);
        assert!(!Path::new(HOME).join("config.json").exists());
        return;
    }
    if let Some(point) = case.strip_prefix("settle-onboard-foreign-fail:") {
        // An unmarked stage beside this job's side tree is never adopted: the
        // later boot keeps the fence and both trees.
        assert_eq!(status, MutationStatus::RecoveryRequired);
        assert_eq!(point, "side-marked");
        let state = record();
        drop(mutation);
        fs::create_dir(onboard_stage()).unwrap();
        private_write(&onboard_stage().join("leftover"), b"older evidence\n");
        jobs::TEST_BOOT.with(|boot| boot.set(Some([0x5a; 16])));
        assert!(crate::native_owner::broker::boot::activate_early().is_err());
        jobs::TEST_BOOT.with(|boot| boot.set(None));
        assert!(record() == state, "a foreign stage keeps the job active");
        assert_eq!(
            fs::read(onboard_stage().join("leftover")).unwrap(),
            b"older evidence\n"
        );
        assert_eq!(onboard_sides(), 1);
        return;
    }
    if let Some(point) = case.strip_prefix("settle-onboard-fail:") {
        assert_eq!(status, MutationStatus::RecoveryRequired);
        let state = record();
        let before_spawn = matches!(point, "side-created" | "side-marked" | "stage-created");
        let phase = if before_spawn || point == "pair-imported" {
            4
        } else {
            5
        };
        assert_eq!(state[128 + 169], phase);
        assert_eq!(state[128 + 168], 1, "Onboard");
        let imported = !before_spawn;
        assert_eq!(Path::new(HOME).join("config.json").exists(), imported);
        // The fixed name exists only while it carries the job's marker.
        assert_eq!(
            marker.exists(),
            matches!(
                point,
                "stage-created" | "pair-imported" | "committed-renamed"
            )
        );
        assert_eq!(onboard_stage().exists(), marker.exists());
        assert_eq!(
            onboard_sides(),
            usize::from(matches!(
                point,
                "side-created" | "side-marked" | "stage-renamed" | "side-emptied"
            ))
        );
        let mutation = match mutation.into_broker() {
            Ok(_) => panic!("uncertain onboarding returned its broker"),
            Err(mutation) => *mutation,
        };
        drop(mutation);
        drop(ProcessLock::acquire().unwrap());
        assert!(StateWriters::default().configuration().is_err());
        activate_same_boot_fenced(&state);
        let settled = activate_later_boot();
        assert!(settled[128..RECEIPT].iter().all(|byte| *byte == 0));
        assert_eq!(settled[RECEIPT + 169], 8, "Completed");
        assert_eq!(settled[RECEIPT + 173], 2, "runtime NotRequested");
        assert_eq!(
            settled[RECEIPT + 172],
            if imported { 1 } else { 3 },
            "outcome"
        );
        assert!(!onboard_stage().exists(), "the job's own stage is retired");
        assert_eq!(onboard_sides(), 0);
        if imported {
            assert_onboarded();
        } else {
            assert!(!Path::new(HOME).join("config.json").exists());
        }
        return;
    }
    let state = record();
    match case {
        "settle-onboard-noop-absent" => {
            let MutationStatus::Completed(_) = status else {
                panic!("{case}: {status:?}");
            };
            assert_eq!(state[RECEIPT + 168], 1, "Onboard");
            assert_eq!(state[RECEIPT + 172], 2, "Noop");
            assert_pair_unchanged(pair);
            assert!(!onboard_stage().exists());
        }
        "settle-onboard-refused-absent" | "settle-onboard-orphan-absent" => {
            let MutationStatus::SettlementRefused(_) = status else {
                panic!("{case}: {status:?}");
            };
            assert_eq!(state[RECEIPT + 172], 3, "Failed");
            assert!(!Path::new(HOME).join("config.json").exists());
            if case == "settle-onboard-orphan-absent" {
                // Older evidence is kept, never adopted or deleted.
                assert_eq!(
                    fs::read(onboard_stage().join("leftover")).unwrap(),
                    b"older evidence\n"
                );
            } else {
                assert_eq!(
                    fs::read(Path::new(HOME).join(".security.yml")).unwrap(),
                    b"kept: true\n"
                );
            }
        }
        "settle-onboard-absent" => {
            let MutationStatus::Completed(_) = status else {
                panic!("{case}: {status:?}");
            };
            assert_eq!(state[RECEIPT + 168], 1, "Onboard");
            assert_eq!(state[RECEIPT + 172], 1, "Changed");
            assert_eq!(state[RECEIPT + 173], 2, "runtime NotRequested");
            assert_onboarded();
            assert!(!onboard_stage().exists());
        }
        _ => {
            // A failed or stopped one-shot changes nothing but its own stage.
            let MutationStatus::Superseded(_) = status else {
                panic!("{case}: {status:?}");
            };
            assert_eq!(state[RECEIPT + 172], 3, "Failed");
            assert_eq!(state[RECEIPT + 173], 2, "runtime NotRequested");
            assert!(!Path::new(HOME).join("config.json").exists());
            assert!(!onboard_stage().exists());
        }
    }
    assert_eq!(members_present(), [false; 3]);
    assert!(!plan_present());
    drop(assert_released(mutation));
}

const STAGED_BINARY: &[u8] = b"synthetic staged runtime executable, never run\n";
const OLD_BINARY: &[u8] = b"synthetic previous runtime executable, never run\n";

pub(crate) fn staged_digest() -> [u8; 64] {
    use sha2::Digest as _;
    sha2::Sha512::digest(STAGED_BINARY).into()
}

fn executable_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

// The installer's staged executable and the executable a case starts from.
fn install_fixture(case: &str) {
    for directory in ["/root/.picoclaw-cache", "/usr/bin"] {
        fs::create_dir_all(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
    }
    executable_write(Path::new("/root/.picoclaw-cache/picoclaw"), STAGED_BINARY);
    match case {
        "settle-install-noop-absent" => executable_write(Path::new(BINARY), STAGED_BINARY),
        "settle-install-replace-live"
        | "settle-install-legacy-live"
        | "settle-install-refused-absent" => executable_write(Path::new(BINARY), OLD_BINARY),
        _ => {}
    }
}

// The installed executable's bytes, after checking its executable mode.
pub(crate) fn installed_binary() -> Option<Vec<u8>> {
    let metadata = fs::symlink_metadata(BINARY).ok()?;
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o755);
    Some(fs::read(BINARY).unwrap())
}

const SHIPPED_DEFAULT: &[u8] = b"---\nname: pico\n---\nsynthetic default profile\n";
const SHIPPED_KVM: &[u8] = b"---\nname: pico-kvm\n---\nsynthetic kvm profile\n";
const CUSTOM_AGENT: &[u8] = b"---\nname: pico\n---\nmy own customized notes\n";

fn agent_path() -> std::path::PathBuf {
    Path::new(HOME).join("workspace/AGENT.md")
}

pub(crate) fn assert_profile_installed() {
    assert!(fs::read(agent_path()).unwrap() == SHIPPED_KVM);
}

fn public_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
}

// The shipped profiles and the workspace document a case starts from. The
// workspace document is 0644 as the legacy writer left it.
fn profile_fixture(case: &str) {
    fs::create_dir_all("/kvmapp/picoclaw").unwrap();
    public_write(Path::new("/kvmapp/picoclaw/AGENT.md"), SHIPPED_DEFAULT);
    public_write(Path::new("/kvmapp/picoclaw/AGENT_KVM.md"), SHIPPED_KVM);
    let current = match case {
        "settle-profile-create-absent" => return,
        "settle-profile-noop-absent" => SHIPPED_KVM,
        "settle-profile-custom-absent" => CUSTOM_AGENT,
        _ => SHIPPED_DEFAULT,
    };
    fs::create_dir_all(Path::new(HOME).join("workspace")).unwrap();
    public_write(&agent_path(), current);
}

// Which managed files are present: executable, credential, config, security.
pub(crate) fn managed_present() -> [bool; 4] {
    [
        fs::symlink_metadata(BINARY).is_ok(),
        Path::new("/etc/kvm/.picoclaw_internal_token").exists(),
        Path::new(HOME).join("config.json").exists(),
        Path::new(HOME).join(".security.yml").exists(),
    ]
}

// User data in Home is never part of a removal.
pub(crate) fn assert_workspace_kept() {
    assert!(fs::read(Path::new(HOME).join("workspace/AGENT.md")).unwrap() == AGENT);
}

pub(crate) fn internal_on_disk() -> Option<String> {
    fs::read_to_string("/etc/kvm/.picoclaw_internal_token")
        .ok()
        .map(|value| value.trim().to_string())
}

// The exact canonical pair the job must install, from the ORIGINAL bytes.
fn desired(pair: &SettlePair, internal: &str) -> crate::update::picoclaw_startup::Encoding {
    use crate::update::picoclaw_startup as startup;
    let security = &pair.security.as_ref().unwrap().0;
    let mut documents = startup::decode(&pair.config.0, Some(security)).unwrap();
    if pair.model {
        crate::update::picoclaw_model::apply(
            &mut documents.config,
            &mut documents.security,
            MODEL,
            API_BASE,
            API_KEY,
        )
        .unwrap();
    }
    startup::desired(&documents, GATEWAY, internal, Path::new(HOME)).unwrap()
}

pub(crate) fn assert_pair_desired(pair: &SettlePair, internal: &str) {
    let wanted = desired(pair, internal);
    assert!(fs::read(Path::new(HOME).join("config.json")).unwrap() == wanted.config[..]);
    assert!(
        fs::read(Path::new(HOME).join(".security.yml")).unwrap() == *wanted.security.as_bytes()
    );
    assert!(!Path::new(HOME).join(".picoclaw-config-pair").exists());
}

pub(crate) fn members_present() -> [bool; 3] {
    ["active", "payload", "source"].map(|name| {
        Path::new("/etc/kvm/picoclaw-operations")
            .join(name)
            .exists()
    })
}

// The bridge can run however its job went, nothing temporary is left beside it,
// and whatever came to stand at an asset's path is still there.
fn assert_assets_installed(case: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let skill = Path::new(HOME).join(SKILL);
    if case.starts_with("settle-assets-foreign-") {
        assert!(skill.is_dir());
    } else if case.starts_with("settle-assets-edited-") {
        assert_eq!(fs::read(&skill).unwrap(), EDIT);
    } else {
        assert_eq!(
            fs::read(&skill).unwrap(),
            crate::update::picoclaw_config::GENERATED[1].1
        );
    }
    let bridge = Path::new(HOME).join(BRIDGE);
    if case.starts_with("settle-assets-parent-") {
        assert_eq!(fs::read(bridge.parent().unwrap()).unwrap(), EDIT);
        return;
    }
    assert_eq!(
        fs::read(&bridge).unwrap(),
        crate::update::picoclaw_config::GENERATED[2].1
    );
    assert_eq!(
        fs::metadata(&bridge).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::read_dir(bridge.parent().unwrap()).unwrap().count(),
        1,
        "a temporary stayed beside the bridge"
    );
}

fn plan_present() -> bool {
    Path::new("/etc/kvm/picoclaw-operations/plan").exists()
}

fn settle_until(mutation: &mut Mutation) -> MutationStatus {
    let mut status = MutationStatus::Idle;
    until(|| {
        status = mutation.poll();
        matches!(
            status,
            MutationStatus::Completed(_)
                | MutationStatus::Superseded(_)
                | MutationStatus::SettlementRefused(_)
                | MutationStatus::Quiesced(_)
                | MutationStatus::RecoveryRequired
        )
    });
    status
}

fn shutdown(broker: Broker) {
    let admission = broker.runtime_permit().unwrap();
    let crate::native_owner::broker::Shutdown::Draining(mut drain) = broker.shutdown(admission)
    else {
        panic!("owned test cleanup was refused");
    };
    until(|| drain.poll().unwrap() == crate::native_owner::controller::DrainStatus::Drained);
}

fn assert_released(mutation: Mutation) -> Broker {
    let mut broker = match mutation.into_broker() {
        Ok(broker) => broker,
        Err(_) => panic!("terminal settlement kept its broker"),
    };
    // Admissions are free again and the store accepts new work.
    drop(broker.prepare_picoclaw_submission().unwrap());
    drop(ProcessLock::acquire().unwrap());
    drop(StateWriters::default().configuration().unwrap());
    broker
}

fn settle_case(
    case: &str,
    mut mutation: Mutation,
    live: bool,
    pair: &SettlePair,
    accepted: &[u8],
    fixture: Option<&std::path::PathBuf>,
) {
    if case.starts_with("settle-onboard") {
        return onboard_case(case, mutation, pair);
    }
    if let Some(program) = fixture {
        mutation.launch_fixture = Some((
            program.clone(),
            ["scope", "owned-tree", "/pico"].map(Into::into).to_vec(),
        ));
    }
    if case == "settle-superseded-absent" {
        // An unmanaged writer replaces the accepted pair before apply.
        private_write(
            &Path::new(HOME).join("config.json"),
            b"{\"superseded\":true}",
        );
    }
    let blocked = (case == "settle-change-stop-live").then(|| {
        let (entered, receive) = std::sync::mpsc::channel();
        let (resume, wait) = std::sync::mpsc::channel();
        mutation
            .submission
            .fixture_work(jobs::WorkFixture::Block(entered, wait));
        (receive, resume)
    });
    mutation.request_settlement();
    if let Some((entered, resume)) = blocked {
        assert!(matches!(mutation.poll(), MutationStatus::Settling(_)));
        entered.recv_timeout(Duration::from_secs(30)).unwrap();
        // An explicit Stop arrives while the preflight is still running.
        mutation.request_stop();
        resume.send(()).unwrap();
    }
    let status = settle_until(&mut mutation);
    if let Some(point) = case.strip_prefix("settle-fail:") {
        assert_pair_unchanged(pair);
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
        let settled = if point == "completed-begin" {
            activate_same_boot_fenced(&state);
            let settled = activate_later_boot();
            assert_eq!(settled[RECEIPT + 172], 4, "Cancelled");
            assert_eq!(settled[RECEIPT + 173], 2, "runtime NotRequested");
            settled
        } else {
            // A durable terminal receipt only needs its exact retirement
            // finished, already in this boot; the receipt is never rewritten.
            crate::native_owner::broker::boot::activate_early().unwrap();
            assert!(record() == state);
            assert_eq!(members_present(), [false; 3]);
            state
        };
        assert!(settled[128..RECEIPT].iter().all(|byte| *byte == 0));
        assert_eq!(settled[RECEIPT + 169], 8, "Completed");
        assert_pair_unchanged(pair);
        drop(StateWriters::default().configuration().unwrap());
        return;
    }
    if let Some(point) = case.strip_prefix("settle-install-fail:") {
        assert_eq!(status, MutationStatus::RecoveryRequired);
        for _ in 0..3 {
            assert_eq!(mutation.poll(), MutationStatus::RecoveryRequired);
        }
        let state = record();
        let phase = match point {
            "plan-durable" => 1,
            "closed-renamed" => 3,
            "committed-renamed" => 5,
            _ => 4,
        };
        assert_eq!(state[128 + 169], phase);
        assert_eq!(state[128 + 168], 5, "Install");
        assert_eq!(members_present(), [true; 3]);
        assert!(plan_present(), "the install stays bound to its plan");
        let installed = matches!(point, "binary-installed" | "committed-renamed");
        assert!(installed_binary().as_deref() == installed.then_some(STAGED_BINARY));
        let mutation = match mutation.into_broker() {
            Ok(_) => panic!("uncertain install returned its broker"),
            Err(mutation) => *mutation,
        };
        drop(mutation);
        drop(ProcessLock::acquire().unwrap());
        assert!(StateWriters::default().configuration().is_err());
        activate_same_boot_fenced(&state);
        let settled = activate_later_boot();
        assert!(settled[128..RECEIPT].iter().all(|byte| *byte == 0));
        assert_eq!(settled[RECEIPT + 169], 8, "Completed");
        assert_eq!(settled[RECEIPT + 173], 2, "runtime NotRequested");
        if phase < 4 {
            assert_eq!(settled[RECEIPT + 172], 4, "Cancelled");
            assert!(installed_binary().is_none(), "nothing was installed");
        } else {
            assert_eq!(settled[RECEIPT + 172], 1, "Changed");
            assert!(installed_binary().as_deref() == Some(STAGED_BINARY));
        }
        assert_pair_unchanged(pair);
        return;
    }
    if let Some(point) = case.strip_prefix("settle-profile-fail:") {
        assert_eq!(status, MutationStatus::RecoveryRequired);
        for _ in 0..3 {
            assert_eq!(mutation.poll(), MutationStatus::RecoveryRequired);
        }
        let state = record();
        let phase = match point {
            "plan-durable" => 1,
            "closed-renamed" => 3,
            "committed-renamed" => 5,
            _ => 4,
        };
        assert_eq!(state[128 + 169], phase);
        assert_eq!(state[128 + 168], 4, "Profile");
        assert_eq!(members_present(), [true; 3]);
        assert!(plan_present(), "the profile change stays bound to its plan");
        let installed = matches!(point, "profile-published" | "committed-renamed");
        assert!(
            fs::read(agent_path()).unwrap()
                == if installed {
                    SHIPPED_KVM
                } else {
                    SHIPPED_DEFAULT
                }
        );
        assert_pair_unchanged(pair);
        let mutation = match mutation.into_broker() {
            Ok(_) => panic!("uncertain profile change returned its broker"),
            Err(mutation) => *mutation,
        };
        drop(mutation);
        drop(ProcessLock::acquire().unwrap());
        assert!(StateWriters::default().configuration().is_err());
        activate_same_boot_fenced(&state);
        let settled = activate_later_boot();
        assert!(settled[128..RECEIPT].iter().all(|byte| *byte == 0));
        assert_eq!(settled[RECEIPT + 169], 8, "Completed");
        assert_eq!(settled[RECEIPT + 173], 2, "runtime NotRequested");
        if phase < 4 {
            assert_eq!(settled[RECEIPT + 172], 4, "Cancelled");
            assert!(fs::read(agent_path()).unwrap() == SHIPPED_DEFAULT);
        } else {
            assert_eq!(settled[RECEIPT + 172], 1, "Changed");
            assert!(fs::read(agent_path()).unwrap() == SHIPPED_KVM);
        }
        assert_pair_unchanged(pair);
        return;
    }
    if let Some(point) = case.strip_prefix("settle-remove-fail:") {
        assert_eq!(status, MutationStatus::RecoveryRequired);
        for _ in 0..3 {
            assert_eq!(mutation.poll(), MutationStatus::RecoveryRequired);
        }
        let state = record();
        let phase = match point {
            "plan-durable" => 1,
            "closed-renamed" => 3,
            "committed-renamed" => 5,
            _ => 4,
        };
        assert_eq!(state[128 + 169], phase);
        assert_eq!(state[128 + 168], 6, "Remove");
        assert_eq!(members_present(), [true; 3]);
        assert!(plan_present(), "the removal stays bound to its plan");
        // Pair, then credential, then executable: each step exactly once.
        let present = match point {
            "pair-removed" => [true, true, false, false],
            "internal-removed" => [true, false, false, false],
            "binary-removed" | "committed-renamed" => [false; 4],
            _ => [true; 4],
        };
        assert_eq!(managed_present(), present);
        assert_workspace_kept();
        let mutation = match mutation.into_broker() {
            Ok(_) => panic!("uncertain removal returned its broker"),
            Err(mutation) => *mutation,
        };
        drop(mutation);
        drop(ProcessLock::acquire().unwrap());
        assert!(StateWriters::default().configuration().is_err());
        activate_same_boot_fenced(&state);
        let settled = activate_later_boot();
        assert!(settled[128..RECEIPT].iter().all(|byte| *byte == 0));
        assert_eq!(settled[RECEIPT + 169], 8, "Completed");
        assert_eq!(settled[RECEIPT + 174], 0, "a removal never resumes");
        if phase < 4 {
            assert_eq!(settled[RECEIPT + 172], 4, "Cancelled");
            assert_eq!(settled[RECEIPT + 173], 2, "runtime NotRequested");
            assert_eq!(managed_present(), [true; 4], "nothing was removed");
        } else {
            assert_eq!(settled[RECEIPT + 172], 1, "Changed");
            assert_eq!(settled[RECEIPT + 173], 5, "runtime Removed");
            assert_eq!(managed_present(), [false; 4], "the SAME plan completed");
        }
        assert_workspace_kept();
        return;
    }
    if let Some(point) = change_failure(case) {
        let new_internal = case.starts_with("settle-internal-fail:");
        assert_eq!(status, MutationStatus::RecoveryRequired);
        // Each came after the job stopped and before the recovery of the boot.
        if case.starts_with("settle-assets-foreign-fail:") {
            fs::create_dir(Path::new(HOME).join(SKILL)).unwrap();
        }
        if case.starts_with("settle-assets-edited-fail:") {
            fs::write(Path::new(HOME).join(SKILL), EDIT).unwrap();
        }
        if case.starts_with("settle-assets-parent-fail:") {
            let scripts = Path::new(HOME).join(BRIDGE);
            let scripts = scripts.parent().unwrap();
            fs::remove_dir(scripts).unwrap();
            fs::write(scripts, EDIT).unwrap();
        }
        for _ in 0..3 {
            assert_eq!(mutation.poll(), MutationStatus::RecoveryRequired);
        }
        let state = record();
        let phase = match point {
            "plan-durable" => 1,
            "closed-renamed" => 3,
            "committed-renamed" => 5,
            "activating-renamed" => 7,
            _ => 4,
        };
        assert_eq!(state[128 + 169], phase);
        assert_eq!(state[128 + 174], u8::from(live), "quiescence keeps resume");
        assert_eq!(members_present(), [true; 3]);
        assert!(plan_present(), "the change stays bound to its plan");
        let planned = internal_on_disk();
        match (new_internal, point) {
            (false, _) => assert_eq!(planned.as_deref(), Some(INTERNAL)),
            (true, "applying-renamed") => assert_eq!(planned, None),
            (true, _) => assert!(planned.as_deref().is_some_and(|value| {
                crate::update::picoclaw_token::valid_token(value) && value != INTERNAL
            })),
        }
        if phase >= 5 || point == "pair-published" {
            assert_pair_desired(pair, planned.as_deref().unwrap());
        } else {
            assert_pair_unchanged(pair);
        }
        let mutation = match mutation.into_broker() {
            Ok(_) => panic!("uncertain apply returned its broker"),
            Err(mutation) => *mutation,
        };
        drop(mutation);
        drop(ProcessLock::acquire().unwrap());
        assert!(StateWriters::default().configuration().is_err());
        activate_same_boot_fenced(&state);
        let settled = activate_later_boot();
        assert!(settled[128..RECEIPT].iter().all(|byte| *byte == 0));
        assert_eq!(settled[RECEIPT + 169], 8, "Completed");
        if case.starts_with("settle-assets-") {
            assert_pair_unchanged(pair);
            assert_eq!(
                fs::read(Path::new(HOME).join("workspace/AGENT.md")).unwrap(),
                AGENT
            );
            assert_assets_installed(case);
        }
        assert_eq!(settled[RECEIPT + 170], u8::from(live));
        let (outcome, runtime, resume) = match phase {
            // No target change began: cancelled, pair and credential kept.
            1 | 3 => (4, 2, 0),
            // The relaunched scope cannot have survived the boot.
            7 => (1, 4, 1),
            // The SAME plan completed; recovery never resumes a runtime.
            _ if live => (1, 6, 0),
            _ => (1, 2, 0),
        };
        assert_eq!(settled[RECEIPT + 172], outcome, "outcome");
        assert_eq!(settled[RECEIPT + 173], runtime, "runtime result");
        assert_eq!(settled[RECEIPT + 174], resume, "resume permission");
        if outcome == 4 {
            assert_pair_unchanged(pair);
            assert_eq!(internal_on_disk(), planned);
            return;
        }
        let internal = internal_on_disk().unwrap();
        if new_internal {
            assert!(crate::update::picoclaw_token::valid_token(&internal));
            assert_ne!(internal, INTERNAL);
        } else {
            assert_eq!(internal, INTERNAL);
        }
        if let Some(planned) = &planned {
            assert_eq!(&internal, planned, "never a second new credential");
        }
        if case.starts_with("settle-assets-") {
            assert_pair_unchanged(pair);
        } else {
            assert_pair_desired(pair, &internal);
        }
        return;
    }
    match case {
        "settle-noop-absent" | "settle-noop-live" | "settle-model-noop-absent" => {
            assert_pair_unchanged(pair);
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
            let mut broker = assert_released(mutation);
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
            assert_pair_unchanged(pair);
            if live {
                shutdown(broker);
            }
        }
        "settle-refused-absent" | "settle-refused-live" | "settle-model-refused-absent" => {
            // Refused before any plan or stop: terminal at once, like a no-op.
            let MutationStatus::SettlementRefused(id) = status else {
                panic!("{case}: {status:?}");
            };
            assert_eq!(id.sequence, 1);
            // A later explicit Stop cannot reopen or stop a terminal job.
            mutation.request_stop();
            for _ in 0..3 {
                assert_eq!(mutation.poll(), MutationStatus::SettlementRefused(id));
            }
            let state = record();
            assert!(state[128..RECEIPT].iter().all(|byte| *byte == 0));
            assert_eq!(state[RECEIPT + 169], 8, "Completed");
            assert_eq!(state[RECEIPT + 172], 3, "Failed");
            assert_eq!(state[RECEIPT + 173], 1, "runtime Unchanged");
            assert_eq!(state[RECEIPT + 170], u8::from(live));
            assert_eq!(state[RECEIPT + 174], u8::from(live), "resume kept");
            assert_eq!(members_present(), [false; 3]);
            assert!(!plan_present());
            assert_pair_unchanged(pair);
            let mut broker = assert_released(mutation);
            if live {
                // The live scope was never stopped and keeps its generation.
                assert_eq!(broker.group.poll()[3], Some(Status::Running));
                assert!(
                    broker.group.picoclaw_generation()
                        == Some(crate::update::picoclaw_config::Generation::fixture(
                            [0x31; 32]
                        ))
                );
                shutdown(broker);
            }
        }
        "settle-assets-changed-absent" => {
            let MutationStatus::Superseded(_) = status else {
                panic!("{case}: {status:?}");
            };
            let state = record();
            assert_eq!(state[RECEIPT + 172], 3, "Failed");
            assert_eq!(state[RECEIPT + 173], 2, "runtime NotRequested");
            assert_pair_unchanged(pair);
            assert_eq!(fs::read(Path::new(HOME).join(SKILL)).unwrap(), EDIT);
            assert!(
                !Path::new(HOME).join(BRIDGE).exists(),
                "nothing was applied"
            );
            assert!(!plan_present());
            drop(assert_released(mutation));
        }
        "settle-superseded-absent" => {
            let MutationStatus::Superseded(id) = status else {
                panic!("{case}: {status:?}");
            };
            let state = record();
            assert!(state[128..RECEIPT].iter().all(|byte| *byte == 0));
            assert_eq!(state[RECEIPT + 169], 8, "Completed");
            assert_eq!(state[RECEIPT + 172], 3, "Failed");
            assert_eq!(state[RECEIPT + 173], 2, "runtime NotRequested");
            assert_eq!(id.sequence, 1);
            assert_eq!(members_present(), [false; 3]);
            assert!(!plan_present());
            // The concurrent writer's bytes are kept; nothing was applied.
            assert!(
                fs::read(Path::new(HOME).join("config.json")).unwrap() == b"{\"superseded\":true}"
            );
            assert_eq!(internal_on_disk().as_deref(), Some(INTERNAL));
            drop(assert_released(mutation));
        }
        "settle-install-noop-absent" => {
            let MutationStatus::Completed(_) = status else {
                panic!("{case}: {status:?}");
            };
            let state = record();
            assert_eq!(state[RECEIPT + 168], 5, "Install");
            assert_eq!(state[RECEIPT + 172], 2, "Noop");
            assert_eq!(state[RECEIPT + 173], 1, "runtime Unchanged");
            assert!(installed_binary().as_deref() == Some(STAGED_BINARY));
            assert!(!plan_present());
            drop(assert_released(mutation));
        }
        "settle-install-refused-absent" => {
            // A staged file that is not the requested one refuses before any stop.
            let MutationStatus::SettlementRefused(_) = status else {
                panic!("{case}: {status:?}");
            };
            let state = record();
            assert_eq!(state[RECEIPT + 172], 3, "Failed");
            assert_eq!(state[RECEIPT + 173], 1, "runtime Unchanged");
            assert!(installed_binary().as_deref() == Some(OLD_BINARY));
            drop(assert_released(mutation));
        }
        "settle-install-absent"
        | "settle-install-unconfigured-absent"
        | "settle-install-replace-live"
        | "settle-install-legacy-live" => {
            let MutationStatus::Completed(id) = status else {
                panic!("{case}: {status:?}");
            };
            for _ in 0..3 {
                assert_eq!(mutation.poll(), MutationStatus::Completed(id));
            }
            let state = record();
            assert!(state[128..RECEIPT].iter().all(|byte| *byte == 0));
            assert_eq!(state[RECEIPT + 168], 5, "Install");
            assert_eq!(state[RECEIPT + 172], 1, "Changed");
            // No owner helper exists in this chroot, so a relaunch attempt
            // truthfully fails instead of claiming the old task resumed. A
            // pair without the local tool policy is not relaunched at all and
            // reports the same: the running runtime did not resume.
            assert_eq!(
                state[RECEIPT + 173],
                if live { 4 } else { 2 },
                "runtime result"
            );
            assert_eq!(state[RECEIPT + 174], u8::from(live));
            assert!(installed_binary().as_deref() == Some(STAGED_BINARY));
            assert_eq!(members_present(), [false; 3]);
            assert!(!plan_present());
            if case != "settle-install-unconfigured-absent" {
                assert_pair_unchanged(pair);
            }
            let broker = assert_released(mutation);
            if live {
                shutdown(broker);
            }
        }
        "settle-profile-noop-absent" => {
            let MutationStatus::Completed(_) = status else {
                panic!("{case}: {status:?}");
            };
            let state = record();
            assert_eq!(state[RECEIPT + 168], 4, "Profile");
            assert_eq!(state[RECEIPT + 172], 2, "Noop");
            assert_eq!(state[RECEIPT + 173], 1, "runtime Unchanged");
            assert!(fs::read(agent_path()).unwrap() == SHIPPED_KVM);
            assert!(!plan_present());
            assert_pair_unchanged(pair);
            drop(assert_released(mutation));
        }
        "settle-profile-custom-absent" => {
            // The user's own document is kept and nothing is stopped.
            let MutationStatus::SettlementRefused(_) = status else {
                panic!("{case}: {status:?}");
            };
            let state = record();
            assert_eq!(state[RECEIPT + 172], 3, "Failed");
            assert_eq!(state[RECEIPT + 173], 1, "runtime Unchanged");
            assert!(fs::read(agent_path()).unwrap() == CUSTOM_AGENT);
            assert_pair_unchanged(pair);
            drop(assert_released(mutation));
        }
        "settle-profile-change-absent"
        | "settle-profile-create-absent"
        | "settle-profile-change-live"
        | "settle-profile-legacy-live" => {
            let MutationStatus::Completed(id) = status else {
                panic!("{case}: {status:?}");
            };
            for _ in 0..3 {
                assert_eq!(mutation.poll(), MutationStatus::Completed(id));
            }
            let state = record();
            assert!(state[128..RECEIPT].iter().all(|byte| *byte == 0));
            assert_eq!(state[RECEIPT + 168], 4, "Profile");
            assert_eq!(state[RECEIPT + 172], 1, "Changed");
            // A pair without the local tool policy is never relaunched: the
            // runtime that was running reports that it did not resume.
            let relaunch = case == "settle-profile-change-live";
            assert_eq!(
                state[RECEIPT + 173],
                if relaunch {
                    3
                } else if live {
                    4
                } else {
                    2
                },
                "runtime result"
            );
            assert_eq!(state[RECEIPT + 174], u8::from(live));
            assert!(fs::read(agent_path()).unwrap() == SHIPPED_KVM);
            assert_eq!(members_present(), [false; 3]);
            assert!(!plan_present());
            // Only the workspace document changed; the pair kept its bytes and inodes.
            assert_pair_unchanged(pair);
            let mut broker = assert_released(mutation);
            if live && !relaunch {
                assert!(matches!(
                    broker.group.poll()[3],
                    None | Some(Status::Closed(_))
                ));
                shutdown(broker);
            } else if live {
                // Relaunched with the generation of the SAME unchanged pair.
                let security = pair.security.as_ref().unwrap().0.as_slice();
                assert_eq!(broker.group.poll()[3], Some(Status::Running));
                assert!(
                    broker.group.picoclaw_generation()
                        == Some(crate::update::picoclaw_config::Generation::from_pair(
                            &pair.config.0,
                            Some(security),
                        ))
                );
                shutdown(broker);
            }
        }
        "settle-remove-noop-absent" => {
            // Nothing managed is left: a no-op that changes and stops nothing.
            let MutationStatus::Completed(_) = status else {
                panic!("{case}: {status:?}");
            };
            let state = record();
            assert_eq!(state[RECEIPT + 168], 6, "Remove");
            assert_eq!(state[RECEIPT + 172], 2, "Noop");
            assert_eq!(state[RECEIPT + 173], 1, "runtime Unchanged");
            assert_eq!(managed_present(), [false; 4]);
            assert!(!plan_present());
            drop(assert_released(mutation));
        }
        "settle-remove-refused-absent" => {
            // A link in place of the executable refuses before any stop.
            let MutationStatus::SettlementRefused(_) = status else {
                panic!("{case}: {status:?}");
            };
            let state = record();
            assert_eq!(state[RECEIPT + 172], 3, "Failed");
            assert_eq!(state[RECEIPT + 173], 1, "runtime Unchanged");
            assert_eq!(managed_present(), [true; 4]);
            assert!(
                fs::symlink_metadata(BINARY)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_pair_unchanged(pair);
            assert_workspace_kept();
            drop(assert_released(mutation));
        }
        "settle-remove-absent" | "settle-remove-live" => {
            let MutationStatus::Completed(id) = status else {
                panic!("{case}: {status:?}");
            };
            for _ in 0..3 {
                assert_eq!(mutation.poll(), MutationStatus::Completed(id));
            }
            let state = record();
            assert!(state[128..RECEIPT].iter().all(|byte| *byte == 0));
            assert_eq!(state[RECEIPT + 168], 6, "Remove");
            assert_eq!(state[RECEIPT + 169], 8, "Completed");
            assert_eq!(state[RECEIPT + 172], 1, "Changed");
            assert_eq!(state[RECEIPT + 173], 5, "runtime Removed");
            assert_eq!(state[RECEIPT + 170], u8::from(live));
            assert_eq!(state[RECEIPT + 174], 0, "a removal never resumes");
            assert_eq!(managed_present(), [false; 4]);
            assert_eq!(members_present(), [false; 3]);
            assert!(!plan_present());
            // Home itself and its user data stay.
            assert!(Path::new(HOME).is_dir());
            assert_workspace_kept();
            let mut broker = assert_released(mutation);
            if live {
                // The quiesced scope stays closed: nothing is relaunched.
                assert!(matches!(
                    broker.group.poll()[3],
                    Some(Status::Closed(Completion::Stopped))
                ));
                shutdown(broker);
            }
        }
        "settle-assets-absent"
        | "settle-assets-default-absent"
        | "settle-assets-foreign-absent" => {
            let MutationStatus::Completed(id) = status else {
                panic!("{case}: {status:?}");
            };
            for _ in 0..3 {
                assert_eq!(mutation.poll(), MutationStatus::Completed(id));
            }
            assert_pair_unchanged(pair);
            let agent = if case == "settle-assets-default-absent" {
                crate::update::picoclaw_profile::SHIPPED_AGENT
            } else {
                AGENT
            };
            assert!(fs::read(Path::new(HOME).join("workspace/AGENT.md")).unwrap() == agent);
            assert_assets_installed(case);
            assert!(!plan_present());
            drop(assert_released(mutation));
        }
        _ => {
            // A change applies its once-chosen plan exactly and records the
            // runtime result it actually observed.
            let MutationStatus::Completed(id) = status else {
                panic!("{case}: {status:?}");
            };
            for _ in 0..3 {
                assert_eq!(mutation.poll(), MutationStatus::Completed(id));
            }
            let state = record();
            assert!(state[128..RECEIPT].iter().all(|byte| *byte == 0));
            assert_eq!(state[RECEIPT + 169], 8, "Completed");
            assert_eq!(state[RECEIPT + 172], 1, "Changed");
            assert_eq!(state[RECEIPT + 170], u8::from(live));
            let runtime = match case {
                _ if relaunched(case) => 3,
                "settle-change-stop-live" => 6,
                _ => 2,
            };
            assert_eq!(state[RECEIPT + 173], runtime, "runtime result");
            assert_eq!(state[RECEIPT + 174], u8::from(relaunched(case)));
            assert_eq!(state[RECEIPT + 168], if pair.model { 2 } else { 3 }, "kind");
            assert_eq!(members_present(), [false; 3]);
            assert!(!plan_present());
            let internal = internal_on_disk().unwrap();
            if case == "settle-internal-absent" {
                assert!(crate::update::picoclaw_token::valid_token(&internal));
                assert_ne!(internal, INTERNAL);
            } else {
                assert_eq!(internal, INTERNAL);
            }
            assert_pair_desired(pair, &internal);
            let mut broker = assert_released(mutation);
            if relaunched(case) {
                // The SAME broker relaunched one scope bound to the installed pair.
                let wanted = desired(pair, &internal);
                assert_eq!(broker.group.poll()[3], Some(Status::Running));
                assert!(
                    broker.group.picoclaw_generation()
                        == Some(crate::update::picoclaw_config::Generation::from_pair(
                            &wanted.config,
                            Some(wanted.security.as_bytes()),
                        ))
                );
            } else if live {
                assert!(matches!(
                    broker.group.poll()[3],
                    Some(Status::Closed(Completion::Stopped))
                ));
            }
            if live {
                shutdown(broker);
            }
        }
    }
}
