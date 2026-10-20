//! Actual fixed-root recovery composition with synthetic support/empty-native
//! fixtures. This is not hardware boot, real process quiescence or trial health.
use super::tests::{fixture, terminal_fixture};
use super::*;
use crate::update::app_slot::{Status, boot_gate, job_status, recover, status};
use std::{
    fs,
    io::{self, BufRead, BufReader},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::mpsc,
    time::Duration,
};

const NATIVE: &str = "/etc/kvm/native-runtime-owner/state";
const APP: &str = "/etc/kvm/application-slot/current/state";
const INTENT: &str = "/etc/kvm/application-slot/recovery";
const EXPECTED: &str = "/support-expected-plan";

fn write_plan(root: &Path, name: &str, plan: &Plan) {
    let path = root.join("etc/kvm/application-support").join(name);
    fs::write(&path, plan.encode(0, 0).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn prepare(root: &Path, case: &str) {
    assert!(nix::unistd::geteuid().is_root());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let mut install = runtime.block_on(fixture(root));
    let closed = ClosedRuntime::fixture(install.transaction());
    let sources = Sources::open(&install, &closed).unwrap();
    let mut prepared = stage(&mut install, closed, sources).unwrap();
    let expected = prepared.plan.clone();
    match case {
        "prepared" | "pending-ready" | "staging-zero" | "staging-some" | "foreign-next" => {}
        "mixed-committed"
        | "cleanup-new"
        | "pending-cleanup-new"
        | "empty-committed"
        | "foreign-next-committed" => {
            terminal_fixture(&mut prepared, true);
        }
        "cleanup-old" | "pending-cleanup-old" | "empty-rolled-back" => {
            terminal_fixture(&mut prepared, false);
        }
        "published" | "mixed-published" | "unknown-late" | "native-busy" | "native-stopping"
        | "writer-busy" | "update-busy" => {
            prepared.exchange().unwrap();
            prepared.install.publish(&prepared.closed).unwrap();
        }
        _ => panic!("unknown private fixed-root support case"),
    }
    if matches!(case, "mixed-published" | "mixed-committed") {
        for index in [0, 2, 4, 6, 8] {
            renameat_with(
                prepared.directories.live(index),
                live_name(index),
                &prepared.directories.support,
                NAMES[index],
                RenameFlags::EXCHANGE,
            )
            .unwrap();
        }
    }
    if matches!(case, "staging-zero" | "staging-some" | "pending-ready") {
        let mut staging = expected.clone();
        staging.phase = SupportPhase::Staging;
        write_plan(root, PLAN, &staging);
        if case == "pending-ready" {
            write_plan(root, NEXT, &expected);
        } else {
            for name in &NAMES[if case == "staging-zero" { 0 } else { 3 }..] {
                fs::remove_file(root.join("etc/kvm/application-support").join(name)).unwrap();
            }
        }
    }
    if case.starts_with("cleanup-") || case.starts_with("pending-cleanup-") {
        let mut cleanup = expected.clone();
        cleanup.phase = if case.ends_with("new") {
            SupportPhase::CleanupNew
        } else {
            SupportPhase::CleanupOld
        };
        if case.starts_with("pending-") {
            write_plan(root, NEXT, &cleanup);
        } else {
            write_plan(root, PLAN, &cleanup);
            for name in &NAMES[4..] {
                fs::remove_file(root.join("etc/kvm/application-support").join(name)).unwrap();
            }
        }
    }
    if case == "unknown-late" {
        fs::write(
            root.join("etc/kvm/application-support").join(NAMES[8]),
            b"unknown late support member",
        )
        .unwrap();
    }
    if case.starts_with("foreign-next") {
        let mut next = expected.clone();
        next.phase = SupportPhase::CleanupOld;
        next.app.version = "666.0.0".into();
        write_plan(root, NEXT, &next);
    }
    if case.starts_with("empty-") {
        settlement::run(&prepared.install._store).unwrap();
    }
    fs::write(
        root.join(EXPECTED.trim_start_matches('/')),
        expected.encode(0, 0).unwrap(),
    )
    .unwrap();
    drop(prepared);
    drop(install);
    fs::rename(
        root.join("application-slot"),
        root.join("etc/kvm/application-slot"),
    )
    .unwrap();
}

fn mount_root(root: &Path) {
    fs::create_dir_all(root.join("proc")).unwrap();
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
}

fn snapshot() -> Vec<(PathBuf, u64, Vec<u8>)> {
    let mut entries = Vec::with_capacity(COUNT + 2);
    for entry in fs::read_dir("/etc/kvm/application-support").unwrap() {
        let path = entry.unwrap().path();
        entries.push((
            path.clone(),
            path.metadata().unwrap().ino(),
            fs::read(path).unwrap(),
        ));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

fn expect_complete(case: &str) {
    let plan = Plan::decode(&fs::read(EXPECTED).unwrap(), 0, 0).unwrap();
    let new = case.contains("committed") || case.ends_with("new");
    for (index, entry) in plan.entries.iter().enumerate() {
        let expected = if new { entry.new } else { entry.old };
        let path = Path::new(if index < 5 {
            "/usr/libexec"
        } else {
            "/etc/init.d"
        })
        .join(live_name(index));
        let actual = path.metadata().unwrap();
        assert_eq!(
            (actual.dev(), actual.ino()),
            (expected.identity.device, expected.identity.inode)
        );
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(fs::read(path).unwrap())),
            expected.sha256
        );
    }
    assert_eq!(status().unwrap(), Status::NoTransaction);
    assert_eq!(boot_gate().unwrap(), Status::NoTransaction);
    assert!(!Path::new(INTENT).exists());
    assert!(snapshot().is_empty());
    let job = job_status(plan.app.transaction).unwrap().unwrap();
    assert!(job.archived);
    assert_eq!(
        job.phase,
        if new {
            AppPhase::Committed
        } else {
            AppPhase::RolledBack
        }
    );
    let native = fs::read(NATIVE).unwrap();
    assert_eq!(native[44], 2);
    assert_eq!(
        &native[8..44],
        &fs::read("/proc/sys/kernel/random/boot_id").unwrap()[..36]
    );
    drop(crate::update::operation_lock::ProcessLock::acquire().unwrap());
    drop(
        crate::update::state_writers::StateWriters::default()
            .try_drain()
            .unwrap(),
    );
}

fn prior_epoch_after_proven_same_boot_refusal() {
    let before = fs::read(NATIVE).unwrap();
    if before[44] == 4 {
        let app = fs::read(APP).ok();
        let intent = fs::read(INTENT).unwrap();
        let support = snapshot();
        assert!(matches!(recover(), Err(SlotError::Busy)));
        assert_eq!(fs::read(NATIVE).unwrap(), before);
        assert_eq!(fs::read(APP).ok(), app);
        assert_eq!(fs::read(INTENT).unwrap(), intent);
        assert_eq!(snapshot(), support);
        // Synthetic prior-epoch record, NOT a physical reboot or process-drain
        // proof. The production reader still uses the real procfs boot ID.
        let mut prior = before;
        let other = if &prior[8..44] == b"12345678-1234-1234-1234-123456789abc" {
            b"87654321-4321-4321-4321-cba987654321"
        } else {
            b"12345678-1234-1234-1234-123456789abc"
        };
        prior[8..44].copy_from_slice(other);
        let hash = Sha256::digest(&prior[..48]);
        prior[48..].copy_from_slice(&hash);
        fs::write(NATIVE, prior).unwrap();
        File::open(NATIVE).unwrap().sync_all().unwrap();
    } else {
        assert_eq!(before[44], 2);
    }
}

#[test]
fn recovery_child() {
    let Some(root) = std::env::var_os("NANOKVM_SUPPORT_RECOVERY_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let case = std::env::var("NANOKVM_SUPPORT_RECOVERY_CASE").unwrap();
    let mode = std::env::var("NANOKVM_SUPPORT_RECOVERY_MODE").unwrap_or_else(|_| "initial".into());
    if mode != "resume" {
        prepare(&root, &case);
    }
    mount_root(&root);
    if mode == "resume" {
        prior_epoch_after_proven_same_boot_refusal();
        let expected = if case.contains("committed") || case.ends_with("new") {
            AppPhase::Committed
        } else {
            AppPhase::RolledBack
        };
        assert_eq!(recover().unwrap(), Status::Transaction(expected));
        expect_complete(&case);
        println!("support-fixed-root-completed");
        return;
    }
    crate::native_owner::broker::app_recovery_closed_fixture(&File::open("/etc/kvm").unwrap());
    drop(crate::update::operation_lock::ProcessLock::acquire().unwrap());
    let _update = (case == "update-busy")
        .then(|| crate::update::operation_lock::ProcessLock::acquire().unwrap());
    let _native = (case == "native-busy")
        .then(|| crate::native_owner::broker::ReadyAppRecovery::acquire().unwrap());
    let _writers = (case == "writer-busy").then(|| {
        crate::update::state_writers::StateWriters::default()
            .try_drain()
            .unwrap()
    });
    if case == "native-stopping" {
        let mut bytes = fs::read(NATIVE).unwrap();
        bytes[44] = 4;
        let digest = Sha256::digest(&bytes[..48]);
        bytes[48..].copy_from_slice(&digest);
        fs::write(NATIVE, bytes).unwrap();
    }
    let before = snapshot();
    let app = fs::read(APP).unwrap();
    fs::write("/support-recovery-active", b"private fixed-root fixture").unwrap();
    let result = recover();
    if mode == "fault" {
        let expected = std::env::var("NANOKVM_SUPPORT_RECOVERY_FAULT").unwrap();
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string("/support-recovery-fault-reached").unwrap(),
            expected
        );
        println!("support-fixed-root-fault-reached");
        return;
    }
    assert_ne!(
        mode, "stop",
        "requested recovery checkpoint was not reached"
    );
    if case == "unknown-late"
        || case.starts_with("foreign-next")
        || case.ends_with("busy")
        || case == "native-stopping"
    {
        if case.ends_with("busy") || case == "native-stopping" {
            assert!(matches!(result, Err(SlotError::Busy)), "{case}: {result:?}");
            assert!(!Path::new(INTENT).exists());
        } else {
            assert!(
                matches!(result, Err(SlotError::Invalid | SlotError::Unsafe)),
                "{case}: {result:?}"
            );
            assert_eq!(fs::read(NATIVE).unwrap()[44], 4);
            assert!(Path::new(INTENT).is_file());
            assert!(matches!(recover(), Err(SlotError::Busy)));
        }
        assert_eq!(snapshot(), before);
        assert_eq!(fs::read(APP).unwrap(), app);
        assert!(!Path::new("/etc/kvm/application-slot/history").exists());
    } else {
        let expected = if case.contains("committed") || case.ends_with("new") {
            AppPhase::Committed
        } else {
            AppPhase::RolledBack
        };
        assert_eq!(result.unwrap(), Status::Transaction(expected));
        expect_complete(&case);
    }
    println!("support-fixed-root-completed");
}

fn command(root: &Path, case: &str) -> Command {
    let mut command = Command::new("/usr/bin/unshare");
    command
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::app_slot::support::recovery_tests::recovery_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_SUPPORT_RECOVERY_ROOT", root)
        .env("NANOKVM_SUPPORT_RECOVERY_CASE", case);
    command
}

fn passed(output: Output, case: &str) {
    assert!(output.status.success(), "{case}: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("support-fixed-root-completed") && stdout.contains("1 passed; 0 failed"),
        "{case}: {stdout}"
    );
}

#[test]
fn fixed_root_recovery_composes_all_support_phases_and_refuses_unknown_or_unclosed_state() {
    for case in [
        "prepared",
        "published",
        "mixed-published",
        "mixed-committed",
        "staging-zero",
        "staging-some",
        "pending-ready",
        "cleanup-old",
        "cleanup-new",
        "pending-cleanup-old",
        "pending-cleanup-new",
        "empty-committed",
        "empty-rolled-back",
        "unknown-late",
        "foreign-next",
        "foreign-next-committed",
        "native-busy",
        "native-stopping",
        "writer-busy",
        "update-busy",
    ] {
        let root = tempfile::tempdir().unwrap();
        passed(command(root.path(), case).output().unwrap(), case);
    }
}

fn stopped(root: &Path, case: &str, point: &str, framework: bool) {
    let mut child = command(root, case)
        .env("NANOKVM_SUPPORT_RECOVERY_MODE", "stop")
        .env(
            if framework {
                "NANOKVM_APP_SLOT_TEST_STOP"
            } else {
                "NANOKVM_SUPPORT_RECOVERY_STOP"
            },
            point,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let (send, receive) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut sent = false;
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if !sent
                && (line.contains("support-checkpoint-ready")
                    || line.contains("slot-checkpoint-ready"))
            {
                send.send(()).unwrap();
                sent = true;
            }
        }
    });
    let errors = std::thread::spawn(move || {
        let mut kept = Vec::with_capacity(65536);
        let mut buffer = [0; 2048];
        loop {
            let n = io::Read::read(&mut stderr, &mut buffer).unwrap();
            if n == 0 {
                break;
            }
            let save = n.min(65536 - kept.len());
            kept.extend_from_slice(&buffer[..save]);
        }
        kept
    });
    let reached = receive.recv_timeout(Duration::from_secs(90)).is_ok();
    let _ = child.kill();
    let status = child.wait().unwrap();
    reader.join().unwrap();
    let errors = errors.join().unwrap();
    assert!(
        reached,
        "{case}/{point}: {status}, stderr={}",
        String::from_utf8_lossy(&errors)
    );
    assert_eq!(status.signal(), Some(9));
}

fn resumed(root: &Path, case: &str) {
    passed(
        command(root, case)
            .env("NANOKVM_SUPPORT_RECOVERY_MODE", "resume")
            .output()
            .unwrap(),
        case,
    );
}

#[test]
fn every_composed_exchange_cleanup_and_archival_crash_preserves_fence_until_exact_recovery() {
    for case in ["published", "mixed-published", "mixed-committed"] {
        for point in [
            "recovery-intent-durable",
            "recovery-native-fenced",
            "recovery-support-reconciled",
            "recovery-slot-terminal",
            "recovery-support-settled",
            "retire-history-ready",
            "retire-terminal-synced",
            "retire-current-renamed",
            "retire-history-synced",
            "retire-parent-synced",
            "recovery-app-archived",
            "recovery-native-closed",
        ] {
            let root = tempfile::tempdir().unwrap();
            stopped(root.path(), case, point, true);
            if point == "recovery-support-reconciled" {
                let record = Record::decode(
                    &fs::read(root.path().join(APP.trim_start_matches('/'))).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    record.phase,
                    if case == "mixed-committed" {
                        AppPhase::Committed
                    } else {
                        AppPhase::Published
                    }
                );
                let plan = Plan::decode(
                    &fs::read(root.path().join(EXPECTED.trim_start_matches('/'))).unwrap(),
                    0,
                    0,
                )
                .unwrap();
                for (index, entry) in plan.entries.iter().enumerate() {
                    let expected = if case == "mixed-committed" {
                        entry.new
                    } else {
                        entry.old
                    };
                    let path = root
                        .path()
                        .join(if index < 5 {
                            "usr/libexec"
                        } else {
                            "etc/init.d"
                        })
                        .join(live_name(index));
                    assert_eq!(path.metadata().unwrap().ino(), expected.identity.inode);
                }
            }
            resumed(root.path(), case);
        }
        println!("support recovery archival prefixes complete: {case}");
    }
}

#[test]
fn every_composed_support_io_and_process_loss_prefix_recovers_only_the_canonical_family() {
    for case in ["published", "mixed-published", "mixed-committed"] {
        let new = case == "mixed-committed";
        let mut points = Vec::with_capacity(52);
        for index in 0..COUNT {
            for step in ["renamed", "live-synced", "stage-synced"] {
                let needs_rename = match case {
                    "published" => true,
                    "mixed-published" => index % 2 == 1,
                    _ => index % 2 == 0,
                };
                if step != "renamed" || needs_rename {
                    points.push(format!(
                        "{}-{step}-{index}",
                        if new { "new" } else { "old" }
                    ));
                }
            }
        }
        for step in [
            "file-synced",
            "linked",
            "link-synced",
            "renamed",
            "rename-synced",
        ] {
            points.push(format!(
                "cleanup-{}-plan-{step}",
                if new { "new" } else { "old" }
            ));
        }
        for index in 0..COUNT {
            for step in ["unlinked", "synced"] {
                points.push(format!("cleanup-member-{step}-{index}"));
            }
        }
        points.push("cleanup-plan-unlinked".into());
        points.push("cleanup-empty-synced".into());
        assert_eq!(
            points.len(),
            match case {
                "published" => 52,
                "mixed-published" => 47,
                _ => 48,
            }
        );
        for fault in [false, true] {
            for (index, point) in points.iter().enumerate() {
                let root = tempfile::tempdir().unwrap();
                if fault {
                    let output = command(root.path(), case)
                        .env("NANOKVM_SUPPORT_RECOVERY_MODE", "fault")
                        .env("NANOKVM_SUPPORT_RECOVERY_FAULT", point)
                        .output()
                        .unwrap();
                    assert!(output.status.success(), "{case}/{point}: {output:?}");
                    assert!(
                        String::from_utf8_lossy(&output.stdout)
                            .contains("support-fixed-root-fault-reached")
                    );
                } else {
                    stopped(root.path(), case, point, false);
                }
                resumed(root.path(), case);
                if (index + 1) % 16 == 0 || index + 1 == points.len() {
                    println!(
                        "support recovery prefixes: {case} fault={fault} {}/{}",
                        index + 1,
                        points.len()
                    );
                }
            }
        }
    }
    for case in [
        "pending-ready",
        "pending-cleanup-old",
        "pending-cleanup-new",
    ] {
        for point in ["settlement-next-renamed", "settlement-next-synced"] {
            for fault in [false, true] {
                let root = tempfile::tempdir().unwrap();
                if fault {
                    let output = command(root.path(), case)
                        .env("NANOKVM_SUPPORT_RECOVERY_MODE", "fault")
                        .env("NANOKVM_SUPPORT_RECOVERY_FAULT", point)
                        .output()
                        .unwrap();
                    assert!(output.status.success(), "{case}/{point}: {output:?}");
                    assert!(
                        String::from_utf8_lossy(&output.stdout)
                            .contains("support-fixed-root-fault-reached")
                    );
                } else {
                    stopped(root.path(), case, point, false);
                }
                resumed(root.path(), case);
            }
        }
    }
}
