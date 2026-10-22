use super::*;

#[test]
fn read_fence_releases_its_description_before_a_following_exclusive_producer() {
    let root = tempfile::tempdir().unwrap();
    let lease = ReadLease::acquire(File::open(root.path()).unwrap()).unwrap();
    let alias = lease.directory.try_clone().unwrap();
    let producer = File::open(root.path()).unwrap();
    assert!(flock(&producer, FlockOperation::NonBlockingLockExclusive).is_err());
    drop(lease);
    assert!(alias.metadata().unwrap().is_dir());
    flock(&producer, FlockOperation::NonBlockingLockExclusive).unwrap();
}
use crate::update::{operation_lock::ProcessLock, state_writers::StateWriters};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub(super) fn record(sequence: u64, phase: Phase) -> Record {
    Record {
        sequence,
        nonce: [1; 16],
        boot: [2; 16],
        home: [3; 32],
        support: [4; 32],
        request: [5; 32],
        source: [6; 32],
        kind: Kind::Model,
        phase,
        was_running: true,
        resume_allowed: true,
        uncertain: false,
        outcome: if phase == Phase::Completed {
            Outcome::Changed
        } else {
            Outcome::Pending
        },
        runtime: if phase == Phase::Completed {
            Runtime::Resumed
        } else {
            Runtime::Pending
        },
    }
}

fn snapshot(sequence: u64, active: bool) -> Snapshot {
    let end = sequence - u64::from(active);
    let mut receipts = [None; RETAINED];
    for offset in 0..end.min(RETAINED as u64) {
        let seq = end - offset;
        receipts[((seq - 1) % RETAINED as u64) as usize] = Some(record(seq, Phase::Completed));
    }
    Snapshot {
        epoch: [7; 16],
        sequence,
        active: active.then(|| record(sequence, Phase::Accepted)),
        receipts,
    }
}

fn hash_again(bytes: &mut [u8]) {
    let hash = digest(&bytes[..PREFIX]);
    bytes[PREFIX..].copy_from_slice(&hash);
}

fn save(root: &Path, state: &Snapshot) -> std::path::PathBuf {
    // Explicit synthetic enrollment, not a production initializer.
    let mut anchor = [0; 96];
    anchor[..8].copy_from_slice(b"NKPENR01");
    anchor[8] = 3;
    anchor[16..32].copy_from_slice(&state.epoch);
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM Pico enrollment v1\0");
    hash.update(&anchor[..64]);
    anchor[64..].copy_from_slice(&hash.finalize());
    let enrollment = root.join("picoclaw-enrollment");
    fs::write(&enrollment, anchor).unwrap();
    fs::set_permissions(enrollment, fs::Permissions::from_mode(0o600)).unwrap();
    let directory = root.join(DIRECTORY);
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join(STATE);
    fs::write(&path, state.encode().unwrap().as_slice()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

#[test]
fn canonical_empty_active_and_retained_ring_snapshots_roundtrip_without_debug_payloads() {
    for (sequence, active) in [
        (0, false),
        (1, true),
        (1, false),
        (31, true),
        (32, false),
        (33, true),
        (67, false),
        (u64::MAX, true),
        (u64::MAX, false),
    ] {
        let state = snapshot(sequence, active);
        let bytes = state.encode().unwrap();
        let decoded = Snapshot::decode(bytes.as_slice()).unwrap();
        assert!(
            decoded.epoch == state.epoch
                && decoded.sequence == sequence
                && decoded.active == state.active
                && decoded.receipts == state.receipts
        );
        assert_eq!(decoded.encode().unwrap().as_slice(), bytes.as_slice());
    }
}

#[test]
fn every_fixed_kind_phase_and_uncertain_active_record_remains_nonterminal() {
    for kind in [
        Kind::Onboard,
        Kind::Model,
        Kind::Startup,
        Kind::Profile,
        Kind::Install,
        Kind::Remove,
    ] {
        for phase in [
            Phase::Accepted,
            Phase::Stopping,
            Phase::Closed,
            Phase::Applying,
            Phase::Committed,
            Phase::Retiring,
            Phase::Activating,
        ] {
            for uncertain in [false, true] {
                let mut state = snapshot(9, true);
                let active = state.active.as_mut().unwrap();
                active.kind = kind;
                active.resume_allowed = kind != Kind::Remove;
                active.phase = phase;
                active.uncertain = uncertain;
                assert!(
                    Snapshot::decode(state.encode().unwrap().as_slice())
                        .unwrap()
                        .active
                        .is_some()
                );
            }
        }
    }
}

#[test]
fn terminal_outcome_and_runtime_semantics_are_checked_independently() {
    for kind in [
        Kind::Onboard,
        Kind::Model,
        Kind::Startup,
        Kind::Profile,
        Kind::Install,
        Kind::Remove,
    ] {
        for was_running in [false, true] {
            for resume_allowed in [false, true] {
                for outcome in [
                    Outcome::Pending,
                    Outcome::Changed,
                    Outcome::Noop,
                    Outcome::Failed,
                    Outcome::Cancelled,
                ] {
                    for runtime in [
                        Runtime::Pending,
                        Runtime::Unchanged,
                        Runtime::NotRequested,
                        Runtime::Resumed,
                        Runtime::ResumeFailed,
                        Runtime::Removed,
                        Runtime::Suppressed,
                    ] {
                        let mut value = record(1, Phase::Completed);
                        value.kind = kind;
                        value.was_running = was_running;
                        value.resume_allowed = resume_allowed;
                        value.outcome = outcome;
                        value.runtime = runtime;
                        let expected = !(resume_allowed && (!was_running || kind == Kind::Remove))
                            && match outcome {
                                Outcome::Pending => false,
                                Outcome::Noop if was_running && !resume_allowed => {
                                    runtime == Runtime::Suppressed
                                }
                                Outcome::Noop => runtime == Runtime::Unchanged,
                                Outcome::Failed | Outcome::Cancelled => {
                                    runtime == Runtime::NotRequested
                                }
                                Outcome::Changed if kind == Kind::Remove => {
                                    runtime == Runtime::Removed
                                }
                                Outcome::Changed if resume_allowed => {
                                    matches!(runtime, Runtime::Resumed | Runtime::ResumeFailed)
                                }
                                Outcome::Changed if was_running => runtime == Runtime::Suppressed,
                                Outcome::Changed => runtime == Runtime::NotRequested,
                            };
                        assert_eq!(value.encode().is_ok(), expected);
                        if let Ok(bytes) = value.encode() {
                            assert!(Record::decode(&bytes).unwrap() == value);
                        }
                        value.uncertain = true;
                        assert!(value.encode().is_err());
                    }
                }
            }
        }
    }
}

#[test]
fn rehashed_unknown_fields_bad_domains_holes_and_misplaced_receipts_refuse() {
    let good = snapshot(67, true).encode().unwrap();
    for (offset, value) in [
        (0, 0),
        (8, 0),
        (32, 1),
        (HEADER + 168, 0),
        (HEADER + 169, 0),
        (HEADER + 170, 2),
        (HEADER + 171, 2),
        (HEADER + 172, 1),
        (HEADER + 173, 1),
        (HEADER + 174, 2),
        (HEADER + 175, 1),
    ] {
        let mut bad = good.to_vec();
        bad[offset] = value;
        hash_again(&mut bad);
        if offset == 8 {
            bad[8..24].fill(0);
            hash_again(&mut bad);
        }
        assert!(Snapshot::decode(&bad).is_err(), "offset {offset}");
    }
    for size in [0, 8, BYTES - 1, BYTES + 1] {
        let mut bad = good.to_vec();
        bad.resize(size, 0);
        assert!(Snapshot::decode(&bad).is_err());
    }
    for change in 0..4 {
        let mut bad = snapshot(67, true);
        match change {
            0 => bad.receipts[0] = None,
            1 => bad.receipts.swap(0, 1),
            2 => bad.active.as_mut().unwrap().sequence -= 1,
            _ => bad.receipts[0] = Some(record(1, Phase::Completed)),
        }
        assert!(bad.encode().is_err());
    }
    let mut bad = good.to_vec();
    bad[PREFIX] ^= 1;
    assert!(Snapshot::decode(&bad).is_err());
}

#[tokio::test]
async fn existing_pending_or_uncertain_state_fences_config_and_both_drains_after_locks_drop() {
    for phase in [
        Phase::Accepted,
        Phase::Stopping,
        Phase::Closed,
        Phase::Applying,
        Phase::Committed,
        Phase::Retiring,
        Phase::Activating,
    ] {
        let root = tempfile::tempdir().unwrap();
        let parent = File::open(root.path()).unwrap();
        let writers = StateWriters::for_test_parent(parent.try_clone().unwrap());
        let update = ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap();
        let configuration = writers.configuration().unwrap();
        let mut state = snapshot(1, true);
        state.active.as_mut().unwrap().phase = phase;
        save(root.path(), &state);
        drop(configuration);
        drop(update);
        // No live owner/lock is manufactured by these records. A new Update
        // lease is possible, but enrolled mutation/capture must still refuse.
        drop(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap());
        assert!(writers.configuration().is_err());
        assert!(writers.try_drain().is_err());
        assert!(writers.drain(Duration::from_secs(1)).await.is_err());
        // Failed fences release their temporary guards; unrelated account work
        // remains possible and no query rewrites this private journal.
        drop(writers.account().unwrap());
        assert_eq!(
            fs::read(root.path().join(DIRECTORY).join(STATE)).unwrap(),
            state.encode().unwrap().as_slice()
        );
    }
}

#[tokio::test]
async fn terminal_snapshot_and_legacy_absence_allow_admission_without_creating_or_rewriting_state()
{
    let root = tempfile::tempdir().unwrap();
    let parent = File::open(root.path()).unwrap();
    let writers = StateWriters::for_test_parent(parent);
    drop(writers.configuration().unwrap());
    assert!(!root.path().join(DIRECTORY).exists());
    let path = save(root.path(), &snapshot(39, false));
    let before = Revision::from(&fs::metadata(&path).unwrap());
    let bytes = fs::read(&path).unwrap();
    for _ in 0..3 {
        drop(writers.configuration().unwrap());
        drop(writers.try_drain().unwrap());
        drop(writers.drain(Duration::from_secs(1)).await.unwrap());
    }
    assert!(Revision::from(&fs::metadata(&path).unwrap()) == before);
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn unsafe_state_links_types_modes_sizes_and_pending_evidence_are_preserved_and_refused() {
    for case in [
        "link",
        "hardlink",
        "fifo",
        "directory",
        "mode",
        "size",
        "corrupt",
        "missing",
        "next",
        "payload",
        "active",
        "unknown",
        "lease",
    ] {
        let root = tempfile::tempdir().unwrap();
        let path = save(root.path(), &snapshot(u64::from(case == "active"), false));
        let directory = File::open(path.parent().unwrap()).unwrap();
        match case {
            "link" => {
                fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink("../sentinel", &path).unwrap();
            }
            "hardlink" => fs::hard_link(&path, root.path().join("sentinel")).unwrap(),
            "fifo" => {
                fs::remove_file(&path).unwrap();
                rustix::fs::mknodat(
                    &directory,
                    STATE,
                    rustix::fs::FileType::Fifo,
                    rustix::fs::Mode::from_raw_mode(0o600),
                    0,
                )
                .unwrap();
            }
            "directory" => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "size" => File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len((BYTES + 1) as u64)
                .unwrap(),
            "corrupt" => fs::write(&path, [0; BYTES]).unwrap(),
            "missing" => fs::remove_file(&path).unwrap(),
            "lease" => flock(&directory, FlockOperation::NonBlockingLockExclusive).unwrap(),
            other => fs::write(
                path.parent().unwrap().join(if other == "next" {
                    ".state.next"
                } else {
                    other
                }),
                b"preserved evidence",
            )
            .unwrap(),
        }
        let before = fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert!(
            check_fixture(&File::open(root.path()).unwrap()).is_err(),
            "{case}"
        );
        assert_eq!(
            fs::read_dir(path.parent().unwrap()).unwrap().count(),
            before
        );
    }
}

pub(super) struct OwnedChild(pub(super) Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn actual_sigkill_releases_process_leases_but_never_the_persisted_job_fence() {
    use std::os::unix::process::ExitStatusExt;
    for point in ["state", "next"] {
        let root = tempfile::tempdir().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::picoclaw_config::jobs::tests::writer_child",
                "--nocapture",
            ])
            .env_clear()
            .env("NANOKVM_PICO_JOB_FIXTURE", root.path())
            .env("NANOKVM_PICO_JOB_POINT", point)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut child = OwnedChild(Some(child));
        let start = Instant::now();
        while !root.path().join("child-ready").is_file() {
            assert!(
                child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                "writer died before fixture checkpoint"
            );
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "writer checkpoint watchdog"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let parent = File::open(root.path()).unwrap();
        assert!(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).is_err());
        child.0.as_mut().unwrap().kill().unwrap();
        assert_eq!(child.0.as_mut().unwrap().wait().unwrap().signal(), Some(9));
        child.0 = None;
        drop(ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap());
        let writers = StateWriters::for_test_parent(parent);
        assert!(writers.configuration().is_err());
        assert!(writers.try_drain().is_err());
        assert!(
            root.path()
                .join(DIRECTORY)
                .join(if point == "state" {
                    STATE
                } else {
                    ".state.next"
                })
                .is_file()
        );
    }
}

#[test]
fn writer_child() {
    let Some(root) = std::env::var_os("NANOKVM_PICO_JOB_FIXTURE") else {
        return;
    };
    let root = Path::new(&root);
    let parent = File::open(root).unwrap();
    let _update = ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap();
    let writers = StateWriters::for_test_parent(parent);
    let _configuration = writers.configuration().unwrap();
    let path = save(root, &snapshot(1, true));
    File::open(&path).unwrap().sync_all().unwrap();
    if std::env::var("NANOKVM_PICO_JOB_POINT").as_deref() == Ok("next") {
        fs::rename(&path, path.parent().unwrap().join(".state.next")).unwrap();
    }
    File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
    let mut ready = File::create(root.join("child-ready")).unwrap();
    ready.write_all(b"fixture only").unwrap();
    ready.sync_all().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn fixed_production_root_refuses_pending_and_cross_mount_state_without_initialization() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("etc/kvm")).unwrap();
    fs::set_permissions(
        root.path().join("etc/kvm"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let child = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "update::picoclaw_config::jobs::tests::private_root_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("NANOKVM_PICO_JOB_ROOT", root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = OwnedChild(Some(child));
    let start = Instant::now();
    loop {
        if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "private-root journal fixture watchdog"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("fixed-pico-job-root-checked")
    );
}

#[test]
fn private_root_child() {
    let Some(root) = std::env::var_os("NANOKVM_PICO_JOB_ROOT") else {
        return;
    };
    nix::unistd::chroot(Path::new(&root)).unwrap();
    std::env::set_current_dir("/").unwrap();
    let parent = Path::new("/etc/kvm");
    check_writer_admission().unwrap();
    assert!(!parent.join(DIRECTORY).exists());
    let writers = StateWriters::default();
    drop(writers.configuration().unwrap());
    let state = snapshot(1, true);
    let path = save(parent, &state);
    assert!(check_writer_admission().is_err());
    assert!(writers.configuration().is_err());
    assert!(writers.try_drain().is_err());
    assert_eq!(fs::read(&path).unwrap(), state.encode().unwrap().as_slice());
    // Test-only explicit settlement fixture, not an implemented recovery path.
    save(parent, &snapshot(1, false));
    drop(writers.configuration().unwrap());
    let mounted = parent.join(DIRECTORY);
    nix::mount::mount(
        Some("tmpfs"),
        &mounted,
        Some("tmpfs"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
        Some("mode=0700,size=1m"),
    )
    .unwrap();
    fs::write(mounted.join("sentinel"), b"private mount, never adopted").unwrap();
    assert!(check_writer_admission().is_err());
    assert!(writers.configuration().is_err());
    assert_eq!(
        fs::read(mounted.join("sentinel")).unwrap(),
        b"private mount, never adopted"
    );
    println!("fixed-pico-job-root-checked");
}
