use super::*;
use crate::{
    api::application::{AppCandidate, manual_candidate_fixture},
    update::{
        operation::{Kind, UpdateCoordinator, UpdateOwner},
        operation_lock::{Domain, LockError},
        state_writers::StateWriters,
    },
};
use sha2::Sha512;
use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

pub(crate) fn archive() -> Vec<u8> {
    let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gzip);
    for (name, data) in [
        ("kvmapp/version", b"2.0.43\n".as_slice()),
        ("kvmapp/server/NanoKVM-Server", b"test launcher"),
        ("kvmapp/backends/NanoKVM-Server.rust", b"test backend"),
        ("kvmapp/system/init.d/S95nanokvm", b"test init"),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar.append_data(&mut header, name, data).unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

async fn admission(root: &Path) -> (UpdateOwner, Handoff) {
    let parent = File::open(root).unwrap();
    let coordinator = Arc::new(UpdateCoordinator::with_test_parent(
        parent.try_clone().unwrap(),
    ));
    let owner = coordinator.acquire(Kind::ApplicationOffline).unwrap();
    let writers = StateWriters::for_test_parent(parent)
        .drain(Duration::from_secs(1))
        .await
        .unwrap();
    let handoff = owner.prepare_install_handoff(writers).unwrap();
    (owner, handoff)
}

fn candidate(root: &Path) -> AppCandidate {
    manual_candidate_fixture(AppStage::fixture(root).unwrap(), &archive()).unwrap()
}

fn init(root: &Path) {
    fs::create_dir(root.join("kvmapp")).unwrap();
    fs::write(root.join("kvmapp/identity"), b"old unchanged").unwrap();
}

fn issue(root: &Path, candidate: AppCandidate, handoff: Handoff) -> Result<PreparedInstall> {
    prepare_at(
        File::open(root).unwrap(),
        File::open(root).unwrap(),
        nix::unistd::geteuid().as_raw(),
        Preparation { candidate, handoff },
    )
}

pub(crate) async fn accepted_fixture(root: &Path) -> AcceptedInstall {
    let (owner, prepared) = prepared_fixture(root).await;
    let received = received_fixture(root, prepared);
    drop(owner);
    accept_fixture(root, received).unwrap()
}

pub(crate) async fn prepared_fixture(root: &Path) -> (UpdateOwner, PreparedInstall) {
    if !root.join("kvmapp").exists() {
        init(root);
    }
    let (owner, handoff) = admission(root).await;
    let prepared = issue(root, candidate(root), handoff).unwrap();
    (owner, prepared)
}

pub(crate) fn accept_fixture(root: &Path, admission: Accepted) -> Result<AcceptedInstall> {
    accept_at(
        read_store(root, true)?.ok_or(SlotError::Invalid)?,
        admission,
    )
}

pub(crate) fn received_fixture(root: &Path, prepared: PreparedInstall) -> Accepted {
    crate::update::app_install_lease::exchange_fixture(
        prepared.into_handoff(),
        &File::open(root).unwrap(),
    )
}

fn read_store(root: &Path, exclusive: bool) -> Result<Option<Store>> {
    Store::at_root(
        File::open(root).unwrap(),
        File::open(root.join(DIRECTORY)).unwrap(),
        nix::unistd::geteuid().as_raw(),
        exclusive,
    )
}

fn assert_old(root: &Path) {
    assert_eq!(
        fs::read(root.join("kvmapp/identity")).unwrap(),
        b"old unchanged"
    );
}

pub(crate) fn assert_excluded(root: &Path) {
    let parent = File::open(root).unwrap();
    for domain in [
        Domain::Update,
        Domain::WriterAdmission,
        Domain::WriterActivity,
    ] {
        assert!(matches!(
            ProcessLock::at_parent(&parent, nix::unistd::geteuid().as_raw(), domain, false),
            Err(LockError::Busy)
        ));
    }
}

#[cfg(feature = "app-bootstrap-bound-test-fixture")]
pub(crate) fn fixed_root_recovery_fixture(root: &Path) {
    let fixture = super::tests::Fixture::new(Phase::Published, super::tests::Position::Published);
    // Only the caller's fresh disposable native-root fixture is populated.
    fs::remove_dir(root.join("kvmapp")).unwrap();
    fs::rename(fixture.root.path().join("kvmapp"), root.join("kvmapp")).unwrap();
    fs::rename(
        fixture.root.path().join(DIRECTORY),
        root.join("etc/kvm").join(DIRECTORY),
    )
    .unwrap();
}

#[tokio::test]
async fn actual_private_extraction_issues_exact_prepared_record_without_live_swap() {
    let root = tempfile::tempdir().unwrap();
    init(root.path());
    let (owner, handoff) = admission(root.path()).await;
    let transaction = handoff.transaction();
    let candidate = candidate(root.path());
    let source = candidate.fixture_root().to_path_buf();
    let inode = source.metadata().unwrap().ino();
    let prepared = issue(root.path(), candidate, handoff).unwrap();
    assert_eq!(
        fs::metadata(
            root.path()
                .join("application-slot/current/new/server/NanoKVM-Server")
        )
        .unwrap()
        .mode()
            & 0o7777,
        0o755
    );
    assert_eq!(
        fs::metadata(root.path().join("application-slot/current/new/version"))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    drop(owner);
    assert_eq!(prepared.transaction(), transaction);
    assert_eq!(prepared.record.phase, Phase::Prepared);
    assert_eq!(prepared.record.import, Import::Manual);
    assert_eq!(
        prepared.record.archive_sha512,
        <[u8; 64]>::from(Sha512::digest(archive()))
    );
    assert_eq!(prepared.record.metadata_sha256, [0; 32]);
    assert_eq!(prepared.record.signature_sha256, [0; 32]);
    assert_eq!(prepared.record.version, "2.0.43");
    assert_eq!(prepared.record.new.inode, inode);
    assert_eq!(
        prepared.store.record().unwrap().encode().unwrap(),
        prepared.record.encode().unwrap()
    );
    assert!(!source.exists());
    assert_old(root.path());
    assert_excluded(root.path());
    assert!(matches!(
        read_store(root.path(), false),
        Err(SlotError::Busy)
    ));
    assert_eq!(
        root.path()
            .join(DIRECTORY)
            .join("current/new")
            .metadata()
            .unwrap()
            .ino(),
        inode
    );
    drop(prepared);
    let store = read_store(root.path(), true).unwrap().unwrap();
    assert_eq!(
        store.recover().unwrap(),
        Status::Transaction(Phase::RolledBack)
    );
    assert_old(root.path());
}

#[tokio::test]
async fn handoff_releases_only_local_store_not_the_three_kernel_exclusions() {
    let root = tempfile::tempdir().unwrap();
    init(root.path());
    let (owner, handoff) = admission(root.path()).await;
    let id = handoff.transaction();
    let prepared = issue(root.path(), candidate(root.path()), handoff).unwrap();
    drop(owner);
    let handoff = prepared.into_handoff();
    assert_eq!(handoff.transaction(), id);
    assert_excluded(root.path());
    let store = read_store(root.path(), false).unwrap().unwrap();
    assert_eq!(store.record().unwrap().transaction, id);
    assert_eq!(store.record().unwrap().phase, Phase::Prepared);
    assert_old(root.path());
    drop(handoff);
}

#[tokio::test]
async fn worker_binds_received_leases_to_the_exact_prepared_transaction() {
    let root = tempfile::tempdir().unwrap();
    init(root.path());
    let (owner, handoff) = admission(root.path()).await;
    let id = handoff.transaction();
    let prepared = issue(root.path(), candidate(root.path()), handoff).unwrap();
    let handoff = prepared.into_handoff();
    drop(owner);
    let accepted = crate::update::app_install_lease::exchange_fixture(
        handoff,
        &File::open(root.path()).unwrap(),
    );
    let install = accept_at(read_store(root.path(), true).unwrap().unwrap(), accepted).unwrap();
    assert_eq!(install.transaction(), id);
    assert_excluded(root.path());
    assert_old(root.path());
    assert!(matches!(
        read_store(root.path(), false),
        Err(SlotError::Busy)
    ));
    drop(install);
    let store = read_store(root.path(), true).unwrap().unwrap();
    assert_eq!(
        store.recover().unwrap(),
        Status::Transaction(Phase::RolledBack)
    );
    assert_old(root.path());
}

#[tokio::test]
async fn worker_rejects_other_transaction_and_nonprepared_or_already_swapped_layouts() {
    for kind in 0..3 {
        let root = tempfile::tempdir().unwrap();
        init(root.path());
        let (owner, handoff) = admission(root.path()).await;
        let prepared = issue(root.path(), candidate(root.path()), handoff).unwrap();
        let handoff = prepared.into_handoff();
        let accepted = crate::update::app_install_lease::exchange_fixture(
            handoff,
            &File::open(root.path()).unwrap(),
        );
        let store = read_store(root.path(), true).unwrap().unwrap();
        let mut record = store.record().unwrap();
        match kind {
            0 => record.transaction[0] ^= 0xff,
            1 => record.phase = Phase::Published,
            _ => {
                fs::rename(
                    root.path().join("kvmapp"),
                    root.path().join(DIRECTORY).join("current/old"),
                )
                .unwrap();
                fs::rename(
                    root.path().join(DIRECTORY).join("current/new"),
                    root.path().join("kvmapp"),
                )
                .unwrap();
            }
        }
        store.publish(&record).unwrap();
        let before = fs::read(root.path().join(DIRECTORY).join("current/state")).unwrap();
        assert!(matches!(
            accept_at(store, accepted),
            Err(SlotError::Invalid)
        ));
        assert_eq!(
            fs::read(root.path().join(DIRECTORY).join("current/state")).unwrap(),
            before
        );
        if kind != 2 {
            assert_old(root.path());
        }
        drop(owner);
    }
}

#[tokio::test]
async fn current_transaction_or_foreign_binding_is_never_replaced_or_cleaned() {
    for kind in 0..4 {
        let root = tempfile::tempdir().unwrap();
        init(root.path());
        fs::create_dir(root.path().join(DIRECTORY)).unwrap();
        fs::set_permissions(
            root.path().join(DIRECTORY),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let path = root.path().join(DIRECTORY).join(CURRENT);
        match kind {
            0 => {
                fs::create_dir(&path).unwrap();
                fs::write(path.join("evidence"), b"retain").unwrap();
            }
            1 => {
                fs::write(&path, b"retain").unwrap();
            }
            2 => {
                symlink("missing", &path).unwrap();
            }
            _ => {
                fs::create_dir(&path).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
            }
        }
        let before = fs::symlink_metadata(&path).unwrap().ino();
        let (owner, handoff) = admission(root.path()).await;
        assert!(issue(root.path(), candidate(root.path()), handoff).is_err());
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), before);
        if kind == 0 {
            assert_eq!(fs::read(path.join("evidence")).unwrap(), b"retain");
        }
        if kind == 1 {
            assert_eq!(fs::read(&path).unwrap(), b"retain");
        }
        assert_old(root.path());
        drop(owner);
    }
}

#[tokio::test]
async fn candidate_links_special_files_and_unsafe_modes_fail_before_publication() {
    for kind in 0..5 {
        let root = tempfile::tempdir().unwrap();
        init(root.path());
        let (owner, handoff) = admission(root.path()).await;
        let candidate = candidate(root.path());
        let path = candidate.fixture_root().join("bad");
        match kind {
            0 => symlink("version", &path).unwrap(),
            1 => fs::hard_link(candidate.fixture_root().join("version"), &path).unwrap(),
            2 => rustix::fs::mknodat(
                rustix::fs::CWD,
                &path,
                rustix::fs::FileType::Fifo,
                Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap(),
            3 => {
                fs::write(&path, b"bad").unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o666)).unwrap();
            }
            _ => {
                fs::create_dir(&path).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o777)).unwrap();
            }
        }
        assert!(issue(root.path(), candidate, handoff).is_err());
        assert!(!root.path().join(DIRECTORY).join(CURRENT).exists());
        assert_old(root.path());
        drop(owner);
    }
}

#[test]
fn issuer_crash_child() {
    let Some(root) = std::env::var_os("NANOKVM_APP_ISSUER_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (_owner, handoff) = runtime.block_on(admission(&root));
    let candidate = candidate(&root);
    fs::write(
        root.join("candidate-path"),
        candidate.fixture_root().to_str().unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("candidate-inode"),
        candidate
            .fixture_root()
            .metadata()
            .unwrap()
            .ino()
            .to_string(),
    )
    .unwrap();
    let _prepared = issue(&root, candidate, handoff).unwrap();
    panic!("parent must stop the child at the selected checkpoint");
}

#[test]
fn killed_issuer_never_exposes_partial_current_or_changes_the_live_old_slot() {
    for stop in [
        "issuer-directory-created",
        "issuer-candidate-moved",
        "issuer-source-synced",
        "issuer-candidate-synced",
        "prepared:record-written",
        "prepared:record-synced",
        "prepared:record-renamed",
        "prepared:record-published",
        "issuer-record-durable",
        "issuer-current-renamed",
        "issuer-current-durable",
    ] {
        let root = tempfile::tempdir().unwrap();
        init(root.path());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_slot::issuer_tests::issuer_crash_child",
                "--nocapture",
            ])
            .env("NANOKVM_APP_ISSUER_CHILD", root.path())
            .env("NANOKVM_APP_SLOT_TEST_STOP", stop)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut lines = BufReader::new(stdout);
            let mut line = String::new();
            while lines.read_line(&mut line).unwrap() != 0 {
                if line.trim() == "slot-checkpoint-ready" {
                    tx.send(()).unwrap();
                    break;
                }
                line.clear();
            }
        });
        let ready = rx.recv_timeout(Duration::from_secs(15));
        child.kill().unwrap();
        let output = child.wait_with_output().unwrap();
        reader.join().unwrap();
        assert!(
            ready.is_ok(),
            "checkpoint {stop}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_old(root.path());
        let expected_inode = fs::read_to_string(root.path().join("candidate-inode"))
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let store = read_store(root.path(), true).unwrap();
        if matches!(stop, "issuer-current-renamed" | "issuer-current-durable") {
            let store = store.unwrap();
            assert_eq!(store.record().unwrap().phase, Phase::Prepared);
            assert_eq!(store.record().unwrap().new.inode, expected_inode);
            assert_eq!(
                store.recover().unwrap(),
                Status::Transaction(Phase::RolledBack)
            );
            assert!(
                root.path()
                    .join(DIRECTORY)
                    .join("current/new/backends/NanoKVM-Server.rust")
                    .is_file()
            );
        } else {
            assert!(
                store.is_none(),
                "unpublished transaction must not become authority at {stop}"
            );
            // Assertion only: production recovery never scans/promotes orphans.
            let orphan = fs::read_dir(root.path().join(DIRECTORY))
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".prepare-")
                })
                .unwrap();
            let candidate_path = if stop == "issuer-directory-created" {
                PathBuf::from(fs::read_to_string(root.path().join("candidate-path")).unwrap())
            } else {
                orphan.join("new")
            };
            assert_eq!(candidate_path.metadata().unwrap().ino(), expected_inode);
            assert_eq!(
                fs::read(candidate_path.join("version")).unwrap(),
                b"2.0.43\n"
            );
        }
        assert_old(root.path());
        // A dead issuer has no live process left holding its kernel leases.
        let parent = File::open(root.path()).unwrap();
        let start = Instant::now();
        loop {
            match ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()) {
                Ok(guard) => {
                    drop(guard);
                    break;
                }
                Err(LockError::Busy) if start.elapsed() < Duration::from_secs(3) => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("issuer lease did not end at {stop}: {error}"),
            }
        }
    }
}

struct Worker(std::process::Child);
impl Worker {
    fn finish(&mut self) {
        let start = Instant::now();
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "prepared worker failed: {status}");
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "prepared worker deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn rejected_issuer_cleanup_child() {
    let Some(root) = std::env::var_os("NANOKVM_APP_REJECTED_ISSUER_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let (owner, handoff) = runtime.block_on(admission(&root));
    let candidate = candidate(&root);
    fs::write(
        root.join("rejected-candidate-path"),
        candidate.fixture_root().to_str().unwrap(),
    )
    .unwrap();
    drop(owner);
    assert!(issue(&root, candidate, handoff).is_err());
    assert_old(&root);
}

#[test]
fn early_rejection_retains_exclusion_through_owned_staging_cleanup() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    init(root.path());
    fs::create_dir(root.path().join(DIRECTORY)).unwrap();
    fs::set_permissions(
        root.path().join(DIRECTORY),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::create_dir(root.path().join(DIRECTORY).join(CURRENT)).unwrap();
    fs::write(
        root.path().join(DIRECTORY).join("current/evidence"),
        b"retain current",
    )
    .unwrap();
    let mut child = Worker(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_slot::issuer_tests::rejected_issuer_cleanup_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("NANOKVM_APP_REJECTED_ISSUER_ROOT", root.path())
            .env("NANOKVM_APP_STAGE_DROP_CHECK", "cleanup")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut reported = false;
        for line in BufReader::new(stdout).lines() {
            // Single-threaded libtest prints its test-name prefix on the same
            // line as uncaptured output; do not miss the real cleanup barrier.
            if line.unwrap().trim_end().ends_with("stage-cleanup-ready") && !reported {
                tx.send(()).unwrap();
                reported = true;
            }
            // Keep draining through child exit. Closing stdout at the barrier
            // would make libtest's final result write fail with BrokenPipe.
        }
    });
    let ready = rx.recv_timeout(Duration::from_secs(10));
    if ready.is_err() {
        let _ = child.0.kill();
        reader.join().unwrap();
        panic!("rejected issuer did not reach owned staging cleanup");
    }
    assert_excluded(root.path());
    let candidate_path =
        PathBuf::from(fs::read_to_string(root.path().join("rejected-candidate-path")).unwrap());
    assert!(candidate_path.is_dir());
    child.0.stdin.take().unwrap().write_all(&[1]).unwrap();
    child.finish();
    reader.join().unwrap();
    assert!(!candidate_path.exists());
    assert_old(root.path());
    assert_eq!(
        fs::read(root.path().join(DIRECTORY).join("current/evidence")).unwrap(),
        b"retain current"
    );
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn fixed_root_issuer_child() {
    use crate::update::app_install_lease::{Receiver, channel};
    let Some(root) = std::env::var_os("NANOKVM_APP_ISSUER_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    assert!(nix::unistd::geteuid().is_root());
    if std::env::var("NANOKVM_APP_ISSUER_ROLE").unwrap() == "worker" {
        let socket = rustix::io::dup(std::io::stdin()).unwrap();
        let null = File::open("/dev/null").unwrap();
        use std::os::fd::AsRawFd;
        nix::unistd::dup2(null.as_raw_fd(), 0).unwrap();
        drop(null);
        let receiver = Receiver::adopt(socket, nix::unistd::getppid().as_raw() as u32).unwrap();
        nix::unistd::chroot(&root).unwrap();
        std::env::set_current_dir("/").unwrap();
        let start = Instant::now();
        while !Path::new("/expected-id").exists() {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(5));
        }
        let expected = u128::from_str_radix(&fs::read_to_string("/expected-id").unwrap(), 16)
            .unwrap()
            .to_be_bytes();
        let accepted = receiver.receive(expected).unwrap();
        // No private root/uid/parent override: production receiver and issuer
        // acceptance operate on the same fixed protected journal.
        let install = accept_prepared(accepted).unwrap();
        assert_eq!(install.transaction(), expected);
        fs::write("/worker-accepted", b"accepted preparation, not healthy").unwrap();
        let start = Instant::now();
        while !Path::new("/release-worker").exists() {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(install);
        return;
    }
    use nix::mount::{MsFlags, mount};
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .unwrap();
    fs::create_dir_all(root.join("etc/kvm")).unwrap();
    fs::create_dir(root.join("proc")).unwrap();
    mount(
        Some("proc"),
        &root.join("proc"),
        Some("proc"),
        MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID,
        None::<&str>,
    )
    .unwrap();
    init(&root);
    let (sender, receiver) = channel().unwrap();
    let mut worker = Worker(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_slot::issuer_tests::fixed_root_issuer_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_APP_ISSUER_ROOT", &root)
            .env("NANOKVM_APP_ISSUER_ROLE", "worker")
            .stdin(receiver.into_stdio())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    nix::unistd::chroot(&root).unwrap();
    std::env::set_current_dir("/").unwrap();
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::ApplicationOffline).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let writers = runtime
        .block_on(StateWriters::default().drain(Duration::from_secs(1)))
        .unwrap();
    let candidate = manual_candidate_fixture(AppStage::prepare().unwrap(), &archive()).unwrap();
    let prepared = prepare(candidate, owner.prepare_install_handoff(writers).unwrap()).unwrap();
    let id = prepared.transaction();
    fs::write(
        "/expected-id.next",
        format!("{:032x}", u128::from_be_bytes(id)),
    )
    .unwrap();
    fs::rename("/expected-id.next", "/expected-id").unwrap();
    sender.send(prepared.into_handoff()).unwrap();
    drop(owner);
    let start = Instant::now();
    while !Path::new("/worker-accepted").exists() {
        assert!(
            worker.0.try_wait().unwrap().is_none(),
            "worker exited before acceptance"
        );
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(5));
    }
    let parent = File::open("/etc/kvm").unwrap();
    for domain in [
        Domain::Update,
        Domain::WriterAdmission,
        Domain::WriterActivity,
    ] {
        assert!(matches!(
            ProcessLock::at_parent(&parent, 0, domain, false),
            Err(LockError::Busy)
        ));
    }
    assert!(matches!(status(), Err(SlotError::Busy)));
    assert_old(Path::new("/"));
    fs::write("/release-worker", b"release").unwrap();
    worker.finish();
    crate::native_owner::broker::app_recovery_closed_fixture(&File::open("/etc/kvm").unwrap());
    assert_eq!(recover().unwrap(), Status::Transaction(Phase::RolledBack));
    assert_eq!(status().unwrap(), Status::NoTransaction);
    assert!(job_status(id).unwrap().unwrap().archived);
    assert_old(Path::new("/"));
}

#[cfg(feature = "sandbox-test-fixture")]
#[test]
fn actual_fixed_root_issuer_and_exec_worker_bind_provenance_and_keep_exclusion() {
    let root = tempfile::tempdir().unwrap();
    let mut child = Worker(
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
                "update::app_slot::issuer_tests::fixed_root_issuer_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_APP_ISSUER_ROOT", root.path())
            .env("NANOKVM_APP_ISSUER_ROLE", "issuer")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    child.finish();
    assert!(root.path().join("worker-accepted").exists());
    assert_old(root.path());
}
