//! Actual fixed-root bootstrap entry in a disposable user namespace/chroot.
//! Bound RV64 images are data only; none is executed by these host fixtures.

use super::*;
use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};

#[derive(Clone, Copy, Debug)]
enum Journal {
    Absent,
    Valid(u8),
    Corrupt,
    ForeignLayout,
    Orphan,
}

#[derive(Clone, Copy, Debug)]
enum Helper {
    Absent,
    Current,
    Previous,
    Unknown,
    CorruptPrevious,
    Symlink,
    UnsafeParent,
}

struct Fixture {
    root: TempDir,
    current_image: &'static [u8],
    previous: Vec<u8>,
}

impl Fixture {
    fn new(journal: Journal, helper: Helper) -> Self {
        let root = tempdir().unwrap();
        let current_image = embedded_recovery()
            .expect("run the reviewed bound-root fixture script with a valid app binding");
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("build/audit/remediation-2026-10-17/host/helper-migration/predecessor-v1");
        let mut previous = Vec::with_capacity(V1_PREDECESSORS[0].size + 1);
        File::open(source)
            .unwrap()
            .take(restore_binding::MAX_HELPER + 1)
            .read_to_end(&mut previous)
            .unwrap();
        assert_eq!(previous.len(), V1_PREDECESSORS[0].size);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&previous)),
            V1_PREDECESSORS[0].sha256
        );
        assert_ne!(
            previous, current_image,
            "this gate must exercise a real forward transition"
        );
        for directory in [
            "etc/init.d",
            "etc/kvm/update-operation",
            "usr/libexec",
            "kvmapp",
        ] {
            fs::create_dir_all(root.path().join(directory)).unwrap();
        }
        fs::set_permissions(
            root.path().join("etc/kvm/update-operation"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(root.path().join("kvmapp/identity"), b"old").unwrap();
        let fixture = Self {
            root,
            current_image,
            previous,
        };
        fixture.journal(journal);
        match helper {
            Helper::Absent => {}
            Helper::Current => fixture.write_helper(current_image),
            Helper::Previous => fixture.write_helper(&fixture.previous),
            Helper::Unknown => fixture.write_helper(b"unknown fixture helper"),
            Helper::CorruptPrevious => {
                let mut bytes = fixture.previous.clone();
                bytes[0] ^= 1;
                fixture.write_helper(&bytes);
            }
            Helper::Symlink => {
                fs::write(
                    fixture.root.path().join("usr/libexec/other"),
                    &fixture.previous,
                )
                .unwrap();
                std::os::unix::fs::symlink("other", fixture.helper()).unwrap();
            }
            Helper::UnsafeParent => {
                fixture.write_helper(current_image);
                fs::set_permissions(
                    fixture.helper().parent().unwrap(),
                    fs::Permissions::from_mode(0o777),
                )
                .unwrap();
            }
        }
        fixture
    }

    fn helper(&self) -> PathBuf {
        self.root.path().join("usr/libexec").join(EXECUTABLE)
    }

    fn write_helper(&self, bytes: &[u8]) {
        fs::write(self.helper(), bytes).unwrap();
        fs::set_permissions(self.helper(), fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn state(&self) -> PathBuf {
        self.root
            .path()
            .join("etc/kvm/application-slot/current/state")
    }

    fn journal(&self, kind: Journal) {
        if matches!(kind, Journal::Absent) {
            return;
        }
        let directory = self.root.path().join("etc/kvm/application-slot");
        let current = directory.join("current");
        fs::create_dir_all(current.join("new")).unwrap();
        for path in [&directory, &current] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(current.join("new/identity"), b"new").unwrap();
        let old = self.root.path().join("kvmapp");
        let old_identity = old.metadata().unwrap();
        let new_identity = current.join("new").metadata().unwrap();
        let phase = match kind {
            Journal::Valid(phase) => phase,
            _ => 4,
        };
        if matches!(phase, 2..=5) {
            fs::rename(&old, current.join("old")).unwrap();
        }
        if matches!(phase, 3..=5) {
            fs::rename(current.join("new"), &old).unwrap();
        }
        // Independent fixed v1 fixture encoder, not a production issuer or a
        // signature. Actual app_slot::status() must decode/check these bytes.
        let mut bytes = [0_u8; 512];
        bytes[..8].copy_from_slice(b"NKAPPJ01");
        bytes[8] = phase;
        bytes[9] = 2; // Explicit manual-import fixture, no invented RSA proof.
        bytes[16..32].fill(2);
        for (offset, value) in [
            (32, old_identity.dev()),
            (40, old_identity.ino()),
            (48, new_identity.dev()),
            (56, new_identity.ino()),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[64..128].fill(3);
        bytes[192..194].copy_from_slice(&6_u16.to_le_bytes());
        bytes[194..200].copy_from_slice(b"2.0.43");
        let mut hash = Sha256::new();
        hash.update(b"NanoKVM app slot journal v1\0");
        hash.update(&bytes[..480]);
        bytes[480..].copy_from_slice(&hash.finalize());
        fs::write(self.state(), bytes).unwrap();
        fs::set_permissions(self.state(), fs::Permissions::from_mode(0o600)).unwrap();
        if matches!(kind, Journal::Corrupt) {
            fs::write(self.state(), b"corrupt fixed-root fixture").unwrap();
        }
        if matches!(kind, Journal::ForeignLayout) {
            fs::rename(&old, self.root.path().join("foreign-retained")).unwrap();
            fs::create_dir(old).unwrap();
        }
        if matches!(kind, Journal::Orphan) {
            fs::rename(current, directory.join("unpublished-evidence")).unwrap();
        }
    }

    fn command(&self, expected: &str) -> Command {
        let mut command = Command::new("/usr/bin/unshare");
        command
            .args(["--user", "--map-root-user", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "update::app_bootstrap::root_tests::fixed_root_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env("NANOKVM_APP_ROOT_FIXTURE", self.root.path())
            .env("NANOKVM_APP_ROOT_EXPECTED", expected)
            .stdin(Stdio::null());
        command
    }

    fn run(&self, expected: &str) {
        let output = Probe::spawn(&mut self.command(expected), None)
            .wait(Duration::from_secs(20))
            .unwrap();
        assert!(output.status.success(), "{expected}: {output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains("fixed-root-bootstrap-fixture-ran")
                && text.contains("1 passed; 0 failed"),
            "{text}"
        );
    }
}

// The fixture child never launches helpers/native work. Own/reap that direct
// child on normal completion, timeout, error and parent assertion unwind.
struct Probe {
    child: Child,
    finished: bool,
    stdout: Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
    stderr: Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
}

impl Probe {
    fn spawn(command: &mut Command, ready: Option<mpsc::SyncSender<()>>) -> Self {
        let child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut probe = Self {
            child,
            finished: false,
            stdout: None,
            stderr: None,
        };
        let stdout = probe.child.stdout.take().unwrap();
        probe.stdout = Some(capture(stdout, ready));
        let stderr = probe.child.stderr.take().unwrap();
        probe.stderr = Some(capture(stderr, None));
        probe
    }

    fn wait(mut self, timeout: Duration) -> io::Result<Output> {
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        self.finished = true;
        let stdout = self
            .stdout
            .take()
            .unwrap()
            .join()
            .map_err(|_| io::Error::other("fixture stdout reader panicked"))??;
        let stderr = self
            .stderr
            .take()
            .unwrap()
            .join()
            .map_err(|_| io::Error::other("fixture stderr reader panicked"))??;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }

    fn kill(mut self) -> ExitStatus {
        let _ = self.child.kill();
        let status = self.child.wait().unwrap();
        self.finished = true;
        status
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        for reader in [&mut self.stdout, &mut self.stderr] {
            if let Some(reader) = reader.take() {
                let _ = reader.join();
            }
        }
    }
}

fn capture(
    mut source: impl Read + Send + 'static,
    mut ready: Option<mpsc::SyncSender<()>>,
) -> std::thread::JoinHandle<io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        const LIMIT: usize = 64 * 1024;
        let mut output = Vec::with_capacity(LIMIT);
        let mut buffer = [0; 4096];
        loop {
            let count = match source.read(&mut buffer) {
                Ok(0) => return Ok(output),
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            output.extend_from_slice(&buffer[..count.min(LIMIT - output.len())]);
            if ready.is_some()
                && output
                    .windows(b"app-bootstrap-checkpoint-ready".len())
                    .any(|bytes| bytes == b"app-bootstrap-checkpoint-ready")
            {
                let _ = ready.take().unwrap().send(());
            }
        }
    })
}

type Tree = BTreeMap<PathBuf, (u64, u32, Vec<u8>)>;

fn snapshot(root: &Path) -> Tree {
    fn visit(root: &Path, path: &Path, tree: &mut Tree) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let content = if metadata.is_file() {
            fs::read(path).unwrap()
        } else if metadata.file_type().is_symlink() {
            fs::read_link(path)
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec()
        } else {
            Vec::new()
        };
        tree.insert(
            path.strip_prefix(root).unwrap().to_path_buf(),
            (metadata.ino(), metadata.mode(), content),
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), tree);
            }
        }
    }
    let mut tree = BTreeMap::new();
    visit(root, root, &mut tree);
    tree
}

#[test]
fn fixed_root_child() {
    let Ok(root) = std::env::var("NANOKVM_APP_ROOT_FIXTURE") else {
        return;
    };
    let expected = std::env::var("NANOKVM_APP_ROOT_EXPECTED").unwrap();
    assert!(nix::unistd::geteuid().is_root());
    nix::unistd::chroot(Path::new(&root)).unwrap();
    std::env::set_current_dir("/").unwrap();
    let result = ensure_installed();
    match expected.as_str() {
        "success" => result.unwrap(),
        "failure" => assert!(result.is_err()),
        "admission-busy" => {
            let error = result.unwrap_err();
            assert!(matches!(
                error.get_ref().and_then(
                    |inner| inner.downcast_ref::<super::super::operation_lock::LockError>()
                ),
                Some(super::super::operation_lock::LockError::Busy)
            ));
        }
        "slot-busy" => {
            let error = result.unwrap_err();
            assert!(matches!(
                error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<app_slot::SlotError>()),
                Some(app_slot::SlotError::Busy)
            ));
        }
        _ => panic!("invalid fixed fixture case"),
    }
    println!("fixed-root-bootstrap-fixture-ran");
}

#[test]
fn actual_fixed_root_journal_matrix_publishes_only_allowed_helper_transitions() {
    for (journal, helper, allowed) in [
        (Journal::Absent, Helper::Absent, true),
        (Journal::Absent, Helper::Current, true),
        (Journal::Absent, Helper::Previous, true),
        (Journal::Valid(4), Helper::Previous, true),
        (Journal::Valid(6), Helper::Previous, true),
        (Journal::Valid(1), Helper::Current, true),
        (Journal::Valid(2), Helper::Current, true),
        (Journal::Valid(3), Helper::Current, true),
        (Journal::Valid(4), Helper::Current, true),
        (Journal::Valid(5), Helper::Current, true),
        (Journal::Valid(6), Helper::Current, true),
        (Journal::Orphan, Helper::Absent, true),
        (Journal::Orphan, Helper::Unknown, false),
        (Journal::Valid(1), Helper::Previous, false),
        (Journal::Valid(2), Helper::Previous, false),
        (Journal::Valid(3), Helper::Previous, false),
        (Journal::Valid(5), Helper::Previous, false),
        (Journal::Valid(4), Helper::Absent, false),
        (Journal::Valid(6), Helper::Absent, false),
        (Journal::Absent, Helper::Unknown, false),
        (Journal::Valid(4), Helper::CorruptPrevious, false),
        (Journal::Absent, Helper::Symlink, false),
        (Journal::Absent, Helper::UnsafeParent, false),
        (Journal::Corrupt, Helper::Absent, false),
        (Journal::Corrupt, Helper::Current, false),
        (Journal::ForeignLayout, Helper::Previous, false),
        (Journal::ForeignLayout, Helper::Current, false),
    ] {
        let fixture = Fixture::new(journal, helper);
        let before = snapshot(fixture.root.path());
        let record = fs::read(fixture.state()).ok();
        fixture.run(if allowed { "success" } else { "failure" });
        if allowed {
            assert_eq!(
                fs::read(fixture.helper()).unwrap(),
                fixture.current_image,
                "{journal:?}/{helper:?}"
            );
            assert_eq!(fixture.helper().metadata().unwrap().mode() & 0o7777, 0o755);
            assert_eq!(fs::read(fixture.state()).ok(), record);
            let after = snapshot(fixture.root.path());
            if matches!(helper, Helper::Current) {
                assert_eq!(
                    after, before,
                    "exact verification must not rewrite or authorize app state"
                );
            }
            for (path, value) in &before {
                if path != Path::new("usr/libexec").join(EXECUTABLE).as_path() {
                    assert_eq!(
                        after.get(path),
                        Some(value),
                        "{journal:?}/{helper:?}: {path:?}"
                    );
                }
            }
            if matches!(helper, Helper::Previous) {
                let old = &before[Path::new("usr/libexec").join(EXECUTABLE).as_path()];
                assert!(after.iter().any(|(path, value)| path
                    != Path::new("usr/libexec").join(EXECUTABLE).as_path()
                    && value == old));
            }
        } else {
            assert_eq!(
                snapshot(fixture.root.path()),
                before,
                "{journal:?}/{helper:?}"
            );
        }
    }
}

#[test]
fn actual_fixed_root_bootstrap_refuses_competing_update_admission() {
    let fixture = Fixture::new(Journal::Valid(4), Helper::Previous);
    let before = snapshot(fixture.root.path());
    let parent = File::open(fixture.root.path().join("etc/kvm")).unwrap();
    let admission = ProcessLock::from_parent(&parent, nix::unistd::geteuid().as_raw()).unwrap();
    fixture.run("admission-busy");
    assert_eq!(snapshot(fixture.root.path()), before);
    drop(admission);
    fixture.run("success");
    assert_eq!(fs::read(fixture.helper()).unwrap(), fixture.current_image);
}

#[test]
fn actual_fixed_root_bootstrap_refuses_an_exclusively_owned_decoded_store() {
    let fixture = Fixture::new(Journal::Valid(4), Helper::Current);
    let before = snapshot(fixture.root.path());
    let store = File::open(fixture.root.path().join("etc/kvm/application-slot")).unwrap();
    rustix::fs::flock(&store, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    fixture.run("slot-busy");
    assert_eq!(snapshot(fixture.root.path()), before);
    drop(store);
    fixture.run("success");
    assert_eq!(snapshot(fixture.root.path()), before);
}

fn paused_child(fixture: &Fixture, point: &str) -> Probe {
    let (send, receive) = mpsc::sync_channel(1);
    let mut command = fixture.command("success");
    command.env("NANOKVM_APP_BOOTSTRAP_TEST_STOP", point);
    let child = Probe::spawn(&mut command, Some(send));
    receive
        .recv_timeout(Duration::from_secs(10))
        .unwrap_or_else(|_| panic!("fixed-root checkpoint not reached: {point}"));
    child
}

#[test]
fn actual_fixed_root_migration_retains_admission_and_recovers_after_process_death() {
    for point in ["synced", "exchanged"] {
        let fixture = Fixture::new(Journal::Valid(4), Helper::Previous);
        let record = fs::read(fixture.state()).unwrap();
        let old = fixture.helper().metadata().unwrap().ino();
        let child = paused_child(&fixture, point);
        fixture.run("admission-busy");
        assert_eq!(child.kill().signal(), Some(9));
        assert_eq!(fs::read(fixture.state()).unwrap(), record);
        assert_eq!(
            fs::read(fixture.helper()).unwrap(),
            if point == "synced" {
                fixture.previous.as_slice()
            } else {
                fixture.current_image
            }
        );
        fixture.run("success");
        fixture.run("success");
        assert_eq!(fs::read(fixture.state()).unwrap(), record);
        assert_eq!(fs::read(fixture.helper()).unwrap(), fixture.current_image);
        assert!(
            fs::read_dir(fixture.helper().parent().unwrap())
                .unwrap()
                .any(|entry| entry.unwrap().metadata().unwrap().ino() == old)
        );
    }
}

#[test]
fn fixture_timeout_kills_and_reaps_its_owned_direct_child() {
    let probe = Probe::spawn(Command::new("/bin/sleep").arg("30"), None);
    let pid = nix::unistd::Pid::from_raw(probe.child.id() as i32);
    assert_eq!(
        probe.wait(Duration::from_millis(25)).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(matches!(
        nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
        Err(nix::errno::Errno::ECHILD)
    ));
}
