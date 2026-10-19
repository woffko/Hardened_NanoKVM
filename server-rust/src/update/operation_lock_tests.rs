use super::*;
use std::{
    fs::{self, Permissions},
    os::{
        fd::AsRawFd,
        unix::fs::{PermissionsExt, symlink},
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn acquire(path: &Path) -> Result<ProcessLock, LockError> {
    ProcessLock::from_parent(&File::open(path).unwrap(), nix::unistd::geteuid().as_raw())
}

#[test]
fn same_inode_conflicts_and_drop_unlocks_without_removing_it() {
    let temporary = tempfile::tempdir().unwrap();
    let lock = acquire(temporary.path()).unwrap();
    let before = lock.directory.metadata().unwrap();
    let flags =
        nix::fcntl::fcntl(lock.directory.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap();
    assert_ne!(flags & nix::fcntl::FdFlag::FD_CLOEXEC.bits(), 0);
    assert!(matches!(acquire(temporary.path()), Err(LockError::Busy)));
    drop(lock);
    let next = acquire(temporary.path()).unwrap();
    let after = next.directory.metadata().unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(after.mode() & 0o7777, 0o700);
}

#[test]
fn transferred_description_stays_busy_until_its_last_alias_closes() {
    let temporary = tempfile::tempdir().unwrap();
    let mut original = acquire(temporary.path()).unwrap();
    let receiver = original.transfer_alias().unwrap();
    // Deterministically model an inherited pre-exec FD without a timing race
    // or unsafe fork in this multithreaded test process. This is not evidence
    // that a particular failed aggregate was caused by a particular child.
    let inherited = receiver.try_clone().unwrap();
    drop(original);
    assert!(matches!(acquire(temporary.path()), Err(LockError::Busy)));
    drop(receiver);
    assert!(matches!(acquire(temporary.path()), Err(LockError::Busy)));
    drop(inherited);
    let next = acquire(temporary.path()).unwrap();
    let identity = next.directory.metadata().unwrap();
    assert_eq!(
        identity.ino(),
        fs::metadata(temporary.path().join(DIRECTORY))
            .unwrap()
            .ino()
    );
}

#[test]
fn unsafe_parent_or_member_is_rejected_without_repair_or_removal() {
    let uid = nix::unistd::geteuid().as_raw();
    let temporary = tempfile::tempdir().unwrap();
    let parent = File::open(temporary.path()).unwrap();
    assert!(matches!(
        ProcessLock::from_parent(&parent, uid.wrapping_add(1)),
        Err(LockError::Unsafe)
    ));
    fs::set_permissions(temporary.path(), Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        ProcessLock::from_parent(&parent, uid),
        Err(LockError::Unsafe)
    ));
    fs::set_permissions(temporary.path(), Permissions::from_mode(0o700)).unwrap();
    let member = temporary.path().join(DIRECTORY);
    symlink("/", &member).unwrap();
    assert!(acquire(temporary.path()).is_err());
    assert!(fs::symlink_metadata(&member).unwrap().is_symlink());
    fs::remove_file(&member).unwrap();
    fs::write(&member, b"synthetic invalid lock object").unwrap();
    assert!(acquire(temporary.path()).is_err());
    assert_eq!(fs::read(&member).unwrap(), b"synthetic invalid lock object");
    fs::remove_file(&member).unwrap();
    fs::create_dir(&member).unwrap();
    fs::set_permissions(&member, Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(acquire(temporary.path()), Err(LockError::Unsafe)));
    assert_eq!(fs::metadata(&member).unwrap().mode() & 0o7777, 0o755);
    assert!(ProcessLock::from_parent(&File::open("/dev/null").unwrap(), uid).is_err());
}

// Unit-only subprocess probe. Environment fields are public fixture controls,
// not configuration accepted by the shipped backend or credentials.
#[test]
fn child_lock_probe() {
    let Some(root) = std::env::var_os("NANOKVM_OPERATION_LOCK_FIXTURE") else {
        return;
    };
    let mode = std::env::var("NANOKVM_OPERATION_LOCK_EXPECT").unwrap();
    let root = Path::new(&root);
    let result = acquire(root);
    if mode == "busy" {
        assert!(matches!(result, Err(LockError::Busy)));
        return;
    }
    let _guard = result.unwrap();
    if mode == "hold" {
        fs::write(root.join("ready"), b"fixture").unwrap();
        std::thread::sleep(Duration::from_secs(30));
        return;
    }
    assert_eq!(mode, "free");
}

fn child(root: &Path, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "update::operation_lock::tests::child_lock_probe",
            "--nocapture",
        ])
        .env("NANOKVM_OPERATION_LOCK_FIXTURE", root)
        .env("NANOKVM_OPERATION_LOCK_EXPECT", mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

struct OwnedProbe(std::process::Child);
impl Drop for OwnedProbe {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn independent_exec_contends_and_process_death_releases_kernel_lock() {
    let temporary = tempfile::tempdir().unwrap();
    let lock = acquire(temporary.path()).unwrap();
    assert!(child(temporary.path(), "busy").status().unwrap().success());
    drop(lock);
    assert!(child(temporary.path(), "free").status().unwrap().success());
    let mut command = child(temporary.path(), "hold");
    let mut process = OwnedProbe(command.spawn().unwrap());
    drop(command);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !temporary.path().join("ready").exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let started = temporary.path().join("ready").exists();
    let busy = matches!(acquire(temporary.path()), Err(LockError::Busy));
    let _ = process.0.kill();
    process.0.wait().unwrap();
    assert!(
        started && busy,
        "subprocess did not hold the independent lock"
    );
    let _next = acquire(temporary.path()).unwrap();
}
