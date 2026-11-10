//! Process identity for S95 watchdog migration. Numeric PIDs never authorize signals.

use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    io::Errno,
    process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal},
};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::{
        fd::OwnedFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Root-only static-helper interface. Status 3 means absent, never an I/O error.
pub fn run(args: &[OsString]) -> i32 {
    if !nix::unistd::geteuid().is_root() {
        return 77;
    }
    match command(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("watchdog operation refused: {error}");
            70
        }
    }
}

fn command(args: &[OsString]) -> io::Result<i32> {
    let (action, role) = match args {
        [action, role] | [action, role, _] => (action.to_str(), role.to_str()),
        _ => return Err(invalid()),
    };
    let name = match role {
        Some("runtime") => "nanokvm-watchdog",
        Some("update") => "system-update-watchdog",
        _ => return Err(invalid()),
    };
    let parent = nix::unistd::getppid().as_raw();
    let child_pid = || {
        args.get(2)
            .and_then(|v| v.to_str())
            .and_then(|v| v.parse::<i32>().ok())
            .ok_or_else(invalid)
    };
    if action == Some("discard") && args.len() == 3 {
        Pinned::capture_child(child_pid()?, parent, 0)?.terminate()?;
        return Ok(0);
    }
    let store = Store::open(&PathBuf::from(format!("/run/{name}.pid")), 0)?;
    let legacy_path = PathBuf::from(format!("/tmp/{name}.pid"));
    match (action, args.len()) {
        (Some("record"), 3) => {
            let child = Pinned::capture_child(child_pid()?, parent, 0)?;
            if legacy_watchdog(&legacy_path)?.is_some() {
                return Err(invalid());
            }
            store.publish(&child)?;
            Ok(0)
        }
        (Some("owned"), 2) => {
            let Some(record) = store.load()? else {
                return Ok(3);
            };
            Ok(
                if record.identity.pid == parent
                    && Pinned::from_identity(&record.identity, 0)?.is_some()
                {
                    0
                } else {
                    3
                },
            )
        }
        (Some("status"), 2) => {
            if let Some(record) = store.load()?
                && let Some(pinned) = Pinned::from_identity(&record.identity, 0)?
            {
                println!("{}", pinned.identity.pid);
                return Ok(0);
            }
            if let Some((pinned, _)) = legacy_watchdog(&legacy_path)? {
                println!("{}", pinned.identity.pid);
                return Ok(0);
            }
            Ok(3)
        }
        (Some("stop"), 2) => {
            store.stop()?;
            if let Some((pinned, observed)) = legacy_watchdog(&legacy_path)? {
                pinned.terminate()?;
                let current = fs::symlink_metadata(&legacy_path)?;
                if current.is_file()
                    && current.dev() == observed.dev()
                    && current.ino() == observed.ino()
                {
                    fs::remove_file(&legacy_path)?;
                } else {
                    return Err(invalid());
                }
            }
            Ok(0)
        }
        _ => Err(invalid()),
    }
}

fn legacy_shell_command(bytes: &[u8]) -> bool {
    let arguments: Vec<_> = bytes.split(|b| *b == 0).collect();
    matches!(arguments.as_slice(), [shell, script, action, end]
        if matches!(*shell, b"/bin/sh" | b"sh" | b"/bin/ash" | b"ash")
        && matches!(*script, b"/etc/init.d/S95nanokvm" | b"/kvmapp/system/init.d/S95nanokvm")
        && matches!(*action, b"start" | b"restart") && end.is_empty())
}

/// Legacy PID text nominates a candidate only. Pin before examining procfs;
/// accept only an orphaned root S95 shell running the system shell executable.
fn legacy_watchdog(path: &Path) -> io::Result<Option<(Pinned, fs::Metadata)>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.raw_os_error() == Some(nix::libc::ELOOP) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
        || meta.len() > 11
    {
        return Ok(None);
    }
    let mut value = String::new();
    file.take(12).read_to_string(&mut value)?;
    let Ok(pid) = value.trim().parse::<i32>() else {
        return Ok(None);
    };
    if pid <= 1 {
        return Ok(None);
    }
    if pid == nix::unistd::getppid().as_raw() {
        return Ok(None);
    }
    let Some(fd) = pidfd(pid)? else {
        return Ok(None);
    };
    if exited(&fd)? {
        return Ok(None);
    }
    let (parent, start_ticks) = match proc_identity(pid, 0) {
        Ok(value) => value,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.kind() == io::ErrorKind::InvalidData =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if parent != 1 {
        return Ok(None);
    }
    let mut command = Vec::new();
    File::open(format!("/proc/{pid}/cmdline"))?
        .take(4097)
        .read_to_end(&mut command)?;
    if command.len() > 4096 || !legacy_shell_command(&command) {
        return Ok(None);
    }
    let shell = fs::metadata("/bin/sh")?;
    let executable = fs::metadata(format!("/proc/{pid}/exe"))?;
    if executable.dev() != shell.dev() || executable.ino() != shell.ino() || exited(&fd)? {
        return Ok(None);
    }
    Ok(Some((
        Pinned {
            fd,
            identity: Identity {
                pid,
                start_ticks,
                boot: boot_id()?,
            },
        },
        meta,
    )))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    pid: i32,
    start_ticks: u64,
    boot: String,
}

struct Pinned {
    fd: OwnedFd,
    identity: Identity,
}

struct Record {
    identity: Identity,
    device: u64,
    inode: u64,
}

struct Store {
    path: PathBuf,
    owner: u32,
    _lock: File,
}

fn private_file(file: &File, owner: u32) -> io::Result<fs::Metadata> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != owner || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
        return Err(invalid());
    }
    Ok(meta)
}

impl Identity {
    fn decode(value: &str) -> io::Result<Self> {
        let fields: Vec<_> = value.split_ascii_whitespace().collect();
        if fields.len() != 4 || fields[0] != "v1" {
            return Err(invalid());
        }
        let pid = fields[1].parse::<i32>().map_err(|_| invalid())?;
        let start_ticks = fields[2].parse::<u64>().map_err(|_| invalid())?;
        let boot = fields[3];
        if pid <= 1
            || start_ticks == 0
            || boot.len() != 36
            || !boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
        {
            return Err(invalid());
        }
        Ok(Self {
            pid,
            start_ticks,
            boot: boot.to_owned(),
        })
    }
}

impl Store {
    fn open(path: &Path, owner: u32) -> io::Result<Self> {
        let parent = path.parent().ok_or_else(invalid)?;
        let meta = fs::symlink_metadata(parent)?;
        if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
            return Err(invalid());
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
            .open(path.with_extension("lock"))?;
        private_file(&lock, owner)?;
        // Parent registration and child admission may arrive together. Give a
        // short observer time to release the lock, without waiting indefinitely
        // behind a stuck operation.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => break,
                Err(Errno::WOULDBLOCK) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(Self {
            path: path.to_owned(),
            owner,
            _lock: lock,
        })
    }

    fn load(&self) -> io::Result<Option<Record>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let meta = private_file(&file, self.owner)?;
        if meta.len() > 128 {
            return Err(invalid());
        }
        let mut value = String::new();
        file.take(129).read_to_string(&mut value)?;
        if value.len() > 128 {
            return Err(invalid());
        }
        Ok(Some(Record {
            identity: Identity::decode(&value)?,
            device: meta.dev(),
            inode: meta.ino(),
        }))
    }

    fn remove(&self, record: &Record) -> io::Result<()> {
        let current = fs::symlink_metadata(&self.path)?;
        if !current.is_file() || current.dev() != record.device || current.ino() != record.inode {
            return Err(invalid());
        }
        fs::remove_file(&self.path)
    }

    fn publish(&self, pinned: &Pinned) -> io::Result<()> {
        if exited(&pinned.fd)? {
            return Err(invalid());
        }
        if let Some(old) = self.load()? {
            if Pinned::from_identity(&old.identity, self.owner)?.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "watchdog is already running",
                ));
            }
            self.remove(&old)?;
        }
        let identity = &pinned.identity;
        let data = format!(
            "v1 {} {} {}\n",
            identity.pid, identity.start_ticks, identity.boot
        );
        super::files::write_atomic(&self.path, data.as_bytes(), 0o600).map_err(io::Error::other)
    }

    fn stop(&self) -> io::Result<()> {
        let Some(record) = self.load()? else {
            return Ok(());
        };
        if let Some(pinned) = Pinned::from_identity(&record.identity, self.owner)? {
            pinned.terminate()?;
        }
        self.remove(&record)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "watchdog identity is not proven",
    )
}

fn boot_id() -> io::Result<String> {
    let mut value = String::new();
    File::open("/proc/sys/kernel/random/boot_id")?
        .take(38)
        .read_to_string(&mut value)?;
    let value = value.trim();
    if value.len() != 36 || !value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(invalid());
    }
    Ok(value.to_owned())
}

fn proc_identity(pid: i32, owner: u32) -> io::Result<(i32, u64)> {
    let file = File::open(format!("/proc/{pid}/stat"))?;
    if file.metadata()?.uid() != owner {
        return Err(invalid());
    }
    let mut value = String::new();
    file.take(4097).read_to_string(&mut value)?;
    if value.len() > 4096 {
        return Err(invalid());
    }
    let (_, fields) = value.rsplit_once(") ").ok_or_else(invalid)?;
    let mut fields = fields.split_whitespace();
    let parent = fields
        .nth(1)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    let start = fields
        .nth(17)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    Ok((parent, start))
}

fn pidfd(pid: i32) -> io::Result<Option<OwnedFd>> {
    if pid <= 1 {
        return Err(invalid());
    }
    match pidfd_open(Pid::from_raw(pid).ok_or_else(invalid)?, PidfdFlags::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::SRCH) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn exited(fd: &OwnedFd) -> io::Result<bool> {
    let mut events = [PollFd::new(fd, PollFlags::IN)];
    let zero = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    Ok(poll(&mut events, Some(&zero))? != 0)
}

impl Pinned {
    /// Registration accepts only a still-live direct child of the invoking shell.
    fn capture_child(pid: i32, parent: i32, owner: u32) -> io::Result<Self> {
        let fd = pidfd(pid)?.ok_or_else(invalid)?;
        let (actual_parent, start_ticks) = proc_identity(pid, owner)?;
        if actual_parent != parent || exited(&fd)? {
            return Err(invalid());
        }
        Ok(Self {
            fd,
            identity: Identity {
                pid,
                start_ticks,
                boot: boot_id()?,
            },
        })
    }

    fn from_identity(identity: &Identity, owner: u32) -> io::Result<Option<Self>> {
        if identity.boot != boot_id()? {
            return Ok(None);
        }
        let Some(fd) = pidfd(identity.pid)? else {
            return Ok(None);
        };
        if exited(&fd)? {
            return Ok(None);
        }
        let current = match proc_identity(identity.pid, owner) {
            Ok(current) => current,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if current.1 != identity.start_ticks || exited(&fd)? {
            return Ok(None);
        }
        Ok(Some(Self {
            fd,
            identity: identity.clone(),
        }))
    }

    fn wait_exit(&self, limit: Duration) -> io::Result<bool> {
        let end = Instant::now() + limit;
        loop {
            if exited(&self.fd)? {
                return Ok(true);
            }
            if Instant::now() >= end {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate(self) -> io::Result<()> {
        for (signal, wait) in [(Signal::TERM, 3), (Signal::KILL, 1)] {
            match pidfd_send_signal(&self.fd, signal) {
                Ok(()) | Err(Errno::SRCH) => {}
                Err(error) => return Err(error.into()),
            }
            if self.wait_exit(Duration::from_secs(wait))? {
                return Ok(());
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "watchdog did not exit",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn child() -> ChildGuard {
        ChildGuard(Command::new("sleep").arg("30").spawn().unwrap())
    }

    #[test]
    fn exact_live_child_can_be_pinned_and_stopped() {
        let mut child = child();
        let owner = nix::unistd::geteuid().as_raw();
        let pinned =
            Pinned::capture_child(child.0.id() as i32, std::process::id() as i32, owner).unwrap();
        let record = pinned.identity.clone();
        drop(pinned);
        Pinned::from_identity(&record, owner)
            .unwrap()
            .unwrap()
            .terminate()
            .unwrap();
        assert!(!child.0.wait().unwrap().success());
        assert!(Pinned::from_identity(&record, owner).unwrap().is_none());
    }

    #[test]
    fn mismatched_boot_start_owner_or_parent_cannot_authorize_signal() {
        let mut child = child();
        let owner = nix::unistd::geteuid().as_raw();
        let pinned =
            Pinned::capture_child(child.0.id() as i32, std::process::id() as i32, owner).unwrap();
        let mut stale = pinned.identity.clone();
        stale.start_ticks += 1;
        assert!(Pinned::from_identity(&stale, owner).unwrap().is_none());
        stale = pinned.identity.clone();
        stale.boot = "previous boot".into();
        assert!(Pinned::from_identity(&stale, owner).unwrap().is_none());
        assert!(Pinned::from_identity(&pinned.identity, owner.wrapping_add(1)).is_err());
        assert!(Pinned::capture_child(child.0.id() as i32, 1, owner).is_err());
        assert!(child.0.try_wait().unwrap().is_none());
    }

    #[test]
    fn special_pid_values_are_never_opened() {
        for pid in [-1, 0, 1] {
            assert!(pidfd(pid).is_err());
        }
    }

    #[test]
    fn legacy_command_recognition_is_exact_not_a_substring_scan() {
        assert!(legacy_shell_command(
            b"/bin/sh\0/etc/init.d/S95nanokvm\0start\0"
        ));
        assert!(legacy_shell_command(
            b"sh\0/kvmapp/system/init.d/S95nanokvm\0restart\0"
        ));
        for command in [
            b"/bin/sh\0/etc/init.d/S95nanokvm\0stop\0".as_slice(),
            b"/bin/sh\0/tmp/S95nanokvm\0start\0",
            b"/bin/sh\0-c\0/etc/init.d/S95nanokvm start\0",
            b"other\0/etc/init.d/S95nanokvm\0start\0",
            b"/bin/sh\0/etc/init.d/S95nanokvm\0start\0extra\0",
            b"/bin/sh\0/etc/init.d/S95nanokvm\0start",
        ] {
            assert!(!legacy_shell_command(command));
        }
    }

    #[test]
    fn brief_observer_lock_does_not_reject_parent_registration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watchdog.pid");
        let owner = nix::unistd::geteuid().as_raw();
        let observer = Store::open(&path, owner).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(observer);
        });
        let parent = Store::open(&path, owner).unwrap();
        release.join().unwrap();
        drop(parent);
    }

    #[test]
    fn private_store_serializes_registration_and_preserves_a_live_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watchdog.pid");
        let owner = nix::unistd::geteuid().as_raw();
        let store = Store::open(&path, owner).unwrap();
        assert!(Store::open(&path, owner).is_err());
        let mut first = child();
        let mut second = child();
        let a =
            Pinned::capture_child(first.0.id() as i32, std::process::id() as i32, owner).unwrap();
        let b =
            Pinned::capture_child(second.0.id() as i32, std::process::id() as i32, owner).unwrap();
        store.publish(&a).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(store.publish(&b).is_err());
        assert_eq!(store.load().unwrap().unwrap().identity, a.identity);
        store.stop().unwrap();
        assert!(!first.0.wait().unwrap().success());
        assert!(second.0.try_wait().unwrap().is_none());
        assert!(!path.exists());
    }

    #[test]
    fn record_metadata_and_replacement_are_not_trusted() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watchdog.pid");
        let owner = nix::unistd::geteuid().as_raw();
        let store = Store::open(&path, owner).unwrap();
        let process = child();
        let pinned =
            Pinned::capture_child(process.0.id() as i32, std::process::id() as i32, owner).unwrap();
        store.publish(&pinned).unwrap();
        let record = store.load().unwrap().unwrap();
        fs::rename(&path, dir.path().join("original")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert!(store.remove(&record).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        assert!(store.load().is_err());
        fs::remove_file(&path).unwrap();
        symlink(dir.path().join("original"), &path).unwrap();
        assert!(store.load().is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(dir.path().join("original"), &path).unwrap();
        assert!(store.load().is_err());
        fs::remove_file(&path).unwrap();
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(store.load().is_err());
        fs::remove_file(&path).unwrap();
        fs::rename(dir.path().join("original"), &path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load().is_err());
    }

    #[test]
    fn malformed_or_oversized_records_do_not_authorize_a_stop() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watchdog.pid");
        let store = Store::open(&path, nix::unistd::geteuid().as_raw()).unwrap();
        for value in [
            String::new(),
            "-1".into(),
            "42".into(),
            "v1 0 1 invalid".into(),
            "x".repeat(129),
        ] {
            fs::write(&path, value).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(store.stop().is_err());
            assert!(path.exists());
        }
    }
}
