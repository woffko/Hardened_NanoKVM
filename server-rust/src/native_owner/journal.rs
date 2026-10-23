//! Native process ownership only, never raw-update/restore authorization.

use crate::update::restore_capsule::ticket::BootId;
use rustix::fs::{
    FlockOperation, Mode, OFlags, PROC_SUPER_MAGIC, ResolveFlags, flock, fstatfs, mkdirat, openat2,
    renameat,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
};

const DIRECTORY: &str = "native-runtime-owner";
const STATE: &str = "state";
const NEXT: &str = ".state.next";
const RECOVERY: &str = "recovery";
const MAGIC: &[u8; 8] = b"NKBROK01";
const BYTES: usize = 80;
const HASH: usize = 48;
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

#[path = "app_recovery_boundary.rs"]
pub(super) mod app_recovery;
#[path = "backend_policy.rs"]
pub(super) mod backend_policy;
#[path = "boot_activation.rs"]
pub mod boot;
#[path = "recovery.rs"]
pub mod recovery;
#[path = "broker_socket.rs"]
pub(super) mod socket;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("another native runtime owner holds the singleton lease")]
    Busy,
    #[error("native runtime journal storage is not protected rootfs")]
    Unsafe,
    #[error("native runtime journal or kernel boot identity is invalid")]
    Invalid,
    #[error("native runtime ownership from this boot is unresolved")]
    Unresolved,
    #[error("native runtime journal publication is ambiguous")]
    Ambiguous,
    #[error("native runtime recovery is fenced and requires explicit completion")]
    Recovery,
    #[error("native runtime recovery requires a different kernel boot epoch")]
    Reboot,
    #[error("native runtime journal directory does not exist")]
    Absent,
    #[error("native runtime requires early enrollment on a fresh kernel boot")]
    Inactive,
    #[error("native runtime journal I/O failed")]
    Io,
}
impl From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Epoch([u8; 36]);

fn pico_boot_tag(epoch: &Epoch) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM Pico job kernel epoch v1\0");
    hash.update(epoch.0);
    let full = hash.finalize();
    let mut boot = [0; 16];
    boot.copy_from_slice(&full[..16]);
    boot
}

/// The current kernel boot's Pico job tag, without a broker lease. Equality
/// with a job's tag means its native scope may still exist in this boot.
pub(super) fn current_pico_boot_tag() -> Result<[u8; 16], Error> {
    Ok(pico_boot_tag(&Epoch::current()?))
}
impl Epoch {
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(bytes).map_err(|_| Error::Invalid)?;
        // Reuse the restore-ticket parser, including non-zero UUID validation.
        BootId::parse(text).map_err(|_| Error::Invalid)?;
        let mut value = [0; 36];
        value.copy_from_slice(bytes);
        value.make_ascii_lowercase();
        Ok(Self(value))
    }

    fn current() -> Result<Self, Error> {
        let proc = kernel_proc()?;
        let mut file = open(
            &proc,
            "sys/kernel/random/boot_id",
            OFlags::RDONLY | OFlags::NONBLOCK,
            false,
        )?;
        if fstatfs(&file).map_err(|_| Error::Io)?.f_type != PROC_SUPER_MAGIC {
            return Err(Error::Unsafe);
        }
        let mut bytes = [0; 37];
        file.read_exact(&mut bytes)?;
        if bytes[36] != b'\n' || file.read(&mut [0])? != 0 {
            return Err(Error::Invalid);
        }
        Self::parse(&bytes[..36])
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Active = 1,
    Closed = 2,
    Maintenance = 3,
    Stopping = 4,
}

pub(super) struct Store {
    directory: File,
    uid: u32,
    device: u64,
    epoch: Epoch,
    active: bool,
    poisoned: bool,
    previous_boot: bool,
    #[cfg(test)]
    fail_at: Option<Step>,
    #[cfg(test)]
    pause_at: Option<(Step, std::path::PathBuf)>,
}

impl Store {
    pub(super) fn endpoint(&self) -> io::Result<socket::Endpoint> {
        socket::Endpoint::bind(&self.directory, self.uid, self.device)
    }

    pub(super) fn install_endpoint(&self) -> io::Result<socket::Endpoint> {
        socket::Endpoint::bind_install(&self.directory, self.uid, self.device)
    }

    pub(super) fn picoclaw_job_endpoint(&self) -> io::Result<socket::Endpoint> {
        socket::Endpoint::bind_picoclaw_job(&self.directory, self.uid, self.device)
    }

    pub(super) fn connect_control() -> io::Result<std::os::unix::net::UnixStream> {
        socket::connect(&Self::control_directory()?, 0)
    }

    pub(super) fn connect_install() -> io::Result<std::os::fd::OwnedFd> {
        socket::connect_install(&Self::control_directory()?, 0)
    }

    pub(super) fn connect_picoclaw_job() -> io::Result<std::os::fd::OwnedFd> {
        socket::connect_picoclaw_job(&Self::control_directory()?, 0)
    }

    pub(super) fn connect_raw_install() -> io::Result<std::os::fd::OwnedFd> {
        socket::connect_raw_install(&Self::control_directory()?, 0)
    }

    fn control_directory() -> io::Result<File> {
        if !nix::unistd::geteuid().is_root() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let root = File::open("/")?;
        let etc = open(&root, "etc", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
        let parent = open(&etc, "kvm", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
        let directory = open(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY, true)?;
        for file in [&root, &etc, &parent] {
            protected(file, 0, false).map_err(|_| io::ErrorKind::PermissionDenied)?;
        }
        protected(&directory, 0, true).map_err(|_| io::ErrorKind::PermissionDenied)?;
        Ok(directory)
    }

    pub(super) fn open() -> Result<Self, Error> {
        Self::lock_root(true)?.admit()
    }

    pub(super) fn lock_root(create: bool) -> Result<Self, Error> {
        if !nix::unistd::geteuid().is_root() {
            return Err(Error::Unsafe);
        }
        let root = File::open("/")?;
        protected(&root, 0, false)?;
        let etc = open(&root, "etc", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
        protected(&etc, 0, false)?;
        let parent = match open(&etc, "kvm", OFlags::RDONLY | OFlags::DIRECTORY, true) {
            Ok(parent) => parent,
            Err(e) if !create && e.kind() == io::ErrorKind::NotFound => return Err(Error::Absent),
            Err(_) => return Err(Error::Io),
        };
        Self::lease(&parent, 0, Epoch::current()?, create)
    }

    fn lease(parent: &File, uid: u32, epoch: Epoch, create: bool) -> Result<Self, Error> {
        protected(parent, uid, false)?;
        if create {
            match mkdirat(parent, DIRECTORY, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) => parent.sync_all()?,
                Err(rustix::io::Errno::EXIST) => {}
                Err(_) => return Err(Error::Io),
            }
        }
        let directory = match open(parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY, true) {
            Ok(directory) => directory,
            Err(e) if !create && e.kind() == io::ErrorKind::NotFound => return Err(Error::Absent),
            Err(_) => return Err(Error::Io),
        };
        protected(&directory, uid, true)?;
        let device = directory.metadata()?.dev();
        if device != parent.metadata()?.dev() {
            return Err(Error::Unsafe);
        }
        flock(&directory, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == rustix::io::Errno::WOULDBLOCK {
                Error::Busy
            } else {
                Error::Io
            }
        })?;
        // Construct the owner immediately: even a failed load must explicitly
        // unlock, not leave a transient pre-exec alias extending this lease.
        Ok(Self {
            directory,
            uid,
            device,
            epoch,
            active: false,
            poisoned: false,
            previous_boot: false,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            pause_at: None,
        })
    }

    pub(super) fn admit(mut self) -> Result<Self, Error> {
        // Any fence object blocks admission before parsing or repairing state.
        // Missing socket/PID is never authority to bypass explicit recovery.
        match rustix::fs::statat(
            &self.directory,
            RECOVERY,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => return Err(Error::Recovery),
            Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err(Error::Io),
        }
        if self.member(NEXT)?.is_some() {
            return Err(Error::Ambiguous);
        }
        if let Some((prior, phase)) = self.read()? {
            if prior == self.epoch && phase != Phase::Closed {
                return Err(Error::Unresolved);
            }
            self.previous_boot = prior != self.epoch;
        }
        Ok(self)
    }

    pub(super) fn previous_boot(&self) -> bool {
        self.previous_boot
    }

    /// Pinned executing image and validated kernel epoch, not a client-supplied
    /// ABI/hash assertion. Hashing is deferred to the retained acceptance worker.
    pub(super) fn pico_submission_context(&self) -> Result<([u8; 16], File), Error> {
        self.ready()?;
        let proc = kernel_proc()?;
        // This one fixed kernel magic link is intentional. No user path or
        // generic symlink-following primitive is exported by this operation.
        let executable: File = rustix::fs::openat(
            &proc,
            "self/exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::Io)?
        .into();
        Ok((self.pico_boot_tag(), executable))
    }

    pub(super) fn pico_boot_tag(&self) -> [u8; 16] {
        pico_boot_tag(&self.epoch)
    }

    #[cfg(test)]
    pub(super) fn fixture(parent: &File, uid: u32, boot: &str) -> Result<Self, Error> {
        Self::lease(parent, uid, Epoch::parse(boot.as_bytes())?, true)?.admit()
    }

    pub(super) fn begin(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Ambiguous);
        }
        if !self.active {
            self.publish(Phase::Active)?;
            self.active = true;
        }
        Ok(())
    }

    pub(super) fn close(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Ambiguous);
        }
        if self.active {
            self.publish(Phase::Closed)?;
            self.active = false;
        }
        Ok(())
    }

    pub(super) fn maintenance(&mut self) -> Result<(), Error> {
        self.ready()?;
        self.publish(Phase::Maintenance)?;
        self.active = true;
        Ok(())
    }

    pub(super) fn ready(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::Ambiguous)
        } else {
            Ok(())
        }
    }

    pub(super) fn resume_active(&mut self) -> Result<(), Error> {
        self.ready()?;
        // Native maintenance may retain a live backend. Never interpose a
        // false Closed receipt while that sibling still owns a process tree.
        self.publish(Phase::Active)?;
        self.active = true;
        Ok(())
    }

    pub(super) fn stopping(&mut self) -> Result<(), Error> {
        self.ready()?;
        self.publish(Phase::Stopping)?;
        self.active = true;
        Ok(())
    }

    /// Read-only durable stop fence, checked AFTER acquiring update exclusion.
    /// No journal flock is taken: the running broker retains that singleton.
    pub(crate) fn check_update_admission() -> Result<(), Error> {
        if !nix::unistd::geteuid().is_root() {
            return Err(Error::Unsafe);
        }
        let root = File::open("/")?;
        let etc = open(&root, "etc", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
        let parent = open(&etc, "kvm", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
        for file in [&root, &etc, &parent] {
            protected(file, 0, false)?;
        }
        let directory = match open(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY, true) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Error::Unsafe),
        };
        protected(&directory, 0, true)?;
        if directory.metadata()?.dev() != parent.metadata()?.dev() {
            return Err(Error::Unsafe);
        }
        Self::check_update_at(&directory, 0, Epoch::current()?)
    }

    fn check_update_at(directory: &File, uid: u32, epoch: Epoch) -> Result<(), Error> {
        for name in [NEXT, RECOVERY] {
            match rustix::fs::statat(directory, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => {}
                _ => return Err(Error::Recovery),
            }
        }
        // Inspect a non-opening O_PATH descriptor first: corrupt journal paths
        // must not open a device or block on a FIFO before rejecting metadata.
        let pinned = match open(directory, STATE, OFlags::PATH, true) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Error::Unsafe),
        };
        let m = pinned.metadata()?;
        if !m.is_file()
            || m.uid() != uid
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.dev() != directory.metadata()?.dev()
            || m.len() != BYTES as u64
        {
            return Err(Error::Unsafe);
        }
        let mut file = open(directory, STATE, OFlags::RDONLY | OFlags::NONBLOCK, true)?;
        let reopened = file.metadata()?;
        if (
            reopened.dev(),
            reopened.ino(),
            reopened.mode(),
            reopened.uid(),
            reopened.nlink(),
            reopened.len(),
        ) != (m.dev(), m.ino(), m.mode(), m.uid(), m.nlink(), m.len())
        {
            return Err(Error::Unsafe);
        }
        let mut bytes = [0; BYTES];
        file.read_exact(&mut bytes)?;
        let (stored, phase) = decode(&bytes)?;
        // Native-only Maintenance is not UpdateEX admission: an issuer may
        // already own UpdateEX when pausing KVM/hwmon. Only Stopping permits a
        // backend Stop and is serialized under the same update exclusion.
        if file.read(&mut [0])? != 0 || (stored == epoch && phase == Phase::Stopping) {
            return Err(Error::Unresolved);
        }
        Ok(())
    }

    fn member(&self, name: &str) -> Result<Option<File>, Error> {
        let file = match open(
            &self.directory,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK,
            true,
        ) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Io),
        };
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != self.uid
            || m.dev() != self.device
            || m.nlink() != 1
            || m.mode() & 0o7777 != 0o600
        {
            return Err(Error::Unsafe);
        }
        Ok(Some(file))
    }

    fn read(&self) -> Result<Option<(Epoch, Phase)>, Error> {
        let Some(mut file) = self.member(STATE)? else {
            return Ok(None);
        };
        if file.metadata()?.len() != BYTES as u64 {
            return Err(Error::Invalid);
        }
        let mut bytes = [0; BYTES];
        file.read_exact(&mut bytes)?;
        if file.read(&mut [0])? != 0 {
            return Err(Error::Invalid);
        }
        Ok(Some(decode(&bytes)?))
    }

    fn publish(&mut self, phase: Phase) -> Result<(), Error> {
        let bytes = record(self.epoch, phase);
        let result = (|| -> Result<(), Error> {
            #[cfg(test)]
            self.inject(Step::BeforeCreate)?;
            let mut file: File = openat2(
                &self.directory,
                NEXT,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
                RESOLVE | ResolveFlags::NO_XDEV,
            )
            .map_err(|_| Error::Io)?
            .into();
            // Exclusively created inode only: restrictive inherited umask must
            // not publish an unreadable native fence. Existing state is never
            // chmod-repaired or selected as a temporary fallback.
            rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|_| Error::Io)?;
            #[cfg(test)]
            self.inject(Step::Created)?;
            let m = file.metadata()?;
            if !m.is_file()
                || m.uid() != self.uid
                || m.dev() != self.device
                || m.nlink() != 1
                || m.mode() & 0o7777 != 0o600
            {
                return Err(Error::Unsafe);
            }
            file.write_all(&bytes)?;
            #[cfg(test)]
            self.inject(Step::Written)?;
            file.sync_all()?;
            #[cfg(test)]
            self.inject(Step::FileSynced)?;
            renameat(&self.directory, NEXT, &self.directory, STATE).map_err(|_| Error::Io)?;
            #[cfg(test)]
            self.inject(Step::Renamed)?;
            self.directory.sync_all()?;
            #[cfg(test)]
            self.inject(Step::DirectorySynced)?;
            Ok(())
        })();
        if result.is_err() {
            // Preserve canonical and temporary evidence; never retry blindly or
            // erase an unresolved launch intent on Drop/error.
            self.poisoned = true;
            return Err(Error::Ambiguous);
        }
        Ok(())
    }

    #[cfg(test)]
    fn inject(&self, step: Step) -> Result<(), Error> {
        if let Some((pause, ready)) = &self.pause_at
            && *pause == step
        {
            std::fs::write(ready, b"fixture")?;
            std::thread::sleep(std::time::Duration::from_secs(20));
        }
        if self.fail_at == Some(step) {
            Err(Error::Io)
        } else {
            Ok(())
        }
    }
}

fn record(epoch: Epoch, phase: Phase) -> [u8; BYTES] {
    let mut bytes = [0; BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..44].copy_from_slice(&epoch.0);
    bytes[44] = phase as u8;
    let hash = Sha256::digest(&bytes[..HASH]);
    bytes[HASH..].copy_from_slice(&hash);
    bytes
}

fn decode(bytes: &[u8; BYTES]) -> Result<(Epoch, Phase), Error> {
    if &bytes[..8] != MAGIC
        || bytes[45..HASH] != [0; 3]
        || bytes[HASH..] != Sha256::digest(&bytes[..HASH])[..]
    {
        return Err(Error::Invalid);
    }
    let phase = match bytes[44] {
        1 => Phase::Active,
        2 => Phase::Closed,
        3 => Phase::Maintenance,
        4 => Phase::Stopping,
        _ => return Err(Error::Invalid),
    };
    Ok((Epoch::parse(&bytes[8..44])?, phase))
}

fn kernel_proc() -> Result<File, Error> {
    let root = File::open("/")?;
    let proc = open(&root, "proc", OFlags::RDONLY | OFlags::DIRECTORY, false)?;
    if fstatfs(&proc).map_err(|_| Error::Io)?.f_type != PROC_SUPER_MAGIC {
        return Err(Error::Unsafe);
    }
    Ok(proc)
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = flock(&self.directory, FlockOperation::Unlock);
        // Never unlink state/temporary or the singleton directory.
    }
}

fn protected(file: &File, uid: u32, exact: bool) -> Result<(), Error> {
    let m = file.metadata()?;
    if !m.is_dir()
        || m.uid() != uid
        || m.mode() & 0o7022 != 0
        || (exact && m.mode() & 0o7777 != 0o700)
    {
        return Err(Error::Unsafe);
    }
    Ok(())
}

fn open(parent: &File, name: &str, flags: OFlags, same_mount: bool) -> io::Result<File> {
    Ok(openat2(
        parent,
        name,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        if same_mount {
            RESOLVE | ResolveFlags::NO_XDEV
        } else {
            RESOLVE
        },
    )?
    .into())
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    BeforeCreate,
    Created,
    Written,
    FileSynced,
    Renamed,
    DirectorySynced,
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
