//! Fresh-boot enrollment; never infer ownership of legacy native processes.
//! Factory is image-producer input only. Live bootstrap can only arm a reboot.

use super::{Epoch, Error, open, protected};
use rand_core::{OsRng, RngCore};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, mkdirat, openat2, renameat};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};

const DIRECTORY: &str = "native-runtime-boot";
const MAGIC: &[u8; 8] = b"NKBOOT01";
const SCRIPTS: [&str; 4] = ["S02apprecover", "S30eth", "S30wifi", "S95nanokvm"];
const DIGESTS: &[u8; 128] = include_bytes!(concat!(env!("OUT_DIR"), "/native-boot-digests"));

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Factory,
    Armed(Epoch),
    Ready(Epoch),
}

/// Held through script publication or the entire broker/drain lifetime. All
/// descriptors are CLOEXEC. Drop explicitly unlocks fork-before-exec aliases.
pub struct Permit {
    directory: File,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let _ = flock(&self.directory, FlockOperation::Unlock);
    }
}

impl Permit {
    #[cfg(test)]
    pub(crate) fn fixture(parent: &File) -> Self {
        lock(parent, true, false, nix::unistd::geteuid().as_raw()).unwrap()
    }
}

fn parent() -> Result<File, Error> {
    if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
        return Err(Error::Unsafe);
    }
    let root = File::open("/")?;
    protected(&root, 0, false)?;
    let etc = open(&root, "etc", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
    protected(&etc, 0, false)?;
    let parent = open(&etc, "kvm", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
    protected(&parent, 0, false)?;
    Ok(parent)
}

fn lock(parent: &File, create: bool, exclusive: bool, uid: u32) -> Result<Permit, Error> {
    protected(parent, uid, false)?;
    if create {
        match mkdirat(parent, DIRECTORY, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => parent.sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(Error::Io),
        }
    }
    let directory = match open(parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY, true) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(Error::Absent),
        Err(_) => return Err(Error::Io),
    };
    protected(&directory, uid, true)?;
    if directory.metadata()?.dev() != parent.metadata()?.dev() {
        return Err(Error::Unsafe);
    }
    let operation = if exclusive {
        FlockOperation::NonBlockingLockExclusive
    } else {
        FlockOperation::NonBlockingLockShared
    };
    flock(&directory, operation).map_err(|error| {
        if error == rustix::io::Errno::WOULDBLOCK {
            Error::Busy
        } else {
            Error::Io
        }
    })?;
    Ok(Permit { directory })
}

fn regular(parent: &File, name: &str, uid: u32, mode: u32) -> Result<File, Error> {
    let pinned = open(parent, name, OFlags::PATH, true)?;
    let m = pinned.metadata()?;
    if !m.is_file()
        || m.uid() != uid
        || m.gid() != nix::unistd::getegid().as_raw()
        || m.mode() & 0o7777 != mode
        || m.nlink() != 1
        || m.dev() != parent.metadata()?.dev()
    {
        return Err(Error::Unsafe);
    }
    let file = open(parent, name, OFlags::RDONLY | OFlags::NONBLOCK, true)?;
    let observed = file.metadata()?;
    if m.dev() != observed.dev() || m.ino() != observed.ino() {
        return Err(Error::Unsafe);
    }
    Ok(file)
}

fn load(permit: &Permit, uid: u32) -> Result<Option<State>, Error> {
    let mut file = match regular(&permit.directory, "state", uid, 0o600) {
        Ok(file) => file,
        Err(Error::Io) => {
            match rustix::fs::statat(
                &permit.directory,
                "state",
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                _ => return Err(Error::Io),
            }
        }
        Err(error) => return Err(error),
    };
    let mut bytes = [0; 80];
    if file.metadata()?.len() != 80 {
        return Err(Error::Invalid);
    }
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0])? != 0
        || &bytes[..8] != MAGIC
        || bytes[45..48] != [0; 3]
        || bytes[48..] != Sha256::digest(&bytes[..48])[..]
    {
        return Err(Error::Invalid);
    }
    let state = match bytes[44] {
        1 if bytes[8..44] == [0; 36] => State::Factory,
        2 => State::Armed(Epoch::parse(&bytes[8..44])?),
        3 => State::Ready(Epoch::parse(&bytes[8..44])?),
        _ => return Err(Error::Invalid),
    };
    Ok(Some(state))
}

fn record(state: State) -> [u8; 80] {
    let mut bytes = [0; 80];
    bytes[..8].copy_from_slice(MAGIC);
    let (phase, epoch) = match state {
        State::Factory => (1, None),
        State::Armed(epoch) => (2, Some(epoch)),
        State::Ready(epoch) => (3, Some(epoch)),
    };
    bytes[44] = phase;
    if let Some(epoch) = epoch {
        bytes[8..44].copy_from_slice(&epoch.0);
    }
    let hash = Sha256::digest(&bytes[..48]);
    bytes[48..].copy_from_slice(&hash);
    bytes
}

fn publish(permit: &Permit, state: State) -> Result<(), Error> {
    let parent = &permit.directory;
    let mut random = [0; 16];
    OsRng.try_fill_bytes(&mut random).map_err(|_| Error::Io)?;
    let name = format!(".state-next-{:032x}", u128::from_le_bytes(random));
    #[cfg(test)]
    checkpoint("before-create");
    let mut file: File = openat2(
        parent,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
        super::RESOLVE | rustix::fs::ResolveFlags::NO_XDEV,
    )
    .map_err(|_| Error::Io)?
    .into();
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|_| Error::Io)?;
    #[cfg(test)]
    checkpoint("created");
    // Temporary names are evidence only, never read or executed on retry.
    file.write_all(&record(state))?;
    #[cfg(test)]
    checkpoint("written");
    file.sync_all()?;
    #[cfg(test)]
    checkpoint("file-synced");
    renameat(parent, name.as_str(), parent, "state").map_err(|_| Error::Io)?;
    #[cfg(test)]
    checkpoint("renamed");
    parent.sync_all()?;
    #[cfg(test)]
    checkpoint("directory-synced");
    Ok(())
}

fn scripts_at(root: &File, uid: u32, digests: &[u8; 128]) -> Result<(), Error> {
    let etc = open(root, "etc", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
    let init = open(&etc, "init.d", OFlags::RDONLY | OFlags::DIRECTORY, true)?;
    for parent in [root, &etc, &init] {
        protected(parent, uid, false)?;
    }
    for (index, name) in SCRIPTS.iter().enumerate() {
        let mut file = regular(&init, name, uid, 0o755)?;
        let before = file.metadata()?;
        if before.len() == 0 || before.len() > 1024 * 1024 {
            return Err(Error::Invalid);
        }
        let mut hash = Sha256::new();
        let copied = std::io::copy(&mut (&mut file).take(before.len() + 1), &mut hash)?;
        let after = file.metadata()?;
        if copied != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || hash.finalize()[..] != digests[index * 32..(index + 1) * 32]
        {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

/// Main startup only arms this boot before script publication. A ready shared
/// permit permits an ordinary backend restart while a broker owns its scopes.
pub fn prepare() -> Result<Permit, Error> {
    let parent = parent()?;
    let epoch = Epoch::current()?;
    let permit = lock(&parent, true, false, 0)?;
    if load(&permit, 0)? == Some(State::Ready(epoch))
        && scripts_at(&File::open("/")?, 0, DIGESTS).is_ok()
    {
        return Ok(permit);
    }
    drop(permit);
    let permit = lock(&parent, true, true, 0)?;
    // Recheck after reacquiring exclusively. Never promote from helper presence.
    if load(&permit, 0)? == Some(State::Ready(epoch))
        && scripts_at(&File::open("/")?, 0, DIGESTS).is_ok()
    {
        return Ok(permit);
    }
    publish(&permit, State::Armed(epoch))?;
    Ok(permit)
}

/// Fixed early S02 entrypoint. A live legacy transition cannot activate in the
/// same epoch, even after manually invoking S02 with the new scripts installed.
pub fn activate_early() -> Result<(), Error> {
    crate::update::app_slot::boot_gate().map_err(|_| Error::Unsafe)?;
    let parent = parent()?;
    let permit = lock(&parent, false, true, 0)?;
    let epoch = Epoch::current()?;
    scripts_at(&File::open("/")?, 0, DIGESTS)?;
    activate(&permit, epoch, 0)
}

fn activate(permit: &Permit, epoch: Epoch, uid: u32) -> Result<(), Error> {
    match load(permit, uid)? {
        Some(State::Factory) => {}
        Some(State::Armed(prior) | State::Ready(prior)) if prior != epoch => {}
        Some(State::Ready(current)) if current == epoch => return Ok(()),
        _ => return Err(Error::Inactive),
    }
    publish(permit, State::Ready(epoch))
}

pub fn require_ready() -> Result<Permit, Error> {
    let permit = lock(&parent()?, false, false, 0)?;
    if load(&permit, 0)? != Some(State::Ready(Epoch::current()?)) {
        return Err(Error::Inactive);
    }
    scripts_at(&File::open("/")?, 0, DIGESTS)?;
    Ok(permit)
}

#[cfg(test)]
fn checkpoint(name: &str) {
    if std::env::var("NANOKVM_NATIVE_BOOT_STOP").as_deref() == Ok(name) {
        println!("native-boot-state-checkpoint-ready");
        std::io::stdout().flush().unwrap();
        let _ = std::io::stdin().read_exact(&mut [0]);
        panic!("parent must kill the paused fixture");
    }
}

#[cfg(test)]
#[path = "boot_activation_tests.rs"]
mod tests;
