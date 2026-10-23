//! Cooperative one-boot admission, NOT a durable install/restore ticket.
//! Never unlink the lock inode. Rootfs replacement/raw child handoff needs the
//! retained transaction runtime; this front-end lease does not implement it.

use super::restore_fs;
use rustix::fs::{FlockOperation, Mode, OFlags, flock, mkdirat};
use std::{fs::File, io, os::unix::fs::MetadataExt, path::Path};

const DIRECTORY: &str = "update-operation";

#[derive(Clone, Copy)]
pub(crate) enum Domain {
    Update,
    WriterAdmission,
    WriterActivity,
    Account,
    Configuration,
    Firewall,
}
impl Domain {
    pub(super) fn directory(self) -> &'static str {
        match self {
            Self::Update => DIRECTORY,
            Self::WriterAdmission => "state-writer-admission",
            Self::WriterActivity => "state-writer-activity",
            Self::Account => "account-operation",
            Self::Configuration => "configuration-operation",
            Self::Firewall => "firewall-operation",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LockError {
    #[error("update admission is owned by another process")]
    Busy,
    #[error("update admission requires protected rootfs storage")]
    Unsafe,
    #[error("update admission storage I/O failed")]
    Io,
}
impl From<io::Error> for LockError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

pub(crate) struct ProcessLock {
    directory: File,
    unlock_on_drop: bool,
}
impl ProcessLock {
    pub fn acquire() -> Result<Self, LockError> {
        Self::for_domain(Domain::Update, false)
    }

    pub(super) fn for_domain(domain: Domain, shared: bool) -> Result<Self, LockError> {
        if !nix::unistd::geteuid().is_root() {
            return Err(LockError::Unsafe);
        }
        // Fixed build-owned path, never a configurable cache or a p3 marker.
        // Reject every symlink/bind-mount component, including same-device binds.
        for path in ["/", "/etc"] {
            let parent = restore_fs::open_root(Path::new(path), true)?;
            check_parent(&parent, 0)?;
        }
        let parent = restore_fs::open_root(Path::new("/etc/kvm"), true)?;
        Self::at_parent(&parent, 0, domain, shared)
    }

    #[cfg(test)]
    pub(crate) fn from_parent(parent: &File, uid: u32) -> Result<Self, LockError> {
        Self::at_parent(parent, uid, Domain::Update, false)
    }

    pub(crate) fn at_parent(
        parent: &File,
        uid: u32,
        domain: Domain,
        shared: bool,
    ) -> Result<Self, LockError> {
        check_parent(parent, uid)?;
        let device = parent.metadata()?.dev();
        let name = domain.directory();
        match mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => parent.sync_all()?,
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(LockError::Io),
        }
        let directory = restore_fs::open_beneath(parent, name, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != uid
            || metadata.dev() != device
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(LockError::Unsafe);
        }
        let operation = if shared {
            FlockOperation::NonBlockingLockShared
        } else {
            FlockOperation::NonBlockingLockExclusive
        };
        flock(&directory, operation).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                LockError::Busy
            } else {
                LockError::Io
            }
        })?;
        Ok(Self {
            directory,
            unlock_on_drop: true,
        })
    }

    /// Switch to last-open-description release BEFORE exporting any alias.
    /// Once handed off, even an ambiguous failed send must never explicitly
    /// unlock the receiver's shared description. The original still owns EX.
    pub(super) fn transfer_alias(&mut self) -> Result<File, LockError> {
        if !self.unlock_on_drop {
            return Err(LockError::Unsafe);
        }
        let alias = self.directory.try_clone()?;
        rustix::io::fcntl_setfd(&alias, rustix::io::FdFlags::CLOEXEC).map_err(|_| LockError::Io)?;
        self.unlock_on_drop = false;
        Ok(alias)
    }
}
impl Drop for ProcessLock {
    fn drop(&mut self) {
        // A pre-exec child may briefly inherit the open file description.
        // Explicit unlock does not leave admission waiting for that alias.
        if self.unlock_on_drop {
            let _ = flock(&self.directory, FlockOperation::Unlock);
        }
        // Deliberately no unlink/rmdir: all later contenders use this inode.
    }
}

fn check_parent(parent: &File, uid: u32) -> Result<(), LockError> {
    let metadata = parent.metadata()?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7022 != 0 {
        return Err(LockError::Unsafe);
    }
    Ok(())
}

#[cfg(test)]
#[path = "operation_lock_tests.rs"]
mod tests;
