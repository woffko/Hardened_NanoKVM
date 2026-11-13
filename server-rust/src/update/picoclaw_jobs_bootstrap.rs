//! Explicit image-factory enrollment, never initialization from absence.
//! This creates only the empty store; it cannot settle an accepted operation.
use super::*;
use crate::update::{operation_lock::ProcessLock, state_writers::ConfigPermit};
use rand_core::{OsRng, RngCore};
use rustix::fs::{Mode, RenameFlags, fchmod, mkdirat, openat, renameat_with};
use std::io::Write;

const ANCHOR: &str = "picoclaw-enrollment";
const NEXT: &str = ".picoclaw-enrollment.next";
const SIZE: usize = 96;
const MAGIC: &[u8; 8] = b"NKPENR01";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Anchor {
    Factory,
    Pending([u8; 16]),
    Ready([u8; 16]),
}

fn anchor_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM Pico enrollment v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

impl Anchor {
    fn encode(self) -> [u8; SIZE] {
        let mut bytes = [0; SIZE];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = match self {
            Self::Factory => 1,
            Self::Pending(epoch) => {
                bytes[16..32].copy_from_slice(&epoch);
                2
            }
            Self::Ready(epoch) => {
                bytes[16..32].copy_from_slice(&epoch);
                3
            }
        };
        let hash = anchor_digest(&bytes[..64]);
        bytes[64..].copy_from_slice(&hash);
        bytes
    }

    fn decode(bytes: &[u8; SIZE]) -> Result<Self> {
        if &bytes[..8] != MAGIC
            || bytes[9..16] != [0; 7]
            || bytes[32..64] != [0; 32]
            || anchor_digest(&bytes[..64]) != bytes[64..]
        {
            return Err(invalid());
        }
        let epoch: [u8; 16] = bytes[16..32].try_into().map_err(|_| invalid())?;
        match bytes[8] {
            1 if epoch == [0; 16] => Ok(Self::Factory),
            2 if epoch != [0; 16] => Ok(Self::Pending(epoch)),
            3 if epoch != [0; 16] => Ok(Self::Ready(epoch)),
            _ => Err(invalid()),
        }
    }
}

pub(super) fn read_member<const N: usize>(
    parent: &File,
    name: &str,
    uid: u32,
) -> Result<Option<(Zeroizing<[u8; N]>, Revision)>> {
    let pinned = match restore_fs::open_beneath(parent, name, OFlags::PATH) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let m = pinned.metadata()?;
    if !m.is_file()
        || m.uid() != uid
        || m.dev() != parent.metadata()?.dev()
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
        || m.len() != N as u64
    {
        return Err(invalid());
    }
    let before = Revision::from(&m);
    let mut file = restore_fs::open_beneath(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
    if Revision::from(&file.metadata()?) != before {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new([0; N]);
    file.read_exact(bytes.as_mut())?;
    if file.read(&mut [0])? != 0
        || Revision::from(&file.metadata()?) != before
        || Revision::from(&restore_fs::open_beneath(parent, name, OFlags::PATH)?.metadata()?)
            != before
    {
        return Err(invalid());
    }
    Ok(Some((bytes, before)))
}

pub(super) fn read_anchor(parent: &File, uid: u32) -> Result<Option<(Anchor, Revision)>> {
    read_member(parent, ANCHOR, uid)?
        .map(|(bytes, revision)| Anchor::decode(&bytes).map(|anchor| (anchor, revision)))
        .transpose()
}

pub(super) fn check_next_absent(parent: &File) -> Result<()> {
    match restore_fs::open_beneath(parent, NEXT, OFlags::PATH) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(fenced()),
    }
}

fn publish_anchor(parent: &File, uid: u32, before: (Anchor, Revision), next: Anchor) -> Result<()> {
    let mut file: File = openat(
        parent,
        NEXT,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(std::io::Error::from)?
    .into();
    fchmod(&file, Mode::from_raw_mode(0o600)).map_err(std::io::Error::from)?;
    file.write_all(&next.encode())?;
    file.sync_all()?;
    #[cfg(test)]
    checkpoint(if matches!(next, Anchor::Pending(_)) {
        "pending-staged"
    } else {
        "ready-staged"
    });
    let (bytes, revision) = read_member::<SIZE>(parent, NEXT, uid)?.ok_or_else(invalid)?;
    if bytes.as_slice() != next.encode()
        || revision != Revision::from(&file.metadata()?)
        || read_anchor(parent, uid)? != Some(before)
    {
        return Err(invalid());
    }
    renameat_with(parent, NEXT, parent, ANCHOR, RenameFlags::empty())
        .map_err(std::io::Error::from)?;
    parent.sync_all()?;
    #[cfg(test)]
    checkpoint(if matches!(next, Anchor::Pending(_)) {
        "pending-published"
    } else {
        "ready-published"
    });
    Ok(())
}

pub(crate) fn prepare(_configuration: &ConfigPermit, _update: &ProcessLock) -> Result<()> {
    let parent = Directory::open(Path::new("/etc/kvm"), false)?;
    prepare_at(&parent.file, 0)
}

#[cfg(test)]
pub(crate) fn prepare_fixture(parent: &File) -> Result<()> {
    prepare_at(parent, nix::unistd::geteuid().as_raw())
}

struct BootstrapLease {
    directory: File,
}

impl BootstrapLease {
    fn exclusive(directory: File) -> Result<Self> {
        flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(std::io::Error::from)?;
        Ok(Self { directory })
    }
}

impl Drop for BootstrapLease {
    fn drop(&mut self) {
        // A fork child can retain the open description until exec. Bootstrap
        // transfers no authority through this FD: unlock this owner's lease
        // before the normal read-side fence reopens the same directory.
        let _ = flock(&self.directory, FlockOperation::Unlock);
    }
}

fn prepare_at(parent: &File, uid: u32) -> Result<()> {
    let m = parent.metadata()?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o7022 != 0 {
        return Err(invalid());
    }
    check_next_absent(parent)?;
    let Some(mut observed) = read_anchor(parent, uid)? else {
        // No factory input: ordinary legacy validation only, never mkdir/reset.
        return check_parent(parent, uid);
    };
    if matches!(observed.0, Anchor::Ready(_)) {
        check_parent(parent, uid)?;
        // A prior Ready rename may have returned unknown directory-sync status.
        restore_fs::open_beneath(parent, ANCHOR, OFlags::RDONLY)?.sync_all()?;
        parent.sync_all()?;
        return Ok(());
    }
    if observed.0 == Anchor::Factory {
        match restore_fs::open_beneath(parent, DIRECTORY, OFlags::PATH) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(invalid()),
        }
        let mut epoch = [0; 16];
        OsRng.try_fill_bytes(&mut epoch).map_err(|_| invalid())?;
        if epoch == [0; 16] {
            return Err(invalid());
        }
        publish_anchor(parent, uid, observed, Anchor::Pending(epoch))?;
        observed = read_anchor(parent, uid)?.ok_or_else(invalid)?;
    }
    let Anchor::Pending(epoch) = observed.0 else {
        return Err(invalid());
    };
    let empty = Snapshot {
        epoch,
        sequence: 0,
        active: None,
        receipts: [None; RETAINED],
    }
    .encode()?;
    match mkdirat(parent, DIRECTORY, Mode::from_raw_mode(0o700)) {
        Ok(()) => parent.sync_all()?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(std::io::Error::from(error).into()),
    }
    let directory =
        restore_fs::open_beneath(parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let m = directory.metadata()?;
    if m.uid() != uid || m.dev() != parent.metadata()?.dev() || m.mode() & 0o7777 != 0o700 {
        return Err(invalid());
    }
    let lease = BootstrapLease::exclusive(directory)?;
    let directory = &lease.directory;
    let identity = (m.dev(), m.ino());
    for entry in rustix::fs::Dir::read_from(directory).map_err(std::io::Error::from)? {
        let entry = entry.map_err(std::io::Error::from)?;
        match entry.file_name().to_bytes() {
            b"." | b".." | b"state" => {}
            _ => return Err(fenced()),
        }
    }
    if let Some((bytes, _)) = read_member::<BYTES>(directory, STATE, uid)? {
        if bytes.as_slice() != empty.as_slice() {
            return Err(invalid());
        }
    } else {
        let mut state: File = openat(
            directory,
            STATE,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )
        .map_err(std::io::Error::from)?
        .into();
        fchmod(&state, Mode::from_raw_mode(0o600)).map_err(std::io::Error::from)?;
        state.write_all(empty.as_slice())?;
        #[cfg(test)]
        checkpoint("state-written");
        state.sync_all()?;
    }
    restore_fs::open_beneath(directory, STATE, OFlags::RDONLY)?.sync_all()?;
    directory.sync_all()?;
    // Bind the exact name and empty bytes again before authorizing the store.
    let named = restore_fs::open_beneath(parent, DIRECTORY, OFlags::PATH)?.metadata()?;
    let (bytes, _) = read_member::<BYTES>(directory, STATE, uid)?.ok_or_else(invalid)?;
    if (named.dev(), named.ino()) != identity || bytes.as_slice() != empty.as_slice() {
        return Err(invalid());
    }
    #[cfg(test)]
    checkpoint("state-durable");
    publish_anchor(parent, uid, observed, Anchor::Ready(epoch))?;
    drop(lease);
    check_parent(parent, uid)
}

#[cfg(test)]
fn checkpoint(point: &str) {
    if std::env::var("NANOKVM_PICO_ENROLL_POINT").as_deref() == Ok(point) {
        println!("pico-enrollment-checkpoint-ready");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
}

#[cfg(test)]
#[path = "picoclaw_jobs_bootstrap_tests.rs"]
mod tests;
