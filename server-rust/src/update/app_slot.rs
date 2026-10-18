//! Fixed-rootfs app-slot journal recovery. The producer/bootstrap and first-start
//! acceptance are not wired yet. Recovery only restores a recorded old slot;
//! neither a checksum nor an arbitrary staging directory authorizes new code.

use super::{operation_lock::ProcessLock, restore_fs};
use rand_core::{OsRng, RngCore};
use rustix::fs::{FlockOperation, Mode, OFlags, RenameFlags, flock, renameat, renameat_with};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
};

const DIRECTORY: &str = "application-slot";
const CURRENT: &str = "current";
const STATE: &str = "state";
const MAGIC: &[u8; 8] = b"NKAPPJ01";
const RECORD_BYTES: usize = 512;
const HASH_OFFSET: usize = 480;
const HASH_DOMAIN: &[u8] = b"NanoKVM app slot journal v1\0";

#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    #[error("application slot storage requires protected rootfs directories")]
    Unsafe,
    #[error("application slot journal or layout is invalid; evidence retained")]
    Invalid,
    #[error("application slot recovery is owned by another operation")]
    Busy,
    #[error("application slot recovery I/O failed; inspect durable state before retry")]
    Io(#[source] io::Error),
}
impl From<io::Error> for SlotError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<rustix::io::Errno> for SlotError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}
type Result<T> = std::result::Result<T, SlotError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Prepared = 1,
    Publishing = 2,
    Published = 3,
    Committed = 4,
    RollingBack = 5,
    RolledBack = 6,
}
impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Publishing => "publishing",
            Self::Published => "published",
            Self::Committed => "committed",
            Self::RollingBack => "rolling-back",
            Self::RolledBack => "rolled-back",
        }
    }
}

/// Diagnostics, not permission to execute an app or proof of runtime health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    NoTransaction,
    Transaction(Phase),
}
impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::NoTransaction => "no-transaction",
            Self::Transaction(phase) => phase.label(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: u64,
    inode: u64,
}
impl Identity {
    fn of(directory: &File, device: u64, uid: u32) -> Result<Self> {
        protected_directory(directory, device, uid, false)?;
        let metadata = directory.metadata()?;
        if metadata.ino() == 0 {
            return Err(SlotError::Unsafe);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Import {
    Signed = 1,
    Manual = 2,
    UnsignedLab = 3,
}

// The hashes retain the issuing install's exact-byte context. They do not
// verify RSA or grant authority on an attacker-writable filesystem. Only the
// fixed protected rootfs store may supply a recovery record.
struct Record {
    phase: Phase,
    import: Import,
    transaction: [u8; 16],
    old: Identity,
    new: Identity,
    archive_sha512: [u8; 64],
    metadata_sha256: [u8; 32],
    signature_sha256: [u8; 32],
    version: String,
}
impl Record {
    fn validate(&self) -> Result<()> {
        if self.transaction == [0; 16]
            || self.old.inode == 0
            || self.new.inode == 0
            || self.old.device != self.new.device
            || self.old == self.new
            || self.archive_sha512 == [0; 64]
            || self.version.is_empty()
            || self.version.len() > 128
        {
            return Err(SlotError::Invalid);
        }
        let mut parts = self.version.split('.');
        if !(0..3).all(|_| {
            parts
                .next()
                .is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        }) || parts.next().is_some()
        {
            return Err(SlotError::Invalid);
        }
        let context = match self.import {
            Import::Signed => self.metadata_sha256 != [0; 32] && self.signature_sha256 != [0; 32],
            Import::Manual => self.metadata_sha256 == [0; 32] && self.signature_sha256 == [0; 32],
            Import::UnsignedLab => {
                self.metadata_sha256 != [0; 32] && self.signature_sha256 == [0; 32]
            }
        };
        if !context {
            return Err(SlotError::Invalid);
        }
        Ok(())
    }

    fn encode(&self) -> Result<[u8; RECORD_BYTES]> {
        self.validate()?;
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = self.phase as u8;
        bytes[9] = self.import as u8;
        bytes[16..32].copy_from_slice(&self.transaction);
        for (offset, value) in [
            (32, self.old.device),
            (40, self.old.inode),
            (48, self.new.device),
            (56, self.new.inode),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[64..128].copy_from_slice(&self.archive_sha512);
        bytes[128..160].copy_from_slice(&self.metadata_sha256);
        bytes[160..192].copy_from_slice(&self.signature_sha256);
        bytes[192..194].copy_from_slice(&(self.version.len() as u16).to_le_bytes());
        bytes[194..194 + self.version.len()].copy_from_slice(self.version.as_bytes());
        let digest = record_hash(&bytes[..HASH_OFFSET]);
        bytes[HASH_OFFSET..].copy_from_slice(&digest);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECORD_BYTES
            || &bytes[..8] != MAGIC
            || bytes[10..16] != [0; 6]
            || record_hash(&bytes[..HASH_OFFSET]) != bytes[HASH_OFFSET..]
        {
            return Err(SlotError::Invalid);
        }
        let phase = match bytes[8] {
            1 => Phase::Prepared,
            2 => Phase::Publishing,
            3 => Phase::Published,
            4 => Phase::Committed,
            5 => Phase::RollingBack,
            6 => Phase::RolledBack,
            _ => return Err(SlotError::Invalid),
        };
        let import = match bytes[9] {
            1 => Import::Signed,
            2 => Import::Manual,
            3 => Import::UnsignedLab,
            _ => return Err(SlotError::Invalid),
        };
        let length = u16::from_le_bytes([bytes[192], bytes[193]]) as usize;
        if length > 128 || bytes[194 + length..HASH_OFFSET].iter().any(|b| *b != 0) {
            return Err(SlotError::Invalid);
        }
        let u64_at = |n| {
            bytes[n..n + 8]
                .try_into()
                .map(u64::from_le_bytes)
                .map_err(|_| SlotError::Invalid)
        };
        let record = Self {
            phase,
            import,
            transaction: bytes[16..32].try_into().map_err(|_| SlotError::Invalid)?,
            old: Identity {
                device: u64_at(32)?,
                inode: u64_at(40)?,
            },
            new: Identity {
                device: u64_at(48)?,
                inode: u64_at(56)?,
            },
            archive_sha512: bytes[64..128].try_into().map_err(|_| SlotError::Invalid)?,
            metadata_sha256: bytes[128..160].try_into().map_err(|_| SlotError::Invalid)?,
            signature_sha256: bytes[160..192].try_into().map_err(|_| SlotError::Invalid)?,
            version: std::str::from_utf8(&bytes[194..194 + length])
                .map_err(|_| SlotError::Invalid)?
                .to_string(),
        };
        record.validate()?;
        Ok(record)
    }
}

fn record_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(HASH_DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

struct Store {
    rootfs: File,
    _lock: StoreLock,
    current: File,
    uid: u32,
    device: u64,
}

struct StoreLock(File);
impl Drop for StoreLock {
    fn drop(&mut self) {
        // This owner never hands work/aliases to children. A concurrent fork's
        // pre-exec FD alias must not prolong an already completed store lease.
        // This does not assert descendant quiescence or unlink the lock inode.
        let _ = flock(&self.0, FlockOperation::Unlock);
    }
}
impl Store {
    fn open(recover: bool) -> Result<Option<Self>> {
        if !nix::unistd::geteuid().is_root() {
            return Err(SlotError::Unsafe);
        }
        let rootfs = restore_fs::open_root(Path::new("/"), true)?;
        let device = rootfs.metadata()?.dev();
        for path in ["/", "/etc", "/etc/kvm"] {
            let parent = restore_fs::open_root(Path::new(path), true)?;
            protected_directory(&parent, device, 0, false)?;
        }
        let parent = restore_fs::open_root(Path::new("/etc/kvm"), true)?;
        let Some(directory) = open_optional(&parent, DIRECTORY)? else {
            return Ok(None);
        };
        Self::at_root(rootfs, directory, 0, recover)
    }

    fn at_root(rootfs: File, directory: File, uid: u32, recover: bool) -> Result<Option<Self>> {
        let device = rootfs.metadata()?.dev();
        protected_directory(&rootfs, device, uid, false)?;
        protected_directory(&directory, device, uid, true)?;
        flock(
            &directory,
            if recover {
                FlockOperation::NonBlockingLockExclusive
            } else {
                FlockOperation::NonBlockingLockShared
            },
        )
        .map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                SlotError::Busy
            } else {
                SlotError::Io(error.into())
            }
        })?;
        let lock = StoreLock(directory);
        let Some(current) = open_optional(&lock.0, CURRENT)? else {
            return Ok(None);
        };
        protected_directory(&current, device, uid, true)?;
        Ok(Some(Self {
            rootfs,
            _lock: lock,
            current,
            uid,
            device,
        }))
    }

    fn record(&self) -> Result<Record> {
        let mut file =
            restore_fs::open_beneath(&self.current, STATE, OFlags::RDONLY | OFlags::NONBLOCK)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.uid
            || metadata.dev() != self.device
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() != RECORD_BYTES as u64
        {
            return Err(SlotError::Unsafe);
        }
        let mut bytes = [0; RECORD_BYTES];
        file.read_exact(&mut bytes)?;
        let mut tail = [0];
        if file.read(&mut tail)? != 0 {
            return Err(SlotError::Invalid);
        }
        let record = Record::decode(&bytes)?;
        if record.old.device != self.device {
            return Err(SlotError::Invalid);
        }
        Ok(record)
    }

    fn layout(&self, record: &Record) -> Result<Layout> {
        let identity = |parent: &File, name| -> Result<Option<Identity>> {
            open_optional(parent, name)?
                .map(|directory| Identity::of(&directory, self.device, self.uid))
                .transpose()
        };
        let layout = Layout {
            live: identity(&self.rootfs, "kvmapp")?,
            new: identity(&self.current, "new")?,
            old: identity(&self.current, "old")?,
        };
        if !matches!(
            (layout.live, layout.new, layout.old),
            (Some(live), Some(new), None) if live == record.old && new == record.new
        ) && !matches!(
            (layout.live, layout.new, layout.old),
            (None, Some(new), Some(old)) if new == record.new && old == record.old
        ) && !matches!(
            (layout.live, layout.new, layout.old),
            (Some(live), None, Some(old)) if live == record.new && old == record.old
        ) {
            return Err(SlotError::Invalid);
        }
        match record.phase {
            Phase::Committed if layout.live != Some(record.new) => Err(SlotError::Invalid),
            Phase::RolledBack if layout.live != Some(record.old) => Err(SlotError::Invalid),
            _ => Ok(layout),
        }
    }

    fn publish(&self, record: &Record) -> Result<()> {
        let bytes = record.encode()?;
        let mut nonce = [0; 16];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| SlotError::Io(io::Error::other("slot journal entropy unavailable")))?;
        let name = format!(".state-next-{:032x}", u128::from_be_bytes(nonce));
        let mut file: File = rustix::fs::openat(
            &self.current,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?
        .into();
        // The inode is fresh and exclusively owned, not an existing object
        // being repaired. Parent umask must not publish an unreadable record.
        rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
        file.write_all(&bytes)?;
        #[cfg(test)]
        checkpoint(&format!("{}:record-written", record.phase.label()));
        file.sync_all()?;
        #[cfg(test)]
        checkpoint(&format!("{}:record-synced", record.phase.label()));
        // A failed/torn temporary is never a recovery input or removed here.
        renameat(&self.current, name.as_str(), &self.current, STATE)?;
        #[cfg(test)]
        checkpoint(&format!("{}:record-renamed", record.phase.label()));
        self.current.sync_all()?;
        #[cfg(test)]
        checkpoint(&format!("{}:record-published", record.phase.label()));
        Ok(())
    }

    fn recover(&self) -> Result<Status> {
        let mut record = self.record()?;
        let layout = self.layout(&record)?;
        if matches!(record.phase, Phase::Committed | Phase::RolledBack) {
            // A prior process may have died after publishing a terminal rename
            // but before syncing its directory. Read-only status is not this
            // durability barrier; recovery must finish it before returning.
            self.sync_parents()?;
            return Ok(Status::Transaction(record.phase));
        }
        if record.phase != Phase::RollingBack {
            record.phase = Phase::RollingBack;
            self.publish(&record)?;
        }
        // Every supported pre-commit state selects the same recorded old inode.
        // Unknown/missing/aliased objects were rejected before the first write.
        if layout.live == Some(record.new) {
            renameat_with(
                &self.rootfs,
                "kvmapp",
                &self.current,
                "new",
                RenameFlags::NOREPLACE,
            )?;
            #[cfg(test)]
            checkpoint("candidate-parked");
            self.sync_parents()?;
            #[cfg(test)]
            checkpoint("candidate-parked-synced");
        }
        if layout.live != Some(record.old) {
            renameat_with(
                &self.current,
                "old",
                &self.rootfs,
                "kvmapp",
                RenameFlags::NOREPLACE,
            )?;
            #[cfg(test)]
            checkpoint("old-restored");
            self.sync_parents()?;
            #[cfg(test)]
            checkpoint("old-restored-synced");
        }
        self.layout(&record)?;
        record.phase = Phase::RolledBack;
        self.publish(&record)?;
        Ok(Status::Transaction(Phase::RolledBack))
    }

    fn sync_parents(&self) -> Result<()> {
        self.rootfs.sync_all()?;
        self.current.sync_all()?;
        self._lock.0.sync_all()?;
        Ok(())
    }
}

struct Layout {
    live: Option<Identity>,
    new: Option<Identity>,
    old: Option<Identity>,
}

fn protected_directory(directory: &File, device: u64, uid: u32, private: bool) -> Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.dev() != device
        || metadata.uid() != uid
        || metadata.mode() & 0o7022 != 0
        || (private && metadata.mode() & 0o7777 != 0o700)
    {
        return Err(SlotError::Unsafe);
    }
    Ok(())
}

fn open_optional(parent: &File, name: &str) -> Result<Option<File>> {
    match restore_fs::open_beneath(parent, name, OFlags::RDONLY | OFlags::DIRECTORY) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Read only the fixed protected store. Missing transaction is diagnostics, not
/// a boot-good decision. Never create, repair, scan or delete a store here.
pub fn status() -> Result<Status> {
    let Some(store) = Store::open(false)? else {
        return Ok(Status::NoTransaction);
    };
    let record = store.record()?;
    store.layout(&record)?;
    Ok(Status::Transaction(record.phase))
}

/// Restore the recorded old slot after an interrupted, uncommitted publication.
/// This cannot publish a new candidate or assert that any app is healthy. Only
/// the future trusted installer may issue records; legacy markers are ignored.
pub fn recover() -> Result<Status> {
    let _admission = ProcessLock::acquire().map_err(|error| match error {
        super::operation_lock::LockError::Busy => SlotError::Busy,
        super::operation_lock::LockError::Unsafe => SlotError::Unsafe,
        super::operation_lock::LockError::Io => {
            SlotError::Io(io::Error::other("update admission unavailable"))
        }
    })?;
    let Some(store) = Store::open(true)? else {
        return Ok(Status::NoTransaction);
    };
    store.recover()
}

#[cfg(test)]
#[path = "app_slot_tests.rs"]
mod tests;

#[cfg(test)]
fn checkpoint(name: &str) {
    if std::env::var("NANOKVM_APP_SLOT_TEST_STOP").as_deref() == Ok(name) {
        println!("slot-checkpoint-ready");
        io::stdout().flush().unwrap();
        let mut byte = [0];
        let _ = io::stdin().read_exact(&mut byte);
        panic!("parent must kill the child before allowing continuation");
    }
}
