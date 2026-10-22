//! Admission reader/fence and explicit image-factory empty-store bootstrap.
//! No query initializes/repairs state or supplies native closure authority.
//! The only recovery is the typed early-boot settlement of a job a previous
//! kernel boot left behind; same-boot jobs stay with their native owner.
use super::{Directory, Revision};
use crate::{
    AppError, Result,
    update::{operation_lock::ProcessLock, restore_fs, state_writers::ConfigPermit},
};
use rustix::fs::{FlockOperation, OFlags, flock};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path};
use zeroize::Zeroizing;

#[path = "picoclaw_jobs_bootstrap.rs"]
mod bootstrap;
#[cfg(test)]
pub(crate) use bootstrap::prepare_fixture;

#[path = "picoclaw_jobs_submit.rs"]
mod submit;
#[cfg(all(test, feature = "sandbox-test-fixture"))]
pub(crate) use submit::WorkFixture;
#[cfg(all(test, feature = "sandbox-test-fixture"))]
pub(crate) use submit::tests::setup as prepare_factory_fixture;
pub use submit::{Acceptance, Cursor, JobId, Profile, Request, Submission};
pub(crate) use submit::{RuntimeResult, TransitionStatus};

const DIRECTORY: &str = "picoclaw-operations";
const STATE: &str = "state";
const MAGIC: &[u8; 8] = b"NKPJOB01";
const HEADER: usize = 128;
const RECORD: usize = 256;
const RETAINED: usize = 32;
const PREFIX: usize = HEADER + (RETAINED + 1) * RECORD;
const BYTES: usize = PREFIX + 32;

fn invalid() -> AppError {
    AppError::Config("invalid or unsafe Pico mutation journal".into())
}

#[cfg(test)]
thread_local! {
    /// Stands in for a later kernel boot in recovery tests.
    pub(crate) static TEST_BOOT: std::cell::Cell<Option<[u8; 16]>> =
        const { std::cell::Cell::new(None) };
}

/// The current kernel boot's job tag, as the native broker computes it.
fn current_boot() -> Result<[u8; 16]> {
    #[cfg(test)]
    if let Some(boot) = TEST_BOOT.with(std::cell::Cell::get) {
        return Ok(boot);
    }
    crate::native_owner::broker::current_pico_boot_tag()
        .map_err(|_| AppError::Internal("kernel boot identity unavailable".into()))
}

/// Early-boot entry under Update and Config: settle a job that a previous
/// kernel boot left behind, then factory enrollment and the normal fence.
pub(crate) fn prepare(configuration: &ConfigPermit, update: &ProcessLock) -> Result<()> {
    submit::recover_prior_boot(configuration)?;
    bootstrap::prepare(configuration, update)
}

fn fenced() -> AppError {
    AppError::Conflict("Pico mutation requires checked settlement".into())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM Pico mutation journal v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    Onboard = 1,
    Model = 2,
    Startup = 3,
    Profile = 4,
    Install = 5,
    Remove = 6,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Phase {
    Accepted = 1,
    Stopping = 2,
    Closed = 3,
    Applying = 4,
    Committed = 5,
    Retiring = 6,
    Activating = 7,
    Completed = 8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Outcome {
    Pending = 0,
    Changed = 1,
    Noop = 2,
    Failed = 3,
    Cancelled = 4,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Runtime {
    Pending = 0,
    Unchanged = 1,
    NotRequested = 2,
    Resumed = 3,
    ResumeFailed = 4,
    Removed = 5,
    Suppressed = 6,
}

// Private metadata can include credential-derived request/source digests. Do
// not derive Debug/Serialize or expose this as the public job status frame.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Record {
    sequence: u64,
    nonce: [u8; 16],
    boot: [u8; 16],
    home: [u8; 32],
    support: [u8; 32],
    request: [u8; 32],
    source: [u8; 32],
    kind: Kind,
    phase: Phase,
    was_running: bool,
    resume_allowed: bool,
    uncertain: bool,
    outcome: Outcome,
    runtime: Runtime,
}

impl Record {
    fn validate(&self) -> Result<()> {
        if self.sequence == 0
            || self.nonce == [0; 16]
            || self.boot == [0; 16]
            || [self.home, self.support, self.request, self.source].contains(&[0; 32])
            || (self.phase == Phase::Stopping && !self.was_running)
            || (self.resume_allowed && (!self.was_running || self.kind == Kind::Remove))
        {
            return Err(invalid());
        }
        if self.phase != Phase::Completed {
            return if self.outcome == Outcome::Pending && self.runtime == Runtime::Pending {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if self.uncertain {
            return Err(invalid());
        }
        let valid = match self.outcome {
            Outcome::Pending => false,
            Outcome::Noop => {
                (self.runtime == Runtime::Unchanged && (!self.was_running || self.resume_allowed))
                    || (self.was_running
                        && !self.resume_allowed
                        && self.runtime == Runtime::Suppressed)
            }
            Outcome::Failed | Outcome::Cancelled => self.runtime == Runtime::NotRequested,
            Outcome::Changed if self.kind == Kind::Remove => self.runtime == Runtime::Removed,
            Outcome::Changed if self.resume_allowed => {
                matches!(self.runtime, Runtime::Resumed | Runtime::ResumeFailed)
            }
            Outcome::Changed if self.was_running => self.runtime == Runtime::Suppressed,
            Outcome::Changed => self.runtime == Runtime::NotRequested,
        };
        if valid { Ok(()) } else { Err(invalid()) }
    }

    fn encode(&self) -> Result<[u8; RECORD]> {
        self.validate()?;
        let mut bytes = [0; RECORD];
        bytes[..8].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[8..24].copy_from_slice(&self.nonce);
        bytes[24..40].copy_from_slice(&self.boot);
        for (offset, field) in [
            (40, self.home),
            (72, self.support),
            (104, self.request),
            (136, self.source),
        ] {
            bytes[offset..offset + 32].copy_from_slice(&field);
        }
        bytes[168] = self.kind as u8;
        bytes[169] = self.phase as u8;
        bytes[170] = u8::from(self.was_running);
        bytes[171] = u8::from(self.uncertain);
        bytes[172] = self.outcome as u8;
        bytes[173] = self.runtime as u8;
        bytes[174] = u8::from(self.resume_allowed);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RECORD || bytes[175..].iter().any(|byte| *byte != 0) {
            return Err(invalid());
        }
        let value = Self {
            sequence: u64::from_le_bytes(bytes[..8].try_into().map_err(|_| invalid())?),
            nonce: bytes[8..24].try_into().map_err(|_| invalid())?,
            boot: bytes[24..40].try_into().map_err(|_| invalid())?,
            home: bytes[40..72].try_into().map_err(|_| invalid())?,
            support: bytes[72..104].try_into().map_err(|_| invalid())?,
            request: bytes[104..136].try_into().map_err(|_| invalid())?,
            source: bytes[136..168].try_into().map_err(|_| invalid())?,
            kind: match bytes[168] {
                1 => Kind::Onboard,
                2 => Kind::Model,
                3 => Kind::Startup,
                4 => Kind::Profile,
                5 => Kind::Install,
                6 => Kind::Remove,
                _ => return Err(invalid()),
            },
            phase: match bytes[169] {
                1 => Phase::Accepted,
                2 => Phase::Stopping,
                3 => Phase::Closed,
                4 => Phase::Applying,
                5 => Phase::Committed,
                6 => Phase::Retiring,
                7 => Phase::Activating,
                8 => Phase::Completed,
                _ => return Err(invalid()),
            },
            was_running: match bytes[170] {
                0 => false,
                1 => true,
                _ => return Err(invalid()),
            },
            uncertain: match bytes[171] {
                0 => false,
                1 => true,
                _ => return Err(invalid()),
            },
            outcome: match bytes[172] {
                0 => Outcome::Pending,
                1 => Outcome::Changed,
                2 => Outcome::Noop,
                3 => Outcome::Failed,
                4 => Outcome::Cancelled,
                _ => return Err(invalid()),
            },
            runtime: match bytes[173] {
                0 => Runtime::Pending,
                1 => Runtime::Unchanged,
                2 => Runtime::NotRequested,
                3 => Runtime::Resumed,
                4 => Runtime::ResumeFailed,
                5 => Runtime::Removed,
                6 => Runtime::Suppressed,
                _ => return Err(invalid()),
            },
            resume_allowed: match bytes[174] {
                0 => false,
                1 => true,
                _ => return Err(invalid()),
            },
        };
        value.validate()?;
        Ok(value)
    }
}

struct Snapshot {
    epoch: [u8; 16],
    sequence: u64,
    active: Option<Record>,
    receipts: [Option<Record>; RETAINED],
}

impl Snapshot {
    fn validate(&self) -> Result<()> {
        if self.epoch == [0; 16] {
            return Err(invalid());
        }
        if let Some(active) = &self.active {
            active.validate()?;
            if active.sequence != self.sequence || active.phase == Phase::Completed {
                return Err(invalid());
            }
        }
        let end = self
            .sequence
            .checked_sub(u64::from(self.active.is_some()))
            .ok_or_else(invalid)?;
        let count = end.min(RETAINED as u64) as usize;
        if self.receipts.iter().flatten().count() != count {
            return Err(invalid());
        }
        for (slot, receipt) in self.receipts.iter().enumerate() {
            if let Some(receipt) = receipt {
                receipt.validate()?;
                if receipt.phase != Phase::Completed
                    || receipt.sequence > end
                    || end - receipt.sequence >= RETAINED as u64
                    || (receipt.sequence - 1) % RETAINED as u64 != slot as u64
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }

    fn encode(&self) -> Result<Zeroizing<[u8; BYTES]>> {
        self.validate()?;
        let mut bytes = Zeroizing::new([0; BYTES]);
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.epoch);
        bytes[24..32].copy_from_slice(&self.sequence.to_le_bytes());
        for (slot, record) in std::iter::once(self.active.as_ref())
            .chain(self.receipts.iter().map(Option::as_ref))
            .enumerate()
        {
            if let Some(record) = record {
                let offset = HEADER + slot * RECORD;
                bytes[offset..offset + RECORD].copy_from_slice(&record.encode()?);
            }
        }
        let hash = digest(&bytes[..PREFIX]);
        bytes[PREFIX..].copy_from_slice(&hash);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BYTES
            || &bytes[..8] != MAGIC
            || bytes[32..HEADER].iter().any(|byte| *byte != 0)
            || digest(&bytes[..PREFIX]) != bytes[PREFIX..]
        {
            return Err(invalid());
        }
        let read = |slot| -> Result<Option<Record>> {
            let offset = HEADER + slot * RECORD;
            let record = &bytes[offset..offset + RECORD];
            if record.iter().all(|byte| *byte == 0) {
                Ok(None)
            } else {
                Record::decode(record).map(Some)
            }
        };
        let mut receipts = [None; RETAINED];
        for (slot, value) in receipts.iter_mut().enumerate() {
            *value = read(slot + 1)?;
        }
        let value = Self {
            epoch: bytes[8..24].try_into().map_err(|_| invalid())?,
            sequence: u64::from_le_bytes(bytes[24..32].try_into().map_err(|_| invalid())?),
            active: read(0)?,
            receipts,
        };
        // One canonical encoding: no hidden fields/trailing entries survive.
        if value.encode()?.as_slice() != bytes {
            return Err(invalid());
        }
        Ok(value)
    }
}

struct ReadLease {
    directory: File,
}

impl ReadLease {
    fn acquire(directory: File) -> Result<Self> {
        flock(&directory, FlockOperation::NonBlockingLockShared).map_err(|error| {
            if error == rustix::io::Errno::WOULDBLOCK {
                fenced()
            } else {
                std::io::Error::from(error).into()
            }
        })?;
        Ok(Self { directory })
    }
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        // This read-side observation never transfers its lease. A fork alias
        // must not keep SH held when the admitted producer next opens EX.
        let _ = flock(&self.directory, FlockOperation::Unlock);
    }
}

fn check_parent(parent: &File, uid: u32) -> Result<()> {
    // Callers retain Config serial or WriterActivity EX across this check.
    // A future producer/settler MUST acquire Config before directory EX; the
    // short shared directory lock alone is not a lifetime mutation barrier.
    let metadata = parent.metadata()?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o7022 != 0 {
        return Err(invalid());
    }
    bootstrap::check_next_absent(parent)?;
    let enrollment = bootstrap::read_anchor(parent, uid)?;
    if enrollment
        .as_ref()
        .is_some_and(|(anchor, _)| !matches!(anchor, bootstrap::Anchor::Ready(_)))
    {
        return Err(fenced());
    }
    let directory = match restore_fs::open_beneath(
        parent,
        DIRECTORY,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && enrollment.is_none() => {
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    // No shipped version has an unanchored store. Preserve/refuse such data;
    // it cannot downgrade a lost enrollment to the legacy absence exception.
    if enrollment.is_none() {
        return Err(invalid());
    }
    let m = directory.metadata()?;
    if m.uid() != uid || m.dev() != metadata.dev() || m.mode() & 0o7777 != 0o700 {
        return Err(invalid());
    }
    let directory_before = Revision::from(&m);
    let lease = ReadLease::acquire(directory)?;
    let directory = &lease.directory;
    let mut found = false;
    for entry in rustix::fs::Dir::read_from(directory).map_err(std::io::Error::from)? {
        let entry = entry.map_err(std::io::Error::from)?;
        match entry.file_name().to_bytes() {
            b"." | b".." => {}
            b"state" if !found => found = true,
            // Pending next/payload/unknown evidence fences, never adopted or GC'd.
            _ => return Err(fenced()),
        }
    }
    if !found {
        return Err(invalid());
    }
    let pinned = restore_fs::open_beneath(directory, STATE, OFlags::PATH)?;
    let m = pinned.metadata()?;
    if !m.is_file()
        || m.uid() != uid
        || m.dev() != metadata.dev()
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
        || m.len() != BYTES as u64
    {
        return Err(invalid());
    }
    let before = Revision::from(&m);
    let mut file = restore_fs::open_beneath(directory, STATE, OFlags::RDONLY | OFlags::NONBLOCK)?;
    if Revision::from(&file.metadata()?) != before {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new([0; BYTES]);
    file.read_exact(bytes.as_mut())?;
    if file.read(&mut [0])? != 0
        || Revision::from(&file.metadata()?) != before
        || Revision::from(&restore_fs::open_beneath(directory, STATE, OFlags::PATH)?.metadata()?)
            != before
    {
        return Err(invalid());
    }
    let snapshot = Snapshot::decode(bytes.as_slice())?;
    if let Some((bootstrap::Anchor::Ready(epoch), _)) = enrollment
        && epoch != snapshot.epoch
    {
        return Err(invalid());
    }
    if Revision::from(&directory.metadata()?) != directory_before
        || Revision::from(&restore_fs::open_beneath(parent, DIRECTORY, OFlags::PATH)?.metadata()?)
            != directory_before
    {
        return Err(invalid());
    }
    bootstrap::check_next_absent(parent)?;
    if bootstrap::read_anchor(parent, uid)? != enrollment {
        return Err(invalid());
    }
    if snapshot.active.is_some() {
        return Err(fenced());
    }
    Ok(())
}

pub(crate) fn check_writer_admission() -> Result<()> {
    let parent = match Directory::open(Path::new("/etc/kvm"), false) {
        Ok(parent) => parent,
        // Legacy absence only; a future producer must independently require
        // Ready enrollment. No submission may synthesize it from absence.
        Err(AppError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    check_parent(&parent.file, 0)
}

#[cfg(test)]
pub(crate) fn check_fixture(parent: &File) -> Result<()> {
    check_parent(parent, nix::unistd::geteuid().as_raw())
}

#[cfg(test)]
#[path = "picoclaw_jobs_tests.rs"]
mod tests;
