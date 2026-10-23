//! Fixed-rootfs app-slot preparation/recovery. The issuer is not yet connected
//! to API/broker swap or first-start acceptance. Recovery restores a recorded old slot;
//! neither a checksum nor an arbitrary staging directory authorizes new code.

use super::{
    app_install_lease::{Accepted, Handoff},
    app_stage::AppStage,
    operation_lock::ProcessLock,
    restore_fs,
};
use rand_core::{OsRng, RngCore};
use rustix::fs::{
    AtFlags, FileType, FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags, flock, openat2,
    renameat, renameat_with, statat,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};

const DIRECTORY: &str = "application-slot";
const CURRENT: &str = "current";
const STATE: &str = "state";
const MAGIC: &[u8; 8] = b"NKAPPJ01";
const RECORD_BYTES: usize = 512;
const HASH_OFFSET: usize = 480;
const HASH_DOMAIN: &[u8] = b"NanoKVM app slot journal v1\0";

/// Declares an object unsafe and, in test builds only, prints which check did
/// so: a lock-free status read that fails under load can then be located from
/// the test log (G1 on 72cdc9e and c331c4d each failed one delivery test with
/// an `Unsafe` whose origin a backtrace cannot show, since it is a value).
macro_rules! unsafe_at {
    ($($arg:tt)*) => {{
        #[cfg(test)]
        eprintln!("slot-unsafe: {}", format_args!($($arg)*));
        SlotError::Unsafe
    }};
}

#[path = "app_slot_history.rs"]
mod history;
#[path = "app_slot_recovery_intent.rs"]
mod recovery_intent;
#[path = "app_slot_support.rs"]
pub mod support;
use support::support_operation;
#[path = "app_slot_terminal.rs"]
mod terminal;
#[cfg(test)]
pub(crate) use terminal::job_status_fixture;
pub use terminal::{JobStatus, job_status};

#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    #[error("application slot storage requires protected rootfs directories")]
    Unsafe,
    #[error("application slot journal or layout is invalid; evidence retained")]
    Invalid,
    #[error(
        "the executing broker declares no support for this helper transition; nothing was staged"
    )]
    UnsupportedTransition,
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
pub(crate) enum Import {
    Signed = 1,
    Manual = 2,
    UnsignedLab = 3,
}

// Only AppCandidate's private production factory can supply the public issuer.
// Keeping this data private to the crate does not create a second path-based
// install API: prepare() takes the opaque candidate, never CandidateInput.
pub(crate) struct CandidateInput {
    pub(crate) root: std::path::PathBuf,
    pub(crate) stage: AppStage,
    pub(crate) version: String,
    pub(crate) import: Import,
    pub(crate) archive_sha512: [u8; 64],
    pub(crate) metadata_sha256: [u8; 32],
    pub(crate) signature_sha256: [u8; 32],
}

// Even a rejection before opening the fixed store must discard candidate
// staging BEFORE releasing update/writer exclusion. Field order is deliberate.
struct Preparation {
    candidate: crate::api::application::AppCandidate,
    handoff: Handoff,
}

/// A durable prepared receipt plus retained app/update/writer admission. This
/// cannot switch the live slot or claim trial health. The independent installer
/// must reopen and validate this exact transaction before further transitions.
pub struct PreparedInstall {
    store: Store,
    record: Record,
    handoff: Handoff,
}
impl PreparedInstall {
    pub fn transaction(&self) -> [u8; 16] {
        self.record.transaction
    }

    /// Release only the store's local serialization, retaining all transferred
    /// kernel exclusions. This is not a commit or worker-acceptance receipt.
    pub fn into_handoff(self) -> Handoff {
        let Self {
            store,
            record: _,
            handoff,
        } = self;
        drop(store);
        handoff
    }
}

/// The worker's accepted admission bound to the canonical prepared receipt.
/// Root peer credentials alone do not create this capability. No health or
/// permission to bypass native lifecycle is implied by accepting preparation.
pub struct AcceptedInstall {
    _store: Store,
    record: Record,
    _admission: Accepted,
}
impl AcceptedInstall {
    pub fn transaction(&self) -> [u8; 16] {
        self.record.transaction
    }

    fn trial_record(&self) -> Result<Record> {
        let mut record = self._store.record()?;
        let phase = record.phase;
        record.phase = self.record.phase;
        if record != self.record {
            return Err(SlotError::Invalid);
        }
        record.phase = phase;
        let layout = self._store.layout(&record)?;
        if !matches!(phase, Phase::Published | Phase::Committed)
            || layout.live != Some(record.new)
            || layout.old != Some(record.old)
            || layout.new.is_some()
        {
            return Err(SlotError::Invalid);
        }
        Ok(record)
    }

    pub(crate) fn check_trial(
        &self,
        closed: &crate::native_owner::broker::app_install::ClosedRuntime,
    ) -> Result<()> {
        self.check_published(closed)?;
        support::before_trial(self, closed)?;
        Ok(())
    }

    /// The phase part of `check_trial` alone: no support I/O or sync. Only
    /// for a Session whose own joined worker already passed `check_trial`.
    pub(crate) fn check_published(
        &self,
        closed: &crate::native_owner::broker::app_install::ClosedRuntime,
    ) -> Result<()> {
        if closed.transaction() != self.transaction()
            || self.trial_record()?.phase != Phase::Published
        {
            return Err(SlotError::Invalid);
        }
        Ok(())
    }

    pub(crate) fn commit(
        &mut self,
        ready: &crate::native_owner::broker::app_install::TrialReady,
    ) -> Result<Status> {
        #[cfg(test)]
        let _elapsed = support::diagnostics::Elapsed::start("slot.commit.total", None);
        if ready.transaction() != self.transaction() {
            return Err(SlotError::Invalid);
        }
        // Inspect canonical phase/layout before retrying an ambiguous record
        // publication. Never turn an already Committed app into a rollback.
        let mut record = self.trial_record()?;
        if record.phase == Phase::Published {
            record.phase = Phase::Committed;
            support_operation!("slot.commit.publish", None, self._store.publish(&record))?;
        }
        support_operation!(
            "slot.commit.state-sync",
            None,
            restore_fs::open_beneath(&self._store.current, STATE, OFlags::RDONLY)?.sync_all()
        )?;
        support_operation!("slot.commit.parents-sync", None, self._store.sync_parents())?;
        self.record = record;
        Ok(Status::Transaction(Phase::Committed))
    }

    pub(crate) fn publish(
        &mut self,
        closed: &crate::native_owner::broker::app_install::ClosedRuntime,
    ) -> Result<Status> {
        if closed.transaction() != self.record.transaction {
            return Err(SlotError::Invalid);
        }
        let store = &self._store;
        // Re-read canonical state after any earlier I/O error. An in-memory
        // phase or successful rename return is not a durable receipt.
        let mut record = store.record()?;
        let layout = store.layout(&record)?;
        if record.transaction != self.record.transaction
            || record.phase != Phase::Prepared
            || layout.live != Some(record.old)
            || layout.new != Some(record.new)
            || layout.old.is_some()
        {
            return Err(SlotError::Invalid);
        }
        support::before_publish(self, closed)?;
        preserve_app_state(store)?;
        record.phase = Phase::Publishing;
        store.publish(&record)?;
        renameat_with(
            &store.rootfs,
            "kvmapp",
            &store.current,
            "old",
            RenameFlags::NOREPLACE,
        )?;
        #[cfg(test)]
        checkpoint("publish-old-parked");
        store.sync_parents()?;
        #[cfg(test)]
        checkpoint("publish-old-parked-synced");
        renameat_with(
            &store.current,
            "new",
            &store.rootfs,
            "kvmapp",
            RenameFlags::NOREPLACE,
        )?;
        #[cfg(test)]
        checkpoint("publish-new-live");
        store.sync_parents()?;
        #[cfg(test)]
        checkpoint("publish-new-live-synced");
        let layout = store.layout(&record)?;
        if layout.live != Some(record.new) {
            return Err(SlotError::Invalid);
        }
        record.phase = Phase::Published;
        store.publish(&record)?;
        self.record = record;
        Ok(Status::Transaction(Phase::Published))
    }

    pub(crate) fn rollback(
        &mut self,
        closed: &crate::native_owner::broker::app_install::ClosedRuntime,
    ) -> Result<Status> {
        let actual = self._store.record()?;
        if closed.transaction() != self.record.transaction
            || actual.transaction != self.record.transaction
        {
            return Err(SlotError::Invalid);
        }
        support::before_rollback(self, closed)?;
        let status = self._store.recover()?;
        if status != Status::Transaction(Phase::RolledBack) {
            return Err(SlotError::Invalid);
        }
        self.record = self._store.record()?;
        Ok(status)
    }
}

// Data only, identical to the app-state subset of restore_policy::FIXED.
// Do not copy arbitrary config, scripts, executables, keys or init from old app.
const APP_STATE: [&str; 7] = ["ap.ssid", "ap.pass", "type", "fps", "qlty", "gop", "res"];
const APP_STATE_BYTES: u64 = 4096;

fn preserve_app_state(store: &Store) -> Result<()> {
    let old_app =
        restore_fs::open_beneath(&store.rootfs, "kvmapp", OFlags::RDONLY | OFlags::DIRECTORY)?;
    let new = restore_fs::open_beneath(&store.current, "new", OFlags::RDONLY | OFlags::DIRECTORY)?;
    let old = open_optional(&old_app, "kvm")?;
    if let Some(old) = &old {
        protected_directory(old, store.device, store.uid, false)?;
    }
    match rustix::fs::mkdirat(&new, "kvm", Mode::from_raw_mode(0o755)) {
        Ok(()) => new.sync_all()?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let target = restore_fs::open_beneath(&new, "kvm", OFlags::RDONLY | OFlags::DIRECTORY)?;
    protected_directory(&target, store.device, store.uid, false)?;
    // Snapshot and validate the complete bounded allowlist BEFORE changing even
    // candidate data. Native closure + retained writer drain cover enrolled work.
    let mut values: [Option<zeroize::Zeroizing<Vec<u8>>>; 7] = std::array::from_fn(|_| None);
    for (index, name) in APP_STATE.into_iter().enumerate() {
        let Some(old) = &old else {
            continue;
        };
        let pinned: File = match openat2(
            old,
            name,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        ) {
            Ok(fd) => fd.into(),
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        let m = pinned.metadata()?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != store.uid
            || m.dev() != store.device
            || m.mode() & 0o7022 != 0
            || m.len() > APP_STATE_BYTES
        {
            return Err(SlotError::Unsafe);
        }
        let mut source = restore_fs::open_beneath(old, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
        let actual = source.metadata()?;
        if (
            actual.dev(),
            actual.ino(),
            actual.len(),
            actual.mode(),
            actual.uid(),
            actual.nlink(),
        ) != (m.dev(), m.ino(), m.len(), m.mode(), m.uid(), m.nlink())
        {
            return Err(SlotError::Unsafe);
        }
        let mut value = zeroize::Zeroizing::new(Vec::with_capacity(m.len() as usize));
        (&mut source)
            .take(APP_STATE_BYTES + 1)
            .read_to_end(&mut value)?;
        if value.len() as u64 != m.len() {
            return Err(SlotError::Invalid);
        }
        // Rollback keeps this same old inode, including the last native/API
        // settings, not just the newly synced candidate copy.
        source.sync_all()?;
        values[index] = Some(value);
    }
    if let Some(old) = &old {
        old.sync_all()?;
    }
    old_app.sync_all()?;
    // The candidate overlay is additional allocation, not part of the signed
    // archive footprint. Check the complete bounded snapshot before replacing
    // any candidate data; keep recovery reserve out of this optional work.
    let capacity = super::app_space::Capacity::read(&target)?;
    let mut footprint = super::app_space::Footprint::new(capacity.unit)?;
    for value in values.iter().flatten() {
        footprint.path(true)?;
        footprint.file(value.len() as u64)?;
    }
    footprint.check(capacity)?;
    for (name, value) in APP_STATE.into_iter().zip(values) {
        #[cfg(test)]
        checkpoint(&format!("app-state-{name}-begin"));
        // A fresh signed candidate may have a default file here, but never a
        // symlink/alias/special object. Refuse foreign bindings before rename.
        match statat(&target, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(s)
                if FileType::from_raw_mode(s.st_mode) == FileType::RegularFile
                    && s.st_uid == store.uid
                    && s.st_dev == store.device
                    && s.st_nlink == 1
                    && s.st_mode & 0o7022 == 0 => {}
            Ok(_) => return Err(SlotError::Unsafe),
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(value) = value {
            let mut nonce = [0; 16];
            OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| SlotError::Io(io::Error::other("app state entropy unavailable")))?;
            #[cfg(test)]
            checkpoint(&format!("app-state-{name}-entropy-ready"));
            let temporary = format!(".app-state-{:032x}", u128::from_be_bytes(nonce));
            let mut file: File = rustix::fs::openat(
                &target,
                temporary.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )?
            .into();
            rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
            #[cfg(test)]
            checkpoint(&format!("app-state-{name}-created"));
            file.write_all(&value)?;
            #[cfg(test)]
            checkpoint(&format!("app-state-{name}-written"));
            file.sync_all()?;
            #[cfg(test)]
            checkpoint(&format!("app-state-{name}-file-synced"));
            renameat(&target, temporary.as_str(), &target, name)?;
            #[cfg(test)]
            checkpoint(&format!("app-state-{name}-renamed"));
        } else {
            match rustix::fs::unlinkat(&target, name, AtFlags::empty()) {
                Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                Err(error) => return Err(error.into()),
            }
        }
        target.sync_all()?;
        #[cfg(test)]
        checkpoint(&format!("app-state-{name}"));
    }
    new.sync_all()?;
    Ok(())
}

pub fn accept_prepared(admission: Accepted) -> Result<AcceptedInstall> {
    let store = Store::open(true)?.ok_or(SlotError::Invalid)?;
    accept_at(store, admission)
}

fn accept_at(store: Store, admission: Accepted) -> Result<AcceptedInstall> {
    let record = store.record()?;
    if record.phase != Phase::Prepared || record.transaction != admission.transaction() {
        return Err(SlotError::Invalid);
    }
    let layout = store.layout(&record)?;
    if layout.live != Some(record.old) || layout.new != Some(record.new) || layout.old.is_some() {
        return Err(SlotError::Invalid);
    }
    Ok(AcceptedInstall {
        _store: store,
        record,
        _admission: admission,
    })
}

/// Issue from actual extracted bytes and an app-only retained handoff. Never
/// infer authorization from a legacy path, version string or supplied checksum.
/// Existing current transactions (including terminal ones) are not overwritten;
/// retirement is a separate, still required lifecycle operation.
pub fn prepare(
    candidate: crate::api::application::AppCandidate,
    handoff: Handoff,
) -> Result<PreparedInstall> {
    let pending = Preparation { candidate, handoff };
    if !nix::unistd::geteuid().is_root() {
        return Err(SlotError::Unsafe);
    }
    let rootfs = restore_fs::open_root(Path::new("/"), true)?;
    let device = rootfs.metadata()?.dev();
    for path in ["/", "/etc", "/etc/kvm"] {
        protected_directory(
            &restore_fs::open_root(Path::new(path), true)?,
            device,
            0,
            false,
        )?;
    }
    let parent = restore_fs::open_root(Path::new("/etc/kvm"), true)?;
    prepare_at(rootfs, parent, 0, pending)
}

fn prepare_at(
    rootfs: File,
    parent: File,
    uid: u32,
    pending: Preparation,
) -> Result<PreparedInstall> {
    let device = rootfs.metadata()?.dev();
    protected_directory(&rootfs, device, uid, false)?;
    protected_directory(&parent, device, uid, false)?;
    match rustix::fs::mkdirat(&parent, DIRECTORY, Mode::from_raw_mode(0o700)) {
        Ok(()) => parent.sync_all()?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let directory =
        restore_fs::open_beneath(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
    protected_directory(&directory, device, uid, true)?;
    flock(&directory, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
        if error == rustix::io::Errno::WOULDBLOCK {
            SlotError::Busy
        } else {
            SlotError::Io(error.into())
        }
    })?;
    let lock = StoreLock(directory);
    recovery_intent::require_absent(&lock.0)?;
    // NOFOLLOW/NO_XDEV rejects dangling symlinks and mounts rather than treating
    // them as missing. Never retire another transaction as a side effect.
    if open_optional(&lock.0, CURRENT)?.is_some() {
        return Err(SlotError::Busy);
    }
    history::require_preparation(&lock.0, &rootfs, device, uid)?;
    // No fallible operation between splitting this owner and establishing the
    // later-declared staging value, whose cleanup precedes handoff teardown.
    let Preparation { candidate, handoff } = pending;
    let mut input = candidate.into_slot();
    let extraction = input.stage.extraction_path()?;
    if input.root.strip_prefix(&extraction).is_err() || input.root == extraction {
        return Err(SlotError::Unsafe);
    }
    let old = restore_fs::open_beneath(&rootfs, "kvmapp", OFlags::RDONLY | OFlags::DIRECTORY)?;
    let old = Identity::of(&old, device, uid)?;
    let source_parent = input.root.parent().ok_or(SlotError::Unsafe)?;
    let source_name = input.root.file_name().ok_or(SlotError::Unsafe)?;
    let source_parent = restore_fs::open_root(source_parent, true)?;
    protected_directory(&source_parent, device, uid, false)?;
    let new: File = openat2(
        &source_parent,
        Path::new(source_name),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?
    .into();
    let new_identity = Identity::of(&new, device, uid)?;
    let record = Record {
        phase: Phase::Prepared,
        import: input.import,
        transaction: handoff.transaction(),
        old,
        new: new_identity,
        archive_sha512: input.archive_sha512,
        metadata_sha256: input.metadata_sha256,
        signature_sha256: input.signature_sha256,
        version: input.version,
    };
    record.validate()?;
    // Complete the candidate's file + directory durability BEFORE any receipt
    // can become current. The bounded traversal rejects aliases/special files.
    let mut members = 0;
    let mut bytes = 0;
    sync_candidate(
        &new,
        device,
        uid,
        Path::new(""),
        0,
        &mut members,
        &mut bytes,
    )?;
    let name = format!(".prepare-{:032x}", u128::from_be_bytes(record.transaction));
    rustix::fs::mkdirat(&lock.0, name.as_str(), Mode::from_raw_mode(0o700))?;
    lock.0.sync_all()?;
    #[cfg(test)]
    checkpoint("issuer-directory-created");
    let current = restore_fs::open_beneath(&lock.0, &name, OFlags::RDONLY | OFlags::DIRECTORY)?;
    protected_directory(&current, device, uid, true)?;
    let store = Store {
        rootfs,
        _lock: lock,
        current,
        uid,
        device,
    };
    // From this point even ambiguous rename/sync failures retain all source
    // material. No Drop cleanup is allowed to erase a possible recovery input.
    input.stage.preserve_recovery();
    renameat_with(
        &source_parent,
        Path::new(source_name),
        &store.current,
        "new",
        RenameFlags::NOREPLACE,
    )?;
    #[cfg(test)]
    checkpoint("issuer-candidate-moved");
    source_parent.sync_all()?;
    #[cfg(test)]
    checkpoint("issuer-source-synced");
    store.current.sync_all()?;
    #[cfg(test)]
    checkpoint("issuer-candidate-synced");
    store.layout(&record)?;
    store.publish(&record)?;
    #[cfg(test)]
    checkpoint("issuer-record-durable");
    renameat_with(
        &store._lock.0,
        name.as_str(),
        &store._lock.0,
        CURRENT,
        RenameFlags::NOREPLACE,
    )?;
    #[cfg(test)]
    checkpoint("issuer-current-renamed");
    store.sync_parents()?;
    #[cfg(test)]
    checkpoint("issuer-current-durable");
    // The known empty source stage can now be discarded. This never removes
    // the issued candidate, current receipt, old slot or another operation.
    input.stage.discard_after_success();
    Ok(PreparedInstall {
        store,
        record,
        handoff,
    })
}

fn sync_candidate(
    directory: &File,
    device: u64,
    uid: u32,
    relative: &Path,
    depth: usize,
    members: &mut usize,
    bytes: &mut u64,
) -> Result<()> {
    if depth > 64 {
        return Err(SlotError::Invalid);
    }
    protected_directory(directory, device, uid, false)?;
    for entry in rustix::fs::Dir::read_from(directory)? {
        let entry = entry?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        *members += 1;
        if *members > 8192 {
            return Err(SlotError::Invalid);
        }
        let named = statat(directory, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)?;
        if !matches!(
            FileType::from_raw_mode(named.st_mode),
            FileType::Directory | FileType::RegularFile
        ) {
            // Never open a candidate device/socket/FIFO merely to reject it.
            return Err(SlotError::Unsafe);
        }
        let child: File = openat2(
            directory,
            entry.file_name(),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )?
        .into();
        let m = child.metadata()?;
        if m.dev() != device
            || m.uid() != uid
            || m.mode() & 0o7022 != 0
            || (m.dev(), m.ino()) != (named.st_dev, named.st_ino)
        {
            return Err(SlotError::Unsafe);
        }
        if m.is_dir() {
            let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
            sync_candidate(
                &child,
                device,
                uid,
                &relative.join(name),
                depth + 1,
                members,
                bytes,
            )?;
        } else if m.is_file() && m.nlink() == 1 {
            *bytes = bytes
                .checked_add(m.len())
                .filter(|n| *n <= 256 * 1024 * 1024)
                .ok_or(SlotError::Invalid)?;
            let name = std::ffi::OsStr::from_bytes(entry.file_name().to_bytes());
            let path = relative.join(name);
            // Archive extraction is deliberately0600. Grant execution only to
            // fixed runtime code classes, never all data or tar-supplied modes.
            let mode = if executable_member(&path) {
                0o755
            } else {
                0o600
            };
            rustix::fs::fchmod(&child, Mode::from_raw_mode(mode))?;
            child.sync_all()?;
        } else {
            return Err(SlotError::Unsafe);
        }
    }
    rustix::fs::fchmod(directory, Mode::from_raw_mode(0o755))?;
    directory.sync_all()?;
    Ok(())
}

fn executable_member(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some(
            "server/NanoKVM-Server"
                | "backends/NanoKVM-Server.rust"
                | "backends/NanoKVM-Server.go"
                | "kvm_system/kvm_system"
                | "hwmon/nanokvm-hwmon"
                | "system/network/udhcpc6.script"
                | "picoclaw/skills/kvm-control/scripts/nanokvm-bridge.sh"
        )
    ) || matches!(path.parent(), Some(parent) if parent == Path::new("system/bin") || parent == Path::new("system/init.d"))
}

// The hashes retain the issuing install's exact-byte context. They do not
// verify RSA or grant authority on an attacker-writable filesystem. Only the
// fixed protected rootfs store may supply a recovery record.
#[derive(Clone, PartialEq, Eq)]
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
        let Some((rootfs, directory)) = fixed_store_root()? else {
            return Ok(None);
        };
        Self::at_root(rootfs, directory, 0, recover)
    }

    fn open_recovery(exclusive: bool) -> Result<Option<Self>> {
        let Some((rootfs, directory)) = fixed_store_root()? else {
            return Ok(None);
        };
        Self::at_root_mode(rootfs, directory, 0, exclusive, true)
    }

    fn at_root(rootfs: File, directory: File, uid: u32, recover: bool) -> Result<Option<Self>> {
        Self::at_root_mode(rootfs, directory, uid, recover, false)
    }

    fn at_root_mode(
        rootfs: File,
        directory: File,
        uid: u32,
        recover: bool,
        recovering: bool,
    ) -> Result<Option<Self>> {
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
        let current = if recovering {
            let intent = recovery_intent::load(&lock.0, device, uid)?;
            let current = open_optional(&lock.0, CURRENT)?;
            match intent {
                Some(intent) => Some(intent.select(&lock.0, current, uid)?),
                None => current,
            }
        } else {
            recovery_intent::require_absent(&lock.0)?;
            open_optional(&lock.0, CURRENT)?
        };
        let Some(current) = current else {
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
        let record = read_record_at(&self.current, self.device, self.uid)?;
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

fn fixed_store_root() -> Result<Option<(File, File)>> {
    if !nix::unistd::geteuid().is_root() {
        return Err(SlotError::Unsafe);
    }
    let rootfs = restore_fs::open_root(Path::new("/"), true)?;
    let device = rootfs.metadata()?.dev();
    for path in ["/", "/etc", "/etc/kvm"] {
        protected_directory(
            &restore_fs::open_root(Path::new(path), true)?,
            device,
            0,
            false,
        )?;
    }
    let parent = restore_fs::open_root(Path::new("/etc/kvm"), true)?;
    let Some(directory) = open_optional(&parent, DIRECTORY)? else {
        return Ok(None);
    };
    protected_directory(&directory, device, 0, true)?;
    Ok(Some((rootfs, directory)))
}

fn read_record_at(directory: &File, device: u64, uid: u32) -> Result<Record> {
    // Writers and recovery hold the store lock: a replaced inode here is not a
    // normal publish, so it stays Unsafe.
    read_record_once(directory, device, uid)?.ok_or(SlotError::Unsafe)
}

/// Reads of a record that a live install may republish, without the store
/// lock. A publish renames a new immutable record over `state`; a reader that
/// pinned the old inode then reopens a different one. That is a newer record,
/// not an unsafe object: read again, a bounded number of times.
fn read_live_record_at(directory: &File, device: u64, uid: u32) -> Result<Record> {
    for _ in 0..LIVE_RECORD_READS {
        if let Some(record) = read_record_once(directory, device, uid)? {
            return Ok(record);
        }
    }
    Err(unsafe_at!(
        "read_live_record_at: state replaced during each of {LIVE_RECORD_READS} reads"
    ))
}

const LIVE_RECORD_READS: usize = 8;

#[cfg(test)]
thread_local! {
    /// Runs between pinning `state` and reopening it, where a concurrent
    /// publish replaces the record.
    static AFTER_RECORD_PIN: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn after_record_pin(hook: Option<Box<dyn FnMut()>>) {
    AFTER_RECORD_PIN.with(|cell| *cell.borrow_mut() = hook);
}

/// `None` when `state` was replaced during the read: the pinned or reopened
/// inode was unlinked, or the name now refers to another inode.
fn read_record_once(directory: &File, device: u64, uid: u32) -> Result<Option<Record>> {
    // Reject special files before opening them for I/O, then require the same
    // exact inode after reopening. A journal path is never a device selector.
    let pinned = restore_fs::open_beneath(directory, STATE, OFlags::PATH)?;
    let metadata = pinned.metadata()?;
    // A rename over `state` after the pin unlinks the pinned inode.
    if metadata.nlink() == 0 {
        return Ok(None);
    }
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.dev() != device
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != RECORD_BYTES as u64
    {
        return Err(unsafe_at!(
            "read_record_once pinned state: file={} nlink={} mode={:o} len={} uid={} dev={}",
            metadata.is_file(),
            metadata.nlink(),
            metadata.mode() & 0o7777,
            metadata.len(),
            metadata.uid(),
            metadata.dev()
        ));
    }
    #[cfg(test)]
    AFTER_RECORD_PIN.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook();
        }
    });
    let mut file = restore_fs::open_beneath(directory, STATE, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let reopened = file.metadata()?;
    if (reopened.dev(), reopened.ino()) != (metadata.dev(), metadata.ino()) || reopened.nlink() == 0
    {
        return Ok(None);
    }
    if (
        reopened.uid(),
        reopened.mode(),
        reopened.nlink(),
        reopened.len(),
    ) != (
        metadata.uid(),
        metadata.mode(),
        metadata.nlink(),
        metadata.len(),
    ) {
        return Err(unsafe_at!(
            "read_record_once reopened state changed: nlink {}->{} mode {:o}->{:o} len {}->{}",
            metadata.nlink(),
            reopened.nlink(),
            metadata.mode() & 0o7777,
            reopened.mode() & 0o7777,
            metadata.len(),
            reopened.len()
        ));
    }
    let mut bytes = [0; RECORD_BYTES];
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0])? != 0 {
        return Err(SlotError::Invalid);
    }
    Record::decode(&bytes).map(Some)
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
        return Err(unsafe_at!(
            "protected_directory private={private} mode={:o} uid={} dev={}",
            metadata.mode() & 0o7777,
            metadata.uid(),
            metadata.dev()
        ));
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
    let Some(store) = Store::open_recovery(false)? else {
        return Ok(Status::NoTransaction);
    };
    let record = store.record()?;
    store.layout(&record)?;
    Ok(Status::Transaction(record.phase))
}

fn recovery_lock_error(error: super::operation_lock::LockError) -> SlotError {
    match error {
        super::operation_lock::LockError::Busy => SlotError::Busy,
        super::operation_lock::LockError::Unsafe => SlotError::Unsafe,
        super::operation_lock::LockError::Io => {
            SlotError::Io(io::Error::other("update admission unavailable"))
        }
    }
}

/// Recover and archive only under retained update/writer/native lifetime proof.
/// This cannot publish a new candidate or assert app health; legacy markers and
/// missing native state do not mint a recovery capability.
pub fn recover() -> Result<Status> {
    let admission = ProcessLock::acquire().map_err(recovery_lock_error)?;
    recover_locked(admission, false)
}

fn recover_locked(admission: ProcessLock, defer_terminal: bool) -> Result<Status> {
    // Installer death releases UpdateEX, but independent runtime owners may
    // still be alive. The durable same-boot Stop fence, not lock availability,
    // decides whether an early recovery may touch the live slot.
    crate::native_owner::broker::check_update_admission().map_err(|_| SlotError::Busy)?;
    let Some(store) = Store::open_recovery(true)? else {
        support::require_boot_clear()?;
        return Ok(Status::NoTransaction);
    };
    let record = store.record()?;
    store.layout(&record)?;
    let terminal = matches!(record.phase, Phase::Committed | Phase::RolledBack);
    let ready = match crate::native_owner::broker::ReadyAppRecovery::acquire() {
        Ok(ready) => ready,
        Err(
            crate::native_owner::broker::JournalError::Busy
            | crate::native_owner::broker::JournalError::Unresolved
            | crate::native_owner::broker::JournalError::Absent,
        ) if terminal && defer_terminal => {
            support::require_boot_clear()?;
            return Ok(Status::Transaction(record.phase));
        }
        Err(
            crate::native_owner::broker::JournalError::Busy
            | crate::native_owner::broker::JournalError::Unresolved
            | crate::native_owner::broker::JournalError::Absent,
        ) => return Err(SlotError::Busy),
        Err(_) => return Err(SlotError::Unsafe),
    };
    let writers = match super::state_writers::StateWriters::default().try_drain() {
        Ok(writers) => writers,
        Err(crate::AppError::Conflict(_)) if terminal && defer_terminal => {
            support::require_boot_clear()?;
            return Ok(Status::Transaction(record.phase));
        }
        Err(crate::AppError::Conflict(_)) => return Err(SlotError::Busy),
        Err(_) => return Err(SlotError::Unsafe),
    };
    let intent = store.recovery_intent(&record)?;
    #[cfg(test)]
    checkpoint("recovery-intent-durable");
    let native = ready
        .fence()
        .map_err(|_| SlotError::Io(io::Error::other("native recovery fence failed")))?;
    // Declaration order releases app store, writer freeze, native singleton,
    // then UpdateEX. Failed operations leave durable native Stopping behind.
    let mut recovery = Recovery {
        store,
        _writers: writers,
        native,
        _admission: admission,
    };
    #[cfg(test)]
    checkpoint("recovery-native-fenced");
    support::recover_before_app(&recovery.store, &recovery.native)?;
    #[cfg(test)]
    checkpoint("recovery-support-reconciled");
    let status = recovery.store.recover()?;
    #[cfg(test)]
    checkpoint("recovery-slot-terminal");
    let record = recovery.store.record()?;
    recovery.store.retire_recovered(&record, &recovery.native)?;
    #[cfg(test)]
    checkpoint("recovery-app-archived");
    recovery
        .native
        .complete()
        .map_err(|_| SlotError::Io(io::Error::other("native recovery completion failed")))?;
    #[cfg(test)]
    checkpoint("recovery-native-closed");
    recovery.store.finish_recovery_intent(&intent)?;
    Ok(status)
}

struct Recovery {
    store: Store,
    _writers: super::state_writers::WriterDrain,
    native: crate::native_owner::broker::FencedAppRecovery,
    _admission: ProcessLock,
}

/// Gate an app consumer before it opens or executes /kvmapp. A terminal layout
/// may be observed read-only when a restart owns update admission. Otherwise
/// recovery/retirement requires retained update, writer and native exclusions.
/// NoTransaction retains the trusted legacy/factory boot path; it is not a new
/// candidate receipt, runtime health acknowledgement or authorization from p3.
pub fn boot_gate() -> Result<Status> {
    match status()? {
        Status::NoTransaction => {
            support::require_boot_clear()?;
            Ok(Status::NoTransaction)
        }
        ready @ Status::Transaction(Phase::Committed | Phase::RolledBack) => {
            match ProcessLock::acquire() {
                Ok(admission) => recover_locked(admission, true),
                Err(super::operation_lock::LockError::Busy) => {
                    support::require_boot_clear()?;
                    Ok(ready)
                }
                Err(error) => Err(recovery_lock_error(error)),
            }
        }
        Status::Transaction(_) => recover(),
    }
}

#[cfg(test)]
#[path = "app_slot_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "app_slot_issuer_tests.rs"]
pub(crate) mod issuer_tests;

#[cfg(test)]
#[path = "app_slot_publication_tests.rs"]
mod publication_tests;

#[cfg(test)]
#[path = "app_slot_test_diagnostics.rs"]
pub(crate) mod test_diagnostics;

#[cfg(all(test, feature = "sandbox-test-fixture"))]
#[path = "app_slot_recovery_tests.rs"]
mod recovery_tests;

#[cfg(test)]
fn checkpoint(name: &str) {
    if std::env::var_os("NANOKVM_APP_SLOT_TEST_TRACE").is_some() {
        eprintln!("slot-checkpoint: {name}");
    }
    if std::env::var("NANOKVM_APP_SLOT_TEST_STOP").as_deref() == Ok(name) {
        println!("slot-checkpoint-ready");
        io::stdout().flush().unwrap();
        let mut byte = [0];
        let _ = io::stdin().read_exact(&mut byte);
        panic!("parent must kill the child before allowing continuation");
    }
}
