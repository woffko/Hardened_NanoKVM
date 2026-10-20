//! Protected terminal order and pins, not health or independent prune authority.
//! Payload pruning additionally requires the caller's retained lifetime owner.
use super::*;
use rustix::fs::{PROC_SUPER_MAGIC, fstatfs, linkat};
use std::os::fd::AsRawFd;

const HEAD: &str = "history-head";
const NEXT: &str = ".history-head.next";
const ORDER: &str = "order";
const BYTES: usize = 256;
const PREFIX: usize = BYTES - 32;
const MAGIC: &[u8; 8] = b"NKAPPH01";

#[path = "app_slot_history_prune.rs"]
mod prune;

#[derive(Clone, PartialEq, Eq)]
struct Order {
    sequence: u64,
    transaction: [u8; 16],
    previous: [u8; 16],
    directory: Identity,
    baseline: Identity,
    fallback: Identity,
    live: Identity,
    record: [u8; 32],
    predecessor: [u8; 32],
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM app history order v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

impl Order {
    fn validate(&self, device: u64) -> Result<()> {
        if self.sequence == 0
            || self.transaction == [0; 16]
            || self.transaction == self.previous
            || self.record == [0; 32]
            || [self.directory, self.baseline, self.fallback, self.live]
                .iter()
                .any(|id| id.device != device || id.inode == 0)
            || (self.sequence == 1 && (self.previous != [0; 16] || self.predecessor != [0; 32]))
            || (self.sequence > 1 && (self.previous == [0; 16] || self.predecessor == [0; 32]))
        {
            return Err(SlotError::Invalid);
        }
        Ok(())
    }

    fn encode(&self) -> Result<[u8; BYTES]> {
        self.validate(self.directory.device)?;
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[16..32].copy_from_slice(&self.transaction);
        bytes[32..48].copy_from_slice(&self.previous);
        for (offset, id) in [
            (48, self.directory),
            (64, self.baseline),
            (80, self.fallback),
            (96, self.live),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&id.device.to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&id.inode.to_le_bytes());
        }
        bytes[112..144].copy_from_slice(&self.record);
        bytes[144..176].copy_from_slice(&self.predecessor);
        let hash = digest(&bytes[..PREFIX]);
        bytes[PREFIX..].copy_from_slice(&hash);
        Ok(bytes)
    }

    fn decode(bytes: &[u8], device: u64) -> Result<Self> {
        if bytes.len() != BYTES
            || &bytes[..8] != MAGIC
            || bytes[176..PREFIX].iter().any(|b| *b != 0)
            || digest(&bytes[..PREFIX]) != bytes[PREFIX..]
        {
            return Err(SlotError::Invalid);
        }
        let number = |offset| {
            bytes[offset..offset + 8]
                .try_into()
                .map(u64::from_le_bytes)
                .map_err(|_| SlotError::Invalid)
        };
        let identity = |offset| -> Result<Identity> {
            Ok(Identity {
                device: number(offset)?,
                inode: number(offset + 8)?,
            })
        };
        let order = Self {
            sequence: number(8)?,
            transaction: bytes[16..32].try_into().map_err(|_| SlotError::Invalid)?,
            previous: bytes[32..48].try_into().map_err(|_| SlotError::Invalid)?,
            directory: identity(48)?,
            baseline: identity(64)?,
            fallback: identity(80)?,
            live: identity(96)?,
            record: bytes[112..144].try_into().map_err(|_| SlotError::Invalid)?,
            predecessor: bytes[144..176].try_into().map_err(|_| SlotError::Invalid)?,
        };
        order.validate(device)?;
        Ok(order)
    }

    fn next(store: &Store, record: &Record, previous: Option<&Self>) -> Result<Self> {
        if !matches!(record.phase, Phase::Committed | Phase::RolledBack)
            || previous.is_some_and(|p| p.live != record.old || p.transaction == record.transaction)
        {
            return Err(SlotError::Invalid);
        }
        Ok(Self {
            sequence: previous
                .map_or(Some(1), |p| p.sequence.checked_add(1))
                .ok_or(SlotError::Invalid)?,
            transaction: record.transaction,
            previous: previous.map_or([0; 16], |p| p.transaction),
            directory: Identity::of(&store.current, store.device, store.uid)?,
            // This pin names the first enrolled terminal's source app. It is
            // not a health assertion, and no commit promotes/replaces it.
            baseline: previous.map_or(record.old, |p| p.baseline),
            fallback: if record.phase == Phase::Committed {
                record.old
            } else {
                previous.map_or(record.old, |p| p.fallback)
            },
            live: if record.phase == Phase::Committed {
                record.new
            } else {
                record.old
            },
            record: digest(&record.encode()?),
            predecessor: previous
                .map(|p| p.encode().map(|bytes| digest(&bytes)))
                .transpose()?
                .unwrap_or([0; 32]),
        })
    }

    fn check_directory(&self, directory: &File, device: u64, uid: u32) -> Result<Record> {
        protected_directory(directory, device, uid, true)?;
        if Identity::of(directory, device, uid)? != self.directory {
            return Err(SlotError::Invalid);
        }
        let record = read_record_at(directory, device, uid)?;
        self.check_record(&record)?;
        Ok(record)
    }

    fn check_record(&self, record: &Record) -> Result<()> {
        if self.transaction != record.transaction
            || self.record != digest(&record.encode()?)
            || (record.phase == Phase::Committed && self.fallback != record.old)
            || (self.sequence == 1 && (self.baseline != record.old || self.fallback != record.old))
            || self.live
                != match record.phase {
                    Phase::Committed => record.new,
                    Phase::RolledBack => record.old,
                    _ => return Err(SlotError::Invalid),
                }
        {
            return Err(SlotError::Invalid);
        }
        Ok(())
    }
}

struct Stored {
    order: Order,
    file: File,
}

fn load(parent: &File, name: &str, device: u64, uid: u32) -> Result<Option<Stored>> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let pinned = restore_fs::open_beneath(parent, name, OFlags::PATH)?;
    let m = pinned.metadata()?;
    if !m.is_file()
        || m.dev() != device
        || m.uid() != uid
        || m.nlink() != 1
        || m.mode() & 0o7777 != 0o600
        || m.len() != BYTES as u64
    {
        return Err(SlotError::Unsafe);
    }
    let mut file = restore_fs::open_beneath(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let actual = file.metadata()?;
    if (m.dev(), m.ino(), m.uid(), m.mode(), m.len(), m.nlink())
        != (
            actual.dev(),
            actual.ino(),
            actual.uid(),
            actual.mode(),
            actual.len(),
            actual.nlink(),
        )
    {
        return Err(SlotError::Unsafe);
    }
    let mut bytes = [0; BYTES];
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0])? != 0 {
        return Err(SlotError::Invalid);
    }
    Ok(Some(Stored {
        order: Order::decode(&bytes, device)?,
        file,
    }))
}

fn absent(parent: &File, name: &str) -> Result<bool> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn empty_history(parent: &File, device: u64, uid: u32) -> Result<()> {
    if let Some(history) = open_optional(parent, "history")? {
        protected_directory(&history, device, uid, true)?;
        for entry in rustix::fs::Dir::read_from(&history)? {
            let entry = entry?;
            if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
                return Err(SlotError::Invalid);
            }
        }
    }
    Ok(())
}

fn archived(order: &Order, parent: &File, device: u64, uid: u32) -> Result<()> {
    let history = restore_fs::open_beneath(parent, "history", OFlags::RDONLY | OFlags::DIRECTORY)?;
    protected_directory(&history, device, uid, true)?;
    let name = format!("{:032x}", u128::from_be_bytes(order.transaction));
    let directory = restore_fs::open_beneath(&history, &name, OFlags::RDONLY | OFlags::DIRECTORY)?;
    order.check_directory(&directory, device, uid)?;
    if load(&directory, ORDER, device, uid)?
        .ok_or(SlotError::Invalid)?
        .order
        != *order
    {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

/// Called under the store EX and app handoff before issuing another candidate.
/// Unordered history is evidence, not something a new app may silently adopt.
pub(super) fn require_preparation(
    parent: &File,
    rootfs: &File,
    device: u64,
    uid: u32,
) -> Result<()> {
    if !absent(parent, NEXT)? {
        return Err(SlotError::Busy);
    }
    match load(parent, HEAD, device, uid)? {
        Some(head) => {
            prune::require_receipt_preparation(parent, &head.order, device, uid)?;
            archived(&head.order, parent, device, uid)?;
            let live =
                restore_fs::open_beneath(rootfs, "kvmapp", OFlags::RDONLY | OFlags::DIRECTORY)?;
            if Identity::of(&live, device, uid)? != head.order.live {
                return Err(SlotError::Invalid);
            }
            Ok(())
        }
        None => {
            prune::require_empty_receipts(parent)?;
            empty_history(parent, device, uid)
        }
    }
}

/// Publish only a fully written/fsynced anonymous inode. The only magic link
/// followed is our own held FD in verified procfs, never a caller pathname.
fn link_complete(parent: &File, name: &str, order: &Order, role: &str) -> Result<()> {
    #[cfg(test)]
    let _elapsed = super::support::diagnostics::Elapsed::start("history.link.total", None);
    let mut file: File = openat2(
        parent,
        ".",
        OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_SYMLINKS
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_XDEV,
    )?
    .into();
    rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
    file.write_all(&order.encode()?)?;
    super::support::support_operation!("history.link.file-sync", None, file.sync_all())?;
    #[cfg(test)]
    point(&format!("history-{role}-file-synced"))?;
    let procfs = restore_fs::open_root(Path::new("/proc"), false)?;
    if fstatfs(&procfs)?.f_type != PROC_SUPER_MAGIC {
        return Err(SlotError::Unsafe);
    }
    let source = format!("self/fd/{}", file.as_raw_fd());
    linkat(
        &procfs,
        source.as_str(),
        parent,
        name,
        AtFlags::SYMLINK_FOLLOW,
    )?;
    let named = load(parent, name, order.directory.device, file.metadata()?.uid())?
        .ok_or(SlotError::Invalid)?;
    if named.order != *order || named.file.metadata()?.ino() != file.metadata()?.ino() {
        return Err(SlotError::Invalid);
    }
    #[cfg(test)]
    point(&format!("history-{role}-linked"))?;
    super::support::support_operation!("history.link.parent-sync", None, parent.sync_all())?;
    #[cfg(not(test))]
    let _ = role;
    Ok(())
}

/// Called only by canonical terminal retirement while its native/update/store/
/// writer guards are retained. An order alone never authorizes tree removal.
pub(super) fn register(store: &Store, record: &Record) -> Result<()> {
    #[cfg(test)]
    let _elapsed = super::support::diagnostics::Elapsed::start("history.register.total", None);
    if store.record()? != *record {
        return Err(SlotError::Invalid);
    }
    let parent = &store._lock.0;
    let previous = load(parent, HEAD, store.device, store.uid)?;
    let order = match &previous {
        Some(head) if head.order.transaction == record.transaction => {
            head.order
                .check_directory(&store.current, store.device, store.uid)?;
            head.order.clone()
        }
        Some(head) => {
            archived(&head.order, parent, store.device, store.uid)?;
            Order::next(store, record, Some(&head.order))?
        }
        None => {
            prune::require_empty_receipts(parent)?;
            empty_history(parent, store.device, store.uid)?;
            Order::next(store, record, None)?
        }
    };
    match load(&store.current, ORDER, store.device, store.uid)? {
        Some(saved) if saved.order == order => saved.file.sync_all()?,
        Some(_) => return Err(SlotError::Invalid),
        None if previous.as_ref().is_some_and(|head| head.order == order) => {
            return Err(SlotError::Invalid);
        }
        None => link_complete(&store.current, ORDER, &order, "order")?,
    }
    store.current.sync_all()?;
    #[cfg(test)]
    point("history-order-published")?;
    if previous.as_ref().is_some_and(|head| head.order == order) {
        prune::require_absent(store)?;
        if !absent(parent, NEXT)? {
            return Err(SlotError::Invalid);
        }
        previous.ok_or(SlotError::Invalid)?.file.sync_all()?;
        parent.sync_all()?;
        return prune::expire_receipts(store, &order);
    }
    super::support::support_operation!(
        "history.payload-prune",
        None,
        prune::finish(
            store,
            &order,
            previous.as_ref().map(|head| &head.order),
            record,
        )
    )?;
    match load(parent, NEXT, store.device, store.uid)? {
        Some(next) if next.order == order => next.file.sync_all()?,
        Some(_) => return Err(SlotError::Invalid),
        None => link_complete(parent, NEXT, &order, "head")?,
    }
    parent.sync_all()?;
    #[cfg(test)]
    point("history-head-next-synced")?;
    let actual = load(parent, HEAD, store.device, store.uid)?;
    if actual.as_ref().map(|v| &v.order) != previous.as_ref().map(|v| &v.order) {
        return Err(SlotError::Invalid);
    }
    if let (Some(actual), Some(previous)) = (&actual, &previous) {
        let actual = actual.file.metadata()?;
        let previous = previous.file.metadata()?;
        if (actual.dev(), actual.ino()) != (previous.dev(), previous.ino()) {
            return Err(SlotError::Invalid);
        }
    }
    renameat(parent, NEXT, parent, HEAD)?;
    #[cfg(test)]
    point("history-head-renamed")?;
    parent.sync_all()?;
    #[cfg(test)]
    point("history-head-published")?;
    super::support::support_operation!(
        "history.receipt-expiry",
        None,
        prune::expire_receipts(store, &order)
    )
}

/// Receipt deletion may be in progress; do not interpret partial evidence as
/// an installed version, success, or a never-seen transaction.
pub(super) fn receipt_query_guard(
    parent: &File,
    device: u64,
    uid: u32,
    id: [u8; 16],
) -> Result<()> {
    prune::receipt_query_guard(parent, device, uid, id)
}

/// Diagnostic payload availability, not health/rollback permission. Legacy
/// archives remain readable, but cannot manufacture an expiry without ORDER.
pub(super) fn archived_payload(
    directory: &File,
    record: &Record,
    device: u64,
    uid: u32,
) -> Result<bool> {
    match load(directory, ORDER, device, uid)? {
        Some(saved) => {
            saved.order.check_directory(directory, device, uid)?;
            prune::retained(directory, &saved.order, record, uid)
        }
        None => {
            let name = match record.phase {
                Phase::Committed => "old",
                Phase::RolledBack => "new",
                _ => return Err(SlotError::Invalid),
            };
            if !absent(directory, "payload-expired")? || !absent(directory, ".payload-pruning")? {
                return Err(SlotError::Invalid);
            }
            let payload = open_optional(directory, name)?.ok_or(SlotError::Invalid)?;
            let expected = if record.phase == Phase::Committed {
                record.old
            } else {
                record.new
            };
            if Identity::of(&payload, device, uid)? != expected {
                return Err(SlotError::Invalid);
            }
            Ok(true)
        }
    }
}

#[cfg(test)]
fn point(name: &str) -> Result<()> {
    checkpoint(name);
    if std::env::var("NANOKVM_APP_SLOT_TEST_FAIL").as_deref() == Ok(name) {
        return Err(SlotError::Io(io::Error::other(
            "injected history ordering failure",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "app_slot_history_tests.rs"]
mod tests;
