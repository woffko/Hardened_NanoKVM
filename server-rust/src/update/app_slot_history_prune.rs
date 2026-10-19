//! Exact inactive-payload retirement under the caller's retained lifetime owner.
//! Receipts stay intact; bounded receipt expiry/cutoff remains separate work.
use super::*;
use std::collections::BTreeSet;

#[path = "app_slot_prune_tree.rs"]
mod tree;
use tree::Manifest;

const MANIFEST: &str = "prune-manifest";
const CURSOR: &str = "prune-cursor";
const CURSOR_NEXT: &str = ".prune-cursor.next";
const QUARANTINE: &str = ".payload-pruning";
const EXPIRED: &str = "payload-expired";
// Bounded validation backstop, NOT a receipt expiry/retention policy.
const MAX_HISTORY: u64 = 128;

struct Archive {
    order: Order,
    record: Record,
    directory: File,
}

fn inactive(record: &Record) -> Result<(&'static str, Identity)> {
    match record.phase {
        Phase::Committed => Ok(("old", record.old)),
        Phase::RolledBack => Ok(("new", record.new)),
        _ => Err(SlotError::Invalid),
    }
}

fn chain(store: &Store, head: Option<&Order>) -> Result<Vec<Archive>> {
    let Some(head) = head else {
        empty_history(&store._lock.0, store.device, store.uid)?;
        return Ok(Vec::new());
    };
    if head.sequence > MAX_HISTORY {
        return Err(SlotError::Invalid);
    }
    let history = restore_fs::open_beneath(
        &store._lock.0,
        "history",
        OFlags::RDONLY | OFlags::DIRECTORY,
    )?;
    protected_directory(&history, store.device, store.uid, true)?;
    let mut archives: Vec<Archive> = Vec::with_capacity(head.sequence as usize);
    let mut names = BTreeSet::new();
    let mut transaction = head.transaction;
    for sequence in (1..=head.sequence).rev() {
        let name = format!("{:032x}", u128::from_be_bytes(transaction));
        if !names.insert(name.clone()) {
            return Err(SlotError::Invalid);
        }
        let directory =
            restore_fs::open_beneath(&history, &name, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let order = load(&directory, ORDER, store.device, store.uid)?
            .ok_or(SlotError::Invalid)?
            .order;
        let record = order.check_directory(&directory, store.device, store.uid)?;
        if order.sequence != sequence || order.transaction != transaction {
            return Err(SlotError::Invalid);
        }
        if let Some(newer) = archives.last() {
            if newer.order.predecessor != digest(&order.encode()?)
                || newer.order.baseline != order.baseline
                || newer.record.old != order.live
                || (newer.record.phase == Phase::RolledBack
                    && newer.order.fallback != order.fallback)
            {
                return Err(SlotError::Invalid);
            }
        } else if order != *head {
            return Err(SlotError::Invalid);
        }
        let (payload, _) = inactive(&record)?;
        let mut members = 0;
        for entry in rustix::fs::Dir::read_from(&directory)? {
            let entry = entry?;
            let bytes = entry.file_name().to_bytes();
            if matches!(bytes, b"." | b"..") {
                continue;
            }
            members += 1;
            if members > 5
                || ![
                    STATE.as_bytes(),
                    ORDER.as_bytes(),
                    payload.as_bytes(),
                    QUARANTINE.as_bytes(),
                    EXPIRED.as_bytes(),
                ]
                .contains(&bytes)
            {
                return Err(SlotError::Invalid);
            }
        }
        transaction = order.previous;
        archives.push(Archive {
            order,
            record,
            directory,
        });
    }
    if transaction != [0; 16] {
        return Err(SlotError::Invalid);
    }
    let mut seen = 0;
    for entry in rustix::fs::Dir::read_from(&history)? {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        seen += 1;
        if seen > MAX_HISTORY
            || !std::str::from_utf8(bytes)
                .ok()
                .is_some_and(|name| names.contains(name))
        {
            return Err(SlotError::Invalid);
        }
    }
    if seen != head.sequence {
        return Err(SlotError::Invalid);
    }
    Ok(archives)
}

fn open_file(
    parent: &File,
    name: &str,
    device: u64,
    uid: u32,
    minimum: u64,
    maximum: u64,
) -> Result<Option<File>> {
    if absent(parent, name)? {
        return Ok(None);
    }
    let pinned = restore_fs::open_beneath(parent, name, OFlags::PATH)?;
    let m = pinned.metadata()?;
    if !m.is_file()
        || m.dev() != device
        || m.uid() != uid
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || !(minimum..=maximum).contains(&m.len())
    {
        return Err(SlotError::Unsafe);
    }
    let file = restore_fs::open_beneath(parent, name, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let n = file.metadata()?;
    if (m.dev(), m.ino(), m.uid(), m.mode(), m.nlink(), m.len())
        != (n.dev(), n.ino(), n.uid(), n.mode(), n.nlink(), n.len())
    {
        return Err(SlotError::Unsafe);
    }
    Ok(Some(file))
}

fn publish(
    parent: &File,
    name: &str,
    device: u64,
    uid: u32,
    role: &str,
    write: impl FnOnce(&mut File) -> Result<()>,
) -> Result<()> {
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
    write(&mut file)?;
    file.sync_all()?;
    #[cfg(test)]
    point(&format!("prune-{role}-file-synced"))?;
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
    let named = open_file(
        parent,
        name,
        device,
        uid,
        file.metadata()?.len(),
        file.metadata()?.len(),
    )?
    .ok_or(SlotError::Invalid)?;
    if named.metadata()?.ino() != file.metadata()?.ino() {
        return Err(SlotError::Unsafe);
    }
    #[cfg(test)]
    point(&format!("prune-{role}-linked"))?;
    parent.sync_all()?;
    #[cfg(not(test))]
    let _ = role;
    Ok(())
}

fn small_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Cursor {
    index: usize,
    pending: bool,
}

impl Cursor {
    fn encode(self, manifest: &Manifest) -> Result<[u8; 96]> {
        if self.index > manifest.nodes.len() || (self.pending && self.index == manifest.nodes.len())
        {
            return Err(SlotError::Invalid);
        }
        let mut bytes = [0; 96];
        bytes[..8].copy_from_slice(b"NKAPPC01");
        bytes[8..40].copy_from_slice(&manifest.hash);
        bytes[40..44].copy_from_slice(&(self.index as u32).to_le_bytes());
        bytes[44] = u8::from(self.pending);
        let hash = small_hash(b"NanoKVM app prune cursor v1\0", &bytes[..64]);
        bytes[64..].copy_from_slice(&hash);
        Ok(bytes)
    }
    fn successor(self, count: usize) -> Result<Self> {
        if self.index >= count {
            return Err(SlotError::Invalid);
        }
        Ok(if self.pending {
            Self {
                index: self.index + 1,
                pending: false,
            }
        } else {
            Self {
                index: self.index,
                pending: true,
            }
        })
    }
}

fn load_cursor(store: &Store, name: &str, manifest: &Manifest) -> Result<Option<(Cursor, File)>> {
    let Some(mut file) = open_file(&store.current, name, store.device, store.uid, 96, 96)? else {
        return Ok(None);
    };
    let mut bytes = [0; 96];
    file.read_exact(&mut bytes)?;
    let cursor = Cursor {
        index: u32::from_le_bytes(bytes[40..44].try_into().map_err(|_| SlotError::Invalid)?)
            as usize,
        pending: match bytes[44] {
            0 => false,
            1 => true,
            _ => return Err(SlotError::Invalid),
        },
    };
    if cursor.encode(manifest)? != bytes || file.read(&mut [0])? != 0 {
        return Err(SlotError::Invalid);
    }
    Ok(Some((cursor, file)))
}

fn cursor_step(previous: Option<Cursor>, desired: Cursor, count: usize) -> Result<()> {
    let expected = previous
        .map(|p| p.successor(count))
        .transpose()?
        .unwrap_or(Cursor {
            index: 0,
            pending: false,
        });
    if expected != desired {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

fn save_cursor(store: &Store, manifest: &Manifest, desired: Cursor) -> Result<()> {
    let previous = load_cursor(store, CURSOR, manifest)?;
    cursor_step(
        previous.as_ref().map(|v| v.0),
        desired,
        manifest.nodes.len(),
    )?;
    let bytes = desired.encode(manifest)?;
    match load_cursor(store, CURSOR_NEXT, manifest)? {
        Some((next, file)) if next == desired => file.sync_all()?,
        Some(_) => return Err(SlotError::Invalid),
        None => publish(
            &store.current,
            CURSOR_NEXT,
            store.device,
            store.uid,
            "cursor",
            |file| {
                file.write_all(&bytes)?;
                Ok(())
            },
        )?,
    }
    store.current.sync_all()?;
    let actual = load_cursor(store, CURSOR, manifest)?;
    if actual.as_ref().map(|v| v.0) != previous.as_ref().map(|v| v.0) {
        return Err(SlotError::Invalid);
    }
    if let (Some((_, a)), Some((_, b))) = (&actual, &previous)
        && (a.metadata()?.dev(), a.metadata()?.ino()) != (b.metadata()?.dev(), b.metadata()?.ino())
    {
        return Err(SlotError::Unsafe);
    }
    renameat(&store.current, CURSOR_NEXT, &store.current, CURSOR)?;
    #[cfg(test)]
    point("prune-cursor-renamed")?;
    store.current.sync_all()?;
    #[cfg(test)]
    point("prune-cursor-published")?;
    Ok(())
}

fn resume_cursor(store: &Store, manifest: &Manifest) -> Result<Option<Cursor>> {
    if let Some((next, _)) = load_cursor(store, CURSOR_NEXT, manifest)? {
        save_cursor(store, manifest, next)?;
    }
    Ok(load_cursor(store, CURSOR, manifest)?.map(|(cursor, _)| cursor))
}

fn expiry(manifest: &Manifest) -> Result<[u8; 160]> {
    let root = manifest.nodes.last().ok_or(SlotError::Invalid)?;
    let mut bytes = [0; 160];
    bytes[..8].copy_from_slice(b"NKAPPE01");
    bytes[8..40].copy_from_slice(&digest(&manifest.victim.encode()?));
    bytes[40..48].copy_from_slice(&root.identity.device.to_le_bytes());
    bytes[48..56].copy_from_slice(&root.identity.inode.to_le_bytes());
    bytes[56..72].copy_from_slice(&manifest.owner.transaction);
    bytes[72..104].copy_from_slice(&manifest.hash);
    let hash = small_hash(b"NanoKVM app prune expiry v1\0", &bytes[..128]);
    bytes[128..].copy_from_slice(&hash);
    Ok(bytes)
}

fn load_expiry(
    directory: &File,
    order: &Order,
    record: &Record,
    uid: u32,
) -> Result<Option<([u8; 160], File)>> {
    let Some(mut file) = open_file(directory, EXPIRED, order.directory.device, uid, 160, 160)?
    else {
        return Ok(None);
    };
    let mut bytes = [0; 160];
    file.read_exact(&mut bytes)?;
    let (_, identity) = inactive(record)?;
    if &bytes[..8] != b"NKAPPE01"
        || bytes[8..40] != digest(&order.encode()?)
        || bytes[40..48] != identity.device.to_le_bytes()
        || bytes[48..56] != identity.inode.to_le_bytes()
        || bytes[56..72] == [0; 16]
        || bytes[72..104] == [0; 32]
        || bytes[104..128] != [0; 24]
        || small_hash(b"NanoKVM app prune expiry v1\0", &bytes[..128]) != bytes[128..]
        || file.read(&mut [0])? != 0
    {
        return Err(SlotError::Invalid);
    }
    Ok(Some((bytes, file)))
}

pub(super) fn retained(directory: &File, order: &Order, record: &Record, uid: u32) -> Result<bool> {
    let (name, identity) = inactive(record)?;
    let payload = open_optional(directory, name)?;
    let quarantined = open_optional(directory, QUARANTINE)?;
    match load_expiry(directory, order, record, uid)? {
        Some(_) if payload.is_none() && quarantined.is_none() => Ok(false),
        Some(_) => Err(SlotError::Invalid),
        None => match (payload, quarantined) {
            (Some(payload), None) if Identity::of(&payload, identity.device, uid)? == identity => {
                Ok(true)
            }
            _ => Err(SlotError::Busy),
        },
    }
}

fn remove_file(parent: &File, name: &str, file: &File, uid: u32) -> Result<()> {
    let m = file.metadata()?;
    let actual =
        open_file(parent, name, m.dev(), uid, m.len(), m.len())?.ok_or(SlotError::Invalid)?;
    if actual.metadata()?.ino() != m.ino() {
        return Err(SlotError::Unsafe);
    }
    rustix::fs::unlinkat(parent, name, AtFlags::empty())?;
    #[cfg(test)]
    point(&format!("{name}-unlinked"))?;
    parent.sync_all()?;
    Ok(())
}

fn clean(store: &Store, manifest: &Manifest, file: &File) -> Result<()> {
    if !absent(&store.current, CURSOR_NEXT)? {
        return Err(SlotError::Invalid);
    }
    if let Some((cursor, pinned)) = load_cursor(store, CURSOR, manifest)? {
        if cursor.index != manifest.nodes.len() || cursor.pending {
            return Err(SlotError::Invalid);
        }
        remove_file(&store.current, CURSOR, &pinned, store.uid)?;
        #[cfg(test)]
        point("prune-cursor-removed")?;
    }
    remove_file(&store.current, MANIFEST, file, store.uid)?;
    #[cfg(test)]
    point("prune-manifest-removed")?;
    Ok(())
}

fn execute(store: &Store, archive: &Archive, manifest: &Manifest, file: &File) -> Result<()> {
    let (payload_name, identity) = inactive(&archive.record)?;
    if manifest.nodes.last().ok_or(SlotError::Invalid)?.identity != identity {
        return Err(SlotError::Invalid);
    }
    let expected_expiry = expiry(manifest)?;
    if let Some((actual, marker)) = load_expiry(
        &archive.directory,
        &archive.order,
        &archive.record,
        store.uid,
    )? {
        if actual != expected_expiry
            || retained(
                &archive.directory,
                &archive.order,
                &archive.record,
                store.uid,
            )?
        {
            return Err(SlotError::Invalid);
        }
        marker.sync_all()?;
        archive.directory.sync_all()?;
        return clean(store, manifest, file);
    }
    let source = open_optional(&archive.directory, payload_name)?;
    let mut quarantine = open_optional(&archive.directory, QUARANTINE)?;
    let mut cursor = match resume_cursor(store, manifest)? {
        Some(cursor) => cursor,
        None if source.is_some() && quarantine.is_none() => {
            let cursor = Cursor {
                index: 0,
                pending: false,
            };
            save_cursor(store, manifest, cursor)?;
            cursor
        }
        None => return Err(SlotError::Invalid),
    };
    match (&source, &quarantine) {
        (Some(source), None)
            if cursor
                == (Cursor {
                    index: 0,
                    pending: false,
                }) =>
        {
            if Identity::of(source, store.device, store.uid)? != identity {
                return Err(SlotError::Unsafe);
            }
            tree::verify(
                Some(source),
                archive.order.directory,
                &manifest.nodes,
                store.uid,
                false,
            )?;
            renameat_with(
                &archive.directory,
                payload_name,
                &archive.directory,
                QUARANTINE,
                RenameFlags::NOREPLACE,
            )?;
            #[cfg(test)]
            point("prune-payload-quarantined")?;
            archive.directory.sync_all()?;
            #[cfg(test)]
            point("prune-quarantine-synced")?;
            quarantine = open_optional(&archive.directory, QUARANTINE)?;
        }
        (None, Some(quarantine))
            if Identity::of(quarantine, store.device, store.uid)? == identity => {}
        (None, None) => {}
        _ => return Err(SlotError::Invalid),
    }
    // A recovered rename may be visible without its earlier parent fsync.
    // Re-establish quarantine/root-removal durability before consuming cursor.
    archive.directory.sync_all()?;
    #[cfg(test)]
    point("prune-quarantine-boundary-synced")?;
    let remaining = &manifest.nodes[cursor.index..];
    tree::verify(
        quarantine.as_ref(),
        archive.order.directory,
        remaining,
        store.uid,
        cursor.pending,
    )?;
    while cursor.index < manifest.nodes.len() {
        let index = cursor.index;
        let already_pending = cursor.pending;
        if !already_pending {
            cursor = cursor.successor(manifest.nodes.len())?;
            save_cursor(store, manifest, cursor)?;
        }
        #[cfg(test)]
        point(&format!("prune-delete-{}-pending", cursor.index))?;
        tree::remove_node(
            &archive.directory,
            quarantine.as_ref(),
            &manifest.nodes[index],
            store.uid,
            already_pending,
        )?;
        #[cfg(test)]
        point(&format!("prune-delete-{}-synced", cursor.index))?;
        cursor = cursor.successor(manifest.nodes.len())?;
        save_cursor(store, manifest, cursor)?;
        #[cfg(test)]
        point(&format!("prune-delete-{index}-advanced"))?;
    }
    if !absent(&archive.directory, payload_name)? || !absent(&archive.directory, QUARANTINE)? {
        return Err(SlotError::Invalid);
    }
    publish(
        &archive.directory,
        EXPIRED,
        store.device,
        store.uid,
        "expired",
        |file| {
            file.write_all(&expected_expiry)?;
            Ok(())
        },
    )?;
    #[cfg(test)]
    point("prune-expiry-published")?;
    clean(store, manifest, file)
}

fn pending(store: &Store) -> Result<Option<(Manifest, File)>> {
    match open_file(
        &store.current,
        MANIFEST,
        store.device,
        store.uid,
        616,
        tree::MAX_MANIFEST,
    )? {
        Some(mut file) => {
            let manifest = Manifest::read(&mut file, store.device)?;
            Ok(Some((manifest, file)))
        }
        None => {
            require_absent(store)?;
            Ok(None)
        }
    }
}

pub(super) fn require_absent(store: &Store) -> Result<()> {
    for name in [MANIFEST, CURSOR, CURSOR_NEXT] {
        if !absent(&store.current, name)? {
            return Err(SlotError::Busy);
        }
    }
    Ok(())
}

pub(super) fn check_head_capacity(order: &Order) -> Result<()> {
    if order.sequence >= MAX_HISTORY {
        return Err(SlotError::Busy);
    }
    Ok(())
}

fn protected(identity: Identity, order: &Order, record: &Record) -> bool {
    [
        order.baseline,
        order.fallback,
        order.live,
        record.old,
        record.new,
        order.directory,
    ]
    .contains(&identity)
}

struct Pins {
    identities: [Identity; 3],
    present: [bool; 3],
}
impl Pins {
    fn new(order: &Order, record: &Record) -> Self {
        let identities = [order.baseline, order.fallback, order.live];
        Self {
            identities,
            present: identities.map(|id| [record.old, record.new].contains(&id)),
        }
    }
    fn observe(&mut self, identity: Identity, retained: bool) {
        if retained {
            for (pin, present) in self.identities.iter().zip(&mut self.present) {
                *present |= *pin == identity;
            }
        }
    }
    fn require_all(self) -> Result<()> {
        if self.present.contains(&false) {
            Err(SlotError::Invalid)
        } else {
            Ok(())
        }
    }
}

pub(super) fn finish(
    store: &Store,
    order: &Order,
    previous: Option<&Order>,
    record: &Record,
) -> Result<()> {
    let archives = chain(store, previous)?;
    let inflight = pending(store)?;
    if let Some((manifest, _)) = &inflight
        && (manifest.owner != *order
            || !archives.iter().any(|a| a.order == manifest.victim)
            || protected(
                manifest.nodes.last().ok_or(SlotError::Invalid)?.identity,
                order,
                record,
            ))
    {
        return Err(SlotError::Invalid);
    }
    // Validate every receipt and root state before deleting any selected payload.
    // An expired historical inode can legitimately be reused by a later app.
    // Only present roots claim current pins; an expiry is not a missing pin.
    let mut pins = Pins::new(order, record);
    for archive in &archives {
        if !inflight
            .as_ref()
            .is_some_and(|(m, _)| m.victim == archive.order)
        {
            let retained = retained(
                &archive.directory,
                &archive.order,
                &archive.record,
                store.uid,
            )?;
            pins.observe(inactive(&archive.record)?.1, retained);
        }
    }
    pins.require_all()?;
    if let Some((manifest, file)) = inflight {
        let archive = archives
            .iter()
            .find(|a| a.order == manifest.victim)
            .ok_or(SlotError::Invalid)?;
        execute(store, archive, &manifest, &file)?;
    }
    for archive in archives.iter().rev() {
        let (name, identity) = inactive(&archive.record)?;
        if protected(identity, order, record)
            || !retained(
                &archive.directory,
                &archive.order,
                &archive.record,
                store.uid,
            )?
        {
            continue;
        }
        let payload = open_optional(&archive.directory, name)?.ok_or(SlotError::Invalid)?;
        let nodes = tree::collect(&payload, archive.order.directory, store.device, store.uid)?;
        drop(payload);
        let manifest = Manifest::new(order.clone(), archive.order.clone(), nodes)?;
        publish(
            &store.current,
            MANIFEST,
            store.device,
            store.uid,
            "manifest",
            |file| {
                if manifest.encode(file)? != manifest.hash {
                    return Err(SlotError::Invalid);
                }
                Ok(())
            },
        )?;
        #[cfg(test)]
        point("prune-manifest-published")?;
        let expected_hash = manifest.hash;
        drop(manifest);
        let (saved, file) = pending(store)?.ok_or(SlotError::Invalid)?;
        if saved.owner != *order || saved.victim != archive.order || saved.hash != expected_hash {
            return Err(SlotError::Invalid);
        }
        execute(store, archive, &saved, &file)?;
    }
    require_absent(store)
}

#[cfg(test)]
fn point(name: &str) -> Result<()> {
    checkpoint(name);
    if std::env::var("NANOKVM_APP_SLOT_TEST_FAIL").as_deref() == Ok(name) {
        return Err(SlotError::Io(io::Error::other(
            "injected app payload prune failure",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "app_slot_history_prune_tests.rs"]
mod tests;
