//! Bounded terminal receipts. Only retained canonical retirement calls expiry.
//! A protected cutoff is not health, rollback authority, or a missing-job proof.
use super::*;
use std::collections::BTreeSet;

const KEEP: u64 = 32;
const LEGACY_LIMIT: u64 = 129;
const ANCHOR: &str = "history-anchor";
const ANCHOR_NEXT: &str = ".history-anchor.next";
const JOURNAL: &str = "receipt-manifest";
const PROGRESS: &str = "receipt-cursor";
const PROGRESS_NEXT: &str = ".receipt-cursor.next";
const GARBAGE: &str = ".receipts-pruning";
const ANCHOR_BYTES: usize = 1088;
const JOURNAL_HEADER: usize = 1408;
const VICTIM_BYTES: usize = 952;
const JOURNAL_MAX: u64 = 128 * 1024;
const MEMBERS: [&str; 3] = [EXPIRED, ORDER, STATE];

fn name(id: [u8; 16]) -> String {
    format!("{:032x}", u128::from_be_bytes(id))
}

#[derive(Clone, PartialEq, Eq)]
struct Anchor {
    owner: Order,
    floor: Order,
    pins: Vec<Order>,
}

impl Anchor {
    fn encode(&self) -> Result<[u8; ANCHOR_BYTES]> {
        let device = self.owner.directory.device;
        self.owner.validate(device)?;
        self.floor.validate(device)?;
        if self.owner.sequence <= KEEP
            || self.floor.sequence != self.owner.sequence - (KEEP - 1)
            || self.floor.baseline != self.owner.baseline
            || self.pins.len() > 2
        {
            return Err(SlotError::Invalid);
        }
        let mut sequence = 0;
        for pin in &self.pins {
            pin.validate(device)?;
            if pin.sequence <= sequence
                || pin.sequence >= self.floor.sequence
                || pin.baseline != self.owner.baseline
                || pin.transaction == self.floor.transaction
                || pin.directory == self.floor.directory
            {
                return Err(SlotError::Invalid);
            }
            sequence = pin.sequence;
        }
        let mut bytes = [0; ANCHOR_BYTES];
        bytes[..8].copy_from_slice(b"NKAPPA01");
        bytes[8..16].copy_from_slice(&KEEP.to_le_bytes());
        bytes[16..20].copy_from_slice(&(self.pins.len() as u32).to_le_bytes());
        bytes[32..288].copy_from_slice(&self.owner.encode()?);
        bytes[288..544].copy_from_slice(&self.floor.encode()?);
        for (index, pin) in self.pins.iter().enumerate() {
            bytes[544 + index * BYTES..544 + (index + 1) * BYTES].copy_from_slice(&pin.encode()?);
        }
        let hash = small_hash(b"NanoKVM app receipt anchor v1\0", &bytes[..1056]);
        bytes[1056..].copy_from_slice(&hash);
        Ok(bytes)
    }

    fn decode(bytes: &[u8], device: u64) -> Result<Self> {
        if bytes.len() != ANCHOR_BYTES || &bytes[..8] != b"NKAPPA01" {
            return Err(SlotError::Invalid);
        }
        let count = u32::from_le_bytes(bytes[16..20].try_into().map_err(|_| SlotError::Invalid)?);
        if count > 2 {
            return Err(SlotError::Invalid);
        }
        let mut pins = Vec::with_capacity(2);
        for index in 0..count as usize {
            pins.push(Order::decode(
                &bytes[544 + index * BYTES..544 + (index + 1) * BYTES],
                device,
            )?);
        }
        let anchor = Self {
            owner: Order::decode(&bytes[32..288], device)?,
            floor: Order::decode(&bytes[288..544], device)?,
            pins,
        };
        if anchor.encode()?.as_slice() != bytes {
            return Err(SlotError::Invalid);
        }
        Ok(anchor)
    }
}

fn anchor_at(parent: &File, path: &str, device: u64, uid: u32) -> Result<Option<(Anchor, File)>> {
    let Some(mut file) = open_file(
        parent,
        path,
        device,
        uid,
        ANCHOR_BYTES as u64,
        ANCHOR_BYTES as u64,
    )?
    else {
        return Ok(None);
    };
    let mut bytes = [0; ANCHOR_BYTES];
    file.read_exact(&mut bytes)?;
    Ok(Some((Anchor::decode(&bytes, device)?, file)))
}

fn base_hash(anchor: Option<&Anchor>) -> Result<[u8; 32]> {
    anchor
        .map(|a| {
            a.encode()
                .map(|b| small_hash(b"NanoKVM app receipt base v1\0", &b))
        })
        .transpose()
        .map(|v| v.unwrap_or([0; 32]))
}

fn window(head: &Order, anchor: Option<&Anchor>) -> Result<u64> {
    match anchor {
        Some(anchor)
            if anchor.owner.baseline == head.baseline
                && head.sequence >= anchor.owner.sequence
                && head.sequence - anchor.owner.sequence <= 1 =>
        {
            Ok(anchor.floor.sequence)
        }
        None if head.sequence <= LEGACY_LIMIT => Ok(1),
        _ => Err(SlotError::Invalid),
    }
}

fn archive(
    parent: &File,
    current: Option<&File>,
    history: &File,
    device: u64,
    uid: u32,
    id: [u8; 16],
) -> Result<(Archive, bool)> {
    let path = name(id);
    let archived = open_optional(history, &path)?;
    let own_current = match current {
        Some(file) => (read_record_at(file, device, uid)?.transaction == id).then_some(file),
        None => None,
    };
    let (directory, named) = if let Some(current) = own_current {
        if let Some(directory) = archived {
            if Identity::of(&directory, device, uid)? != Identity::of(current, device, uid)? {
                return Err(SlotError::Invalid);
            }
            (directory, true)
        } else {
            let source = open_optional(parent, CURRENT)?.ok_or(SlotError::Invalid)?;
            if Identity::of(&source, device, uid)? != Identity::of(current, device, uid)? {
                return Err(SlotError::Invalid);
            }
            (source, false)
        }
    } else {
        (archived.ok_or(SlotError::Invalid)?, true)
    };
    let order = load(&directory, ORDER, device, uid)?
        .ok_or(SlotError::Invalid)?
        .order;
    let record = order.check_directory(&directory, device, uid)?;
    if order.transaction != id {
        return Err(SlotError::Invalid);
    }
    let (payload, _) = inactive(&record)?;
    let mut count = 0;
    for entry in rustix::fs::Dir::read_from(&directory)? {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        count += 1;
        let receipt_work = own_current.is_some()
            && [
                JOURNAL.as_bytes(),
                PROGRESS.as_bytes(),
                PROGRESS_NEXT.as_bytes(),
            ]
            .contains(&bytes);
        if count > 8
            || (!receipt_work
                && ![
                    STATE.as_bytes(),
                    ORDER.as_bytes(),
                    payload.as_bytes(),
                    QUARANTINE.as_bytes(),
                    EXPIRED.as_bytes(),
                ]
                .contains(&bytes))
        {
            return Err(SlotError::Invalid);
        }
    }
    Ok((
        Archive {
            order,
            record,
            directory,
        },
        named,
    ))
}

fn namespace(history: &File, names: &BTreeSet<String>) -> Result<()> {
    let mut seen = 0;
    for entry in rustix::fs::Dir::read_from(history)? {
        let entry = entry?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        seen += 1;
        if seen > names.len()
            || !std::str::from_utf8(bytes)
                .ok()
                .is_some_and(|n| names.contains(n))
        {
            return Err(SlotError::Invalid);
        }
    }
    if seen != names.len() {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

fn retained_chain(
    parent: &File,
    current: Option<&File>,
    device: u64,
    uid: u32,
    head: &Order,
    anchor: Option<&Anchor>,
) -> Result<(Vec<Archive>, BTreeSet<String>)> {
    let floor = window(head, anchor)?;
    let count = head
        .sequence
        .checked_sub(floor)
        .and_then(|n| n.checked_add(1))
        .ok_or(SlotError::Invalid)?;
    if count > LEGACY_LIMIT {
        return Err(SlotError::Invalid);
    }
    let history = restore_fs::open_beneath(parent, "history", OFlags::RDONLY | OFlags::DIRECTORY)?;
    protected_directory(&history, device, uid, true)?;
    let mut archives: Vec<Archive> = Vec::with_capacity(count as usize + 2);
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut id = head.transaction;
    for sequence in (floor..=head.sequence).rev() {
        if !ids.insert(id) {
            return Err(SlotError::Invalid);
        }
        let (archive, named) = archive(parent, current, &history, device, uid, id)?;
        if archive.order.sequence != sequence {
            return Err(SlotError::Invalid);
        }
        if let Some(newer) = archives.last() {
            if newer.order.predecessor != digest(&archive.order.encode()?)
                || newer.order.baseline != archive.order.baseline
                || newer.record.old != archive.order.live
                || (newer.record.phase == Phase::RolledBack
                    && newer.order.fallback != archive.order.fallback)
            {
                return Err(SlotError::Invalid);
            }
        } else if archive.order != *head {
            return Err(SlotError::Invalid);
        }
        if named {
            names.insert(name(id));
        }
        id = archive.order.previous;
        archives.push(archive);
    }
    if let Some(anchor) = anchor {
        if archives.last().ok_or(SlotError::Invalid)?.order != anchor.floor {
            return Err(SlotError::Invalid);
        }
        for pin in anchor.pins.iter().rev() {
            if !ids.insert(pin.transaction) {
                return Err(SlotError::Invalid);
            }
            let (archive, named) =
                archive(parent, current, &history, device, uid, pin.transaction)?;
            let (_, inactive) = inactive(&archive.record)?;
            if !named
                || archive.order != *pin
                || ![anchor.owner.baseline, anchor.owner.fallback].contains(&inactive)
            {
                return Err(SlotError::Invalid);
            }
            names.insert(name(pin.transaction));
            archives.push(archive);
        }
    } else if id != [0; 16] {
        return Err(SlotError::Invalid);
    }
    Ok((archives, names))
}

pub(super) fn chain(store: &Store, head: Option<&Order>) -> Result<Vec<Archive>> {
    let Some(head) = head else {
        require_empty(&store._lock.0)?;
        if anchor_at(&store._lock.0, ANCHOR, store.device, store.uid)?.is_some() {
            return Err(SlotError::Invalid);
        }
        empty_history(&store._lock.0, store.device, store.uid)?;
        return Ok(Vec::new());
    };
    require_no_journal(&store.current)?;
    if !absent(&store._lock.0, ANCHOR_NEXT)? {
        return Err(SlotError::Busy);
    }
    let anchor = anchor_at(&store._lock.0, ANCHOR, store.device, store.uid)?;
    let (archives, names) = retained_chain(
        &store._lock.0,
        Some(&store.current),
        store.device,
        store.uid,
        head,
        anchor.as_ref().map(|v| &v.0),
    )?;
    let history = restore_fs::open_beneath(
        &store._lock.0,
        "history",
        OFlags::RDONLY | OFlags::DIRECTORY,
    )?;
    namespace(&history, &names)?;
    Ok(archives)
}

fn require_no_journal(current: &File) -> Result<()> {
    for name in [JOURNAL, PROGRESS, PROGRESS_NEXT] {
        if !absent(current, name)? {
            return Err(SlotError::Busy);
        }
    }
    Ok(())
}

pub(in crate::update::app_slot::history) fn require_preparation(
    parent: &File,
    head: &Order,
    device: u64,
    uid: u32,
) -> Result<()> {
    if !absent(parent, ANCHOR_NEXT)? {
        return Err(SlotError::Busy);
    }
    if open_optional(parent, CURRENT)?.is_some() {
        return Err(SlotError::Busy);
    }
    let anchor = anchor_at(parent, ANCHOR, device, uid)?;
    window(head, anchor.as_ref().map(|v| &v.0))?;
    if head.sequence == u64::MAX || (anchor.is_none() && head.sequence >= LEGACY_LIMIT) {
        return Err(SlotError::Busy);
    }
    let (archives, names) = retained_chain(
        parent,
        None,
        device,
        uid,
        head,
        anchor.as_ref().map(|v| &v.0),
    )?;
    let history = restore_fs::open_beneath(parent, "history", OFlags::RDONLY | OFlags::DIRECTORY)?;
    namespace(&history, &names)?;
    let floor = window(head, anchor.as_ref().map(|v| &v.0))?;
    // The caller independently validates the exact live root before issuance.
    let mut baseline = head.baseline == head.live;
    let mut fallback = head.fallback == head.live;
    for archive in &archives {
        let available = retained(&archive.directory, &archive.order, &archive.record, uid)?;
        let identity = inactive(&archive.record)?.1;
        baseline |= available && identity == head.baseline;
        fallback |= available && identity == head.fallback;
        if archive.order.sequence < floor && !available {
            return Err(SlotError::Invalid);
        }
    }
    if !baseline || !fallback {
        return Err(SlotError::Invalid);
    }
    Ok(())
}

pub(in crate::update::app_slot::history) fn require_empty(parent: &File) -> Result<()> {
    for path in [ANCHOR, ANCHOR_NEXT] {
        if !absent(parent, path)? {
            return Err(SlotError::Invalid);
        }
    }
    if let Some(current) = open_optional(parent, CURRENT)? {
        require_no_journal(&current)?;
    }
    Ok(())
}

struct Victim {
    order: Order,
    record: Record,
    expiry: [u8; 160],
    inodes: [u64; 3],
}

impl Victim {
    fn validate(&self, target: &Anchor) -> Result<()> {
        self.order.validate(target.owner.directory.device)?;
        self.order.check_record(&self.record)?;
        validate_expiry(&self.expiry, &self.order, &self.record)?;
        if self.order.sequence >= target.floor.sequence
            || self.order.baseline != target.owner.baseline
            || target.pins.iter().any(|p| {
                p.transaction == self.order.transaction || p.directory == self.order.directory
            })
            || self.inodes.contains(&0)
            || self.inodes.iter().collect::<BTreeSet<_>>().len() != 3
        {
            return Err(SlotError::Invalid);
        }
        Ok(())
    }
    fn bytes(&self, index: usize) -> Result<Vec<u8>> {
        Ok(match index {
            0 => self.expiry.to_vec(),
            1 => self.order.encode()?.to_vec(),
            2 => self.record.encode()?.to_vec(),
            _ => return Err(SlotError::Invalid),
        })
    }
}

struct Journal {
    base: [u8; 32],
    history: Identity,
    target: Anchor,
    victims: Vec<Victim>,
}

impl Journal {
    fn encode(&self) -> Result<Vec<u8>> {
        let anchor = self.target.encode()?;
        if self.history.device != self.target.owner.directory.device
            || self.history.inode == 0
            || self.victims.len() > LEGACY_LIMIT as usize
        {
            return Err(SlotError::Invalid);
        }
        let length = JOURNAL_HEADER + self.victims.len() * VICTIM_BYTES + 32;
        if length as u64 > JOURNAL_MAX {
            return Err(SlotError::Invalid);
        }
        let mut bytes = vec![0; length];
        bytes[..8].copy_from_slice(b"NKAPPR01");
        bytes[8..12].copy_from_slice(&(self.victims.len() as u32).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.history.device.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.history.inode.to_le_bytes());
        bytes[32..64].copy_from_slice(&self.base);
        bytes[64..320].copy_from_slice(&self.target.owner.encode()?);
        bytes[320..JOURNAL_HEADER].copy_from_slice(&anchor);
        let mut previous = 0;
        let mut ids = BTreeSet::new();
        for (index, victim) in self.victims.iter().enumerate() {
            victim.validate(&self.target)?;
            if victim.order.sequence <= previous || !ids.insert(victim.order.transaction) {
                return Err(SlotError::Invalid);
            }
            previous = victim.order.sequence;
            let offset = JOURNAL_HEADER + index * VICTIM_BYTES;
            bytes[offset..offset + 256].copy_from_slice(&victim.order.encode()?);
            bytes[offset + 256..offset + 768].copy_from_slice(&victim.record.encode()?);
            bytes[offset + 768..offset + 928].copy_from_slice(&victim.expiry);
            for (j, inode) in victim.inodes.iter().enumerate() {
                bytes[offset + 928 + j * 8..offset + 936 + j * 8]
                    .copy_from_slice(&inode.to_le_bytes());
            }
        }
        let hash = small_hash(b"NanoKVM app receipt prune v1\0", &bytes[..length - 32]);
        bytes[length - 32..].copy_from_slice(&hash);
        Ok(bytes)
    }
    fn decode(bytes: &[u8], device: u64) -> Result<Self> {
        if bytes.len() < JOURNAL_HEADER + 32
            || bytes.len() as u64 > JOURNAL_MAX
            || &bytes[..8] != b"NKAPPR01"
        {
            return Err(SlotError::Invalid);
        }
        let count =
            u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| SlotError::Invalid)?) as usize;
        if count > LEGACY_LIMIT as usize
            || bytes.len() != JOURNAL_HEADER + count * VICTIM_BYTES + 32
        {
            return Err(SlotError::Invalid);
        }
        let mut victims = Vec::with_capacity(count);
        for index in 0..count {
            let offset = JOURNAL_HEADER + index * VICTIM_BYTES;
            let mut inodes = [0; 3];
            for (j, inode) in inodes.iter_mut().enumerate() {
                *inode = u64::from_le_bytes(
                    bytes[offset + 928 + j * 8..offset + 936 + j * 8]
                        .try_into()
                        .map_err(|_| SlotError::Invalid)?,
                );
            }
            victims.push(Victim {
                order: Order::decode(&bytes[offset..offset + 256], device)?,
                record: Record::decode(&bytes[offset + 256..offset + 768])?,
                expiry: bytes[offset + 768..offset + 928]
                    .try_into()
                    .map_err(|_| SlotError::Invalid)?,
                inodes,
            });
        }
        let journal = Self {
            base: bytes[32..64].try_into().map_err(|_| SlotError::Invalid)?,
            history: Identity {
                device: u64::from_le_bytes(
                    bytes[16..24].try_into().map_err(|_| SlotError::Invalid)?,
                ),
                inode: u64::from_le_bytes(
                    bytes[24..32].try_into().map_err(|_| SlotError::Invalid)?,
                ),
            },
            target: Anchor::decode(&bytes[320..JOURNAL_HEADER], device)?,
            victims,
        };
        if journal.encode()?.as_slice() != bytes {
            return Err(SlotError::Invalid);
        }
        Ok(journal)
    }
}

fn journal_at(current: &File, device: u64, uid: u32) -> Result<Option<(Journal, File, [u8; 32])>> {
    let Some(mut file) = open_file(
        current,
        JOURNAL,
        device,
        uid,
        (JOURNAL_HEADER + 32) as u64,
        JOURNAL_MAX,
    )?
    else {
        return Ok(None);
    };
    let mut bytes = vec![0; file.metadata()?.len() as usize];
    file.read_exact(&mut bytes)?;
    let journal = Journal::decode(&bytes, device)?;
    let hash = bytes[bytes.len() - 32..]
        .try_into()
        .map_err(|_| SlotError::Invalid)?;
    Ok(Some((journal, file, hash)))
}

fn progress_at(
    store: &Store,
    path: &str,
    hash: &[u8; 32],
    count: usize,
) -> Result<Option<(Cursor, File)>> {
    let Some(mut file) = open_file(&store.current, path, store.device, store.uid, 96, 96)? else {
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
    if progress_bytes(cursor, hash, count)? != bytes {
        return Err(SlotError::Invalid);
    }
    Ok(Some((cursor, file)))
}

fn progress_bytes(cursor: Cursor, hash: &[u8; 32], count: usize) -> Result<[u8; 96]> {
    if cursor.index > count || (cursor.index == count && cursor.pending) {
        return Err(SlotError::Invalid);
    }
    let mut bytes = [0; 96];
    bytes[..8].copy_from_slice(b"NKAPPG01");
    bytes[8..40].copy_from_slice(hash);
    bytes[40..44].copy_from_slice(&(cursor.index as u32).to_le_bytes());
    bytes[44] = u8::from(cursor.pending);
    let sum = small_hash(b"NanoKVM app receipt progress v1\0", &bytes[..64]);
    bytes[64..].copy_from_slice(&sum);
    Ok(bytes)
}

fn save_progress(store: &Store, hash: &[u8; 32], count: usize, desired: Cursor) -> Result<()> {
    let previous = progress_at(store, PROGRESS, hash, count)?;
    cursor_step(previous.as_ref().map(|v| v.0), desired, count)?;
    let bytes = progress_bytes(desired, hash, count)?;
    match progress_at(store, PROGRESS_NEXT, hash, count)? {
        Some((next, file)) if next == desired => file.sync_all()?,
        Some(_) => return Err(SlotError::Invalid),
        None => publish(
            &store.current,
            PROGRESS_NEXT,
            store.device,
            store.uid,
            "receipt-cursor",
            |f| {
                f.write_all(&bytes)?;
                Ok(())
            },
        )?,
    }
    store.current.sync_all()?;
    let actual = progress_at(store, PROGRESS, hash, count)?;
    if actual.as_ref().map(|v| v.0) != previous.as_ref().map(|v| v.0) {
        return Err(SlotError::Invalid);
    }
    if let (Some((_, a)), Some((_, b))) = (&actual, &previous)
        && a.metadata()?.ino() != b.metadata()?.ino()
    {
        return Err(SlotError::Unsafe);
    }
    renameat(&store.current, PROGRESS_NEXT, &store.current, PROGRESS)?;
    point("receipt-cursor-renamed")?;
    store.current.sync_all()?;
    point("receipt-cursor-synced")
}

fn check_member(
    directory: &File,
    victim: &Victim,
    index: usize,
    uid: u32,
    absent_ok: bool,
) -> Result<Option<File>> {
    let expected = victim.bytes(index)?;
    let file = open_file(
        directory,
        MEMBERS[index],
        victim.order.directory.device,
        uid,
        expected.len() as u64,
        expected.len() as u64,
    )?;
    let Some(mut file) = file else {
        return if absent_ok {
            Ok(None)
        } else {
            Err(SlotError::Invalid)
        };
    };
    if file.metadata()?.ino() != victim.inodes[index] {
        return Err(SlotError::Unsafe);
    }
    let mut bytes = vec![0; expected.len()];
    file.read_exact(&mut bytes)?;
    if bytes != expected {
        return Err(SlotError::Invalid);
    }
    Ok(Some(file))
}

fn check_directory(
    directory: &File,
    victim: &Victim,
    uid: u32,
    removed: usize,
    pending: bool,
) -> Result<()> {
    protected_directory(directory, victim.order.directory.device, uid, true)?;
    if Identity::of(directory, victim.order.directory.device, uid)? != victim.order.directory {
        return Err(SlotError::Unsafe);
    }
    let mut names = BTreeSet::new();
    for (index, member) in MEMBERS.iter().enumerate() {
        if index < removed {
            if !absent(directory, member)? {
                return Err(SlotError::Invalid);
            }
        } else if check_member(directory, victim, index, uid, pending && index == removed)?
            .is_some()
        {
            names.insert((*member).to_owned());
        }
    }
    namespace(directory, &names)
}

fn budget(store: &Store, fresh: Option<u64>) -> Result<()> {
    let capacity = Capacity::read(&store.current)?;
    let mut demand = Footprint::new(capacity.unit)?;
    for size in fresh.into_iter().chain([96, 96, ANCHOR_BYTES as u64]) {
        demand.path(true)?;
        demand.file(size)?;
    }
    demand.check(capacity)?;
    Ok(())
}

fn publish_anchor(store: &Store, journal: &Journal) -> Result<()> {
    let parent = &store._lock.0;
    let current = anchor_at(parent, ANCHOR, store.device, store.uid)?;
    if current.as_ref().is_some_and(|v| v.0 == journal.target) {
        if !absent(parent, ANCHOR_NEXT)? {
            return Err(SlotError::Invalid);
        }
        current.ok_or(SlotError::Invalid)?.1.sync_all()?;
        parent.sync_all()?;
        return Ok(());
    }
    if base_hash(current.as_ref().map(|v| &v.0))? != journal.base {
        return Err(SlotError::Invalid);
    }
    let bytes = journal.target.encode()?;
    match anchor_at(parent, ANCHOR_NEXT, store.device, store.uid)? {
        Some((target, file)) if target == journal.target => file.sync_all()?,
        Some(_) => return Err(SlotError::Invalid),
        None => publish(
            parent,
            ANCHOR_NEXT,
            store.device,
            store.uid,
            "receipt-anchor",
            |f| {
                f.write_all(&bytes)?;
                Ok(())
            },
        )?,
    }
    parent.sync_all()?;
    let actual = anchor_at(parent, ANCHOR, store.device, store.uid)?;
    if actual.as_ref().map(|v| &v.0) != current.as_ref().map(|v| &v.0) {
        return Err(SlotError::Invalid);
    }
    if let (Some((_, a)), Some((_, b))) = (&actual, &current)
        && a.metadata()?.ino() != b.metadata()?.ino()
    {
        return Err(SlotError::Unsafe);
    }
    renameat(parent, ANCHOR_NEXT, parent, ANCHOR)?;
    point("receipt-anchor-renamed")?;
    parent.sync_all()?;
    point("receipt-anchor-synced")
}

fn execute(store: &Store, journal: &Journal, file: &File, hash: &[u8; 32]) -> Result<()> {
    let parent = &store._lock.0;
    let anchor = anchor_at(parent, ANCHOR, store.device, store.uid)?;
    let finished = anchor.as_ref().is_some_and(|v| v.0 == journal.target);
    if !finished && base_hash(anchor.as_ref().map(|v| &v.0))? != journal.base {
        return Err(SlotError::Invalid);
    }
    if let Some((next, _)) = anchor_at(parent, ANCHOR_NEXT, store.device, store.uid)?
        && (finished || next != journal.target)
    {
        return Err(SlotError::Invalid);
    }
    if journal.target.owner
        != load(parent, HEAD, store.device, store.uid)?
            .ok_or(SlotError::Invalid)?
            .order
        || journal
            .target
            .owner
            .check_directory(&store.current, store.device, store.uid)?
            != store.record()?
    {
        return Err(SlotError::Invalid);
    }
    let history = restore_fs::open_beneath(parent, "history", OFlags::RDONLY | OFlags::DIRECTORY)?;
    protected_directory(&history, store.device, store.uid, true)?;
    if Identity::of(&history, store.device, store.uid)? != journal.history {
        return Err(SlotError::Unsafe);
    }
    let count = journal.victims.len() * 5;
    if !finished {
        budget(store, None)?;
    }
    if let Some((next, _)) = progress_at(store, PROGRESS_NEXT, hash, count)? {
        save_progress(store, hash, count, next)?;
    }
    let mut cursor = match progress_at(store, PROGRESS, hash, count)? {
        Some((cursor, _)) => cursor,
        None if finished => Cursor {
            index: count,
            pending: false,
        },
        None => {
            // Before any progress publication, every original receipt must
            // still exist intact and the quarantine must be absent.
            if !absent(&history, GARBAGE)? {
                return Err(SlotError::Invalid);
            }
            for victim in &journal.victims {
                let directory = open_optional(&history, &name(victim.order.transaction))?
                    .ok_or(SlotError::Invalid)?;
                check_directory(&directory, victim, store.uid, 0, false)?;
            }
            let cursor = Cursor {
                index: 0,
                pending: false,
            };
            save_progress(store, hash, count, cursor)?;
            cursor
        }
    };
    if finished && (cursor.index != count || cursor.pending) {
        return Err(SlotError::Invalid);
    }
    let (kept, mut names) = retained_chain(
        &store._lock.0,
        Some(&store.current),
        store.device,
        store.uid,
        &journal.target.owner,
        Some(&journal.target),
    )?;
    let mut pins = Pins::new(&journal.target.owner, &store.record()?);
    for archive in &kept {
        let available = retained(
            &archive.directory,
            &archive.order,
            &archive.record,
            store.uid,
        )?;
        pins.observe(inactive(&archive.record)?.1, available);
        if archive.order.sequence < journal.target.floor.sequence && !available {
            return Err(SlotError::Invalid);
        }
    }
    pins.require_all()?;
    // Validate all original/quarantine/completed namespaces before any deletion.
    for (index, victim) in journal.victims.iter().enumerate() {
        let original = name(victim.order.transaction);
        let directory = open_optional(&history, &original)?;
        let step = cursor.index.saturating_sub(index * 5).min(5);
        if step == 0 {
            if let Some(directory) = directory {
                check_directory(&directory, victim, store.uid, 0, false)?;
                names.insert(original);
            } else if cursor.index == index * 5 && cursor.pending {
                let quarantine = open_optional(&history, GARBAGE)?.ok_or(SlotError::Invalid)?;
                check_directory(&quarantine, victim, store.uid, 0, false)?;
                names.insert(GARBAGE.to_owned());
            } else {
                return Err(SlotError::Invalid);
            }
        } else {
            if directory.is_some() {
                return Err(SlotError::Invalid);
            }
            if step < 5 {
                match open_optional(&history, GARBAGE)? {
                    Some(directory) => {
                        check_directory(
                            &directory,
                            victim,
                            store.uid,
                            (step - 1).min(3),
                            cursor.pending,
                        )?;
                        names.insert(GARBAGE.to_owned());
                    }
                    None if step == 4 && cursor.pending => {}
                    None => return Err(SlotError::Invalid),
                }
            }
        }
    }
    namespace(&history, &names)?;
    history.sync_all()?;
    while cursor.index < count {
        let index = cursor.index;
        let victim = &journal.victims[index / 5];
        let step = index % 5;
        let was_pending = cursor.pending;
        if !was_pending {
            cursor = cursor.successor(count)?;
            save_progress(store, hash, count, cursor)?;
        }
        point(&format!("receipt-step-{step}-pending"))?;
        let original = name(victim.order.transaction);
        if step == 0 {
            match (
                open_optional(&history, &original)?,
                open_optional(&history, GARBAGE)?,
            ) {
                (Some(directory), None) => {
                    check_directory(&directory, victim, store.uid, 0, false)?;
                    renameat_with(
                        &history,
                        &original,
                        &history,
                        GARBAGE,
                        RenameFlags::NOREPLACE,
                    )?;
                    point("receipt-quarantined")?;
                }
                (None, Some(directory)) if was_pending => {
                    check_directory(&directory, victim, store.uid, 0, false)?
                }
                _ => return Err(SlotError::Invalid),
            }
        } else if step < 4 {
            let directory = open_optional(&history, GARBAGE)?.ok_or(SlotError::Invalid)?;
            check_directory(&directory, victim, store.uid, step - 1, was_pending)?;
            if let Some(file) = check_member(&directory, victim, step - 1, store.uid, was_pending)?
            {
                let m = file.metadata()?;
                let named = statat(&directory, MEMBERS[step - 1], AtFlags::SYMLINK_NOFOLLOW)?;
                if (named.st_dev, named.st_ino) != (m.dev(), m.ino()) {
                    return Err(SlotError::Unsafe);
                }
                rustix::fs::unlinkat(&directory, MEMBERS[step - 1], AtFlags::empty())?;
                point(&format!("receipt-step-{step}-unlinked"))?;
            }
            directory.sync_all()?;
        } else {
            match open_optional(&history, GARBAGE)? {
                Some(directory) => {
                    check_directory(&directory, victim, store.uid, 3, false)?;
                    let named = statat(&history, GARBAGE, AtFlags::SYMLINK_NOFOLLOW)?;
                    if (named.st_dev, named.st_ino)
                        != (victim.order.directory.device, victim.order.directory.inode)
                    {
                        return Err(SlotError::Unsafe);
                    }
                    rustix::fs::unlinkat(&history, GARBAGE, AtFlags::REMOVEDIR)?;
                    point("receipt-directory-unlinked")?;
                }
                None if was_pending => {}
                None => return Err(SlotError::Invalid),
            }
        }
        history.sync_all()?;
        point(&format!("receipt-step-{step}-synced"))?;
        cursor = cursor.successor(count)?;
        save_progress(store, hash, count, cursor)?;
        point(&format!("receipt-step-{step}-advanced"))?;
    }
    publish_anchor(store, journal)?;
    if !absent(&store.current, PROGRESS_NEXT)? {
        return Err(SlotError::Invalid);
    }
    if let Some((cursor, pinned)) = progress_at(store, PROGRESS, hash, count)? {
        if cursor.index != count || cursor.pending {
            return Err(SlotError::Invalid);
        }
        remove_file(&store.current, PROGRESS, &pinned, store.uid)?;
        point("receipt-cursor-removed")?;
    }
    remove_file(&store.current, JOURNAL, file, store.uid)?;
    point("receipt-manifest-removed")
}

pub(in crate::update::app_slot::history) fn expire_receipts(
    store: &Store,
    head: &Order,
) -> Result<()> {
    if head.check_directory(&store.current, store.device, store.uid)? != store.record()? {
        return Err(SlotError::Invalid);
    }
    if let Some((journal, file, hash)) = journal_at(&store.current, store.device, store.uid)? {
        if journal.target.owner != *head {
            return Err(SlotError::Invalid);
        }
        return execute(store, &journal, &file, &hash);
    }
    require_no_journal(&store.current)?;
    let old = anchor_at(&store._lock.0, ANCHOR, store.device, store.uid)?;
    if head.sequence <= KEEP {
        if old.is_some() || !absent(&store._lock.0, ANCHOR_NEXT)? {
            return Err(SlotError::Invalid);
        }
        return Ok(());
    }
    if old.as_ref().is_some_and(|v| v.0.owner == *head) {
        chain(store, Some(head))?;
        return Ok(());
    }
    let archives = chain(store, Some(head))?;
    let floor = head.sequence - (KEEP - 1);
    let oldest = archives
        .iter()
        .find(|a| a.order.sequence == floor)
        .ok_or(SlotError::Invalid)?;
    let mut pins = Vec::with_capacity(2);
    let mut victims = Vec::with_capacity(archives.len());
    for archive in archives.iter().rev().filter(|a| a.order.sequence < floor) {
        let retained = retained(
            &archive.directory,
            &archive.order,
            &archive.record,
            store.uid,
        )?;
        if retained {
            if ![head.baseline, head.fallback].contains(&inactive(&archive.record)?.1)
                || pins.len() == 2
            {
                return Err(SlotError::Invalid);
            }
            pins.push(archive.order.clone());
        } else {
            let mut inodes = [0; 3];
            for (index, member) in MEMBERS.iter().enumerate() {
                inodes[index] = open_file(
                    &archive.directory,
                    member,
                    store.device,
                    store.uid,
                    [160, BYTES as u64, RECORD_BYTES as u64][index],
                    [160, BYTES as u64, RECORD_BYTES as u64][index],
                )?
                .ok_or(SlotError::Invalid)?
                .metadata()?
                .ino();
            }
            victims.push(Victim {
                order: archive.order.clone(),
                record: archive.record.clone(),
                expiry: load_expiry(
                    &archive.directory,
                    &archive.order,
                    &archive.record,
                    store.uid,
                )?
                .ok_or(SlotError::Invalid)?
                .0,
                inodes,
            });
        }
    }
    // Out-of-window pins precede the contiguous tail, not necessarily iteration
    // order after an old fallback is released; serialized order is canonical.
    pins.sort_by_key(|p| p.sequence);
    victims.sort_by_key(|v| v.order.sequence);
    let history = restore_fs::open_beneath(
        &store._lock.0,
        "history",
        OFlags::RDONLY | OFlags::DIRECTORY,
    )?;
    let journal = Journal {
        base: base_hash(old.as_ref().map(|v| &v.0))?,
        history: Identity::of(&history, store.device, store.uid)?,
        target: Anchor {
            owner: head.clone(),
            floor: oldest.order.clone(),
            pins,
        },
        victims,
    };
    let bytes = journal.encode()?;
    budget(store, Some(bytes.len() as u64))?;
    publish(
        &store.current,
        JOURNAL,
        store.device,
        store.uid,
        "receipt-manifest",
        |f| {
            f.write_all(&bytes)?;
            Ok(())
        },
    )?;
    point("receipt-manifest-published")?;
    let (saved, file, hash) =
        journal_at(&store.current, store.device, store.uid)?.ok_or(SlotError::Invalid)?;
    if saved.encode()? != bytes {
        return Err(SlotError::Invalid);
    }
    execute(store, &saved, &file, &hash)
}

pub(in crate::update::app_slot::history) fn receipt_query_guard(
    parent: &File,
    device: u64,
    uid: u32,
    id: [u8; 16],
) -> Result<()> {
    let Some(current) = open_optional(parent, CURRENT)? else {
        return Ok(());
    };
    protected_directory(&current, device, uid, true)?;
    if let Some((journal, _, _)) = journal_at(&current, device, uid)? {
        journal
            .target
            .owner
            .check_directory(&current, device, uid)?;
        if load(parent, HEAD, device, uid)?
            .ok_or(SlotError::Invalid)?
            .order
            != journal.target.owner
        {
            return Err(SlotError::Busy);
        }
        if journal.victims.iter().any(|v| v.order.transaction == id) {
            return Err(SlotError::Busy);
        }
    }
    Ok(())
}

fn point(name: &str) -> Result<()> {
    #[cfg(test)]
    {
        checkpoint(name);
        if std::env::var("NANOKVM_APP_SLOT_TEST_FAIL").as_deref() == Ok(name) {
            let inject = match std::env::var_os("NANOKVM_RECEIPT_TEST_FAIL_ONCE") {
                None => true,
                Some(path) => match std::fs::remove_file(path) {
                    Ok(()) => true,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                    Err(error) => return Err(error.into()),
                },
            };
            if inject {
                return Err(SlotError::Io(io::Error::other(
                    "injected app receipt failure",
                )));
            }
        }
    }
    #[cfg(not(test))]
    let _ = name;
    Ok(())
}

#[cfg(test)]
#[path = "app_slot_receipts_tests.rs"]
mod tests;
