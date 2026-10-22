//! Fixed private acceptance publication, never a target mutation/recovery API.
use super::*;
use rustix::fs::{
    AtFlags, Mode, RenameFlags, ResolveFlags, fchmod, openat2, renameat_with, unlinkat,
};
use std::io::{Seek, SeekFrom, Write};

enum Member {
    Active,
    Payload,
    Source,
    Next,
}
impl Member {
    fn name(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Payload => "payload",
            Self::Source => "source",
            Self::Next => ".state.next",
        }
    }
}

enum Publication {
    Accepted,
    Stop,
    Closed,
    Completed,
}

impl Publication {
    #[cfg(test)]
    fn label(&self) -> &'static str {
        match self {
            Self::Accepted => "state",
            Self::Stop => "stop",
            Self::Closed => "closed",
            Self::Completed => "completed",
        }
    }
}

struct OwnedMember {
    file: File,
    revision: Revision,
    hash: [u8; 32],
}

impl OwnedMember {
    fn check(&mut self, directory: &File, name: &str) -> Result<()> {
        if Revision::from(&self.file.metadata()?) != self.revision
            || Revision::from(&restore_fs::open_beneath(directory, name, OFlags::PATH)?.metadata()?)
                != self.revision
        {
            return Err(invalid());
        }
        self.file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let length = std::io::copy(
            &mut (&mut self.file).take(self.revision.bytes + 1),
            &mut hash,
        )?;
        if length != self.revision.bytes
            || hash.finalize().as_slice() != self.hash
            || Revision::from(&self.file.metadata()?) != self.revision
            || Revision::from(&restore_fs::open_beneath(directory, name, OFlags::PATH)?.metadata()?)
                != self.revision
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn private_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

pub(super) struct Source {
    _directory: Directory,
    bytes: Zeroizing<Vec<u8>>,
}

impl Source {
    fn capture(facts: &Facts) -> Result<Self> {
        let mut directory = Directory::open(Path::new("/"), false)?;
        let mut present = true;
        let mut depth = 0u32;
        for component in facts.home.components() {
            let std::path::Component::Normal(name) = component else {
                continue;
            };
            let name = name.to_str().ok_or_else(invalid)?;
            match restore_fs::open_beneath(
                &directory.file,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY,
            ) {
                Ok(file) => {
                    directory.file = file;
                    directory.check()?;
                    depth += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    present = false;
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        directory.lock(true)?;
        let before = directory.file.metadata()?;
        let pair = if present {
            super::super::super::pair::read_source(&directory)?
        } else {
            [None, None]
        };
        if Revision::from(&directory.file.metadata()?) != Revision::from(&before) {
            return Err(invalid());
        }
        let home = facts.home.as_os_str().as_encoded_bytes();
        let config_len = pair[0].as_ref().map_or(0, |bytes| bytes.len());
        let security_len = pair[1].as_ref().map_or(0, |bytes| bytes.len());
        let size = 128usize
            .checked_add(home.len())
            .and_then(|n| n.checked_add(config_len))
            .and_then(|n| n.checked_add(security_len))
            .ok_or_else(invalid)?;
        if home.len() > 4095
            || config_len > super::super::super::MAX_FILE_BYTES
            || security_len > super::super::super::MAX_FILE_BYTES
        {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(size));
        bytes.extend_from_slice(&[0; 128]);
        // Private source v2 additionally binds the SAME owned Pico launch.
        // A v1 source is not silently reinterpreted as carrying this proof.
        bytes[..8].copy_from_slice(b"NKPSRC02");
        bytes[8] = u8::from(present);
        bytes[9] = u8::from(pair[0].is_some());
        bytes[10] = u8::from(pair[1].is_some());
        bytes[11] = u8::from(facts.running_generation.is_some());
        if let Some(generation) = facts.running_generation {
            bytes[96..128].copy_from_slice(generation.private_bytes());
        }
        bytes[12..16].copy_from_slice(&depth.to_le_bytes());
        bytes[16..24].copy_from_slice(&before.dev().to_le_bytes());
        bytes[24..32].copy_from_slice(&before.ino().to_le_bytes());
        bytes[32..36].copy_from_slice(&before.uid().to_le_bytes());
        bytes[36..40].copy_from_slice(&before.mode().to_le_bytes());
        for (offset, length) in [(40, home.len()), (44, config_len), (48, security_len)] {
            bytes[offset..offset + 4].copy_from_slice(&(length as u32).to_le_bytes());
        }
        bytes[64..72].copy_from_slice(&before.mtime().to_le_bytes());
        bytes[72..80].copy_from_slice(&before.mtime_nsec().to_le_bytes());
        bytes[80..88].copy_from_slice(&before.ctime().to_le_bytes());
        bytes[88..96].copy_from_slice(&before.ctime_nsec().to_le_bytes());
        bytes.extend_from_slice(home);
        for member in pair.into_iter().flatten() {
            bytes.extend_from_slice(member.as_slice());
        }
        Ok(Self {
            _directory: directory,
            bytes,
        })
    }
}

/// Typed view of the private source captured at acceptance. It borrows the
/// credential-bearing bytes; never Debug/log it.
pub(super) struct SourceView<'a> {
    pub(super) home_present: bool,
    pub(super) config: Option<&'a [u8]>,
    pub(super) security: Option<&'a [u8]>,
}

pub(super) fn decode_source(bytes: &[u8]) -> Result<SourceView<'_>> {
    if bytes.len() < 128 || &bytes[..8] != b"NKPSRC02" {
        return Err(invalid());
    }
    let flag = |index: usize| match bytes[index] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid()),
    };
    let length = |offset: usize| -> Result<usize> {
        Ok(u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize)
    };
    let (present, config_present, security_present, generation) =
        (flag(8)?, flag(9)?, flag(10)?, flag(11)?);
    let (home, config, security) = (length(40)?, length(44)?, length(48)?);
    if bytes[52..64].iter().any(|byte| *byte != 0)
        || (!generation && bytes[96..128].iter().any(|byte| *byte != 0))
        || (!present && (config_present || security_present))
        || (!config_present && config != 0)
        || (!security_present && security != 0)
        || !(1..=4095).contains(&home)
    {
        return Err(invalid());
    }
    let total = 128usize
        .checked_add(home)
        .and_then(|n| n.checked_add(config))
        .and_then(|n| n.checked_add(security))
        .ok_or_else(invalid)?;
    if total != bytes.len() || bytes[128] != b'/' || bytes[128..128 + home].contains(&0) {
        return Err(invalid());
    }
    let config_start = 128 + home;
    let security_start = config_start + config;
    Ok(SourceView {
        home_present: present,
        config: config_present.then(|| &bytes[config_start..security_start]),
        security: security_present.then(|| &bytes[security_start..]),
    })
}

pub(super) struct Store {
    parent: File,
    directory: File,
    identity: (u64, u64),
    anchor: (bootstrap::Anchor, Revision),
    revision: Revision,
    snapshot: Snapshot,
    members: [Option<OwnedMember>; 3],
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = flock(&self.directory, FlockOperation::Unlock);
    }
}

impl Store {
    fn open() -> Result<Self> {
        let parent = Directory::open(Path::new("/etc/kvm"), false)?.file;
        bootstrap::check_next_absent(&parent)?;
        let anchor = bootstrap::read_anchor(&parent, 0)?.ok_or_else(invalid)?;
        let bootstrap::Anchor::Ready(epoch) = anchor.0 else {
            return Err(fenced());
        };
        let directory =
            restore_fs::open_beneath(&parent, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
        let m = directory.metadata()?;
        if m.uid() != 0 || m.dev() != parent.metadata()?.dev() || m.mode() & 0o7777 != 0o700 {
            return Err(invalid());
        }
        flock(&directory, FlockOperation::NonBlockingLockExclusive)
            .map_err(std::io::Error::from)?;
        let (bytes, revision) =
            bootstrap::read_member::<BYTES>(&directory, STATE, 0)?.ok_or_else(invalid)?;
        let snapshot = Snapshot::decode(bytes.as_slice())?;
        if snapshot.epoch != epoch || snapshot.active.is_some() {
            return Err(fenced());
        }
        let store = Self {
            parent,
            directory,
            identity: (m.dev(), m.ino()),
            anchor,
            revision,
            snapshot,
            members: [None, None, None],
        };
        store.inventory(false)?;
        store.check_bound()?;
        // Seal any prior empty bootstrap publication before accepting work.
        restore_fs::open_beneath(&store.parent, "picoclaw-enrollment", OFlags::RDONLY)?
            .sync_all()?;
        restore_fs::open_beneath(&store.directory, STATE, OFlags::RDONLY)?.sync_all()?;
        store.directory.sync_all()?;
        store.parent.sync_all()?;
        Ok(store)
    }

    fn inventory(&self, accepted: bool) -> Result<()> {
        self.inventory_exact([true, accepted, accepted, accepted])
    }

    /// Exactly these of state/active/payload/source; anything else fences.
    fn inventory_exact(&self, expected: [bool; 4]) -> Result<()> {
        let mut found = [false; 4];
        for entry in rustix::fs::Dir::read_from(&self.directory).map_err(std::io::Error::from)? {
            let entry = entry.map_err(std::io::Error::from)?;
            let slot = match entry.file_name().to_bytes() {
                b"." | b".." => continue,
                b"state" => 0,
                b"active" => 1,
                b"payload" => 2,
                b"source" => 3,
                _ => return Err(fenced()),
            };
            if !expected[slot] {
                return Err(fenced());
            }
            if found[slot] {
                return Err(invalid());
            }
            found[slot] = true;
        }
        if found != expected {
            return Err(invalid());
        }
        Ok(())
    }

    fn check_bound(&self) -> Result<()> {
        bootstrap::check_next_absent(&self.parent)?;
        let anchor = bootstrap::read_anchor(&self.parent, 0)?.ok_or_else(invalid)?;
        if anchor != self.anchor {
            return Err(invalid());
        }
        for file in [
            &self.directory,
            &restore_fs::open_beneath(&self.parent, DIRECTORY, OFlags::PATH)?,
        ] {
            let m = file.metadata()?;
            if (m.dev(), m.ino()) != self.identity || m.uid() != 0 || m.mode() & 0o7777 != 0o700 {
                return Err(invalid());
            }
        }
        if Revision::from(
            &restore_fs::open_beneath(&self.directory, STATE, OFlags::PATH)?.metadata()?,
        ) != self.revision
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn write(&self, member: Member, bytes: &[u8], touched: &mut bool) -> Result<OwnedMember> {
        self.check_bound()?;
        let mut file: File = openat2(
            &self.directory,
            member.name(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )
        .map_err(std::io::Error::from)?
        .into();
        *touched = true;
        fchmod(&file, Mode::from_raw_mode(0o600)).map_err(std::io::Error::from)?;
        file.write_all(bytes)?;
        #[cfg(test)]
        checkpoint(member.name(), "written")?;
        file.sync_all()?;
        let before = Revision::from(&file.metadata()?);
        file.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let length = std::io::copy(&mut (&mut file).take(bytes.len() as u64 + 1), &mut hash)?;
        let m = file.metadata()?;
        if length != bytes.len() as u64
            || hash.finalize()[..] != Sha256::digest(bytes)[..]
            || m.uid() != 0
            || m.dev() != self.identity.0
            || m.nlink() != 1
            || m.mode() & 0o7777 != 0o600
            || Revision::from(&m) != before
            || Revision::from(
                &restore_fs::open_beneath(&self.directory, member.name(), OFlags::PATH)?
                    .metadata()?,
            ) != before
        {
            return Err(invalid());
        }
        self.directory.sync_all()?;
        #[cfg(test)]
        checkpoint(member.name(), "durable")?;
        Ok(OwnedMember {
            file,
            revision: before,
            hash: Sha256::digest(bytes).into(),
        })
    }

    fn check_members(&mut self) -> Result<()> {
        for (name, owned) in ["active", "payload", "source"]
            .into_iter()
            .zip(&mut self.members)
        {
            owned
                .as_mut()
                .ok_or_else(invalid)?
                .check(&self.directory, name)?;
        }
        Ok(())
    }

    fn check_current(&mut self) -> Result<()> {
        self.check_bound()?;
        self.inventory(true)?;
        let (bytes, revision) =
            bootstrap::read_member::<BYTES>(&self.directory, STATE, 0)?.ok_or_else(invalid)?;
        if revision != self.revision || bytes.as_slice() != self.snapshot.encode()?.as_slice() {
            return Err(invalid());
        }
        self.check_members()
    }

    fn publish(
        &mut self,
        record: Record,
        touched: &mut bool,
        publication: Publication,
    ) -> Result<()> {
        self.snapshot.sequence = record.sequence;
        self.snapshot.active = Some(record);
        self.commit(touched, publication)
    }

    /// Publish the job's terminal receipt into its ring slot and clear the
    /// active record. The private members stay until `retire` checks them.
    fn publish_terminal(&mut self, record: Record, touched: &mut bool) -> Result<()> {
        if record.phase != Phase::Completed
            || record.sequence != self.snapshot.sequence
            || self
                .snapshot
                .active
                .map(|active| (active.sequence, active.nonce))
                != Some((record.sequence, record.nonce))
        {
            return Err(invalid());
        }
        let slot = ((record.sequence - 1) % RETAINED as u64) as usize;
        self.snapshot.active = None;
        self.snapshot.receipts[slot] = Some(record);
        self.commit(touched, Publication::Completed)
    }

    // The in-memory snapshot already holds the intended value: a failure at
    // any point leaves memory and disk unequal, which later checks fence.
    fn commit(&mut self, touched: &mut bool, publication: Publication) -> Result<()> {
        #[cfg(test)]
        checkpoint(publication.label(), "begin")?;
        #[cfg(not(test))]
        let _ = publication;
        let bytes = self.snapshot.encode()?;
        let file = self.write(Member::Next, bytes.as_slice(), touched)?;
        self.check_bound()?;
        renameat_with(
            &self.directory,
            Member::Next.name(),
            &self.directory,
            STATE,
            RenameFlags::empty(),
        )
        .map_err(std::io::Error::from)?;
        #[cfg(test)]
        checkpoint(publication.label(), "renamed")?;
        self.directory.sync_all()?;
        self.revision = Revision::from(&file.file.metadata()?);
        self.check_bound()?;
        let (published, revision) =
            bootstrap::read_member::<BYTES>(&self.directory, STATE, 0)?.ok_or_else(invalid)?;
        if revision != self.revision || published.as_slice() != bytes.as_slice() {
            return Err(invalid());
        }
        self.inventory(true)?;
        self.check_members()?;
        #[cfg(test)]
        checkpoint(publication.label(), "durable")?;
        Ok(())
    }
}

impl Store {
    /// Exact retirement after a durable terminal receipt. Each member is
    /// re-checked against its owned identity and content just before unlink;
    /// the active fence goes last, after payload and source are durably gone.
    fn retire(&mut self) -> Result<()> {
        if self.snapshot.active.is_some() {
            return Err(invalid());
        }
        self.check_bound()?;
        self.inventory(true)?;
        self.check_members()?;
        for (slot, member) in [
            (1, Member::Payload),
            (2, Member::Source),
            (0, Member::Active),
        ] {
            self.members[slot]
                .as_mut()
                .ok_or_else(invalid)?
                .check(&self.directory, member.name())?;
            unlinkat(&self.directory, member.name(), AtFlags::empty())
                .map_err(std::io::Error::from)?;
            #[cfg(test)]
            checkpoint(member.name(), "retired")?;
            if slot == 2 {
                // Payload/source removal is durable before the fence goes.
                self.directory.sync_all()?;
                self.inventory_exact([true, true, false, false])?;
            }
            self.members[slot] = None;
        }
        self.directory.sync_all()?;
        self.check_bound()?;
        self.inventory(false)
    }
}

fn support(facts: &mut Facts) -> Result<[u8; 32]> {
    let before = facts.image.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7022 != 0
        || !(1..=crate::update::helper_family::MAX_BACKEND_BYTES).contains(&before.len())
    {
        return Err(invalid());
    }
    let mut hash = Sha256::new();
    hash.update(b"NanoKVM Pico executing producer image v1\0");
    let length = std::io::copy(&mut (&mut facts.image).take(before.len() + 1), &mut hash)?;
    if length != before.len() || Revision::from(&facts.image.metadata()?) != Revision::from(&before)
    {
        return Err(invalid());
    }
    Ok(hash.finalize().into())
}

pub(super) fn perform(
    payload: &mut Payload,
    cursor: Cursor,
    nonce: [u8; 16],
) -> Result<Acceptance> {
    if nonce == [0; 16] || cursor.epoch == [0; 16] {
        return Err(invalid());
    }
    let request = payload.request.as_ref().ok_or_else(invalid)?;
    let kind = request.kind();
    let encoded = request.encode()?;
    let request_hash = private_digest(b"NanoKVM Pico request v1\0", encoded.as_slice());
    payload.store = Some(Store::open()?);
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    if cursor.epoch != store.snapshot.epoch {
        return Ok(Acceptance::Expired);
    }
    for receipt in store.snapshot.receipts.iter().flatten() {
        if receipt.nonce == nonce {
            if cursor.sequence.checked_add(1) != Some(receipt.sequence)
                || receipt.kind != kind
                || receipt.request != request_hash
                || receipt.home != payload.facts.home_fingerprint
            {
                return Err(invalid());
            }
            return Ok(Acceptance::Existing(JobId {
                epoch: cursor.epoch,
                sequence: receipt.sequence,
                nonce,
            }));
        }
    }
    if cursor.sequence < store.snapshot.sequence {
        return Ok(Acceptance::Expired);
    }
    if cursor.sequence != store.snapshot.sequence {
        return Err(invalid());
    }
    let sequence = cursor.sequence.checked_add(1).ok_or_else(invalid)?;
    let support = support(&mut payload.facts)?;
    payload.source = Some(Source::capture(&payload.facts)?);
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    let record = Record {
        sequence,
        nonce,
        boot: payload.facts.boot,
        home: payload.facts.home_fingerprint,
        support,
        request: request_hash,
        source: private_digest(b"NanoKVM Pico source v2\0", source.bytes.as_slice()),
        kind,
        phase: Phase::Accepted,
        was_running: payload.facts.running_generation.is_some(),
        resume_allowed: payload.facts.running_generation.is_some() && kind != Kind::Remove,
        uncertain: false,
        outcome: Outcome::Pending,
        runtime: Runtime::Pending,
    };
    let mut active = Zeroizing::new([0; 352]);
    active[..8].copy_from_slice(b"NKPINT01");
    active[8..24].copy_from_slice(&cursor.epoch);
    active[24..32].copy_from_slice(&cursor.sequence.to_le_bytes());
    active[64..320].copy_from_slice(&record.encode()?);
    let hash = private_digest(b"NanoKVM Pico active intent v1\0", &active[..320]);
    active[320..].copy_from_slice(&hash);
    store.members[0] =
        Some(store.write(Member::Active, active.as_slice(), &mut payload.touched)?);
    store.members[1] =
        Some(store.write(Member::Payload, encoded.as_slice(), &mut payload.touched)?);
    store.members[2] = Some(store.write(
        Member::Source,
        source.bytes.as_slice(),
        &mut payload.touched,
    )?);
    store.publish(record, &mut payload.touched, Publication::Accepted)?;
    Ok(Acceptance::Accepted(JobId {
        epoch: cursor.epoch,
        sequence,
        nonce,
    }))
}

pub(super) fn advance(payload: &mut Payload, advance: Advance) -> Result<TransitionStatus> {
    if matches!(advance, Advance::Settle) {
        return settle(payload);
    }
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    store.check_current()?;
    let mut record = store.snapshot.active.ok_or_else(invalid)?;
    let id = JobId {
        epoch: store.snapshot.epoch,
        sequence: record.sequence,
        nonce: record.nonce,
    };
    if record.uncertain
        || record.boot != payload.facts.boot
        || record.home != payload.facts.home_fingerprint
    {
        return Err(fenced());
    }
    let (publication, status) = match advance {
        Advance::Stop(expected)
            if expected == id && record.phase == Phase::Accepted && record.was_running =>
        {
            record.phase = Phase::Stopping;
            (Publication::Stop, TransitionStatus::Stopping)
        }
        Advance::Closed(proof)
            if proof.matches(id, record.boot, record.home)
                && matches!(record.phase, Phase::Accepted | Phase::Stopping) =>
        {
            record.phase = Phase::Closed;
            (Publication::Closed, TransitionStatus::Closed)
        }
        _ => return Err(fenced()),
    };
    // This path is an explicit Stop, not an ordinary automatic quiesce. The
    // permission can only fall and remains distinct from initial was_running.
    record.resume_allowed = false;
    store.publish(record, &mut payload.touched, publication)?;
    Ok(status)
}

/// Ordinary Startup settlement, entered only from Accepted without an explicit
/// Stop. A canonical no-op records its terminal receipt and retires the job
/// without stopping a live runtime or touching the pair; any other result
/// leaves the accepted job exactly as it is.
pub(super) fn settle(payload: &mut Payload) -> Result<TransitionStatus> {
    let store = payload.store.as_mut().ok_or_else(invalid)?;
    store.check_current()?;
    let mut record = store.snapshot.active.ok_or_else(invalid)?;
    if record.uncertain
        || record.boot != payload.facts.boot
        || record.home != payload.facts.home_fingerprint
        || record.phase != Phase::Accepted
    {
        return Err(fenced());
    }
    if record.kind != Kind::Startup {
        // The other fixed operations have no settlement executor yet.
        return Ok(TransitionStatus::Refused);
    }
    let source = payload.source.as_ref().ok_or_else(invalid)?;
    let view = decode_source(source.bytes.as_slice())?;
    let (true, Some(config)) = (view.home_present, view.config) else {
        // Startup never creates a missing Home or config.
        return Ok(TransitionStatus::Refused);
    };
    let Ok(documents) = crate::update::picoclaw_startup::decode(config, view.security) else {
        return Ok(TransitionStatus::Refused);
    };
    let internal = crate::update::picoclaw_token::observe()?;
    let decision = match crate::update::picoclaw_startup::classify(
        &documents,
        internal.as_deref().map(String::as_str),
    ) {
        Ok(decision) => decision,
        Err(_) => return Ok(TransitionStatus::Refused),
    };
    if decision != crate::update::picoclaw_startup::Decision::Noop {
        return Ok(TransitionStatus::ChangeRequired);
    }
    record.phase = Phase::Completed;
    record.outcome = Outcome::Noop;
    record.runtime = if record.was_running && !record.resume_allowed {
        Runtime::Suppressed
    } else {
        Runtime::Unchanged
    };
    store.publish_terminal(record, &mut payload.touched)?;
    store.retire()?;
    Ok(TransitionStatus::Completed)
}

#[cfg(test)]
fn checkpoint(member: &str, phase: &str) -> Result<()> {
    let point = format!("{member}-{phase}");
    if std::env::var("NANOKVM_PICO_ACCEPT_FAIL").as_deref() == Ok(point.as_str()) {
        return Err(invalid());
    }
    if std::env::var("NANOKVM_PICO_ACCEPT_POINT").as_deref() == Ok(point.as_str()) {
        println!("pico-accept-checkpoint-ready");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
    Ok(())
}
