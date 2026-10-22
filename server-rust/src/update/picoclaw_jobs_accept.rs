//! Fixed private acceptance publication, never a target mutation/recovery API.
use super::*;
use rustix::fs::{Mode, RenameFlags, ResolveFlags, fchmod, openat2, renameat_with};
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
        bytes[..8].copy_from_slice(b"NKPSRC01");
        bytes[8] = u8::from(present);
        bytes[9] = u8::from(pair[0].is_some());
        bytes[10] = u8::from(pair[1].is_some());
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

pub(super) struct Store {
    parent: File,
    directory: File,
    identity: (u64, u64),
    anchor: (bootstrap::Anchor, Revision),
    revision: Revision,
    snapshot: Snapshot,
    members: [Option<File>; 3],
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
        let mut found = [false; 4];
        for entry in rustix::fs::Dir::read_from(&self.directory).map_err(std::io::Error::from)? {
            let entry = entry.map_err(std::io::Error::from)?;
            let slot = match entry.file_name().to_bytes() {
                b"." | b".." => continue,
                b"state" => 0,
                b"active" if accepted => 1,
                b"payload" if accepted => 2,
                b"source" if accepted => 3,
                _ => return Err(fenced()),
            };
            if found[slot] {
                return Err(invalid());
            }
            found[slot] = true;
        }
        if found != [true, accepted, accepted, accepted] {
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

    fn write(&self, member: Member, bytes: &[u8], touched: &mut bool) -> Result<File> {
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
        Ok(file)
    }

    fn publish(&mut self, record: Record, touched: &mut bool) -> Result<()> {
        self.snapshot.sequence = record.sequence;
        self.snapshot.active = Some(record);
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
        checkpoint(STATE, "renamed")?;
        self.directory.sync_all()?;
        self.revision = Revision::from(&file.metadata()?);
        self.check_bound()?;
        let (bytes, revision) =
            bootstrap::read_member::<BYTES>(&self.directory, STATE, 0)?.ok_or_else(invalid)?;
        let state = Snapshot::decode(bytes.as_slice())?;
        if revision != self.revision
            || state.active != Some(record)
            || state.sequence != record.sequence
        {
            return Err(invalid());
        }
        self.inventory(true)?;
        for (name, owned) in ["active", "payload", "source"]
            .into_iter()
            .zip(&self.members)
        {
            let file = owned.as_ref().ok_or_else(invalid)?;
            if Revision::from(
                &restore_fs::open_beneath(&self.directory, name, OFlags::PATH)?.metadata()?,
            ) != Revision::from(&file.metadata()?)
            {
                return Err(invalid());
            }
        }
        #[cfg(test)]
        checkpoint(STATE, "durable")?;
        Ok(())
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
        source: private_digest(b"NanoKVM Pico source v1\0", source.bytes.as_slice()),
        kind,
        phase: Phase::Accepted,
        was_running: payload.facts.was_running,
        resume_allowed: payload.facts.was_running && kind != Kind::Remove,
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
    store.publish(record, &mut payload.touched)?;
    Ok(Acceptance::Accepted(JobId {
        epoch: cursor.epoch,
        sequence,
        nonce,
    }))
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
