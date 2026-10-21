//! A private durable intent is the commit point for enrolled Rust pair readers.
//! Native readers/writers still require independent stop/join/enrollment.
use super::*;
use sha2::{Digest, Sha256};

const JOURNAL: &str = ".picoclaw-config-pair";
const MAGIC: &[u8; 16] = b"NKVMPCFGPAIR\0\x01\0\0";
const HEADER: usize = 192;
const MAX_JOURNAL: usize = HEADER + 2 * MAX_FILE_BYTES;
type Bytes = Option<Zeroizing<Vec<u8>>>;
type Hash = Option<[u8; 32]>;

fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn record_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(&bytes[..160]);
    hash.update(&bytes[HEADER..]);
    hash.finalize().into()
}

/// Directory SH/EX is held by the caller. Recheck both names, not only open fds.
pub(super) fn snapshot(directory: &Directory) -> Result<[Bytes; 2]> {
    let before = [directory.inspect(CONFIG)?, directory.inspect(SECURITY)?];
    let data = [directory.read(CONFIG)?, directory.read(SECURITY)?];
    if before != [directory.inspect(CONFIG)?, directory.inspect(SECURITY)?] {
        return Err(AppError::Conflict(
            "picoclaw configuration changed during read".into(),
        ));
    }
    Ok(data)
}

struct Record {
    before: [Hash; 2],
    after: RawDocuments,
}
impl Record {
    fn after(&self) -> [Option<&[u8]>; 2] {
        [
            Some(self.after.config.as_slice()),
            self.after.security.as_deref().map(|value| value.as_slice()),
        ]
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let values = self.after();
        let mut bytes = Zeroizing::new(vec![0; HEADER]);
        bytes[..16].copy_from_slice(MAGIC);
        bytes[16] = u8::from(self.before[0].is_some())
            | (u8::from(self.before[1].is_some()) << 1)
            | (u8::from(values[1].is_some()) << 2);
        bytes[24..28].copy_from_slice(&(self.after.config.len() as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&(values[1].map_or(0, <[u8]>::len) as u32).to_le_bytes());
        for (index, hash) in self.before.iter().enumerate() {
            if let Some(hash) = hash {
                bytes[32 + index * 32..64 + index * 32].copy_from_slice(hash);
            }
        }
        for (index, value) in values.into_iter().enumerate() {
            if let Some(value) = value {
                bytes[96 + index * 32..128 + index * 32].copy_from_slice(&digest(value));
                bytes.extend_from_slice(value);
            }
        }
        let checksum = record_digest(&bytes);
        bytes[160..HEADER].copy_from_slice(&checksum);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER
            || bytes.len() > MAX_JOURNAL
            || &bytes[..16] != MAGIC
            || bytes[16] & !7 != 0
            || bytes[17..24] != [0; 7]
            || record_digest(bytes).as_slice() != &bytes[160..HEADER]
        {
            return Err(invalid());
        }
        let config_len =
            u32::from_le_bytes(bytes[24..28].try_into().map_err(|_| invalid())?) as usize;
        let security_len =
            u32::from_le_bytes(bytes[28..32].try_into().map_err(|_| invalid())?) as usize;
        let security_present = bytes[16] & 4 != 0;
        if config_len > MAX_FILE_BYTES
            || security_len > MAX_FILE_BYTES
            || bytes.len() != HEADER + config_len + security_len
            || (!security_present
                && (security_len != 0 || bytes[128..160] != [0; 32] || bytes[16] & 2 != 0))
        {
            return Err(invalid());
        }
        let mut before = [None; 2];
        for (index, slot) in before.iter_mut().enumerate() {
            let stored = &bytes[32 + index * 32..64 + index * 32];
            if bytes[16] & (1 << index) != 0 {
                *slot = Some(stored.try_into().map_err(|_| invalid())?);
            } else if stored != [0; 32] {
                return Err(invalid());
            }
        }
        let config = &bytes[HEADER..HEADER + config_len];
        let security = &bytes[HEADER + config_len..];
        if digest(config).as_slice() != &bytes[96..128]
            || (security_present && digest(security).as_slice() != &bytes[128..160])
        {
            return Err(invalid());
        }
        Ok(Self {
            before,
            after: RawDocuments {
                config: Zeroizing::new(config.to_vec()),
                security: security_present.then(|| Zeroizing::new(security.to_vec())),
            },
        })
    }

    fn check_current(&self, current: &[Bytes; 2]) -> Result<()> {
        for (index, desired) in self.after().into_iter().enumerate() {
            let actual = current[index].as_deref().map(|value| digest(value));
            if actual != self.before[index] && actual != desired.map(digest) {
                return Err(AppError::Conflict(
                    "picoclaw pair recovery found foreign state".into(),
                ));
            }
        }
        Ok(())
    }
}

struct Pending {
    record: Record,
    revision: Revision,
}

fn pending(directory: &Directory) -> Result<Option<Pending>> {
    let Some(revision) = directory.inspect_bounded(JOURNAL, MAX_JOURNAL)? else {
        return Ok(None);
    };
    let bytes = directory
        .read_bounded(JOURNAL, MAX_JOURNAL)?
        .ok_or_else(invalid)?;
    let record = Record::decode(&bytes)?;
    if directory.inspect_bounded(JOURNAL, MAX_JOURNAL)?.as_ref() != Some(&revision) {
        return Err(invalid());
    }
    Ok(Some(Pending { record, revision }))
}

pub(super) fn read(directory: &Directory) -> Result<RawDocuments> {
    let journal = pending(directory)?;
    let mut current = snapshot(directory)?;
    if let Some(journal) = journal {
        journal.record.check_current(&current)?;
        Ok(journal.record.after)
    } else {
        Ok(RawDocuments {
            config: current[0]
                .take()
                .ok_or_else(|| AppError::Config("picoclaw config is missing".into()))?,
            security: current[1].take(),
        })
    }
}

pub(super) fn recover(directory: &Directory) -> Result<()> {
    if let Some(journal) = pending(directory)? {
        // Visibility does not prove the interrupted publisher synced its
        // journal rename. Re-establish durable intent before touching either
        // canonical destination; normal publish already has its own fence.
        let file =
            restore_fs::open_beneath(&directory.file, JOURNAL, OFlags::RDONLY | OFlags::NONBLOCK)?;
        if Revision::from(&file.metadata()?) != journal.revision {
            return Err(invalid());
        }
        file.sync_all()?;
        directory.file.sync_all()?;
        if directory.inspect_bounded(JOURNAL, MAX_JOURNAL)?.as_ref() != Some(&journal.revision) {
            return Err(invalid());
        }
        checkpoint("recovery-intent-synced");
        finish(directory, journal)?;
    }
    Ok(())
}

pub(super) fn publish(directory: &Directory, config: &[u8], security: Option<&[u8]>) -> Result<()> {
    if config.len() > MAX_FILE_BYTES || security.is_some_and(|bytes| bytes.len() > MAX_FILE_BYTES) {
        return Err(invalid());
    }
    let current = snapshot(directory)?;
    if security.is_none() && current[1].is_some() {
        return Err(invalid());
    }
    let record = Record {
        before: [
            current[0].as_deref().map(|value| digest(value)),
            current[1].as_deref().map(|value| digest(value)),
        ],
        after: RawDocuments {
            config: Zeroizing::new(config.to_vec()),
            security: security.map(|bytes| Zeroizing::new(bytes.to_vec())),
        },
    };
    let bytes = record.encode();
    let mut staged = directory.temporary(MAX_JOURNAL)?;
    staged.file.write_all(&bytes)?;
    staged.file.sync_all()?;
    checkpoint("journal-file-synced");
    staged.publish(JOURNAL, None)?;
    checkpoint("journal-published");
    // After an error here intent visibility/durability is ambiguous. Do not
    // delete or retry it as an uncommitted temporary.
    directory.file.sync_all()?;
    checkpoint("journal-parent-synced");
    finish(directory, pending(directory)?.ok_or_else(invalid)?)
}

fn finish(directory: &Directory, journal: Pending) -> Result<()> {
    // Validate both destinations BEFORE touching either, including on recovery.
    journal.record.check_current(&snapshot(directory)?)?;
    for (index, desired) in journal.record.after().into_iter().enumerate() {
        let name = [CONFIG, SECURITY][index];
        let Some(desired) = desired else {
            continue;
        };
        let current = directory.read(name)?;
        let actual = current.as_deref().map(|value| digest(value));
        if actual != journal.record.before[index] && actual != Some(digest(desired)) {
            return Err(AppError::Conflict(
                "picoclaw pair recovery found foreign state".into(),
            ));
        }
        if actual != Some(digest(desired)) {
            let before = directory.inspect(name)?;
            let mut staged = directory.temporary(MAX_FILE_BYTES)?;
            staged.file.write_all(desired)?;
            staged.file.sync_all()?;
            staged.publish(name, before)?;
        } else {
            // Recovery may find a rename whose parent sync did not finish.
            // Fence existing content too, before retiring its durable intent.
            restore_fs::open_beneath(&directory.file, name, OFlags::RDONLY | OFlags::NONBLOCK)?
                .sync_all()?;
        }
        checkpoint(if index == 0 {
            "config-published"
        } else {
            "security-published"
        });
        directory.file.sync_all()?;
        checkpoint(if index == 0 {
            "config-parent-synced"
        } else {
            "security-parent-synced"
        });
    }
    let current = snapshot(directory)?;
    for (index, desired) in journal.record.after().into_iter().enumerate() {
        if current[index].as_deref().map(|value| value.as_slice()) != desired {
            return Err(invalid());
        }
    }
    checkpoint("pair-verified");
    if directory.inspect_bounded(JOURNAL, MAX_JOURNAL)? != Some(journal.revision) {
        return Err(invalid());
    }
    unlinkat(&directory.file, JOURNAL, AtFlags::empty()).map_err(std::io::Error::from)?;
    checkpoint("journal-removed");
    directory.file.sync_all()?;
    checkpoint("journal-retired");
    Ok(())
}

fn checkpoint(_name: &str) {
    #[cfg(all(test, feature = "sandbox-test-fixture"))]
    if std::env::var("NANOKVM_PICO_PAIR_CUT").as_deref() == Ok(_name) {
        println!("pico-pair-cut:{_name}");
        let _ = std::io::stdout().flush();
        let mut resume = [0];
        let _ = std::io::stdin().read_exact(&mut resume);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(security: bool) -> Record {
        Record {
            before: [
                Some(digest(b"old JSON")),
                security.then(|| digest(b"old YAML")),
            ],
            after: RawDocuments {
                config: Zeroizing::new(b"new JSON\0with bytes".to_vec()),
                security: security.then(|| Zeroizing::new(b"new YAML\0with bytes".to_vec())),
            },
        }
    }

    #[test]
    fn pair_record_roundtrip_preserves_presence_and_exact_bytes() {
        for has_config in [false, true] {
            for security in [false, true] {
                let mut original = record(security);
                if !has_config {
                    original.before[0] = None;
                }
                let encoded = original.encode();
                let decoded = Record::decode(&encoded).unwrap();
                assert_eq!(decoded.before, original.before);
                assert_eq!(decoded.after(), original.after());
            }
        }
    }

    #[test]
    fn pair_record_rejects_every_corruption_truncation_and_trailing_byte() {
        let original = record(true).encode();
        for offset in 0..original.len() {
            let mut changed = original.clone();
            changed[offset] ^= 1;
            assert!(Record::decode(&changed).is_err(), "offset {offset}");
            assert!(
                Record::decode(&original[..offset]).is_err(),
                "prefix {offset}"
            );
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(Record::decode(&trailing).is_err());
    }

    #[test]
    fn pair_record_rejects_unknown_schema_invalid_presence_and_oversize() {
        for offset in [0, 13, 16, 17, 24, 28] {
            let mut changed = record(false).encode();
            changed[offset] ^= 0x80;
            let checksum = record_digest(&changed);
            changed[160..HEADER].copy_from_slice(&checksum);
            assert!(Record::decode(&changed).is_err(), "offset {offset}");
        }
        let mut absent_security = record(false);
        absent_security.before[1] = Some(digest(b"must not delete this file"));
        assert!(Record::decode(&absent_security.encode()).is_err());
        let mut oversize = record(false);
        oversize.after.config.resize(MAX_FILE_BYTES + 1, 0);
        assert!(Record::decode(&oversize.encode()).is_err());
    }

    #[test]
    fn pair_record_accepts_only_expected_old_or_committed_new_members() {
        let journal = record(true);
        for first in [b"old JSON".as_slice(), journal.after.config.as_slice()] {
            for second in [
                b"old YAML".as_slice(),
                journal.after.security.as_ref().unwrap().as_slice(),
            ] {
                assert!(
                    journal
                        .check_current(&[
                            Some(Zeroizing::new(first.to_vec())),
                            Some(Zeroizing::new(second.to_vec())),
                        ])
                        .is_ok()
                );
            }
        }
        for bad in [None, Some(Zeroizing::new(b"foreign".to_vec()))] {
            assert!(
                journal
                    .check_current(&[bad, Some(Zeroizing::new(b"old YAML".to_vec()))])
                    .is_err()
            );
        }
    }
}
