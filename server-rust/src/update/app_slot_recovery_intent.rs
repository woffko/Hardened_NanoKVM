//! Bounded fixed-name recovery receipt. It selects one pinned transaction,
//! including after current->history; it never grants native lifetime authority.
use super::*;

const INTENT: &str = "recovery";
const NEXT: &str = ".recovery.next";
const INTENT_MAGIC: &[u8; 8] = b"NKAPPR01";
const PREFIX: usize = 24 + RECORD_BYTES;
const BYTES: usize = PREFIX + 32;

pub(super) struct Intent {
    record: Record,
    directory: Identity,
    inode: u64,
}

fn absent(parent: &File, name: &str) -> Result<bool> {
    match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn require_absent(parent: &File) -> Result<()> {
    if absent(parent, INTENT)? && absent(parent, NEXT)? {
        Ok(())
    } else {
        Err(SlotError::Busy)
    }
}

pub(super) fn load(parent: &File, device: u64, uid: u32) -> Result<Option<Intent>> {
    // Any interrupted publication is evidence, never a candidate to repair.
    if !absent(parent, NEXT)? {
        return Err(SlotError::Invalid);
    }
    if absent(parent, INTENT)? {
        return Ok(None);
    }
    let pinned = restore_fs::open_beneath(parent, INTENT, OFlags::PATH)?;
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
    let mut file = restore_fs::open_beneath(parent, INTENT, OFlags::RDONLY | OFlags::NONBLOCK)?;
    let reopened = file.metadata()?;
    if (m.dev(), m.ino(), m.uid(), m.mode(), m.nlink(), m.len())
        != (
            reopened.dev(),
            reopened.ino(),
            reopened.uid(),
            reopened.mode(),
            reopened.nlink(),
            reopened.len(),
        )
    {
        return Err(SlotError::Unsafe);
    }
    let mut bytes = [0; BYTES];
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0])? != 0
        || &bytes[..8] != INTENT_MAGIC
        || record_hash(&bytes[..PREFIX]) != bytes[PREFIX..]
    {
        return Err(SlotError::Invalid);
    }
    let directory = Identity {
        device: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| SlotError::Invalid)?),
        inode: u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| SlotError::Invalid)?),
    };
    let record = Record::decode(&bytes[24..PREFIX])?;
    if directory.device != device || directory.inode == 0 || record.old.device != device {
        return Err(SlotError::Invalid);
    }
    Ok(Some(Intent {
        record,
        directory,
        inode: m.ino(),
    }))
}

impl Intent {
    pub(super) fn select(&self, parent: &File, current: Option<File>, uid: u32) -> Result<File> {
        let archived = current.is_none();
        let directory = if let Some(current) = current {
            current
        } else {
            let history =
                restore_fs::open_beneath(parent, "history", OFlags::RDONLY | OFlags::DIRECTORY)?;
            protected_directory(&history, self.directory.device, uid, true)?;
            let name = format!("{:032x}", u128::from_be_bytes(self.record.transaction));
            restore_fs::open_beneath(&history, name.as_str(), OFlags::RDONLY | OFlags::DIRECTORY)?
        };
        if Identity::of(&directory, self.directory.device, uid)? != self.directory {
            return Err(SlotError::Invalid);
        }
        protected_directory(&directory, self.directory.device, uid, true)?;
        let actual = read_record_at(&directory, self.directory.device, uid)?;
        if archived && !matches!(actual.phase, Phase::Committed | Phase::RolledBack) {
            return Err(SlotError::Invalid);
        }
        self.check_record(&actual)?;
        Ok(directory)
    }

    fn check_record(&self, actual: &Record) -> Result<()> {
        let mut expected = self.record.clone();
        // Recovery may only preserve Committed or move an uncommitted record
        // toward RolledBack; it never upgrades an uncommitted receipt to commit.
        let phase_matches = actual.phase == expected.phase
            || (!matches!(expected.phase, Phase::Committed | Phase::RolledBack)
                && matches!(actual.phase, Phase::RollingBack | Phase::RolledBack));
        if !phase_matches {
            return Err(SlotError::Invalid);
        }
        expected.phase = actual.phase;
        if expected != *actual {
            return Err(SlotError::Invalid);
        }
        Ok(())
    }
}

impl Store {
    pub(super) fn recovery_intent(&self, record: &Record) -> Result<Intent> {
        if let Some(intent) = load(&self._lock.0, self.device, self.uid)? {
            intent.check_record(record)?;
            if Identity::of(&self.current, self.device, self.uid)? != intent.directory {
                return Err(SlotError::Invalid);
            }
            return Ok(intent);
        }
        let directory = Identity::of(&self.current, self.device, self.uid)?;
        let mut bytes = [0; BYTES];
        bytes[..8].copy_from_slice(INTENT_MAGIC);
        bytes[8..16].copy_from_slice(&directory.device.to_le_bytes());
        bytes[16..24].copy_from_slice(&directory.inode.to_le_bytes());
        bytes[24..PREFIX].copy_from_slice(&record.encode()?);
        let hash = record_hash(&bytes[..PREFIX]);
        bytes[PREFIX..].copy_from_slice(&hash);
        let mut file: File = openat2(
            &self._lock.0,
            NEXT,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        )?
        .into();
        rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        renameat_with(
            &self._lock.0,
            NEXT,
            &self._lock.0,
            INTENT,
            RenameFlags::NOREPLACE,
        )?;
        self._lock.0.sync_all()?;
        load(&self._lock.0, self.device, self.uid)?.ok_or(SlotError::Invalid)
    }

    pub(super) fn finish_recovery_intent(&self, intent: &Intent) -> Result<()> {
        let actual = load(&self._lock.0, self.device, self.uid)?.ok_or(SlotError::Invalid)?;
        if actual.inode != intent.inode
            || actual.directory != intent.directory
            || actual.record != intent.record
        {
            return Err(SlotError::Invalid);
        }
        rustix::fs::unlinkat(&self._lock.0, INTENT, AtFlags::empty())?;
        self._lock.0.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::app_slot::tests::{Fixture, Position};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    #[test]
    fn receipt_selects_only_exact_current_or_archived_inode_and_context() {
        for committed in [false, true] {
            let fixture = Fixture::new(
                if committed {
                    Phase::Committed
                } else {
                    Phase::Published
                },
                Position::Published,
            );
            let store = fixture.store(true).unwrap();
            let intent = store.recovery_intent(&fixture.record).unwrap();
            assert!(require_absent(&store._lock.0).is_err());
            assert!(
                intent
                    .select(
                        &store._lock.0,
                        Some(store.current.try_clone().unwrap()),
                        store.uid
                    )
                    .is_ok()
            );
            store.recover().unwrap();
            let history = fixture.root.path().join(DIRECTORY).join("history");
            fs::create_dir(&history).unwrap();
            fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
            let archive = history.join(format!(
                "{:032x}",
                u128::from_be_bytes(fixture.record.transaction)
            ));
            fs::rename(fixture.current(), &archive).unwrap();
            assert!(intent.select(&store._lock.0, None, store.uid).is_ok());
            fs::rename(&archive, history.join("preserved-original")).unwrap();
            fs::create_dir(&archive).unwrap();
            fs::set_permissions(&archive, fs::Permissions::from_mode(0o700)).unwrap();
            fs::copy(
                history.join("preserved-original/state"),
                archive.join(STATE),
            )
            .unwrap();
            assert!(intent.select(&store._lock.0, None, store.uid).is_err());
            assert!(history.join("preserved-original").exists());
            store.finish_recovery_intent(&intent).unwrap();
            require_absent(&store._lock.0).unwrap();
        }
    }

    #[test]
    fn invalid_receipts_and_incomplete_publication_are_preserved_not_repaired() {
        for fault in [
            "hash", "mode", "short", "symlink", "fifo", "hardlink", "next",
        ] {
            let fixture = Fixture::new(Phase::Published, Position::Published);
            let store = fixture.store(true).unwrap();
            let intent = store.recovery_intent(&fixture.record).unwrap();
            let parent = fixture.root.path().join(DIRECTORY);
            let path = parent.join(INTENT);
            match fault {
                "hash" => {
                    let mut bytes = fs::read(&path).unwrap();
                    bytes[PREFIX] ^= 1;
                    fs::write(&path, bytes).unwrap();
                }
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "short" => fs::write(&path, b"short").unwrap(),
                "symlink" | "fifo" => {
                    fs::remove_file(&path).unwrap();
                    if fault == "fifo" {
                        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
                    } else {
                        symlink(parent.join("absent"), &path).unwrap();
                    }
                }
                "hardlink" => fs::hard_link(&path, parent.join("alias")).unwrap(),
                "next" => symlink(parent.join("absent"), parent.join(NEXT)).unwrap(),
                _ => unreachable!(),
            }
            let before = fs::symlink_metadata(&path).unwrap();
            assert!(
                load(&store._lock.0, store.device, store.uid).is_err(),
                "{fault}"
            );
            assert!(store.finish_recovery_intent(&intent).is_err());
            let after = fs::symlink_metadata(&path).unwrap();
            assert_eq!(
                (before.ino(), before.mode(), before.len()),
                (after.ino(), after.mode(), after.len())
            );
            assert_eq!(
                fs::read(fixture.current().join(STATE)).unwrap(),
                fixture.record.encode().unwrap()
            );
        }
    }

    #[test]
    fn receipt_cannot_upgrade_commit_or_change_transaction_context() {
        let fixture = Fixture::new(Phase::Published, Position::Published);
        let store = fixture.store(true).unwrap();
        let intent = store.recovery_intent(&fixture.record).unwrap();
        for change in ["commit", "backwards", "transaction", "hash"] {
            let mut changed = fixture.record.clone();
            match change {
                "commit" => changed.phase = Phase::Committed,
                "backwards" => changed.phase = Phase::Prepared,
                "transaction" => changed.transaction[0] ^= 1,
                "hash" => changed.metadata_sha256[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(intent.check_record(&changed).is_err(), "{change}");
        }
        let mut changed = fixture.record.clone();
        changed.phase = Phase::RolledBack;
        intent.check_record(&changed).unwrap();
    }

    #[test]
    fn archived_nonterminal_record_never_becomes_a_recovery_input() {
        let fixture = Fixture::new(Phase::Published, Position::Published);
        let store = fixture.store(true).unwrap();
        let intent = store.recovery_intent(&fixture.record).unwrap();
        let history = fixture.root.path().join(DIRECTORY).join("history");
        fs::create_dir(&history).unwrap();
        fs::set_permissions(&history, fs::Permissions::from_mode(0o700)).unwrap();
        let archive = history.join(format!(
            "{:032x}",
            u128::from_be_bytes(fixture.record.transaction)
        ));
        fs::rename(fixture.current(), &archive).unwrap();
        assert!(intent.select(&store._lock.0, None, store.uid).is_err());
        assert_eq!(
            fs::read(archive.join(STATE)).unwrap(),
            fixture.record.encode().unwrap()
        );
        assert_eq!(
            fs::read(fixture.root.path().join("kvmapp/identity")).unwrap(),
            b"new"
        );
    }
}
