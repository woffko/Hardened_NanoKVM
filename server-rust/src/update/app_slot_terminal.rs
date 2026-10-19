//! Retirement archives the exact current directory; older inactive payloads may
//! be pruned separately under the same retained lifetime owner.
//! Read-only job snapshots are diagnostics, not runtime-health or execution grants.
use super::*;
use crate::native_owner::broker::app_install::TerminalBoundary;

const HISTORY: &str = "history";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobStatus {
    pub transaction: [u8; 16],
    pub phase: Phase,
    pub version: String,
    /// Canonical namespace observation, not proof of physical durability/health.
    pub archived: bool,
    /// True only for an observed exact inactive payload. False requires a
    /// validated expiry receipt, never a missing pathname or a health guess.
    pub inactive_payload_retained: bool,
}

fn summary(record: Record, archived: bool) -> JobStatus {
    JobStatus {
        transaction: record.transaction,
        phase: record.phase,
        version: record.version,
        archived,
        inactive_payload_retained: true,
    }
}

impl AcceptedInstall {
    pub(crate) fn retire(&mut self, boundary: &TerminalBoundary) -> Result<JobStatus> {
        if boundary.transaction() != self.transaction() {
            return Err(SlotError::Invalid);
        }
        let record = self._store.record()?;
        if record != self.record || record.phase != boundary.phase() {
            return Err(SlotError::Invalid);
        }
        self._store.retire(&record)
    }
}

impl Store {
    pub(super) fn retire_recovered(
        &self,
        record: &Record,
        _native: &crate::native_owner::broker::FencedAppRecovery,
    ) -> Result<JobStatus> {
        // This borrow can only come from a retained native lifetime lease with
        // durable current-boot Stopping, not from a public status or phase.
        self.retire(record)
    }

    fn retire(&self, record: &Record) -> Result<JobStatus> {
        if !matches!(record.phase, Phase::Committed | Phase::RolledBack)
            || self.record()? != *record
        {
            return Err(SlotError::Invalid);
        }
        self.layout(record)?;
        let pinned = self.current.metadata()?;
        protected_directory(&self.current, self.device, self.uid, true)?;
        let name = format!("{:032x}", u128::from_be_bytes(record.transaction));
        let created = match rustix::fs::mkdirat(&self._lock.0, HISTORY, Mode::from_raw_mode(0o700))
        {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(error) => return Err(error.into()),
        };
        let history =
            restore_fs::open_beneath(&self._lock.0, HISTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
        if created {
            // Fresh root-owned inode only; never chmod-repair existing history.
            rustix::fs::fchmod(&history, Mode::from_raw_mode(0o700))?;
            history.sync_all()?;
            self._lock.0.sync_all()?;
        }
        protected_directory(&history, self.device, self.uid, true)?;
        #[cfg(test)]
        retirement_checkpoint("retire-history-ready")?;
        let same = |directory: &File| -> Result<bool> {
            protected_directory(directory, self.device, self.uid, true)?;
            let actual = directory.metadata()?;
            Ok((actual.dev(), actual.ino()) == (pinned.dev(), pinned.ino()))
        };
        let source = open_optional(&self._lock.0, CURRENT)?;
        let archived = open_optional(&history, &name)?;
        match (&source, &archived) {
            (Some(source), None) if same(source)? => {
                // Terminal record and live layout must already be durable.
                restore_fs::open_beneath(&self.current, STATE, OFlags::RDONLY)?.sync_all()?;
                self.sync_parents()?;
                #[cfg(test)]
                retirement_checkpoint("retire-terminal-synced")?;
                super::history::register(self, record)?;
                if !open_optional(&self._lock.0, CURRENT)?
                    .as_ref()
                    .map(&same)
                    .transpose()?
                    .unwrap_or(false)
                {
                    return Err(SlotError::Invalid);
                }
                renameat_with(
                    &self._lock.0,
                    CURRENT,
                    &history,
                    name.as_str(),
                    RenameFlags::NOREPLACE,
                )?;
                #[cfg(test)]
                retirement_checkpoint("retire-current-renamed")?;
            }
            (None, Some(archived)) if same(archived)? => {
                // An earlier rename may have succeeded before fsync failed.
                // Only this still-pinned exact directory authorizes retry.
                super::history::register(self, record)?;
            }
            _ => return Err(SlotError::Invalid),
        }
        let archived = open_optional(&history, &name)?.ok_or(SlotError::Invalid)?;
        if !same(&archived)? || read_record_at(&archived, self.device, self.uid)? != *record {
            return Err(SlotError::Invalid);
        }
        self.current.sync_all()?;
        history.sync_all()?;
        #[cfg(test)]
        retirement_checkpoint("retire-history-synced")?;
        self._lock.0.sync_all()?;
        #[cfg(test)]
        retirement_checkpoint("retire-parent-synced")?;
        Ok(summary(
            read_record_at(&archived, self.device, self.uid)?,
            true,
        ))
    }
}

/// Bounded, fixed-root read with no store flock: install owns EX while its
/// canonical immutable records remain readable. Never repair or execute here.
pub fn job_status(transaction: [u8; 16]) -> Result<Option<JobStatus>> {
    if transaction == [0; 16] {
        return Err(SlotError::Invalid);
    }
    let Some((rootfs, directory)) = fixed_store_root()? else {
        return Ok(None);
    };
    job_at(&directory, rootfs.metadata()?.dev(), 0, transaction)
}

fn archived_job(
    directory: &File,
    device: u64,
    uid: u32,
    transaction: [u8; 16],
) -> Result<Option<JobStatus>> {
    super::history::receipt_query_guard(directory, device, uid, transaction)?;
    let Some(history) = open_optional(directory, HISTORY)? else {
        return Ok(None);
    };
    protected_directory(&history, device, uid, true)?;
    let name = format!("{:032x}", u128::from_be_bytes(transaction));
    let Some(archived) = open_optional(&history, &name)? else {
        return Ok(None);
    };
    protected_directory(&archived, device, uid, true)?;
    let record = read_record_at(&archived, device, uid)?;
    if record.transaction != transaction
        || !matches!(record.phase, Phase::Committed | Phase::RolledBack)
    {
        return Err(SlotError::Invalid);
    }
    let retained = super::history::archived_payload(&archived, &record, device, uid)?;
    let mut status = summary(record, true);
    status.inactive_payload_retained = retained;
    Ok(Some(status))
}

fn job_at(
    directory: &File,
    device: u64,
    uid: u32,
    transaction: [u8; 16],
) -> Result<Option<JobStatus>> {
    if transaction == [0; 16] {
        return Err(SlotError::Invalid);
    }
    protected_directory(directory, device, uid, true)?;
    if let Some(status) = archived_job(directory, device, uid, transaction)? {
        return Ok(Some(status));
    }
    if let Some(current) = open_optional(directory, CURRENT)? {
        protected_directory(&current, device, uid, true)?;
        let record = read_record_at(&current, device, uid)?;
        if record.transaction == transaction {
            return Ok(Some(summary(record, false)));
        }
    }
    // Close the one current->history rename race without scanning history or
    // interpreting a different current transaction as the requested one.
    archived_job(directory, device, uid, transaction)
}

#[cfg(test)]
pub(crate) fn job_status_fixture(root: &Path, transaction: [u8; 16]) -> Result<Option<JobStatus>> {
    let rootfs = File::open(root)?;
    let directory =
        restore_fs::open_beneath(&rootfs, DIRECTORY, OFlags::RDONLY | OFlags::DIRECTORY)?;
    job_at(
        &directory,
        rootfs.metadata()?.dev(),
        nix::unistd::geteuid().as_raw(),
        transaction,
    )
}

#[cfg(test)]
fn retirement_checkpoint(name: &str) -> Result<()> {
    checkpoint(name);
    if std::env::var("NANOKVM_APP_SLOT_TEST_FAIL").as_deref() == Ok(name) {
        return Err(SlotError::Io(io::Error::other(
            "injected terminal retirement failure",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "app_slot_terminal_tests.rs"]
mod tests;
