//! Explicit native-admission recovery. Never a raw/restore recovery authority.
use super::{
    BYTES, Epoch, Error, NEXT, Phase, RECOVERY, RESOLVE, STATE, Store, kernel_proc, open,
    protected, record,
};
use rustix::fs::{
    AtFlags, Dir, Mode, OFlags, RenameFlags, linkat, mkdirat, openat2, renameat_with, statat,
};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Write,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

const EVIDENCE: &str = "evidence";
const QUARANTINED: &str = "quarantined";
const MEMBERS: [&str; 3] = [STATE, NEXT, "control.sock"];
const ABSENT: [&str; 3] = ["absent-state", "absent-next", "absent-control"];

fn boot_name(epoch: Epoch) -> Result<String, Error> {
    let mut hash = Sha256::new();
    hash.update(b"NKNATIVE-RECOVERY-BOOT-v1\0");
    hash.update(epoch.0);
    Ok(format!(
        "boot-{}-{:x}",
        std::str::from_utf8(&epoch.0).map_err(|_| Error::Invalid)?,
        hash.finalize()
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NoFence,
    IncompleteFence,
    AwaitingReboot,
    ReadyAfterReboot,
}

/// Read-only observation, not a native closure or raw transaction receipt.
pub fn inspect() -> Result<Status, Error> {
    match Recovery::root(false) {
        Ok(recovery) => recovery.inspect(),
        Err(Error::Absent) => Ok(Status::NoFence),
        Err(error) => Err(error),
    }
}

/// Persist an admission fence. Does not stop processes, reboot, or clear state.
pub fn prepare() -> Result<Status, Error> {
    Recovery::root(true)?.prepare()
}

/// Preserve exact old members and reset only native admission after a new boot.
/// A live broker's singleton lease always wins; no PID/socket-absence override.
pub fn complete() -> Result<(), Error> {
    Recovery::root(false)?.complete()
}

struct Fence {
    directory: File,
    epoch: Option<Epoch>,
    quarantined: bool,
}

struct Recovery {
    // This store holds only the private singleton lease, never passed to Broker.
    // Normal admission parsing is deliberately unavailable until completion.
    store: Store,
    #[cfg(test)]
    fail_at: Option<Step>,
    #[cfg(test)]
    pause_at: Option<(Step, std::path::PathBuf)>,
    #[cfg(test)]
    create_at: Option<(Step, &'static str)>,
}

impl Recovery {
    fn root(create: bool) -> Result<Self, Error> {
        Ok(Self {
            store: Store::lock_root(create)?,
            #[cfg(test)]
            fail_at: None,
            #[cfg(test)]
            pause_at: None,
            #[cfg(test)]
            create_at: None,
        })
    }

    fn directory(&self, parent: &File, name: &str, create: bool) -> Result<Option<File>, Error> {
        if create {
            match mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => {}
                Err(_) => return Err(Error::Io),
            }
        }
        let file = match open(parent, name, OFlags::RDONLY | OFlags::DIRECTORY, true) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
            Err(_) => return Err(Error::Unsafe),
        };
        protected(&file, self.store.uid, true)?;
        if file.metadata()?.dev() != self.store.device {
            return Err(Error::Unsafe);
        }
        if create {
            file.sync_all()?;
            parent.sync_all()?;
        }
        Ok(Some(file))
    }

    fn marker(&self, directory: &File, name: &str, create: bool) -> Result<bool, Error> {
        let file = match open(directory, name, OFlags::RDONLY | OFlags::NONBLOCK, true) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    return Ok(false);
                }
                openat2(
                    directory,
                    name,
                    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                    RESOLVE | rustix::fs::ResolveFlags::NO_XDEV,
                )
                .map(File::from)
                .map_err(|_| Error::Io)?
            }
            Err(_) => return Err(Error::Unsafe),
        };
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != self.store.uid
            || m.dev() != self.store.device
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() != 0
        {
            return Err(Error::Unsafe);
        }
        if create {
            file.sync_all()?;
            directory.sync_all()?;
        }
        Ok(true)
    }

    fn fence(&self) -> Result<Option<Fence>, Error> {
        let Some(directory) = self.directory(&self.store.directory, RECOVERY, false)? else {
            return Ok(None);
        };
        let mut epoch = None;
        let mut evidence = false;
        let mut quarantined = false;
        for (count, entry) in Dir::read_from(&directory)
            .map_err(|_| Error::Io)?
            .enumerate()
        {
            if count >= 8 {
                return Err(Error::Invalid);
            }
            let entry = entry.map_err(|_| Error::Io)?;
            let name = entry.file_name().to_bytes();
            match name {
                b"." | b".." => {}
                b"evidence" => evidence = true,
                b"quarantined" => quarantined = true,
                _ => {
                    let boot = name.strip_prefix(b"boot-").ok_or(Error::Invalid)?;
                    if epoch.is_some() {
                        return Err(Error::Invalid);
                    }
                    let parsed = Epoch::parse(boot.get(..36).ok_or(Error::Invalid)?)?;
                    // The domain-separated checksum detects a changed valid-looking
                    // epoch. Protected rootfs, not this hash, is authentication.
                    if boot_name(parsed)?.as_bytes() != name {
                        return Err(Error::Invalid);
                    }
                    let name = std::str::from_utf8(name).map_err(|_| Error::Invalid)?;
                    if !self.marker(&directory, name, false)? {
                        return Err(Error::Invalid);
                    }
                    epoch = Some(parsed);
                }
            }
        }
        if evidence {
            self.directory(&directory, EVIDENCE, false)?
                .ok_or(Error::Invalid)?;
        }
        if quarantined && !self.marker(&directory, QUARANTINED, false)? {
            return Err(Error::Invalid);
        }
        if (evidence || quarantined) && epoch.is_none() || quarantined && !evidence {
            return Err(Error::Invalid);
        }
        Ok(Some(Fence {
            directory,
            epoch,
            quarantined,
        }))
    }

    fn status(&self, fence: &Fence) -> Status {
        match fence.epoch {
            None => Status::IncompleteFence,
            Some(epoch) if epoch == self.store.epoch => Status::AwaitingReboot,
            Some(_) => Status::ReadyAfterReboot,
        }
    }

    fn inspect(&self) -> Result<Status, Error> {
        Ok(match self.fence()? {
            Some(fence) => self.status(&fence),
            None => Status::NoFence,
        })
    }

    fn prepare(&self) -> Result<Status, Error> {
        self.directory(&self.store.directory, RECOVERY, true)?
            .ok_or(Error::Invalid)?;
        #[cfg(test)]
        self.inject(Step::FenceCreated)?;
        let fence = self.fence()?.ok_or(Error::Invalid)?;
        if fence.epoch.is_none() {
            self.marker(&fence.directory, &boot_name(self.store.epoch)?, true)?;
            #[cfg(test)]
            self.inject(Step::EpochSynced)?;
        }
        self.inspect()
    }

    fn exists(directory: &File, name: &str) -> Result<bool, Error> {
        match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(_) => Err(Error::Io),
        }
    }

    fn evidence_names(directory: &File) -> Result<(), Error> {
        for (count, entry) in Dir::read_from(directory)
            .map_err(|_| Error::Io)?
            .enumerate()
        {
            if count >= 10 {
                return Err(Error::Invalid);
            }
            let entry = entry.map_err(|_| Error::Io)?;
            let name = entry.file_name().to_bytes();
            if !matches!(name, b"." | b"..")
                && !MEMBERS
                    .iter()
                    .chain(ABSENT.iter())
                    .any(|s| s.as_bytes() == name)
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }

    fn complete(&self) -> Result<(), Error> {
        let fence = self.fence()?.ok_or(Error::Recovery)?;
        let epoch = fence.epoch.ok_or(Error::Recovery)?;
        if epoch == self.store.epoch {
            return Err(Error::Reboot);
        }
        let evidence = self
            .directory(&fence.directory, EVIDENCE, true)?
            .ok_or(Error::Invalid)?;
        Self::evidence_names(&evidence)?;
        for index in 0..MEMBERS.len() {
            let member = MEMBERS[index];
            let present = Self::exists(&evidence, member)?;
            let absent = self.marker(&evidence, ABSENT[index], false)?;
            if present && absent {
                return Err(Error::Invalid);
            }
            if fence.quarantined {
                if !present && !absent {
                    return Err(Error::Invalid);
                }
            } else {
                let source = Self::exists(&self.store.directory, member)?;
                if source && (present || absent) {
                    return Err(Error::Ambiguous);
                }
                if source {
                    renameat_with(
                        &self.store.directory,
                        member,
                        &evidence,
                        member,
                        RenameFlags::NOREPLACE,
                    )
                    .map_err(|_| Error::Io)?;
                } else if !present && !absent {
                    self.marker(&evidence, ABSENT[index], true)?;
                }
                evidence.sync_all()?;
                self.store.directory.sync_all()?;
                #[cfg(test)]
                self.inject(Step::MemberQuarantined(index))?;
            }
        }
        if !fence.quarantined {
            self.marker(&fence.directory, QUARANTINED, true)?;
            #[cfg(test)]
            self.inject(Step::EvidenceSynced)?;
        }
        // No service can recreate these while the recovery fence is present.
        if Self::exists(&self.store.directory, NEXT)?
            || Self::exists(&self.store.directory, MEMBERS[2])?
        {
            return Err(Error::Ambiguous);
        }
        match self.store.read()? {
            Some((_, Phase::Closed)) => {} // Prior completion, interrupted before fence archive.
            Some(_) => return Err(Error::Ambiguous),
            None => self.publish_closed()?,
        }
        if Self::exists(&self.store.directory, NEXT)?
            || Self::exists(&self.store.directory, MEMBERS[2])?
        {
            return Err(Error::Ambiguous);
        }
        let before = fence.directory.metadata()?;
        let actual = statat(&self.store.directory, RECOVERY, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Error::Io)?;
        if actual.st_dev != before.dev() || actual.st_ino != before.ino() {
            return Err(Error::Unsafe);
        }
        let boot = std::str::from_utf8(&epoch.0).map_err(|_| Error::Invalid)?;
        renameat_with(
            &self.store.directory,
            RECOVERY,
            &self.store.directory,
            format!("recovered-{boot}"),
            RenameFlags::NOREPLACE,
        )
        .map_err(|_| Error::Io)?;
        #[cfg(test)]
        self.inject(Step::FenceArchived)?;
        self.store.directory.sync_all()?;
        Ok(())
    }

    fn publish_closed(&self) -> Result<(), Error> {
        // Only derived public journal bytes are anonymous here; original evidence
        // was moved and synced first. TMPFILE failure has no named fallback.
        let mut file: File = openat2(
            &self.store.directory,
            ".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            RESOLVE | rustix::fs::ResolveFlags::NO_XDEV,
        )
        .map_err(|_| Error::Io)?
        .into();
        let before = file.metadata()?;
        if !before.is_file()
            || before.uid() != self.store.uid
            || before.dev() != self.store.device
            || before.mode() & 0o7777 != 0o600
            || before.nlink() != 0
            || before.len() != 0
        {
            return Err(Error::Unsafe);
        }
        file.write_all(&record(self.store.epoch, Phase::Closed))?;
        file.sync_all()?;
        #[cfg(test)]
        self.inject(Step::ClosureFileSynced)?;
        // Deliberate own-fd procfs link avoids AT_EMPTY_PATH's extra capability.
        // The source FD remains owned; no caller pathname or magic-link selector.
        linkat(
            &kernel_proc()?,
            format!("self/fd/{}", file.as_raw_fd()),
            &self.store.directory,
            STATE,
            AtFlags::SYMLINK_FOLLOW,
        )
        .map_err(|_| Error::Io)?;
        let actual = statat(&self.store.directory, STATE, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| Error::Io)?;
        if actual.st_dev != before.dev()
            || actual.st_ino != before.ino()
            || actual.st_size != BYTES as i64
            || actual.st_nlink != 1
        {
            return Err(Error::Unsafe);
        }
        #[cfg(test)]
        self.inject(Step::ClosureLinked)?;
        self.store.directory.sync_all()?;
        #[cfg(test)]
        self.inject(Step::ClosureSynced)?;
        Ok(())
    }

    #[cfg(test)]
    fn inject(&self, step: Step) -> Result<(), Error> {
        if let Some((at, name)) = self.create_at
            && at == step
        {
            let file: File = openat2(
                &self.store.directory,
                name,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
                RESOLVE | rustix::fs::ResolveFlags::NO_XDEV,
            )
            .map_err(|_| Error::Io)?
            .into();
            file.sync_all()?;
            self.store.directory.sync_all()?;
        }
        if let Some((pause, ready)) = &self.pause_at
            && *pause == step
        {
            std::fs::write(ready, b"fixture")?;
            std::thread::sleep(std::time::Duration::from_secs(20));
        }
        if self.fail_at == Some(step) {
            return Err(Error::Io);
        }
        Ok(())
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    FenceCreated,
    EpochSynced,
    MemberQuarantined(usize),
    EvidenceSynced,
    ClosureFileSynced,
    ClosureLinked,
    ClosureSynced,
    FenceArchived,
}

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
