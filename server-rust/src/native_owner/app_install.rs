//! Broker-owned closure, published-slot trial and retained commit/rollback.
//! No HTTP/worker transport or arbitrary executable selector is exposed.

use super::{Broker, JournalError, controller, journal};
use crate::update::app_slot::{AcceptedInstall, SlotError, Status};

/// Only the fixed protected broker endpoint, never a caller-selected address.
pub(crate) fn connect_peer() -> std::io::Result<std::os::fd::OwnedFd> {
    journal::Store::connect_install()
}

pub enum Start {
    Draining(Session),
    Retained {
        broker: Broker,
        install: AcceptedInstall,
    },
}

/// Only this retained owner can mint the closed-runtime borrow. Drop never
/// resumes anything; a same-boot Stopping fence survives lost ownership.
pub struct Session {
    group: controller::Drain,
    journal: journal::Store,
    enrollment: super::boot::Permit,
    #[cfg(test)]
    update_parent: Option<std::fs::File>,
    // Drop native handles first, then release update/writer admission LAST.
    install: AcceptedInstall,
}

pub(crate) struct ClosedRuntime {
    transaction: [u8; 16],
}
impl ClosedRuntime {
    pub(crate) fn transaction(&self) -> [u8; 16] {
        self.transaction
    }

    #[cfg(test)]
    pub(crate) fn fixture(transaction: [u8; 16]) -> Self {
        Self { transaction }
    }
}

pub enum Rollback {
    Restored(RolledBack),
    Retained(Session),
}

/// Durable old-slot recovery, with admission still retained for explicit
/// terminal disposition. No caller may start the old runtime before release.
pub struct RolledBack {
    broker: Broker,
    install: AcceptedInstall,
}

pub enum BeginTrial {
    Started(TrialSession),
    Retained(Session),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrialStatus {
    Starting,
    Ready,
    Failed,
    Uncertain,
}

/// No rollback API while this owner may have a new runtime tree. stop() moves
/// it back to a drain; only proven ECHILD receipts permit old-slot recovery.
pub struct TrialSession {
    group: controller::Group,
    journal: journal::Store,
    enrollment: super::boot::Permit,
    #[cfg(test)]
    update_parent: Option<std::fs::File>,
    failed: bool,
    native_resumed: bool,
    install: AcceptedInstall,
}

pub(crate) struct TrialReady {
    transaction: [u8; 16],
}
impl TrialReady {
    pub(crate) fn transaction(&self) -> [u8; 16] {
        self.transaction
    }
}

pub enum StopTrial {
    Draining(Session),
    Retained(TrialSession),
}

pub enum CommitTrial {
    Committed(Committed),
    Pending(TrialSession),
    Retained(TrialSession),
}

pub struct Committed {
    broker: Broker,
    install: AcceptedInstall,
}
impl Committed {
    /// Terminal journal/old slot remain. Retirement is a separate durable
    /// transition; releasing this freeze does not delete rollback evidence.
    pub fn release(self) -> Broker {
        let Self { broker, install } = self;
        drop(install);
        broker
    }
}
impl RolledBack {
    pub fn transaction(&self) -> [u8; 16] {
        self.install.transaction()
    }

    pub fn release(self) -> Broker {
        let Self { broker, install } = self;
        drop(install);
        broker
    }
}

impl Broker {
    /// An accepted app install already owns UpdateEX + writer admission/activity
    /// EX. Do NOT reacquire UpdateEX or an enrolled ConfigPermit underneath it.
    /// Stopping must be durable BEFORE any of the three scope Stop requests.
    pub fn begin_app_install(mut self, install: AcceptedInstall) -> Start {
        if self.journal.stopping().is_err() {
            return Start::Retained {
                broker: self,
                install,
            };
        }
        Start::Draining(Session {
            group: self.group.begin_drain(),
            journal: self.journal,
            enrollment: self.enrollment,
            #[cfg(test)]
            update_parent: self.update_parent,
            install,
        })
    }
}

impl Session {
    pub fn transaction(&self) -> [u8; 16] {
        self.install.transaction()
    }

    pub fn poll(&mut self) -> Result<controller::DrainStatus, JournalError> {
        self.journal.ready()?;
        // Deliberately never publish Closed. The app transaction is ongoing
        // even after all three native/backend trees have been joined.
        Ok(self.group.poll())
    }

    fn closed(&mut self) -> Result<ClosedRuntime, SlotError> {
        if !matches!(self.poll(), Ok(controller::DrainStatus::Drained)) {
            return Err(SlotError::Busy);
        }
        Ok(ClosedRuntime {
            transaction: self.install.transaction(),
        })
    }

    /// Preserve only the fixed mutable data allowlist and journal the two live
    /// renames. This is publication, NOT trial health/commit or API success.
    pub fn publish(&mut self) -> Result<Status, SlotError> {
        let closed = self.closed()?;
        self.install.publish(&closed)
    }

    pub fn start_trial(self) -> BeginTrial {
        self.start_trial_command(controller::backend_trial_command())
    }

    pub(super) fn start_trial_command(mut self, command: std::process::Command) -> BeginTrial {
        let Ok(closed) = self.closed() else {
            return BeginTrial::Retained(self);
        };
        if self.install.check_trial(&closed).is_err() {
            return BeginTrial::Retained(self);
        }
        let group = match self.group.try_resume() {
            controller::Resume::Running(group) => group,
            controller::Resume::Retained(group) => {
                return BeginTrial::Retained(Self { group, ..self });
            }
        };
        let mut trial = TrialSession {
            group,
            journal: self.journal,
            enrollment: self.enrollment,
            #[cfg(test)]
            update_parent: self.update_parent,
            failed: false,
            native_resumed: false,
            install: self.install,
        };
        let transaction = trial.install.transaction();
        // Native services can write settings outside StateWriters. Keep both
        // closed throughout the frozen trial; normal broker supervision may
        // restart them only AFTER Committed::release ends the writer freeze.
        trial.failed = trial.group.start_trial(command, transaction).is_err();
        BeginTrial::Started(trial)
    }

    /// After every old/trial tree has joined, restore the uncommitted old slot
    /// under the SAME exclusions and resume only after durability.
    /// Any unknown closure/layout/I/O result retains the complete owner.
    pub fn rollback(mut self) -> Rollback {
        let Ok(closed) = self.closed() else {
            return Rollback::Retained(self);
        };
        if self.install.rollback(&closed).is_err() || self.journal.resume_active().is_err() {
            return Rollback::Retained(self);
        }
        match self.group.try_resume() {
            controller::Resume::Running(group) => Rollback::Restored(RolledBack {
                broker: Broker {
                    group,
                    journal: self.journal,
                    enrollment: self.enrollment,
                    #[cfg(test)]
                    update_parent: self.update_parent,
                },
                install: self.install,
            }),
            controller::Resume::Retained(group) => Rollback::Retained(Self {
                group,
                journal: self.journal,
                enrollment: self.enrollment,
                #[cfg(test)]
                update_parent: self.update_parent,
                install: self.install,
            }),
        }
    }
}

impl TrialSession {
    pub fn poll(&mut self) -> TrialStatus {
        if self.journal.ready().is_err() {
            return TrialStatus::Uncertain;
        }
        let status = self.group.poll();
        if status.contains(&Some(controller::Status::Uncertain))
            || status[..2]
                .iter()
                .any(|s| !matches!(s, None | Some(controller::Status::Closed(_))))
        {
            TrialStatus::Uncertain
        } else if self.failed
            || matches!(
                status[2],
                None | Some(controller::Status::Closed(_) | controller::Status::TrialFailed)
            )
        {
            TrialStatus::Failed
        } else if status[2] == Some(controller::Status::Running) {
            TrialStatus::Ready
        } else {
            TrialStatus::Starting
        }
    }

    pub fn stop(mut self) -> StopTrial {
        let fence = if self.native_resumed {
            self.journal.stopping()
        } else {
            self.journal.ready()
        };
        if fence.is_err() {
            return StopTrial::Retained(self);
        }
        StopTrial::Draining(Session {
            group: self.group.begin_drain(),
            journal: self.journal,
            enrollment: self.enrollment,
            #[cfg(test)]
            update_parent: self.update_parent,
            install: self.install,
        })
    }

    pub fn commit(mut self) -> CommitTrial {
        match self.poll() {
            TrialStatus::Starting => return CommitTrial::Pending(self),
            TrialStatus::Ready => {}
            _ => return CommitTrial::Retained(self),
        }
        let transaction = self.install.transaction();
        let ready = TrialReady { transaction };
        if self.install.commit(&ready).is_err() {
            return CommitTrial::Retained(self);
        }
        if !self.native_resumed {
            if self.journal.resume_active().is_err() {
                return CommitTrial::Retained(self);
            }
            self.native_resumed = true;
        }
        match self.group.commit_trial(transaction) {
            Ok(false) => CommitTrial::Pending(self),
            Ok(true) => CommitTrial::Committed(Committed {
                broker: Broker {
                    group: self.group,
                    journal: self.journal,
                    enrollment: self.enrollment,
                    #[cfg(test)]
                    update_parent: self.update_parent,
                },
                install: self.install,
            }),
            Err(_) => CommitTrial::Retained(self),
        }
    }
}

#[cfg(test)]
#[path = "app_install_tests.rs"]
mod tests;
