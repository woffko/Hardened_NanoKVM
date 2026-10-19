//! Broker-side app transaction closure. No HTTP/worker transport or trial-start
//! authority is supplied here. The retained group forbids launches until an
//! explicit rollback has restored the old app and resumed native admission.

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

    /// Before any new runtime has been launched through this owner, restore
    /// the old slot under the SAME exclusions and resume only after durability.
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

#[cfg(test)]
#[path = "app_install_tests.rs"]
mod tests;
