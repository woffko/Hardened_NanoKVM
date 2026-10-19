//! Retained native-service admission plus durable same-boot crash detection.
//! S95 native roles are wired; transaction/raw/early-restore joining remains open.

use super::controller::{self, DrainStatus, Group, Role, StartError, Status};
#[path = "journal.rs"]
mod journal;
pub use journal::Error as JournalError;
pub use journal::boot;
pub use journal::recovery;
#[path = "ipc.rs"]
pub mod ipc;

#[derive(Debug)]
pub enum StartFailure {
    Journal(JournalError),
    Scope(StartError),
}

/// The singleton lease stays alive through all child scopes and maintenance.
/// The trusted lifecycle daemon retains this object through init/native work.
pub struct Broker {
    group: Group,
    journal: journal::Store,
    enrollment: boot::Permit,
}

impl Broker {
    pub fn acquire() -> Result<Self, JournalError> {
        let enrollment = boot::require_ready()?;
        Ok(Self {
            group: Group::default(),
            journal: journal::Store::open()?,
            enrollment,
        })
    }

    /// Positive closed-journal + exclusive-lease proof, never a PID/socket guess.
    pub fn verify_stopped() -> Result<(), JournalError> {
        let _enrollment = boot::require_ready()?;
        match journal::Store::lock_root(false) {
            Ok(store) => {
                let _closed = store.admit()?;
                Ok(())
            }
            Err(JournalError::Absent) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Informational native ownership observation, NOT proof of restored state,
    /// image acceptance, critical-service health, or permission for raw writes.
    pub fn journal_is_from_previous_boot(&self) -> bool {
        self.journal.previous_boot()
    }

    pub fn start(&mut self, role: Role) -> Result<(), StartFailure> {
        self.start_owned(role, role.command())
    }

    fn start_owned(
        &mut self,
        role: Role,
        command: std::process::Command,
    ) -> Result<(), StartFailure> {
        // Durably commit Active BEFORE any possible child spawn. Even spawn
        // failure remains conservative until an explicit, proven empty drain.
        self.journal.begin().map_err(StartFailure::Journal)?;
        self.group
            .start_command(role, command)
            .map_err(StartFailure::Scope)
    }

    pub fn poll(&mut self) -> [Option<Status>; 2] {
        self.group.poll()
    }

    pub fn begin_drain(self) -> RetainedDrain {
        RetainedDrain {
            group: self.group.begin_drain(),
            journal: self.journal,
            maintenance: false,
            enrollment: self.enrollment,
        }
    }

    /// Close starts immediately; retain durable maintenance even after native
    /// closure. Only the same retained owner can explicitly resume/abort it.
    pub fn begin_maintenance(self) -> RetainedDrain {
        let mut drain = self.begin_drain();
        drain.maintenance = true;
        // Failure poisons the retained journal; poll cannot grant readiness.
        let _ = drain.journal.maintenance();
        drain
    }
}

pub struct RetainedDrain {
    group: controller::Drain,
    journal: journal::Store,
    maintenance: bool,
    enrollment: boot::Permit,
}

/// Ownership transition, not an error carrying a discarded cleanup handle.
/// The caller must keep polling Retained; no allocation or detached cleanup.
pub enum Resume {
    Running(Broker),
    Retained(RetainedDrain),
}

impl RetainedDrain {
    pub fn poll(&mut self) -> Result<DrainStatus, JournalError> {
        let status = self.group.poll();
        if self.maintenance {
            self.journal.ready()?;
        } else if status == DrainStatus::Drained {
            // Never publish Closed merely because the owner PID disappeared,
            // the caller disconnected, or its cleanup deadline elapsed.
            self.journal.close()?;
        }
        Ok(status)
    }

    pub fn resume(mut self) -> Resume {
        if !matches!(self.poll(), Ok(DrainStatus::Drained)) {
            return Resume::Retained(self);
        }
        if self.journal.close().is_err() {
            return Resume::Retained(self);
        }
        match self.group.try_resume() {
            Ok(group) => Resume::Running(Broker {
                group,
                journal: self.journal,
                enrollment: self.enrollment,
            }),
            Err(group) => Resume::Retained(Self {
                group,
                journal: self.journal,
                maintenance: self.maintenance,
                enrollment: self.enrollment,
            }),
        }
    }
}

#[cfg(test)]
#[path = "broker_tests.rs"]
mod tests;
