//! Retained native-service admission plus durable same-boot crash detection.
//! Not yet the S95/watchdog daemon or a raw-update/early-restore coordinator.

use super::controller::{self, DrainStatus, Group, Role, StartError, Status};
#[path = "journal.rs"]
mod journal;
pub use journal::Error as JournalError;

#[derive(Debug)]
pub enum StartFailure {
    Journal(JournalError),
    Scope(StartError),
}

/// The singleton lease stays alive through all child scopes and maintenance.
/// Only a future trusted lifecycle daemon may own this production object.
pub struct Broker {
    group: Group,
    journal: journal::Store,
}

impl Broker {
    pub fn acquire() -> Result<Self, JournalError> {
        Ok(Self {
            group: Group::default(),
            journal: journal::Store::open()?,
        })
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
        }
    }
}

pub struct RetainedDrain {
    group: controller::Drain,
    journal: journal::Store,
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
        if status == DrainStatus::Drained {
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
        match self.group.try_resume() {
            Ok(group) => Resume::Running(Broker {
                group,
                journal: self.journal,
            }),
            Err(group) => Resume::Retained(Self {
                group,
                journal: self.journal,
            }),
        }
    }
}

#[cfg(test)]
#[path = "broker_tests.rs"]
mod tests;
