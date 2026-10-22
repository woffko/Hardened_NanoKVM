//! Retained native-service admission plus durable same-boot crash detection.
//! S95 native roles are wired; transaction/raw/early-restore joining remains open.

use super::controller::{self, DrainStatus, Group, Role, StartError, Status};
use crate::update::{
    operation_lock::{LockError, ProcessLock},
    state_writers::{ConfigPermit, StateWriters},
};
#[path = "journal.rs"]
mod journal;
pub use crate::update::picoclaw_config::jobs::{
    Acceptance as PicoAcceptance, Cursor as PicoCursor, JobId as PicoJobId, Profile as PicoProfile,
    Request as PicoRequest, Submission as PicoSubmission,
};
pub use journal::Error as JournalError;
#[path = "picoclaw_mutation.rs"]
pub(crate) mod picoclaw_mutation;
#[cfg(all(test, feature = "sandbox-test-fixture"))]
pub(crate) use journal::app_recovery::closed_fixture as app_recovery_closed_fixture;
pub(crate) use journal::app_recovery::{FencedAppRecovery, ReadyAppRecovery};
pub use journal::boot;
pub use journal::recovery;
pub use picoclaw_mutation::{
    Mutation as PicoMutation, MutationAdmission as PicoMutationAdmission,
    MutationStatus as PicoMutationStatus,
};
#[path = "app_install.rs"]
pub mod app_install;
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
    #[cfg(test)]
    update_parent: Option<std::fs::File>,
}

pub(super) struct RuntimePermit {
    _configuration: ConfigPermit,
    _update: ProcessLock,
}

/// Backend owner uses this ONLY after losing its controller/natural leader,
/// never for a broker's already update-admitted explicit Stop.
pub struct BackendOrphanPermit {
    _update: ProcessLock,
}
impl BackendOrphanPermit {
    pub fn try_acquire() -> Result<Option<Self>, JournalError> {
        match ProcessLock::acquire() {
            Ok(update) => Ok(Some(Self { _update: update })),
            Err(LockError::Busy) => Ok(None),
            Err(LockError::Unsafe) => Err(JournalError::Unsafe),
            Err(LockError::Io) => Err(JournalError::Io),
        }
    }
}

pub(crate) fn check_update_admission() -> Result<(), JournalError> {
    journal::Store::check_update_admission()
}

/// Current kernel boot tag for prior-boot Pico job recovery at early boot.
pub(crate) fn current_pico_boot_tag() -> Result<[u8; 16], JournalError> {
    journal::current_pico_boot_tag()
}

impl Broker {
    /// Moves this same native owner into the job. Refusal returns it intact;
    /// neither acceptance nor a public status is a native closure capability.
    pub fn begin_picoclaw_mutation(mut self) -> PicoMutationAdmission {
        match self.prepare_picoclaw_submission() {
            Ok(submission) => {
                PicoMutationAdmission::Owned(Box::new(PicoMutation::new(self, submission)))
            }
            Err(_) => PicoMutationAdmission::Refused(Box::new(self)),
        }
    }

    /// Prepare an owned acceptance worker, not a native closure/execute ticket.
    /// HTTP/S96 are not wired to this API until their correlated transport moves
    /// together. The caller retains this owner across disconnects and errors.
    pub fn prepare_picoclaw_submission(&mut self) -> crate::Result<PicoSubmission> {
        let admission = self
            .runtime_permit()
            .map_err(|_| crate::AppError::Conflict("Pico mutation admission unavailable".into()))?;
        self.journal.ready().map_err(|_| {
            crate::AppError::Conflict("Pico native ownership requires settlement".into())
        })?;
        self.check_picoclaw_launch().map_err(|_| {
            crate::AppError::Conflict("Pico application support unavailable".into())
        })?;
        let status = self.group.poll()[3];
        if self.group.uncertainty_latched()
            || !matches!(status, None | Some(Status::Running | Status::Closed(_)))
        {
            return Err(crate::AppError::Conflict(
                "Pico native state is not stable".into(),
            ));
        }
        let running_generation = if status == Some(Status::Running) {
            Some(self.group.picoclaw_generation().ok_or_else(|| {
                crate::AppError::Conflict("Pico launch generation is not owned".into())
            })?)
        } else {
            None
        };
        let (boot, image) = self
            .journal
            .pico_submission_context()
            .map_err(|_| crate::AppError::Conflict("Pico producer identity unavailable".into()))?;
        Ok(PicoSubmission::new(
            admission._configuration,
            admission._update,
            &self.group.home,
            boot,
            image,
            running_generation,
        ))
    }

    /// This SAME executing broker's build, not a newly installed broker file.
    /// Diagnostics only: equal epochs do not supply install/native authority.
    pub fn support_epochs(&self) -> crate::update::support_abi::Epochs {
        crate::update::support_abi::CURRENT
    }

    /// Read-only compatibility preflight using this executing build's constant.
    /// Not a ClosedRuntime capability or permission to mutate support files.
    pub fn check_support_transition(
        &self,
        predecessor: &crate::update::support_abi_catalog::Catalog,
        successor: &crate::update::support_abi_catalog::Catalog,
    ) -> Result<(), crate::update::support_abi_catalog::CompatibilityError> {
        crate::update::support_abi_catalog::check_transition(predecessor, successor)
    }

    pub fn acquire() -> Result<Self, JournalError> {
        let enrollment = boot::require_ready()?;
        Ok(Self {
            group: Group::new(
                super::picoclaw_home::Home::resolve().map_err(|_| JournalError::Unsafe)?,
            ),
            journal: journal::Store::open()?,
            enrollment,
            #[cfg(test)]
            update_parent: None,
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
        if role == Role::Picoclaw {
            // Only the generation-bound fixed service operation owns optional
            // start/stop policy. Generic native-role startup is insufficient.
            Err(StartFailure::Journal(JournalError::Unsafe))
        } else if role == Role::Backend {
            let admission = self.runtime_permit().map_err(StartFailure::Journal)?;
            self.start_backend(role.command(&self.group.home), &admission)
        } else {
            self.start_owned(role, role.command(&self.group.home))
        }
    }

    fn start_owned(
        &mut self,
        role: Role,
        command: std::process::Command,
    ) -> Result<(), StartFailure> {
        if matches!(role, Role::Backend | Role::Picoclaw) {
            return Err(StartFailure::Journal(JournalError::Unsafe));
        }
        self.launch(role, command)
    }

    fn start_backend(
        &mut self,
        command: std::process::Command,
        _admission: &RuntimePermit,
    ) -> Result<(), StartFailure> {
        #[cfg(test)]
        let fixture = self.update_parent.is_some();
        #[cfg(not(test))]
        let fixture = false;
        if !fixture
            && !matches!(
                crate::update::app_slot::status(),
                Ok(crate::update::app_slot::Status::NoTransaction
                    | crate::update::app_slot::Status::Transaction(
                        crate::update::app_slot::Phase::Committed
                            | crate::update::app_slot::Phase::RolledBack
                    ))
            )
        {
            return Err(StartFailure::Journal(JournalError::Unsafe));
        }
        self.launch(Role::Backend, command)
    }

    fn launch(&mut self, role: Role, command: std::process::Command) -> Result<(), StartFailure> {
        // Durably commit Active BEFORE any possible child spawn. Even spawn
        // failure remains conservative until an explicit, proven empty drain.
        self.journal.begin().map_err(StartFailure::Journal)?;
        self.group
            .start_command(role, command)
            .map_err(StartFailure::Scope)
    }

    fn start_picoclaw(
        &mut self,
        command: std::process::Command,
        _admission: &RuntimePermit,
        generation: crate::update::picoclaw_config::Generation,
    ) -> Result<(), StartFailure> {
        self.check_picoclaw_launch()
            .map_err(StartFailure::Journal)?;
        // Active remains durable before spawn, exactly as for other roles.
        self.journal.begin().map_err(StartFailure::Journal)?;
        self.group
            .start_picoclaw(command, generation)
            .map_err(StartFailure::Scope)
    }

    /// Launch for a settled Startup job. Its retained submission holds Update
    /// and Config for the whole call, so no separate runtime permit exists.
    fn start_picoclaw_for_job(
        &mut self,
        command: std::process::Command,
        generation: crate::update::picoclaw_config::Generation,
    ) -> Result<(), StartFailure> {
        self.check_picoclaw_launch()
            .map_err(StartFailure::Journal)?;
        // Active remains durable before spawn, exactly as for other roles.
        self.journal.begin().map_err(StartFailure::Journal)?;
        self.group
            .start_picoclaw(command, generation)
            .map_err(StartFailure::Scope)
    }

    fn start_picoclaw_onboard(
        &mut self,
        command: std::process::Command,
        _admission: &RuntimePermit,
    ) -> Result<(), StartFailure> {
        self.check_picoclaw_launch()
            .map_err(StartFailure::Journal)?;
        self.launch(Role::Picoclaw, command)
    }

    /// Gate before any stopped-pair recovery as well as before native spawn.
    fn check_picoclaw_launch(&self) -> Result<(), JournalError> {
        #[cfg(test)]
        let fixture = self.update_parent.is_some();
        #[cfg(not(test))]
        let fixture = false;
        if !fixture
            && !matches!(
                crate::update::app_slot::status(),
                Ok(crate::update::app_slot::Status::NoTransaction
                    | crate::update::app_slot::Status::Transaction(
                        crate::update::app_slot::Phase::Committed
                            | crate::update::app_slot::Phase::RolledBack
                    ))
            )
        {
            return Err(JournalError::Unsafe);
        }
        Ok(())
    }

    pub fn poll(&mut self) -> [Option<Status>; 2] {
        let [kvm, hwmon, _backend, _picoclaw] = self.group.poll();
        [kvm, hwmon]
    }

    pub(super) fn backend_status(&mut self) -> Option<Status> {
        self.group.poll()[2]
    }

    pub(super) fn runtime_admission(&self) -> Result<ProcessLock, JournalError> {
        #[cfg(test)]
        let result = if let Some(parent) = &self.update_parent {
            ProcessLock::from_parent(parent, nix::unistd::geteuid().as_raw())
        } else {
            ProcessLock::acquire()
        };
        #[cfg(not(test))]
        let result = ProcessLock::acquire();
        result.map_err(|error| match error {
            LockError::Busy => JournalError::Busy,
            LockError::Unsafe => JournalError::Unsafe,
            LockError::Io => JournalError::Io,
        })
    }

    pub(super) fn runtime_permit(&self) -> Result<RuntimePermit, JournalError> {
        let update = self.runtime_admission()?;
        #[cfg(test)]
        let writers = if let Some(parent) = &self.update_parent {
            StateWriters::for_test_parent(parent.try_clone().map_err(|_| JournalError::Io)?)
        } else {
            StateWriters::default()
        };
        #[cfg(not(test))]
        let writers = StateWriters::default();
        let configuration = writers.configuration().map_err(|error| match error {
            crate::AppError::Conflict(_) => JournalError::Busy,
            _ => JournalError::Unsafe,
        })?;
        Ok(RuntimePermit {
            _configuration: configuration,
            _update: update,
        })
    }

    pub(super) fn prepare_safe_mode(&self, _admission: &RuntimePermit) -> Result<(), JournalError> {
        #[cfg(test)]
        if let Some(parent) = &self.update_parent {
            return journal::backend_policy::safe_mode_at(parent, nix::unistd::geteuid().as_raw());
        }
        journal::backend_policy::safe_mode()
    }

    pub(super) fn stop_backend(&mut self, _admission: &RuntimePermit) -> Result<(), JournalError> {
        self.journal.stopping()?;
        self.group.stop_backend();
        Ok(())
    }

    pub(super) fn finish_backend_restart(&mut self) -> Result<(), JournalError> {
        self.journal.resume_active()
    }

    fn begin_drain(self) -> RetainedDrain {
        RetainedDrain {
            group: self.group.begin_drain(),
            journal: self.journal,
            maintenance: false,
            enrollment: self.enrollment,
            shutdown_admission: None,
            #[cfg(test)]
            update_parent: self.update_parent,
        }
    }

    pub(super) fn shutdown(mut self, admission: RuntimePermit) -> Shutdown {
        if self.journal.stopping().is_err() {
            return Shutdown::Retained(self);
        }
        let mut drain = self.begin_drain();
        drain.shutdown_admission = Some(admission);
        Shutdown::Draining(drain)
    }

    /// Close starts immediately; retain durable maintenance even after native
    /// closure. Only the same retained owner can explicitly resume/abort it.
    pub fn begin_maintenance(self) -> RetainedDrain {
        let mut drain = RetainedDrain {
            group: self.group.begin_native_drain(),
            journal: self.journal,
            maintenance: true,
            enrollment: self.enrollment,
            shutdown_admission: None,
            #[cfg(test)]
            update_parent: self.update_parent,
        };
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
    // Full shutdown retains update exclusion until every owned tree joins.
    shutdown_admission: Option<RuntimePermit>,
    #[cfg(test)]
    update_parent: Option<std::fs::File>,
}

/// Ownership transition, not an error carrying a discarded cleanup handle.
/// The caller must keep polling Retained; no allocation or detached cleanup.
pub enum Resume {
    Running(Broker),
    Retained(RetainedDrain),
}

pub(super) enum Shutdown {
    Draining(RetainedDrain),
    Retained(Broker),
}

impl RetainedDrain {
    pub(super) fn backend_status(&mut self) -> Option<Status> {
        self.group.backend_status()
    }
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
        let publication = if self.maintenance {
            self.journal.resume_active()
        } else {
            self.journal.close()
        };
        if publication.is_err() {
            return Resume::Retained(self);
        }
        match self.group.try_resume() {
            controller::Resume::Running(group) => Resume::Running(Broker {
                group,
                journal: self.journal,
                enrollment: self.enrollment,
                #[cfg(test)]
                update_parent: self.update_parent,
            }),
            controller::Resume::Retained(group) => Resume::Retained(Self {
                group,
                journal: self.journal,
                maintenance: self.maintenance,
                enrollment: self.enrollment,
                shutdown_admission: self.shutdown_admission,
                #[cfg(test)]
                update_parent: self.update_parent,
            }),
        }
    }
}

#[cfg(test)]
#[path = "broker_tests.rs"]
mod tests;
