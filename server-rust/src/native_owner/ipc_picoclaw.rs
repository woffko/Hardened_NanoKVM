//! Fixed optional-scope commands, not adoption of an independently launched
//! gateway or enforcement of its local filesystem/tool privileges.
use super::*;
use crate::update::picoclaw_config::{self, Generation};

#[path = "picoclaw_onboard_work.rs"]
pub(super) mod work;
use work::{ImportStatus, ImportWork};

pub(super) struct Onboard {
    pub(super) work: ImportWork,
    pub(super) deadline: Instant,
    cancelled: bool,
    importing: bool,
}

impl Engine {
    pub(super) fn tick_picoclaw(&mut self, broker: &mut Broker) {
        self.picoclaw_status = broker.group.poll()[3];
        if broker.group.uncertainty_latched() || self.mode == Mode::Uncertain {
            self.mode = Mode::Uncertain;
            return;
        }
        if let Some(mut onboard) = self.picoclaw_onboard.take() {
            if let Some(Status::Closed(completion)) = self.picoclaw_status {
                let success = !onboard.cancelled && completion == Completion::SuccessfulExit;
                if success || onboard.importing {
                    // Stop after import admission cannot drop/join a live I/O
                    // worker on this loop or reinterpret its partial result.
                    onboard.importing = true;
                    match onboard.work.poll_closed() {
                        ImportStatus::Pending => self.picoclaw_onboard = Some(onboard),
                        ImportStatus::Complete => {
                            self.picoclaw_onboard_result = Some(!onboard.cancelled);
                            // Successful I/O and joined worker, not a returned
                            // Err, release the complete in-memory owner.
                            drop(onboard);
                        }
                        ImportStatus::Failed => {
                            self.picoclaw_onboard_result = Some(false);
                            self.mode = Mode::Uncertain;
                            self.picoclaw_onboard = Some(onboard);
                        }
                    }
                } else {
                    // No import was started: the one-shot is proven closed.
                    // Scratch remains evidence; durable retirement is separate.
                    self.picoclaw_onboard_result = Some(false);
                    drop(onboard);
                }
            } else {
                if !onboard.cancelled && Instant::now() >= onboard.deadline {
                    onboard.cancelled = true;
                    broker.group.stop_picoclaw();
                }
                self.picoclaw_onboard = Some(onboard);
            }
        }
        if matches!(self.picoclaw_status, None | Some(Status::Closed(_))) {
            self.picoclaw_generation = None;
            // Only this proven closed owned scope releases Stop's UpdateEX.
            self.picoclaw_stop = None;
        }
    }

    fn configuration_generation(
        &self,
        broker: &Broker,
        admission: &RuntimePermit,
        stopped: bool,
    ) -> crate::Result<Generation> {
        #[cfg(test)]
        if let Some(root) = &self.fixture {
            // Protocol fixtures use synthetic opaque generations, not a proof
            // of rootfs trust or pair recovery. Those have separate root tests.
            let bytes = std::fs::read(root.join("pico-generation"))?;
            return Ok(Generation::fixture(bytes.try_into().map_err(|_| {
                crate::AppError::Config("invalid synthetic generation".into())
            })?));
        }
        let path = broker.group.home.path().join("config.json");
        if stopped {
            picoclaw_config::prepare_launch(&admission._configuration, &path)
        } else {
            picoclaw_config::current_generation(&path)
        }
    }

    fn ensure_picoclaw(&mut self, broker: &mut Broker) -> Code {
        if self.picoclaw_stop.is_some()
            || self.picoclaw_onboard.is_some()
            || matches!(
                self.picoclaw_status,
                Some(Status::Stopping | Status::Uncertain | Status::TrialFailed)
            )
        {
            return Code::Busy;
        }
        let admission = match broker.runtime_permit() {
            Ok(admission) => admission,
            Err(super::super::JournalError::Busy) => return Code::Busy,
            Err(_) => return Code::Unavailable,
        };
        let stopped = matches!(self.picoclaw_status, None | Some(Status::Closed(_)));
        if stopped && broker.check_picoclaw_launch().is_err() {
            return Code::Unavailable;
        }
        let generation = match self.configuration_generation(broker, &admission, stopped) {
            Ok(generation) => generation,
            Err(_) => return Code::Unavailable,
        };
        if !stopped {
            // No restart/adoption on configuration mismatch. A separate Stop
            // and proven join must precede preparing a different pair.
            return if self.picoclaw_generation == Some(generation) {
                Code::Ok
            } else {
                Code::Invalid
            };
        }
        let command = self.command(broker, Role::Picoclaw);
        match broker.start_picoclaw(command, &admission, generation) {
            Ok(()) => {
                self.picoclaw_generation = Some(generation);
                self.picoclaw_status = broker.group.poll()[3];
                Code::Ok
            }
            Err(StartFailure::Scope(StartError::Spawn(_))) => Code::Unavailable,
            Err(_) => {
                self.mode = Mode::Uncertain;
                Code::Uncertain
            }
        }
    }

    fn stop_picoclaw(&mut self, broker: &mut Broker) -> Code {
        if let Some(onboard) = self.picoclaw_onboard.as_mut() {
            // Already owns both admissions. Never recursively acquire Update
            // while stopping the one-shot or report it as a successful import.
            onboard.cancelled = true;
            broker.group.stop_picoclaw();
            self.picoclaw_status = broker.group.poll()[3];
            return Code::Ok;
        }
        if self.picoclaw_stop.is_some()
            || matches!(self.picoclaw_status, None | Some(Status::Closed(_)))
        {
            return Code::Ok;
        }
        // Callers may already own Config. Stop/join cannot reacquire it. The
        // already-Active global journal stays conservative through owner loss;
        // this is not whole-broker Stopping or an all-writer closure receipt.
        let admission = match broker.runtime_admission() {
            Ok(admission) => admission,
            Err(super::super::JournalError::Busy) => return Code::Busy,
            Err(_) => return Code::Unavailable,
        };
        self.picoclaw_stop = Some(admission);
        broker.group.stop_picoclaw();
        self.picoclaw_status = broker.group.poll()[3];
        Code::Ok
    }

    fn onboard_picoclaw(&mut self, broker: &mut Broker) -> Code {
        if self.picoclaw_stop.is_some()
            || self.picoclaw_onboard.is_some()
            || !matches!(self.picoclaw_status, None | Some(Status::Closed(_)))
        {
            return Code::Busy;
        }
        let admission = match broker.runtime_permit() {
            Ok(admission) => admission,
            Err(super::super::JournalError::Busy) => return Code::Busy,
            Err(_) => return Code::Unavailable,
        };
        if broker.check_picoclaw_launch().is_err() {
            return Code::Unavailable;
        }
        self.picoclaw_onboard_result = None;
        #[cfg(test)]
        let fixture = self.fixture.is_some();
        #[cfg(not(test))]
        let fixture = false;
        let stage = if fixture {
            None
        } else {
            match picoclaw_config::Onboarding::prepare(
                &admission._configuration,
                &broker.group.home.path().join("config.json"),
            ) {
                Ok(Some(stage)) => Some(stage),
                Ok(None) => {
                    self.picoclaw_onboard_result = Some(true);
                    return Code::Ok;
                }
                Err(_) => return Code::Unavailable,
            }
        };
        #[cfg(test)]
        let command = if let Some(root) = &self.fixture {
            tests::onboard_command(root)
        } else {
            crate::native_owner::controller::picoclaw_onboard_command(&broker.group.home)
        };
        #[cfg(not(test))]
        let command = crate::native_owner::controller::picoclaw_onboard_command(&broker.group.home);
        match broker.start_picoclaw_onboard(command, &admission) {
            Ok(()) => {
                self.picoclaw_generation = None;
                self.picoclaw_onboard = Some(Onboard {
                    work: ImportWork::new(admission, stage),
                    deadline: Instant::now() + Duration::from_secs(60),
                    cancelled: false,
                    importing: false,
                });
                self.picoclaw_status = broker.group.poll()[3];
                Code::Ok
            }
            Err(StartFailure::Scope(StartError::Spawn(_))) => Code::Unavailable,
            Err(_) => {
                // No closure proof: retain admission even for a journal or
                // ownership failure, and close further lifecycle admission.
                self.picoclaw_onboard = Some(Onboard {
                    work: ImportWork::new(admission, stage),
                    deadline: Instant::now(),
                    cancelled: true,
                    importing: false,
                });
                self.mode = Mode::Uncertain;
                Code::Uncertain
            }
        }
    }

    pub(super) fn picoclaw_request(&mut self, op: Operation) -> Reply {
        if matches!(
            op,
            Operation::EnsurePicoclaw | Operation::StopPicoclaw | Operation::OnboardPicoclaw
        ) {
            self.tick();
        }
        if self.mode == Mode::Uncertain {
            return self.reply(Code::Uncertain);
        }
        if self.mode != Mode::Running
            || self.install.is_some()
            || self.lease.is_some()
            || self.abandoned
            || self.backend_restart.is_some()
        {
            return self.reply(Code::Busy);
        }
        let code = match op {
            Operation::PicoclawRunning => {
                if self.picoclaw_status == Some(Status::Running)
                    && self.picoclaw_generation.is_some()
                    && self.picoclaw_stop.is_none()
                    && self.picoclaw_onboard.is_none()
                {
                    Code::Ok
                } else {
                    Code::Unavailable
                }
            }
            Operation::PicoclawStopped => {
                if matches!(self.picoclaw_status, None | Some(Status::Closed(_)))
                    && self.picoclaw_stop.is_none()
                    && self.picoclaw_onboard.is_none()
                {
                    Code::Ok
                } else {
                    Code::Unavailable
                }
            }
            Operation::PicoclawOnboardComplete => match self.picoclaw_onboard_result {
                Some(true) if self.picoclaw_onboard.is_none() => Code::Ok,
                Some(false) => Code::Invalid,
                _ => Code::Unavailable,
            },
            Operation::EnsurePicoclaw | Operation::StopPicoclaw | Operation::OnboardPicoclaw => {
                let owner = self.owner.take();
                match owner {
                    Some(Owner::Running(mut broker)) => {
                        let code = match op {
                            Operation::EnsurePicoclaw => self.ensure_picoclaw(&mut broker),
                            Operation::OnboardPicoclaw => self.onboard_picoclaw(&mut broker),
                            _ => self.stop_picoclaw(&mut broker),
                        };
                        self.owner = Some(Owner::Running(broker));
                        code
                    }
                    other => {
                        self.owner = other;
                        Code::Busy
                    }
                }
            }
            _ => Code::Invalid,
        };
        self.reply(code)
    }
}
