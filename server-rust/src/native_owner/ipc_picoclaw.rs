//! Fixed optional-scope commands, not adoption of an independently launched
//! gateway or enforcement of its local filesystem/tool privileges.
use super::*;
use crate::update::picoclaw_config::{self, Generation};

impl Engine {
    pub(super) fn tick_picoclaw(&mut self, broker: &mut Broker) {
        self.picoclaw_status = broker.group.poll()[3];
        if broker.group.uncertainty_latched() || self.mode == Mode::Uncertain {
            self.mode = Mode::Uncertain;
            return;
        }
        if matches!(self.picoclaw_status, None | Some(Status::Closed(_))) {
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
            return if broker.group.picoclaw_generation() == Some(generation) {
                Code::Ok
            } else {
                Code::Invalid
            };
        }
        let command = self.command(broker, Role::Picoclaw);
        match broker.start_picoclaw(command, &admission, generation) {
            Ok(()) => {
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

    pub(super) fn picoclaw_request(&mut self, op: Operation) -> Reply {
        if matches!(op, Operation::EnsurePicoclaw | Operation::StopPicoclaw) {
            self.tick();
        }
        if self.mode == Mode::Uncertain {
            return self.reply(Code::Uncertain);
        }
        if self.mode != Mode::Running
            || self.install.is_some()
            || self.raw.is_some()
            || self.lease.is_some()
            || self.abandoned
            || self.backend_restart.is_some()
            || matches!(self.owner, Some(Owner::PicoJob(_)))
        {
            // A broker-owned job owns the Pico cell until its durable end.
            return self.reply(Code::Busy);
        }
        let code = match op {
            Operation::PicoclawRunning => {
                if self.picoclaw_status == Some(Status::Running)
                    && self.owner.as_ref().is_some_and(|owner| {
                        matches!(owner, Owner::Running(broker) if broker.group.picoclaw_generation().is_some())
                    })
                    && self.picoclaw_stop.is_none()
                {
                    Code::Ok
                } else {
                    Code::Unavailable
                }
            }
            Operation::PicoclawStopped => {
                if matches!(self.picoclaw_status, None | Some(Status::Closed(_)))
                    && self.picoclaw_stop.is_none()
                {
                    Code::Ok
                } else {
                    Code::Unavailable
                }
            }
            Operation::EnsurePicoclaw | Operation::StopPicoclaw => {
                let owner = self.owner.take();
                match owner {
                    Some(Owner::Running(mut broker)) => {
                        let code = match op {
                            Operation::EnsurePicoclaw => self.ensure_picoclaw(&mut broker),
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
