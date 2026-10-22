//! One accepted job retains the SAME native broker through fixed I/O workers.
//! Explicit Stop/closure only; no target mutation, activation or recovery API.
use super::{Broker, PicoAcceptance, PicoCursor, PicoJobId, PicoRequest, PicoSubmission};
use crate::{
    Result,
    native_owner::controller::{Role, Status},
    update::picoclaw_config::{
        Generation,
        jobs::{RuntimeResult, TransitionStatus},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationStatus {
    Idle,
    Accepting,
    Accepted(PicoJobId),
    StopPending(PicoJobId),
    /// Resume suppression is durable; Stop is queued/sent, not a closure ack.
    Stopping(PicoJobId),
    /// This Pico tree is proven closed; the mutation job is still nonterminal.
    Closed(PicoJobId),
    /// Ordinary settlement is running in its fixed joined worker.
    Settling(PicoJobId),
    /// The change's plan is durable and the SAME owned scope is proven
    /// closed with resume permission kept; the change is not applied yet.
    Quiesced(PicoJobId),
    /// Settlement cannot run for this job; it stays accepted and fenced.
    SettlementRefused(PicoJobId),
    /// Terminal receipt published and private members retired.
    Completed(PicoJobId),
    /// The accepted source changed before apply: terminal failure receipt,
    /// nothing changed, private members retired.
    Superseded(PicoJobId),
    Existing(PicoJobId),
    Expired,
    Rejected,
    RecoveryRequired,
}

pub enum MutationAdmission {
    Owned(Box<Mutation>),
    Refused(Box<Broker>),
}

// Not Clone/Copy/Debug or publicly constructible. Only the owning Mutation can
// mint this after polling receipt + EOF + matching reap on its retained Group,
// or proving that this Group never held a Pico cell. This is not task success.
pub(crate) struct ClosedPico {
    id: PicoJobId,
    boot: [u8; 16],
    home: [u8; 32],
}

impl ClosedPico {
    pub(crate) fn matches(&self, id: PicoJobId, boot: [u8; 16], home: [u8; 32]) -> bool {
        self.id == id && self.boot == boot && self.home == home
    }
}

/// Field order is part of ownership: Submission joins ALL I/O before Broker
/// teardown may forfeit native closure. No broker extraction/restart is exposed.
///
/// ```compile_fail
/// use nanokvm_rust_server::native_owner::broker::PicoMutation;
/// fn extract(mutation: PicoMutation) {
///     let _broker = mutation.broker;
/// }
/// ```
pub struct Mutation {
    submission: PicoSubmission,
    broker: Broker,
    stop_requested: bool,
    settle_requested: bool,
    /// A durable plan exists; an explicit Stop may then continue settlement.
    planned: bool,
    /// Apply started: from here an explicit Stop only suppresses resume.
    applying: bool,
    launch: Option<Generation>,
    spawned: bool,
    #[cfg(test)]
    launch_fixture: Option<(std::path::PathBuf, Vec<std::ffi::OsString>)>,
    status: MutationStatus,
}

impl Mutation {
    pub(super) fn new(broker: Broker, submission: PicoSubmission) -> Self {
        Self {
            submission,
            broker,
            stop_requested: false,
            settle_requested: false,
            planned: false,
            applying: false,
            launch: None,
            spawned: false,
            #[cfg(test)]
            launch_fixture: None,
            status: MutationStatus::Idle,
        }
    }

    pub fn submit(
        &mut self,
        cursor: PicoCursor,
        nonce: [u8; 16],
        request: PicoRequest,
    ) -> Result<()> {
        self.broker.group.poll();
        if self.broker.group.uncertainty_latched()
            || self.status == MutationStatus::RecoveryRequired
        {
            self.status = MutationStatus::RecoveryRequired;
            return Err(crate::AppError::Conflict(
                "Pico native ownership requires settlement".into(),
            ));
        }
        self.submission.submit(cursor, nonce, request)
    }

    /// Queue an explicit administrative Stop, NOT its durable acknowledgement.
    /// Repeating it never reenables resume. Observe Stopping/Closed through poll.
    /// Ordinary mutation must later perform its fixed no-op preflight first;
    /// accepting a request alone never implicitly stops a live runtime.
    pub fn request_stop(&mut self) {
        self.stop_requested = true;
    }

    /// Queue ordinary settlement: the fixed no-op preflight first. It never
    /// stops a live runtime by itself; an explicit Stop keeps priority.
    pub fn request_settlement(&mut self) {
        self.settle_requested = true;
    }

    /// Return this SAME broker only once the job is durably terminal and its
    /// private members are retired. Otherwise the owner comes back unchanged.
    /// Dropping the submission first joins its workers and releases the
    /// store, source, Config and Update leases before the broker leaves.
    pub fn into_broker(self) -> std::result::Result<Broker, Box<Self>> {
        if !matches!(
            self.status,
            MutationStatus::Completed(_) | MutationStatus::Superseded(_)
        ) {
            return Err(Box::new(self));
        }
        let Self {
            submission, broker, ..
        } = self;
        drop(submission);
        Ok(broker)
    }

    pub fn poll(&mut self) -> MutationStatus {
        let native = self.broker.group.poll()[3];
        if self.broker.group.uncertainty_latched()
            || matches!(self.status, MutationStatus::RecoveryRequired)
        {
            self.status = MutationStatus::RecoveryRequired;
            return self.status;
        }
        let accepted = self.submission.poll();
        let id = match accepted {
            PicoAcceptance::Idle => {
                self.status = MutationStatus::Idle;
                return self.status;
            }
            PicoAcceptance::Pending => {
                self.status = MutationStatus::Accepting;
                return self.status;
            }
            PicoAcceptance::Accepted(id) => id,
            other => {
                self.status = match other {
                    PicoAcceptance::Existing(id) => MutationStatus::Existing(id),
                    PicoAcceptance::Expired => MutationStatus::Expired,
                    PicoAcceptance::Rejected => MutationStatus::Rejected,
                    _ => MutationStatus::RecoveryRequired,
                };
                return self.status;
            }
        };
        // Every valid completion, including failed/runtime-error work, is sent
        // only after the subreaper proves ECHILD. Closure is not task success.
        let closed = matches!(native, None | Some(Status::Closed(_)));
        let phase = self.submission.poll_transition();
        if phase == TransitionStatus::Planned {
            self.planned = true;
        }
        self.status = if self.stop_requested && !self.applying {
            let status = self.explicit_stop(id, phase, native, closed);
            // Once resume is durably lowered and the scope closed, a planned
            // change still applies; it just never resumes the runtime.
            if self.settle_requested && self.planned && status == MutationStatus::Closed(id) {
                self.settle(id, phase, native, closed)
            } else {
                status
            }
        } else if self.settle_requested {
            self.settle(id, phase, native, closed)
        } else {
            MutationStatus::Accepted(id)
        };
        self.status
    }

    fn pico_command(&self) -> std::process::Command {
        #[cfg(test)]
        if let Some((program, args)) = &self.launch_fixture {
            let mut command = std::process::Command::new(program);
            command
                .args(args)
                .env_clear()
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            return command;
        }
        Role::Picoclaw.command(&self.broker.group.home)
    }

    fn proof(&self, id: PicoJobId) -> ClosedPico {
        ClosedPico {
            id,
            boot: self.broker.journal.pico_boot_tag(),
            home: self.broker.group.home.fingerprint(),
        }
    }

    // Ordinary settlement: no-op preflight first, then a durable plan, then
    // automatic quiescence of the SAME scope that keeps resume permission.
    fn settle(
        &mut self,
        id: PicoJobId,
        phase: TransitionStatus,
        native: Option<Status>,
        closed: bool,
    ) -> MutationStatus {
        let started = match phase {
            TransitionStatus::Idle => self.submission.begin_settlement(),
            TransitionStatus::Pending => return MutationStatus::Settling(id),
            TransitionStatus::Completed => return MutationStatus::Completed(id),
            TransitionStatus::Refused => return MutationStatus::SettlementRefused(id),
            TransitionStatus::Closed if !self.planned => return MutationStatus::Quiesced(id),
            TransitionStatus::Closed => {
                self.applying = true;
                self.submission.begin_apply()
            }
            TransitionStatus::Superseded => return MutationStatus::Superseded(id),
            TransitionStatus::Committed(generation) => {
                self.launch = Some(generation);
                match self.submission.resume_allowed() {
                    Some(true) if !self.stop_requested => self.submission.begin_activation(),
                    Some(true) => self.submission.begin_finish(RuntimeResult::Suppressed),
                    Some(false) => self.submission.begin_finish(RuntimeResult::NotRequested),
                    None => return MutationStatus::RecoveryRequired,
                }
            }
            TransitionStatus::Activating if self.stop_requested && !self.spawned => {
                self.submission.begin_finish(RuntimeResult::Suppressed)
            }
            TransitionStatus::Activating if !self.spawned => {
                // Resume intent is durable; launch exactly once with the
                // installed generation, then wait for its runtime result.
                self.spawned = true;
                let launched = self.launch.is_some_and(|generation| {
                    let command = self.pico_command();
                    self.broker
                        .start_picoclaw_for_job(command, generation)
                        .is_ok()
                });
                if launched {
                    return MutationStatus::Settling(id);
                }
                self.submission.begin_finish(RuntimeResult::ResumeFailed)
            }
            TransitionStatus::Activating => match native {
                Some(Status::Starting) => return MutationStatus::Settling(id),
                Some(Status::Running) => self.submission.begin_finish(RuntimeResult::Resumed),
                _ => self.submission.begin_finish(RuntimeResult::ResumeFailed),
            },
            TransitionStatus::Planned | TransitionStatus::Stopping if closed => {
                let proof = self.proof(id);
                self.submission.persist_quiesced(proof)
            }
            TransitionStatus::Planned if native == Some(Status::Running) => {
                self.submission.persist_quiesce(id)
            }
            TransitionStatus::Stopping => {
                // Durable Stopping precedes the native Stop, as for Stop.
                self.broker.group.stop_picoclaw();
                return MutationStatus::Settling(id);
            }
            TransitionStatus::Planned | TransitionStatus::Failed => {
                return MutationStatus::RecoveryRequired;
            }
        };
        match started {
            Ok(()) => MutationStatus::Settling(id),
            Err(_) => MutationStatus::RecoveryRequired,
        }
    }

    // Explicit administrative Stop: resume permission is lowered durably
    // before any native Stop, also in place for an already quiesced job, and
    // a settled state is never re-published.
    fn explicit_stop(
        &mut self,
        id: PicoJobId,
        phase: TransitionStatus,
        native: Option<Status>,
        closed: bool,
    ) -> MutationStatus {
        let resume = self.submission.resume_allowed();
        let started = match phase {
            TransitionStatus::Pending => return MutationStatus::StopPending(id),
            TransitionStatus::Completed => return MutationStatus::Completed(id),
            TransitionStatus::Closed if resume == Some(false) => {
                return MutationStatus::Closed(id);
            }
            TransitionStatus::Closed if resume == Some(true) => {
                let proof = self.proof(id);
                self.submission.persist_closed(proof)
            }
            TransitionStatus::Idle
            | TransitionStatus::Planned
            | TransitionStatus::Refused
            | TransitionStatus::Stopping
                if closed =>
            {
                let proof = self.proof(id);
                self.submission.persist_closed(proof)
            }
            TransitionStatus::Stopping if resume == Some(true) => self.submission.persist_stop(id),
            TransitionStatus::Stopping if resume == Some(false) => {
                // This worker result is after checked state+directory sync.
                // request_stop itself and a disconnected caller grant no ack.
                self.broker.group.stop_picoclaw();
                return MutationStatus::Stopping(id);
            }
            TransitionStatus::Idle | TransitionStatus::Planned | TransitionStatus::Refused
                if native == Some(Status::Running) =>
            {
                self.submission.persist_stop(id)
            }
            _ => return MutationStatus::RecoveryRequired,
        };
        match started {
            Ok(()) => MutationStatus::StopPending(id),
            Err(_) => MutationStatus::RecoveryRequired,
        }
    }
}

#[cfg(all(test, feature = "sandbox-test-fixture"))]
#[path = "picoclaw_mutation_tests.rs"]
mod tests;
