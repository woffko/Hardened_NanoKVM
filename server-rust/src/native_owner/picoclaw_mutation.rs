//! One accepted job retains the SAME native broker through fixed I/O workers.
//! Explicit Stop/closure only; no target mutation, activation or recovery API.
use super::{Broker, PicoAcceptance, PicoCursor, PicoJobId, PicoRequest, PicoSubmission};
use crate::{
    Result, native_owner::controller::Status, update::picoclaw_config::jobs::TransitionStatus,
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
    /// Settlement found work to do; nothing was published or changed yet.
    ChangeRequired(PicoJobId),
    /// Settlement cannot run for this job; it stays accepted and fenced.
    SettlementRefused(PicoJobId),
    /// Terminal receipt published and private members retired.
    Completed(PicoJobId),
    Existing(PicoJobId),
    Expired,
    Rejected,
    RecoveryRequired,
}

pub enum MutationAdmission {
    Owned(Mutation),
    Refused(Broker),
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
    status: MutationStatus,
}

impl Mutation {
    pub(super) fn new(broker: Broker, submission: PicoSubmission) -> Self {
        Self {
            submission,
            broker,
            stop_requested: false,
            settle_requested: false,
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
        if !matches!(self.status, MutationStatus::Completed(_)) {
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
        if !self.stop_requested {
            if !self.settle_requested {
                self.status = MutationStatus::Accepted(id);
                return self.status;
            }
            self.status = match self.submission.poll_transition() {
                TransitionStatus::Idle => match self.submission.begin_settlement() {
                    Ok(()) => MutationStatus::Settling(id),
                    Err(_) => MutationStatus::RecoveryRequired,
                },
                TransitionStatus::Pending => MutationStatus::Settling(id),
                TransitionStatus::Completed => MutationStatus::Completed(id),
                TransitionStatus::ChangeRequired => MutationStatus::ChangeRequired(id),
                TransitionStatus::Refused => MutationStatus::SettlementRefused(id),
                TransitionStatus::Stopping
                | TransitionStatus::Closed
                | TransitionStatus::Failed => MutationStatus::RecoveryRequired,
            };
            return self.status;
        }
        let phase = match self.submission.poll_transition() {
            // A settlement that changed nothing leaves the job as accepted.
            TransitionStatus::ChangeRequired | TransitionStatus::Refused => TransitionStatus::Idle,
            other => other,
        };
        // Every valid completion, including failed/runtime-error work, is sent
        // only after the subreaper proves ECHILD. Closure is not task success.
        let closed = matches!(native, None | Some(Status::Closed(_)));
        self.status = match phase {
            TransitionStatus::Idle | TransitionStatus::Stopping if closed => {
                let proof = ClosedPico {
                    id,
                    boot: self.broker.journal.pico_boot_tag(),
                    home: self.broker.group.home.fingerprint(),
                };
                if self.submission.persist_closed(proof).is_ok() {
                    MutationStatus::StopPending(id)
                } else {
                    MutationStatus::RecoveryRequired
                }
            }
            TransitionStatus::Idle => {
                if native != Some(Status::Running) {
                    MutationStatus::RecoveryRequired
                } else if self.submission.persist_stop(id).is_ok() {
                    MutationStatus::StopPending(id)
                } else {
                    MutationStatus::RecoveryRequired
                }
            }
            TransitionStatus::Pending => MutationStatus::StopPending(id),
            TransitionStatus::Stopping => {
                // This worker result is after checked state+directory sync.
                // request_stop itself and a disconnected caller grant no ack.
                self.broker.group.stop_picoclaw();
                MutationStatus::Stopping(id)
            }
            TransitionStatus::Closed => MutationStatus::Closed(id),
            TransitionStatus::Completed => MutationStatus::Completed(id),
            TransitionStatus::ChangeRequired
            | TransitionStatus::Refused
            | TransitionStatus::Failed => MutationStatus::RecoveryRequired,
        };
        self.status
    }
}

#[cfg(all(test, feature = "sandbox-test-fixture"))]
#[path = "picoclaw_mutation_tests.rs"]
mod tests;
