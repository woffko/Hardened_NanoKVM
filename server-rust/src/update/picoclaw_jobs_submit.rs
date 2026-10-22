//! Retained, fixed-kind acceptance work. No native execution/settlement API.
use super::*;
use crate::{
    native_owner::broker::picoclaw_mutation::ClosedPico,
    native_owner::picoclaw_home::Home,
    update::{operation_lock::ProcessLock, state_writers::ConfigPermit},
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

#[path = "picoclaw_jobs_accept.rs"]
mod accept;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub epoch: [u8; 16],
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobId {
    pub epoch: [u8; 16],
    pub sequence: u64,
    pub nonce: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Default,
    Kvm,
}

// Deliberately no Debug/Clone/Serialize. The secret survives only in owned
// zeroizing memory and fixed private files, never in argv/env/public status.
pub enum Request {
    Onboard,
    Model {
        model: Zeroizing<String>,
        api_base: Zeroizing<String>,
        api_key: Zeroizing<String>,
    },
    Startup,
    Profile(Profile),
    Install,
    Remove,
}

impl Request {
    fn kind(&self) -> Kind {
        match self {
            Self::Onboard => Kind::Onboard,
            Self::Model { .. } => Kind::Model,
            Self::Startup => Kind::Startup,
            Self::Profile(_) => Kind::Profile,
            Self::Install => Kind::Install,
            Self::Remove => Kind::Remove,
        }
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let fields: [&[u8]; 3] = match self {
            Self::Model {
                model,
                api_base,
                api_key,
            } => {
                if model.trim().is_empty() {
                    return Err(invalid());
                }
                [model.as_bytes(), api_base.as_bytes(), api_key.as_bytes()]
            }
            Self::Profile(Profile::Default) => [b"default", b"", b""],
            Self::Profile(Profile::Kvm) => [b"kvm", b"", b""],
            _ => [b"", b"", b""],
        };
        let total = fields
            .iter()
            .try_fold(32usize, |sum, bytes| sum.checked_add(bytes.len()))
            .ok_or_else(invalid)?;
        if total > super::super::MAX_FILE_BYTES {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(total));
        bytes.extend_from_slice(&[0; 32]);
        bytes[..8].copy_from_slice(b"NKPREQ01");
        bytes[8] = self.kind() as u8;
        for (index, field) in fields.into_iter().enumerate() {
            let offset = 12 + index * 4;
            bytes[offset..offset + 4].copy_from_slice(&(field.len() as u32).to_le_bytes());
            bytes.extend_from_slice(field);
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acceptance {
    Idle,
    Pending,
    Accepted(JobId),
    Existing(JobId),
    Expired,
    Rejected,
    RecoveryRequired,
}

struct Facts {
    home: PathBuf,
    home_fingerprint: [u8; 32],
    boot: [u8; 16],
    image: File,
    running_generation: Option<super::super::Generation>,
}

struct Payload {
    // Store/home leases retire before Config and Update on final owner drop.
    store: Option<accept::Store>,
    source: Option<accept::Source>,
    _configuration: ConfigPermit,
    _update: ProcessLock,
    facts: Facts,
    request: Option<Request>,
    plan: Option<accept::Plan>,
    touched: bool,
}

enum Advance {
    Stop { id: JobId, explicit: bool },
    Closed { proof: ClosedPico, explicit: bool },
    Settle,
    Apply,
    Activate,
    Finish(RuntimeResult),
}

/// Runtime result the owner observed for a committed change.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeResult {
    NotRequested,
    Resumed,
    ResumeFailed,
    Suppressed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransitionStatus {
    Idle,
    Pending,
    Stopping,
    Closed,
    /// Ordinary settlement published the terminal receipt and retired the
    /// job's private members. Only this proves the job is finished.
    Completed,
    /// Settlement found work to do and made its once-chosen plan durable;
    /// no runtime was stopped and no target was changed.
    Planned,
    /// Settlement cannot run for this accepted job; nothing was changed.
    Refused,
    /// The planned change is installed; carries the installed generation.
    Committed(super::super::Generation),
    /// Resume intent is durable; the owner may launch the runtime now.
    Activating,
    /// The accepted source changed before apply: terminal failure receipt,
    /// nothing changed and the job retired.
    Superseded,
    Failed,
}

enum TransitionWorker {
    Idle,
    Running(JoinHandle<TransitionStatus>),
    Settled(TransitionStatus),
}

enum Worker {
    Idle,
    Running(JoinHandle<Acceptance>),
    Settled(Acceptance),
}

/// Own across caller disconnect and every filesystem error. Acceptance is NOT
/// a closure proof or permission to replay/mutate a target. No retry/extraction
/// or arbitrary worker callback is available. Drop joins before guard release.
pub struct Submission {
    worker: Worker,
    payload: Arc<Mutex<Payload>>,
    transition: TransitionWorker,
    #[cfg(test)]
    fixture: Option<Fixture>,
}

#[cfg(test)]
enum Fixture {
    Block(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>),
    Fail,
    Panic,
    SpawnFailure,
}

#[cfg(all(test, feature = "sandbox-test-fixture"))]
pub(crate) enum WorkFixture {
    Block(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>),
    Fail,
    Panic,
    SpawnFailure,
}

impl Submission {
    pub(crate) fn new(
        configuration: ConfigPermit,
        update: ProcessLock,
        home: &Home,
        boot: [u8; 16],
        image: File,
        running_generation: Option<super::super::Generation>,
    ) -> Self {
        Self {
            worker: Worker::Idle,
            transition: TransitionWorker::Idle,
            #[cfg(test)]
            fixture: None,
            payload: Arc::new(Mutex::new(Payload {
                store: None,
                source: None,
                _configuration: configuration,
                _update: update,
                facts: Facts {
                    home: home.path().to_path_buf(),
                    home_fingerprint: home.fingerprint(),
                    boot,
                    image,
                    running_generation,
                },
                request: None,
                plan: None,
                touched: false,
            })),
        }
    }

    /// One fixed acceptance worker, no filesystem wait on the control loop.
    /// Even a failed spawn consumes this submission: it cannot be silently retried.
    pub fn submit(&mut self, cursor: Cursor, nonce: [u8; 16], request: Request) -> Result<()> {
        if !matches!(self.worker, Worker::Idle) {
            return Err(fenced());
        }
        let payload = Arc::get_mut(&mut self.payload)
            .ok_or_else(invalid)?
            .get_mut()
            .map_err(|_| invalid())?;
        payload.request = Some(request);
        self.worker = Worker::Settled(Acceptance::Rejected);
        #[cfg(test)]
        let fixture = self.fixture.take();
        #[cfg(test)]
        if matches!(fixture, Some(Fixture::SpawnFailure)) {
            return Err(AppError::Internal(
                "Pico acceptance worker unavailable".into(),
            ));
        }
        let owned = Arc::clone(&self.payload);
        match thread::Builder::new()
            .name("pico-job-accept".into())
            .spawn(move || {
                let Ok(mut payload) = owned.lock() else {
                    return Acceptance::RecoveryRequired;
                };
                match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    match fixture {
                        Some(Fixture::Block(entered, resume)) => {
                            entered.send(()).map_err(|_| invalid())?;
                            resume.recv().map_err(|_| invalid())?;
                        }
                        Some(Fixture::Fail) => return Err(invalid()),
                        Some(Fixture::Panic) => panic!("fixture Pico acceptance worker failure"),
                        Some(Fixture::SpawnFailure) | None => {}
                    }
                    accept::perform(&mut payload, cursor, nonce)
                })) {
                    Ok(Ok(status)) => status,
                    Ok(Err(_)) if !payload.touched => Acceptance::Rejected,
                    _ => Acceptance::RecoveryRequired,
                }
            }) {
            Ok(worker) => {
                self.worker = Worker::Running(worker);
                Ok(())
            }
            Err(_) => Err(AppError::Internal(
                "Pico acceptance worker unavailable".into(),
            )),
        }
    }

    pub fn poll(&mut self) -> Acceptance {
        match &self.worker {
            Worker::Idle => return Acceptance::Idle,
            Worker::Settled(status) => return *status,
            Worker::Running(worker) if !worker.is_finished() => return Acceptance::Pending,
            Worker::Running(_) => {}
        }
        if let Worker::Running(worker) = std::mem::replace(
            &mut self.worker,
            Worker::Settled(Acceptance::RecoveryRequired),
        ) {
            self.worker = Worker::Settled(worker.join().unwrap_or(Acceptance::RecoveryRequired));
        }
        match self.worker {
            Worker::Settled(status) => status,
            _ => Acceptance::RecoveryRequired,
        }
    }

    /// Explicit administrative Stop: durably lowers resume permission.
    pub(crate) fn persist_stop(&mut self, id: JobId) -> Result<()> {
        self.begin_transition(Advance::Stop { id, explicit: true })
    }

    pub(crate) fn persist_closed(&mut self, proof: ClosedPico) -> Result<()> {
        self.begin_transition(Advance::Closed {
            proof,
            explicit: true,
        })
    }

    /// Automatic quiescence of a planned change: resume permission is kept.
    pub(crate) fn persist_quiesce(&mut self, id: JobId) -> Result<()> {
        self.begin_transition(Advance::Stop {
            id,
            explicit: false,
        })
    }

    pub(crate) fn persist_quiesced(&mut self, proof: ClosedPico) -> Result<()> {
        self.begin_transition(Advance::Closed {
            proof,
            explicit: false,
        })
    }

    /// The accepted job's current resume permission, read only while no
    /// worker owns the payload. `None` means it cannot be observed now.
    pub(crate) fn resume_allowed(&self) -> Option<bool> {
        if matches!(self.transition, TransitionWorker::Running(_))
            || matches!(self.worker, Worker::Running(_))
        {
            return None;
        }
        let payload = self.payload.try_lock().ok()?;
        payload
            .store
            .as_ref()?
            .active_record()
            .map(|record| record.resume_allowed)
    }

    /// One fixed ordinary-settlement worker; never an explicit Stop.
    pub(crate) fn begin_settlement(&mut self) -> Result<()> {
        self.begin_transition(Advance::Settle)
    }

    pub(crate) fn begin_apply(&mut self) -> Result<()> {
        self.begin_transition(Advance::Apply)
    }

    pub(crate) fn begin_activation(&mut self) -> Result<()> {
        self.begin_transition(Advance::Activate)
    }

    pub(crate) fn begin_finish(&mut self, resume: RuntimeResult) -> Result<()> {
        self.begin_transition(Advance::Finish(resume))
    }

    fn begin_transition(&mut self, advance: Advance) -> Result<()> {
        let settled = match &self.transition {
            TransitionWorker::Idle => None,
            TransitionWorker::Settled(status) => Some(*status),
            TransitionWorker::Running(_) => return Err(fenced()),
        };
        // Each step may only follow its own predecessor; the store re-checks
        // the durable phase before publishing anything.
        let ready = match (&advance, settled) {
            (Advance::Settle | Advance::Stop { .. } | Advance::Closed { .. }, None) => true,
            // Stop/close may follow settlement, and an explicit Stop may
            // lower a quiesced job's resume permission in place.
            (
                Advance::Stop { .. } | Advance::Closed { .. },
                Some(
                    TransitionStatus::Stopping
                    | TransitionStatus::Closed
                    | TransitionStatus::Planned
                    | TransitionStatus::Refused,
                ),
            ) => true,
            (Advance::Apply, Some(TransitionStatus::Closed)) => true,
            (Advance::Activate, Some(TransitionStatus::Committed(_))) => true,
            (
                Advance::Finish(_),
                Some(TransitionStatus::Committed(_) | TransitionStatus::Activating),
            ) => true,
            _ => false,
        };
        if !matches!(self.worker, Worker::Settled(Acceptance::Accepted(_))) || !ready {
            return Err(fenced());
        }
        self.transition = TransitionWorker::Settled(TransitionStatus::Failed);
        #[cfg(test)]
        let fixture = self.fixture.take();
        #[cfg(test)]
        if matches!(fixture, Some(Fixture::SpawnFailure)) {
            return Err(AppError::Internal(
                "Pico stop publication unavailable".into(),
            ));
        }
        let owned = Arc::clone(&self.payload);
        let worker = thread::Builder::new()
            .name(
                match advance {
                    Advance::Settle => "pico-job-settle",
                    Advance::Apply | Advance::Activate | Advance::Finish(_) => "pico-job-apply",
                    Advance::Stop { .. } | Advance::Closed { .. } => "pico-job-stop",
                }
                .into(),
            )
            .spawn(move || {
                let Ok(mut payload) = owned.lock() else {
                    return TransitionStatus::Failed;
                };
                match catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    match fixture {
                        Some(Fixture::Block(entered, resume)) => {
                            entered.send(()).map_err(|_| invalid())?;
                            resume.recv().map_err(|_| invalid())?;
                        }
                        Some(Fixture::Fail) => return Err(invalid()),
                        Some(Fixture::Panic) => panic!("fixture Pico stop worker failure"),
                        Some(Fixture::SpawnFailure) | None => {}
                    }
                    accept::advance(&mut payload, advance)
                })) {
                    Ok(Ok(status)) => status,
                    _ => TransitionStatus::Failed,
                }
            })
            .map_err(|_| AppError::Internal("Pico stop publication unavailable".into()))?;
        self.transition = TransitionWorker::Running(worker);
        Ok(())
    }

    pub(crate) fn poll_transition(&mut self) -> TransitionStatus {
        match &self.transition {
            TransitionWorker::Idle => return TransitionStatus::Idle,
            TransitionWorker::Settled(status) => return *status,
            TransitionWorker::Running(worker) if !worker.is_finished() => {
                return TransitionStatus::Pending;
            }
            TransitionWorker::Running(_) => {}
        }
        if let TransitionWorker::Running(worker) = std::mem::replace(
            &mut self.transition,
            TransitionWorker::Settled(TransitionStatus::Failed),
        ) {
            self.transition =
                TransitionWorker::Settled(worker.join().unwrap_or(TransitionStatus::Failed));
        }
        match self.transition {
            TransitionWorker::Settled(status) => status,
            _ => TransitionStatus::Failed,
        }
    }

    #[cfg(all(test, feature = "sandbox-test-fixture"))]
    pub(crate) fn fixture_image(&mut self, image: File) {
        assert!(matches!(self.worker, Worker::Idle));
        Arc::get_mut(&mut self.payload)
            .unwrap()
            .get_mut()
            .unwrap()
            .facts
            .image = image;
    }

    #[cfg(all(test, feature = "sandbox-test-fixture"))]
    pub(crate) fn fixture_work(&mut self, fixture: WorkFixture) {
        assert!(matches!(
            self.worker,
            Worker::Idle | Worker::Settled(Acceptance::Accepted(_))
        ));
        assert!(matches!(self.transition, TransitionWorker::Idle));
        self.fixture = Some(match fixture {
            WorkFixture::Block(entered, resume) => Fixture::Block(entered, resume),
            WorkFixture::Fail => Fixture::Fail,
            WorkFixture::Panic => Fixture::Panic,
            WorkFixture::SpawnFailure => Fixture::SpawnFailure,
        });
    }
}

#[cfg(test)]
#[path = "picoclaw_jobs_submit_tests.rs"]
pub(super) mod tests;

impl Drop for Submission {
    fn drop(&mut self) {
        if let Worker::Running(worker) = std::mem::replace(
            &mut self.worker,
            Worker::Settled(Acceptance::RecoveryRequired),
        ) {
            let _ = worker.join();
        }
        if let TransitionWorker::Running(worker) = std::mem::replace(
            &mut self.transition,
            TransitionWorker::Settled(TransitionStatus::Failed),
        ) {
            let _ = worker.join();
        }
        // The last Arc drops only after this join. Error/success does not remove
        // any active intent, private snapshot or journal member from disk.
    }
}
