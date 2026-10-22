//! Fixed filesystem operations under one retained accepted-install owner.
//! Native supervision and proof construction never run in this worker.

use super::{AcceptedInstall, ClosedRuntime, TerminalBoundary, TrialReady, journal};
use crate::update::app_slot::support::support_operation;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

enum Operation {
    Support {
        closed: ClosedRuntime,
        #[cfg(test)]
        fixture: bool,
    },
    Publish(ClosedRuntime),
    CheckTrial(ClosedRuntime),
    Commit(TrialReady),
    Rollback(ClosedRuntime),
    Retire(TerminalBoundary),
}

pub(super) struct JournaledInstall {
    // Release the singleton before accepted update/writer admission LAST.
    pub(super) journal: journal::Store,
    pub(super) install: AcceptedInstall,
}

enum Payload {
    Install(AcceptedInstall),
    Commit(JournaledInstall),
    Rollback(JournaledInstall),
}
impl Operation {
    fn worker_copy(&self) -> Self {
        match self {
            Self::Support {
                closed,
                #[cfg(test)]
                fixture,
            } => Self::Support {
                closed: ClosedRuntime {
                    transaction: closed.transaction(),
                },
                #[cfg(test)]
                fixture: *fixture,
            },
            Self::Publish(closed) => Self::Publish(ClosedRuntime {
                transaction: closed.transaction(),
            }),
            Self::CheckTrial(closed) => Self::CheckTrial(ClosedRuntime {
                transaction: closed.transaction(),
            }),
            Self::Commit(ready) => Self::Commit(TrialReady {
                transaction: ready.transaction(),
            }),
            Self::Rollback(closed) => Self::Rollback(ClosedRuntime {
                transaction: closed.transaction(),
            }),
            Self::Retire(boundary) => Self::Retire(TerminalBoundary {
                transaction: boundary.transaction(),
                phase: boundary.phase(),
            }),
        }
    }

    fn execute(self, payload: &mut Payload, #[cfg(test)] fault: &Option<Fixture>) -> bool {
        match (self, payload) {
            (
                Self::Support {
                    closed,
                    #[cfg(test)]
                    fixture,
                },
                Payload::Install(install),
            ) => {
                #[cfg(test)]
                let prepared = if fixture {
                    crate::update::app_slot::support::prepare_retained_fixture(install, closed)
                } else {
                    crate::update::app_slot::support::prepare(install, closed)
                };
                #[cfg(not(test))]
                let prepared = crate::update::app_slot::support::prepare(install, closed);
                prepared.and_then(|mut support| support.exchange()).is_ok()
            }
            (Self::Publish(closed), Payload::Install(install)) => matches!(
                install.publish(&closed),
                Ok(crate::update::app_slot::Status::Transaction(
                    crate::update::app_slot::Phase::Published
                ))
            ),
            (Self::CheckTrial(closed), Payload::Install(install)) => {
                install.check_trial(&closed).is_ok()
            }
            (Self::Commit(ready), Payload::Commit(state)) => {
                if !matches!(
                    support_operation!("native.commit.slot", None, state.install.commit(&ready)),
                    Ok(crate::update::app_slot::Status::Transaction(
                        crate::update::app_slot::Phase::Committed
                    ))
                ) {
                    return false;
                }
                #[cfg(test)]
                match fault {
                    Some(Fixture::BlockCommitJournal { entered, resume }) => {
                        if entered.send(()).is_err() || resume.recv().is_err() {
                            return false;
                        }
                    }
                    Some(Fixture::PanicAfterCommitRecord) => {
                        panic!("fixture failure between commit record and native journal");
                    }
                    _ => {}
                }
                support_operation!(
                    "native.commit.journal-resume",
                    None,
                    state.journal.resume_active()
                )
                .is_ok()
            }
            (Self::Retire(boundary), Payload::Install(install)) => {
                install.retire(&boundary).is_ok()
            }
            (Self::Rollback(closed), Payload::Rollback(state)) => {
                if !matches!(
                    support_operation!(
                        "native.rollback.slot",
                        None,
                        state.install.rollback(&closed)
                    ),
                    Ok(crate::update::app_slot::Status::Transaction(
                        crate::update::app_slot::Phase::RolledBack
                    ))
                ) {
                    return false;
                }
                #[cfg(test)]
                match fault {
                    Some(Fixture::BlockRollbackJournal { entered, resume }) => {
                        if entered.send(()).is_err() || resume.recv().is_err() {
                            return false;
                        }
                    }
                    Some(Fixture::PanicAfterRollbackRecord) => {
                        panic!("fixture failure between rollback record and native journal");
                    }
                    _ => {}
                }
                support_operation!(
                    "native.rollback.journal-resume",
                    None,
                    state.journal.resume_active()
                )
                .is_ok()
            }
            // A mismatched fixed factory cannot shed or reinterpret authority.
            _ => false,
        }
    }
}

enum State {
    Idle,
    Running(Worker),
    Failed,
    Complete,
}
struct Worker(Option<JoinHandle<bool>>);
impl Drop for Worker {
    fn drop(&mut self) {
        // Teardown joins, never detaches a borrower of accepted admission.
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Status {
    Pending,
    Failed,
    Complete,
}

pub(super) struct InstallWork {
    state: State,
    operation: Operation,
    // Declaration order: join the worker before releasing admission LAST.
    payload: Arc<Mutex<Option<Payload>>>,
    #[cfg(test)]
    fixture: Option<Fixture>,
    #[cfg(test)]
    diagnostic: Option<Box<WorkerObservation>>,
}

#[cfg(test)]
struct WorkerObservation {
    started: std::time::Instant,
    pid: u32,
    tid: Option<u32>,
    receive: std::sync::mpsc::Receiver<u32>,
}

#[cfg(test)]
pub(crate) enum Fixture {
    Block {
        entered: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    },
    BlockAfterIo {
        entered: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    },
    BlockCommitJournal {
        entered: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    },
    BlockRollbackJournal {
        entered: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    },
    Panic,
    PanicAfterIo,
    PanicAfterCommitRecord,
    PanicAfterRollbackRecord,
    SpawnFailure,
}

impl InstallWork {
    pub(super) fn support(install: AcceptedInstall, closed: ClosedRuntime) -> Self {
        Self::new(
            Payload::Install(install),
            Operation::Support {
                closed,
                #[cfg(test)]
                fixture: false,
            },
        )
    }

    #[cfg(test)]
    pub(super) fn support_fixture(install: AcceptedInstall, closed: ClosedRuntime) -> Self {
        Self::new(
            Payload::Install(install),
            Operation::Support {
                closed,
                fixture: true,
            },
        )
    }

    pub(super) fn retire(install: AcceptedInstall, boundary: TerminalBoundary) -> Self {
        Self::new(Payload::Install(install), Operation::Retire(boundary))
    }

    pub(super) fn publish(install: AcceptedInstall, closed: ClosedRuntime) -> Self {
        Self::new(Payload::Install(install), Operation::Publish(closed))
    }

    pub(super) fn check_trial(install: AcceptedInstall, closed: ClosedRuntime) -> Self {
        Self::new(Payload::Install(install), Operation::CheckTrial(closed))
    }

    pub(super) fn commit(state: JournaledInstall, ready: TrialReady) -> Self {
        Self::new(Payload::Commit(state), Operation::Commit(ready))
    }

    pub(super) fn rollback(state: JournaledInstall, closed: ClosedRuntime) -> Self {
        Self::new(Payload::Rollback(state), Operation::Rollback(closed))
    }

    fn new(payload: Payload, operation: Operation) -> Self {
        Self {
            state: State::Idle,
            operation,
            payload: Arc::new(Mutex::new(Some(payload))),
            #[cfg(test)]
            fixture: None,
            #[cfg(test)]
            diagnostic: None,
        }
    }

    #[cfg(test)]
    pub(super) fn set_fixture(&mut self, fixture: Fixture) {
        assert!(matches!(self.state, State::Idle));
        self.fixture = Some(fixture);
    }

    #[cfg(test)]
    pub(super) fn fixture_settled(&self) -> bool {
        matches!(self.state, State::Failed | State::Complete)
    }

    #[cfg(test)]
    pub(super) fn fixture_diagnostics(&mut self) -> String {
        // Never lock accepted payload or join/poll the worker to observe it.
        let (state, finished) = match &self.state {
            State::Idle => ("idle", None),
            State::Running(worker) => ("running", worker.0.as_ref().map(JoinHandle::is_finished)),
            State::Failed => ("failed", None),
            State::Complete => ("complete", None),
        };
        let Some(observation) = &mut self.diagnostic else {
            return format!(
                "app-worker-observation: state={state}, finished={finished:?}, task=unreported"
            );
        };
        if observation.tid.is_none() {
            observation.tid = observation.receive.try_recv().ok();
        }
        let task = match (finished, observation.tid) {
            (Some(false), Some(tid)) => {
                crate::update::app_slot::test_diagnostics::observed_thread(observation.pid, tid)
            }
            (Some(false), None) => "task id not reported yet\n".into(),
            _ => "worker is not observed running; proc task not sampled\n".into(),
        };
        format!(
            "app-worker-observation: state={state}, finished={finished:?}, pid={}, tid={:?}, elapsed={:?}\n{task}",
            observation.pid,
            observation.tid,
            observation.started.elapsed(),
        )
    }

    pub(super) fn retry_terminal(&mut self) -> bool {
        if !matches!(self.operation, Operation::Retire(_)) || !matches!(self.state, State::Failed) {
            return false;
        }
        self.state = State::Idle;
        true
    }

    pub(super) fn poll(&mut self, start_allowed: bool) -> Status {
        match &self.state {
            State::Idle => {
                if start_allowed {
                    self.start();
                } else {
                    self.state = State::Failed;
                }
                return if matches!(self.state, State::Failed) {
                    Status::Failed
                } else {
                    Status::Pending
                };
            }
            State::Running(worker) => {
                if !worker.0.as_ref().is_some_and(JoinHandle::is_finished) {
                    return Status::Pending;
                }
            }
            State::Failed => return Status::Failed,
            State::Complete => return Status::Complete,
        }
        if let State::Running(worker) = &mut self.state {
            // is_finished proves this join does not wait for filesystem work.
            self.state = match worker.0.take().map(JoinHandle::join) {
                Some(Ok(true)) => State::Complete,
                _ => State::Failed,
            };
        }
        if matches!(self.state, State::Complete) {
            Status::Complete
        } else {
            Status::Failed
        }
    }

    pub(super) fn into_install(mut self) -> Result<AcceptedInstall, Self> {
        if !matches!(self.state, State::Failed | State::Complete) {
            return Err(self);
        }
        // Joined worker + unique Arc: exclusive get_mut cannot block. Never
        // recover a poisoned mutex or manufacture an empty accepted owner.
        let payload = Arc::get_mut(&mut self.payload)
            .and_then(|slot| slot.get_mut().ok())
            .and_then(|slot| slot.take_if(|payload| matches!(payload, Payload::Install(_))));
        match payload {
            Some(Payload::Install(install)) => Ok(install),
            _ => Err(self),
        }
    }

    pub(super) fn into_commit(mut self) -> Result<JournaledInstall, Self> {
        // Failed/unknown commit work has no extractable success authority.
        if !matches!(self.state, State::Complete) {
            return Err(self);
        }
        let payload = Arc::get_mut(&mut self.payload)
            .and_then(|slot| slot.get_mut().ok())
            .and_then(|slot| {
                slot.take_if(|payload| {
                    matches!(payload, Payload::Commit(state) if state.journal.ready().is_ok())
                })
            });
        match payload {
            Some(Payload::Commit(state)) => Ok(state),
            _ => Err(self),
        }
    }

    pub(super) fn into_rollback(mut self) -> Result<JournaledInstall, Self> {
        // A failed/unknown rollback cannot be retried or resumed by extraction.
        if !matches!(self.state, State::Complete) {
            return Err(self);
        }
        let payload = Arc::get_mut(&mut self.payload)
            .and_then(|slot| slot.get_mut().ok())
            .and_then(|slot| {
                slot.take_if(|payload| {
                    matches!(payload, Payload::Rollback(state) if state.journal.ready().is_ok())
                })
            });
        match payload {
            Some(Payload::Rollback(state)) => Ok(state),
            _ => Err(self),
        }
    }

    fn start(&mut self) {
        #[cfg(test)]
        {
            self.diagnostic = None;
        }
        #[cfg(test)]
        let fixture = self.fixture.take();
        #[cfg(test)]
        if matches!(fixture, Some(Fixture::SpawnFailure)) {
            self.state = State::Failed;
            return;
        }
        let payload = Arc::clone(&self.payload);
        let operation = self.operation.worker_copy();
        #[cfg(test)]
        let (report_tid, receive) = std::sync::mpsc::sync_channel(1);
        #[cfg(test)]
        {
            self.diagnostic = Some(Box::new(WorkerObservation {
                started: std::time::Instant::now(),
                pid: std::process::id(),
                tid: None,
                receive,
            }));
        }
        let name = match operation {
            Operation::Support { .. } => "app-support",
            Operation::Publish(_) => "app-publication",
            Operation::CheckTrial(_) => "app-trial-check",
            Operation::Commit(_) => "app-commit",
            Operation::Rollback(_) => "app-rollback",
            Operation::Retire(_) => "app-retirement",
        };
        self.state = match thread::Builder::new().name(name.into()).spawn(move || {
            #[cfg(test)]
            let _ = report_tid.try_send(rustix::thread::gettid().as_raw_pid() as u32);
            // The original Arc remains with the main owner even on spawn
            // failure/panic. Catch only a borrow of the complete payload.
            let Ok(mut slot) = payload.lock() else {
                return false;
            };
            let Some(payload) = slot.as_mut() else {
                return false;
            };
            catch_unwind(AssertUnwindSafe(|| {
                #[cfg(test)]
                let panic_after_io = matches!(&fixture, Some(Fixture::PanicAfterIo));
                #[cfg(test)]
                match &fixture {
                    Some(Fixture::Block { entered, resume }) => {
                        if entered.send(()).is_err() || resume.recv().is_err() {
                            return false;
                        }
                    }
                    Some(Fixture::Panic) => panic!("fixture install worker failure"),
                    Some(
                        Fixture::SpawnFailure
                        | Fixture::PanicAfterIo
                        | Fixture::PanicAfterCommitRecord
                        | Fixture::PanicAfterRollbackRecord
                        | Fixture::BlockCommitJournal { .. }
                        | Fixture::BlockRollbackJournal { .. }
                        | Fixture::BlockAfterIo { .. },
                    )
                    | None => {}
                }
                let succeeded = operation.execute(
                    payload,
                    #[cfg(test)]
                    &fixture,
                );
                #[cfg(test)]
                if let Some(Fixture::BlockAfterIo { entered, resume }) = fixture
                    && (entered.send(()).is_err() || resume.recv().is_err())
                {
                    return false;
                }
                #[cfg(test)]
                if panic_after_io {
                    panic!("fixture install failure after filesystem result");
                }
                succeeded
            }))
            .unwrap_or(false)
        }) {
            Ok(handle) => State::Running(Worker(Some(handle))),
            Err(_) => State::Failed,
        };
    }
}
