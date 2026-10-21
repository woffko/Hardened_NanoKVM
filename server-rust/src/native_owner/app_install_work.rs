//! Fixed filesystem operations under one retained accepted-install owner.
//! Native supervision and proof construction never run in this worker.

use super::{AcceptedInstall, ClosedRuntime, TerminalBoundary};
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
    Retire(TerminalBoundary),
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
            Self::Retire(boundary) => Self::Retire(TerminalBoundary {
                transaction: boundary.transaction(),
                phase: boundary.phase(),
            }),
        }
    }

    fn execute(self, install: &mut AcceptedInstall) -> bool {
        match self {
            Self::Support {
                closed,
                #[cfg(test)]
                fixture,
            } => {
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
            Self::Retire(boundary) => install.retire(&boundary).is_ok(),
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
    install: Arc<Mutex<Option<AcceptedInstall>>>,
    #[cfg(test)]
    fixture: Option<Fixture>,
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
    Panic,
    PanicAfterIo,
    SpawnFailure,
}

impl InstallWork {
    pub(super) fn support(install: AcceptedInstall, closed: ClosedRuntime) -> Self {
        Self::new(
            install,
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
            install,
            Operation::Support {
                closed,
                fixture: true,
            },
        )
    }

    pub(super) fn retire(install: AcceptedInstall, boundary: TerminalBoundary) -> Self {
        Self::new(install, Operation::Retire(boundary))
    }

    fn new(install: AcceptedInstall, operation: Operation) -> Self {
        Self {
            state: State::Idle,
            operation,
            install: Arc::new(Mutex::new(Some(install))),
            #[cfg(test)]
            fixture: None,
        }
    }

    #[cfg(test)]
    pub(super) fn set_fixture(&mut self, fixture: Fixture) {
        assert!(matches!(self.state, State::Idle));
        self.fixture = Some(fixture);
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
        let install = Arc::get_mut(&mut self.install)
            .and_then(|slot| slot.get_mut().ok())
            .and_then(Option::take);
        match install {
            Some(install) => Ok(install),
            None => Err(self),
        }
    }

    fn start(&mut self) {
        #[cfg(test)]
        let fixture = self.fixture.take();
        #[cfg(test)]
        if matches!(fixture, Some(Fixture::SpawnFailure)) {
            self.state = State::Failed;
            return;
        }
        let install = Arc::clone(&self.install);
        let operation = self.operation.worker_copy();
        let name = match operation {
            Operation::Support { .. } => "app-support",
            Operation::Retire(_) => "app-retirement",
        };
        self.state = match thread::Builder::new().name(name.into()).spawn(move || {
            // The original Arc remains with the main owner even on spawn
            // failure/panic. Catch only a borrow; never move out the install.
            let Ok(mut slot) = install.lock() else {
                return false;
            };
            let Some(install) = slot.as_mut() else {
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
                        | Fixture::BlockAfterIo { .. },
                    )
                    | None => {}
                }
                let succeeded = operation.execute(install);
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
