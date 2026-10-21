//! One retained terminal transaction, with blocking filesystem work off the
//! broker loop. The worker cannot supervise, launch or release native scopes.

use super::{AcceptedInstall, Broker, TerminalBoundary, controller};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

pub(crate) enum Poll {
    Pending(Retirement),
    Failed(Retirement),
    Released(Box<Broker>),
}

enum Work {
    Idle,
    Running(Worker),
    Failed,
    Complete,
}

struct Worker(Option<JoinHandle<bool>>);
impl Drop for Worker {
    fn drop(&mut self) {
        // Never detach a task that still borrows the accepted exclusions. This
        // may block daemon teardown, never an ordinary poll/request/caller EOF.
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

pub(crate) struct Retirement {
    // On teardown native handles close first, the worker joins second, and
    // accepted update/store/writer admissions are released LAST.
    broker: Broker,
    work: Work,
    install: Arc<Mutex<AcceptedInstall>>,
    boundary: TerminalBoundary,
    #[cfg(test)]
    fixture: Option<Fixture>,
}

#[cfg(test)]
pub(crate) enum Fixture {
    Block {
        entered: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    },
    Panic,
    PanicAfterIo,
    SpawnFailure,
}

impl Retirement {
    // Only the parent terminal proof types can construct a boundary/owner.
    pub(super) fn new(
        broker: Broker,
        install: AcceptedInstall,
        boundary: TerminalBoundary,
    ) -> Self {
        Self {
            broker,
            work: Work::Idle,
            install: Arc::new(Mutex::new(install)),
            boundary,
            #[cfg(test)]
            fixture: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_fixture(&mut self, fixture: Fixture) {
        assert!(matches!(self.work, Work::Idle));
        self.fixture = Some(fixture);
    }

    pub(crate) fn observe(
        &mut self,
    ) -> ([Option<controller::Status>; 2], Option<controller::Status>) {
        let roles = self.broker.poll();
        (roles, self.broker.backend_status())
    }

    pub(crate) fn retry(&mut self) -> bool {
        if !matches!(self.work, Work::Failed) || self.broker.group.ownership_uncertain() {
            return false;
        }
        self.work = Work::Idle;
        true
    }

    pub(crate) fn poll(mut self) -> Poll {
        if self.broker.group.ownership_uncertain() {
            return Poll::Failed(self);
        }
        match &self.work {
            Work::Idle => {
                self.start();
                return if matches!(self.work, Work::Failed) {
                    Poll::Failed(self)
                } else {
                    Poll::Pending(self)
                };
            }
            Work::Running(worker) => {
                if !worker.0.as_ref().is_some_and(JoinHandle::is_finished) {
                    return Poll::Pending(self);
                }
            }
            Work::Failed => return Poll::Failed(self),
            Work::Complete => {}
        }
        if let Work::Running(worker) = &mut self.work {
            // is_finished above proves this join does not wait for filesystem
            // work. Panic/no result is failure, never successful retirement.
            self.work = match worker.0.take().map(JoinHandle::join) {
                Some(Ok(true)) => Work::Complete,
                _ => Work::Failed,
            };
        }
        if !matches!(self.work, Work::Complete)
            || self.broker.group.ownership_uncertain()
            || Arc::strong_count(&self.install) != 1
        {
            return Poll::Failed(self);
        }
        let Self {
            broker,
            work,
            install,
            ..
        } = self;
        let broker = Box::new(broker);
        drop(work);
        drop(install);
        Poll::Released(broker)
    }

    fn start(&mut self) {
        #[cfg(test)]
        let fixture = self.fixture.take();
        #[cfg(test)]
        if matches!(fixture, Some(Fixture::SpawnFailure)) {
            self.work = Work::Failed;
            return;
        }
        let install = Arc::clone(&self.install);
        let boundary = TerminalBoundary {
            transaction: self.boundary.transaction,
            phase: self.boundary.phase,
        };
        // Keep the original Arc in this owner even when spawning fails. The
        // worker only borrows the install under its mutex, so unwinding cannot
        // drop the accepted authority. The broker never locks this mutex.
        self.work = match thread::Builder::new()
            .name("app-retirement".into())
            .spawn(move || {
                let Ok(mut install) = install.lock() else {
                    return false;
                };
                catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    let panic_after_io = matches!(fixture, Some(Fixture::PanicAfterIo));
                    #[cfg(test)]
                    match fixture {
                        Some(Fixture::Block { entered, resume }) => {
                            if entered.send(()).is_err() || resume.recv().is_err() {
                                return false;
                            }
                        }
                        Some(Fixture::Panic) => panic!("fixture retirement worker failure"),
                        Some(Fixture::SpawnFailure | Fixture::PanicAfterIo) | None => {}
                    }
                    let succeeded = install.retire(&boundary).is_ok();
                    #[cfg(test)]
                    if panic_after_io {
                        panic!("fixture retirement failure after filesystem result");
                    }
                    succeeded
                }))
                .unwrap_or(false)
            }) {
            Ok(handle) => Work::Running(Worker(Some(handle))),
            Err(_) => Work::Failed,
        };
    }
}
