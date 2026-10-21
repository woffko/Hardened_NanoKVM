//! One fixed import under retained Update/Config and scratch ownership.
//! This is not a durable mutation job or a recovery/retry capability.
use super::*;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

struct Payload {
    stage: Option<picoclaw_config::Onboarding>,
    admission: RuntimePermit,
}

enum State {
    Idle,
    Running(Worker),
    Complete,
    Failed,
}

struct Worker(Option<JoinHandle<bool>>);
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ImportStatus {
    Pending,
    Complete,
    Failed,
}

pub(in crate::native_owner::broker::ipc) struct ImportWork {
    // Join before releasing scratch and admissions, including on teardown.
    state: State,
    payload: Arc<Mutex<Payload>>,
    #[cfg(test)]
    fixture: Option<Fixture>,
}

#[cfg(test)]
pub(in crate::native_owner::broker::ipc) enum Fixture {
    Block {
        entered: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    },
    Fail,
    Panic,
    SpawnFailure,
}

impl ImportWork {
    pub(super) fn new(
        admission: RuntimePermit,
        stage: Option<picoclaw_config::Onboarding>,
    ) -> Self {
        Self {
            state: State::Idle,
            payload: Arc::new(Mutex::new(Payload { stage, admission })),
            #[cfg(test)]
            fixture: None,
        }
    }

    #[cfg(test)]
    pub(in crate::native_owner::broker::ipc) fn set_fixture(&mut self, fixture: Fixture) {
        assert!(matches!(self.state, State::Idle));
        self.fixture = Some(fixture);
    }

    #[cfg(test)]
    pub(in crate::native_owner::broker::ipc) fn prepare_stage_fixture(
        &mut self,
        path: &std::path::Path,
        fail_after_member: usize,
    ) {
        assert!(matches!(self.state, State::Idle));
        let payload = Arc::get_mut(&mut self.payload).unwrap().get_mut().unwrap();
        assert!(payload.stage.is_none());
        let mut stage =
            picoclaw_config::Onboarding::prepare(&payload.admission._configuration, path)
                .unwrap()
                .unwrap();
        stage.fail_after_member(fail_after_member);
        payload.stage = Some(stage);
    }

    #[cfg(test)]
    pub(in crate::native_owner::broker::ipc) fn worker_finished_fixture(&self) -> bool {
        match &self.state {
            State::Idle => false,
            State::Running(worker) => worker.0.as_ref().is_some_and(JoinHandle::is_finished),
            State::Complete | State::Failed => true,
        }
    }

    /// Only the native owner may call this, after successful one-shot closure.
    /// Failed work cannot be retried or extracted as successful settlement.
    pub(super) fn poll_closed(&mut self) -> ImportStatus {
        match &self.state {
            State::Idle => {
                self.start();
                return if matches!(self.state, State::Failed) {
                    ImportStatus::Failed
                } else {
                    ImportStatus::Pending
                };
            }
            State::Running(worker) => {
                if !worker.0.as_ref().is_some_and(JoinHandle::is_finished) {
                    return ImportStatus::Pending;
                }
            }
            State::Complete => return ImportStatus::Complete,
            State::Failed => return ImportStatus::Failed,
        }
        if let State::Running(worker) = &mut self.state {
            // Only join a finished worker: no filesystem wait on the broker.
            self.state = match worker.0.take().map(JoinHandle::join) {
                Some(Ok(true)) => State::Complete,
                _ => State::Failed,
            };
        }
        if matches!(self.state, State::Complete) {
            ImportStatus::Complete
        } else {
            ImportStatus::Failed
        }
    }

    /// Engine teardown joins while its native singleton is still retained.
    /// Keep payload/guards here until the rest of Engine teardown releases them.
    pub(in crate::native_owner::broker::ipc) fn join_for_teardown(&mut self) {
        if let State::Running(worker) = &mut self.state {
            self.state = match worker.0.take().map(JoinHandle::join) {
                Some(Ok(true)) => State::Complete,
                _ => State::Failed,
            };
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
        let payload = Arc::clone(&self.payload);
        self.state = match thread::Builder::new()
            .name("pico-onboard-import".into())
            .spawn(move || {
                // Catch a borrow, not the owner: Err/panic cannot drop guards
                // or stage. The main loop never locks this mutex.
                let Ok(mut payload) = payload.lock() else {
                    return false;
                };
                catch_unwind(AssertUnwindSafe(|| {
                    #[cfg(test)]
                    match fixture {
                        Some(Fixture::Block { entered, resume }) => {
                            if entered.send(()).is_err() || resume.recv().is_err() {
                                return false;
                            }
                        }
                        Some(Fixture::Fail) => return false,
                        Some(Fixture::Panic) => panic!("fixture onboard import failure"),
                        Some(Fixture::SpawnFailure) | None => {}
                    }
                    let Payload { stage, admission } = &mut *payload;
                    match stage {
                        Some(stage) => stage.finish(&admission._configuration).is_ok(),
                        None => cfg!(test),
                    }
                }))
                .unwrap_or(false)
            }) {
            Ok(handle) => State::Running(Worker(Some(handle))),
            Err(_) => State::Failed,
        };
    }
}
