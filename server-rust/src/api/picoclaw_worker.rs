//! One lazy, app-owned executor. Queue admission is nonblocking and bounded;
//! request cancellation never starts a second executor or frees a running slot.
//! Control bookkeeping is independent of the work queue and never waits on HID.
use super::execution::{Call, CallStatus, Completion};
use super::{
    ActionResult, CODE_RUNTIME_UNAVAILABLE, PicoclawErrorData, PreparedBatch, ScreenshotMeta,
    ScreenshotQuery, acquire_session_lock, capture_screenshot_blocking, execute_actions_blocking,
    release_session_lock,
};
use serde::Serialize;
use std::{
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};
use tokio::sync::oneshot;

const QUEUED_CALLS: usize = 1;
const CODE_WORKER_BUSY: &str = "ACTION_WORKER_BUSY";

#[derive(Default)]
pub(crate) struct Worker {
    admission: Mutex<Admission>,
    calls: Mutex<[Option<Arc<Call>>; 2]>,
}

#[derive(Default)]
struct Admission {
    sender: Option<mpsc::SyncSender<Job>>,
    next_id: u64,
}

enum Work {
    Actions(String, PreparedBatch),
    Screenshot(Option<String>, ScreenshotQuery),
    #[cfg(test)]
    UncertainReports(String, PreparedBatch),
    #[cfg(test)]
    Probe {
        started: mpsc::SyncSender<std::thread::ThreadId>,
        release: mpsc::Receiver<()>,
    },
}

enum Output {
    Actions(ActionResult),
    Screenshot(Vec<u8>, ScreenshotMeta),
    #[cfg(test)]
    Probe,
}

struct Job {
    work: Work,
    reply: oneshot::Sender<Result<Output, PicoclawErrorData>>,
    ticket: Ticket,
}

// Exactly one ticket follows the job through queue/execute/unwind. Losing a
// queued job is clean; losing a running job is uncertain, never a drain proof.
struct Ticket(Arc<Call>);
impl Drop for Ticket {
    fn drop(&mut self) {
        self.0.abandon();
    }
}

pub(super) struct CancelReceipt {
    calls: [Option<Arc<Call>>; 2],
}

#[derive(Serialize)]
pub(super) struct CancelSummary {
    call_ids: [Option<u64>; 2],
    matched_calls: u8,
    pending_calls: u8,
    uncertain_calls: u8,
    calls_drained: bool,
}

impl CancelReceipt {
    pub(super) async fn wait(self, budget: Duration) -> CancelSummary {
        let _ = tokio::time::timeout(budget, async {
            for call in self.calls.iter().flatten() {
                call.wait_terminal().await;
            }
        })
        .await;
        let mut summary = CancelSummary {
            call_ids: [None; 2],
            matched_calls: 0,
            pending_calls: 0,
            uncertain_calls: 0,
            calls_drained: true,
        };
        for (index, call) in self.calls.iter().enumerate() {
            if let Some(call) = call {
                summary.call_ids[index] = Some(call.id);
                summary.matched_calls += 1;
                match call.status() {
                    CallStatus::Pending => summary.pending_calls += 1,
                    CallStatus::Uncertain => summary.uncertain_calls += 1,
                    CallStatus::Clean => {}
                }
            }
        }
        summary.calls_drained = summary.pending_calls == 0 && summary.uncertain_calls == 0;
        summary
    }
}

fn unavailable(message: &'static str) -> PicoclawErrorData {
    PicoclawErrorData::new(CODE_RUNTIME_UNAVAILABLE, message)
}

impl Worker {
    #[cfg(test)]
    pub(super) fn started(&self) -> bool {
        self.admission.lock().unwrap().sender.is_some()
    }

    pub(super) fn cancel(&self, session: Option<&str>) -> Result<CancelReceipt, PicoclawErrorData> {
        let calls = self
            .calls
            .lock()
            .map_err(|_| unavailable("action control registry poisoned"))?;
        let mut selected = [None, None];
        for (index, call) in calls.iter().enumerate() {
            if let Some(call) = call
                && call.status() != CallStatus::Clean
                && session.is_none_or(|session| call.session.as_deref() == Some(session))
            {
                selected[index] = Some(Arc::clone(call));
            }
        }
        drop(calls);
        let mut first_error = None;
        for call in selected.iter().flatten() {
            if let Err(error) = call.cancel() {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(CancelReceipt { calls: selected }),
        }
    }

    pub(super) async fn actions(
        &self,
        session_id: String,
        batch: PreparedBatch,
    ) -> Result<ActionResult, PicoclawErrorData> {
        match self.submit(Work::Actions(session_id, batch)).await? {
            Output::Actions(result) => Ok(result),
            _ => Err(unavailable("invalid action worker response")),
        }
    }

    pub(super) async fn screenshot(
        &self,
        session_id: Option<String>,
        query: ScreenshotQuery,
    ) -> Result<(Vec<u8>, ScreenshotMeta), PicoclawErrorData> {
        match self.submit(Work::Screenshot(session_id, query)).await? {
            Output::Screenshot(bytes, meta) => Ok((bytes, meta)),
            _ => Err(unavailable("invalid screenshot worker response")),
        }
    }

    async fn submit(&self, work: Work) -> Result<Output, PicoclawErrorData> {
        let (reply, received) = oneshot::channel();
        {
            let mut admission = self
                .admission
                .lock()
                .map_err(|_| unavailable("action worker admission poisoned"))?;
            if admission.sender.is_none() {
                let (send, queue) = mpsc::sync_channel::<Job>(QUEUED_CALLS);
                std::thread::Builder::new()
                    .name("picoclaw-actions".into())
                    .spawn(move || {
                        // The sole sender belongs to Worker, not this thread.
                        // Dropping the app closes admission; discarded queued
                        // requests are skipped, then recv() ends the thread.
                        while let Ok(Job {
                            work,
                            reply,
                            ticket,
                        }) = queue.recv()
                        {
                            if reply.is_closed() {
                                continue;
                            }
                            let completion = match ticket.0.start() {
                                Ok(()) => execute(work, &ticket.0),
                                Err(error) => Completion {
                                    result: Err(error),
                                    clean: true,
                                },
                            };
                            ticket.0.finish(completion.clean);
                            let _ = reply.send(completion.result);
                            if !completion.clean {
                                break;
                            }
                        }
                    })
                    .map_err(|_| unavailable("could not start action worker"))?;
                admission.sender = Some(send);
            }
            let mut calls = self
                .calls
                .lock()
                .map_err(|_| unavailable("action control registry poisoned"))?;
            let slot = calls
                .iter_mut()
                .find(|slot| {
                    slot.as_ref()
                        .is_none_or(|call| call.status() == CallStatus::Clean)
                })
                .ok_or_else(|| {
                    PicoclawErrorData::new(
                        CODE_WORKER_BUSY,
                        "action worker queue is full or retained; call was not admitted",
                    )
                })?;
            admission.next_id = admission
                .next_id
                .checked_add(1)
                .ok_or_else(|| unavailable("action call IDs exhausted"))?;
            let session = match &work {
                Work::Actions(session, _) => Some(session.clone()),
                Work::Screenshot(session, _) => session.clone(),
                #[cfg(test)]
                Work::UncertainReports(session, _) => Some(session.clone()),
                #[cfg(test)]
                Work::Probe { .. } => None,
            };
            let call = Arc::new(Call::new(admission.next_id, session));
            *slot = Some(Arc::clone(&call));
            let Some(sender) = admission.sender.as_ref() else {
                return Err(unavailable("action worker unavailable"));
            };
            match sender.try_send(Job {
                work,
                reply,
                ticket: Ticket(call),
            }) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    return Err(PicoclawErrorData::new(
                        CODE_WORKER_BUSY,
                        "action worker queue is full; retry only calls that were not admitted",
                    ));
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    // Do not replace a failed executor and risk overlapping
                    // uncertain effects with an automatically retried call.
                    return Err(unavailable("action worker stopped"));
                }
            }
        }
        received
            .await
            .map_err(|_| unavailable("action worker lost its result"))?
    }
}

fn execute(work: Work, call: &Call) -> Completion<Output> {
    match work {
        #[cfg(test)]
        Work::UncertainReports(_, batch) => {
            let reports = tests::UncertainReports { call };
            let completion = super::execute_prepared(&reports, None, &batch, call);
            Completion {
                result: completion.result.map(Output::Actions),
                clean: completion.clean,
            }
        }
        Work::Actions(session, batch) => {
            let release_after = match acquire_session_lock(&session) {
                Ok(acquired) => acquired,
                Err(error) => {
                    return Completion {
                        result: Err(error),
                        clean: true,
                    };
                }
            };
            let completion = execute_actions_blocking(&session, &batch, call);
            if release_after {
                release_session_lock(&session);
            }
            Completion {
                result: completion.result.map(Output::Actions),
                clean: completion.clean,
            }
        }
        Work::Screenshot(session, query) => {
            let release_after = match &session {
                Some(session) => match acquire_session_lock(session) {
                    Ok(acquired) => acquired,
                    Err(error) => {
                        return Completion {
                            result: Err(error),
                            clean: true,
                        };
                    }
                },
                None => false,
            };
            let result = call
                .check()
                .and_then(|()| capture_screenshot_blocking(query));
            if let Some(session) = session.filter(|_| release_after) {
                release_session_lock(&session);
            }
            Completion {
                result: result.and_then(|(bytes, meta)| {
                    call.check()?;
                    Ok(Output::Screenshot(bytes, meta))
                }),
                clean: true,
            }
        }
        #[cfg(test)]
        Work::Probe { started, release } => {
            started.send(std::thread::current().id()).unwrap();
            release.recv().unwrap();
            Completion {
                result: Ok(Output::Probe),
                clean: true,
            }
        }
    }
}

#[cfg(test)]
#[path = "picoclaw_worker_tests.rs"]
mod tests;
