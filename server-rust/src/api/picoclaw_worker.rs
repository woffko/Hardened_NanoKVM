//! One lazy, app-owned executor. Queue admission is nonblocking and bounded;
//! request cancellation never starts a second executor or frees a running slot.
//! In-action cancellation and session/HID ownership are separate boundaries.
use super::{
    ActionResult, CODE_RUNTIME_UNAVAILABLE, PicoclawErrorData, PreparedBatch, ScreenshotMeta,
    ScreenshotQuery, acquire_session_lock, capture_screenshot_blocking, execute_actions_blocking,
    release_session_lock,
};
use std::sync::{Mutex, mpsc};
use tokio::sync::oneshot;

const QUEUED_CALLS: usize = 1;
const CODE_WORKER_BUSY: &str = "ACTION_WORKER_BUSY";

#[derive(Default)]
pub(crate) struct Worker {
    sender: Mutex<Option<mpsc::SyncSender<Job>>>,
}

enum Work {
    Actions(String, PreparedBatch),
    Screenshot(Option<String>, ScreenshotQuery),
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
}

fn unavailable(message: &'static str) -> PicoclawErrorData {
    PicoclawErrorData::new(CODE_RUNTIME_UNAVAILABLE, message)
}

impl Worker {
    #[cfg(test)]
    pub(super) fn started(&self) -> bool {
        self.sender.lock().unwrap().is_some()
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
            let mut sender = self
                .sender
                .lock()
                .map_err(|_| unavailable("action worker admission poisoned"))?;
            if sender.is_none() {
                let (send, queue) = mpsc::sync_channel::<Job>(QUEUED_CALLS);
                std::thread::Builder::new()
                    .name("picoclaw-actions".into())
                    .spawn(move || {
                        // The sole sender belongs to Worker, not this thread.
                        // Dropping the app closes admission; discarded queued
                        // requests are skipped, then recv() ends the thread.
                        while let Ok(job) = queue.recv() {
                            if !job.reply.is_closed() {
                                let result = execute(job.work);
                                let _ = job.reply.send(result);
                            }
                        }
                    })
                    .map_err(|_| unavailable("could not start action worker"))?;
                *sender = Some(send);
            }
            let Some(sender) = sender.as_ref() else {
                return Err(unavailable("action worker unavailable"));
            };
            match sender.try_send(Job { work, reply }) {
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

fn execute(work: Work) -> Result<Output, PicoclawErrorData> {
    match work {
        Work::Actions(session, batch) => {
            let release_after = acquire_session_lock(&session)?;
            let result = execute_actions_blocking(&session, &batch);
            if release_after {
                release_session_lock(&session);
            }
            result.map(Output::Actions)
        }
        Work::Screenshot(session, query) => {
            let release_after = match &session {
                Some(session) => acquire_session_lock(session)?,
                None => false,
            };
            let result = capture_screenshot_blocking(query);
            if let Some(session) = session.filter(|_| release_after) {
                release_session_lock(&session);
            }
            result.map(|(bytes, meta)| Output::Screenshot(bytes, meta))
        }
        #[cfg(test)]
        Work::Probe { started, release } => {
            started.send(std::thread::current().id()).unwrap();
            release.recv().unwrap();
            Ok(Output::Probe)
        }
    }
}

#[cfg(test)]
#[path = "picoclaw_worker_tests.rs"]
mod tests;
