//! Per-admitted-call cancellation. This is not browser/task authority: a new
//! request still needs session-generation binding at the gateway/bridge boundary.
use super::{CODE_RUNTIME_UNAVAILABLE, PicoclawErrorData};
use std::{
    sync::{Condvar, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

const QUEUE_MAX_AGE: Duration = Duration::from_secs(30);
const EXECUTION_MAX_AGE: Duration = Duration::from_secs(30);

pub(super) struct Completion<T> {
    pub result: Result<T, PicoclawErrorData>,
    pub clean: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Queued,
    Running(Instant),
    Finished,
    Uncertain,
}

struct State {
    phase: Phase,
    cancelled: bool,
    #[cfg(test)]
    waiting: bool,
}

pub(crate) struct Call {
    pub(super) id: u64,
    pub(super) session: Option<String>,
    admitted: Instant,
    state: Mutex<State>,
    changed: Condvar,
    terminal: Notify,
}

fn poisoned() -> PicoclawErrorData {
    PicoclawErrorData::new(CODE_RUNTIME_UNAVAILABLE, "action control poisoned")
}

impl Call {
    #[cfg(test)]
    pub(crate) fn fixture() -> Self {
        let call = Self::new(0, None);
        call.start().unwrap();
        call
    }

    #[cfg(test)]
    pub(crate) fn cancel_fixture(&self) {
        assert!(self.cancel().is_ok());
    }

    pub(super) fn new(id: u64, session: Option<String>) -> Self {
        Self {
            id,
            session,
            admitted: Instant::now(),
            state: Mutex::new(State {
                phase: Phase::Queued,
                cancelled: false,
                #[cfg(test)]
                waiting: false,
            }),
            changed: Condvar::new(),
            terminal: Notify::new(),
        }
    }

    pub(super) fn start(&self) -> Result<(), PicoclawErrorData> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        self.check_state(&state, Instant::now())?;
        if state.phase != Phase::Queued {
            return Err(poisoned());
        }
        state.phase = Phase::Running(Instant::now());
        Ok(())
    }

    fn check_state(&self, state: &State, now: Instant) -> Result<(), PicoclawErrorData> {
        if state.cancelled {
            return Err(PicoclawErrorData::new(
                "ACTION_CANCELLED",
                "action call cancelled",
            ));
        }
        let (started, budget, code) = match state.phase {
            Phase::Queued => (self.admitted, QUEUE_MAX_AGE, "ACTION_QUEUE_EXPIRED"),
            Phase::Running(started) => (started, EXECUTION_MAX_AGE, "ACTION_DEADLINE"),
            Phase::Finished | Phase::Uncertain => return Err(poisoned()),
        };
        if now.saturating_duration_since(started) >= budget {
            return Err(PicoclawErrorData::new(code, "action call deadline expired"));
        }
        Ok(())
    }

    pub(super) fn check(&self) -> Result<(), PicoclawErrorData> {
        let state = self.state.lock().map_err(|_| poisoned())?;
        self.check_state(&state, Instant::now())
    }

    pub(super) fn wait(&self, duration: Duration) -> Result<(), PicoclawErrorData> {
        let until = Instant::now() + duration;
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        loop {
            let now = Instant::now();
            self.check_state(&state, now)?;
            if now >= until {
                return Ok(());
            }
            let Phase::Running(started) = state.phase else {
                return Err(poisoned());
            };
            let remaining = (until - now)
                .min(EXECUTION_MAX_AGE.saturating_sub(now.saturating_duration_since(started)));
            #[cfg(test)]
            {
                state.waiting = true;
            }
            (state, _) = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| poisoned())?;
            #[cfg(test)]
            {
                state.waiting = false;
            }
        }
    }

    #[cfg(test)]
    pub(super) fn waiting(&self) -> bool {
        self.state.lock().unwrap().waiting
    }

    pub(super) fn cancel(&self) -> Result<(), PicoclawErrorData> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        if matches!(state.phase, Phase::Queued | Phase::Running(_)) {
            state.cancelled = true;
            self.changed.notify_all();
        }
        Ok(())
    }

    pub(super) fn finish(&self, clean: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.phase = if clean {
                Phase::Finished
            } else {
                Phase::Uncertain
            };
        }
        self.terminal.notify_waiters();
    }

    pub(super) fn abandon(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.phase = match state.phase {
                // Never started: no input or cleanup was attempted.
                Phase::Queued => Phase::Finished,
                Phase::Running(_) => Phase::Uncertain,
                terminal => terminal,
            };
        }
        self.terminal.notify_waiters();
    }

    pub(super) fn status(&self) -> CallStatus {
        match self.state.lock() {
            Ok(state) => match state.phase {
                Phase::Queued | Phase::Running(_) => CallStatus::Pending,
                Phase::Finished => CallStatus::Clean,
                Phase::Uncertain => CallStatus::Uncertain,
            },
            Err(_) => CallStatus::Uncertain,
        }
    }

    pub(super) async fn wait_terminal(&self) {
        let notified = self.terminal.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.status() == CallStatus::Pending {
            notified.await;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CallStatus {
    Pending,
    Clean,
    Uncertain,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_cancel_is_connection_bound_and_ambiguous_or_binary_controls_are_rejected() {
        use super::super::{AxumWsMessage, gateway_requests_cancel};
        let text = |raw: &str| AxumWsMessage::Text(raw.to_owned().into());
        for raw in [
            r#"{"type":"message.cancel","session_id":"s","payload":{}}"#,
            r#"{"type":"message.cancel"}"#,
        ] {
            assert!(gateway_requests_cancel(&text(raw), "s").unwrap());
        }
        assert!(
            !gateway_requests_cancel(
                &text(r#"{"type":"message.send","session_id":"s","payload":{"content":"hello"}}"#),
                "s"
            )
            .unwrap()
        );
        for raw in [
            r#"{"type":"message.cancel","session_id":"foreign"}"#,
            r#"{"type":"message.send","type":"message.cancel"}"#,
            r#"{"type":"message.cancel","session_id":"s","session_id":"foreign"}"#,
            r#"{"type":7}"#,
            "not-json",
        ] {
            assert!(gateway_requests_cancel(&text(raw), "s").is_err());
        }
        assert!(
            gateway_requests_cancel(
                &AxumWsMessage::Binary(br#"{"type":"message.cancel"}"#.as_slice().into()),
                "s"
            )
            .is_err()
        );
    }

    #[test]
    fn queue_age_and_execution_clock_are_distinct_and_never_restarted_by_check() {
        let mut queued = Call::new(1, None);
        queued.admitted = Instant::now() - QUEUE_MAX_AGE;
        assert_eq!(queued.start().unwrap_err().code, "ACTION_QUEUE_EXPIRED");
        let running = Call::new(2, None);
        running.start().unwrap();
        let old = Instant::now() - EXECUTION_MAX_AGE;
        running.state.lock().unwrap().phase = Phase::Running(old);
        for _ in 0..2 {
            assert_eq!(running.check().unwrap_err().code, "ACTION_DEADLINE");
        }
        assert!(
            matches!(running.state.lock().unwrap().phase, Phase::Running(start) if start == old)
        );
    }

    #[test]
    fn cancellation_before_start_has_no_authority_to_start_or_claim_drain() {
        let call = Call::new(1, None);
        call.cancel().unwrap();
        assert_eq!(call.start().unwrap_err().code, "ACTION_CANCELLED");
        assert!(call.status() == CallStatus::Pending);
        call.abandon();
        assert!(call.status() == CallStatus::Clean);
    }

    #[test]
    fn abandoned_running_or_failed_cleanup_remain_uncertain() {
        for explicit_failure in [false, true] {
            let call = Call::new(1, None);
            call.start().unwrap();
            if explicit_failure {
                call.finish(false);
            } else {
                call.abandon();
            }
            call.abandon();
            call.cancel().unwrap();
            assert!(call.status() == CallStatus::Uncertain);
        }
    }

    #[tokio::test]
    async fn terminal_wait_observes_completion_on_either_side_of_registration() {
        let done = Call::new(1, None);
        done.finish(true);
        done.wait_terminal().await;
        let live = Call::new(2, None);
        live.start().unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(live.wait_terminal(), async {
                tokio::task::yield_now().await;
                live.finish(true);
            });
        })
        .await
        .unwrap();
        assert!(live.status() == CallStatus::Clean);
    }
}
