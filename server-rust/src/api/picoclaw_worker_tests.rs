use super::*;
use std::{future::Future, pin::Pin, sync::Arc, task::Poll, time::Duration};

async fn poll_pending<T>(mut future: Pin<&mut impl Future<Output = T>>) {
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

fn probe() -> (
    Work,
    mpsc::Receiver<std::thread::ThreadId>,
    mpsc::SyncSender<()>,
) {
    let (started, observed) = mpsc::sync_channel(1);
    let (resume, release) = mpsc::sync_channel(1);
    (Work::Probe { started, release }, observed, resume)
}

pub(super) struct UncertainReports<'a> {
    pub(super) call: &'a Call,
}

impl crate::ws::hid::HidReports for UncertainReports<'_> {
    fn keyboard(&self, _: &[u8; 8]) -> std::io::Result<usize> {
        self.call.cancel().unwrap();
        Ok(1)
    }
    fn absolute(&self, _: &[u8; 6]) -> std::io::Result<usize> {
        panic!("unexpected mouse fixture report")
    }
    fn settle_keyboard(&self) -> std::io::Result<usize> {
        panic!("canceled hold must unwind to cleanup")
    }
    fn settle_absolute(&self) -> std::io::Result<usize> {
        panic!("unexpected mouse fixture settle")
    }
    fn finish(&self) -> std::io::Result<usize> {
        Err(std::io::Error::other("synthetic owned cleanup failure"))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn real_executor_cleanup_failure_pins_uncertainty_and_stops_worker_replacement() {
    let worker = Worker::default();
    let batch =
        super::super::normalize_actions(br#"{"action":"hotkey","keys":["ctrl","alt","Delete"]}"#)
            .and_then(PreparedBatch::prepare)
            .unwrap();
    let error = worker
        .submit(Work::UncertainReports("cleanup-fixture".into(), batch))
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, "HID_CLEANUP_UNCERTAIN");
    assert_eq!(error.index, Some(0));
    let summary = worker
        .cancel(Some("cleanup-fixture"))
        .unwrap()
        .wait(Duration::from_millis(10))
        .await;
    assert_eq!(summary.uncertain_calls, 1);
    assert!(!summary.calls_drained);
    let (work, never_started, _) = probe();
    assert_eq!(
        worker.submit(work).await.err().unwrap().code,
        CODE_RUNTIME_UNAVAILABLE
    );
    assert!(matches!(
        never_started.recv_timeout(Duration::from_secs(1)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn one_thread_bounds_queue_rejects_overflow_and_skips_cancelled_queued_work() {
    let worker = Worker::default();
    assert!(!worker.started());
    let (work, started, release) = probe();
    let mut first = Box::pin(worker.submit(work));
    poll_pending(first.as_mut()).await;
    let thread = started.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(worker.started());
    assert_ne!(thread, std::thread::current().id());

    let (work, cancelled_started, _) = probe();
    let mut queued = Box::pin(worker.submit(work));
    poll_pending(queued.as_mut()).await;
    let (overflow, not_started, _) = probe();
    let Err(error) = worker.submit(overflow).await else {
        panic!("unbounded queue accepted a third call")
    };
    assert_eq!(error.code, CODE_WORKER_BUSY);
    assert!(matches!(
        not_started.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
    drop(queued);
    release.send(()).unwrap();
    assert!(matches!(first.await.unwrap(), Output::Probe));
    assert!(matches!(
        cancelled_started.recv_timeout(Duration::from_secs(2)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));

    let (work, started, release) = probe();
    let mut next = Box::pin(worker.submit(work));
    poll_pending(next.as_mut()).await;
    assert_eq!(
        started.recv_timeout(Duration::from_secs(2)).unwrap(),
        thread
    );
    release.send(()).unwrap();
    assert!(matches!(next.await.unwrap(), Output::Probe));
}

#[tokio::test(flavor = "current_thread")]
async fn abandoned_running_request_does_not_free_the_executor_or_overlap_the_next_call() {
    let worker = Worker::default();
    let (work, started, release) = probe();
    let mut abandoned = Box::pin(worker.submit(work));
    poll_pending(abandoned.as_mut()).await;
    let thread = started.recv_timeout(Duration::from_secs(2)).unwrap();
    drop(abandoned);
    let (work, next_started, next_release) = probe();
    let mut next = Box::pin(worker.submit(work));
    poll_pending(next.as_mut()).await;
    assert!(matches!(
        next_started.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let (overflow, _, _) = probe();
    assert_eq!(
        worker.submit(overflow).await.err().unwrap().code,
        CODE_WORKER_BUSY
    );
    release.send(()).unwrap();
    assert_eq!(
        next_started.recv_timeout(Duration::from_secs(2)).unwrap(),
        thread
    );
    next_release.send(()).unwrap();
    assert!(matches!(next.await.unwrap(), Output::Probe));
}

#[tokio::test(flavor = "current_thread")]
async fn cancel_bypasses_a_full_queue_and_drain_waits_for_the_running_call() {
    let worker = Worker::default();
    let (work, began, release) = probe();
    let mut running = Box::pin(worker.submit(work));
    poll_pending(running.as_mut()).await;
    began.recv_timeout(Duration::from_secs(2)).unwrap();
    let (work, queued_began, _) = probe();
    let mut queued = Box::pin(worker.submit(work));
    poll_pending(queued.as_mut()).await;
    let foreign = worker
        .cancel(Some("foreign-session"))
        .unwrap()
        .wait(Duration::ZERO)
        .await;
    assert_eq!(foreign.matched_calls, 0);
    let receipt = worker.cancel(None).unwrap();
    let pending = receipt.wait(Duration::from_millis(10)).await;
    assert_eq!(pending.matched_calls, 2);
    assert_eq!(pending.pending_calls, 2);
    assert!(!pending.calls_drained);
    let (overflow, _, _) = probe();
    assert_eq!(
        worker.submit(overflow).await.err().unwrap().code,
        CODE_WORKER_BUSY
    );
    release.send(()).unwrap();
    assert!(matches!(running.await.unwrap(), Output::Probe));
    assert_eq!(queued.await.err().unwrap().code, "ACTION_CANCELLED");
    assert!(matches!(
        queued_began.recv_timeout(Duration::from_secs(2)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
    let done = worker
        .cancel(None)
        .unwrap()
        .wait(Duration::from_secs(1))
        .await;
    assert_eq!(done.pending_calls, 0);
    assert!(done.calls_drained);
}

#[tokio::test(flavor = "current_thread")]
async fn old_cancel_receipt_never_retargets_a_reused_control_slot() {
    let worker = Worker::default();
    let (work, began, release) = probe();
    let mut first = Box::pin(worker.submit(work));
    poll_pending(first.as_mut()).await;
    began.recv_timeout(Duration::from_secs(2)).unwrap();
    let old = worker.cancel(None).unwrap();
    release.send(()).unwrap();
    first.await.unwrap();
    let (work, began, release) = probe();
    let mut next = Box::pin(worker.submit(work));
    poll_pending(next.as_mut()).await;
    began.recv_timeout(Duration::from_secs(2)).unwrap();
    let summary = old.wait(Duration::from_secs(1)).await;
    assert!(summary.calls_drained);
    assert_eq!(summary.call_ids, [Some(1), None]);
    let current = worker
        .calls
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .find(|call| call.id == 2)
        .unwrap()
        .clone();
    assert!(current.check().is_ok());
    release.send(()).unwrap();
    next.await.unwrap();
}

#[tokio::test]
async fn call_id_exhaustion_never_wraps_or_executes_unadmitted_work() {
    let worker = Worker::default();
    worker.admission.lock().unwrap().next_id = u64::MAX;
    let (work, began, _) = probe();
    assert_eq!(
        worker.submit(work).await.err().unwrap().code,
        CODE_RUNTIME_UNAVAILABLE
    );
    assert!(matches!(
        began.recv_timeout(Duration::from_secs(1)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
    assert_eq!(worker.admission.lock().unwrap().next_id, u64::MAX);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_executor_is_not_automatically_replaced_or_replayed() {
    let worker = Worker::default();
    let (work, started, release) = probe();
    let mut failed = Box::pin(worker.submit(work));
    poll_pending(failed.as_mut()).await;
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    drop(release); // Deliberate panic in the cfg(test)-only executor probe.
    assert_eq!(failed.await.err().unwrap().code, CODE_RUNTIME_UNAVAILABLE);
    let summary = worker
        .cancel(None)
        .unwrap()
        .wait(Duration::from_millis(10))
        .await;
    assert_eq!(summary.uncertain_calls, 1);
    assert!(!summary.calls_drained);
    let (work, started, _) = probe();
    let Err(error) = worker.submit(work).await else {
        panic!("uncertain executor was replaced")
    };
    assert_eq!(error.code, CODE_RUNTIME_UNAVAILABLE);
    assert!(matches!(
        started.try_recv(),
        Err(mpsc::TryRecvError::Disconnected)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn direct_and_mcp_actions_and_screenshots_all_share_the_same_bounded_admission() {
    use super::super::{HeaderMap, Query, SESSION_ID_HEADER, State, actions, mcp, screenshot};
    use serde_json::json;
    let mut config = crate::config::Config::default();
    config.security.allow_default_admin = false;
    let state = crate::state::AppState::new(config).await.unwrap();
    let (work, started, release) = probe();
    let mut active = Box::pin(state.picoclaw_worker.submit(work));
    poll_pending(active.as_mut()).await;
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    let (work, not_started, _) = probe();
    let mut queued = Box::pin(state.picoclaw_worker.submit(work));
    poll_pending(queued.as_mut()).await;

    let mut headers = HeaderMap::new();
    headers.insert(SESSION_ID_HEADER, "shared-admission-test".parse().unwrap());
    let arguments = json!({"actions":[{"action":"wait","duration_ms":0}]});
    let direct = actions(
        State(state.clone()),
        headers.clone(),
        serde_json::to_vec(&arguments).unwrap().into(),
    )
    .await
    .unwrap();
    let direct_screenshot = screenshot(
        State(state.clone()),
        headers.clone(),
        Query(ScreenshotQuery::default()),
    )
    .await
    .unwrap();
    for response in [direct, direct_screenshot] {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["code"], CODE_WORKER_BUSY);
    }
    for (name, arguments) in [("kvm_actions", arguments), ("kvm_screenshot", json!({}))] {
        let rpc = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}});
        let response = mcp(
            State(state.clone()),
            headers.clone(),
            serde_json::to_vec(&rpc).unwrap().into(),
        )
        .await
        .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["result"]["isError"], true);
        assert!(
            value["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("queue is full")
        );
    }
    drop(queued);
    release.send(()).unwrap();
    assert!(matches!(active.await.unwrap(), Output::Probe));
    assert!(matches!(
        not_started.recv_timeout(Duration::from_secs(2)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn valid_direct_and_mcp_waits_leave_tokio_responsive_and_share_app_worker() {
    use super::super::{SESSION_ID_HEADER, State, actions, mcp};
    use serde_json::json;
    let mut config = crate::config::Config::default();
    config.security.allow_default_admin = false;
    let state = crate::state::AppState::new(config).await.unwrap();
    assert!(Arc::ptr_eq(
        &state.picoclaw_worker,
        &state.clone().picoclaw_worker
    ));
    assert!(!state.picoclaw_worker.started());
    let mut headers = super::super::HeaderMap::new();
    headers.insert(SESSION_ID_HEADER, "worker-valid-wait-test".parse().unwrap());
    for call_mcp in [false, true] {
        let body = json!({"actions":[{"action":"wait","duration_ms":2000}]});
        let mut request = Box::pin(async {
            if call_mcp {
                let rpc = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"kvm_actions","arguments":body}});
                mcp(
                    State(state.clone()),
                    headers.clone(),
                    serde_json::to_vec(&rpc).unwrap().into(),
                )
                .await
            } else {
                actions(
                    State(state.clone()),
                    headers.clone(),
                    serde_json::to_vec(&body).unwrap().into(),
                )
                .await
            }
        });
        let started = std::time::Instant::now();
        poll_pending(request.as_mut()).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        let response = tokio::time::timeout(Duration::from_secs(5), request)
            .await
            .unwrap()
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let result = if call_mcp {
            assert!(value["result"]["isError"].is_null());
            serde_json::from_str(value["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
        } else {
            assert_eq!(value["code"], 0);
            value["data"].clone()
        };
        assert_eq!(result["action"], "wait");
        assert_eq!(result["hid_writes"], 0);
    }
    for call_mcp in [false, true] {
        let body = serde_json::json!({"actions":[{"action":"wait","duration_ms":5000}]});
        let mut request = Box::pin(async {
            if call_mcp {
                let rpc = serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kvm_actions","arguments":body}});
                mcp(
                    State(state.clone()),
                    headers.clone(),
                    serde_json::to_vec(&rpc).unwrap().into(),
                )
                .await
            } else {
                actions(
                    State(state.clone()),
                    headers.clone(),
                    serde_json::to_vec(&body).unwrap().into(),
                )
                .await
            }
        });
        poll_pending(request.as_mut()).await;
        let until = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let waiting = state
                .picoclaw_worker
                .calls
                .lock()
                .unwrap()
                .iter()
                .flatten()
                .any(|call| {
                    call.session.as_deref() == Some("worker-valid-wait-test") && call.waiting()
                });
            if waiting {
                break;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "actual worker wait never began"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let began = std::time::Instant::now();
        if call_mcp {
            let response =
                super::super::release_runtime_session(State(state.clone()), headers.clone())
                    .await
                    .unwrap();
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["code"], 0);
            assert_eq!(value["data"]["released"], true);
            assert_eq!(value["data"]["execution_stop_verified"], false);
            assert_eq!(value["data"]["cancelled_calls"]["matched_calls"], 1);
            assert_eq!(value["data"]["cancelled_calls"]["calls_drained"], true);
        } else {
            let receipt = state
                .picoclaw_worker
                .cancel(Some("worker-valid-wait-test"))
                .unwrap();
            let summary = receipt.wait(Duration::from_secs(1)).await;
            assert_eq!(summary.matched_calls, 1);
            assert!(summary.calls_drained);
        }
        let response = tokio::time::timeout(Duration::from_secs(1), request)
            .await
            .unwrap()
            .unwrap();
        assert!(began.elapsed() < Duration::from_secs(1));
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if call_mcp {
            assert_eq!(value["result"]["isError"], true);
            assert_eq!(
                value["result"]["content"][0]["text"],
                "action call cancelled"
            );
        } else {
            assert_eq!(value["code"], "ACTION_CANCELLED");
        }
    }
    assert!(state.picoclaw_worker.started());
    assert_ne!(super::super::session_lock_owner(), "worker-valid-wait-test");
}
