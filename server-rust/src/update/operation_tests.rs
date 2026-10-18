use super::*;
use std::{collections::BTreeSet, sync::mpsc, time::Duration};

const KINDS: [Kind; 6] = [
    Kind::ApplicationOnline,
    Kind::ApplicationOffline,
    Kind::SystemDownload,
    Kind::SystemInstall,
    Kind::SystemRollback,
    Kind::SystemConfirm,
];

struct ResultCleanup {
    started: Option<oneshot::Sender<()>>,
    finish: mpsc::Receiver<()>,
}
struct PanicCleanup;
impl Drop for PanicCleanup {
    fn drop(&mut self) {
        panic!("synthetic result cleanup panic");
    }
}
impl Drop for ResultCleanup {
    fn drop(&mut self) {
        let _ = self.started.take().unwrap().send(());
        let _ = self.finish.recv_timeout(Duration::from_secs(5));
    }
}

async fn idle(coordinator: &UpdateCoordinator) -> Snapshot {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let state = coordinator.snapshot().unwrap();
            if state.active.is_none() {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("registered work did not finish")
}

#[test]
fn one_common_admission_and_bounded_public_receipt() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let mut ids = BTreeSet::new();
    for kind in KINDS {
        let owner = coordinator.acquire(kind).unwrap();
        let active = coordinator.snapshot().unwrap().active.unwrap();
        let id = active.id.to_string();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(ids.insert(id.clone()));
        for other in KINDS {
            let error = match coordinator.acquire(other) {
                Ok(_) => panic!("concurrent admission"),
                Err(error) => error,
            };
            assert!(matches!(error, AppError::Conflict(ref text) if text.contains(&id)));
        }
        assert!(active.kind == kind && active.phase == Phase::Running);
        drop(owner); // unstarted/abandoned work is never reported as success
        let snapshot = coordinator.snapshot().unwrap();
        assert!(snapshot.active.is_none());
        assert!(snapshot.last.unwrap().phase == Phase::Failed);
        assert!(serde_json::to_vec(&snapshot).unwrap().len() < 256);
    }
}

#[tokio::test]
async fn detached_http_receiver_does_not_cancel_async_job() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::SystemDownload).unwrap();
    let id = coordinator.snapshot().unwrap().active.unwrap().id;
    let (started, start) = oneshot::channel();
    let (finish, wait) = oneshot::channel();
    let request = task::spawn(owner.run(move |_job| async move {
        started.send(()).unwrap();
        wait.await.unwrap();
        Ok(17)
    }));
    start.await.unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(coordinator.snapshot().unwrap().active.unwrap().id == id);
    assert!(matches!(
        coordinator.acquire(Kind::ApplicationOffline),
        Err(AppError::Conflict(_))
    ));
    finish.send(()).unwrap();
    let snapshot = idle(&coordinator).await;
    assert!(snapshot.last.unwrap().id == id && snapshot.last.unwrap().phase == Phase::Finished);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_disconnect_keeps_blocking_work_and_cleanup_exclusive() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::ApplicationOffline).unwrap();
    let (started, start) = oneshot::channel();
    let (finish, wait) = mpsc::channel();
    let (cleaned, clean) = oneshot::channel();
    let request = task::spawn(owner.run(move |job| async move {
        job.blocking("synthetic install", move || {
            started.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            cleaned.send(()).unwrap();
            Ok(())
        })
        .await
    }));
    start.await.unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(matches!(
        coordinator.acquire(Kind::SystemInstall),
        Err(AppError::Conflict(_))
    ));
    finish.send(()).unwrap();
    clean.await.unwrap();
    assert!(idle(&coordinator).await.last.unwrap().phase == Phase::Finished);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_blocking_waiter_retains_admission_and_late_error() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::SystemInstall).unwrap();
    let (started, start) = oneshot::channel();
    let (finish, wait) = mpsc::channel();
    owner
        .run(move |job| async move {
            let work = job.blocking("synthetic cancelled waiter", move || -> Result<()> {
                started.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(5)).unwrap();
                Err(AppError::BadRequest(
                    "synthetic private callback detail".into(),
                ))
            });
            tokio::pin!(work);
            tokio::select! {
                _ = start => Ok(()),
                result = &mut work => { result?; panic!("callback completed without release") }
            }
        })
        .await
        .unwrap();
    assert!(coordinator.snapshot().unwrap().active.is_some());
    assert!(matches!(
        coordinator.acquire(Kind::ApplicationOnline),
        Err(AppError::Conflict(_))
    ));
    finish.send(()).unwrap();
    let snapshot = idle(&coordinator).await;
    assert!(snapshot.last.unwrap().phase == Phase::Failed);
    assert!(
        !serde_json::to_string(&snapshot)
            .unwrap()
            .contains("private")
    );
}

#[tokio::test]
async fn callback_error_and_panic_release_only_after_unwind() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::SystemRollback).unwrap();
    let result: Result<()> = owner
        .run(|job| async move {
            job.blocking("synthetic panic", || panic!("synthetic fixture panic"))
                .await
        })
        .await;
    assert!(result.is_err());
    assert!(idle(&coordinator).await.last.unwrap().phase == Phase::Failed);
    let owner = coordinator.acquire(Kind::SystemConfirm).unwrap();
    let result: Result<()> = owner
        .run(|_| async { Err(AppError::BadRequest("synthetic error".into())) })
        .await;
    assert!(result.is_err());
    assert!(idle(&coordinator).await.last.unwrap().phase == Phase::Failed);
}

#[tokio::test]
async fn retained_restart_owner_blocks_until_finished_and_failure_is_sticky() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::ApplicationOnline).unwrap();
    let restart = owner.run(|job| async { Ok(job) }).await.unwrap();
    assert!(coordinator.snapshot().unwrap().active.is_some());
    restart.record_outcome(false);
    restart.record_outcome(true);
    drop(restart);
    assert!(coordinator.snapshot().unwrap().last.unwrap().phase == Phase::Failed);
}

#[test]
fn poisoned_coordinator_fails_closed() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::SystemDownload).unwrap();
    let poison = Arc::clone(&coordinator);
    assert!(
        std::thread::spawn(move || {
            let _slot = poison.slot.lock().unwrap();
            panic!("synthetic poison");
        })
        .join()
        .is_err()
    );
    drop(owner);
    assert!(coordinator.snapshot().is_err());
    assert!(matches!(
        coordinator.acquire(Kind::ApplicationOffline),
        Err(AppError::Internal(_))
    ));
}

#[tokio::test]
async fn restart_scheduled_inside_worker_survives_lost_reply() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::ApplicationOffline).unwrap();
    let (scheduled, schedule) = oneshot::channel();
    let (reply_finish, reply_wait) = oneshot::channel();
    let (restart_finish, restart_wait) = oneshot::channel();
    let request = task::spawn(owner.run(move |job| async move {
        task::spawn(async move {
            restart_wait.await.unwrap();
            job.record_outcome(false); // synthetic failed restart
        });
        scheduled.send(()).unwrap();
        reply_wait.await.unwrap();
        Ok(())
    }));
    schedule.await.unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    reply_finish.send(()).unwrap();
    assert!(matches!(
        coordinator.acquire(Kind::SystemDownload),
        Err(AppError::Conflict(_))
    ));
    restart_finish.send(()).unwrap();
    assert!(idle(&coordinator).await.last.unwrap().phase == Phase::Failed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discarded_blocking_result_cleanup_still_owns_admission() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::SystemInstall).unwrap();
    let (started, start) = oneshot::channel();
    let (finish_work, wait_work) = mpsc::channel();
    let (cleaned, cleanup) = oneshot::channel();
    let (finish_cleanup, wait_cleanup) = mpsc::channel();
    owner
        .run(move |job| async move {
            let work = job.blocking("synthetic returned-resource cleanup", move || {
                started.send(()).unwrap();
                wait_work.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(ResultCleanup {
                    started: Some(cleaned),
                    finish: wait_cleanup,
                })
            });
            tokio::pin!(work);
            tokio::select! {
                _ = start => Ok(()),
                _ = &mut work => panic!("callback completed before release"),
            }
        })
        .await
        .unwrap();
    finish_work.send(()).unwrap();
    cleanup.await.unwrap();
    assert!(matches!(
        coordinator.acquire(Kind::ApplicationOffline),
        Err(AppError::Conflict(_))
    ));
    finish_cleanup.send(()).unwrap();
    assert!(idle(&coordinator).await.last.unwrap().phase == Phase::Finished);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discarded_http_result_cleanup_still_owns_admission() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::ApplicationOnline).unwrap();
    let (started, start) = oneshot::channel();
    let (finish_work, wait_work) = oneshot::channel();
    let (cleaned, cleanup) = oneshot::channel();
    let (finish_cleanup, wait_cleanup) = mpsc::channel();
    let request = task::spawn(owner.run(move |_job| async move {
        started.send(()).unwrap();
        wait_work.await.unwrap();
        Ok(ResultCleanup {
            started: Some(cleaned),
            finish: wait_cleanup,
        })
    }));
    start.await.unwrap();
    request.abort();
    assert!(request.await.is_err());
    finish_work.send(()).unwrap();
    cleanup.await.unwrap();
    assert!(matches!(
        coordinator.acquire(Kind::SystemDownload),
        Err(AppError::Conflict(_))
    ));
    finish_cleanup.send(()).unwrap();
    assert!(idle(&coordinator).await.last.unwrap().phase == Phase::Finished);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discarded_result_cleanup_panic_cannot_report_success() {
    let coordinator = Arc::new(UpdateCoordinator::default());
    let owner = coordinator.acquire(Kind::ApplicationOnline).unwrap();
    let (started, start) = oneshot::channel();
    let (finish, wait) = oneshot::channel();
    let request = task::spawn(owner.run(move |_| async move {
        started.send(()).unwrap();
        wait.await.unwrap();
        Ok(PanicCleanup)
    }));
    start.await.unwrap();
    request.abort();
    assert!(request.await.is_err());
    finish.send(()).unwrap();
    assert!(idle(&coordinator).await.last.unwrap().phase == Phase::Failed);

    let owner = coordinator.acquire(Kind::SystemInstall).unwrap();
    let (started, start) = oneshot::channel();
    let (finish, wait) = mpsc::channel();
    owner
        .run(move |job| async move {
            let work = job.blocking("synthetic cleanup panic", move || {
                started.send(()).unwrap();
                wait.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(PanicCleanup)
            });
            tokio::pin!(work);
            tokio::select! {
                _ = start => Ok(()),
                _ = &mut work => panic!("work ended before release"),
            }
        })
        .await
        .unwrap();
    finish.send(()).unwrap();
    assert!(idle(&coordinator).await.last.unwrap().phase == Phase::Failed);
}
