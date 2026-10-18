use super::*;
use std::{
    fs::{self, File},
    path::Path,
    sync::mpsc,
};

const LIMIT: Duration = Duration::from_secs(5);
fn gate(path: &Path) -> Arc<StateWriters> {
    Arc::new(StateWriters::for_test_parent(File::open(path).unwrap()))
}
async fn admission_closed(gate: &StateWriters) {
    time::timeout(LIMIT, async {
        loop {
            match gate.lock(Domain::WriterAdmission, true) {
                Err(LockError::Busy) => break,
                Ok(lock) => drop(lock),
                Err(error) => panic!("unexpected fixture error: {error}"),
            }
            time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn drain_closes_new_admission_then_waits_existing_work() {
    let temporary = tempfile::tempdir().unwrap();
    let first = gate(temporary.path());
    let other = gate(temporary.path());
    let writer = first.account().unwrap();
    assert!(matches!(other.account(), Err(AppError::Conflict(_))));
    let draining = Arc::clone(&other);
    let waiter = task::spawn(async move { draining.drain(LIMIT).await });
    admission_closed(&first).await;
    assert!(
        matches!(first.account(), Err(AppError::Conflict(ref text)) if text.contains("paused"))
    );
    assert!(!waiter.is_finished());
    drop(writer);
    let barrier = waiter.await.unwrap().unwrap();
    assert!(first.account().is_err());
    drop(barrier);
    let _next = first.account().unwrap();
}

#[tokio::test]
async fn timeout_or_cancel_reopens_admission_without_faking_a_drained_state() {
    let temporary = tempfile::tempdir().unwrap();
    let gate = gate(temporary.path());
    let writer = gate.account().unwrap();
    assert!(gate.drain(Duration::from_millis(30)).await.is_err());
    drop(gate.lock(Domain::WriterAdmission, true).unwrap());
    let pending = Arc::clone(&gate);
    let waiter = task::spawn(async move { pending.drain(LIMIT).await });
    admission_closed(&gate).await;
    waiter.abort();
    assert!(waiter.await.err().unwrap().is_cancelled());
    drop(gate.lock(Domain::WriterAdmission, true).unwrap());
    assert!(
        matches!(gate.account(), Err(AppError::Conflict(ref text)) if text.contains("account change"))
    );
    drop(writer);
    drop(gate.drain(LIMIT).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_http_reply_does_not_cancel_the_enrolled_job() {
    let temporary = tempfile::tempdir().unwrap();
    let gate = gate(temporary.path());
    let permit = gate.account().unwrap();
    let (started, start) = oneshot::channel();
    let (finish, wait) = mpsc::channel();
    let request = task::spawn(permit.run(move |writer| async move {
        writer
            .blocking(move |_| {
                started.send(()).unwrap();
                wait.recv_timeout(LIMIT).unwrap();
                Ok(())
            })
            .await
    }));
    start.await.unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(gate.drain(Duration::from_millis(30)).await.is_err());
    finish.send(()).unwrap();
    drop(gate.drain(LIMIT).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discarded_blocking_waiter_keeps_its_own_permit() {
    let temporary = tempfile::tempdir().unwrap();
    let gate = gate(temporary.path());
    let permit = gate.account().unwrap();
    let (started, start) = oneshot::channel();
    let (finish, wait) = mpsc::channel();
    permit
        .run(move |writer| async move {
            let work = writer.blocking(move |_| {
                started.send(()).unwrap();
                wait.recv_timeout(LIMIT).unwrap();
                Ok(())
            });
            tokio::pin!(work);
            tokio::select! {
                _ = start => Ok(()),
                _ = &mut work => panic!("fixture worker completed too early"),
            }
        })
        .await
        .unwrap();
    assert!(gate.drain(Duration::from_millis(30)).await.is_err());
    finish.send(()).unwrap();
    drop(gate.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn command_owner_retains_permit_until_cancelled_child_is_reaped() {
    use nix::{errno::Errno, sys::wait::waitpid, unistd::Pid};
    let temporary = tempfile::tempdir().unwrap();
    let gate = gate(temporary.path());
    let permit = gate.account().unwrap();
    let path = temporary.path().join("pid");
    let argument = path.clone();
    let request = task::spawn(async move {
        permit
            .command_with_stdin(
                AllowedCommand::CustomForTest("/bin/sh".into()),
                [
                    "-c",
                    "echo $$ > \"$1\"; exec sleep 30",
                    "fixture",
                    argument.to_str().unwrap(),
                ],
                b"synthetic fixture input",
                Duration::from_secs(30),
            )
            .await
    });
    let pid = time::timeout(LIMIT, async {
        loop {
            if let Ok(text) = fs::read_to_string(&path)
                && let Ok(pid) = text.trim().parse::<i32>()
            {
                return pid;
            }
            time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    let barrier = gate.drain(LIMIT).await.unwrap();
    assert_eq!(waitpid(Pid::from_raw(pid), None), Err(Errno::ECHILD));
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    drop(barrier);
}

#[tokio::test]
async fn account_handlers_reject_paused_writes_before_validation_or_native_commands() {
    use crate::{
        api::account::{self, ChangePasswordReq},
        config::Config,
        http::middleware::CurrentSession,
        state::AppState,
    };
    use axum::{Extension, Json, extract::State};
    let temporary = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.paths.account_file = temporary.path().join("pwd");
    let mut state = AppState::new(config).await.unwrap();
    state.writers = gate(temporary.path());
    let barrier = state.writers.drain(LIMIT).await.unwrap();
    // Deliberately invalid short password: even an admission regression cannot
    // reach real passwd on a host test runner, including a root test runner.
    let request = || {
        Json(ChangePasswordReq {
            username: "fixture".into(),
            password: "short".into(),
        })
    };
    assert!(
        matches!(account::setup_first_account(State(state.clone()), request()).await,
        Err(AppError::Conflict(ref text)) if text.contains("paused"))
    );
    let session = state.sessions.issue("fixture", 900).await;
    assert!(
        matches!(account::change_password(State(state.clone()), Extension(CurrentSession(session)), request()).await,
        Err(AppError::Conflict(ref text)) if text.contains("paused"))
    );
    assert!(!state.config.paths.account_file.exists());
    drop(barrier);
}

#[test]
fn normal_constructor_never_chooses_a_test_parent() {
    let gate = StateWriters::default();
    assert!(gate.parent.is_none());
    assert!(gate.config_path.is_none());
    if !nix::unistd::geteuid().is_root() {
        assert!(matches!(gate.account(), Err(AppError::Internal(_))));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_reply_still_publishes_the_synthetic_web_account_under_its_permit() {
    use crate::auth::password::AccountStore;
    let temporary = tempfile::tempdir().unwrap();
    let gate = gate(temporary.path());
    let store = Arc::new(AccountStore::new(temporary.path().join("pwd")));
    let accounts = Arc::clone(&store);
    let permit = gate.account().unwrap();
    let (started, start) = oneshot::channel();
    let (finish, wait) = oneshot::channel();
    let request = task::spawn(permit.run(move |writer| async move {
        started.send(()).unwrap();
        wait.await.unwrap();
        writer
            .blocking(move |permit| {
                accounts.set_account(permit, "fixture", "synthetic fixture password")
            })
            .await
    }));
    start.await.unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    finish.send(()).unwrap();
    let barrier = gate.drain(LIMIT).await.unwrap();
    assert!(
        store
            .verify("fixture", "synthetic fixture password")
            .unwrap()
    );
    drop(barrier);
}

struct Cleanup {
    started: Option<oneshot::Sender<()>>,
    finish: mpsc::Receiver<()>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.started.take().unwrap().send(());
        let _ = self.finish.recv_timeout(LIMIT);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discarded_callback_result_cleanup_keeps_writer_activity() {
    let temporary = tempfile::tempdir().unwrap();
    let gate = gate(temporary.path());
    let permit = gate.account().unwrap();
    let (started, start) = oneshot::channel();
    let (finish_work, work_wait) = mpsc::channel();
    let (cleanup_started, cleanup) = oneshot::channel();
    let (finish_cleanup, cleanup_wait) = mpsc::channel();
    permit
        .run(move |writer| async move {
            let work = writer.blocking(move |_| {
                started.send(()).unwrap();
                work_wait.recv_timeout(LIMIT).unwrap();
                Ok(Cleanup {
                    started: Some(cleanup_started),
                    finish: cleanup_wait,
                })
            });
            tokio::pin!(work);
            tokio::select! {
                _ = start => Ok(()),
                _ = &mut work => panic!("fixture callback completed too early"),
            }
        })
        .await
        .unwrap();
    finish_work.send(()).unwrap();
    cleanup.await.unwrap();
    assert!(gate.drain(Duration::from_millis(30)).await.is_err());
    finish_cleanup.send(()).unwrap();
    drop(gate.drain(LIMIT).await.unwrap());
}
