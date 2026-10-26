use super::*;
use crate::{
    api::{download, system_update, vm},
    config::Config,
    http::middleware::CurrentSession,
    state::AppState,
};
use axum::{Extension, Json, extract::State};
use std::{
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    task::{Context, Poll, Waker},
};

const LIMIT: Duration = Duration::from_secs(5);

async fn fixture() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config {
        proto: "http".to_string(),
        ..Config::default()
    };
    config.paths.account_file = dir.path().join("pwd");
    config.paths.session_secret_file = dir.path().join("session_secret");
    let mut state = AppState::new(config.clone()).await.unwrap();
    state.writers = Arc::new(StateWriters::for_test_config(
        File::open(dir.path()).unwrap(),
        dir.path().join("server.yaml"),
    ));
    let permit = state.writers.configuration().unwrap();
    config.write(&permit).unwrap();
    (dir, state)
}

#[tokio::test]
async fn distinct_role_proofs_allow_independent_writers_but_drain_waits_both() {
    assert_ne!(
        std::any::TypeId::of::<AccountPermit>(),
        std::any::TypeId::of::<ConfigPermit>()
    );
    let (_dir, state) = fixture().await;
    let account = state.writers.account().unwrap();
    let config = state.writers.configuration().unwrap();
    assert!(state.writers.account().is_err());
    assert!(state.writers.configuration().is_err());
    assert!(
        state
            .writers
            .drain(Duration::from_millis(30))
            .await
            .is_err()
    );
    drop(config);
    assert!(
        state
            .writers
            .drain(Duration::from_millis(30))
            .await
            .is_err()
    );
    drop(account);
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn real_setters_serialize_whole_rmw_and_lost_reply_still_updates_runtime() {
    let (_dir, state) = fixture().await;
    let mut request = Box::pin(vm::set_terminal_enabled(
        State(state.clone()),
        Json(vm::SetTerminalReq { enabled: true }),
    ));
    // Current-thread runtime cannot run the newly owned worker until we yield.
    // Poll once to enroll it, then drop the actual HTTP handler's reply future.
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    assert!(matches!(
        download::set_remote_image_download_enabled(
            State(state.clone()),
            Json(download::SetRemoteImageDownloadReq { enabled: true }),
        )
        .await,
        Err(AppError::Conflict(ref text)) if text.contains("configuration change")
    ));
    let barrier = state.writers.drain(LIMIT).await.unwrap();
    assert!(state.terminal_enabled());
    assert!(!state.remote_image_download_enabled());
    drop(barrier);
    download::set_remote_image_download_enabled(
        State(state.clone()),
        Json(download::SetRemoteImageDownloadReq { enabled: true }),
    )
    .await
    .unwrap();
    let permit = state.writers.configuration().unwrap();
    let persisted = Config::read_for(&permit).unwrap();
    assert!(persisted.security.allow_terminal);
    assert!(persisted.security.allow_remote_image_download);
    assert!(state.remote_image_download_enabled());
    assert!(!persisted.security.allow_raw_system_updates);
    assert_eq!(persisted.security.access_token_duration, 900);
}

#[tokio::test]
async fn lost_session_lock_reply_still_persists_and_retimes_the_live_session() {
    let (_dir, state) = fixture().await;
    let session = state.sessions.issue("fixture", 900).await;
    let mut request = Box::pin(vm::set_session_lock(
        State(state.clone()),
        Extension(CurrentSession(session.clone())),
        Json(vm::SetSessionLockReq { duration: 1800 }),
    ));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    let barrier = state.writers.drain(LIMIT).await.unwrap();
    assert_eq!(state.session_lock_duration(), 1800);
    let current = state.sessions.validate(&session.token).await.unwrap();
    assert!(current.expires_at > session.expires_at);
    assert!(current.expires_at_unix >= session.expires_at_unix + 900);
    drop(barrier);
    let permit = state.writers.configuration().unwrap();
    assert_eq!(
        Config::read_for(&permit)
            .unwrap()
            .security
            .access_token_duration,
        1800
    );
}

#[tokio::test]
async fn paused_yaml_setters_cannot_publish_disk_or_runtime_changes() {
    let (dir, state) = fixture().await;
    let before = fs::read(dir.path().join("server.yaml")).unwrap();
    let barrier = state.writers.drain(LIMIT).await.unwrap();
    assert!(matches!(
        vm::set_terminal_enabled(
            State(state.clone()),
            Json(vm::SetTerminalReq { enabled: true })
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        download::set_remote_image_download_enabled(
            State(state.clone()),
            Json(download::SetRemoteImageDownloadReq { enabled: true })
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    let session = state.sessions.issue("fixture", 900).await;
    assert!(matches!(
        vm::set_session_lock(
            State(state.clone()),
            Extension(CurrentSession(session)),
            Json(vm::SetSessionLockReq { duration: 1800 })
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        system_update::set_raw_enabled(
            State(state.clone()),
            Json(system_update::SetRawUpdateEnabledReq { enabled: true })
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    assert_eq!(fs::read(dir.path().join("server.yaml")).unwrap(), before);
    assert!(!state.terminal_enabled());
    assert!(!state.remote_image_download_enabled());
    assert_eq!(state.session_lock_duration(), 900);
    drop(barrier);
}

#[tokio::test]
async fn raw_flag_setter_preserves_other_fields_and_existing_http_choice() {
    let (_dir, state) = fixture().await;
    system_update::set_raw_enabled(
        State(state.clone()),
        Json(system_update::SetRawUpdateEnabledReq { enabled: true }),
    )
    .await
    .unwrap();
    let permit = state.writers.configuration().unwrap();
    let persisted = Config::read_for(&permit).unwrap();
    assert!(persisted.security.allow_raw_system_updates);
    assert_eq!(persisted.proto, "http");
    assert!(!persisted.security.allow_default_admin);
    assert!(!persisted.security.allow_terminal);
}

#[tokio::test]
async fn parse_or_publication_error_does_not_change_runtime_or_leak_the_permit() {
    let (dir, state) = fixture().await;
    let path = dir.path().join("server.yaml");
    fs::write(&path, b"proto: [broken fixture\n").unwrap();
    assert!(
        vm::set_terminal_enabled(
            State(state.clone()),
            Json(vm::SetTerminalReq { enabled: true })
        )
        .await
        .is_err()
    );
    assert!(!state.terminal_enabled());
    drop(state.writers.drain(LIMIT).await.unwrap());
    fs::remove_file(&path).unwrap();
    let permit = state.writers.configuration().unwrap();
    Config::default().write(&permit).unwrap();
    drop(permit);
    // Permission failures are not reliable on root runners; a path symlink is
    // rejected by the existing publication policy on both root and non-root.
    let target = dir.path().join("target.yaml");
    fs::rename(&path, &target).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(
        vm::set_terminal_enabled(
            State(state.clone()),
            Json(vm::SetTerminalReq { enabled: true })
        )
        .await
        .is_err()
    );
    assert!(!state.terminal_enabled());
    assert!(fs::symlink_metadata(&path).unwrap().is_symlink());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn startup_load_uses_the_config_domain_and_does_not_regenerate_a_secret() {
    let (dir, state) = fixture().await;
    let permit = state.writers.configuration().unwrap();
    let first = Config::load_for(&permit).unwrap();
    assert!(!first.jwt.secret_key.is_empty());
    let path = dir.path().join("session_secret");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bytes = fs::read(&path).unwrap();
    let second = Config::load_for(&permit).unwrap();
    assert!(first.jwt.secret_key == second.jwt.secret_key);
    assert!(fs::read(&path).unwrap() == bytes);
    assert!(Config::read_for(&permit).unwrap().jwt.secret_key.is_empty());
    assert!(state.writers.configuration().is_err());
    drop(permit);
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn no_stdin_command_owner_keeps_config_activity_until_direct_child_reap() {
    use nix::{errno::Errno, sys::wait::waitpid, unistd::Pid};
    let (dir, state) = fixture().await;
    let permit = state.writers.configuration().unwrap();
    let pid_path = dir.path().join("pid");
    let argument = pid_path.clone();
    let request = task::spawn(async move {
        permit
            .command(
                AllowedCommand::CustomForTest("/bin/sh".into()),
                [
                    "-c",
                    "echo $$ > \"$1\"; exec sleep 30",
                    "fixture",
                    argument.to_str().unwrap(),
                ],
                Duration::from_secs(30),
            )
            .await
    });
    let pid = time::timeout(LIMIT, async {
        loop {
            if let Ok(text) = fs::read_to_string(&pid_path)
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
    let barrier = state.writers.drain(LIMIT).await.unwrap();
    assert_eq!(waitpid(Pid::from_raw(pid), None), Err(Errno::ECHILD));
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    drop(barrier);
}

#[tokio::test]
async fn owned_followup_keeps_config_activity_after_the_root_job_replies() {
    let (_dir, state) = fixture().await;
    let permit = state.writers.configuration().unwrap();
    let (started, start) = oneshot::channel();
    let (finish, wait) = oneshot::channel();
    permit
        .run(move |writer| async move {
            task::spawn(async move {
                started.send(()).unwrap();
                wait.await.unwrap();
                writer
                    .blocking(|permit| {
                        let mut config = Config::read_for(permit)?;
                        config.security.allow_terminal = true;
                        config.write(permit)
                    })
                    .await
                    .unwrap();
                drop(writer);
            });
            Ok(())
        })
        .await
        .unwrap();
    start.await.unwrap();
    assert!(
        state
            .writers
            .drain(Duration::from_millis(30))
            .await
            .is_err()
    );
    finish.send(()).unwrap();
    drop(state.writers.drain(LIMIT).await.unwrap());
    let permit = state.writers.configuration().unwrap();
    assert!(Config::read_for(&permit).unwrap().security.allow_terminal);
}
