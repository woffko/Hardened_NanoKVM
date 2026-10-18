use super::*;
use std::{
    fs::File,
    task::{Context, Poll, Waker},
};

const LIMIT: Duration = Duration::from_secs(5);

async fn fixture(delay: Duration) -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path(), delay).await;
    (dir, state)
}

async fn state_at(root: &Path, delay: Duration) -> AppState {
    let mut config = Config {
        proto: "https".into(),
        ..Config::default()
    };
    config.paths.account_file = root.join("pwd");
    config.paths.session_secret_file = root.join("session_secret");
    let mut state = AppState::new(config.clone()).await.unwrap();
    state.writers = Arc::new(StateWriters::for_test_config(
        File::open(root).unwrap(),
        root.join("server.yaml"),
    ));
    state.firewall = Arc::new(FirewallController {
        control: Arc::new(Mutex::new(ControlState::default())),
        paths: Arc::new(FirewallPaths {
            config: root.join("firewall.json"),
            pending: root.join("pending.json"),
        }),
        rollback_delay: delay,
        command: Some("/bin/true".into()),
    });
    let writer = state.writers.configuration().unwrap();
    config.write(&writer).unwrap();
    state
}

async fn set(state: &AppState, mode: &str) {
    set_config(
        State(state.clone()),
        Json(SetFirewallReq { mode: mode.into() }),
    )
    .await
    .unwrap();
}

fn mode(state: &AppState) -> String {
    read_config_at(&state.firewall.paths.config).unwrap().mode
}

fn pending(state: &AppState) -> PendingRollback {
    serde_json::from_slice(&fs::read(&state.firewall.paths.pending).unwrap()).unwrap()
}

async fn wait_file(path: &Path) {
    time::timeout(LIMIT, async {
        while !path.exists() {
            time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
}

fn controlled_command(dir: &Path, state: &mut AppState) {
    let path = dir.join("command");
    fs::write(&path, b"#!/bin/sh\nd=${0%/*}\nif [ \"$1\" = restart ]; then\n if [ -f \"$d/block\" ]; then\n  echo started > \"$d/started\"\n  while [ ! -f \"$d/release\" ]; do sleep 0.01; done\n fi\n if [ -f \"$d/fail\" ]; then exit 1; fi\nfi\nexit 0\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    Arc::get_mut(&mut state.firewall).unwrap().command = Some(path);
}

#[tokio::test]
async fn pending_timer_releases_config_serial_but_retains_common_activity() {
    let (_dir, state) = fixture(Duration::from_secs(60)).await;
    set(&state, MODE_RESTRICTED).await;
    let config = state.writers.configuration().unwrap();
    assert!(state.writers.firewall(&config).is_err());
    drop(config);
    assert!(
        state
            .writers
            .drain(Duration::from_millis(30))
            .await
            .is_err()
    );
    drop(state.drain_writers(LIMIT).await.unwrap());
    assert_eq!(mode(&state), MODE_MODERATE);
}

#[tokio::test]
async fn confirm_joins_the_owner_and_keeps_the_requested_mode() {
    let (_dir, state) = fixture(Duration::from_secs(60)).await;
    set(&state, MODE_PARANOID).await;
    confirm_pending(State(state.clone())).await.unwrap();
    assert_eq!(mode(&state), MODE_PARANOID);
    assert!(!state.firewall.paths.pending.exists());
    assert!(state.firewall.control.lock().await.pending.is_none());
    drop(state.drain_writers(LIMIT).await.unwrap());
    assert_eq!(mode(&state), MODE_PARANOID);
}

#[tokio::test]
async fn replacement_joins_old_timer_before_publishing_a_new_transaction() {
    let (_dir, state) = fixture(Duration::from_secs(60)).await;
    set(&state, MODE_RESTRICTED).await;
    let first = pending(&state);
    set(&state, MODE_PARANOID).await;
    let second = pending(&state);
    assert_ne!(first.transaction_id, second.transaction_id);
    assert_eq!(second.previous_mode, MODE_MODERATE);
    assert_eq!(mode(&state), MODE_PARANOID);
    confirm_pending(State(state.clone())).await.unwrap();
    drop(state.drain_writers(LIMIT).await.unwrap());
    assert_eq!(mode(&state), MODE_PARANOID);
}

#[tokio::test]
async fn deadline_still_rolls_back_without_a_confirmation() {
    let (_dir, state) = fixture(Duration::from_millis(40)).await;
    set(&state, MODE_RESTRICTED).await;
    time::timeout(LIMIT, async {
        while state.firewall.paths.pending.exists() {
            time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(mode(&state), MODE_MODERATE);
    drop(state.drain_writers(LIMIT).await.unwrap());
}

#[tokio::test]
async fn lost_set_reply_still_installs_an_owned_rollback_that_drain_joins() {
    let (_dir, state) = fixture(Duration::from_secs(60)).await;
    let mut request = Box::pin(set_config(
        State(state.clone()),
        Json(SetFirewallReq {
            mode: MODE_RESTRICTED.into(),
        }),
    ));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    // The owned root has the controller mutex, so drain must wait for the
    // operation to install its timer before asking that timer to roll back.
    let barrier = state.drain_writers(LIMIT).await.unwrap();
    assert_eq!(mode(&state), MODE_MODERATE);
    assert!(!state.firewall.paths.pending.exists());
    assert!(state.firewall.control.lock().await.pending.is_none());
    assert!(
        set_config(
            State(state.clone()),
            Json(SetFirewallReq {
                mode: MODE_BASELINE.into()
            })
        )
        .await
        .is_err()
    );
    drop(barrier);
}

#[tokio::test]
async fn lost_confirmation_reply_cannot_silently_turn_into_a_rollback() {
    let (_dir, state) = fixture(Duration::from_secs(60)).await;
    set(&state, MODE_RESTRICTED).await;
    let mut request = Box::pin(confirm_pending(State(state.clone())));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    drop(state.drain_writers(LIMIT).await.unwrap());
    assert_eq!(mode(&state), MODE_RESTRICTED);
    assert!(!state.firewall.paths.pending.exists());
}

#[tokio::test]
async fn cancelled_stop_waiter_keeps_the_join_handle_and_command_activity() {
    let (dir, mut state) = fixture(Duration::from_secs(60)).await;
    controlled_command(dir.path(), &mut state);
    set(&state, MODE_RESTRICTED).await;
    fs::write(dir.path().join("block"), b"fixture").unwrap();
    let waiting = state.clone();
    let waiter = tokio::spawn(async move { waiting.drain_writers(LIMIT).await });
    wait_file(&dir.path().join("started")).await;
    waiter.abort();
    assert!(waiter.await.err().unwrap().is_cancelled());
    assert!(state.firewall.control.lock().await.pending.is_some());
    assert!(
        state
            .writers
            .drain(Duration::from_millis(30))
            .await
            .is_err()
    );
    fs::write(dir.path().join("release"), b"fixture").unwrap();
    drop(state.drain_writers(LIMIT).await.unwrap());
    assert!(!state.firewall.paths.pending.exists());
}

#[tokio::test]
async fn stop_deadline_does_not_claim_success_or_abandon_the_owner() {
    let (dir, mut state) = fixture(Duration::from_secs(60)).await;
    controlled_command(dir.path(), &mut state);
    set(&state, MODE_RESTRICTED).await;
    fs::write(dir.path().join("block"), b"fixture").unwrap();
    assert!(
        state
            .drain_writers(Duration::from_millis(40))
            .await
            .is_err()
    );
    assert!(state.firewall.control.lock().await.pending.is_some());
    fs::write(dir.path().join("release"), b"fixture").unwrap();
    drop(state.drain_writers(LIMIT).await.unwrap());
}

#[tokio::test]
async fn foreign_marker_identity_aborts_without_overwriting_its_config() {
    let (_dir, state) = fixture(Duration::from_secs(60)).await;
    set(&state, MODE_RESTRICTED).await;
    let mut foreign = pending(&state);
    foreign.transaction_id[0] ^= 1;
    write_pending_at(&state.firewall.paths.pending, &foreign).unwrap();
    assert!(state.drain_writers(LIMIT).await.is_err());
    assert_eq!(mode(&state), MODE_RESTRICTED);
    assert_eq!(pending(&state), foreign);
    fs::remove_file(&state.firewall.paths.pending).unwrap();
    assert!(state.drain_writers(LIMIT).await.is_err());
    set(&state, MODE_MODERATE).await;
    drop(state.drain_writers(LIMIT).await.unwrap());
}

#[tokio::test]
async fn failed_rollback_is_sticky_until_an_explicit_successful_recovery() {
    let (dir, mut state) = fixture(Duration::from_secs(60)).await;
    controlled_command(dir.path(), &mut state);
    set(&state, MODE_RESTRICTED).await;
    fs::write(dir.path().join("fail"), b"fixture").unwrap();
    assert!(state.drain_writers(LIMIT).await.is_err());
    assert!(state.firewall.paths.pending.exists());
    fs::remove_file(&state.firewall.paths.pending).unwrap();
    assert!(state.drain_writers(LIMIT).await.is_err());
    fs::remove_file(dir.path().join("fail")).unwrap();
    set(&state, MODE_MODERATE).await;
    drop(state.drain_writers(LIMIT).await.unwrap());
}

#[tokio::test]
async fn orphan_marker_is_not_confirmed_or_treated_as_quiescent() {
    let (_dir, state) = fixture(Duration::from_secs(60)).await;
    fs::write(&state.firewall.paths.pending, b"legacy fixture marker").unwrap();
    assert!(confirm_pending(State(state.clone())).await.is_err());
    assert!(state.drain_writers(LIMIT).await.is_err());
    set(&state, MODE_MODERATE).await;
    drop(state.drain_writers(LIMIT).await.unwrap());
}

#[tokio::test]
async fn admitted_tls_followup_can_settle_firewall_after_new_admission_closes() {
    let (_dir, state) = fixture(Duration::from_secs(60)).await;
    set(&state, MODE_RESTRICTED).await;
    let config = state.writers.configuration().unwrap();
    let pause = state.writers.pause().unwrap();
    state
        .firewall
        .force_moderate_mode(&state.writers, &config)
        .await
        .unwrap();
    assert_eq!(mode(&state), MODE_MODERATE);
    assert!(!state.firewall.paths.pending.exists());
    assert!(state.writers.configuration().is_err());
    drop(config);
    drop(pause.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn paused_or_invalid_https_requests_do_not_write_or_spawn_a_timer() {
    let (_dir, state) = fixture(Duration::from_secs(60)).await;
    let barrier = state.drain_writers(LIMIT).await.unwrap();
    assert!(
        set_config(
            State(state.clone()),
            Json(SetFirewallReq {
                mode: MODE_RESTRICTED.into()
            })
        )
        .await
        .is_err()
    );
    assert!(confirm_pending(State(state.clone())).await.is_err());
    assert!(!state.firewall.paths.config.exists());
    assert!(!state.firewall.paths.pending.exists());
    drop(barrier);
    let writer = state.writers.configuration().unwrap();
    let mut config = Config::read_for(&writer).unwrap();
    config.proto = "http".into();
    config.write(&writer).unwrap();
    drop(writer);
    assert!(matches!(
        set_config(
            State(state.clone()),
            Json(SetFirewallReq {
                mode: MODE_RESTRICTED.into()
            })
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
    assert!(!state.firewall.paths.config.exists());
    assert!(!state.firewall.paths.pending.exists());
    drop(state.drain_writers(LIMIT).await.unwrap());
}

#[tokio::test]
async fn firewall_owner_is_exclusive_across_an_independent_process() {
    use std::{io::Read, process::Stdio};
    use tokio::io::AsyncWriteExt;
    const ROOT_ENV: &str = "NANOKVM_FIREWALL_OWNER_TEST_ROOT";
    if let Some(root) = std::env::var_os(ROOT_ENV) {
        let root = PathBuf::from(root);
        let state = state_at(&root, Duration::from_secs(60)).await;
        set(&state, MODE_RESTRICTED).await;
        fs::write(root.join("child-ready"), b"fixture").unwrap();
        tokio::task::spawn_blocking(|| {
            let mut byte = [0];
            std::io::stdin().read_exact(&mut byte).unwrap();
        })
        .await
        .unwrap();
        confirm_pending(State(state)).await.unwrap();
        return;
    }
    let (dir, state) = fixture(Duration::from_secs(60)).await;
    // Environment is child-local; no test mutates global process configuration.
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "api::system_firewall::writer_tests::firewall_owner_is_exclusive_across_an_independent_process", "--test-threads=1"])
        .env(ROOT_ENV, dir.path())
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped())
        .kill_on_drop(true).spawn().unwrap();
    wait_file(&dir.path().join("child-ready")).await;
    assert_eq!(mode(&state), MODE_RESTRICTED);
    let before = fs::read(&state.firewall.paths.pending).unwrap();
    assert!(matches!(
        set_config(
            State(state.clone()),
            Json(SetFirewallReq {
                mode: MODE_BASELINE.into()
            })
        )
        .await,
        Err(AppError::Conflict(_))
    ));
    assert!(confirm_pending(State(state.clone())).await.is_err());
    assert!(state.drain_writers(LIMIT).await.is_err());
    assert_eq!(fs::read(&state.firewall.paths.pending).unwrap(), before);
    assert_eq!(mode(&state), MODE_RESTRICTED);
    child.stdin.take().unwrap().write_all(b"x").await.unwrap();
    let result = time::timeout(LIMIT, child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    drop(state.drain_writers(LIMIT).await.unwrap());
    set(&state, MODE_BASELINE).await;
    assert_eq!(mode(&state), MODE_BASELINE);
}

#[test]
fn pending_read_is_bounded_and_rejects_links_modes_and_special_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pending");
    let expected = PendingRollback {
        transaction_id: [3; 16],
        previous_mode: MODE_MODERATE.into(),
        requested_mode: MODE_RESTRICTED.into(),
        created_at: 1,
    };
    write_pending_at(&path, &expected).unwrap();
    assert_eq!(read_pending_at(&path).unwrap(), expected);
    fs::write(&path, vec![b' '; MAX_PENDING_BYTES + 1]).unwrap();
    assert!(read_pending_at(&path).is_err());
    write_pending_at(&path, &expected).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_pending_at(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = dir.path().join("alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(read_pending_at(&path).is_err());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&alias, &path).unwrap();
    assert!(read_pending_at(&path).is_err());
    fs::remove_file(&path).unwrap();
    nix::unistd::mkfifo(
        &path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(read_pending_at(&path).is_err());
}
