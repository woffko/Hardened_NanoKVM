use super::*;
use crate::{
    api::{system_log, system_time},
    config::Config,
    state::AppState,
};
use axum::{Json, extract::State};
use std::{
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::Path,
    task::{Context, Poll, Waker},
};

const LIMIT: Duration = Duration::from_secs(5);

async fn fixture() -> (tempfile::TempDir, AppState) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.paths.account_file = dir.path().join("pwd");
    config.paths.session_secret_file = dir.path().join("session_secret");
    let mut state = AppState::new(config.clone()).await.unwrap();
    state.writers = Arc::new(StateWriters::for_test_config(
        File::open(dir.path()).unwrap(),
        dir.path().join("server.yaml"),
    ));
    let writer = state.writers.configuration().unwrap();
    config.write(&writer).unwrap();
    fs::create_dir_all(dir.path().join("usr/share/zoneinfo/Etc")).unwrap();
    fs::write(
        dir.path().join("usr/share/zoneinfo/Etc/UTC"),
        b"TZif2 fixture timezone",
    )
    .unwrap();
    const SCRIPT: &[u8] = b"#!/bin/sh\nd=${0%/*}\ntag=${0##*/}\nprintf '%s\\n' \"$*\" >> \"$d/$tag.args\"\nif [ -f \"$d/$tag.block\" ]; then\n echo started > \"$d/$tag.started\"\n while [ ! -f \"$d/$tag.release\" ]; do sleep 0.01; done\nfi\nif [ -f \"$d/$tag.fail\" ]; then exit 1; fi\nexit 0\n";
    for name in ["time-command", "syslog-command"] {
        let path = dir.path().join(name);
        fs::write(&path, SCRIPT).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    (dir, state)
}

fn time_request(enabled: bool) -> system_time::TimeConfig {
    system_time::TimeConfig {
        ntp_enabled: enabled,
        timezone: "Etc/UTC".into(),
        servers: vec!["192.0.2.123".into()],
    }
}

fn log_request(kernel: bool) -> system_log::SystemLogConfig {
    system_log::SystemLogConfig {
        remote_enabled: true,
        remote_host: "192.0.2.9".into(),
        remote_port: 5514,
        priority: 4,
        buffer_kb: 300,
        rotations: 2,
        small_output: true,
        strip_timestamps: false,
        kernel_enabled: kernel,
        kernel_console_level: 6,
    }
}

fn time_json(root: &Path) -> system_time::TimeConfig {
    serde_json::from_slice(&fs::read(root.join("etc/kvm/time.json")).unwrap()).unwrap()
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

#[tokio::test]
async fn lost_time_set_reply_keeps_full_publication_and_service_followup_owned() {
    let (dir, state) = fixture().await;
    let mut request = Box::pin(system_time::set_config(
        State(state.clone()),
        Json(time_request(true)),
    ));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    drop(state.writers.drain(LIMIT).await.unwrap());
    let config = time_json(dir.path());
    assert!(config.ntp_enabled);
    assert_eq!(config.timezone, "Etc/UTC");
    assert_eq!(config.servers, ["192.0.2.123"]);
    let ntp = fs::read_to_string(dir.path().join("etc/ntp.conf")).unwrap();
    assert!(ntp.contains("server 192.0.2.123 iburst\n"));
    assert!(ntp.contains("restrict default kod nomodify notrap nopeer noquery"));
    assert_eq!(
        fs::read_to_string(dir.path().join("etc/default/ntpd")).unwrap(),
        "NTPD_ARGS=\" -g\"\n"
    );
    assert_eq!(
        fs::read_link(dir.path().join("etc/localtime")).unwrap(),
        Path::new("../usr/share/zoneinfo/Etc/UTC")
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("time-command.args")).unwrap(),
        "restart\n"
    );
}

#[tokio::test]
async fn lost_syslog_reply_keeps_both_defaults_and_both_service_actions_owned() {
    let (dir, state) = fixture().await;
    let mut request = Box::pin(system_log::set_config(
        State(state.clone()),
        Json(log_request(false)),
    ));
    assert!(matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    drop(request);
    drop(state.writers.drain(LIMIT).await.unwrap());
    let config: system_log::SystemLogConfig =
        serde_json::from_slice(&fs::read(dir.path().join("etc/kvm/syslog.json")).unwrap()).unwrap();
    assert!(config.remote_enabled);
    assert_eq!(config.remote_host, "192.0.2.9");
    assert_eq!(config.remote_port, 5514);
    assert!(!config.kernel_enabled);
    let defaults = fs::read_to_string(dir.path().join("etc/default/syslogd")).unwrap();
    assert!(defaults.contains("-R 192.0.2.9:5514 -L"));
    assert!(defaults.contains("-s 300 -b 2 -l 4"));
    assert_eq!(
        fs::read_to_string(dir.path().join("etc/default/klogd")).unwrap(),
        "KLOGD_ARGS='-c 6'\n"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("syslog-command.args")).unwrap(),
        "restart\nstop\n"
    );
}

#[tokio::test]
async fn sync_and_service_chain_survive_reply_cancellation_and_exclude_other_writers() {
    let (dir, state) = fixture().await;
    system_time::set_config(State(state.clone()), Json(time_request(true)))
        .await
        .unwrap();
    fs::remove_file(dir.path().join("time-command.args")).unwrap();
    fs::write(dir.path().join("time-command.block"), b"fixture").unwrap();
    let running = state.clone();
    let request =
        tokio::spawn(async move { system_time::sync_now(State(running)).await.map(|_| ()) });
    wait_file(&dir.path().join("time-command.started")).await;
    assert!(matches!(
        system_log::set_config(State(state.clone()), Json(log_request(true))).await,
        Err(AppError::Conflict(_))
    ));
    assert!(!dir.path().join("etc/kvm/syslog.json").exists());
    request.abort();
    assert!(request.await.err().unwrap().is_cancelled());
    assert!(
        state
            .writers
            .drain(Duration::from_millis(30))
            .await
            .is_err()
    );
    fs::write(dir.path().join("time-command.release"), b"fixture").unwrap();
    drop(state.writers.drain(LIMIT).await.unwrap());
    assert_eq!(
        fs::read_to_string(dir.path().join("time-command.args")).unwrap(),
        "-u 192.0.2.123\nrestart\n"
    );
    system_log::set_config(State(state), Json(log_request(true)))
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(dir.path().join("syslog-command.args")).unwrap(),
        "restart\nrestart\n"
    );
}

#[tokio::test]
async fn paused_time_sync_and_syslog_cannot_write_or_start_commands() {
    let (dir, state) = fixture().await;
    let yaml = fs::read(dir.path().join("server.yaml")).unwrap();
    let barrier = state.writers.drain(LIMIT).await.unwrap();
    assert!(matches!(
        system_time::set_config(State(state.clone()), Json(time_request(true))).await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        system_time::sync_now(State(state.clone())).await,
        Err(AppError::Conflict(_))
    ));
    assert!(matches!(
        system_log::set_config(State(state.clone()), Json(log_request(true))).await,
        Err(AppError::Conflict(_))
    ));
    assert!(!dir.path().join("etc").exists());
    assert!(!dir.path().join("time-command.args").exists());
    assert!(!dir.path().join("syslog-command.args").exists());
    assert_eq!(fs::read(dir.path().join("server.yaml")).unwrap(), yaml);
    drop(barrier);
}

#[tokio::test]
async fn invalid_settings_do_not_publish_or_run_services() {
    let (dir, state) = fixture().await;
    let mut invalid = time_request(true);
    invalid.timezone = "../invalid".into();
    assert!(matches!(
        system_time::set_config(State(state.clone()), Json(invalid)).await,
        Err(AppError::BadRequest(_))
    ));
    let mut invalid = time_request(true);
    invalid.servers = vec!["pool.example;invalid".into()];
    assert!(matches!(
        system_time::set_config(State(state.clone()), Json(invalid)).await,
        Err(AppError::BadRequest(_))
    ));
    let mut invalid = log_request(true);
    invalid.remote_host = "log.example;invalid".into();
    assert!(matches!(
        system_log::set_config(State(state.clone()), Json(invalid)).await,
        Err(AppError::BadRequest(_))
    ));
    assert!(!dir.path().join("etc").exists());
    assert!(!dir.path().join("time-command.args").exists());
    assert!(!dir.path().join("syslog-command.args").exists());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn time_publication_error_stops_before_service_without_claiming_rollback() {
    let (dir, state) = fixture().await;
    fs::create_dir_all(dir.path().join("etc/ntp.conf")).unwrap();
    assert!(
        system_time::set_config(State(state.clone()), Json(time_request(false)))
            .await
            .is_err()
    );
    // Existing multi-file crash/rollback deficiency remains visible: JSON was
    // published before the derived-file error. Drain here proves no active work,
    // NOT that this failed transaction produced coherent device state.
    assert!(!time_json(dir.path()).ntp_enabled);
    assert!(dir.path().join("etc/ntp.conf").is_dir());
    assert!(!dir.path().join("time-command.args").exists());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn syslog_publication_error_stops_before_services_without_claiming_rollback() {
    let (dir, state) = fixture().await;
    fs::create_dir_all(dir.path().join("etc/default/klogd")).unwrap();
    assert!(
        system_log::set_config(State(state.clone()), Json(log_request(true)))
            .await
            .is_err()
    );
    assert!(dir.path().join("etc/kvm/syslog.json").is_file());
    assert!(dir.path().join("etc/default/syslogd").is_file());
    assert!(!dir.path().join("syslog-command.args").exists());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn time_service_failure_is_reported_and_does_not_leak_the_owner() {
    let (dir, state) = fixture().await;
    fs::write(dir.path().join("time-command.fail"), b"fixture").unwrap();
    assert!(matches!(
        system_time::set_config(State(state.clone()), Json(time_request(false))).await,
        Err(AppError::Internal(_))
    ));
    assert!(!time_json(dir.path()).ntp_enabled);
    assert_eq!(
        fs::read_to_string(dir.path().join("time-command.args")).unwrap(),
        "stop\n"
    );
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn syslog_first_service_failure_does_not_launch_the_second_service() {
    let (dir, state) = fixture().await;
    fs::write(dir.path().join("syslog-command.fail"), b"fixture").unwrap();
    assert!(matches!(
        system_log::set_config(State(state.clone()), Json(log_request(true))).await,
        Err(AppError::Internal(_))
    ));
    assert_eq!(
        fs::read_to_string(dir.path().join("syslog-command.args")).unwrap(),
        "restart\n"
    );
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn disabled_sync_does_not_run_ntpdate_or_restart_ntpd() {
    let (dir, state) = fixture().await;
    system_time::set_config(State(state.clone()), Json(time_request(false)))
        .await
        .unwrap();
    fs::remove_file(dir.path().join("time-command.args")).unwrap();
    assert!(matches!(
        system_time::sync_now(State(state.clone())).await,
        Err(AppError::BadRequest(_))
    ));
    assert!(!dir.path().join("time-command.args").exists());
    drop(state.writers.drain(LIMIT).await.unwrap());
}

#[tokio::test]
async fn missing_fixture_command_fails_without_falling_back_to_device_commands() {
    let (dir, state) = fixture().await;
    fs::remove_file(dir.path().join("time-command")).unwrap();
    fs::remove_file(dir.path().join("syslog-command")).unwrap();
    assert!(
        system_time::set_config(State(state.clone()), Json(time_request(true)))
            .await
            .is_err()
    );
    assert!(
        system_log::set_config(State(state.clone()), Json(log_request(true)))
            .await
            .is_err()
    );
    assert!(!dir.path().join("time-command.args").exists());
    assert!(!dir.path().join("syslog-command.args").exists());
    drop(state.writers.drain(LIMIT).await.unwrap());
}
