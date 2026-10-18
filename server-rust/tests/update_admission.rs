//! Real handler admission only: no install, service, network or device writes.

use axum::{
    body::Body,
    extract::{FromRequest, Multipart, State},
    http::Request,
};
use nanokvm_rust_server::{
    AppError,
    api::{application, system_update},
    config::Config,
    state::AppState,
    update::operation::{Kind, Phase},
};

async fn state(path: &std::path::Path) -> AppState {
    let mut config = Config::default();
    config.security.allow_default_admin = false;
    config.paths.account_file = path.join("account");
    config.paths.update_cache_dir = path.join("cache");
    AppState::new(config).await.unwrap()
}

fn conflict(error: AppError, id: &str) {
    assert!(
        matches!(error, AppError::Conflict(ref text) if text.contains(id)),
        "{error}"
    );
}

#[tokio::test]
async fn public_install_endpoints_share_admission_before_any_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let state = state(temporary.path()).await;
    let owner = state.updates.acquire(Kind::SystemDownload).unwrap();
    let id = state
        .updates
        .snapshot()
        .unwrap()
        .active
        .unwrap()
        .id
        .to_string();
    let request = Request::builder()
        .header("content-type", "multipart/form-data; boundary=fixture")
        .body(Body::from("--fixture--\r\n"))
        .unwrap();
    let multipart = Multipart::from_request(request, &()).await.unwrap();
    conflict(
        application::offline_update(State(state.clone()), multipart)
            .await
            .err()
            .unwrap(),
        &id,
    );
    conflict(
        system_update::install(State(state.clone()))
            .await
            .err()
            .unwrap(),
        &id,
    );
    conflict(
        system_update::rollback(State(state.clone()))
            .await
            .err()
            .unwrap(),
        &id,
    );
    conflict(
        system_update::confirm(State(state.clone()))
            .await
            .err()
            .unwrap(),
        &id,
    );
    let snapshot = application::update_status(State(state.clone()))
        .await
        .unwrap()
        .0
        .data
        .unwrap();
    assert_eq!(snapshot.active.unwrap().id.to_string(), id);
    assert!(snapshot.active.unwrap().phase == Phase::Running);
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
    drop(owner);
    assert!(state.updates.snapshot().unwrap().active.is_none());
}

#[tokio::test]
async fn cloned_app_state_exposes_one_readonly_bounded_operation_status() {
    let temporary = tempfile::tempdir().unwrap();
    let state = state(temporary.path()).await;
    let other = state.clone();
    let owner = state.updates.acquire(Kind::ApplicationOnline).unwrap();
    let status = application::update_status(State(other.clone()))
        .await
        .unwrap();
    let encoded = serde_json::to_vec(&status.0).unwrap();
    assert!(encoded.len() < 300);
    let id = status.0.data.unwrap().active.unwrap().id.to_string();
    assert!(
        !String::from_utf8(encoded)
            .unwrap()
            .contains(&temporary.path().to_string_lossy().to_string())
    );
    conflict(
        system_update::install(State(other)).await.err().unwrap(),
        &id,
    );
    drop(owner);
    assert!(
        application::update_status(State(state))
            .await
            .unwrap()
            .0
            .data
            .unwrap()
            .last
            .unwrap()
            .phase
            == Phase::Failed
    );
}
