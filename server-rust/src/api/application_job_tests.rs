use super::*;
use crate::update::app_slot::{Phase, issuer_tests::prepared_fixture, job_status_fixture};
use axum::body::to_bytes;
use serde_json::{Value, json};
use std::{fs, io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};

const ID: &str = "0123456789abcdef0123456789abcdef";

async fn decode(response: Response, status: StatusCode) -> Value {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn only_nonzero_canonical_transaction_ids_are_accepted() {
    for byte in 1..=u8::MAX {
        let id = [byte; 16];
        let encoded = format!("{:032x}", u128::from_be_bytes(id));
        assert_eq!(parse_id(&encoded), Some(id));
    }
    for raw in [
        "",
        "0",
        "00000000000000000000000000000000",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef0",
        "0123456789ABCDEF0123456789ABCDEF",
        " 123456789abcdef0123456789abcdef",
        "0123456789abcdef0123456789abcdeg",
        "../../../../../../../../etc/passwd",
        "éééééééééééééééé",
    ] {
        assert!(parse_id(raw).is_none(), "{raw}");
    }
}

#[tokio::test]
async fn every_phase_is_observed_without_inventing_health_or_completion() {
    for phase in [
        Phase::Prepared,
        Phase::Publishing,
        Phase::Published,
        Phase::Committed,
        Phase::RollingBack,
        Phase::RolledBack,
    ] {
        let archived = matches!(phase, Phase::Committed | Phase::RolledBack);
        let response = query(ID.into(), Arc::new(Semaphore::new(1)), move |id| {
            Ok(Some(JobStatus {
                transaction: id,
                phase,
                version: "2.0.43".into(),
                archived,
                inactive_payload_retained: !archived,
            }))
        })
        .await;
        assert_eq!(
            decode(response, StatusCode::OK).await,
            json!({
                "code": 0, "msg": "success", "data": {
                    "transactionId": ID, "state": "observed", "phase": phase.label(),
                    "version": "2.0.43", "archived": archived,
                    "inactivePayloadRetained": !archived
                }
            })
        );
    }
}

#[tokio::test]
async fn busy_and_unknown_or_expired_never_become_failed_or_successful_installation() {
    for busy in [false, true] {
        let response = query(ID.into(), Arc::new(Semaphore::new(1)), move |_| {
            if busy { Err(SlotError::Busy) } else { Ok(None) }
        })
        .await;
        assert_eq!(
            decode(response, StatusCode::OK).await,
            json!({
                "code": 0, "msg": "success", "data": {
                    "transactionId": ID,
                    "state": if busy { "busy" } else { "unknownOrExpired" }
                }
            })
        );
    }
}

#[tokio::test]
async fn unsafe_corrupt_io_wrong_transaction_and_worker_loss_are_unavailable_not_absent() {
    for case in 0..5 {
        let slots = Arc::new(Semaphore::new(1));
        let response = query(ID.into(), Arc::clone(&slots), move |_| match case {
            0 => Err(SlotError::Unsafe),
            1 => Err(SlotError::Invalid),
            2 => Err(SlotError::Io(io::Error::other(
                "private fixture path must not escape",
            ))),
            3 => Ok(Some(JobStatus {
                transaction: [1; 16],
                phase: Phase::Committed,
                version: "2.0.43".into(),
                archived: true,
                inactive_payload_retained: true,
            })),
            _ => panic!("synthetic lookup worker loss"),
        })
        .await;
        assert_eq!(
            decode(response, StatusCode::SERVICE_UNAVAILABLE).await,
            json!({"code": -503, "msg": "app job status is unavailable"})
        );
        assert_eq!(slots.available_permits(), 1);
    }
}

#[tokio::test]
async fn invalid_id_is_rejected_before_capacity_or_filesystem_work() {
    let slots = Arc::new(Semaphore::new(0));
    let response = query("../invalid".into(), slots, |_| {
        panic!("invalid ID must never reach lookup")
    })
    .await;
    assert_eq!(
        decode(response, StatusCode::BAD_REQUEST).await,
        json!({"code": -1, "msg": "invalid app update transaction ID"})
    );
}

#[tokio::test]
async fn actual_prepared_job_is_readable_under_issuer_exclusion_without_any_mutation() {
    let root = tempfile::tempdir().unwrap();
    let (owner, prepared) = prepared_fixture(root.path()).await;
    let transaction = prepared.transaction();
    let id = format!("{:032x}", u128::from_be_bytes(transaction));
    let old = fs::read(root.path().join("kvmapp/identity")).unwrap();
    let path = root.path().join("application-slot/current/state");
    let before = fs::read(&path).unwrap();
    let source = root.path().to_path_buf();
    let response = query(id.clone(), Arc::new(Semaphore::new(1)), move |id| {
        job_status_fixture(&source, id)
    })
    .await;
    let body = decode(response, StatusCode::OK).await;
    assert_eq!(body["data"]["transactionId"], id);
    assert_eq!(body["data"]["state"], "observed");
    assert_eq!(body["data"]["phase"], "prepared");
    assert_eq!(body["data"]["archived"], false);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(root.path().join("kvmapp/identity")).unwrap(), old);
    assert!(
        !body
            .to_string()
            .contains(&root.path().to_string_lossy().to_string())
    );
    drop(prepared);
    drop(owner);
}

#[tokio::test]
async fn disconnected_http_waiters_keep_bounded_read_ownership_until_actual_lookup_returns() {
    let slots = Arc::new(Semaphore::new(4));
    let (ready, mut received) = mpsc::channel(4);
    let mut release = Vec::with_capacity(4);
    let mut waiters = Vec::with_capacity(4);
    for index in 0..4 {
        let (send, receive) = std::sync::mpsc::channel();
        release.push(send);
        let ready = ready.clone();
        let slots = Arc::clone(&slots);
        waiters.push(tokio::spawn(query(ID.into(), slots, move |_| {
            ready.try_send(index).unwrap();
            receive.recv().unwrap();
            Ok(None)
        })));
    }
    for _ in 0..4 {
        tokio::time::timeout(Duration::from_secs(30), received.recv())
            .await
            .unwrap()
            .unwrap();
    }
    // An unrelated async task still runs while all blocking readers are held.
    let (send, receive) = oneshot::channel();
    tokio::spawn(async move { send.send(()).unwrap() });
    tokio::time::timeout(Duration::from_secs(30), receive)
        .await
        .unwrap()
        .unwrap();
    for waiter in waiters {
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
    }
    assert_eq!(slots.available_permits(), 0);
    let response = query(ID.into(), Arc::clone(&slots), |_| {
        panic!("saturated lookup must not be queued")
    })
    .await;
    assert_eq!(
        decode(response, StatusCode::TOO_MANY_REQUESTS).await,
        json!({"code": -429, "msg": "app job status capacity is busy"})
    );
    for sender in release {
        sender.send(()).unwrap();
    }
    let permits = tokio::time::timeout(Duration::from_secs(30), slots.acquire_many_owned(4))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(permits.num_permits(), 4);
}

#[test]
fn queued_blocking_lookup_keeps_capacity_after_its_http_waiter_is_cancelled() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let (ready, received) = std::sync::mpsc::channel();
    let (release, held) = std::sync::mpsc::channel();
    let blocker = runtime.spawn_blocking(move || {
        ready.send(()).unwrap();
        held.recv().unwrap();
    });
    received.recv_timeout(Duration::from_secs(30)).unwrap();
    runtime.block_on(async move {
        let slots = Arc::new(Semaphore::new(1));
        let (executed, execution) = oneshot::channel();
        let waiter = tokio::spawn(query(ID.into(), Arc::clone(&slots), move |_| {
            executed.send(()).unwrap();
            Ok(None)
        }));
        tokio::time::timeout(Duration::from_secs(30), async {
            while slots.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert_eq!(slots.available_permits(), 0);
        let response = query(ID.into(), Arc::clone(&slots), |_| {
            panic!("cancelled waiters must not admit extra queued work")
        })
        .await;
        assert_eq!(
            decode(response, StatusCode::TOO_MANY_REQUESTS).await["code"],
            -429
        );
        release.send(()).unwrap();
        blocker.await.unwrap();
        tokio::time::timeout(Duration::from_secs(30), execution)
            .await
            .unwrap()
            .unwrap();
        let _permit = tokio::time::timeout(Duration::from_secs(30), slots.acquire_owned())
            .await
            .unwrap()
            .unwrap();
    });
}

async fn http_request(
    address: std::net::SocketAddr,
    path: &str,
    token: Option<&str>,
) -> (u16, Value) {
    let mut socket = TcpStream::connect(address).await.unwrap();
    let authentication = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\n{authentication}Connection: close\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), socket.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(bytes.len() < 4096);
    let text = std::str::from_utf8(&bytes).unwrap();
    let (headers, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(
        headers
            .lines()
            .any(|line| { line.eq_ignore_ascii_case("cache-control: no-store, max-age=0") })
    );
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn real_registered_route_authenticates_before_parsing_or_read_admission() {
    let root = tempfile::tempdir().unwrap();
    let (owner, prepared) = prepared_fixture(root.path()).await;
    let transaction = prepared.transaction();
    let id = format!("{:032x}", u128::from_be_bytes(transaction));
    let path = root.path().join("application-slot/current/state");
    let original = fs::read(&path).unwrap();
    let entries = fs::read_dir(root.path()).unwrap().count();
    let mut config = crate::config::Config::default();
    config.security.allow_default_admin = false;
    config.security.allow_auth_disable = false;
    config.paths.account_file = root.path().join("account");
    config.paths.web_root = root.path().join("web");
    let mut state = AppState::new(config).await.unwrap();
    state.app_job_test_root = Some(Arc::new(root.path().to_path_buf()));
    assert_eq!(state.app_job_reads.available_permits(), 4);
    let cloned = state.clone();
    assert!(Arc::ptr_eq(&state.app_job_reads, &cloned.app_job_reads));
    let session = state.sessions.issue("fixture-admin", 60).await;
    // Exhaust admission first, then exercise the same registered route using
    // the explicit cfg(test)-only disposable canonical root, not the host root.
    let held = Arc::clone(&state.app_job_reads)
        .acquire_many_owned(4)
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = crate::http::routes::build(state);
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let valid = format!("/api/application/update/jobs/{id}");
    for path in [&valid, "/api/application/update/jobs/invalid"] {
        let (status, body) = http_request(address, path, None).await;
        assert_eq!(status, 401);
        assert_eq!(body["code"], -401);
    }
    let (status, body) = http_request(
        address,
        "/api/application/update/jobs/invalid",
        Some(&session.token),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["code"], -1);
    let (status, body) = http_request(address, &valid, Some(&session.token)).await;
    assert_eq!(status, 429);
    assert_eq!(body["code"], -429);
    drop(held);
    let (status, body) = http_request(address, &valid, Some(&session.token)).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"]["transactionId"], id);
    assert_eq!(body["data"]["state"], "observed");
    assert_eq!(body["data"]["phase"], "prepared");
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut other = transaction;
    other[0] ^= 1;
    if other == [0; 16] {
        other[1] = 1;
    }
    let unknown = format!(
        "/api/application/update/jobs/{:032x}",
        u128::from_be_bytes(other)
    );
    let (status, body) = http_request(address, &unknown, Some(&session.token)).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"]["state"], "unknownOrExpired");
    fs::write(&path, b"malformed fixture record").unwrap();
    let (status, body) = http_request(address, &valid, Some(&session.token)).await;
    assert_eq!(status, 503);
    assert_eq!(
        body,
        json!({"code": -503, "msg": "app job status is unavailable"})
    );
    assert_eq!(fs::read(&path).unwrap(), b"malformed fixture record");
    fs::write(&path, &original).unwrap();
    let (status, body) = http_request(address, &valid, Some(&session.token)).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"]["state"], "observed");
    stop.send(()).unwrap();
    server.await.unwrap();
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), entries);
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(cloned.app_job_reads.available_permits(), 4);
    drop(prepared);
    drop(owner);
}
