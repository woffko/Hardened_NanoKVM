use super::*;
use crate::http::middleware::protected;
use axum::{Router, middleware::from_fn_with_state, routing::get};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

// Like every other authenticated WebSocket, the Pico gateway refuses a
// missing or foreign Origin before it takes the session lock, runs the
// Startup job or connects upstream. A same-host Origin passes this check.
#[tokio::test]
async fn the_gateway_socket_refuses_a_missing_or_foreign_origin_before_any_effect() {
    let _serial = SESSION_LOCK_TESTS.lock().await;
    let config = crate::config::Config {
        stun: "disable".into(),
        ..crate::config::Config::default()
    };
    let state = AppState::new(config).await.unwrap();
    let login = state.sessions.issue("admin", 60).await;
    let router = Router::new()
        .route("/api/picoclaw/gateway/ws", get(gateway_ws))
        .route_layer(from_fn_with_state(state.clone(), protected))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let session = "origin-refusal-fixture";
    let same = format!("http://{address}");
    for origin in [None, Some("http://foreign.invalid"), Some(same.as_str())] {
        let mut request = format!("ws://{address}/api/picoclaw/gateway/ws?session_id={session}")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", login.token).parse().unwrap(),
        );
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert(axum::http::header::ORIGIN, origin.parse().unwrap());
        }
        let Err(tokio_tungstenite::tungstenite::Error::Http(response)) =
            tokio_tungstenite::connect_async(request).await
        else {
            panic!("no upstream gateway exists in this fixture");
        };
        if origin == Some(same.as_str()) {
            // Past the Origin check, the handler reports its own state.
            assert_ne!(response.status(), StatusCode::FORBIDDEN);
        } else {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        // Neither outcome leaves this request's session holding the lock.
        // Other tests may hold it for their own sessions at the same time.
        assert_ne!(session_lock_owner(), session);
    }
    server.abort();
}

// The relay ends with the login that opened it: revoking the session closes an
// idle socket with 1008, and the upstream gateway is closed too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_gateway_relay_closes_when_its_session_ends() {
    // The relay's first ping renews the process-wide Pico session lock.
    let _serial = SESSION_LOCK_TESTS.lock().await;
    let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_address = upstream_listener.local_addr().unwrap();
    let (upstream_closed, upstream_close) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = upstream_listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = socket.next().await {
            if message.is_close() {
                break;
            }
        }
        let _ = upstream_closed.send(());
    });

    let config = crate::config::Config {
        stun: "disable".into(),
        ..crate::config::Config::default()
    };
    let state = AppState::new(config).await.unwrap();
    let login = state.sessions.issue("admin", 60).await;
    let transport = TransportSession::capture(
        &state.config,
        Some(Extension(CurrentSession(login.clone()))),
    )
    .unwrap();
    // Long ping and read intervals: only the session end can close the relay.
    let settings = GatewaySettings {
        gateway_host: "127.0.0.1".to_string(),
        gateway_port: upstream_address.port(),
        token: String::new(),
        allow_token_query: false,
        connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
        read_timeout_ms: 60_000,
        write_timeout_ms: 1_000,
        ping_interval_ms: 60_000,
        max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        model_configured: true,
        model_name: "model".to_string(),
        target_model_name: "model".to_string(),
    };
    let worker = Arc::clone(&state.picoclaw_worker);
    let relay = Router::new().route(
        "/relay",
        get(move |ws: WebSocketUpgrade| async move {
            let upstream = connect_gateway_upstream(&settings, "relay-fixture")
                .await
                .unwrap();
            ws.on_upgrade(move |socket| {
                handle_gateway_socket(
                    "relay-fixture".to_string(),
                    socket,
                    upstream,
                    settings,
                    worker,
                    transport,
                )
            })
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, relay).await.unwrap() });
    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{address}/relay"))
        .await
        .unwrap();

    // While the login lives, the idle relay stays open.
    assert_eq!(
        next_frame(&mut client, Duration::from_millis(300)).await,
        None
    );
    state.sessions.revoke(&login.token).await;
    let closed = next_frame(&mut client, Duration::from_secs(2)).await;
    let Some(TungsteniteMessage::Close(Some(frame))) = closed else {
        panic!("expected a close frame after the session ended, got {closed:?}");
    };
    assert_eq!(u16::from(frame.code), CLOSE_SESSION_ENDED);
    time::timeout(Duration::from_secs(2), upstream_close)
        .await
        .expect("the upstream gateway stayed open")
        .unwrap();
    assert_ne!(session_lock_owner(), "relay-fixture");
    server.abort();
}

/// The next frame other than a ping or pong, if one arrives within `limit`.
async fn next_frame(client: &mut GatewayUpstream, limit: Duration) -> Option<TungsteniteMessage> {
    let deadline = time::Instant::now() + limit;
    loop {
        match time::timeout_at(deadline, client.next()).await {
            Err(_) => return None,
            Ok(Some(Ok(TungsteniteMessage::Ping(_) | TungsteniteMessage::Pong(_)))) => {}
            Ok(Some(Ok(message))) => return Some(message),
            Ok(other) => panic!("the relay socket failed: {other:?}"),
        }
    }
}
