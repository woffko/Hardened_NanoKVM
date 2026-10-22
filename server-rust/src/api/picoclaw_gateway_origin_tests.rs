use super::*;
use crate::http::middleware::protected;
use axum::{Router, middleware::from_fn_with_state, routing::get};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

// Like every other authenticated WebSocket, the Pico gateway refuses a
// missing or foreign Origin before it takes the session lock, runs the
// Startup job or connects upstream. A same-host Origin passes this check.
#[tokio::test]
async fn the_gateway_socket_refuses_a_missing_or_foreign_origin_before_any_effect() {
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
        // Neither outcome leaves the session lock held.
        assert!(ensure_session_lock(session).is_ok());
        release_session_lock(session);
    }
    server.abort();
}
