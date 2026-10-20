use super::*;
use crate::{auth::session::SessionStore, config::Config, http::middleware::protected};
use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{get, post},
};
use futures_util::StreamExt;
use std::{future::Future, pin::Pin, sync::Arc, task::Poll};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{Message as ClientMessage, client::IntoClientRequest};

async fn pending<T>(mut future: Pin<&mut impl Future<Output = T>>) {
    std::future::poll_fn(|context| {
        assert!(matches!(future.as_mut().poll(context), Poll::Pending));
        Poll::Ready(())
    })
    .await;
}

fn capture(session: &crate::auth::session::Session) -> TransportSession {
    TransportSession::capture(
        &Config::default(),
        Some(Extension(CurrentSession(session.clone()))),
    )
    .unwrap()
}

fn frame() -> MjpegFrame {
    MjpegFrame {
        header: Bytes::from_static(b"header"),
        data: Bytes::from_static(b"synthetic-image"),
    }
}

#[tokio::test]
async fn mjpeg_revocation_between_chunks_drops_queued_suffix_and_client_lease() {
    for stop_after in [1, 2, 3] {
        let sessions = SessionStore::new();
        let session = sessions.issue("admin", 60).await;
        let fanout = StreamFanout::new(4);
        let chunks = mjpeg_chunks(fanout.subscribe(), capture(&session), fanout.add_client());
        tokio::pin!(chunks);
        assert_eq!(fanout.client_count(), 1);
        fanout.send(frame());
        fanout.send(frame());
        for expected in [b"header".as_slice(), b"synthetic-image", b"\r\n"]
            .into_iter()
            .take(stop_after)
        {
            assert_eq!(chunks.next().await.unwrap().unwrap().as_ref(), expected);
        }
        sessions.revoke(&session.token).await;
        assert!(chunks.next().await.is_none());
        assert_eq!(fanout.client_count(), 0);
    }
}

#[tokio::test]
async fn idle_mjpeg_wait_is_woken_by_logout_or_shortened_expiry_and_releases_client() {
    for expire in [false, true] {
        let sessions = SessionStore::new();
        let session = sessions.issue("admin", 60).await;
        let fanout = StreamFanout::new(4);
        let chunks = mjpeg_chunks(fanout.subscribe(), capture(&session), fanout.add_client());
        tokio::pin!(chunks);
        let mut next = Box::pin(chunks.next());
        pending(next.as_mut()).await;
        if expire {
            sessions.retime(&session.token, 0).await.unwrap();
        } else {
            sessions.revoke(&session.token).await;
        }
        assert!(
            time::timeout(Duration::from_secs(2), next)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(fanout.client_count(), 0);
    }
}

#[tokio::test]
async fn mjpeg_valid_successive_frames_continue_until_their_own_session_ends() {
    let sessions = SessionStore::new();
    let session = sessions.issue("admin", 60).await;
    let unrelated = sessions.issue("admin", 60).await;
    let fanout = StreamFanout::new(4);
    let chunks = mjpeg_chunks(fanout.subscribe(), capture(&session), fanout.add_client());
    tokio::pin!(chunks);
    sessions.revoke(&unrelated.token).await;
    sessions.retime(&session.token, 300).await.unwrap();
    for _ in 0..2 {
        fanout.send(frame());
        for expected in [b"header".as_slice(), b"synthetic-image", b"\r\n"] {
            assert_eq!(chunks.next().await.unwrap().unwrap().as_ref(), expected);
        }
    }
    assert_eq!(fanout.client_count(), 1);
    sessions.revoke(&session.token).await;
    assert!(chunks.next().await.is_none());
    assert_eq!(fanout.client_count(), 0);
}

// The real protected/logout middleware and actual H264 client loop run over a
// real loopback socket. Only capture production is replaced with a bounded
// synthetic fanout; this does not exercise FFI, target hardware or the route's
// Origin policy, which has separate admission checks.
async fn h264_fixture(
    State(state): State<AppState>,
    Extension(fanout): Extension<Arc<StreamFanout<H264DirectFrame>>>,
    current: Option<Extension<CurrentSession>>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    let session = TransportSession::capture(&state.config, current)?;
    let rx = fanout.subscribe();
    Ok(ws.on_upgrade(move |socket| async move {
        let guard = fanout.add_client();
        h264_client(socket, rx, session, guard).await;
    }))
}

struct ServerTask(Option<tokio::task::JoinHandle<()>>);
impl Drop for ServerTask {
    fn drop(&mut self) {
        // Fixture-only final safety on an assertion failure, not runtime drain.
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

#[tokio::test]
async fn actual_authenticated_h264_loop_stops_on_http_logout_and_keeps_new_login_live() {
    let mut config = Config::default();
    config.security.allow_default_admin = false;
    let state = AppState::new(config).await.unwrap();
    let fanout = Arc::new(StreamFanout::<H264DirectFrame>::new(4));
    let router = Router::new()
        .route("/h264", get(h264_fixture))
        .route("/logout", post(crate::api::account::logout))
        .route_layer(from_fn_with_state(state.clone(), protected))
        .layer(Extension(Arc::clone(&fanout)))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut server = ServerTask(Some(tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    })));

    let unauthorized = tokio_tungstenite::connect_async(format!("ws://{address}/h264")).await;
    let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = unauthorized else {
        panic!("unauthenticated socket was not rejected by HTTP authentication");
    };
    assert_eq!(response.status(), 401);

    let old = state.sessions.issue("admin", 60).await;
    let mut request = format!("ws://{address}/h264")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {}", old.token).parse().unwrap(),
    );
    let (mut old_socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    fanout.send(H264DirectFrame {
        packet: Bytes::from_static(b"old-valid"),
    });
    let first = time::timeout(Duration::from_secs(2), old_socket.next())
        .await
        .unwrap();
    assert!(
        matches!(first, Some(Ok(ClientMessage::Binary(data))) if data == b"old-valid".as_slice())
    );

    let next = state.sessions.issue("admin", 60).await;
    let mut request = format!("ws://{address}/h264")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {}", next.token).parse().unwrap(),
    );
    let (mut next_socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let logout_request = format!(
        "POST /logout HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {}\r\nx-csrf-token: {}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        old.token, old.csrf_token
    );
    let logout = time::timeout(Duration::from_secs(2), async {
        let mut connection = tokio::net::TcpStream::connect(address).await?;
        connection.write_all(logout_request.as_bytes()).await?;
        let mut response = Vec::with_capacity(2048);
        connection
            .take(16 * 1024)
            .read_to_end(&mut response)
            .await?;
        Ok::<_, io::Error>(response)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(logout.starts_with(b"HTTP/1.1 200"));
    let closed = time::timeout(Duration::from_secs(2), old_socket.next())
        .await
        .unwrap();
    assert!(matches!(closed, Some(Ok(ClientMessage::Close(_))) | None));
    drop(old_socket);

    fanout.send(H264DirectFrame {
        packet: Bytes::from_static(b"new-valid"),
    });
    let frame = time::timeout(Duration::from_secs(2), next_socket.next())
        .await
        .unwrap();
    assert!(
        matches!(frame, Some(Ok(ClientMessage::Binary(data))) if data == b"new-valid".as_slice())
    );
    assert!(state.sessions.validate(&old.token).await.is_none());
    assert!(state.sessions.validate(&next.token).await.is_some());
    state.sessions.retime(&next.token, 0).await.unwrap();
    let closed = time::timeout(Duration::from_secs(2), next_socket.next())
        .await
        .unwrap();
    assert!(matches!(closed, Some(Ok(ClientMessage::Close(_))) | None));
    drop(next_socket);

    time::timeout(Duration::from_secs(2), async {
        while fanout.client_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stop.send(()).unwrap();
    time::timeout(Duration::from_secs(2), server.0.take().unwrap())
        .await
        .unwrap()
        .unwrap();
}
