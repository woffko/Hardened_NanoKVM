use super::*;
use crate::{auth::session::Session, http::middleware::protected};
use axum::{Router, middleware::from_fn_with_state, routing::get};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

fn access(session: &Session) -> PeerAccess {
    PeerAccess::new(
        TransportSession::capture(
            &Config::default(),
            Some(Extension(CurrentSession(session.clone()))),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn real_unconnected_peer_reader_is_joined_before_capacity_reuse() {
    let config = Config {
        stun: "disable".into(),
        ..Config::default()
    };
    let state = AppState::new(config.clone()).await.unwrap();
    let login = state.sessions.issue("admin", 60).await;
    let access = access(&login);
    let mut admission = PeerAdmission::reserve(&state.webrtc.slots).unwrap();
    admission.start();
    let (tx, _rx) = mpsc::channel(SIGNAL_BUFFER);
    let ReadyPeer {
        client,
        rtcp: reader,
    } = ReadyPeer::create(&config, tx, access.clone(), &state.webrtc)
        .await
        .unwrap()
        .unwrap();
    access.stop();
    time::timeout(Duration::from_secs(2), reader)
        .await
        .unwrap()
        .unwrap();
    client.peer.close().await.unwrap();
    admission.cleaned();
    assert_eq!(state.webrtc.slots.available_permits(), 2);
    assert_eq!(state.webrtc.clients().await.iter().flatten().count(), 0);
}

#[tokio::test]
async fn real_library_stop_before_first_read_needs_the_app_latched_stop() {
    let mut media = MediaEngine::default();
    media.register_default_codecs().unwrap();
    let api = APIBuilder::new().with_media_engine(media).build();
    let peer = api
        .new_peer_connection(RTCConfiguration::default())
        .await
        .unwrap();
    let track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_H264.into(),
            ..Default::default()
        },
        "video".into(),
        "fixture".into(),
    ));
    let sender = peer.add_track(track).await.unwrap();
    sender.stop().await.unwrap();
    let mut bytes = [0u8; 1500];
    assert!(
        time::timeout(Duration::from_millis(50), sender.read(&mut bytes))
            .await
            .is_err()
    );
    let store = crate::auth::session::SessionStore::new();
    let login = store.issue("admin", 60).await;
    let access = access(&login);
    access.stop();
    let reader = tokio::spawn(read_rtcp(sender, access));
    time::timeout(Duration::from_secs(2), reader)
        .await
        .unwrap()
        .unwrap();
    peer.close().await.unwrap();
}

#[tokio::test]
async fn full_callback_queue_stops_only_its_peer_without_waiting_for_a_receiver() {
    let store = crate::auth::session::SessionStore::new();
    let login = store.issue("admin", 60).await;
    let access = access(&login);
    let (tx, _rx) = mpsc::channel(1);
    send_signal(&tx, "heartbeat", "").unwrap();
    assert!(send_peer_signal(&access, &tx, "video-candidate", "{}").is_err());
    assert!(store.validate(&login.token).await.is_some());
    assert!(!access.is_active());
}

struct Server {
    address: std::net::SocketAddr,
    state: AppState,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Server {
    async fn start(config: Config) -> Self {
        let router = Router::new().route("/webrtc", get(h264_webrtc_stream));
        Self::with_router(config, router).await
    }

    async fn with_router(config: Config, router: Router<AppState>) -> Self {
        let state = AppState::new(config).await.unwrap();
        let router = router
            .route_layer(from_fn_with_state(state.clone(), protected))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self {
            address,
            state,
            stop: Some(stop),
            task: Some(task),
        }
    }

    fn request(
        &self,
        session: Option<&Session>,
        origin: bool,
    ) -> tokio_tungstenite::tungstenite::http::Request<()> {
        let mut request = format!("ws://{}/webrtc", self.address)
            .into_client_request()
            .unwrap();
        if let Some(session) = session {
            request.headers_mut().insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {}", session.token).parse().unwrap(),
            );
        }
        if origin {
            request.headers_mut().insert(
                axum::http::header::ORIGIN,
                format!("http://{}", self.address).parse().unwrap(),
            );
        }
        request
    }

    async fn capacity(&self, expected: usize) {
        time::timeout(Duration::from_secs(3), async {
            while self.state.webrtc.slots.available_permits() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn finish(mut self) {
        self.state.stop_webrtc().await.unwrap();
        self.stop.take().unwrap().send(()).unwrap();
        time::timeout(Duration::from_secs(3), self.task.take().unwrap())
            .await
            .unwrap()
            .unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // Only fixture panic safety; not a production transport drain.
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn config() -> Config {
    Config {
        stun: "disable".into(),
        ..Config::default()
    }
}

#[tokio::test]
async fn actual_protected_route_rejects_auth_origin_and_third_peer_before_setup() {
    let server = Server::start(config()).await;
    let login = server.state.sessions.issue("admin", 60).await;
    for (session, origin, expected) in [(None, true, 401), (Some(&login), false, 403)] {
        let result = tokio_tungstenite::connect_async(server.request(session, origin)).await;
        let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = result else {
            panic!("expected rejection");
        };
        assert_eq!(response.status().as_u16(), expected);
        assert_eq!(server.state.webrtc.slots.available_permits(), 2);
    }
    let (mut first, _) = tokio_tungstenite::connect_async(server.request(Some(&login), true))
        .await
        .unwrap();
    let (mut second, _) = tokio_tungstenite::connect_async(server.request(Some(&login), true))
        .await
        .unwrap();
    assert!(matches!(first.next().await, Some(Ok(Message::Text(_)))));
    assert!(matches!(second.next().await, Some(Ok(Message::Text(_)))));
    let result = tokio_tungstenite::connect_async(server.request(Some(&login), true)).await;
    let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = result else {
        panic!("expected saturation rejection");
    };
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    first.close(None).await.unwrap();
    second.close(None).await.unwrap();
    drop((first, second));
    server.capacity(2).await;
    server.finish().await;
}

#[tokio::test]
async fn actual_idle_peer_revoke_and_expiry_close_their_socket_but_not_a_new_same_name_login() {
    for expire in [false, true] {
        let server = Server::start(config()).await;
        let old = server.state.sessions.issue("admin", 60).await;
        let next = server.state.sessions.issue("admin", 60).await;
        let (mut first, _) = tokio_tungstenite::connect_async(server.request(Some(&old), true))
            .await
            .unwrap();
        let (mut second, _) = tokio_tungstenite::connect_async(server.request(Some(&next), true))
            .await
            .unwrap();
        assert!(matches!(first.next().await, Some(Ok(Message::Text(_)))));
        assert!(matches!(second.next().await, Some(Ok(Message::Text(_)))));
        if expire {
            server.state.sessions.retime(&old.token, 0).await.unwrap();
        } else {
            server.state.sessions.revoke(&old.token).await;
        }
        let closed = time::timeout(Duration::from_secs(2), first.next())
            .await
            .unwrap();
        assert!(matches!(closed, Some(Ok(Message::Close(_))) | None));
        second
            .send(Message::Text(r#"{"event":"heartbeat","data":""}"#.into()))
            .await
            .unwrap();
        let response = time::timeout(Duration::from_secs(2), second.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(response, Message::Text(text) if text.contains("heartbeat")));
        second.close(None).await.unwrap();
        drop((first, second));
        server.capacity(2).await;
        server.finish().await;
    }
}

#[tokio::test]
async fn actual_signaling_rate_saturation_and_oversize_release_only_after_cleanup() {
    for oversized in [false, true] {
        let mut config = config();
        config.security.webrtc_signals_per_second = 1;
        let server = Server::start(config).await;
        let login = server.state.sessions.issue("admin", 60).await;
        let (mut socket, _) = tokio_tungstenite::connect_async(server.request(Some(&login), true))
            .await
            .unwrap();
        assert!(matches!(socket.next().await, Some(Ok(Message::Text(_)))));
        if oversized {
            socket
                .send(Message::Text("x".repeat(64 * 1024 + 1).into()))
                .await
                .unwrap();
        } else {
            socket
                .send(Message::Text(r#"{"event":"heartbeat","data":""}"#.into()))
                .await
                .unwrap();
            assert!(matches!(socket.next().await, Some(Ok(Message::Text(_)))));
            socket
                .send(Message::Text(r#"{"event":"heartbeat","data":""}"#.into()))
                .await
                .unwrap();
        }
        let closed = time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap();
        assert!(matches!(
            closed,
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None
        ));
        drop(socket);
        server.capacity(2).await;
        server.finish().await;
    }
}

#[tokio::test]
async fn canceled_shutdown_waiter_keeps_the_actual_cleanup_owner_registered() {
    let config = config();
    let state = AppState::new(config).await.unwrap();
    let login = state.sessions.issue("admin", 60).await;
    let access = access(&login);
    let (release, released) = tokio::sync::oneshot::channel();
    let mut admission = state.webrtc.reserve().unwrap();
    admission.start();
    state.webrtc.tasks.lock().unwrap().peers[0] = Some(PeerTask {
        access: access.clone(),
        task: Some(tokio::spawn(async move {
            released.await.unwrap();
            admission.cleaned();
            true
        })),
    });
    let mut first_wait = Box::pin(state.stop_webrtc());
    std::future::poll_fn(|cx| {
        assert!(matches!(
            first_wait.as_mut().poll(cx),
            std::task::Poll::Pending
        ));
        std::task::Poll::Ready(())
    })
    .await;
    assert!(!access.is_active());
    assert!(state.webrtc.slots.is_closed());
    assert!(state.webrtc.reserve().is_none());
    drop(first_wait);
    assert!(
        state.webrtc.tasks.lock().unwrap().peers[0]
            .as_ref()
            .unwrap()
            .task
            .is_some()
    );
    release.send(()).unwrap();
    time::timeout(Duration::from_secs(2), state.stop_webrtc())
        .await
        .unwrap()
        .unwrap();
    assert!(
        state
            .webrtc
            .tasks
            .lock()
            .unwrap()
            .peers
            .iter()
            .all(Option::is_none)
    );
    assert!(state.sessions.validate(&login.token).await.is_some());
    state.stop_webrtc().await.unwrap();
}

#[tokio::test]
async fn failed_or_panicked_owner_remains_uncertain_and_cannot_be_replayed() {
    for panic in [false, true] {
        let state = AppState::new(config()).await.unwrap();
        let login = state.sessions.issue("admin", 60).await;
        let access = access(&login);
        let mut admission = state.webrtc.reserve().unwrap();
        admission.start();
        let stop = StopOnDrop(access.clone());
        state.webrtc.tasks.lock().unwrap().peers[0] = Some(PeerTask {
            access: access.clone(),
            task: Some(tokio::spawn(async move {
                let _stop = stop;
                let _admission = admission;
                assert!(!panic, "controlled owner panic");
                false
            })),
        });
        assert!(
            time::timeout(Duration::from_secs(2), state.stop_webrtc())
                .await
                .unwrap()
                .is_err()
        );
        assert!(!access.is_active());
        assert_eq!(state.webrtc.slots.available_permits(), 1);
        assert!(state.webrtc.reserve().is_none());
        assert!(
            state.webrtc.tasks.lock().unwrap().peers[0]
                .as_ref()
                .unwrap()
                .task
                .is_none()
        );
        assert!(state.stop_webrtc().await.is_err());
    }
}

#[tokio::test]
async fn app_shutdown_joins_real_idle_peer_and_rejects_subsequent_upgrades() {
    let server = Server::start(config()).await;
    let login = server.state.sessions.issue("admin", 60).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(server.request(Some(&login), true))
        .await
        .unwrap();
    assert!(matches!(socket.next().await, Some(Ok(Message::Text(_)))));
    time::timeout(Duration::from_secs(2), server.state.stop_webrtc())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        socket.next().await,
        Some(Ok(Message::Close(_))) | None
    ));
    assert!(
        server
            .state
            .webrtc
            .tasks
            .lock()
            .unwrap()
            .peers
            .iter()
            .all(Option::is_none)
    );
    let result = tokio_tungstenite::connect_async(server.request(Some(&login), true)).await;
    let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = result else {
        panic!("expected stopped rejection");
    };
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(server.state.sessions.validate(&login.token).await.is_some());
    server.finish().await;
}

#[tokio::test]
async fn idle_producer_has_one_retained_owner_and_shutdown_joins_it_without_capture() {
    let state = AppState::new(config()).await.unwrap();
    state.webrtc.start_video_stream();
    let id = state
        .webrtc
        .tasks
        .lock()
        .unwrap()
        .producer
        .as_ref()
        .unwrap()
        .id();
    tokio::task::yield_now().await;
    state.webrtc.start_video_stream();
    assert_eq!(
        state
            .webrtc
            .tasks
            .lock()
            .unwrap()
            .producer
            .as_ref()
            .unwrap()
            .id(),
        id
    );
    time::timeout(Duration::from_secs(2), state.stop_webrtc())
        .await
        .unwrap()
        .unwrap();
    assert!(state.webrtc.tasks.lock().unwrap().producer.is_none());
}

struct SetupGate {
    entered: tokio::sync::Notify,
    release: Mutex<Option<tokio::sync::oneshot::Receiver<u32>>>,
    returned: watch::Sender<bool>,
}

async fn owned_operation_fixture(
    State(state): State<AppState>,
    Extension(gate): Extension<Arc<SetupGate>>,
    current: Option<Extension<CurrentSession>>,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    let access = PeerAccess::new(TransportSession::capture(&state.config, current)?);
    Ok(ws.on_upgrade(move |mut socket| async move {
        let result = finish_owned(&mut socket, &access, async {
            let released = gate.release.lock().await.take().unwrap();
            gate.entered.notify_one();
            released.await.unwrap()
        })
        .await;
        assert_eq!(result, 42);
        gate.returned.send_replace(true);
    }))
}

#[tokio::test]
async fn revoke_closes_browser_before_a_gated_owned_setup_finishes_without_dropping_it() {
    let (release, released) = tokio::sync::oneshot::channel();
    let gate = Arc::new(SetupGate {
        entered: tokio::sync::Notify::new(),
        release: Mutex::new(Some(released)),
        returned: watch::channel(false).0,
    });
    let router = Router::new()
        .route("/webrtc", get(owned_operation_fixture))
        .layer(Extension(gate.clone()));
    let server = Server::with_router(config(), router).await;
    let login = server.state.sessions.issue("admin", 60).await;
    let (mut socket, _) = tokio_tungstenite::connect_async(server.request(Some(&login), true))
        .await
        .unwrap();
    time::timeout(Duration::from_secs(2), gate.entered.notified())
        .await
        .unwrap();
    server.state.sessions.revoke(&login.token).await;
    let closed = time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap();
    assert!(matches!(closed, Some(Ok(Message::Close(_))) | None));
    assert!(!*gate.returned.borrow());
    release.send(42).unwrap();
    time::timeout(
        Duration::from_secs(2),
        gate.returned.subscribe().wait_for(|returned| *returned),
    )
    .await
    .unwrap()
    .unwrap();
    server.finish().await;
}
