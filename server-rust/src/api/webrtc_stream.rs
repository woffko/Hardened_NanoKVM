use axum::{
    Extension,
    extract::{
        State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rtcp::payload_feedbacks::{
    full_intra_request::FullIntraRequest, picture_loss_indication::PictureLossIndication,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    future::Future,
    sync::{Arc, Weak},
    task::{Context, Waker},
    time::Duration,
};
use tokio::{
    sync::{Mutex, Semaphore, mpsc, watch},
    task::JoinHandle,
    time,
};
use tracing::{debug, warn};
use webrtc::{
    api::{
        APIBuilder,
        interceptor_registry::register_default_interceptors,
        media_engine::{MIME_TYPE_H264, MediaEngine},
        setting_engine::SettingEngine,
    },
    dtls::extension::extension_use_srtp::SrtpProtectionProfile,
    ice::mdns::MulticastDnsMode,
    ice::network_type::NetworkType,
    ice_transport::{
        ice_candidate::RTCIceCandidateInit, ice_connection_state::RTCIceConnectionState,
        ice_server::RTCIceServer,
    },
    interceptor::registry::Registry,
    media::Sample,
    peer_connection::{
        RTCPeerConnection, configuration::RTCConfiguration,
        sdp::session_description::RTCSessionDescription, signaling_state::RTCSignalingState,
    },
    rtp::extension::{HeaderExtension, playout_delay_extension::PlayoutDelayExtension},
    rtp_transceiver::{
        rtp_codec::{RTCRtpCodecCapability, RTCRtpHeaderExtensionCapability, RTPCodecType},
        rtp_sender::RTCRtpSender,
        rtp_transceiver_direction::RTCRtpTransceiverDirection,
    },
    track::track_local::{TrackLocal, track_local_static_sample::TrackLocalStaticSample},
};

use crate::{
    AppError, Result,
    api::{
        stream::{
            H264Subscription, H264Viewer, current_h264_screen, h264_frame_duration,
            request_h264_keyframe, subscribe_h264,
        },
        system_firewall,
        webrtc_policy::{PeerAccess, PeerAdmission, SignalBudget, StopOnDrop},
        webrtc_tasks::{PeerTask, Tasks},
    },
    config::{Config, WEBRTC_PEER_CEILING, WebRtcLimits},
    http::middleware::{CurrentSession, TransportSession},
    state::AppState,
    ws::origin::validate_ws_origin,
};

const SIGNAL_BUFFER: usize = 64;
const PLAYOUT_DELAY_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay";

/// How long the idle producer sleeps between looks for an active peer, and
/// how long a viewer waits for a frame before it looks again.
const PRODUCER_IDLE_POLL: Duration = Duration::from_millis(100);
const PRODUCER_FRAME_WAIT: Duration = Duration::from_secs(1);

pub async fn h264_webrtc_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    current: Option<Extension<CurrentSession>>,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    if system_firewall::webrtc_blocked_by_firewall() {
        return Err(AppError::Forbidden(
            system_firewall::webrtc_blocked_message().to_string(),
        ));
    }

    if !validate_ws_origin(&headers, &state.config) {
        return Err(AppError::Forbidden("invalid websocket origin".to_string()));
    }

    let access = PeerAccess::new(TransportSession::capture(&state.config, current)?);
    let Some(admission) = state.webrtc.reserve() else {
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            "WebRTC peer capacity exhausted",
        )
            .into_response());
    };
    let limits = state.webrtc.limits;
    Ok(ws
        .max_message_size(limits.message_bytes)
        .max_frame_size(limits.message_bytes)
        .on_upgrade(move |socket| async move {
            state
                .webrtc
                .start_peer(socket, state.config, access, admission);
        }))
}

async fn close_socket(socket: &mut WebSocket) {
    let _ = time::timeout(
        Duration::from_millis(250),
        socket.send(WsMessage::Close(None)),
    )
    .await;
}

/// Unlike socket I/O, library setup/negotiation is not assumed drop-safe.
/// End browser access promptly but retain the admitted operation to completion.
async fn finish_owned<F: Future>(
    socket: &mut WebSocket,
    access: &PeerAccess,
    operation: F,
) -> F::Output {
    tokio::pin!(operation);
    tokio::select! {
        biased;
        _ = access.ended() => {
            close_socket(socket).await;
            operation.await
        },
        result = &mut operation => result,
    }
}

async fn handle_h264_webrtc_socket(
    mut socket: WebSocket,
    config: Arc<Config>,
    manager: Arc<WebRtcManager>,
    access: PeerAccess,
    mut admission: PeerAdmission,
) -> bool {
    let _stop = StopOnDrop(access.clone());
    if !access.is_active() {
        close_socket(&mut socket).await;
        return true;
    }
    let (signal_tx, mut signal_rx) = mpsc::channel(SIGNAL_BUFFER);
    admission.start();
    let ReadyPeer { client, rtcp } = match finish_owned(
        &mut socket,
        &access,
        ReadyPeer::create(&config, signal_tx.clone(), access.clone(), &manager),
    )
    .await
    {
        Ok(Some(owned)) => owned,
        Ok(None) => {
            admission.cleaned();
            close_socket(&mut socket).await;
            return true;
        }
        Err(_) => {
            access.stop();
            close_socket(&mut socket).await;
            warn!("WebRTC setup failed; peer capacity retained pending recovery");
            return false;
        }
    };

    manager.add_client(Arc::clone(&client)).await;
    debug!(client_id = client.id, "h264 webrtc websocket connected");

    if send_ice_servers(&access, &signal_tx, &config).is_err() {
        access.stop();
    }

    let mut budget = SignalBudget::new(manager.limits);
    loop {
        tokio::select! {
            biased;
            _ = access.ended() => break,
            Some(signal) = signal_rx.recv() => {
                if !access.is_active() { break; }
                let payload = match serde_json::to_string(&signal) {
                    Ok(payload) => payload,
                    Err(err) => {
                        warn!(error = ?err, "failed to serialize h264 webrtc signal");
                        continue;
                    }
                };
                if !matches!(access.io(socket.send(WsMessage::Text(payload.into()))).await, Some(Ok(()))) {
                    break;
                }
            }
            message = socket.recv() => {
                let message = match message {
                    Some(Ok(message)) => message,
                    Some(Err(err)) => {
                        debug!(error = ?err, "h264 webrtc websocket read failed");
                        break;
                    }
                    None => break,
                };
                let bytes = match &message {
                    WsMessage::Text(text) => text.len(),
                    WsMessage::Binary(data) | WsMessage::Ping(data) | WsMessage::Pong(data) => data.len(),
                    WsMessage::Close(_) => 0,
                };
                if !access.is_active() || budget.frame(bytes).is_err() {
                    break;
                }

                match message {
                    WsMessage::Text(text) => {
                        if finish_owned(&mut socket, &access,
                            handle_signal_message(&client, &signal_tx, &mut budget, text.as_str())).await.is_err() {
                            break;
                        }
                    }
                    WsMessage::Binary(data) => {
                        if let Ok(text) = std::str::from_utf8(&data) {
                            if finish_owned(&mut socket, &access,
                                handle_signal_message(&client, &signal_tx, &mut budget, text)).await.is_err() {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    WsMessage::Ping(data) => {
                        if !matches!(access.io(socket.send(WsMessage::Pong(data))).await, Some(Ok(()))) {
                            break;
                        }
                    }
                    WsMessage::Close(_) => break,
                    WsMessage::Pong(_) => {}
                }
            }
        }
    }

    access.stop();
    signal_rx.close();
    drop(signal_rx);
    close_socket(&mut socket).await;
    manager.remove_client(client.id).await;
    // This is the sole normal close owner. Never timeout or concurrently retry
    // the library close: its closed flag precedes completion of cleanup.
    let reader_joined = rtcp.await.is_ok();
    let peer_closed = client.peer.close().await.is_ok();
    if reader_joined && peer_closed {
        admission.cleaned();
    } else {
        warn!(
            client_id = client.id,
            "WebRTC cleanup uncertain; peer capacity retained"
        );
    }
    debug!(client_id = client.id, "h264 webrtc websocket disconnected");
    reader_joined && peer_closed
}

async fn handle_signal_message(
    client: &Arc<WebRtcClient>,
    signal_tx: &mpsc::Sender<SignalMessage>,
    budget: &mut SignalBudget,
    raw: &str,
) -> Result<()> {
    if !client.access.is_active() {
        return Err(AppError::Unauthorized);
    }
    let message: SignalMessage =
        serde_json::from_str(raw).map_err(|err| AppError::BadRequest(err.to_string()))?;

    budget.signal(&message.event, &message.data)?;
    match message.event.as_str() {
        "video-offer" => handle_video_offer(client, signal_tx, budget, &message.data).await,
        "video-candidate" => handle_video_candidate(client, &message.data).await,
        "heartbeat" => send_peer_signal(&client.access, signal_tx, "heartbeat", ""),
        _ => Err(AppError::BadRequest("unsupported WebRTC signal".into())),
    }
}

async fn handle_video_offer(
    client: &Arc<WebRtcClient>,
    signal_tx: &mpsc::Sender<SignalMessage>,
    budget: &mut SignalBudget,
    data: &str,
) -> Result<()> {
    if client.peer.signaling_state() != RTCSignalingState::Stable {
        return Err(AppError::Conflict(
            "video signaling is not stable".to_string(),
        ));
    }

    let offer: RTCSessionDescription =
        serde_json::from_str(data).map_err(|err| AppError::BadRequest(err.to_string()))?;
    budget.sdp(&offer)?;
    if !client.access.is_active() {
        return Err(AppError::Unauthorized);
    }
    client
        .peer
        .set_remote_description(offer)
        .await
        .map_err(|err| webrtc_error("set remote video offer", err))?;

    if !client.access.is_active() {
        return Err(AppError::Unauthorized);
    }

    let answer = client
        .peer
        .create_answer(None)
        .await
        .map_err(|err| webrtc_error("create video answer", err))?;
    if !client.access.is_active() {
        return Err(AppError::Unauthorized);
    }
    client
        .peer
        .set_local_description(answer.clone())
        .await
        .map_err(|err| webrtc_error("set local video answer", err))?;

    let data = serde_json::to_string(&answer)
        .map_err(|err| AppError::Internal(format!("serialize video answer: {err}")))?;
    if !client.access.is_active() {
        return Err(AppError::Unauthorized);
    }
    send_peer_signal(&client.access, signal_tx, "video-answer", data)
}

async fn handle_video_candidate(client: &Arc<WebRtcClient>, data: &str) -> Result<()> {
    let candidate: RTCIceCandidateInit =
        serde_json::from_str(data).map_err(|err| AppError::BadRequest(err.to_string()))?;
    client
        .peer
        .add_ice_candidate(candidate)
        .await
        .map_err(|err| webrtc_error("add video ICE candidate", err))
}

fn send_ice_servers(
    access: &PeerAccess,
    signal_tx: &mpsc::Sender<SignalMessage>,
    config: &Config,
) -> Result<()> {
    let data = serde_json::to_string(&client_ice_servers(config))
        .map_err(|err| AppError::Internal(format!("serialize ICE servers: {err}")))?;
    send_peer_signal(access, signal_tx, "ice-servers", data)
}

fn send_peer_signal(
    access: &PeerAccess,
    signal_tx: &mpsc::Sender<SignalMessage>,
    event: impl Into<String>,
    data: impl Into<String>,
) -> Result<()> {
    if !access.is_active() {
        return Err(AppError::Unauthorized);
    }
    let result = send_signal(signal_tx, event, data);
    if result.is_err() {
        access.stop();
    }
    result
}

fn send_signal(
    signal_tx: &mpsc::Sender<SignalMessage>,
    event: impl Into<String>,
    data: impl Into<String>,
) -> Result<()> {
    signal_tx
        .try_send(SignalMessage {
            event: event.into(),
            data: data.into(),
        })
        .map_err(|_| AppError::Conflict("WebRTC signal queue unavailable".to_string()))
}

pub(crate) struct WebRtcManager {
    limits: WebRtcLimits,
    slots: Arc<Semaphore>,
    clients: Mutex<[Option<Arc<WebRtcClient>>; WEBRTC_PEER_CEILING]>,
    next_client_id: std::sync::Mutex<u64>,
    tasks: std::sync::Mutex<Tasks>,
    producer_stop: watch::Sender<bool>,
    shutdown_wait: Mutex<()>,
}

impl WebRtcManager {
    pub(crate) fn new(limits: WebRtcLimits) -> Self {
        Self {
            limits,
            slots: Arc::new(Semaphore::new(limits.peers)),
            clients: Mutex::new(std::array::from_fn(|_| None)),
            next_client_id: std::sync::Mutex::new(1),
            tasks: std::sync::Mutex::new(Tasks::default()),
            producer_stop: watch::channel(false).0,
            shutdown_wait: Mutex::new(()),
        }
    }

    fn reserve(&self) -> Option<PeerAdmission> {
        let mut tasks = self.tasks.lock().ok()?;
        if tasks.stopping {
            return None;
        }
        let _ = tasks.poll(&mut Context::from_waker(Waker::noop()), true);
        if tasks.uncertain() {
            return None;
        }
        PeerAdmission::reserve(&self.slots)
    }

    fn start_peer(
        self: &Arc<Self>,
        socket: WebSocket,
        config: Arc<Config>,
        access: PeerAccess,
        admission: PeerAdmission,
    ) {
        let Ok(mut tasks) = self.tasks.lock() else {
            return;
        };
        if tasks.stopping || tasks.uncertain() {
            return;
        }
        let _ = tasks.poll(&mut Context::from_waker(Waker::noop()), true);
        if tasks.uncertain() {
            return;
        }
        let Some(slot) = tasks.peers.iter_mut().find(|slot| slot.is_none()) else {
            warn!("WebRTC task registry unavailable; rejecting upgrade");
            return;
        };
        let manager = Arc::clone(self);
        let owned_access = access.clone();
        *slot = Some(PeerTask {
            access,
            task: Some(tokio::spawn(async move {
                handle_h264_webrtc_socket(socket, config, manager, owned_access, admission).await
            })),
        });
    }

    /// Stop admission and access first, then join the retained peer and media
    /// owners. A canceled waiter leaves every pending handle in this manager.
    pub(crate) async fn stop_and_join(&self) -> Result<()> {
        let _waiter = self.shutdown_wait.lock().await;
        self.slots.close();
        {
            let mut tasks = self
                .tasks
                .lock()
                .map_err(|_| AppError::Internal("WebRTC task owner unavailable".into()))?;
            tasks.stopping = true;
            for peer in tasks.peers.iter().flatten() {
                peer.access.stop();
            }
            self.producer_stop.send_replace(true);
        }
        std::future::poll_fn(|cx| {
            let Ok(mut tasks) = self.tasks.lock() else {
                return std::task::Poll::Ready(Err(AppError::Internal(
                    "WebRTC task owner unavailable".into(),
                )));
            };
            tasks.poll(cx, false)
        })
        .await
    }

    fn next_client_id(&self) -> Result<u64> {
        let mut next = self
            .next_client_id
            .lock()
            .map_err(|_| AppError::Internal("WebRTC identity unavailable".into()))?;
        let id = *next;
        *next = id
            .checked_add(1)
            .ok_or_else(|| AppError::Internal("WebRTC identity exhausted".into()))?;
        Ok(id)
    }

    async fn add_client(&self, client: Arc<WebRtcClient>) {
        let mut clients = self.clients.lock().await;
        if let Some(slot) = clients.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(client);
        } else {
            // Admission permits imply a free array slot. Fail closed if that
            // invariant is broken instead of allocating a larger registry.
            client.access.stop();
        }
    }

    async fn remove_client(&self, client_id: u64) {
        let mut clients = self.clients.lock().await;
        if let Some(slot) = clients
            .iter_mut()
            .find(|slot| slot.as_ref().is_some_and(|client| client.id == client_id))
        {
            *slot = None;
        }
    }

    async fn clients(&self) -> [Option<Arc<WebRtcClient>>; WEBRTC_PEER_CEILING] {
        let clients = self.clients.lock().await;
        clients.clone()
    }

    fn start_video_stream(self: &Arc<Self>) {
        let Ok(mut tasks) = self.tasks.lock() else {
            return;
        };
        if tasks.stopping || tasks.uncertain() || tasks.producer.is_some() {
            return;
        }
        let manager = Arc::downgrade(self);
        let stopped = self.producer_stop.subscribe();
        tasks.producer = Some(tokio::spawn(Self::send_video_stream(manager, stopped)));
        debug!("start sending h264 webrtc stream");
    }

    /// The retained media producer. While a peer is connected it is one viewer
    /// of the single H.264 source (shared with Direct viewers) and writes
    /// every frame to every active peer; without a peer it holds no
    /// subscription, so the source can stop, and it looks again shortly.
    async fn send_video_stream(manager: Weak<Self>, mut stopped: watch::Receiver<bool>) -> bool {
        let playout_delay = [HeaderExtension::PlayoutDelay(PlayoutDelayExtension::new(
            0, 0,
        ))];
        let mut subscription: Option<H264Subscription> = None;

        loop {
            let Some(manager) = manager.upgrade() else {
                return true;
            };
            let clients = manager.clients().await;
            if !clients
                .iter()
                .flatten()
                .any(|client| client.access.is_active())
            {
                // Stay owned and idle. Exiting here races a newly connected
                // peer against producer retirement and can lose its restart.
                subscription = None;
                tokio::select! {
                    biased;
                    _ = stopped.wait_for(|stopped| *stopped) => return true,
                    _ = time::sleep(PRODUCER_IDLE_POLL) => continue,
                }
            }
            drop(manager);

            let viewer = subscription.get_or_insert_with(|| subscribe_h264(H264Viewer::WebRtc));
            let frame = tokio::select! {
                biased;
                _ = stopped.wait_for(|stopped| *stopped) => return true,
                frame = time::timeout(PRODUCER_FRAME_WAIT, viewer.recv()) => match frame {
                    // Nothing yet: MJPEG is selected or capture is disabled.
                    // Look at the peers again; the subscription stays.
                    Err(_) => continue,
                    Ok(Some(frame)) => frame,
                    Ok(None) => {
                        subscription = None;
                        continue;
                    }
                },
            };

            let sample = Sample {
                data: frame.data,
                duration: h264_frame_duration(current_h264_screen().fps),
                ..Default::default()
            };
            for client in clients.iter().flatten() {
                if !client.access.is_active() {
                    continue;
                }
                let result = client
                    .access
                    .io(client
                        .track
                        .write_sample_with_extensions(&sample, &playout_delay))
                    .await;
                if let Some(Err(err)) = result {
                    warn!(
                        client_id = client.id,
                        error = ?err,
                        "failed to write h264 webrtc sample"
                    );
                    client.access.stop();
                }
            }
        }
    }
}

struct WebRtcClient {
    id: u64,
    peer: Arc<RTCPeerConnection>,
    track: Arc<TrackLocalStaticSample>,
    access: PeerAccess,
}

struct ReadyPeer {
    client: Arc<WebRtcClient>,
    rtcp: JoinHandle<()>,
}

impl ReadyPeer {
    async fn create(
        config: &Config,
        signal_tx: mpsc::Sender<SignalMessage>,
        access: PeerAccess,
        manager: &Arc<WebRtcManager>,
    ) -> Result<Option<Self>> {
        if !access.is_active() {
            return Ok(None);
        }
        let id = manager.next_client_id()?;
        let ice_servers = rtc_ice_servers(config);
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|err| webrtc_error("register default codecs", err))?;
        media_engine
            .register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: PLAYOUT_DELAY_URI.to_string(),
                },
                RTPCodecType::Video,
                Some(RTCRtpTransceiverDirection::Sendonly),
            )
            .map_err(|err| webrtc_error("register playout delay extension", err))?;

        let registry = register_default_interceptors(Registry::new(), &mut media_engine)
            .map_err(|err| webrtc_error("register default interceptors", err))?;

        let mut setting_engine = SettingEngine::default();
        setting_engine.set_network_types(vec![NetworkType::Udp4]);
        setting_engine.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);
        setting_engine.set_srtp_protection_profiles(vec![
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        ]);

        let api = APIBuilder::new()
            .with_setting_engine(setting_engine)
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        let peer = Arc::new(
            api.new_peer_connection(RTCConfiguration {
                ice_servers,
                ..Default::default()
            })
            .await
            .map_err(|err| webrtc_error("create h264 peer connection", err))?,
        );

        register_peer_callbacks(&peer, signal_tx, access.clone(), Arc::downgrade(manager));

        if !access.is_active() {
            peer.close()
                .await
                .map_err(|err| webrtc_error("close revoked setup", err))?;
            return Ok(None);
        }

        let track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: MIME_TYPE_H264.to_string(),
                ..Default::default()
            },
            "video".to_string(),
            "pion-video".to_string(),
        ));
        let sender = match peer
            .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
        {
            Ok(sender) => sender,
            Err(err) => {
                let _ = peer.close().await;
                return Err(webrtc_error("add h264 track", err));
            }
        };
        let rtcp = tokio::spawn(read_rtcp(sender, access.clone()));

        Ok(Some(Self {
            client: Arc::new(WebRtcClient {
                id,
                peer,
                track,
                access,
            }),
            rtcp,
        }))
    }
}

fn register_peer_callbacks(
    peer: &RTCPeerConnection,
    signal_tx: mpsc::Sender<SignalMessage>,
    access: PeerAccess,
    manager: Weak<WebRtcManager>,
) {
    let candidate_access = access.clone();
    peer.on_ice_candidate(Box::new(move |candidate| {
        let signal_tx = signal_tx.clone();
        let access = candidate_access.clone();
        Box::pin(async move {
            if !access.is_active() {
                return;
            }
            let Some(candidate) = candidate else {
                return;
            };
            let candidate = match candidate.to_json() {
                Ok(candidate) => candidate,
                Err(err) => {
                    warn!(error = ?err, "failed to convert h264 ICE candidate");
                    return;
                }
            };
            let data = match serde_json::to_string(&candidate) {
                Ok(data) => data,
                Err(err) => {
                    warn!(error = ?err, "failed to serialize h264 ICE candidate");
                    return;
                }
            };
            let _ = send_peer_signal(&access, &signal_tx, "video-candidate", data);
        })
    }));

    peer.on_ice_connection_state_change(Box::new(move |state| {
        let manager = manager.clone();
        let access = access.clone();
        Box::pin(async move {
            if state == RTCIceConnectionState::Connected
                && access.is_active()
                && let Some(manager) = manager.upgrade()
            {
                manager.start_video_stream();
            } else if matches!(
                state,
                RTCIceConnectionState::Failed | RTCIceConnectionState::Closed
            ) {
                access.stop();
            }
            debug!(%state, "h264 webrtc ICE connection state changed");
        })
    }));
}

async fn read_rtcp(sender: Arc<RTCRtpSender>, access: PeerAccess) {
    let mut buffer = [0u8; 1500];
    loop {
        let (packets, _) = match access.io(sender.read(&mut buffer)).await {
            Some(Ok(result)) => result,
            Some(Err(err)) => {
                debug!(error = ?err, "h264 rtcp reader stopped");
                return;
            }
            None => return,
        };

        for packet in packets {
            if !access.is_active() {
                return;
            }
            if let Some(reason) = h264_keyframe_request_reason(packet.as_ref()) {
                request_h264_keyframe(reason);
            }
        }
    }
}

fn h264_keyframe_request_reason(
    packet: &(dyn rtcp::packet::Packet + Send + Sync),
) -> Option<&'static str> {
    if packet
        .as_any()
        .downcast_ref::<PictureLossIndication>()
        .is_some()
    {
        Some("rtcp picture loss indication")
    } else if packet.as_any().downcast_ref::<FullIntraRequest>().is_some() {
        Some("rtcp full intra request")
    } else {
        None
    }
}

fn rtc_ice_servers(config: &Config) -> Vec<RTCIceServer> {
    let mut servers = Vec::new();
    if !config.stun.is_empty() && config.stun != "disable" {
        servers.push(RTCIceServer {
            urls: vec![format!("stun:{}", config.stun)],
            ..Default::default()
        });
    }
    if !config.turn.turn_addr.is_empty()
        && !config.turn.turn_user.is_empty()
        && !config.turn.turn_cred.is_empty()
    {
        servers.push(RTCIceServer {
            urls: vec![format!("turn:{}", config.turn.turn_addr)],
            username: config.turn.turn_user.clone(),
            credential: config.turn.turn_cred.clone(),
        });
    }
    servers
}

fn client_ice_servers(config: &Config) -> Vec<ClientIceServer> {
    rtc_ice_servers(config)
        .into_iter()
        .map(|server| ClientIceServer {
            urls: server.urls,
            username: server.username,
            credential: if server.credential.is_empty() {
                None
            } else {
                Some(server.credential)
            },
        })
        .collect()
}

fn webrtc_error(context: &str, err: impl fmt::Display) -> AppError {
    AppError::Internal(format!("{context}: {err}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignalMessage {
    event: String,
    #[serde(default)]
    data: String,
}

#[derive(Debug, Serialize)]
struct ClientIceServer {
    urls: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<String>,
}

#[cfg(test)]
mod tests {
    use rtcp::{
        payload_feedbacks::{
            full_intra_request::FullIntraRequest, picture_loss_indication::PictureLossIndication,
        },
        receiver_report::ReceiverReport,
    };

    use super::{Config, client_ice_servers, h264_keyframe_request_reason};

    #[test]
    fn ice_servers_match_frontend_shape() {
        let config = Config::default();
        let data = serde_json::to_value(client_ice_servers(&config)).unwrap();

        assert_eq!(data[0]["urls"][0], "stun:stun.l.google.com:19302");
        assert!(data[0].get("username").is_none());
        assert!(data[0].get("credential").is_none());
    }

    #[test]
    fn detects_rtcp_keyframe_requests() {
        let pli = PictureLossIndication::default();
        let fir = FullIntraRequest::default();
        let receiver_report = ReceiverReport::default();

        assert_eq!(
            h264_keyframe_request_reason(&pli),
            Some("rtcp picture loss indication")
        );
        assert_eq!(
            h264_keyframe_request_reason(&fir),
            Some("rtcp full intra request")
        );
        assert_eq!(h264_keyframe_request_reason(&receiver_report), None);
    }
}

#[cfg(test)]
#[path = "webrtc_stream_tests.rs"]
mod lifecycle_tests;
