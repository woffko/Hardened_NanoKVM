use axum::{
    extract::{
        State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    http::HeaderMap,
    response::IntoResponse,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::{
    sync::{Mutex, mpsc},
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};
use webrtc::{
    api::{
        APIBuilder,
        interceptor_registry::register_default_interceptors,
        media_engine::{MIME_TYPE_H264, MediaEngine},
        setting_engine::SettingEngine,
    },
    dtls::extension::extension_use_srtp::SrtpProtectionProfile,
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
    api::stream::{
        CAPTURE_MODE_H264, current_h264_screen, h264_frame_duration, update_capture_status,
    },
    config::Config,
    ffi::kvm,
    state::AppState,
    ws::origin::validate_ws_origin,
};

const SIGNAL_BUFFER: usize = 64;
const PLAYOUT_DELAY_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay";

static WEBRTC_MANAGER: LazyLock<WebRtcManager> = LazyLock::new(WebRtcManager::new);
static H264_WEBRTC_FIRST_READ_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_WEBRTC_FIRST_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static H264_WEBRTC_FIRST_ERROR_LOGGED: AtomicBool = AtomicBool::new(false);

pub async fn h264_webrtc_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse> {
    if !validate_ws_origin(&headers, &state.config) {
        return Err(AppError::Forbidden("invalid websocket origin".to_string()));
    }

    Ok(ws.on_upgrade(move |socket| handle_h264_webrtc_socket(socket, Arc::clone(&state.config))))
}

async fn handle_h264_webrtc_socket(mut socket: WebSocket, config: Arc<Config>) {
    let (signal_tx, mut signal_rx) = mpsc::channel(SIGNAL_BUFFER);
    let client = match WebRtcClient::new(&config, signal_tx.clone()).await {
        Ok(client) => client,
        Err(err) => {
            warn!(error = ?err, "failed to create h264 webrtc client");
            return;
        }
    };

    manager().add_client(Arc::clone(&client)).await;
    debug!(client_id = client.id, "h264 webrtc websocket connected");

    if let Err(err) = send_ice_servers(&signal_tx, &config).await {
        warn!(error = ?err, "failed to send h264 webrtc ICE servers");
        manager().remove_client(client.id).await;
        client.close().await;
        return;
    }

    loop {
        tokio::select! {
            Some(signal) = signal_rx.recv() => {
                let payload = match serde_json::to_string(&signal) {
                    Ok(payload) => payload,
                    Err(err) => {
                        warn!(error = ?err, "failed to serialize h264 webrtc signal");
                        continue;
                    }
                };
                if socket.send(WsMessage::Text(payload.into())).await.is_err() {
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

                match message {
                    WsMessage::Text(text) => {
                        if let Err(err) = handle_signal_message(&client, &signal_tx, text.as_str()).await {
                            warn!(error = ?err, "failed to handle h264 webrtc signal");
                        }
                    }
                    WsMessage::Binary(data) => {
                        if let Ok(text) = std::str::from_utf8(&data) {
                            if let Err(err) = handle_signal_message(&client, &signal_tx, text).await {
                                warn!(error = ?err, "failed to handle h264 webrtc binary signal");
                            }
                        }
                    }
                    WsMessage::Ping(data) => {
                        if socket.send(WsMessage::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    WsMessage::Close(_) => break,
                    WsMessage::Pong(_) => {}
                }
            }
        }
    }

    manager().remove_client(client.id).await;
    client.close().await;
    debug!(client_id = client.id, "h264 webrtc websocket disconnected");
}

async fn handle_signal_message(
    client: &Arc<WebRtcClient>,
    signal_tx: &mpsc::Sender<SignalMessage>,
    raw: &str,
) -> Result<()> {
    let message: SignalMessage =
        serde_json::from_str(raw).map_err(|err| AppError::BadRequest(err.to_string()))?;

    match message.event.as_str() {
        "video-offer" => handle_video_offer(client, signal_tx, &message.data).await,
        "video-candidate" => handle_video_candidate(client, &message.data).await,
        "heartbeat" => send_signal(signal_tx, "heartbeat", "").await,
        event => {
            debug!(event, "unhandled h264 webrtc signal");
            Ok(())
        }
    }
}

async fn handle_video_offer(
    client: &Arc<WebRtcClient>,
    signal_tx: &mpsc::Sender<SignalMessage>,
    data: &str,
) -> Result<()> {
    if client.peer.signaling_state() != RTCSignalingState::Stable {
        return Err(AppError::Conflict(
            "video signaling is not stable".to_string(),
        ));
    }

    let offer: RTCSessionDescription =
        serde_json::from_str(data).map_err(|err| AppError::BadRequest(err.to_string()))?;
    client
        .peer
        .set_remote_description(offer)
        .await
        .map_err(|err| webrtc_error("set remote video offer", err))?;

    let answer = client
        .peer
        .create_answer(None)
        .await
        .map_err(|err| webrtc_error("create video answer", err))?;
    client
        .peer
        .set_local_description(answer.clone())
        .await
        .map_err(|err| webrtc_error("set local video answer", err))?;

    let data = serde_json::to_string(&answer)
        .map_err(|err| AppError::Internal(format!("serialize video answer: {err}")))?;
    send_signal(signal_tx, "video-answer", data).await
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

async fn send_ice_servers(signal_tx: &mpsc::Sender<SignalMessage>, config: &Config) -> Result<()> {
    let data = serde_json::to_string(&client_ice_servers(config))
        .map_err(|err| AppError::Internal(format!("serialize ICE servers: {err}")))?;
    send_signal(signal_tx, "ice-servers", data).await
}

async fn send_signal(
    signal_tx: &mpsc::Sender<SignalMessage>,
    event: impl Into<String>,
    data: impl Into<String>,
) -> Result<()> {
    signal_tx
        .send(SignalMessage {
            event: event.into(),
            data: data.into(),
        })
        .await
        .map_err(|_| AppError::Internal("h264 webrtc signal channel closed".to_string()))
}

#[derive(Debug)]
struct WebRtcManager {
    clients: Mutex<HashMap<u64, Arc<WebRtcClient>>>,
    next_client_id: AtomicU64,
    video_sending: AtomicBool,
}

impl WebRtcManager {
    fn new() -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            next_client_id: AtomicU64::new(1),
            video_sending: AtomicBool::new(false),
        }
    }

    fn next_client_id(&self) -> u64 {
        self.next_client_id.fetch_add(1, Ordering::Relaxed)
    }

    async fn add_client(&self, client: Arc<WebRtcClient>) {
        let mut clients = self.clients.lock().await;
        clients.insert(client.id, client);
    }

    async fn remove_client(&self, client_id: u64) {
        let mut clients = self.clients.lock().await;
        clients.remove(&client_id);
    }

    async fn clients(&self) -> Vec<Arc<WebRtcClient>> {
        let clients = self.clients.lock().await;
        clients.values().cloned().collect()
    }

    fn start_video_stream(&'static self) {
        if self
            .video_sending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            tokio::spawn(async move {
                self.send_video_stream().await;
            });
            debug!("start sending h264 webrtc stream");
        }
    }

    async fn send_video_stream(&'static self) {
        struct SendingGuard(&'static AtomicBool);
        impl Drop for SendingGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _guard = SendingGuard(&self.video_sending);

        let mut screen = current_h264_screen();
        let mut duration = h264_frame_duration(screen.fps);
        let mut interval = time::interval(duration);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let playout_delay = [HeaderExtension::PlayoutDelay(PlayoutDelayExtension::new(
            0, 0,
        ))];

        loop {
            interval.tick().await;

            let clients = self.clients().await;
            if clients.is_empty() {
                debug!("stop sending h264 webrtc stream");
                return;
            }

            screen = current_h264_screen();
            if !H264_WEBRTC_FIRST_READ_LOGGED.swap(true, Ordering::Relaxed) {
                info!(
                    width = screen.width,
                    height = screen.height,
                    bit_rate = screen.bit_rate,
                    "reading first h264 webrtc frame"
                );
            }

            let frame = tokio::task::spawn_blocking(move || {
                kvm::read_h264(screen.width, screen.height, screen.bit_rate)
            })
            .await;
            let (data, result) = match frame {
                Ok(Ok(frame)) => frame,
                Ok(Err(err)) => {
                    update_capture_status(CAPTURE_MODE_H264, -1);
                    if !H264_WEBRTC_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                        warn!(error = ?err, "failed to read h264 webrtc frame");
                    }
                    continue;
                }
                Err(err) => {
                    update_capture_status(CAPTURE_MODE_H264, -1);
                    if !H264_WEBRTC_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                        warn!(error = ?err, "h264 webrtc frame task failed");
                    }
                    continue;
                }
            };
            update_capture_status(CAPTURE_MODE_H264, result);

            if result < 0 || data.is_empty() {
                if !H264_WEBRTC_FIRST_ERROR_LOGGED.swap(true, Ordering::Relaxed) {
                    warn!(result, bytes = data.len(), "h264 webrtc frame unavailable");
                }
                continue;
            }

            if !H264_WEBRTC_FIRST_SUCCESS_LOGGED.swap(true, Ordering::Relaxed) {
                info!(result, bytes = data.len(), "read first h264 webrtc frame");
            }

            let sample = Sample {
                data: Bytes::from(data),
                duration,
                ..Default::default()
            };

            for client in clients {
                if let Err(err) = client
                    .track
                    .write_sample_with_extensions(&sample, &playout_delay)
                    .await
                {
                    warn!(
                        client_id = client.id,
                        error = ?err,
                        "failed to write h264 webrtc sample"
                    );
                    self.remove_client(client.id).await;
                    client.close().await;
                }
            }

            let latest = current_h264_screen();
            if latest.fps != screen.fps {
                screen = latest;
                duration = h264_frame_duration(screen.fps);
                interval = time::interval(duration);
                interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            }
        }
    }
}

#[derive(Debug)]
struct WebRtcClient {
    id: u64,
    peer: Arc<RTCPeerConnection>,
    track: Arc<TrackLocalStaticSample>,
}

impl WebRtcClient {
    async fn new(config: &Config, signal_tx: mpsc::Sender<SignalMessage>) -> Result<Arc<Self>> {
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

        register_peer_callbacks(Arc::clone(&peer), signal_tx);

        let track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: MIME_TYPE_H264.to_string(),
                ..Default::default()
            },
            "video".to_string(),
            "pion-video".to_string(),
        ));
        let sender = peer
            .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|err| webrtc_error("add h264 track", err))?;
        tokio::spawn(read_rtcp(sender));

        Ok(Arc::new(Self {
            id: manager().next_client_id(),
            peer,
            track,
        }))
    }

    async fn close(&self) {
        if let Err(err) = self.peer.close().await {
            debug!(client_id = self.id, error = ?err, "failed to close h264 peer");
        }
    }
}

fn register_peer_callbacks(peer: Arc<RTCPeerConnection>, signal_tx: mpsc::Sender<SignalMessage>) {
    peer.on_ice_candidate(Box::new(move |candidate| {
        let signal_tx = signal_tx.clone();
        Box::pin(async move {
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
            let _ = send_signal(&signal_tx, "video-candidate", data).await;
        })
    }));

    peer.on_ice_connection_state_change(Box::new(move |state| {
        Box::pin(async move {
            if state == RTCIceConnectionState::Connected {
                manager().start_video_stream();
            }
            debug!(%state, "h264 webrtc ICE connection state changed");
        })
    }));
}

async fn read_rtcp(sender: Arc<RTCRtpSender>) {
    let mut buffer = vec![0u8; 1500];
    loop {
        if sender.read(&mut buffer).await.is_err() {
            return;
        }
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

fn manager() -> &'static WebRtcManager {
    &WEBRTC_MANAGER
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
    use super::{Config, client_ice_servers};

    #[test]
    fn ice_servers_match_frontend_shape() {
        let config = Config::default();
        let data = serde_json::to_value(client_ice_servers(&config)).unwrap();

        assert_eq!(data[0]["urls"][0], "stun:stun.l.google.com:19302");
        assert!(data[0].get("username").is_none());
        assert!(data[0].get("credential").is_none());
    }
}
