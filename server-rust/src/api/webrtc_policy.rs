use std::{future::Future, sync::Arc, time::Duration};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    time::Instant,
};
use webrtc::peer_connection::sdp::{
    sdp_type::RTCSdpType, session_description::RTCSessionDescription,
};

use crate::{AppError, Result, config::WebRtcLimits, http::middleware::TransportSession};

pub(super) const MAX_SDP_BYTES: usize = 48 * 1024;
pub(super) const MAX_CANDIDATE_BYTES: usize = 4096;
const MAX_OFFERS: usize = 4;

/// A connection-local stop never revokes another transport of the same login.
#[derive(Clone)]
pub(super) struct PeerAccess {
    session: TransportSession,
    stopped: watch::Sender<bool>,
}

pub(super) struct StopOnDrop(pub PeerAccess);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.stop();
    }
}

impl PeerAccess {
    pub(super) fn new(session: TransportSession) -> Self {
        Self {
            session,
            stopped: watch::channel(false).0,
        }
    }

    pub(super) fn is_active(&self) -> bool {
        !*self.stopped.borrow() && self.session.is_active()
    }

    pub(super) fn stop(&self) {
        self.stopped.send_replace(true);
    }

    pub(super) async fn ended(&self) {
        let mut stopped = self.stopped.subscribe();
        tokio::select! {
            biased;
            _ = self.session.ended() => {},
            _ = stopped.wait_for(|stopped| *stopped) => {},
        }
    }

    /// For cancellation-safe I/O only. Setup/negotiation/close must instead
    /// remain owned through their terminal result, even after authority ends.
    pub(super) async fn io<F: Future>(&self, operation: F) -> Option<F::Output> {
        tokio::select! {
            biased;
            _ = self.ended() => None,
            output = operation => Some(output),
        }
    }
}

/// Capacity covers setup, active work and cleanup. A dropped started owner or
/// uncertain cleanup pins its slot; it cannot authorize unlimited replacements.
pub(super) struct PeerAdmission {
    permit: Option<OwnedSemaphorePermit>,
    started: bool,
}

impl PeerAdmission {
    pub(super) fn reserve(slots: &Arc<Semaphore>) -> Option<Self> {
        slots.clone().try_acquire_owned().ok().map(|permit| Self {
            permit: Some(permit),
            started: false,
        })
    }

    pub(super) fn start(&mut self) {
        self.started = true;
    }

    pub(super) fn cleaned(mut self) {
        self.started = false;
        drop(self.permit.take());
    }
}

impl Drop for PeerAdmission {
    fn drop(&mut self) {
        if self.started
            && let Some(permit) = self.permit.take()
        {
            permit.forget();
        }
    }
}

pub(super) struct SignalBudget {
    limits: WebRtcLimits,
    window: Instant,
    frames: u32,
    offers: usize,
    candidates: usize,
}

impl SignalBudget {
    pub(super) fn new(limits: WebRtcLimits) -> Self {
        Self {
            limits,
            window: Instant::now(),
            frames: 0,
            offers: 0,
            candidates: 0,
        }
    }

    pub(super) fn frame(&mut self, bytes: usize) -> Result<()> {
        let now = Instant::now();
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.frames = 0;
        }
        if bytes > self.limits.message_bytes || self.frames >= self.limits.signals_per_second {
            return Err(AppError::BadRequest(
                "WebRTC signaling budget exceeded".into(),
            ));
        }
        self.frames += 1;
        Ok(())
    }

    pub(super) fn signal(&mut self, event: &str, data: &str) -> Result<()> {
        match event {
            "video-offer" if data.len() <= MAX_SDP_BYTES && self.offers < MAX_OFFERS => {
                self.offers += 1;
                Ok(())
            }
            "video-candidate" if data.len() <= MAX_CANDIDATE_BYTES => self.candidates(1),
            "heartbeat" if data.is_empty() => Ok(()),
            _ => Err(AppError::BadRequest(
                "invalid WebRTC signal or budget".into(),
            )),
        }
    }

    pub(super) fn sdp(&mut self, offer: &RTCSessionDescription) -> Result<()> {
        if offer.sdp.len() > MAX_SDP_BYTES || offer.sdp_type != RTCSdpType::Offer {
            return Err(AppError::BadRequest("WebRTC SDP budget exceeded".into()));
        }
        // Use the same pinned SDP parser as the peer, not a second lexical
        // interpretation whose whitespace/newline rules could differ.
        let parsed = offer
            .unmarshal()
            .map_err(|_| AppError::BadRequest("invalid WebRTC SDP".into()))?;
        let [media] = parsed.media_descriptions.as_slice() else {
            return Err(AppError::BadRequest(
                "WebRTC requires one video track".into(),
            ));
        };
        if media.media_name.media != "video" {
            return Err(AppError::BadRequest(
                "WebRTC requires one video track".into(),
            ));
        }
        let candidates = parsed
            .attributes
            .iter()
            .chain(&media.attributes)
            .filter(|attribute| attribute.key == "candidate")
            .count();
        self.candidates(candidates)
    }

    fn candidates(&mut self, count: usize) -> Result<()> {
        if count > self.limits.ice_candidates.saturating_sub(self.candidates) {
            return Err(AppError::BadRequest("WebRTC ICE budget exceeded".into()));
        }
        self.candidates += count;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::session::{Session, SessionStore},
        config::Config,
        http::middleware::CurrentSession,
    };
    use axum::Extension;

    fn access(session: &Session) -> PeerAccess {
        PeerAccess::new(
            TransportSession::capture(
                &Config::default(),
                Some(Extension(CurrentSession(session.clone()))),
            )
            .unwrap(),
        )
    }

    #[test]
    fn reserved_upgrade_failure_releases_but_started_uncertainty_pins_capacity() {
        let slots = Arc::new(Semaphore::new(2));
        let reserved = PeerAdmission::reserve(&slots).unwrap();
        assert_eq!(slots.available_permits(), 1);
        drop(reserved);
        assert_eq!(slots.available_permits(), 2);
        let mut uncertain = PeerAdmission::reserve(&slots).unwrap();
        uncertain.start();
        drop(uncertain);
        assert_eq!(slots.available_permits(), 1);
        let mut cleaned = PeerAdmission::reserve(&slots).unwrap();
        cleaned.start();
        assert!(PeerAdmission::reserve(&slots).is_none());
        cleaned.cleaned();
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn local_stop_is_latched_before_first_poll_without_revoking_other_connections() {
        let store = SessionStore::new();
        let login = store.issue("admin", 60).await;
        let stopped = access(&login);
        let independent = access(&login);
        stopped.stop();
        tokio::time::timeout(Duration::from_secs(1), stopped.ended())
            .await
            .unwrap();
        assert!(stopped.io(std::future::ready(42)).await.is_none());
        assert!(independent.is_active());
        assert!(store.validate(&login.token).await.is_some());
    }

    #[tokio::test]
    async fn live_session_revoke_expiry_and_retime_override_stale_peer_clones() {
        for expire in [false, true] {
            let store = SessionStore::new();
            let old = store.issue("admin", 60).await;
            let next = store.issue("admin", 60).await;
            let old_access = access(&old);
            let stale = old_access.clone();
            let next_access = access(&next);
            store.retime(&old.token, 120).await.unwrap();
            assert!(stale.is_active());
            if expire {
                store.retime(&old.token, 0).await.unwrap();
            } else {
                store.revoke(&old.token).await;
            }
            tokio::time::timeout(Duration::from_secs(1), old_access.ended())
                .await
                .unwrap();
            assert!(!stale.is_active());
            assert!(next_access.is_active());
        }
    }

    #[test]
    fn rate_window_counts_control_frames_and_recovers_without_lifetime_budget_reset() {
        let limits = Config::default().webrtc_limits().unwrap();
        let mut budget = SignalBudget::new(limits);
        for _ in 0..limits.signals_per_second {
            budget.frame(0).unwrap();
        }
        assert!(budget.frame(0).is_err());
        budget.window -= Duration::from_secs(1);
        budget.frame(limits.message_bytes).unwrap();
        assert!(budget.frame(limits.message_bytes + 1).is_err());
        for _ in 0..MAX_OFFERS {
            budget.signal("video-offer", "bounded").unwrap();
        }
        budget.window -= Duration::from_secs(1);
        assert!(budget.signal("video-offer", "bounded").is_err());
    }

    #[test]
    fn signal_kind_sdp_candidate_size_and_total_ice_are_separate_budgets() {
        let mut limits = Config::default().webrtc_limits().unwrap();
        limits.ice_candidates = 2;
        let mut budget = SignalBudget::new(limits);
        assert!(budget.signal("untrusted-event", "").is_err());
        assert!(budget.signal("heartbeat", "extra").is_err());
        budget.signal("heartbeat", "").unwrap();
        assert!(
            budget
                .signal("video-offer", &"x".repeat(MAX_SDP_BYTES + 1))
                .is_err()
        );
        assert!(
            budget
                .signal("video-candidate", &"x".repeat(MAX_CANDIDATE_BYTES + 1))
                .is_err()
        );
        fn offer(media: &str) -> RTCSessionDescription {
            let mut offer = RTCSessionDescription::default();
            offer.sdp_type = RTCSdpType::Offer;
            offer.sdp = format!("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n{media}");
            offer
        }
        budget
            .sdp(&offer(
                "m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=candidate:synthetic\r\n",
            ))
            .unwrap();
        budget.signal("video-candidate", "{}").unwrap();
        assert!(budget.signal("video-candidate", "{}").is_err());
        assert!(budget.sdp(&offer("m=audio 9 RTP/AVP 0\r\n")).is_err());
        assert!(
            budget
                .sdp(&offer(
                    "m=video 9 RTP/AVP 96\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
                ))
                .is_err()
        );
        assert!(budget.sdp(&offer("")).is_err());
    }
}
