//! Decode-driven flow control for the direct H.264 stream.
//!
//! A client that passes `?flow=N` acknowledges each frame once it has decoded it.
//! The server keeps at most N frames in flight and drops the rest, so stale
//! frames cannot pile up in the TCP and WebSocket buffers between a slow client
//! and the encoder. After a drop the client only gets frames again from the next
//! keyframe, because the frames in between cannot be decoded. Clients that do not
//! ask for flow control are not tracked.

use std::collections::VecDeque;

/// Largest window a client may ask for.
pub const MAX_FLOW_WINDOW: usize = 8;
/// Largest control message a client may send.
pub const MAX_CONTROL_BYTES: usize = 64;

const ACK_MESSAGE: u8 = 2;
const RESYNC_MESSAGE: u8 = 3;

/// A message from the client on the direct stream socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    /// Everything up to and including this timestamp has been decoded.
    Ack(u64),
    /// The client lost its decoder state and needs a keyframe.
    Resync,
}

/// Parses `[2, timestamp as u64 LE]` (an acknowledgement) or `[3]` (a resync request).
pub fn parse_control(data: &[u8]) -> Option<Control> {
    match data {
        [ACK_MESSAGE, rest @ ..] if rest.len() == 8 => {
            let timestamp = u64::from_le_bytes(rest.try_into().ok()?);
            Some(Control::Ack(timestamp))
        }
        [RESYNC_MESSAGE] => Some(Control::Resync),
        _ => None,
    }
}

/// What to do with a frame that is ready to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    Send,
    /// Skip it; the client now needs a keyframe.
    Skip,
}

#[derive(Debug)]
pub struct DirectFlow {
    window: Option<usize>,
    in_flight: VecDeque<u64>,
    waiting_for_keyframe: bool,
}

impl DirectFlow {
    /// `window` is the number of frames the client allows in flight, or `None`
    /// for a client that does not use flow control.
    pub fn new(window: Option<usize>) -> Self {
        Self {
            window: window.map(|window| window.clamp(1, MAX_FLOW_WINDOW)),
            in_flight: VecDeque::new(),
            waiting_for_keyframe: true,
        }
    }

    pub fn offer(&mut self, keyframe: bool, timestamp: u64) -> Offer {
        let Some(window) = self.window else {
            return Offer::Send;
        };

        if keyframe {
            if self.in_flight.len() >= window {
                self.waiting_for_keyframe = true;
                return Offer::Skip;
            }
            self.waiting_for_keyframe = false;
        } else if self.waiting_for_keyframe {
            return Offer::Skip;
        } else if self.in_flight.len() >= window {
            self.waiting_for_keyframe = true;
            return Offer::Skip;
        }

        self.in_flight.push_back(timestamp);
        Offer::Send
    }

    pub fn acknowledge(&mut self, timestamp: u64) {
        while self
            .in_flight
            .front()
            .is_some_and(|sent| *sent <= timestamp)
        {
            self.in_flight.pop_front();
        }
    }

    pub fn resync(&mut self) {
        self.in_flight.clear();
        self.waiting_for_keyframe = true;
    }

    pub fn apply(&mut self, control: Control) {
        match control {
            Control::Ack(timestamp) => self.acknowledge(timestamp),
            Control::Resync => self.resync(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_acknowledgements_and_resync_requests() {
        let mut ack = vec![2];
        ack.extend_from_slice(&1_234_567_u64.to_le_bytes());
        assert_eq!(parse_control(&ack), Some(Control::Ack(1_234_567)));
        assert_eq!(parse_control(&[3]), Some(Control::Resync));
    }

    #[test]
    fn rejects_malformed_control_messages() {
        assert_eq!(parse_control(&[]), None);
        assert_eq!(parse_control(&[2]), None);
        assert_eq!(parse_control(&[2, 0, 0, 0]), None);
        assert_eq!(parse_control(&[2; 10]), None);
        assert_eq!(parse_control(&[3, 0]), None);
        assert_eq!(parse_control(&[9]), None);
    }

    #[test]
    fn a_client_without_flow_control_gets_every_frame() {
        let mut flow = DirectFlow::new(None);
        for timestamp in 0..100 {
            assert_eq!(flow.offer(timestamp % 30 == 0, timestamp), Offer::Send);
        }
    }

    #[test]
    fn frames_before_the_first_keyframe_are_skipped() {
        let mut flow = DirectFlow::new(Some(4));
        assert_eq!(flow.offer(false, 1), Offer::Skip);
        assert_eq!(flow.offer(true, 2), Offer::Send);
        assert_eq!(flow.offer(false, 3), Offer::Send);
    }

    #[test]
    fn a_full_window_drops_frames_until_the_next_keyframe() {
        let mut flow = DirectFlow::new(Some(2));
        assert_eq!(flow.offer(true, 1), Offer::Send);
        assert_eq!(flow.offer(false, 2), Offer::Send);
        // Window full: the next frame is dropped and the stream waits for a keyframe.
        assert_eq!(flow.offer(false, 3), Offer::Skip);

        flow.acknowledge(2);
        // Acknowledging frees the window, but a delta frame cannot be decoded after a gap.
        assert_eq!(flow.offer(false, 4), Offer::Skip);
        assert_eq!(flow.offer(true, 5), Offer::Send);
        assert_eq!(flow.offer(false, 6), Offer::Send);
    }

    #[test]
    fn a_keyframe_is_dropped_while_the_window_is_full() {
        let mut flow = DirectFlow::new(Some(1));
        assert_eq!(flow.offer(true, 1), Offer::Send);
        assert_eq!(flow.offer(true, 2), Offer::Skip);

        flow.acknowledge(1);
        assert_eq!(flow.offer(true, 3), Offer::Send);
    }

    #[test]
    fn an_acknowledgement_covers_every_earlier_frame() {
        let mut flow = DirectFlow::new(Some(3));
        assert_eq!(flow.offer(true, 10), Offer::Send);
        assert_eq!(flow.offer(false, 20), Offer::Send);
        assert_eq!(flow.offer(false, 30), Offer::Send);
        assert_eq!(flow.offer(false, 40), Offer::Skip);

        flow.acknowledge(25);
        // Frames 10 and 20 are acknowledged; 30 is still in flight.
        assert_eq!(flow.in_flight.len(), 1);

        // An old acknowledgement changes nothing.
        flow.acknowledge(5);
        assert_eq!(flow.in_flight.len(), 1);
    }

    #[test]
    fn a_resync_request_empties_the_window_and_waits_for_a_keyframe() {
        let mut flow = DirectFlow::new(Some(3));
        assert_eq!(flow.offer(true, 1), Offer::Send);
        assert_eq!(flow.offer(false, 2), Offer::Send);

        flow.apply(Control::Resync);
        assert!(flow.in_flight.is_empty());
        assert_eq!(flow.offer(false, 3), Offer::Skip);
        assert_eq!(flow.offer(true, 4), Offer::Send);
    }

    #[test]
    fn the_window_is_clamped_to_a_sane_range() {
        assert_eq!(DirectFlow::new(Some(0)).window, Some(1));
        assert_eq!(DirectFlow::new(Some(100)).window, Some(MAX_FLOW_WINDOW));
        assert_eq!(DirectFlow::new(None).window, None);
    }
}
