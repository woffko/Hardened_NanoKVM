use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::task::JoinHandle;

use super::webrtc_policy::PeerAccess;
use crate::{AppError, Result, config::WEBRTC_PEER_CEILING};

pub(super) struct PeerTask {
    pub access: PeerAccess,
    pub task: Option<JoinHandle<bool>>,
}

/// Handles stay here while polled; canceling a waiter cannot detach cleanup.
pub(super) struct Tasks {
    pub peers: [Option<PeerTask>; WEBRTC_PEER_CEILING],
    pub producer: Option<JoinHandle<bool>>,
    pub stopping: bool,
    uncertain: bool,
}

impl Default for Tasks {
    fn default() -> Self {
        Self {
            peers: std::array::from_fn(|_| None),
            producer: None,
            stopping: false,
            uncertain: false,
        }
    }
}

impl Tasks {
    pub fn poll(&mut self, cx: &mut Context<'_>, finished_only: bool) -> Poll<Result<()>> {
        let mut pending = false;
        for slot in &mut self.peers {
            let Some(peer) = slot else {
                continue;
            };
            let Some(task) = &mut peer.task else {
                continue;
            };
            if finished_only && !task.is_finished() {
                pending = true;
                continue;
            }
            match Pin::new(task).poll(cx) {
                Poll::Ready(Ok(true)) => *slot = None,
                Poll::Ready(_) => {
                    peer.access.stop();
                    peer.task = None;
                    self.uncertain = true;
                }
                Poll::Pending => pending = true,
            }
        }
        if let Some(producer) = &mut self.producer {
            if finished_only && !producer.is_finished() {
                pending = true;
            } else {
                match Pin::new(producer).poll(cx) {
                    Poll::Ready(Ok(true)) => self.producer = None,
                    Poll::Ready(_) => {
                        self.producer = None;
                        self.uncertain = true;
                    }
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else if self.uncertain {
            Poll::Ready(Err(AppError::Internal(
                "WebRTC task cleanup uncertain".into(),
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    pub fn uncertain(&self) -> bool {
        self.uncertain
    }
}
