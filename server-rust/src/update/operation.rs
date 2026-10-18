//! In-process app/system work ownership, not durable update/restore authority.
//! HTTP cancellation drops only a reply receiver. The runtime task and blocking
//! callbacks retain admission through their own completion. Legacy process
//! handoffs still need separate child supervision and durable authority.

use crate::{AppError, Result};
use rand_core::{OsRng, RngCore};
use serde::{Serialize, Serializer};
use std::{
    fmt,
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::{sync::oneshot, task};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationId([u8; 16]);
impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl Serialize for OperationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    ApplicationOnline,
    ApplicationOffline,
    SystemDownload,
    SystemInstall,
    SystemRollback,
    SystemConfirm,
}
impl Kind {
    pub fn is_system(self) -> bool {
        matches!(
            self,
            Self::SystemDownload | Self::SystemInstall | Self::SystemRollback | Self::SystemConfirm
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Running,
    Finished,
    Failed,
}

/// Bounded public diagnostics only. Finished means request work ended, NOT
/// boot/raw acceptance. No paths, credentials, payloads or callback error text.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub id: OperationId,
    pub kind: Kind,
    pub phase: Phase,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Snapshot {
    pub active: Option<Status>,
    pub last: Option<Status>,
}

struct Active {
    status: Status,
    outcome: Option<bool>,
}
#[derive(Default)]
struct Slot {
    active: Option<Active>,
    last: Option<Status>,
}
#[derive(Default)]
pub struct UpdateCoordinator {
    slot: Mutex<Slot>,
}

impl UpdateCoordinator {
    pub fn acquire(self: &Arc<Self>, kind: Kind) -> Result<UpdateOwner> {
        let mut slot = self.slot.lock().map_err(|_| poisoned())?;
        if let Some(active) = &slot.active {
            return Err(AppError::Conflict(format!(
                "update operation {} is already in progress",
                active.status.id
            )));
        }
        let mut id = [0; 16];
        for _ in 0..2 {
            OsRng
                .try_fill_bytes(&mut id)
                .map_err(|_| AppError::Internal("update operation entropy unavailable".into()))?;
            if id != [0; 16] {
                break;
            }
        }
        if id == [0; 16] {
            return Err(AppError::Internal(
                "update operation entropy invalid".into(),
            ));
        }
        let id = OperationId(id);
        slot.active = Some(Active {
            status: Status {
                id,
                kind,
                phase: Phase::Running,
            },
            outcome: None,
        });
        Ok(UpdateOwner(Arc::new(Ownership {
            coordinator: Arc::clone(self),
            id,
        })))
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        let slot = self.slot.lock().map_err(|_| poisoned())?;
        Ok(Snapshot {
            active: slot.active.as_ref().map(|active| active.status),
            last: slot.last,
        })
    }
}

struct Ownership {
    coordinator: Arc<UpdateCoordinator>,
    id: OperationId,
}
impl Drop for Ownership {
    fn drop(&mut self) {
        // Poisoning never silently authorizes another update. No recovery from
        // p3 markers or HTTP data, and no global lock shared by independent tests.
        if let Ok(mut slot) = self.coordinator.slot.lock()
            && slot
                .active
                .as_ref()
                .is_some_and(|active| active.status.id == self.id)
            && let Some(mut active) = slot.active.take()
        {
            active.status.phase = if active.outcome == Some(true) {
                Phase::Finished
            } else {
                Phase::Failed
            };
            slot.last = Some(active.status);
        }
    }
}

// Not publicly Clone: only the driver/blocking helper issue work ownership.
pub struct UpdateOwner(Arc<Ownership>);
struct BlockingOwnership {
    owner: UpdateOwner,
    success: bool,
}
// Declaration order matters: discarded callback results clean up BEFORE their
// work ownership is released, including when the JoinHandle waiter is gone.
struct ReturnedWork<T> {
    result: Result<T>,
    _ownership: BlockingOwnership,
}
impl Drop for BlockingOwnership {
    fn drop(&mut self) {
        if !self.success || std::thread::panicking() {
            self.owner.record_outcome(false);
        }
    }
}
impl UpdateOwner {
    /// Runtime-owned work continues after disconnect. No abort handle is
    /// exposed. Schedule follow-up work inside this job, never by returning an
    /// owner through the HTTP reply. Not a restart journal/user cancellation API.
    pub async fn run<T, F, Fut>(self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(UpdateOwner) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let (reply, receive) = oneshot::channel();
        let worker = UpdateOwner(Arc::clone(&self.0));
        task::spawn(async move {
            let result = work(worker).await;
            let success = result.is_ok();
            drop(reply.send(result)); // also clean up an undeliverable result
            self.record_outcome(success);
            drop(self);
        });
        receive
            .await
            .map_err(|_| AppError::Internal("update job ended without a result".into()))?
    }

    /// Every callback owns admission even if its awaiting future is dropped.
    /// Destructive workers must still signal AND join owned children; dropping
    /// a JoinHandle does not implement cancellation.
    pub async fn blocking<T, F>(&self, operation: &'static str, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let completion = BlockingOwnership {
            owner: UpdateOwner(Arc::clone(&self.0)),
            success: false,
        };
        let completed = task::spawn_blocking(move || {
            // Move the whole Drop guard, never only a captured bool field.
            let mut completion = completion;
            let result = work();
            completion.success = result.is_ok();
            ReturnedWork {
                result,
                _ownership: completion,
            }
        })
        .await
        .map_err(|_| AppError::Internal(format!("{operation} task failed")))?;
        completed.result
    }

    pub(crate) fn record_outcome(&self, success: bool) {
        if let Ok(mut slot) = self.0.coordinator.slot.lock()
            && let Some(active) = slot.active.as_mut()
            && active.status.id == self.0.id
        {
            // Root success cannot overwrite a later restart/child failure.
            active.outcome = Some(success && active.outcome != Some(false));
        }
    }
}

fn poisoned() -> AppError {
    AppError::Internal("update coordinator poisoned".into())
}

#[cfg(test)]
#[path = "operation_tests.rs"]
mod tests;
