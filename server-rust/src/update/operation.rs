//! App/system work ownership and cooperative cross-process front-end admission,
//! not durable update/restore authority.
//! HTTP cancellation drops only a reply receiver. The runtime task and blocking
//! callbacks retain admission through their own completion. Legacy process
//! handoffs still need separate child supervision and durable authority.

use super::operation_lock::{LockError, ProcessLock};
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
    #[cfg(test)]
    fixture: Option<TestAdmission>,
}
#[cfg(test)]
enum TestAdmission {
    InProcess,
    Parent(std::fs::File),
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
        let process_lock = self.acquire_process_lock()?;
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
            kind,
            process_lock: Mutex::new(process_lock),
        })))
    }

    fn acquire_process_lock(&self) -> Result<Option<ProcessLock>> {
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            return match fixture {
                TestAdmission::InProcess => Ok(None),
                TestAdmission::Parent(parent) => {
                    ProcessLock::from_parent(parent, nix::unistd::geteuid().as_raw())
                        .map(Some)
                        .map_err(lock_error)
                }
            };
        }
        let lock = ProcessLock::acquire().map_err(lock_error)?;
        crate::native_owner::broker::check_update_admission().map_err(|_| {
            AppError::Conflict("native lifecycle is fenced; update admission refused".into())
        })?;
        Ok(Some(lock))
    }

    #[cfg(test)]
    pub(crate) fn in_process_fixture() -> Self {
        Self {
            slot: Mutex::default(),
            fixture: Some(TestAdmission::InProcess),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_parent(parent: std::fs::File) -> Self {
        Self {
            slot: Mutex::default(),
            fixture: Some(TestAdmission::Parent(parent)),
        }
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
    kind: Kind,
    // Dropped only with the LAST owner, after the local completion receipt.
    process_lock: Mutex<Option<ProcessLock>>,
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
impl UpdateOwner {
    /// Crate-private clone for a blocking worker that must prepare a handoff
    /// under the same retained operation while the caller still owns work.
    pub(crate) fn clone_for_work(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
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
    /// Prepare only app-job admission transfer. This does not submit an
    /// installer, authorize a candidate or mark the operation successful.
    /// The returned sender ownership also retains this frontend job.
    pub fn prepare_install_handoff(
        &self,
        writers: super::state_writers::WriterDrain,
    ) -> Result<super::app_install_lease::Handoff> {
        if !matches!(
            self.0.kind,
            Kind::ApplicationOnline | Kind::ApplicationOffline
        ) {
            return Err(AppError::Conflict(
                "install handoff requires an application operation".into(),
            ));
        }
        let mut lease = self.0.process_lock.lock().map_err(|_| poisoned())?;
        let lease = lease.as_mut().ok_or_else(|| {
            AppError::Internal("install handoff requires process admission".into())
        })?;
        let update = lease.transfer_alias().map_err(lock_error)?;
        super::app_install_lease::Handoff::new(
            self.0.id.0,
            update,
            writers,
            UpdateOwner(Arc::clone(&self.0)),
        )
    }

    /// Prepare only the raw write's admission transfer: the retained update and
    /// writer exclusions plus the two image snapshots. `transaction` is the
    /// prepared ticket's; this neither publishes nor authorizes anything.
    pub fn prepare_raw_handoff(
        &self,
        transaction: [u8; 16],
        images: super::raw_install_lease::RawImages,
        writers: super::state_writers::WriterDrain,
    ) -> Result<super::raw_install_lease::RawHandoff> {
        if self.0.kind != Kind::SystemInstall {
            return Err(AppError::Conflict(
                "raw handoff requires a system install operation".into(),
            ));
        }
        let mut lease = self.0.process_lock.lock().map_err(|_| poisoned())?;
        let lease = lease
            .as_mut()
            .ok_or_else(|| AppError::Internal("raw handoff requires process admission".into()))?;
        let update = lease.transfer_alias().map_err(lock_error)?;
        super::raw_install_lease::RawHandoff::new(
            transaction,
            images,
            update,
            writers,
            UpdateOwner(Arc::clone(&self.0)),
        )
    }

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

fn lock_error(error: LockError) -> AppError {
    match error {
        LockError::Busy => AppError::Conflict(error.to_string()),
        LockError::Unsafe | LockError::Io => AppError::Internal(error.to_string()),
    }
}

#[cfg(test)]
#[path = "operation_tests.rs"]
mod tests;
