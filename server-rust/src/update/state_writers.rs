//! Cooperative writer admission/drain. Only enrolled writers are covered;
//! currently account mutation/legacy seed and Config YAML/startup secret.
//! NOT a coherent device snapshot, service stop, raw-writer ticket or durable crash protocol.

use super::operation_lock::{Domain, LockError, ProcessLock};
use crate::{
    AppError, Result,
    system::command::{self, AllowedCommand, CommandOutput},
};
use std::{ffi::OsStr, future::Future, marker::PhantomData, sync::Arc, time::Duration};
use tokio::{sync::oneshot, task, time};

#[derive(Default)]
pub struct StateWriters {
    #[cfg(test)]
    parent: Option<std::fs::File>,
    #[cfg(test)]
    config_path: Option<std::path::PathBuf>,
}
impl StateWriters {
    fn lock(&self, domain: Domain, shared: bool) -> std::result::Result<ProcessLock, LockError> {
        #[cfg(test)]
        if let Some(parent) = &self.parent {
            return ProcessLock::at_parent(parent, nix::unistd::geteuid().as_raw(), domain, shared);
        }
        ProcessLock::for_domain(domain, shared)
    }

    pub(crate) fn account(&self) -> Result<AccountPermit> {
        self.enroll(Domain::Account, "account change already in progress")
    }

    pub(crate) fn configuration(&self) -> Result<ConfigPermit> {
        self.enroll(
            Domain::Configuration,
            "configuration change already in progress",
        )
    }

    fn enroll<Role>(&self, domain: Domain, busy: &'static str) -> Result<WriterPermit<Role>> {
        // Lock order: short admission SH -> activity SH -> serial domain EX. A drain
        // owns admission EX before waiting for all existing activity shares.
        let admission = self
            .lock(Domain::WriterAdmission, true)
            .map_err(writer_error)?;
        let activity = self
            .lock(Domain::WriterActivity, true)
            .map_err(writer_error)?;
        let serial = self.lock(domain, false).map_err(|error| match error {
            LockError::Busy => AppError::Conflict(busy.into()),
            error => writer_error(error),
        })?;
        drop(admission);
        Ok(WriterPermit {
            locks: Arc::new(WriterLocks {
                _serial: serial,
                _activity: activity,
            }),
            role: PhantomData,
            #[cfg(test)]
            config_path: self.config_path.clone(),
        })
    }

    /// Closes new enrollment before draining current enrolled work. HTTP/raw
    /// integration must retain this barrier on its owned phase, not a handler.
    /// Unenrolled settings/services/PTYs/scripts are NOT quiescent by this API.
    pub async fn drain(&self, timeout: Duration) -> Result<WriterDrain> {
        let admission = self
            .lock(Domain::WriterAdmission, false)
            .map_err(writer_error)?;
        let activity = time::timeout(timeout, async {
            loop {
                match self.lock(Domain::WriterActivity, false) {
                    Ok(lock) => return Ok(lock),
                    Err(LockError::Busy) => time::sleep(Duration::from_millis(20)).await,
                    Err(error) => return Err(writer_error(error)),
                }
            }
        })
        .await
        .map_err(|_| AppError::Conflict("configuration writers did not drain".into()))??;
        Ok(WriterDrain {
            _activity: activity,
            _admission: admission,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test_parent(parent: std::fs::File) -> Self {
        Self {
            parent: Some(parent),
            config_path: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_config(parent: std::fs::File, path: std::path::PathBuf) -> Self {
        Self {
            parent: Some(parent),
            config_path: Some(path),
        }
    }
}

// Field order releases the serial domain before the last active-writer share.
struct WriterLocks {
    _serial: ProcessLock,
    _activity: ProcessLock,
}
// A Config permit must never authorize AccountStore mutation. Zero-sized role
// tags preserve that proof while sharing exactly the same lifetime machinery.
pub(crate) enum Account {}
pub(crate) enum Configuration {}
pub(crate) type AccountPermit = WriterPermit<Account>;
pub(crate) type ConfigPermit = WriterPermit<Configuration>;
pub(crate) struct WriterPermit<Role> {
    locks: Arc<WriterLocks>,
    role: PhantomData<Role>,
    #[cfg(test)]
    config_path: Option<std::path::PathBuf>,
}

impl ConfigPermit {
    #[cfg(test)]
    pub(crate) fn fixture_config_path(&self) -> Option<&std::path::Path> {
        self.config_path.as_deref()
    }
}

#[must_use = "retain the barrier until the enrolled read/capture phase ends"]
pub struct WriterDrain {
    _activity: ProcessLock,
    _admission: ProcessLock,
}

// On discarded results, cleanup precedes release of the callback's permit.
struct Returned<T, Role> {
    result: Result<T>,
    _permit: WriterPermit<Role>,
}
impl<Role: Send + Sync + 'static> WriterPermit<Role> {
    fn share(&self) -> Self {
        Self {
            locks: Arc::clone(&self.locks),
            role: PhantomData,
            #[cfg(test)]
            config_path: self.config_path.clone(),
        }
    }

    pub(crate) async fn run<T, F, Fut>(self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T>> + Send + 'static,
    {
        let (reply, receive) = oneshot::channel();
        let worker = self.share();
        task::spawn(async move {
            let result = work(worker).await;
            drop(reply.send(result));
            drop(self);
        });
        receive
            .await
            .map_err(|_| AppError::Internal("configuration writer ended without a result".into()))?
    }

    pub(crate) async fn blocking<T, F>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Self) -> Result<T> + Send + 'static,
    {
        let permit = self.share();
        let completed = task::spawn_blocking(move || {
            let result = work(&permit);
            Returned {
                result,
                _permit: permit,
            }
        })
        .await
        .map_err(|_| AppError::Internal("configuration writer callback failed".into()))?;
        completed.result
    }

    pub(crate) async fn command_with_stdin<I, S>(
        &self,
        command: AllowedCommand,
        args: I,
        input: &[u8],
        timeout: Duration,
    ) -> Result<CommandOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        // The command owner, not just its awaiting future, retains activity
        // through cancellation/timeout I/O cleanup and direct-child reap.
        command::run_allowed_with_stdin_owned(command, args, input, timeout, self.share()).await
    }

    pub(crate) async fn command<I, S>(
        &self,
        command: AllowedCommand,
        args: I,
        timeout: Duration,
    ) -> Result<CommandOutput>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        command::run_allowed_owned(command, args, timeout, self.share()).await
    }
}

fn writer_error(error: LockError) -> AppError {
    match error {
        LockError::Busy => AppError::Conflict("configuration writers are paused".into()),
        LockError::Unsafe => {
            AppError::Internal("configuration writers require protected rootfs storage".into())
        }
        LockError::Io => AppError::Internal("configuration writer storage I/O failed".into()),
    }
}

#[cfg(test)]
#[path = "state_writers_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "state_writers_config_tests.rs"]
mod config_tests;
