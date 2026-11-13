use std::{future::Future, sync::LazyLock};
use tokio::sync::Mutex;

use crate::{AppError, Result};

// One lock for every backend operation that changes the composite gadget.
// Synchronous HID recovery uses try_lock: it must not restart a gadget while a
// storage/network operation owns it, nor deadlock on a cached HID descriptor.
pub static GADGET_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub async fn run_exclusive<F, T>(operation: F) -> Result<T>
where
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let guard = GADGET_LOCK
        .try_lock()
        .map_err(|_| AppError::Conflict("USB gadget operation is in progress".to_string()))?;
    // The job, not the HTTP future, owns the guard. Disconnecting the client
    // cannot cancel a switch between disconnect and reconnect.
    tokio::spawn(async move {
        let _guard = guard;
        operation.await
    })
    .await
    .map_err(|err| AppError::Internal(format!("USB gadget operation failed: {err}")))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn operation_survives_request_cancellation_and_retains_lock() {
        let (started_tx, started_rx) = oneshot::channel();
        let (finish_tx, finish_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let request = tokio::spawn(run_exclusive(async move {
            started_tx.send(()).unwrap();
            finish_rx.await.unwrap();
            done_tx.send(()).unwrap();
            Ok(())
        }));
        started_rx.await.unwrap();
        request.abort();
        assert!(matches!(
            run_exclusive(async { Ok(()) }).await,
            Err(AppError::Conflict(_))
        ));
        assert!(GADGET_LOCK.try_lock().is_err());
        finish_tx.send(()).unwrap();
        done_rx.await.unwrap();
        // Completion is signalled inside the operation; acquiring this lock
        // also waits for its owning task to return and release the guard.
        let _guard = GADGET_LOCK.lock().await;
    }
}
