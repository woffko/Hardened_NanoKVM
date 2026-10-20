//! Credential-free lifetime of one issued session, shared by captured users.
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionEnd {
    Revoked,
    Expired,
    Uncertain,
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Active(Instant),
    Ended(SessionEnd),
}

#[derive(Debug)]
struct Inner {
    phase: Mutex<Phase>,
    changed: Notify,
}

#[derive(Clone, Debug)]
pub(crate) struct SessionLifetime {
    inner: Arc<Inner>,
}

impl SessionLifetime {
    pub(super) fn new(deadline: Instant) -> Self {
        Self {
            inner: Arc::new(Inner {
                phase: Mutex::new(Phase::Active(deadline)),
                changed: Notify::new(),
            }),
        }
    }

    fn snapshot(&self) -> Phase {
        let Ok(mut phase) = self.inner.phase.lock() else {
            self.inner.changed.notify_waiters();
            return Phase::Ended(SessionEnd::Uncertain);
        };
        let expired = matches!(*phase, Phase::Active(deadline) if Instant::now() >= deadline);
        if expired {
            *phase = Phase::Ended(SessionEnd::Expired);
        }
        let snapshot = *phase;
        drop(phase);
        if expired {
            self.inner.changed.notify_waiters();
        }
        snapshot
    }

    pub(crate) fn is_active(&self) -> bool {
        matches!(self.snapshot(), Phase::Active(_))
    }

    pub(super) fn retime(&self, deadline: Instant) -> bool {
        let Ok(mut phase) = self.inner.phase.lock() else {
            self.inner.changed.notify_waiters();
            return false;
        };
        let now = Instant::now();
        let renewed = match *phase {
            Phase::Ended(_) => return false,
            Phase::Active(previous) if now >= previous => {
                *phase = Phase::Ended(SessionEnd::Expired);
                false
            }
            Phase::Active(_) => {
                *phase = if now >= deadline {
                    Phase::Ended(SessionEnd::Expired)
                } else {
                    Phase::Active(deadline)
                };
                true
            }
        };
        drop(phase);
        self.inner.changed.notify_waiters();
        renewed
    }

    pub(super) fn revoke(&self) {
        let changed = match self.inner.phase.lock() {
            Ok(mut phase) if matches!(*phase, Phase::Active(_)) => {
                *phase = Phase::Ended(SessionEnd::Revoked);
                true
            }
            Ok(_) => false,
            Err(_) => true,
        };
        if changed {
            self.inner.changed.notify_waiters();
        }
    }

    pub(crate) async fn ended(&self) -> SessionEnd {
        loop {
            // Register before the state check: revoke/retime cannot be lost
            // between observing Active and waiting for a notification.
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let deadline = match self.snapshot() {
                Phase::Ended(reason) => return reason,
                Phase::Active(deadline) => deadline,
            };
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {}
            }
            // A prior timer is only a wakeup. Recheck the shared state under
            // the same lock used by retime; never expire a renewed deadline.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, pin::Pin, task::Poll, time::Duration};

    async fn pending(mut future: Pin<&mut impl Future<Output = SessionEnd>>) {
        std::future::poll_fn(|context| {
            assert!(matches!(future.as_mut().poll(context), Poll::Pending));
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn revocation_is_observed_before_and_after_wait_registration_by_all_captures() {
        for revoke_first in [false, true] {
            let lifetime = SessionLifetime::new(Instant::now() + Duration::from_secs(60));
            let capture = lifetime.clone();
            let mut first = Box::pin(lifetime.ended());
            let mut second = Box::pin(capture.ended());
            if !revoke_first {
                pending(first.as_mut()).await;
                pending(second.as_mut()).await;
            }
            lifetime.revoke();
            assert_eq!(first.await, SessionEnd::Revoked);
            assert_eq!(second.await, SessionEnd::Revoked);
            assert!(!capture.is_active());
            assert!(!lifetime.retime(Instant::now() + Duration::from_secs(300)));
        }
    }

    #[tokio::test]
    async fn expiry_wakes_without_a_validation_request_and_cannot_be_renewed() {
        let lifetime = SessionLifetime::new(Instant::now() + Duration::from_millis(25));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), lifetime.ended())
                .await
                .unwrap(),
            SessionEnd::Expired
        );
        assert!(!lifetime.retime(Instant::now() + Duration::from_secs(300)));
        lifetime.revoke();
        assert_eq!(lifetime.ended().await, SessionEnd::Expired);
    }

    #[tokio::test]
    async fn retiming_notifies_captures_and_an_old_timer_cannot_expire_a_renewed_handle() {
        let lifetime = SessionLifetime::new(Instant::now() + Duration::from_secs(1));
        let mut ended = Box::pin(lifetime.ended());
        pending(ended.as_mut()).await;
        let renewed = Instant::now() + Duration::from_secs(60);
        assert!(lifetime.retime(renewed));
        // Leave the old wait unpolled until both its old timer and the retime
        // notification are ready; neither may end the renewed lifetime.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        pending(ended.as_mut()).await;
        assert!(matches!(lifetime.snapshot(), Phase::Active(at) if at == renewed));
        assert!(lifetime.retime(Instant::now()));
        assert_eq!(ended.await, SessionEnd::Expired);
    }

    #[tokio::test]
    async fn unobserved_expiry_and_poison_are_not_renewable_authority() {
        let expired = SessionLifetime::new(Instant::now());
        assert!(!expired.retime(Instant::now() + Duration::from_secs(60)));
        assert_eq!(expired.ended().await, SessionEnd::Expired);

        let poisoned = SessionLifetime::new(Instant::now() + Duration::from_secs(60));
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoned.inner.phase.lock().unwrap();
            panic!("synthetic session lifetime poison");
        }));
        assert!(failure.is_err());
        assert!(!poisoned.is_active());
        assert!(!poisoned.retime(Instant::now() + Duration::from_secs(60)));
        assert_eq!(poisoned.ended().await, SessionEnd::Uncertain);
    }

    #[test]
    fn concurrent_revoke_and_retime_never_reopen_a_revoked_handle() {
        for _ in 0..16 {
            let lifetime = SessionLifetime::new(Instant::now() + Duration::from_secs(60));
            let start = std::sync::Barrier::new(3);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    start.wait();
                    lifetime.revoke();
                });
                scope.spawn(|| {
                    start.wait();
                    lifetime.retime(Instant::now() + Duration::from_secs(300));
                });
                start.wait();
            });
            assert!(matches!(
                lifetime.snapshot(),
                Phase::Ended(SessionEnd::Revoked)
            ));
            assert!(!lifetime.retime(Instant::now() + Duration::from_secs(300)));
        }
    }
}
