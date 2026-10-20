//! Test-only elapsed-operation evidence. Never an authority or progress lease.
use std::time::{Duration, Instant};

pub(crate) struct Elapsed {
    operation: &'static str,
    member: Option<usize>,
    started: Instant,
}

impl Elapsed {
    pub(crate) fn start(operation: &'static str, member: Option<usize>) -> Self {
        Self {
            operation,
            member,
            started: Instant::now(),
        }
    }
}

impl Drop for Elapsed {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        if elapsed >= Duration::from_millis(100) {
            let thread = std::thread::current();
            eprintln!(
                "support-operation-elapsed: test={:?}, operation={}, member={:?}, elapsed={elapsed:?}",
                thread.name(),
                self.operation,
                self.member
            );
        }
    }
}
