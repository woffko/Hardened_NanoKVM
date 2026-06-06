use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
struct Attempt {
    failures: u32,
    lockout_until: Option<Instant>,
    last_failure: Instant,
}

#[derive(Debug)]
pub struct LoginRateLimiter {
    max_failures: u32,
    lockout_duration: Duration,
    attempts: HashMap<String, Attempt>,
}

impl LoginRateLimiter {
    pub fn new(max_failures: u32, lockout_duration_secs: u64) -> Self {
        Self {
            max_failures: max_failures.max(1),
            lockout_duration: Duration::from_secs(lockout_duration_secs.max(1)),
            attempts: HashMap::new(),
        }
    }

    pub fn check(&mut self, source_ip: &str, username: &str) -> bool {
        self.prune();
        let now = Instant::now();
        let key = key(source_ip, username);
        self.attempts
            .get(&key)
            .and_then(|attempt| attempt.lockout_until)
            .is_some_and(|until| now < until)
    }

    pub fn record_failure(&mut self, source_ip: &str, username: &str) -> bool {
        self.prune();
        let now = Instant::now();
        let key = key(source_ip, username);
        let attempt = self.attempts.entry(key).or_insert(Attempt {
            failures: 0,
            lockout_until: None,
            last_failure: now,
        });

        if now.duration_since(attempt.last_failure) > self.lockout_duration {
            attempt.failures = 0;
            attempt.lockout_until = None;
        }

        attempt.failures += 1;
        attempt.last_failure = now;
        if attempt.failures >= self.max_failures {
            attempt.lockout_until = Some(now + self.lockout_duration);
            return true;
        }
        false
    }

    pub fn record_success(&mut self, source_ip: &str, username: &str) {
        self.attempts.remove(&key(source_ip, username));
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.attempts.retain(|_, attempt| {
            if let Some(until) = attempt.lockout_until {
                now < until
            } else {
                now.duration_since(attempt.last_failure) <= self.lockout_duration
            }
        });
    }
}

fn key(source_ip: &str, username: &str) -> String {
    format!("{source_ip}:{username}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_threshold() {
        let mut limiter = LoginRateLimiter::new(2, 60);
        assert!(!limiter.record_failure("1.2.3.4", "admin"));
        assert!(limiter.record_failure("1.2.3.4", "admin"));
        assert!(limiter.check("1.2.3.4", "admin"));
        assert!(!limiter.check("1.2.3.4", "other"));
    }
}
