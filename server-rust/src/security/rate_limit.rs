use std::{
    collections::HashMap,
    net::IpAddr,
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

    pub fn check(&mut self, source: IpAddr, username: &str) -> bool {
        self.prune();
        let now = Instant::now();
        let key = key(source, username);
        self.attempts
            .get(&key)
            .and_then(|attempt| attempt.lockout_until)
            .is_some_and(|until| now < until)
    }

    pub fn record_failure(&mut self, source: IpAddr, username: &str) -> bool {
        self.prune();
        let now = Instant::now();
        let key = key(source, username);
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

    pub fn record_success(&mut self, source: IpAddr, username: &str) {
        self.attempts.remove(&key(source, username));
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

// The source a lockout applies to: an IPv4 address, or the /64 network of an
// IPv6 address, through which one host can rotate freely.
fn source_key(source: IpAddr) -> String {
    let v6 = match source {
        IpAddr::V4(v4) => return v4.to_string(),
        IpAddr::V6(v6) => v6,
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return v4.to_string();
    }
    let s = v6.segments();
    format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
}

fn key(source: IpAddr, username: &str) -> String {
    format!("{} {username}", source_key(source))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn locks_after_threshold() {
        let mut limiter = LoginRateLimiter::new(2, 60);
        assert!(!limiter.record_failure(ip("1.2.3.4"), "admin"));
        assert!(limiter.record_failure(ip("1.2.3.4"), "admin"));
        assert!(limiter.check(ip("1.2.3.4"), "admin"));
        assert!(!limiter.check(ip("1.2.3.4"), "other"));
        assert!(!limiter.check(ip("1.2.3.5"), "admin"));
    }

    #[test]
    fn an_ipv6_host_cannot_rotate_out_of_its_lockout_within_its_64() {
        let mut limiter = LoginRateLimiter::new(2, 60);
        assert!(!limiter.record_failure(ip("2001:db8:1:2::1"), "admin"));
        assert!(limiter.record_failure(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"), "admin"));
        for inside in ["2001:db8:1:2::7", "2001:db8:1:2:abcd::1"] {
            assert!(limiter.check(ip(inside), "admin"), "{inside}");
        }
        for outside in ["2001:db8:1:3::1", "2001:db9:1:2::1"] {
            assert!(!limiter.check(ip(outside), "admin"), "{outside}");
        }
        limiter.record_success(ip("2001:db8:1:2::42"), "admin");
        assert!(!limiter.check(ip("2001:db8:1:2::1"), "admin"));
    }

    #[test]
    fn an_ipv4_mapped_source_is_its_ipv4_address() {
        let mut limiter = LoginRateLimiter::new(1, 60);
        assert!(limiter.record_failure(ip("::ffff:192.0.2.7"), "admin"));
        assert!(limiter.check(ip("192.0.2.7"), "admin"));
        assert!(!limiter.check(ip("192.0.2.8"), "admin"));
    }
}
