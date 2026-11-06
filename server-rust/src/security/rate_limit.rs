use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
struct Attempt {
    failures: u32,
    lockout_until: Option<Instant>,
    last_failure: Instant,
}

/// A source may fail this many times the per-name limit across all names before
/// it is locked out for every name, so rotating names gets around nothing.
const SOURCE_BUDGET_FACTOR: u32 = 4;
/// Entries kept in each map at most. Past this the oldest leave first, and an
/// entry that still locks someone out leaves last.
const MAX_ENTRIES: usize = 1024;

#[derive(Debug)]
pub struct LoginRateLimiter {
    max_failures: u32,
    lockout_duration: Duration,
    attempts: HashMap<String, Attempt>,
    sources: HashMap<String, Attempt>,
}

impl LoginRateLimiter {
    pub fn new(max_failures: u32, lockout_duration_secs: u64) -> Self {
        Self {
            max_failures: max_failures.max(1),
            lockout_duration: Duration::from_secs(lockout_duration_secs.max(1)),
            attempts: HashMap::new(),
            sources: HashMap::new(),
        }
    }

    pub fn check(&mut self, source: IpAddr, username: &str) -> bool {
        self.prune();
        let now = Instant::now();
        let locked = |attempt: Option<&Attempt>| {
            attempt
                .and_then(|attempt| attempt.lockout_until)
                .is_some_and(|until| now < until)
        };
        locked(self.attempts.get(&key(source, username)))
            || locked(self.sources.get(&source_key(source)))
    }

    pub fn record_failure(&mut self, source: IpAddr, username: &str) -> bool {
        self.prune();
        let now = Instant::now();
        let name = bump(
            &mut self.attempts,
            key(source, username),
            self.max_failures,
            self.lockout_duration,
            now,
        );
        let all = bump(
            &mut self.sources,
            source_key(source),
            self.max_failures.saturating_mul(SOURCE_BUDGET_FACTOR),
            self.lockout_duration,
            now,
        );
        name || all
    }

    pub fn record_success(&mut self, source: IpAddr, username: &str) {
        self.attempts.remove(&key(source, username));
        self.sources.remove(&source_key(source));
    }

    fn prune(&mut self) {
        let now = Instant::now();
        let lockout = self.lockout_duration;
        let current = |attempt: &Attempt| {
            if let Some(until) = attempt.lockout_until {
                now < until
            } else {
                now.duration_since(attempt.last_failure) <= lockout
            }
        };
        self.attempts.retain(|_, attempt| current(attempt));
        self.sources.retain(|_, attempt| current(attempt));
    }
}

/// Count one failure against `key`; true when it now locks.
fn bump(
    map: &mut HashMap<String, Attempt>,
    key: String,
    limit: u32,
    lockout: Duration,
    now: Instant,
) -> bool {
    if !map.contains_key(&key) && map.len() >= MAX_ENTRIES {
        let oldest = map
            .iter()
            .min_by_key(|(_, attempt)| (attempt.lockout_until.is_some(), attempt.last_failure))
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            map.remove(&oldest);
        }
    }
    let attempt = map.entry(key).or_insert(Attempt {
        failures: 0,
        lockout_until: None,
        last_failure: now,
    });
    if now.duration_since(attempt.last_failure) > lockout {
        attempt.failures = 0;
        attempt.lockout_until = None;
    }
    attempt.failures += 1;
    attempt.last_failure = now;
    if attempt.failures >= limit {
        attempt.lockout_until = Some(now + lockout);
        return true;
    }
    false
}

/// Attempts at the Wi-Fi AP provisioning key, which has few possible values:
/// a lockout per source, and one budget shared by all sources. Every client on
/// the AP gets its own address, so a per-source lockout alone is not enough.
pub struct ApKeyLimiter {
    per_source: LoginRateLimiter,
    shared: LoginRateLimiter,
}

const AP_KEY: &str = "wifi-ap-key";
const AP_KEY_SHARED: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

impl ApKeyLimiter {
    pub fn new() -> Self {
        Self {
            per_source: LoginRateLimiter::new(5, 600),
            shared: LoginRateLimiter::new(20, 600),
        }
    }

    pub fn check(&mut self, source: IpAddr) -> bool {
        self.per_source.check(source, AP_KEY) || self.shared.check(AP_KEY_SHARED, AP_KEY)
    }

    pub fn record_failure(&mut self, source: IpAddr) {
        self.per_source.record_failure(source, AP_KEY);
        self.shared.record_failure(AP_KEY_SHARED, AP_KEY);
    }

    /// A correct key clears its own source, not the shared budget.
    pub fn record_success(&mut self, source: IpAddr) {
        self.per_source.record_success(source, AP_KEY);
    }
}

impl Default for ApKeyLimiter {
    fn default() -> Self {
        Self::new()
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
    fn rotating_names_locks_the_source_for_every_name() {
        let mut limiter = LoginRateLimiter::new(5, 60);
        for name in 0..19 {
            assert!(!limiter.record_failure(ip("192.0.2.7"), &format!("guess{name}")));
        }
        assert!(!limiter.check(ip("192.0.2.7"), "admin"));
        assert!(limiter.record_failure(ip("192.0.2.7"), "guess19"));
        for name in ["admin", "terminal:admin", "never-tried"] {
            assert!(limiter.check(ip("192.0.2.7"), name), "{name}");
        }
        assert!(!limiter.check(ip("192.0.2.8"), "admin"));
        limiter.record_success(ip("192.0.2.7"), "admin");
        assert!(!limiter.check(ip("192.0.2.7"), "never-tried"));
    }

    #[test]
    fn the_maps_stay_bounded_and_keep_a_lockout_longest() {
        let mut limiter = LoginRateLimiter::new(1, 60);
        assert!(limiter.record_failure(ip("198.51.100.1"), "admin"));
        let mut limiter_unlocked = LoginRateLimiter::new(5, 60);
        for n in 0..3000u32 {
            let source = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n));
            limiter.record_failure(source, &format!("name{n}"));
            limiter_unlocked.record_failure(source, &format!("name{n}"));
        }
        assert!(limiter.attempts.len() <= MAX_ENTRIES);
        assert!(limiter.sources.len() <= MAX_ENTRIES);
        assert!(limiter_unlocked.attempts.len() <= MAX_ENTRIES);
        // With a limit of one every entry locks, so the oldest lockout leaves.
        assert!(!limiter.check(ip("198.51.100.1"), "admin"));
        let mut kept = LoginRateLimiter::new(2, 60);
        assert!(!kept.record_failure(ip("198.51.100.1"), "admin"));
        assert!(kept.record_failure(ip("198.51.100.1"), "admin"));
        for n in 0..3000u32 {
            let source = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n));
            kept.record_failure(source, "admin");
        }
        assert!(
            kept.check(ip("198.51.100.1"), "admin"),
            "a lockout left before entries that lock nothing"
        );
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
    fn the_ap_key_locks_one_source_then_every_source() {
        let mut limiter = ApKeyLimiter::new();
        for _ in 0..4 {
            limiter.record_failure(ip("192.168.4.100"));
        }
        assert!(!limiter.check(ip("192.168.4.100")));
        limiter.record_failure(ip("192.168.4.100"));
        assert!(
            limiter.check(ip("192.168.4.100")),
            "five failures lock a source"
        );
        assert!(!limiter.check(ip("192.168.4.101")));
        // Rotating through AP client addresses only spends the shared budget.
        for client in 101..116 {
            limiter.record_failure(ip(&format!("192.168.4.{client}")));
        }
        assert!(
            limiter.check(ip("192.168.4.200")),
            "twenty failures lock all"
        );
        limiter.record_success(ip("192.168.4.200"));
        assert!(
            limiter.check(ip("192.168.4.200")),
            "success keeps the shared lock"
        );
    }

    #[test]
    fn an_ipv4_mapped_source_is_its_ipv4_address() {
        let mut limiter = LoginRateLimiter::new(1, 60);
        assert!(limiter.record_failure(ip("::ffff:192.0.2.7"), "admin"));
        assert!(limiter.check(ip("192.0.2.7"), "admin"));
        assert!(!limiter.check(ip("192.0.2.8"), "admin"));
    }
}
