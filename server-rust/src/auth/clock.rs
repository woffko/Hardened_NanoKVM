//! Whether the wall clock can be trusted for time-derived authentication.
//!
//! This board has no battery-backed RTC. It boots at the Unix epoch
//! (`cvi_rtc: RTC invalid time` -> `setting system clock to 1970-01-01`) and
//! only reaches real wall-clock time once NTP succeeds. TOTP codes derived from
//! a 1970 clock are simply wrong, so the login path has to be able to tell
//! "your code is incorrect" apart from "this device does not know what time it
//! is yet".

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

/// 2026-01-01T00:00:00Z. Any wall clock earlier than this means the device has
/// not synchronized since boot.
///
/// This is deliberately a source constant rather than a build timestamp:
/// baking `SystemTime::now()` into the binary through `build.rs` would make
/// builds non-reproducible, which this project goes to considerable lengths to
/// avoid. The constant only has to sit between "the firmware was built" and
/// "now", and the failure mode it guards against is a clock at 1970 -- five
/// decades away from the boundary, so the exact value is not delicate.
pub const MIN_PLAUSIBLE_UNIX_TIME: u64 = 1_767_225_600;

/// Set once an explicit synchronization has been observed to succeed.
static SYNC_OBSERVED: AtomicBool = AtomicBool::new(false);

/// Record that time synchronization succeeded during this boot.
pub fn mark_synced() {
    SYNC_OBSERVED.store(true, Ordering::Relaxed);
}

/// Current wall clock as a Unix timestamp, saturating at the epoch.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Whether the wall clock is trustworthy enough to derive TOTP codes from.
///
/// Two independent signals, either of which is sufficient:
///
///  * the clock reads later than [`MIN_PLAUSIBLE_UNIX_TIME`] -- which also
///    covers `ntpd` correcting the clock in the background, without the server
///    being involved at all; and
///  * a synchronization was observed to succeed through the API this boot.
pub fn is_synced() -> bool {
    read().synced
}

/// One sample of the wall clock, so the time and its trustworthiness agree.
#[derive(Debug, Clone, Copy)]
pub struct Reading {
    pub now_unix: u64,
    pub synced: bool,
}

pub fn read() -> Reading {
    let now_unix = now_unix();
    Reading {
        now_unix,
        synced: SYNC_OBSERVED.load(Ordering::Relaxed) || timestamp_is_plausible(now_unix),
    }
}

/// The clock-only half of [`is_synced`], separated out so it can be tested
/// without touching process-wide state.
pub fn timestamp_is_plausible(now_unix: u64) -> bool {
    now_unix >= MIN_PLAUSIBLE_UNIX_TIME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_boot_is_not_plausible() {
        // What the board actually reports before NTP succeeds.
        assert!(!timestamp_is_plausible(0));
        assert!(!timestamp_is_plausible(1));
    }

    #[test]
    fn a_current_clock_is_plausible() {
        assert!(timestamp_is_plausible(MIN_PLAUSIBLE_UNIX_TIME));
        assert!(timestamp_is_plausible(MIN_PLAUSIBLE_UNIX_TIME + 86_400));
    }

    #[test]
    fn boundary_is_just_below_the_floor() {
        assert!(!timestamp_is_plausible(MIN_PLAUSIBLE_UNIX_TIME - 1));
    }

    #[test]
    fn floor_is_in_the_past_relative_to_the_real_clock() {
        // Guards against a typo that pushes the floor into the future, which
        // would make every device look permanently unsynchronized.
        assert!(
            now_unix() > MIN_PLAUSIBLE_UNIX_TIME,
            "MIN_PLAUSIBLE_UNIX_TIME must already have passed"
        );
    }
}
