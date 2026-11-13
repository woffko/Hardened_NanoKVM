//! Test-only finite progress observation, never installation authority.
use std::time::{Duration, Instant};

const POINTS: usize = 72;
const IDLE: Duration = Duration::from_secs(15);

pub(super) fn points() -> Vec<String> {
    let mut points = Vec::with_capacity(POINTS);
    for name in [
        "issuer-directory-created",
        "issuer-candidate-moved",
        "issuer-source-synced",
        "issuer-candidate-synced",
        "prepared:record-written",
        "prepared:record-synced",
        "prepared:record-renamed",
        "prepared:record-published",
        "issuer-record-durable",
        "issuer-current-renamed",
        "issuer-current-durable",
    ] {
        points.push(name.to_owned());
    }
    for name in super::APP_STATE {
        for step in [
            "begin",
            "entropy-ready",
            "created",
            "written",
            "file-synced",
            "renamed",
        ] {
            points.push(format!("app-state-{name}-{step}"));
        }
        points.push(format!("app-state-{name}"));
    }
    for phase in ["publishing", "published"] {
        if phase == "published" {
            for name in [
                "publish-old-parked",
                "publish-old-parked-synced",
                "publish-new-live",
                "publish-new-live-synced",
            ] {
                points.push(name.to_owned());
            }
        }
        for step in [
            "record-written",
            "record-synced",
            "record-renamed",
            "record-published",
        ] {
            points.push(format!("{phase}:{step}"));
        }
    }
    assert_eq!(points.len(), POINTS);
    points
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Event {
    Progress(usize),
    Ready,
    Invalid,
}

pub(super) fn parse(line: &str, points: &[String]) -> Option<Event> {
    let name = line.strip_prefix("slot-checkpoint: ")?;
    Some(
        points
            .iter()
            .position(|point| point == name)
            .map_or(Event::Invalid, Event::Progress),
    )
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Error {
    InvalidProgress,
    DuplicateReady,
    Timeout,
    Disconnected,
}

pub(super) struct Watch {
    target: usize,
    next: usize,
    ready: bool,
    deadline: Instant,
}

impl Watch {
    pub(super) fn new(target: usize, now: Instant) -> Self {
        assert!(target < POINTS);
        Self {
            target,
            next: 0,
            ready: false,
            deadline: now + IDLE,
        }
    }

    pub(super) fn remaining(&self, now: Instant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }

    pub(super) fn observe(&mut self, event: Event, now: Instant) -> Result<bool, Error> {
        match event {
            Event::Progress(index) if index == self.next && index <= self.target => {
                self.next += 1;
                self.deadline = now + IDLE;
            }
            Event::Progress(_) | Event::Invalid => return Err(Error::InvalidProgress),
            Event::Ready if self.ready => return Err(Error::DuplicateReady),
            Event::Ready => self.ready = true,
        }
        // The two pipes may be read in either order. Both confirmations are
        // required; Ready alone never extends the observation deadline.
        Ok(self.ready && self.next == self.target + 1)
    }
}

#[test]
fn exact_finite_points_parse_uniquely_and_noise_is_not_progress() {
    let points = points();
    assert_eq!(
        points
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        POINTS
    );
    for (index, name) in points.iter().enumerate() {
        assert_eq!(
            parse(&format!("slot-checkpoint: {name}"), &points),
            Some(Event::Progress(index))
        );
    }
    for line in [
        "noise",
        "slot-checkpoint-ready",
        "publication-child: fixture-ready",
    ] {
        assert_eq!(parse(line, &points), None);
    }
    for line in [
        "slot-checkpoint: unknown",
        "slot-checkpoint: ",
        "slot-checkpoint: issuer-current-durable extra",
    ] {
        assert_eq!(parse(line, &points), Some(Event::Invalid));
    }
}

#[test]
fn every_target_requires_exact_progress_and_the_actual_ready_signal() {
    let start = Instant::now();
    for target in 0..POINTS {
        let mut watch = Watch::new(target, start);
        for index in 0..=target {
            let now = start + Duration::from_secs(index as u64 + 1);
            assert_eq!(watch.observe(Event::Progress(index), now), Ok(false));
            assert_eq!(watch.remaining(now), IDLE);
        }
        assert_eq!(watch.observe(Event::Ready, start), Ok(true));
    }
}

#[test]
fn ready_on_the_other_pipe_does_not_extend_or_finish_early() {
    let start = Instant::now();
    let mut watch = Watch::new(1, start);
    assert_eq!(
        watch.observe(Event::Ready, start + Duration::from_secs(10)),
        Ok(false)
    );
    assert_eq!(
        watch.remaining(start + Duration::from_secs(10)),
        Duration::from_secs(5)
    );
    assert_eq!(
        watch.observe(Event::Progress(0), start + Duration::from_secs(11)),
        Ok(false)
    );
    assert_eq!(
        watch.observe(Event::Progress(1), start + Duration::from_secs(12)),
        Ok(true)
    );
}

#[test]
fn duplicate_unknown_skipped_and_beyond_target_events_never_extend() {
    let start = Instant::now();
    for event in [
        Event::Invalid,
        Event::Progress(0),
        Event::Progress(2),
        Event::Progress(POINTS),
    ] {
        let mut watch = Watch::new(1, start);
        watch.observe(Event::Progress(0), start).unwrap();
        let deadline = watch.deadline;
        assert_eq!(
            watch.observe(event, start + Duration::from_secs(10)),
            Err(Error::InvalidProgress)
        );
        assert_eq!(watch.deadline, deadline);
    }
    let mut watch = Watch::new(0, start);
    watch.observe(Event::Progress(0), start).unwrap();
    let deadline = watch.deadline;
    assert_eq!(
        watch.observe(Event::Progress(1), start),
        Err(Error::InvalidProgress)
    );
    assert_eq!(watch.deadline, deadline);
    assert_eq!(watch.observe(Event::Ready, start), Ok(true));
    assert_eq!(
        watch.observe(Event::Ready, start + Duration::from_secs(10)),
        Err(Error::DuplicateReady)
    );
    assert_eq!(watch.deadline, deadline);
}

#[test]
fn no_progress_or_missing_ready_exhausts_the_same_fifteen_seconds() {
    let start = Instant::now();
    let mut watch = Watch::new(0, start);
    assert_eq!(watch.remaining(start + IDLE), Duration::ZERO);
    watch.observe(Event::Progress(0), start + IDLE).unwrap();
    assert_eq!(watch.remaining(start + IDLE + IDLE), Duration::ZERO);
    assert!(!watch.ready);
}
