//! Logical report ownership. A lease authorizes cleanup of its own last report,
//! not another source's input. Device I/O and ownership publication are ordered
//! by the same mutex; a delayed retry cannot race a later successful writer.
use std::{io, sync::Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Endpoint {
    Keyboard,
    Relative,
    Absolute,
}

impl Endpoint {
    fn index(self) -> usize {
        match self {
            Self::Keyboard => 0,
            Self::Relative => 1,
            Self::Absolute => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Report {
    Keyboard([u8; 8]),
    Relative([u8; 4]),
    Absolute([u8; 6]),
}

impl Report {
    fn endpoint(self) -> Endpoint {
        match self {
            Self::Keyboard(_) => Endpoint::Keyboard,
            Self::Relative(_) => Endpoint::Relative,
            Self::Absolute(_) => Endpoint::Absolute,
        }
    }

    fn held(self) -> bool {
        match self {
            Self::Keyboard(bytes) => bytes != [0; 8],
            Self::Relative(bytes) => bytes[0] != 0,
            Self::Absolute(bytes) => bytes[0] != 0,
        }
    }

    fn neutral(self) -> Self {
        match self {
            Self::Keyboard(_) => Self::Keyboard([0; 8]),
            Self::Relative(_) => Self::Relative([0; 4]),
            Self::Absolute([_, x0, x1, y0, y1, _]) => Self::Absolute([0, x0, x1, y0, y1, 0]),
        }
    }
}

pub(super) trait Sink {
    fn write(&mut self, report: Report) -> io::Result<()>;
    fn close(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy)]
struct Current {
    owner: u64,
    report: Report,
    // An unsuccessful neutral write may leave the preceding report held.
    needs_release: bool,
}

struct State<S> {
    sink: S,
    current: [Option<Current>; 3],
    mouse_owner: Option<u64>,
}

pub(super) struct Bus<S> {
    // Lease allocation never waits behind device I/O (e.g. WS setup on Tokio).
    next: Mutex<u64>,
    state: Mutex<State<S>>,
}

pub(super) struct Lease<'a, S> {
    bus: &'a Bus<S>,
    id: u64,
}

impl<S> Copy for Lease<'_, S> {}
impl<S> Clone for Lease<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

fn poisoned() -> io::Error {
    io::Error::other("HID report ownership poisoned")
}

impl<S: Sink> Bus<S> {
    pub(super) fn new(sink: S) -> Self {
        Self {
            next: Mutex::new(0),
            state: Mutex::new(State {
                sink,
                current: [None; 3],
                mouse_owner: None,
            }),
        }
    }

    pub(super) fn begin(&self) -> io::Result<Lease<'_, S>> {
        let mut next = self.next.lock().map_err(|_| poisoned())?;
        *next = next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("HID owner IDs exhausted"))?;
        Ok(Lease {
            bus: self,
            id: *next,
        })
    }

    pub(super) fn close(&self) -> io::Result<()> {
        // Closing cached FDs is not evidence of a physical key/button release.
        // Retain logical ownership for later cleanup/recovery.
        self.state.lock().map_err(|_| poisoned())?.sink.close()
    }
}

impl<S: Sink> Lease<'_, S> {
    pub(super) fn write(self, report: Report) -> io::Result<usize> {
        let mut state = self.bus.state.lock().map_err(|_| poisoned())?;
        state.write(self.id, report)
    }

    pub(super) fn write_if(
        self,
        report: Report,
        allowed: impl FnOnce() -> bool,
    ) -> io::Result<usize> {
        let mut state = self.bus.state.lock().map_err(|_| poisoned())?;
        // Recheck after a possibly delayed bus acquisition, immediately before
        // beginning I/O. The liveness lock is never retained during device I/O.
        if !allowed() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "HID input authority ended",
            ));
        }
        state.write(self.id, report)
    }

    pub(super) fn passive_mouse(self, report: Report, continuation: bool) -> io::Result<usize> {
        if report.endpoint() == Endpoint::Keyboard {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a mouse report",
            ));
        }
        let mut state = self.bus.state.lock().map_err(|_| poisoned())?;
        if state.current[1..]
            .iter()
            .flatten()
            .any(|current| current.needs_release)
            || (continuation && state.mouse_owner != Some(self.id))
        {
            return Ok(0);
        }
        state.write(self.id, report)
    }

    pub(super) fn release(self, endpoint: Endpoint, settle: bool) -> io::Result<usize> {
        self.bus
            .state
            .lock()
            .map_err(|_| poisoned())?
            .release(self.id, endpoint, settle)
    }

    pub(super) fn finish(self) -> io::Result<usize> {
        let mut state = self.bus.state.lock().map_err(|_| poisoned())?;
        let mut writes = 0;
        let mut first_error = None;
        for endpoint in [Endpoint::Keyboard, Endpoint::Relative, Endpoint::Absolute] {
            match state.release(self.id, endpoint, false) {
                Ok(count) => writes += count,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(writes),
        }
    }
}

impl<S: Sink> State<S> {
    fn write(&mut self, owner: u64, report: Report) -> io::Result<usize> {
        // Even an error can follow a device effect. Retain the attempted report
        // for this owner's compensation; a later writer supersedes it atomically.
        let slot = &mut self.current[report.endpoint().index()];
        let possibly_held = report.held() || slot.is_some_and(|previous| previous.needs_release);
        *slot = Some(Current {
            owner,
            report,
            needs_release: possibly_held,
        });
        if report.endpoint() != Endpoint::Keyboard {
            self.mouse_owner = Some(owner);
        }
        self.sink.write(report)?;
        // A successful complete report replaces the previous device state.
        self.current[report.endpoint().index()] = Some(Current {
            owner,
            report,
            needs_release: report.held(),
        });
        Ok(1)
    }

    fn release(&mut self, owner: u64, endpoint: Endpoint, settle: bool) -> io::Result<usize> {
        let Some(current) = self.current[endpoint.index()] else {
            return Ok(0);
        };
        if current.owner != owner || (!settle && !current.needs_release) {
            return Ok(0);
        }
        let neutral = current.report.neutral();
        // Keep the previous held state if compensation fails; a second exact
        // cleanup can retry. Do not turn an I/O error into proof of key-up.
        self.sink.write(neutral)?;
        self.current[endpoint.index()] = Some(Current {
            owner,
            report: neutral,
            needs_release: false,
        });
        if endpoint != Endpoint::Keyboard {
            self.mouse_owner = Some(owner);
        }
        Ok(1)
    }
}

#[cfg(test)]
#[path = "hid_ownership_tests.rs"]
mod tests;
