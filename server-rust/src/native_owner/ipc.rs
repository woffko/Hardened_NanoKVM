//! Root-only, fixed-frame native lifecycle transport. No raw-write authority.
use super::{
    Broker, Resume, RetainedDrain, RuntimePermit, Shutdown, StartFailure, app_install, journal,
};
use crate::native_owner::controller::{Completion, DrainStatus, Role, StartError, Status};
use crate::update::{app_install_lease, app_slot};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

const FRAME: usize = 16;
const CLIENTS: usize = 16;
const STEP: Duration = Duration::from_millis(20);
const IDLE: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_secs(2);
const INSTALL_OFFERS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Observe = 1,
    EnsureKvm = 2,
    EnsureHwmon = 3,
    Pause = 4,
    Resume = 5,
    Shutdown = 6,
    EnsureBackend = 7,
    BackendRunning = 8,
    RestartBackend = 9,
    RestartBackendSafe = 10,
    CancelAppInstall = 11,
}
impl Operation {
    fn decode(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Observe),
            2 => Some(Self::EnsureKvm),
            3 => Some(Self::EnsureHwmon),
            4 => Some(Self::Pause),
            5 => Some(Self::Resume),
            6 => Some(Self::Shutdown),
            7 => Some(Self::EnsureBackend),
            8 => Some(Self::BackendRunning),
            9 => Some(Self::RestartBackend),
            10 => Some(Self::RestartBackendSafe),
            11 => Some(Self::CancelAppInstall),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Running = 1,
    Draining = 2,
    Paused = 3,
    Abandoned = 4,
    Uncertain = 5,
    Stopping = 6,
    Stopped = 7,
    Installing = 8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Ok = 0,
    Busy = 1,
    Invalid = 2,
    Unavailable = 3,
    Uncertain = 4,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: Code,
    pub mode: Mode,
    pub roles: [u8; 2],
}

fn request(op: Operation, serial: u64) -> [u8; FRAME] {
    let mut bytes = [0; FRAME];
    bytes[..4].copy_from_slice(b"NKC1");
    bytes[4] = op as u8;
    bytes[8..].copy_from_slice(&serial.to_be_bytes());
    bytes
}
fn parse_request(bytes: &[u8; FRAME]) -> Option<(Operation, u64)> {
    if &bytes[..4] != b"NKC1" || bytes[5..8] != [0; 3] {
        return None;
    }
    Some((
        Operation::decode(bytes[4])?,
        u64::from_be_bytes(bytes[8..].try_into().ok()?),
    ))
}
impl Reply {
    fn bytes(self, serial: u64) -> [u8; FRAME] {
        let mut bytes = [0; FRAME];
        bytes[..4].copy_from_slice(b"NKR1");
        bytes[4] = self.code as u8;
        bytes[5] = self.mode as u8;
        bytes[6..8].copy_from_slice(&self.roles);
        bytes[8..].copy_from_slice(&serial.to_be_bytes());
        bytes
    }
    fn parse(bytes: &[u8; FRAME], serial: u64) -> io::Result<Self> {
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        if &bytes[..4] != b"NKR1"
            || bytes[8..] != serial.to_be_bytes()
            || bytes[6..8].iter().any(|b| *b > 6)
        {
            return Err(invalid());
        }
        let code = match bytes[4] {
            0 => Code::Ok,
            1 => Code::Busy,
            2 => Code::Invalid,
            3 => Code::Unavailable,
            4 => Code::Uncertain,
            _ => return Err(invalid()),
        };
        let mode = match bytes[5] {
            1 => Mode::Running,
            2 => Mode::Draining,
            3 => Mode::Paused,
            4 => Mode::Abandoned,
            5 => Mode::Uncertain,
            6 => Mode::Stopping,
            7 => Mode::Stopped,
            8 => Mode::Installing,
            _ => return Err(invalid()),
        };
        Ok(Self {
            code,
            mode,
            roles: [bytes[6], bytes[7]],
        })
    }
}

struct Flight {
    bytes: [u8; FRAME],
    sent: usize,
    reply: [u8; FRAME],
    read: usize,
    serial: u64,
}
/// Keep this object across caller deadlines. It retains partial sends/reads and
/// the maintenance connection; begin refuses to replace an unresolved request.
pub struct Channel {
    stream: UnixStream,
    next: u64,
    flight: Option<Flight>,
    broken: bool,
}
impl Channel {
    pub fn connect() -> io::Result<Self> {
        Self::verified(journal::Store::connect_control()?, 0)
    }
    fn verified(stream: UnixStream, uid: u32) -> io::Result<Self> {
        if rustix::net::sockopt::socket_peercred(&stream)?.uid.as_raw() != uid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            next: 1,
            flight: None,
            broken: false,
        })
    }
    pub fn begin(&mut self, op: Operation) -> io::Result<()> {
        if self.broken {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if self.flight.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let serial = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidInput)?;
        self.flight = Some(Flight {
            bytes: request(op, serial),
            sent: 0,
            reply: [0; FRAME],
            read: 0,
            serial,
        });
        Ok(())
    }
    pub fn poll(&mut self) -> io::Result<Option<Reply>> {
        if self.broken {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let Some(f) = self.flight.as_mut() else {
            return Ok(None);
        };
        let result = (|| {
            if f.sent < FRAME {
                match self.stream.write(&f.bytes[f.sent..]) {
                    Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                    Ok(n) => f.sent += n,
                    Err(e) if pending(&e) => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
            if f.sent < FRAME {
                return Ok(None);
            }
            match self.stream.read(&mut f.reply[f.read..]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => f.read += n,
                Err(e) if pending(&e) => return Ok(None),
                Err(e) => return Err(e),
            }
            if f.read < FRAME {
                Ok(None)
            } else {
                Reply::parse(&f.reply, f.serial).map(Some)
            }
        })();
        match &result {
            Ok(Some(_)) => self.flight = None,
            Err(_) => self.broken = true,
            _ => {}
        }
        result
    }
}

fn pending(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
fn role_status(status: Option<Status>) -> u8 {
    match status {
        None => 0,
        Some(Status::Starting) => 1,
        Some(Status::Running) => 2,
        Some(Status::Stopping) => 3,
        Some(Status::Closed(Completion::Stopped | Completion::SuccessfulExit)) => 4,
        Some(Status::Closed(_)) => 5,
        Some(Status::Uncertain | Status::TrialFailed) => 6,
    }
}

enum Owner {
    Running(Broker),
    Paused(RetainedDrain),
    Stopping(RetainedDrain),
}

enum InstallOwner {
    Draining(app_install::Session),
    Refused {
        broker: Broker,
        _install: app_slot::AcceptedInstall,
    },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum InstallStage {
    Draining,
    Published,
    Failed,
}
struct Install {
    owner: InstallOwner,
    stage: InstallStage,
}
struct Engine {
    owner: Option<Owner>,
    install: Option<Install>,
    wanted: [bool; 2],
    retry: [Instant; 2],
    lease: Option<u64>,
    abandoned: bool,
    mode: Mode,
    roles: [u8; 2],
    stopped_at: Option<Instant>,
    backend_wanted: bool,
    backend_status: Option<Status>,
    backend_retry: Instant,
    backend_restart: Option<BackendRestart>,
    #[cfg(test)]
    fixture: Option<std::path::PathBuf>,
    #[cfg(test)]
    fixture_request_completed: Option<Instant>,
}
struct BackendRestart {
    _admission: RuntimePermit,
    safe_mode: bool,
}
impl Engine {
    fn new(broker: Broker) -> Self {
        Self {
            owner: Some(Owner::Running(broker)),
            install: None,
            wanted: [false; 2],
            retry: [Instant::now(); 2],
            lease: None,
            abandoned: false,
            mode: Mode::Running,
            roles: [0; 2],
            stopped_at: None,
            backend_wanted: false,
            backend_status: None,
            backend_retry: Instant::now(),
            backend_restart: None,
            #[cfg(test)]
            fixture: None,
            #[cfg(test)]
            fixture_request_completed: None,
        }
    }
    fn command(&self, role: Role) -> std::process::Command {
        #[cfg(test)]
        if let Some(root) = &self.fixture {
            return tests::owner_command(root, role);
        }
        role.command()
    }
    fn tick(&mut self) {
        if let Some(install) = self.install.as_mut() {
            match &mut install.owner {
                InstallOwner::Draining(session) => {
                    match session.poll() {
                        Ok(DrainStatus::Drained) => {
                            self.roles = [4; 2];
                            self.backend_status = Some(Status::Closed(Completion::Stopped));
                            if install.stage == InstallStage::Draining {
                                // Exactly one attempt. An ambiguous I/O result is
                                // retained, never retried as a fresh transaction.
                                install.stage = match session.publish() {
                                    Ok(app_slot::Status::Transaction(
                                        app_slot::Phase::Published,
                                    )) => InstallStage::Published,
                                    _ => InstallStage::Failed,
                                };
                            }
                        }
                        Ok(DrainStatus::Pending) => self.roles = [3; 2],
                        _ => {
                            self.roles = [6; 2];
                            install.stage = InstallStage::Failed;
                        }
                    }
                }
                InstallOwner::Refused { broker, .. } => {
                    // Journal failure does not discard live scope owners or
                    // admission. Poll only; never launch or fabricate Stop.
                    self.roles = broker.poll().map(role_status);
                    self.backend_status = broker.backend_status();
                    install.stage = InstallStage::Failed;
                }
            }
            self.mode = if install.stage == InstallStage::Failed {
                Mode::Uncertain
            } else {
                Mode::Installing
            };
            return;
        }
        let Some(owner) = self.owner.take() else {
            self.mode = Mode::Uncertain;
            return;
        };
        self.owner = Some(match owner {
            Owner::Running(mut broker) => {
                self.backend_status = broker.backend_status();
                let states = broker.poll();
                self.roles = states.map(role_status);
                if states.contains(&Some(Status::Uncertain)) {
                    self.mode = Mode::Uncertain;
                }
                if self.mode == Mode::Running {
                    for (index, role) in [Role::KvmSystem, Role::Hwmon].into_iter().enumerate() {
                        if self.wanted[index]
                            && Instant::now() >= self.retry[index]
                            && matches!(states[index], None | Some(Status::Closed(_)))
                        {
                            self.retry[index] = Instant::now() + RETRY;
                            let command = self.command(role);
                            if matches!(
                                broker.start_owned(role, command),
                                Err(StartFailure::Journal(_))
                                    | Err(StartFailure::Scope(StartError::UncertainOwnership))
                            ) {
                                self.mode = Mode::Uncertain;
                            }
                        }
                    }
                    if self.backend_restart.is_some()
                        && matches!(self.backend_status, None | Some(Status::Closed(_)))
                    {
                        if let Some(restart) = self.backend_restart.take() {
                            // Both update/config permits remain held through
                            // safe-mode publication and the replacement spawn.
                            let policy = if restart.safe_mode {
                                broker.prepare_safe_mode(&restart._admission)
                            } else {
                                Ok(())
                            };
                            let command = self.command(Role::Backend);
                            if policy.is_err()
                                || broker.start_backend(command, &restart._admission).is_err()
                                || broker.finish_backend_restart().is_err()
                            {
                                self.mode = Mode::Uncertain;
                            }
                            drop(restart);
                        }
                    } else if self.backend_restart.is_none()
                        && self.backend_wanted
                        && Instant::now() >= self.backend_retry
                        && matches!(self.backend_status, None | Some(Status::Closed(_)))
                    {
                        self.backend_retry = Instant::now() + RETRY;
                        match broker.runtime_permit() {
                            Ok(admission) => {
                                let command = self.command(Role::Backend);
                                if matches!(
                                    broker.start_backend(command, &admission),
                                    Err(StartFailure::Journal(_))
                                        | Err(StartFailure::Scope(StartError::UncertainOwnership))
                                ) {
                                    self.mode = Mode::Uncertain;
                                }
                            }
                            Err(super::JournalError::Busy) => {}
                            Err(_) => self.mode = Mode::Uncertain,
                        }
                    }
                }
                self.backend_status = broker.backend_status();
                if self.backend_status == Some(Status::Uncertain) {
                    self.mode = Mode::Uncertain;
                }
                self.roles = broker.poll().map(role_status);
                if self.roles.contains(&6) {
                    self.mode = Mode::Uncertain;
                }
                Owner::Running(broker)
            }
            Owner::Paused(mut drain) => {
                let result = drain.poll();
                self.backend_status = drain.backend_status();
                self.roles = match result {
                    Ok(DrainStatus::Drained) => [4; 2],
                    Ok(DrainStatus::Pending) => [3; 2],
                    _ => [6; 2],
                };
                self.mode = match result {
                    Ok(DrainStatus::Pending) => {
                        if self.abandoned {
                            Mode::Abandoned
                        } else {
                            Mode::Draining
                        }
                    }
                    Ok(DrainStatus::Drained) => {
                        if self.abandoned {
                            Mode::Abandoned
                        } else {
                            Mode::Paused
                        }
                    }
                    _ => Mode::Uncertain,
                };
                if self.backend_status == Some(Status::Uncertain) {
                    self.mode = Mode::Uncertain;
                }
                Owner::Paused(drain)
            }
            Owner::Stopping(mut drain) => {
                self.mode = match drain.poll() {
                    Ok(DrainStatus::Pending) => Mode::Stopping,
                    Ok(DrainStatus::Drained) => {
                        self.stopped_at.get_or_insert_with(Instant::now);
                        Mode::Stopped
                    }
                    _ => Mode::Uncertain,
                };
                self.backend_status = drain.backend_status();
                self.roles = if self.mode == Mode::Stopped {
                    [4; 2]
                } else {
                    [3; 2]
                };
                Owner::Stopping(drain)
            }
        });
    }
    fn reply(&self, code: Code) -> Reply {
        Reply {
            code,
            mode: self.mode,
            roles: self.roles,
        }
    }

    fn accept_install(&mut self, admission: app_install_lease::Accepted) -> Code {
        // Retained lifecycle/maintenance work cannot be replaced by an offer.
        if self.mode != Mode::Running
            || self.install.is_some()
            || self.lease.is_some()
            || self.abandoned
            || self.backend_restart.is_some()
            || !matches!(self.owner, Some(Owner::Running(_)))
        {
            return Code::Busy;
        }
        #[cfg(test)]
        let accepted = match &self.fixture {
            Some(root) => app_slot::issuer_tests::accept_fixture(root, admission),
            None => app_slot::accept_prepared(admission),
        };
        #[cfg(not(test))]
        let accepted = app_slot::accept_prepared(admission);
        let install = match accepted {
            Ok(install) => install,
            Err(app_slot::SlotError::Busy) => return Code::Busy,
            Err(_) => return Code::Invalid,
        };
        let Some(Owner::Running(broker)) = self.owner.take() else {
            return Code::Uncertain;
        };
        self.install = Some(match broker.begin_app_install(install) {
            app_install::Start::Draining(session) => Install {
                owner: InstallOwner::Draining(session),
                stage: InstallStage::Draining,
            },
            app_install::Start::Retained { broker, install } => Install {
                owner: InstallOwner::Refused {
                    broker,
                    _install: install,
                },
                stage: InstallStage::Failed,
            },
        });
        self.tick();
        if self.mode == Mode::Uncertain {
            Code::Uncertain
        } else {
            Code::Ok
        }
    }

    fn cancel_install(&mut self) -> Code {
        let Some(install) = self.install.take() else {
            return Code::Busy;
        };
        let Install { owner, stage } = install;
        match owner {
            InstallOwner::Draining(session) => match session.rollback() {
                app_install::Rollback::Restored(restored) => {
                    self.owner = Some(Owner::Running(restored.release()));
                    self.mode = Mode::Running;
                    self.retry = [Instant::now(); 2];
                    self.backend_retry = Instant::now();
                    self.tick();
                    Code::Ok
                }
                app_install::Rollback::Retained(session) => {
                    self.install = Some(Install {
                        owner: InstallOwner::Draining(session),
                        stage,
                    });
                    Code::Busy
                }
            },
            owner @ InstallOwner::Refused { .. } => {
                self.install = Some(Install { owner, stage });
                Code::Uncertain
            }
        }
    }
    fn request(&mut self, key: u64, op: Operation) -> Reply {
        self.tick();
        let mut code = Code::Ok;
        match op {
            Operation::Observe => {}
            Operation::CancelAppInstall => code = self.cancel_install(),
            Operation::BackendRunning => {
                if self.backend_restart.is_some() || self.backend_status != Some(Status::Running) {
                    code = Code::Unavailable;
                }
            }
            Operation::EnsureBackend => {
                if self.mode != Mode::Running || self.backend_restart.is_some() {
                    code = Code::Busy;
                } else {
                    self.backend_wanted = true;
                    self.backend_retry = Instant::now();
                    self.tick();
                }
            }
            Operation::RestartBackend | Operation::RestartBackendSafe => {
                if self.mode != Mode::Running || self.backend_restart.is_some() {
                    code = Code::Busy;
                } else if let Some(Owner::Running(broker)) = self.owner.as_mut() {
                    match broker.runtime_permit() {
                        Ok(admission) => {
                            if broker.stop_backend(&admission).is_err() {
                                self.mode = Mode::Uncertain;
                                return self.reply(Code::Uncertain);
                            }
                            self.backend_wanted = true;
                            self.backend_restart = Some(BackendRestart {
                                _admission: admission,
                                safe_mode: op == Operation::RestartBackendSafe,
                            });
                            self.tick();
                        }
                        Err(super::JournalError::Busy) => code = Code::Busy,
                        Err(_) => code = Code::Unavailable,
                    }
                } else {
                    code = Code::Busy;
                }
            }
            Operation::EnsureKvm | Operation::EnsureHwmon => {
                if self.mode != Mode::Running {
                    code = Code::Busy;
                } else {
                    let index = usize::from(op == Operation::EnsureHwmon);
                    self.wanted[index] = true;
                    self.retry[index] = Instant::now();
                    self.tick();
                    if self.mode == Mode::Uncertain {
                        code = Code::Uncertain;
                    } else if self.roles[index] == 0 {
                        code = Code::Unavailable;
                    }
                }
            }
            Operation::Pause => {
                if self.backend_restart.is_some() {
                    code = Code::Busy;
                } else if self.lease == Some(key) && !self.abandoned {
                } else {
                    match self.owner.take() {
                        Some(Owner::Running(broker)) => {
                            self.owner = Some(Owner::Paused(broker.begin_maintenance()));
                            self.lease = Some(key);
                            self.tick();
                        }
                        other => {
                            self.owner = other;
                            code = Code::Busy;
                        }
                    }
                }
            }
            Operation::Resume => {
                if self.lease != Some(key) || self.abandoned {
                    code = Code::Busy;
                } else {
                    match self.owner.take() {
                        Some(Owner::Paused(drain)) => match drain.resume() {
                            Resume::Running(broker) => {
                                self.owner = Some(Owner::Running(broker));
                                self.lease = None;
                                self.mode = Mode::Running;
                                self.tick();
                            }
                            Resume::Retained(drain) => {
                                self.owner = Some(Owner::Paused(drain));
                                code = Code::Busy;
                                self.tick();
                            }
                        },
                        other => {
                            self.owner = other;
                            code = Code::Busy;
                        }
                    }
                }
            }
            Operation::Shutdown => {
                if self.lease.is_some() || self.abandoned || self.backend_restart.is_some() {
                    code = Code::Busy;
                } else {
                    match self.owner.take() {
                        Some(Owner::Running(broker)) => match broker.runtime_permit() {
                            Ok(admission) => {
                                self.wanted = [false; 2];
                                self.backend_wanted = false;
                                match broker.shutdown(admission) {
                                    Shutdown::Draining(drain) => {
                                        self.owner = Some(Owner::Stopping(drain));
                                        self.tick();
                                    }
                                    Shutdown::Retained(broker) => {
                                        self.owner = Some(Owner::Running(broker));
                                        self.mode = Mode::Uncertain;
                                    }
                                }
                            }
                            Err(error) => {
                                code = if matches!(error, super::JournalError::Busy) {
                                    Code::Busy
                                } else {
                                    Code::Unavailable
                                };
                                self.owner = Some(Owner::Running(broker));
                            }
                        },
                        other => {
                            self.owner = other;
                            code = Code::Busy;
                        }
                    }
                }
            }
        }
        if self.mode == Mode::Uncertain {
            code = Code::Uncertain;
        }
        #[cfg(test)]
        {
            self.fixture_request_completed = Some(Instant::now());
        }
        self.reply(code)
    }
    fn disconnected(&mut self, key: u64) {
        if self.lease == Some(key) {
            self.lease = None;
            self.abandoned = true;
            self.tick();
        }
    }
}

struct Client {
    stream: UnixStream,
    key: u64,
    input: [u8; FRAME],
    read: usize,
    output: [u8; FRAME],
    sent: usize,
    writing: bool,
    last: Option<([u8; FRAME], [u8; FRAME])>,
    last_activity: Instant,
    stopped_reply: bool,
}
impl Client {
    fn new(stream: UnixStream, key: u64, uid: u32) -> io::Result<Self> {
        if rustix::net::sockopt::socket_peercred(&stream)?.uid.as_raw() != uid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            key,
            input: [0; FRAME],
            read: 0,
            output: [0; FRAME],
            sent: 0,
            writing: false,
            last: None,
            last_activity: Instant::now(),
            stopped_reply: false,
        })
    }
    fn tick(&mut self, engine: &mut Engine) -> io::Result<bool> {
        if self.writing {
            match self.stream.write(&self.output[self.sent..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.sent += n;
                    self.last_activity = Instant::now();
                }
                Err(e) if pending(&e) => {}
                Err(e) => return Err(e),
            }
            if self.sent == FRAME {
                self.writing = false;
                return Ok(self.stopped_reply);
            }
            return Ok(false);
        }
        match self.stream.read(&mut self.input[self.read..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                self.read += n;
                self.last_activity = Instant::now();
            }
            Err(e) if pending(&e) => return Ok(false),
            Err(e) => return Err(e),
        }
        if self.read < FRAME {
            return Ok(false);
        }
        let (op, serial) = parse_request(&self.input).ok_or(io::ErrorKind::InvalidData)?;
        let output = if let Some((prior, reply)) = self.last {
            let (_, old) = parse_request(&prior).ok_or(io::ErrorKind::InvalidData)?;
            if serial == old && prior == self.input {
                reply
            } else if old.checked_add(1) == Some(serial) {
                engine.request(self.key, op).bytes(serial)
            } else {
                return Err(io::ErrorKind::InvalidData.into());
            }
        } else if serial == 1 {
            engine.request(self.key, op).bytes(serial)
        } else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        self.stopped_reply = output[5] == Mode::Stopped as u8;
        self.last = Some((self.input, output));
        self.output = output;
        self.sent = 0;
        self.writing = true;
        self.read = 0;
        // Spawn/journal work is not a stalled receiver. Start the pending
        // reply's transport budget only after that work has produced a reply.
        self.last_activity = Instant::now();
        Ok(false)
    }
}

struct Server {
    // Drop the endpoint before releasing the journal owner/lease.
    endpoint: journal::socket::Endpoint,
    install_endpoint: journal::socket::Endpoint,
    // Close queued rights before dropping accepted engine ownership/admission.
    offers: [Option<(app_install_lease::Incoming, Instant)>; INSTALL_OFFERS],
    engine: Engine,
    clients: [Option<Client>; CLIENTS],
    next_key: u64,
    uid: u32,
    idle: Duration,
    #[cfg(test)]
    cancel: Option<std::sync::mpsc::Receiver<()>>,
}
impl Server {
    fn new(broker: Broker, uid: u32) -> io::Result<Self> {
        Ok(Self {
            endpoint: broker.journal.endpoint()?,
            install_endpoint: broker.journal.install_endpoint()?,
            offers: std::array::from_fn(|_| None),
            engine: Engine::new(broker),
            clients: std::array::from_fn(|_| None),
            next_key: 1,
            uid,
            idle: IDLE,
            #[cfg(test)]
            cancel: None,
        })
    }
    fn run(mut self) -> io::Result<()> {
        loop {
            #[cfg(test)]
            if self
                .cancel
                .as_ref()
                .is_some_and(|r| !matches!(r.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)))
            {
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.engine.tick();
            for slot in &mut self.offers {
                #[cfg(test)]
                if self
                    .engine
                    .fixture
                    .as_ref()
                    .is_some_and(|root| root.join("hold-install-offer").exists())
                {
                    continue;
                }
                let Some((offer, since)) = slot.as_mut() else {
                    continue;
                };
                match offer.poll() {
                    Ok(Some(admission)) => {
                        // Ownership moves to the independent daemon before any
                        // backend Stop. Peer EOF no longer controls this job.
                        self.engine.accept_install(admission);
                        *slot = None;
                    }
                    Ok(None) if since.elapsed() < self.idle => {}
                    _ => *slot = None,
                }
            }
            for slot in &mut self.clients {
                let Some(client) = slot.as_mut() else {
                    continue;
                };
                match client.tick(&mut self.engine) {
                    Ok(true) => return Ok(()),
                    Err(_) => {
                        self.engine.disconnected(client.key);
                        *slot = None;
                    }
                    Ok(false) => {
                        if self.engine.lease != Some(client.key)
                            && client.last_activity.elapsed() >= self.idle
                        {
                            self.engine.disconnected(client.key);
                            *slot = None;
                        }
                    }
                }
            }
            // A stopped caller can disappear; retain completion/lease briefly
            // for a final observed reply, never wait forever solely for an ack.
            if self
                .engine
                .stopped_at
                .is_some_and(|at| at.elapsed() >= RETRY)
            {
                return Ok(());
            }
            for _ in 0..CLIENTS {
                let Some(slot) = self.clients.iter_mut().find(|s| s.is_none()) else {
                    break;
                };
                let fd = match rustix::net::accept_with(
                    &self.endpoint.listener,
                    rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
                ) {
                    Ok(fd) => fd,
                    Err(e) if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::INTR => {
                        break;
                    }
                    Err(e) => return Err(e.into()),
                };
                let key = self.next_key;
                self.next_key = self.next_key.checked_add(1).ok_or(io::ErrorKind::Other)?;
                *slot = Client::new(UnixStream::from(fd), key, self.uid).ok();
            }
            for _ in 0..INSTALL_OFFERS {
                let Some(slot) = self.offers.iter_mut().find(|s| s.is_none()) else {
                    break;
                };
                let fd = match rustix::net::accept_with(
                    &self.install_endpoint.listener,
                    rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
                ) {
                    Ok(fd) => fd,
                    Err(e) if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::INTR => {
                        break;
                    }
                    Err(e) => return Err(e.into()),
                };
                if rustix::net::sockopt::socket_peercred(&fd)?.uid.as_raw() != self.uid {
                    continue;
                }
                #[cfg(test)]
                let offer = match &self.engine.fixture {
                    Some(root) => app_install_lease::Incoming::fixture(
                        fd,
                        std::fs::File::open(root)?,
                        self.uid,
                    ),
                    None => app_install_lease::Incoming::open(fd),
                };
                #[cfg(not(test))]
                let offer = app_install_lease::Incoming::open(fd);
                *slot = offer.ok().map(|offer| (offer, Instant::now()));
            }
            // Every client is nonblocking and gets one bounded read/write tick.
            // Avoid a permanently readable listener spinning when all slots fill.
            let mut none = [];
            let timeout = rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: STEP.as_nanos() as _,
            };
            if !matches!(
                rustix::event::poll(&mut none, Some(&timeout)),
                Ok(_) | Err(rustix::io::Errno::INTR)
            ) {
                return Err(io::ErrorKind::Other.into());
            }
        }
    }
}

pub fn run_daemon() -> io::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut count = 0;
    for entry in std::fs::read_dir("/proc/self/task")? {
        entry?;
        count += 1;
        if count > 1 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    if count != 1 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let broker = Broker::acquire().map_err(|_| io::ErrorKind::PermissionDenied)?;
    Server::new(broker, 0)?.run()
}

#[cfg(test)]
#[path = "ipc_tests.rs"]
mod tests;
