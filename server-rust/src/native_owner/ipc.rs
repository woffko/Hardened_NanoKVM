//! Root-only, fixed-frame native lifecycle transport. No raw-write authority.
use super::{
    Broker, Resume, RetainedDrain, RuntimePermit, Shutdown, StartFailure, app_install, journal,
};
use crate::native_owner::controller::{Completion, DrainStatus, Role, StartError, Status};
use crate::native_owner::picoclaw_home::Home;
use crate::update::{app_install_lease, app_slot};
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

const FRAME: usize = 48;
const CLIENTS: usize = 16;
const STEP: Duration = Duration::from_millis(20);
const IDLE: Duration = Duration::from_secs(5);
const RETRY: Duration = Duration::from_secs(2);
const INSTALL_OFFERS: usize = 4;

#[path = "ipc_picoclaw.rs"]
mod picoclaw;
#[path = "ipc_picoclaw_job.rs"]
pub mod picoclaw_job;
pub use picoclaw_job::{
    JobChannel, JobCode, JobKind, JobReply, JobRequest, run_model_job, run_remove_job,
    run_startup_job,
};

#[cfg(test)]
#[path = "ipc_test_diagnostics.rs"]
mod test_diagnostics;

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
    RetryAppRetirement = 12,
    CheckPicoclawHome = 13,
    EnsurePicoclaw = 14,
    PicoclawRunning = 15,
    StopPicoclaw = 16,
    PicoclawStopped = 17,
    OnboardPicoclaw = 18,
    PicoclawOnboardComplete = 19,
}
impl Operation {
    fn binds_picoclaw_home(self) -> bool {
        matches!(
            self,
            Self::CheckPicoclawHome
                | Self::EnsurePicoclaw
                | Self::PicoclawRunning
                | Self::StopPicoclaw
                | Self::PicoclawStopped
                | Self::OnboardPicoclaw
                | Self::PicoclawOnboardComplete
        )
    }

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
            12 => Some(Self::RetryAppRetirement),
            13 => Some(Self::CheckPicoclawHome),
            14 => Some(Self::EnsurePicoclaw),
            15 => Some(Self::PicoclawRunning),
            16 => Some(Self::StopPicoclaw),
            17 => Some(Self::PicoclawStopped),
            18 => Some(Self::OnboardPicoclaw),
            19 => Some(Self::PicoclawOnboardComplete),
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
    bytes[..4].copy_from_slice(b"NKC2");
    bytes[4] = op as u8;
    bytes[8..16].copy_from_slice(&serial.to_be_bytes());
    bytes
}
fn parse_request(bytes: &[u8; FRAME]) -> Option<(Operation, u64)> {
    if &bytes[..4] != b"NKC2" || bytes[5..8] != [0; 3] {
        return None;
    }
    let operation = Operation::decode(bytes[4])?;
    if !operation.binds_picoclaw_home() && bytes[16..] != [0; 32] {
        return None;
    }
    Some((operation, u64::from_be_bytes(bytes[8..16].try_into().ok()?)))
}
impl Reply {
    fn bytes(self, serial: u64) -> [u8; FRAME] {
        let mut bytes = [0; FRAME];
        bytes[..4].copy_from_slice(b"NKR2");
        bytes[4] = self.code as u8;
        bytes[5] = self.mode as u8;
        bytes[6..8].copy_from_slice(&self.roles);
        bytes[8..16].copy_from_slice(&serial.to_be_bytes());
        bytes
    }
    fn parse(bytes: &[u8; FRAME], serial: u64) -> io::Result<Self> {
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        if &bytes[..4] != b"NKR2"
            || bytes[8..16] != serial.to_be_bytes()
            || bytes[16..] != [0; 32]
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
        if op.binds_picoclaw_home() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.begin_frame(op, None)
    }

    /// Compare the caller's selection with this live broker, without submitting
    /// a pathname, launching a service or changing its selected configuration.
    pub fn check_picoclaw_home(&mut self, home: &Home) -> io::Result<()> {
        self.begin_frame(Operation::CheckPicoclawHome, Some(home.fingerprint()))
    }

    /// Fixed owned-scope service requests, each bound to this caller's home.
    /// A successful Stop reply is admission only; query Stopped for join proof.
    pub fn picoclaw_service(&mut self, op: Operation, home: &Home) -> io::Result<()> {
        if !matches!(
            op,
            Operation::EnsurePicoclaw
                | Operation::PicoclawRunning
                | Operation::StopPicoclaw
                | Operation::PicoclawStopped
                | Operation::OnboardPicoclaw
                | Operation::PicoclawOnboardComplete
        ) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.begin_frame(op, Some(home.fingerprint()))
    }

    fn begin_frame(&mut self, op: Operation, home: Option<[u8; 32]>) -> io::Result<()> {
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
        let mut bytes = request(op, serial);
        if let Some(home) = home {
            bytes[16..].copy_from_slice(&home);
        }
        self.flight = Some(Flight {
            bytes,
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
                let reply = Reply::parse(&f.reply, f.serial)?;
                if Operation::decode(f.bytes[4]).is_some_and(Operation::binds_picoclaw_home)
                    && reply.code == Code::Ok
                    && reply.mode != Mode::Running
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Ok(Some(reply))
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
    /// A broker-owned Pico job holds the SAME broker until its durable end.
    PicoJob(picoclaw_job::Job),
}

enum InstallOwner {
    Draining(app_install::Session),
    PreparingInstall {
        owner: app_install::PreparingInstall,
        cancel_requested: bool,
    },
    Trial(app_install::TrialSession),
    Committing(app_install::CommittingTrial),
    RollingBack(app_install::RollingBack),
    Committed(app_install::Retirement),
    RolledBack(app_install::Retirement),
    Refused {
        broker: Broker,
        _install: app_slot::AcceptedInstall,
    },
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum InstallStage {
    Draining,
    PreparingSupport,
    SupportReady,
    Publishing,
    Published,
    Trial,
    CommitPending,
    Rollback,
    Retiring,
    Failed,
}
struct Install {
    owner: InstallOwner,
    stage: InstallStage,
}
struct Engine {
    home: [u8; 32],
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
    picoclaw_status: Option<Status>,
    // Retained until receipt + owner reap + EOF, even if the caller disconnects.
    picoclaw_stop: Option<crate::update::operation_lock::ProcessLock>,
    picoclaw_onboard: Option<picoclaw::Onboard>,
    picoclaw_onboard_result: Option<bool>,
    /// The last job's identity and final status, for its submitter.
    pico_job_last: Option<(super::PicoJobId, super::PicoMutationStatus)>,
    #[cfg(all(test, feature = "sandbox-test-fixture"))]
    fixture_pico_image: Option<std::path::PathBuf>,
    #[cfg(test)]
    fixture: Option<std::path::PathBuf>,
    #[cfg(test)]
    fixture_request_completed: Option<Instant>,
    #[cfg(test)]
    fixture_hold_published: bool,
    #[cfg(test)]
    fixture_trace_starts: bool,
    #[cfg(test)]
    fixture_allow_unsupported_support: bool,
    #[cfg(test)]
    fixture_retirement: Option<app_install::InstallIoFixture>,
    #[cfg(test)]
    fixture_support: Option<app_install::InstallIoFixture>,
    #[cfg(test)]
    fixture_publication: Option<app_install::InstallIoFixture>,
    #[cfg(test)]
    fixture_commit: Option<app_install::InstallIoFixture>,
    #[cfg(test)]
    fixture_rollback: Option<app_install::InstallIoFixture>,
}
struct BackendRestart {
    _admission: RuntimePermit,
    safe_mode: bool,
}
impl Drop for Engine {
    fn drop(&mut self) {
        // Join filesystem work before implicit field teardown can release the
        // running broker/singleton. Its payload and admissions remain owned.
        if let Some(onboard) = self.picoclaw_onboard.as_mut() {
            onboard.work.join_for_teardown();
        }
    }
}
impl Engine {
    fn new(broker: Broker) -> Self {
        Self {
            home: broker.group.home.fingerprint(),
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
            picoclaw_status: None,
            picoclaw_stop: None,
            picoclaw_onboard: None,
            picoclaw_onboard_result: None,
            pico_job_last: None,
            #[cfg(all(test, feature = "sandbox-test-fixture"))]
            fixture_pico_image: None,
            #[cfg(test)]
            fixture: None,
            #[cfg(test)]
            fixture_request_completed: None,
            #[cfg(test)]
            fixture_hold_published: false,
            #[cfg(test)]
            fixture_trace_starts: false,
            #[cfg(test)]
            fixture_allow_unsupported_support: false,
            #[cfg(test)]
            fixture_retirement: None,
            #[cfg(test)]
            fixture_support: None,
            #[cfg(test)]
            fixture_publication: None,
            #[cfg(test)]
            fixture_commit: None,
            #[cfg(test)]
            fixture_rollback: None,
        }
    }
    fn command(&self, broker: &Broker, role: Role) -> std::process::Command {
        #[cfg(test)]
        if let Some(root) = &self.fixture {
            return tests::owner_command(root, role);
        }
        role.command(&broker.group.home)
    }
    fn tick(&mut self) {
        if let Some(install) = self.install.take() {
            self.install = self.tick_install(install);
            return;
        }
        let Some(owner) = self.owner.take() else {
            self.mode = Mode::Uncertain;
            return;
        };
        self.owner = Some(match owner {
            Owner::Running(mut broker) => {
                self.tick_picoclaw(&mut broker);
                self.supervise(&mut broker);
                self.tick_picoclaw(&mut broker);
                Owner::Running(broker)
            }
            Owner::PicoJob(mut job) => {
                // The job owns the Pico cell; every other cell keeps its
                // ordinary supervision on the SAME broker meanwhile.
                job.supervise_cells(|broker| self.supervise(broker));
                self.tick_pico_job(job)
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

    // KVM, hwmon and backend supervision; never the Pico cell.
    fn supervise(&mut self, broker: &mut Broker) {
        self.backend_status = broker.backend_status();
        let states = broker.poll();
        self.roles = states.map(role_status);
        if broker.group.uncertainty_latched() {
            self.mode = Mode::Uncertain;
        }
        if self.mode == Mode::Running {
            for (index, role) in [Role::KvmSystem, Role::Hwmon].into_iter().enumerate() {
                if self.wanted[index]
                    && Instant::now() >= self.retry[index]
                    && matches!(states[index], None | Some(Status::Closed(_)))
                {
                    self.retry[index] = Instant::now() + RETRY;
                    let command = self.command(broker, role);
                    #[cfg(test)]
                    let started_at = Instant::now();
                    let result = broker.start_owned(role, command);
                    #[cfg(test)]
                    if self.fixture_trace_starts {
                        eprintln!(
                            "fixture-native-start: role={role:?}, prior={:?}, result={result:?}, elapsed={:?}",
                            states[index],
                            started_at.elapsed()
                        );
                    }
                    if matches!(
                        result,
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
                    let command = self.command(broker, Role::Backend);
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
                        let command = self.command(broker, Role::Backend);
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
        if broker.group.uncertainty_latched() {
            self.mode = Mode::Uncertain;
        }
    }

    fn finish_install(&mut self, broker: Broker) {
        self.owner = Some(Owner::Running(broker));
        self.mode = Mode::Running;
        self.retry = [Instant::now(); 2];
        self.backend_retry = Instant::now();
    }

    fn begin_retirement(
        &mut self,
        retirement: app_install::Retirement,
        committed: bool,
    ) -> Install {
        #[cfg(test)]
        let retirement = {
            let mut retirement = retirement;
            if let Some(fixture) = self.fixture_retirement.take() {
                retirement.set_fixture(fixture);
            }
            retirement
        };
        Install {
            owner: if committed {
                InstallOwner::Committed(retirement)
            } else {
                InstallOwner::RolledBack(retirement)
            },
            stage: InstallStage::Retiring,
        }
    }

    fn tick_retirement(
        &mut self,
        mut retirement: app_install::Retirement,
        committed: bool,
        mut stage: InstallStage,
    ) -> Option<Install> {
        let (roles, backend) = retirement.observe();
        self.roles = roles.map(role_status);
        self.backend_status = backend;
        let retirement = if stage == InstallStage::Retiring {
            match retirement.poll() {
                app_install::RetirementPoll::Pending(retirement) => retirement,
                app_install::RetirementPoll::Failed(retirement) => {
                    stage = InstallStage::Failed;
                    retirement
                }
                app_install::RetirementPoll::Released(broker) => {
                    if committed {
                        self.backend_wanted = true;
                    }
                    self.finish_install(*broker);
                    return None;
                }
            }
        } else {
            // Observation, reconnect and path repair never restart failed I/O.
            stage = InstallStage::Failed;
            retirement
        };
        self.mode = if stage == InstallStage::Retiring {
            Mode::Installing
        } else {
            Mode::Uncertain
        };
        Some(Install {
            owner: if committed {
                InstallOwner::Committed(retirement)
            } else {
                InstallOwner::RolledBack(retirement)
            },
            stage,
        })
    }

    fn tick_install(&mut self, install: Install) -> Option<Install> {
        let Install { owner, mut stage } = install;
        self.mode = Mode::Installing;
        let owner = match owner {
            InstallOwner::Draining(mut session) => {
                match session.poll() {
                    Ok(DrainStatus::Drained) => {
                        self.roles = [4; 2];
                        self.backend_status = Some(Status::Closed(Completion::Stopped));
                        match stage {
                            InstallStage::Draining => {
                                // Keep a cancellation/observation boundary after
                                // all three scopes join, before support writes.
                                stage = InstallStage::PreparingSupport;
                            }
                            InstallStage::PreparingSupport => {
                                #[cfg(test)]
                                let started = if self.fixture_allow_unsupported_support {
                                    session.start_support_fixture()
                                } else {
                                    session.start_support()
                                };
                                #[cfg(not(test))]
                                let started = session.start_support();
                                return Some(match started {
                                    app_install::BeginPreparation::Started(owner) => {
                                        #[cfg(test)]
                                        let owner = {
                                            let mut owner = owner;
                                            if let Some(fixture) = self.fixture_support.take() {
                                                owner.set_fixture(fixture);
                                            }
                                            owner
                                        };
                                        Install {
                                            owner: InstallOwner::PreparingInstall {
                                                owner,
                                                cancel_requested: false,
                                            },
                                            stage: InstallStage::PreparingSupport,
                                        }
                                    }
                                    app_install::BeginPreparation::Retained(session) => {
                                        self.mode = Mode::Uncertain;
                                        Install {
                                            owner: InstallOwner::Draining(session),
                                            stage: InstallStage::Failed,
                                        }
                                    }
                                });
                            }
                            InstallStage::SupportReady => {
                                // The same closed Session owns exactly one
                                // asynchronous publication, never a callback or
                                // caller-selected phase. Supervision stays here.
                                return Some(match session.start_publication() {
                                    app_install::BeginPreparation::Started(owner) => {
                                        #[cfg(test)]
                                        let owner = {
                                            let mut owner = owner;
                                            if let Some(fixture) = self.fixture_publication.take() {
                                                owner.set_fixture(fixture);
                                            }
                                            owner
                                        };
                                        Install {
                                            owner: InstallOwner::PreparingInstall {
                                                owner,
                                                cancel_requested: false,
                                            },
                                            stage: InstallStage::Publishing,
                                        }
                                    }
                                    app_install::BeginPreparation::Retained(session) => {
                                        self.mode = Mode::Uncertain;
                                        Install {
                                            owner: InstallOwner::Draining(session),
                                            stage: InstallStage::Failed,
                                        }
                                    }
                                });
                            }
                            InstallStage::Published => {
                                // The fixed-root delivery-only fixture has no
                                // executable/native runtime inside its chroot.
                                #[cfg(test)]
                                if self.fixture_hold_published {
                                    return Some(Install {
                                        owner: InstallOwner::Draining(session),
                                        stage,
                                    });
                                }
                                #[cfg(test)]
                                let trial = match &self.fixture {
                                    Some(root) => session
                                        .start_trial_command(tests::trial_owner_command(root)),
                                    None => session.start_trial(),
                                };
                                #[cfg(not(test))]
                                let trial = session.start_trial();
                                return Some(match trial {
                                    app_install::BeginTrial::Started(trial) => Install {
                                        owner: InstallOwner::Trial(trial),
                                        stage: InstallStage::Trial,
                                    },
                                    app_install::BeginTrial::Retained(session) => {
                                        self.mode = Mode::Uncertain;
                                        Install {
                                            owner: InstallOwner::Draining(session),
                                            stage: InstallStage::Failed,
                                        }
                                    }
                                });
                            }
                            InstallStage::Rollback => {
                                return Some(match session.start_rollback() {
                                    Ok(owner) => {
                                        #[cfg(test)]
                                        let owner = {
                                            let mut owner = owner;
                                            if let Some(fixture) = self.fixture_rollback.take() {
                                                owner.set_fixture(fixture);
                                            }
                                            owner
                                        };
                                        Install {
                                            owner: InstallOwner::RollingBack(owner),
                                            stage: InstallStage::Rollback,
                                        }
                                    }
                                    Err(session) => {
                                        self.mode = Mode::Uncertain;
                                        Install {
                                            owner: InstallOwner::Draining(*session),
                                            stage: InstallStage::Failed,
                                        }
                                    }
                                });
                            }
                            InstallStage::Failed => {}
                            _ => stage = InstallStage::Failed,
                        }
                    }
                    Ok(DrainStatus::Pending) => {
                        self.roles = [3; 2];
                        self.backend_status = Some(Status::Stopping);
                    }
                    _ => {
                        self.roles = [6; 2];
                        self.backend_status = Some(Status::Uncertain);
                        stage = InstallStage::Failed;
                    }
                }
                InstallOwner::Draining(session)
            }
            InstallOwner::PreparingInstall {
                owner,
                cancel_requested,
            } => {
                self.roles = [4; 2];
                self.backend_status = Some(Status::Closed(Completion::Stopped));
                match owner.poll() {
                    app_install::PreparationPoll::Pending { owner, uncertain } => {
                        if uncertain {
                            self.roles = [6; 2];
                            self.backend_status = Some(Status::Uncertain);
                            stage = InstallStage::Failed;
                        }
                        InstallOwner::PreparingInstall {
                            owner,
                            cancel_requested,
                        }
                    }
                    app_install::PreparationPoll::Ready { session, kind } => {
                        stage = if cancel_requested {
                            InstallStage::Rollback
                        } else {
                            match kind {
                                app_install::PreparationKind::Support => InstallStage::SupportReady,
                                app_install::PreparationKind::Publication => {
                                    InstallStage::Published
                                }
                            }
                        };
                        InstallOwner::Draining(session)
                    }
                    app_install::PreparationPoll::Failed { session, uncertain } => {
                        if uncertain {
                            self.roles = [6; 2];
                            self.backend_status = Some(Status::Uncertain);
                        }
                        stage = if cancel_requested && !uncertain {
                            InstallStage::Rollback
                        } else {
                            InstallStage::Failed
                        };
                        InstallOwner::Draining(session)
                    }
                    app_install::PreparationPoll::Retained(owner) => {
                        stage = InstallStage::Failed;
                        InstallOwner::PreparingInstall {
                            owner,
                            cancel_requested,
                        }
                    }
                }
            }
            InstallOwner::Trial(mut trial) => {
                let status = trial.poll();
                self.roles = if status == app_install::TrialStatus::Uncertain {
                    [6; 2]
                } else {
                    [4; 2]
                };
                self.backend_status = Some(match status {
                    app_install::TrialStatus::Starting => Status::Starting,
                    app_install::TrialStatus::Ready => Status::Running,
                    app_install::TrialStatus::Failed => Status::TrialFailed,
                    app_install::TrialStatus::Uncertain => Status::Uncertain,
                });
                if stage == InstallStage::Failed {
                    // A failed/ambiguous commit is not retried by observation.
                    InstallOwner::Trial(trial)
                } else {
                    match status {
                        app_install::TrialStatus::Starting => InstallOwner::Trial(trial),
                        app_install::TrialStatus::Ready => match trial.start_commit() {
                            app_install::BeginCommit::Started(owner) => {
                                #[cfg(test)]
                                let owner = {
                                    let mut owner = owner;
                                    if let Some(fixture) = self.fixture_commit.take() {
                                        owner.set_fixture(fixture);
                                    }
                                    owner
                                };
                                stage = InstallStage::CommitPending;
                                InstallOwner::Committing(owner)
                            }
                            app_install::BeginCommit::Committed(committed) => {
                                return Some(
                                    self.begin_retirement(committed.begin_retirement(), true),
                                );
                            }
                            app_install::BeginCommit::Pending(trial) => {
                                stage = InstallStage::CommitPending;
                                InstallOwner::Trial(trial)
                            }
                            app_install::BeginCommit::Retained(trial) => {
                                stage = InstallStage::Failed;
                                InstallOwner::Trial(trial)
                            }
                        },
                        app_install::TrialStatus::Failed | app_install::TrialStatus::Uncertain
                            if stage == InstallStage::CommitPending =>
                        {
                            // Commit I/O/ack has been admitted. A lost trial
                            // cannot authorize Stop->rollback of possibly
                            // Committed state, even before its acknowledgement.
                            stage = InstallStage::Failed;
                            InstallOwner::Trial(trial)
                        }
                        app_install::TrialStatus::Failed | app_install::TrialStatus::Uncertain => {
                            match trial.stop() {
                                app_install::StopTrial::Draining(session) => {
                                    stage = InstallStage::Rollback;
                                    InstallOwner::Draining(session)
                                }
                                app_install::StopTrial::Retained(trial) => {
                                    stage = InstallStage::Failed;
                                    InstallOwner::Trial(trial)
                                }
                            }
                        }
                    }
                }
            }
            InstallOwner::Committing(owner) => {
                self.roles = [4; 2];
                self.backend_status = Some(Status::Running);
                match owner.poll() {
                    app_install::CommitPoll::Pending { owner, uncertain } => {
                        if uncertain {
                            stage = InstallStage::Failed;
                            self.roles = [6; 2];
                            self.backend_status = Some(Status::Uncertain);
                        }
                        InstallOwner::Committing(owner)
                    }
                    app_install::CommitPoll::Failed(owner) => {
                        stage = InstallStage::Failed;
                        self.roles = [6; 2];
                        self.backend_status = Some(Status::Uncertain);
                        InstallOwner::Committing(owner)
                    }
                    app_install::CommitPoll::Ready(trial) => {
                        stage = InstallStage::CommitPending;
                        InstallOwner::Trial(*trial)
                    }
                }
            }
            InstallOwner::Committed(committed) => {
                return self.tick_retirement(committed, true, stage);
            }
            InstallOwner::RollingBack(owner) => {
                self.roles = [4; 2];
                self.backend_status = Some(Status::Closed(Completion::Stopped));
                match owner.poll() {
                    app_install::RollbackPoll::Pending { owner, uncertain } => {
                        if uncertain {
                            stage = InstallStage::Failed;
                            self.roles = [6; 2];
                            self.backend_status = Some(Status::Uncertain);
                        }
                        InstallOwner::RollingBack(owner)
                    }
                    app_install::RollbackPoll::Failed(owner) => {
                        stage = InstallStage::Failed;
                        self.roles = [6; 2];
                        self.backend_status = Some(Status::Uncertain);
                        InstallOwner::RollingBack(owner)
                    }
                    app_install::RollbackPoll::Ready(rollback) => match *rollback {
                        app_install::Rollback::Restored(restored) => {
                            return Some(self.begin_retirement(restored.begin_retirement(), false));
                        }
                        app_install::Rollback::Retained(session) => {
                            stage = InstallStage::Failed;
                            self.roles = [6; 2];
                            self.backend_status = Some(Status::Uncertain);
                            InstallOwner::Draining(session)
                        }
                    },
                }
            }
            InstallOwner::RolledBack(restored) => {
                return self.tick_retirement(restored, false, stage);
            }
            InstallOwner::Refused {
                mut broker,
                _install,
            } => {
                // Journal failure cannot discard live scopes or admission.
                self.roles = broker.poll().map(role_status);
                self.backend_status = broker.backend_status();
                stage = InstallStage::Failed;
                InstallOwner::Refused { broker, _install }
            }
        };
        if stage == InstallStage::Failed {
            self.mode = Mode::Uncertain;
        }
        Some(Install { owner, stage })
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
            || self.picoclaw_stop.is_some()
            || self.picoclaw_onboard.is_some()
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
        #[cfg(test)]
        if self.fixture.is_some() || self.fixture_hold_published {
            // Synthetic payload only; production never rewrites accepted roots.
            // Positive engine fixtures bypass ONLY epoch0 below, not staging,
            // source/live validation, retained ownership or recovery ordering.
            app_slot::support::populate_retained_fixture(&install);
        }
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
            InstallOwner::PreparingInstall { owner, .. } => {
                // A cancel request owns the eventual rollback, never a second
                // concurrent filesystem operation. Join first, recheck closure.
                self.install = Some(Install {
                    owner: InstallOwner::PreparingInstall {
                        owner,
                        cancel_requested: true,
                    },
                    stage,
                });
                if stage == InstallStage::Failed {
                    Code::Uncertain
                } else {
                    Code::Ok
                }
            }
            InstallOwner::Draining(session) => {
                self.install = Some(Install {
                    owner: InstallOwner::Draining(session),
                    stage: InstallStage::Rollback,
                });
                self.tick();
                if self.mode == Mode::Uncertain {
                    Code::Uncertain
                } else {
                    Code::Ok
                }
            }
            InstallOwner::Committing(owner) => {
                self.install = Some(Install {
                    owner: InstallOwner::Committing(owner),
                    stage,
                });
                if stage == InstallStage::Failed {
                    Code::Uncertain
                } else {
                    Code::Busy
                }
            }
            InstallOwner::Trial(trial) => {
                if matches!(stage, InstallStage::CommitPending | InstallStage::Failed) {
                    self.install = Some(Install {
                        owner: InstallOwner::Trial(trial),
                        stage,
                    });
                    return if stage == InstallStage::Failed {
                        Code::Uncertain
                    } else {
                        Code::Busy
                    };
                }
                match trial.stop() {
                    app_install::StopTrial::Draining(session) => {
                        // Ok acknowledges owned cancellation, not completed
                        // rollback. Mode remains Installing until fresh join.
                        self.install = Some(Install {
                            owner: InstallOwner::Draining(session),
                            stage: InstallStage::Rollback,
                        });
                        self.mode = Mode::Installing;
                        Code::Ok
                    }
                    app_install::StopTrial::Retained(trial) => {
                        self.install = Some(Install {
                            owner: InstallOwner::Trial(trial),
                            stage: InstallStage::Failed,
                        });
                        self.mode = Mode::Uncertain;
                        Code::Uncertain
                    }
                }
            }
            owner @ (InstallOwner::Refused { .. }
            | InstallOwner::RollingBack(_)
            | InstallOwner::Committed(_)
            | InstallOwner::RolledBack(_)) => {
                self.install = Some(Install { owner, stage });
                Code::Uncertain
            }
        }
    }
    fn retry_app_retirement(&mut self) -> Code {
        let Some(mut install) = self.install.take() else {
            return Code::Busy;
        };
        // This operation addresses only the current retained live terminal
        // owner. It cannot publish, commit, cancel or recover a journal-only
        // transaction. Observe/reconnect never performs this retry implicitly.
        let code = match &mut install.owner {
            InstallOwner::Committed(retirement) | InstallOwner::RolledBack(retirement)
                if install.stage == InstallStage::Failed =>
            {
                if retirement.retry() {
                    install.stage = InstallStage::Retiring;
                    self.mode = Mode::Installing;
                    Code::Ok
                } else {
                    self.mode = Mode::Uncertain;
                    Code::Uncertain
                }
            }
            _ => Code::Busy,
        };
        self.install = Some(install);
        code
    }

    fn request(&mut self, key: u64, op: Operation) -> Reply {
        self.tick();
        let mut code = Code::Ok;
        match op {
            Operation::Observe => {}
            Operation::CheckPicoclawHome
            | Operation::EnsurePicoclaw
            | Operation::PicoclawRunning
            | Operation::StopPicoclaw
            | Operation::PicoclawStopped
            | Operation::OnboardPicoclaw
            | Operation::PicoclawOnboardComplete => code = Code::Invalid,
            Operation::CancelAppInstall => code = self.cancel_install(),
            Operation::RetryAppRetirement => code = self.retry_app_retirement(),
            Operation::BackendRunning => {
                if self.install.is_some()
                    || self.backend_restart.is_some()
                    || self.backend_status != Some(Status::Running)
                {
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
                if self.mode != Mode::Running
                    || self.backend_restart.is_some()
                    || self.picoclaw_stop.is_some()
                    || self.picoclaw_onboard.is_some()
                {
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
                if self.backend_restart.is_some()
                    || self.picoclaw_stop.is_some()
                    || self.picoclaw_onboard.is_some()
                {
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
                if self.lease.is_some()
                    || self.abandoned
                    || self.backend_restart.is_some()
                    || self.picoclaw_stop.is_some()
                    || self.picoclaw_onboard.is_some()
                {
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

    fn request_frame(&mut self, key: u64, op: Operation, bytes: &[u8; FRAME]) -> Reply {
        if !op.binds_picoclaw_home() {
            return self.request(key, op);
        }
        // Identity observation is not another lifecycle tick. Pending wanted
        // work belongs to the broker loop, not a caller's read-only query.
        if bytes[16..] != self.home {
            return self.reply(Code::Invalid);
        }
        if op != Operation::CheckPicoclawHome {
            return self.picoclaw_request(op);
        }
        self.reply(if self.mode == Mode::Uncertain {
            Code::Uncertain
        } else if self.mode != Mode::Running {
            Code::Busy
        } else {
            Code::Ok
        })
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
                engine
                    .request_frame(self.key, op, &self.input)
                    .bytes(serial)
            } else {
                return Err(io::ErrorKind::InvalidData.into());
            }
        } else if serial == 1 {
            engine
                .request_frame(self.key, op, &self.input)
                .bytes(serial)
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
    job_endpoint: journal::socket::Endpoint,
    // Close queued rights before dropping accepted engine ownership/admission.
    offers: [Option<(app_install_lease::Incoming, Instant)>; INSTALL_OFFERS],
    job_clients: [Option<picoclaw_job::JobClient>; picoclaw_job::JOB_CLIENTS],
    engine: Engine,
    clients: [Option<Client>; CLIENTS],
    next_key: u64,
    uid: u32,
    idle: Duration,
    #[cfg(test)]
    diagnostic_origin: test_diagnostics::Origin,
    #[cfg(test)]
    cancel: Option<std::sync::mpsc::Receiver<()>>,
}
impl Server {
    fn new(broker: Broker, uid: u32) -> io::Result<Self> {
        Ok(Self {
            endpoint: broker.journal.endpoint()?,
            install_endpoint: broker.journal.install_endpoint()?,
            job_endpoint: broker.journal.picoclaw_job_endpoint()?,
            offers: std::array::from_fn(|_| None),
            job_clients: std::array::from_fn(|_| None),
            engine: Engine::new(broker),
            clients: std::array::from_fn(|_| None),
            next_key: 1,
            uid,
            idle: IDLE,
            #[cfg(test)]
            diagnostic_origin: test_diagnostics::Origin::Fixture,
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
                    Err(error) => {
                        #[cfg(test)]
                        eprintln!(
                            "{}",
                            test_diagnostics::client_close(
                                self.diagnostic_origin,
                                client,
                                &self.engine,
                                self.idle,
                                Some(error.kind()),
                            )
                        );
                        #[cfg(not(test))]
                        let _ = error;
                        self.engine.disconnected(client.key);
                        *slot = None;
                    }
                    Ok(false) => {
                        if self.engine.lease != Some(client.key)
                            && client.last_activity.elapsed() >= self.idle
                        {
                            #[cfg(test)]
                            eprintln!(
                                "{}",
                                test_diagnostics::client_close(
                                    self.diagnostic_origin,
                                    client,
                                    &self.engine,
                                    self.idle,
                                    None,
                                )
                            );
                            self.engine.disconnected(client.key);
                            *slot = None;
                        }
                    }
                }
            }
            for slot in &mut self.job_clients {
                if let Some(client) = slot.as_mut()
                    && !matches!(client.tick(&mut self.engine, self.idle), Ok(true))
                {
                    *slot = None;
                }
            }
            for _ in 0..picoclaw_job::JOB_CLIENTS {
                let Some(slot) = self.job_clients.iter_mut().find(|s| s.is_none()) else {
                    break;
                };
                let fd = match rustix::net::accept_with(
                    &self.job_endpoint.listener,
                    rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
                ) {
                    Ok(fd) => fd,
                    Err(e) if e == rustix::io::Errno::AGAIN || e == rustix::io::Errno::INTR => {
                        break;
                    }
                    Err(e) => return Err(e.into()),
                };
                if rustix::net::sockopt::socket_peercred(&fd)?.uid.as_raw() == self.uid {
                    *slot = Some(picoclaw_job::JobClient::new(fd));
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
