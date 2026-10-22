//! Private fixed-frame Pico job transport on a root-only SEQPACKET endpoint:
//! one bounded request and one reply per datagram. Typed fields and result
//! codes only, never a path, command, credential or error text. The broker
//! owns each job; a client's disconnect never cancels or settles it.
use super::*;
use crate::native_owner::broker::{
    PicoCursor, PicoJobId, PicoMutation, PicoMutationAdmission, PicoMutationStatus, PicoRequest,
};
use crate::update::picoclaw_config::jobs::{self, Observed};
use rustix::net::{RecvFlags, SendFlags};
use std::os::fd::OwnedFd;

pub(super) const PACKET: usize = 64;
pub(super) const JOB_CLIENTS: usize = 4;
const REQUEST_MAGIC: &[u8; 8] = b"NKPJQ001";
const REPLY_MAGIC: &[u8; 8] = b"NKPJS001";
/// The only executor wired to this transport so far; the store's kind code.
const STARTUP: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobRequest {
    /// The next submission cursor of an idle store.
    Cursor,
    /// One Startup job for exactly this observed cursor and client nonce.
    SubmitStartup { cursor: PicoCursor, nonce: [u8; 16] },
    /// A submitted job: its cursor's epoch, the next sequence and its nonce.
    Observe(PicoJobId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum JobCode {
    /// A cursor, or a job's terminal receipt.
    Ok = 1,
    /// Accepting or in progress: observe the same job again.
    Pending = 2,
    /// Nothing was accepted: the broker is serving other work.
    Busy = 3,
    /// A stale cursor, or the receipt left the retained ring.
    Expired = 4,
    /// Acceptance refused the request; nothing was accepted.
    Rejected = 5,
    /// Malformed, never accepted, or a different job.
    Invalid = 6,
    /// The job is fenced until checked recovery.
    RecoveryRequired = 7,
    /// The store or native ownership is not ready.
    Unavailable = 8,
}

impl JobCode {
    fn decode(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Ok,
            2 => Self::Pending,
            3 => Self::Busy,
            4 => Self::Expired,
            5 => Self::Rejected,
            6 => Self::Invalid,
            7 => Self::RecoveryRequired,
            8 => Self::Unavailable,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobReply {
    pub code: JobCode,
    /// The cursor (nonce zero) or the job's identity.
    pub epoch: [u8; 16],
    pub sequence: u64,
    pub nonce: [u8; 16],
    /// Terminal receipt codes: kind, phase, outcome and runtime; else zero.
    pub receipt: [u8; 4],
}

impl JobReply {
    fn code(code: JobCode) -> Self {
        Self {
            code,
            epoch: [0; 16],
            sequence: 0,
            nonce: [0; 16],
            receipt: [0; 4],
        }
    }

    fn job(code: JobCode, id: PicoJobId) -> Self {
        Self {
            epoch: id.epoch,
            sequence: id.sequence,
            nonce: id.nonce,
            ..Self::code(code)
        }
    }
}

pub(super) fn encode_request(request: JobRequest) -> [u8; PACKET] {
    let mut bytes = [0; PACKET];
    bytes[..8].copy_from_slice(REQUEST_MAGIC);
    let (op, kind, epoch, sequence, nonce) = match request {
        JobRequest::Cursor => (1, 0, [0; 16], 0, [0; 16]),
        JobRequest::SubmitStartup { cursor, nonce } => {
            (2, STARTUP, cursor.epoch, cursor.sequence, nonce)
        }
        JobRequest::Observe(id) => (3, 0, id.epoch, id.sequence, id.nonce),
    };
    bytes[8] = op;
    bytes[9] = kind;
    bytes[16..32].copy_from_slice(&epoch);
    bytes[32..40].copy_from_slice(&sequence.to_le_bytes());
    bytes[40..56].copy_from_slice(&nonce);
    bytes
}

pub(super) fn decode_request(bytes: &[u8; PACKET]) -> Option<JobRequest> {
    if &bytes[..8] != REQUEST_MAGIC
        || bytes[10..16].iter().any(|byte| *byte != 0)
        || bytes[56..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let epoch: [u8; 16] = bytes[16..32].try_into().ok()?;
    let sequence = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
    let nonce: [u8; 16] = bytes[40..56].try_into().ok()?;
    match (bytes[8], bytes[9]) {
        (1, 0) if epoch == [0; 16] && sequence == 0 && nonce == [0; 16] => Some(JobRequest::Cursor),
        (2, STARTUP) if epoch != [0; 16] && nonce != [0; 16] && sequence < u64::MAX => {
            Some(JobRequest::SubmitStartup {
                cursor: PicoCursor { epoch, sequence },
                nonce,
            })
        }
        (3, 0) if epoch != [0; 16] && nonce != [0; 16] && sequence != 0 => {
            Some(JobRequest::Observe(PicoJobId {
                epoch,
                sequence,
                nonce,
            }))
        }
        _ => None,
    }
}

pub(super) fn encode_reply(reply: JobReply) -> [u8; PACKET] {
    let mut bytes = [0; PACKET];
    bytes[..8].copy_from_slice(REPLY_MAGIC);
    bytes[8] = reply.code as u8;
    bytes[12..16].copy_from_slice(&reply.receipt);
    bytes[16..32].copy_from_slice(&reply.epoch);
    bytes[32..40].copy_from_slice(&reply.sequence.to_le_bytes());
    bytes[40..56].copy_from_slice(&reply.nonce);
    bytes
}

pub(super) fn decode_reply(bytes: &[u8; PACKET]) -> Option<JobReply> {
    if &bytes[..8] != REPLY_MAGIC
        || bytes[9..12].iter().any(|byte| *byte != 0)
        || bytes[56..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    Some(JobReply {
        code: JobCode::decode(bytes[8])?,
        epoch: bytes[16..32].try_into().ok()?,
        sequence: u64::from_le_bytes(bytes[32..40].try_into().ok()?),
        nonce: bytes[40..56].try_into().ok()?,
        receipt: bytes[12..16].try_into().ok()?,
    })
}

/// A broker-owned job: it holds the SAME broker until nothing durable is
/// left to it. Identity is fixed at submission, before acceptance completes.
pub(super) struct Job {
    mutation: Box<PicoMutation>,
    id: PicoJobId,
    status: PicoMutationStatus,
}

impl Job {
    pub(super) fn supervise_cells(&mut self, supervise: impl FnOnce(&mut Broker)) {
        self.mutation.supervise_cells(supervise);
    }
}

// Fenced store evidence asks for checked recovery; anything else is a store
// that is not ready for jobs.
fn store_code(error: &crate::AppError) -> JobCode {
    if matches!(error, crate::AppError::Conflict(_)) {
        JobCode::RecoveryRequired
    } else {
        JobCode::Unavailable
    }
}

impl Engine {
    fn pico_job_idle(&self) -> bool {
        self.mode == Mode::Running
            && self.install.is_none()
            && self.lease.is_none()
            && !self.abandoned
            && self.backend_restart.is_none()
            && self.picoclaw_stop.is_none()
            && self.picoclaw_onboard.is_none()
    }

    /// Poll the job; once nothing durable is left to it, the SAME broker
    /// returns to ordinary operation.
    pub(super) fn tick_pico_job(&mut self, mut job: Job) -> Owner {
        job.status = job.mutation.poll();
        if matches!(
            job.status,
            PicoMutationStatus::Completed(_)
                | PicoMutationStatus::Superseded(_)
                | PicoMutationStatus::SettlementRefused(_)
                | PicoMutationStatus::Existing(_)
                | PicoMutationStatus::Expired
                | PicoMutationStatus::Rejected
        ) {
            let (id, status) = (job.id, job.status);
            match job.mutation.into_broker() {
                Ok(broker) => {
                    self.pico_job_last = Some((id, status));
                    return Owner::Running(broker);
                }
                Err(mutation) => job.mutation = mutation,
            }
        }
        Owner::PicoJob(job)
    }

    pub(super) fn pico_job_request(&mut self, request: JobRequest) -> JobReply {
        self.tick();
        match request {
            JobRequest::Cursor => {
                if !self.pico_job_idle() || !matches!(self.owner, Some(Owner::Running(_))) {
                    return JobReply::code(JobCode::Busy);
                }
                match jobs::observe_cursor() {
                    Ok(cursor) => JobReply {
                        epoch: cursor.epoch,
                        sequence: cursor.sequence,
                        ..JobReply::code(JobCode::Ok)
                    },
                    Err(error) => JobReply::code(store_code(&error)),
                }
            }
            JobRequest::SubmitStartup { cursor, nonce } => self.submit_startup(cursor, nonce),
            JobRequest::Observe(id) => self.observe_pico_job(id),
        }
    }

    fn submit_startup(&mut self, cursor: PicoCursor, nonce: [u8; 16]) -> JobReply {
        let Some(sequence) = cursor.sequence.checked_add(1) else {
            return JobReply::code(JobCode::Invalid);
        };
        let id = PicoJobId {
            epoch: cursor.epoch,
            sequence,
            nonce,
        };
        if let Some(Owner::PicoJob(job)) = &self.owner {
            // An identical resubmission after a lost reply observes its job.
            return if job.id == id {
                self.observe_pico_job(id)
            } else {
                JobReply::code(JobCode::Busy)
            };
        }
        if !self.pico_job_idle() {
            return JobReply::code(JobCode::Busy);
        }
        let broker = match self.owner.take() {
            Some(Owner::Running(broker)) => broker,
            other => {
                self.owner = other;
                return JobReply::code(JobCode::Busy);
            }
        };
        let mut mutation = match broker.begin_picoclaw_mutation() {
            PicoMutationAdmission::Owned(mutation) => mutation,
            PicoMutationAdmission::Refused(broker) => {
                self.owner = Some(Owner::Running(*broker));
                return JobReply::code(JobCode::Busy);
            }
        };
        self.pico_job_last = None;
        #[cfg(all(test, feature = "sandbox-test-fixture"))]
        if let Some(image) = &self.fixture_pico_image {
            mutation.fixture_image(std::fs::File::open(image).unwrap());
        }
        if mutation
            .submit(cursor, nonce, PicoRequest::Startup)
            .is_err()
        {
            // Nothing was accepted, so the SAME broker comes straight back.
            return match mutation.into_broker() {
                Ok(broker) => {
                    self.owner = Some(Owner::Running(broker));
                    JobReply::code(JobCode::Unavailable)
                }
                Err(mutation) => {
                    self.owner = Some(Owner::PicoJob(Job {
                        mutation,
                        id,
                        status: PicoMutationStatus::RecoveryRequired,
                    }));
                    JobReply::job(JobCode::RecoveryRequired, id)
                }
            };
        }
        mutation.request_settlement();
        let owner = self.tick_pico_job(Job {
            mutation,
            id,
            status: PicoMutationStatus::Accepting,
        });
        self.owner = Some(owner);
        self.observe_pico_job(id)
    }

    fn observe_pico_job(&mut self, id: PicoJobId) -> JobReply {
        if let Some(Owner::PicoJob(job)) = &self.owner {
            if job.id != id {
                return JobReply::code(JobCode::Busy);
            }
            return JobReply::job(
                if job.status == PicoMutationStatus::RecoveryRequired {
                    JobCode::RecoveryRequired
                } else {
                    JobCode::Pending
                },
                id,
            );
        }
        // Outcomes that left no receipt are remembered for their submitter.
        match self.pico_job_last {
            Some((last, PicoMutationStatus::Expired)) if last == id => {
                return JobReply::job(JobCode::Expired, id);
            }
            Some((last, PicoMutationStatus::Rejected)) if last == id => {
                return JobReply::job(JobCode::Rejected, id);
            }
            _ => {}
        }
        match jobs::observe_job(id) {
            Ok(Observed::Receipt {
                kind,
                phase,
                outcome,
                runtime,
            }) => JobReply {
                receipt: [kind, phase, outcome, runtime],
                ..JobReply::job(JobCode::Ok, id)
            },
            Ok(Observed::Expired) => JobReply::job(JobCode::Expired, id),
            Ok(Observed::Unknown) => JobReply::job(JobCode::Invalid, id),
            Err(error) => JobReply::job(store_code(&error), id),
        }
    }
}

/// One accepted job-transport connection. It holds no authority: the job
/// belongs to the broker and survives this connection.
pub(super) struct JobClient {
    socket: OwnedFd,
    last_activity: Instant,
}

impl JobClient {
    pub(super) fn new(socket: OwnedFd) -> Self {
        Self {
            socket,
            last_activity: Instant::now(),
        }
    }

    /// One bounded nonblocking exchange. `false` closes the connection: peer
    /// EOF, idle expiry, a malformed datagram or a full send buffer.
    pub(super) fn tick(&mut self, engine: &mut Engine, idle: Duration) -> io::Result<bool> {
        let mut bytes = [0; PACKET];
        let length = match rustix::net::recv(
            &self.socket,
            &mut bytes,
            RecvFlags::DONTWAIT | RecvFlags::TRUNC,
        ) {
            Ok((_, length)) => length,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                return Ok(self.last_activity.elapsed() < idle);
            }
            Err(error) => return Err(error.into()),
        };
        if length == 0 {
            return Ok(false);
        }
        self.last_activity = Instant::now();
        let request = (length == PACKET).then(|| decode_request(&bytes)).flatten();
        let reply = match request {
            Some(request) => engine.pico_job_request(request),
            None => JobReply::code(JobCode::Invalid),
        };
        let sent = rustix::net::send(
            &self.socket,
            &encode_reply(reply),
            SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
        );
        Ok(request.is_some() && matches!(sent, Ok(PACKET)))
    }
}

/// Backend side of the job transport. It carries requests, never authority.
pub struct JobChannel {
    socket: OwnedFd,
}

impl JobChannel {
    pub fn connect() -> io::Result<Self> {
        Self::verified(journal::Store::connect_picoclaw_job()?, 0)
    }

    fn verified(socket: OwnedFd, uid: u32) -> io::Result<Self> {
        if rustix::net::sockopt::socket_peercred(&socket)?.uid.as_raw() != uid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(Self { socket })
    }

    /// One request and its reply within `timeout`.
    pub fn exchange(&mut self, request: JobRequest, timeout: Duration) -> io::Result<JobReply> {
        let deadline = Instant::now() + timeout;
        if rustix::net::send(&self.socket, &encode_request(request), SendFlags::NOSIGNAL)? != PACKET
        {
            return Err(io::ErrorKind::WriteZero.into());
        }
        loop {
            let mut bytes = [0; PACKET];
            match rustix::net::recv(
                &self.socket,
                &mut bytes,
                RecvFlags::DONTWAIT | RecvFlags::TRUNC,
            ) {
                Ok((_, 0)) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok((_, PACKET)) => {
                    return decode_reply(&bytes).ok_or_else(|| io::ErrorKind::InvalidData.into());
                }
                Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let mut ready = [rustix::event::PollFd::new(
                &self.socket,
                rustix::event::PollFlags::IN,
            )];
            let wait = rustix::event::Timespec {
                tv_sec: left.as_secs() as _,
                tv_nsec: left.subsec_nanos() as _,
            };
            match rustix::event::poll(&mut ready, Some(&wait)) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
}

const STEP: Duration = Duration::from_millis(50);
const EXCHANGE: Duration = Duration::from_secs(5);

fn left(deadline: Instant) -> io::Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(left.min(EXCHANGE))
    }
}

fn nonce() -> io::Result<[u8; 16]> {
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| io::Error::other("job nonce entropy unavailable"))?;
    if nonce == [0; 16] {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(nonce)
}

/// Run one broker-owned Startup job to its durable end within `timeout`.
/// A lost reply re-observes the SAME job and never submits a new one; only an
/// explicit non-acceptance (a stale cursor, or a job the broker reports as
/// never accepted) leads to a fresh submission. The returned reply is the
/// final one, terminal or not.
pub fn run_startup_job(timeout: Duration) -> io::Result<JobReply> {
    let deadline = Instant::now() + timeout;
    let mut channel = JobChannel::connect()?;
    'fresh: for _ in 0..3 {
        let cursor = channel.exchange(JobRequest::Cursor, left(deadline)?)?;
        if cursor.code != JobCode::Ok {
            return Ok(cursor);
        }
        let cursor = PicoCursor {
            epoch: cursor.epoch,
            sequence: cursor.sequence,
        };
        let nonce = nonce()?;
        let id = PicoJobId {
            epoch: cursor.epoch,
            sequence: cursor
                .sequence
                .checked_add(1)
                .ok_or(io::ErrorKind::InvalidData)?,
            nonce,
        };
        let submit = JobRequest::SubmitStartup { cursor, nonce };
        let mut request = submit;
        loop {
            let reply = match channel.exchange(request, left(deadline)?) {
                Ok(reply) => reply,
                Err(error) if error.kind() == io::ErrorKind::TimedOut => return Err(error),
                Err(_) => {
                    // Unknown outcome: reconnect and observe the SAME job.
                    std::thread::sleep(STEP);
                    channel = JobChannel::connect()?;
                    request = JobRequest::Observe(id);
                    continue;
                }
            };
            match (reply.code, request) {
                (JobCode::Pending, _) => {
                    std::thread::sleep(STEP);
                    request = JobRequest::Observe(id);
                }
                // The cursor went stale before acceptance: nothing was accepted.
                (JobCode::Expired, JobRequest::SubmitStartup { .. }) => continue 'fresh,
                // Never accepted, e.g. a lost submission: submit it again as is.
                (JobCode::Invalid, JobRequest::Observe(_)) => request = submit,
                _ => return Ok(reply),
            }
            left(deadline)?;
        }
    }
    Err(io::ErrorKind::TimedOut.into())
}

#[cfg(test)]
#[path = "ipc_picoclaw_job_tests.rs"]
mod tests;
