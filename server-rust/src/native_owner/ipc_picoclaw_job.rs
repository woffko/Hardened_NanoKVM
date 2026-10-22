//! Private fixed-frame Pico job transport on a root-only SEQPACKET endpoint:
//! one bounded request and one reply per datagram. Typed fields and result
//! codes only; a Model key travels only in its submission and is never echoed,
//! logged or Debug-printed. No path, command or error text. The broker owns
//! each job; a client's disconnect never cancels or settles it.
use super::*;
use crate::native_owner::broker::{
    PicoCursor, PicoJobId, PicoMutation, PicoMutationAdmission, PicoMutationStatus, PicoRequest,
};
use crate::update::picoclaw_config::jobs::{self, Observed};
use crate::update::picoclaw_model;
use rustix::net::{RecvFlags, SendFlags};
use sha2::{Digest, Sha256};
use std::os::fd::OwnedFd;
use zeroize::Zeroizing;

pub(super) const PACKET: usize = 64;
/// A Model submission's bounded fields follow its fixed header.
pub(super) const MAX_REQUEST: usize = PACKET
    + picoclaw_model::MAX_MODEL_BYTES
    + picoclaw_model::MAX_API_BASE_BYTES
    + picoclaw_model::MAX_API_KEY_BYTES;
pub(super) const JOB_CLIENTS: usize = 4;
const REQUEST_MAGIC: &[u8; 8] = b"NKPJQ001";
const REPLY_MAGIC: &[u8; 8] = b"NKPJS001";
// The executors wired to this transport; the store's kind codes.
const MODEL: u8 = 2;
const STARTUP: u8 = 3;

/// What a submission asks the broker to settle.
#[derive(Clone, PartialEq, Eq)]
pub enum JobKind {
    Startup,
    /// Bounded, trimmed fields; see `picoclaw_model::check_request`.
    Model {
        model: Zeroizing<String>,
        api_base: Zeroizing<String>,
        api_key: Zeroizing<String>,
    },
}

// Never print the credential-bearing fields.
impl std::fmt::Debug for JobKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Startup => "Startup",
            Self::Model { .. } => "Model { .. }",
        })
    }
}

impl JobKind {
    fn code(&self) -> u8 {
        match self {
            Self::Startup => STARTUP,
            Self::Model { .. } => MODEL,
        }
    }

    fn fields(&self) -> [&str; 3] {
        match self {
            Self::Startup => ["", "", ""],
            Self::Model {
                model,
                api_base,
                api_key,
            } => [model, api_base, api_key],
        }
    }

    // In-memory identity of one submission, so a replay of the same job id
    // with a different request is refused. Never stored or sent.
    fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"NanoKVM Pico job submission v1\0");
        hash.update([self.code()]);
        for field in self.fields() {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
        hash.finalize().into()
    }

    fn request(self) -> PicoRequest {
        match self {
            Self::Startup => PicoRequest::Startup,
            Self::Model {
                model,
                api_base,
                api_key,
            } => PicoRequest::Model {
                model,
                api_base,
                api_key,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobRequest {
    /// The next submission cursor of an idle store.
    Cursor,
    /// One job for exactly this observed cursor and client nonce.
    Submit {
        cursor: PicoCursor,
        nonce: [u8; 16],
        kind: JobKind,
    },
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

/// One request datagram: the fixed header, then a Model's three fields.
pub(super) fn encode_request(request: &JobRequest) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0; PACKET]);
    bytes[..8].copy_from_slice(REQUEST_MAGIC);
    let (op, kind, epoch, sequence, nonce) = match request {
        JobRequest::Cursor => (1, None, [0; 16], 0, [0; 16]),
        JobRequest::Submit {
            cursor,
            nonce,
            kind,
        } => (2, Some(kind), cursor.epoch, cursor.sequence, *nonce),
        JobRequest::Observe(id) => (3, None, id.epoch, id.sequence, id.nonce),
    };
    bytes[8] = op;
    bytes[16..32].copy_from_slice(&epoch);
    bytes[32..40].copy_from_slice(&sequence.to_le_bytes());
    bytes[40..56].copy_from_slice(&nonce);
    if let Some(kind) = kind {
        bytes[9] = kind.code();
        if let JobKind::Model { .. } = kind {
            for (index, field) in kind.fields().into_iter().enumerate() {
                let offset = 56 + index * 2;
                let length = u16::try_from(field.len()).unwrap_or(u16::MAX);
                bytes[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
                bytes.extend_from_slice(field.as_bytes());
            }
        }
    }
    bytes
}

// The three bounded Model fields after the header; their lengths are its
// last bytes and must account for the whole datagram exactly.
fn decode_model(bytes: &[u8]) -> Option<JobKind> {
    if bytes.len() > MAX_REQUEST || bytes[62..PACKET].iter().any(|byte| *byte != 0) {
        return None;
    }
    let length = |index: usize| {
        usize::from(u16::from_le_bytes([
            bytes[56 + index * 2],
            bytes[57 + index * 2],
        ]))
    };
    let (model, api_base, api_key) = (length(0), length(1), length(2));
    if PACKET + model + api_base + api_key != bytes.len() {
        return None;
    }
    let field = |start: usize, length: usize| {
        std::str::from_utf8(&bytes[start..start + length])
            .ok()
            .map(|text| Zeroizing::new(text.to_string()))
    };
    let kind = JobKind::Model {
        model: field(PACKET, model)?,
        api_base: field(PACKET + model, api_base)?,
        api_key: field(PACKET + model + api_base, api_key)?,
    };
    let [model, api_base, api_key] = kind.fields();
    picoclaw_model::check_request(model, api_base, api_key).ok()?;
    Some(kind)
}

pub(super) fn decode_request(bytes: &[u8]) -> Option<JobRequest> {
    if bytes.len() < PACKET
        || &bytes[..8] != REQUEST_MAGIC
        || bytes[10..16].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let epoch: [u8; 16] = bytes[16..32].try_into().ok()?;
    let sequence = u64::from_le_bytes(bytes[32..40].try_into().ok()?);
    let nonce: [u8; 16] = bytes[40..56].try_into().ok()?;
    let submit = |kind: JobKind| {
        (epoch != [0; 16] && nonce != [0; 16] && sequence < u64::MAX).then_some(
            JobRequest::Submit {
                cursor: PicoCursor { epoch, sequence },
                nonce,
                kind,
            },
        )
    };
    if (bytes[8], bytes[9]) == (2, MODEL) {
        return submit(decode_model(bytes)?);
    }
    if bytes.len() != PACKET || bytes[56..].iter().any(|byte| *byte != 0) {
        return None;
    }
    match (bytes[8], bytes[9]) {
        (1, 0) if epoch == [0; 16] && sequence == 0 && nonce == [0; 16] => Some(JobRequest::Cursor),
        (2, STARTUP) => submit(JobKind::Startup),
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
    /// The submission's in-memory identity; see `JobKind::digest`.
    digest: [u8; 32],
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
            JobRequest::Submit {
                cursor,
                nonce,
                kind,
            } => self.submit(cursor, nonce, kind),
            JobRequest::Observe(id) => self.observe_pico_job(id),
        }
    }

    fn submit(&mut self, cursor: PicoCursor, nonce: [u8; 16], kind: JobKind) -> JobReply {
        let Some(sequence) = cursor.sequence.checked_add(1) else {
            return JobReply::code(JobCode::Invalid);
        };
        let id = PicoJobId {
            epoch: cursor.epoch,
            sequence,
            nonce,
        };
        let digest = kind.digest();
        if let Some(Owner::PicoJob(job)) = &self.owner {
            // An identical resubmission after a lost reply observes its job;
            // the same identity with a different request is invalid.
            return match (job.id == id, job.digest == digest) {
                (true, true) => self.observe_pico_job(id),
                (true, false) => JobReply::job(JobCode::Invalid, id),
                (false, _) => JobReply::code(JobCode::Busy),
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
        if mutation.submit(cursor, nonce, kind.request()).is_err() {
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
                        digest,
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
            digest,
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
        // A Model datagram carries a key: clear the buffer after use.
        let mut bytes = Zeroizing::new([0; MAX_REQUEST]);
        let length = match rustix::net::recv(
            &self.socket,
            &mut bytes[..],
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
        let request = (length <= MAX_REQUEST)
            .then(|| decode_request(&bytes[..length]))
            .flatten();
        let decoded = request.is_some();
        let reply = match request {
            Some(request) => engine.pico_job_request(request),
            None => JobReply::code(JobCode::Invalid),
        };
        let sent = rustix::net::send(
            &self.socket,
            &encode_reply(reply),
            SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
        );
        Ok(decoded && matches!(sent, Ok(PACKET)))
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
    pub fn exchange(&mut self, request: &JobRequest, timeout: Duration) -> io::Result<JobReply> {
        let deadline = Instant::now() + timeout;
        let bytes = encode_request(request);
        if rustix::net::send(&self.socket, &bytes, SendFlags::NOSIGNAL)? != bytes.len() {
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
pub fn run_startup_job(timeout: Duration) -> io::Result<JobReply> {
    run_job(JobKind::Startup, timeout)
}

/// Run one broker-owned Model job; the fields must pass
/// `picoclaw_model::check_request` or the broker refuses the datagram.
pub fn run_model_job(
    model: Zeroizing<String>,
    api_base: Zeroizing<String>,
    api_key: Zeroizing<String>,
    timeout: Duration,
) -> io::Result<JobReply> {
    run_job(
        JobKind::Model {
            model,
            api_base,
            api_key,
        },
        timeout,
    )
}

/// A lost reply re-observes the SAME job and never submits a new one; only an
/// explicit non-acceptance (a stale cursor, or a job the broker reports as
/// never accepted) leads to a fresh submission. The returned reply is the
/// final one, terminal or not.
fn run_job(kind: JobKind, timeout: Duration) -> io::Result<JobReply> {
    let deadline = Instant::now() + timeout;
    let mut channel = JobChannel::connect()?;
    'fresh: for _ in 0..3 {
        let cursor = channel.exchange(&JobRequest::Cursor, left(deadline)?)?;
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
        let submit = JobRequest::Submit {
            cursor,
            nonce,
            kind: kind.clone(),
        };
        let mut request = submit.clone();
        loop {
            let reply = match channel.exchange(&request, left(deadline)?) {
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
            match (reply.code, &request) {
                (JobCode::Pending, _) => {
                    std::thread::sleep(STEP);
                    request = JobRequest::Observe(id);
                }
                // The cursor went stale before acceptance: nothing was accepted.
                (JobCode::Expired, JobRequest::Submit { .. }) => continue 'fresh,
                // Never accepted, e.g. a lost submission: submit it again as is.
                (JobCode::Invalid, JobRequest::Observe(_)) => request = submit.clone(),
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
