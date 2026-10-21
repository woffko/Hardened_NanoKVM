//! Sibling native scopes for a future lifecycle broker. This is an in-process
//! ownership primitive, not a durable crash journal or an authenticated IPC API.

use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Child, Command, ExitStatus, Stdio},
};

pub use crate::app_trial_wire as trial_wire;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    KvmSystem,
    Hwmon,
    Backend,
    Picoclaw,
}

impl Role {
    pub(super) const NATIVE: [Self; 3] = [Self::KvmSystem, Self::Hwmon, Self::Picoclaw];

    fn index(self) -> usize {
        match self {
            Self::KvmSystem => 0,
            Self::Hwmon => 1,
            Self::Backend => 2,
            Self::Picoclaw => 3,
        }
    }

    pub(super) fn command(self) -> Command {
        let role = match self {
            Self::KvmSystem => "kvm-system",
            Self::Hwmon => "hwmon",
            Self::Backend => "backend",
            Self::Picoclaw => "picoclaw",
        };
        owner_command(role)
    }
}

pub(super) fn backend_trial_command() -> Command {
    owner_command("backend-trial")
}

fn owner_command(role: &'static str) -> Command {
    let mut command = Command::new("/usr/libexec/nanokvm-native-owner");
    command
        .args(["--scope", role])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // This is one named configuration input, not a generic environment API.
    // The fresh owner resolves it before chdir; backend/Pico must not silently
    // disagree merely because the controller clears unrelated environment.
    if matches!(role, "backend" | "backend-trial" | "picoclaw")
        && let Some(home) = std::env::var_os("PICOCLAW_HOME")
    {
        command.env("PICOCLAW_HOME", home);
    }
    command
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Stopped,
    SuccessfulExit,
    FailedExit,
    RuntimeError,
}

impl Completion {
    fn decode(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Stopped),
            1 => Some(Self::SuccessfulExit),
            2 => Some(Self::FailedExit),
            3 => Some(Self::RuntimeError),
            _ => None,
        }
    }

    fn matches(self, status: ExitStatus) -> bool {
        status.code()
            == Some(match self {
                Self::Stopped | Self::SuccessfulExit => 0,
                Self::FailedExit => 71,
                Self::RuntimeError => 72,
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Starting,
    Running,
    Stopping,
    TrialFailed,
    Closed(Completion),
    Uncertain,
}

#[derive(Debug)]
pub enum StartError {
    AlreadyOwned,
    UncertainOwnership,
    Spawn(io::Error),
}

struct Cell {
    child: Child,
    control: UnixStream,
    ready: bool,
    done_prefix: bool,
    completion: Option<Completion>,
    eof: bool,
    exit: Option<ExitStatus>,
    stop_requested: bool,
    stop_sent: bool,
    invalid: bool,
    guarded_eof: bool,
    trial: Option<TrialControl>,
}

struct TrialControl {
    transaction: [u8; 16],
    commit: [u8; trial_wire::BYTES],
    requested: bool,
    written: usize,
    committed: bool,
    failed: bool,
}

impl TrialControl {
    fn forward(&mut self, control: &mut UnixStream) -> io::Result<bool> {
        if self.written < self.commit.len() {
            match control.write(&self.commit[self.written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(size) => self.written += size,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(self.written == self.commit.len())
    }
}

impl Cell {
    fn spawn(command: Command, role: Role) -> io::Result<Self> {
        Self::spawn_kind(command, role, None)
    }

    fn spawn_kind(
        mut command: Command,
        role: Role,
        transaction: Option<[u8; 16]>,
    ) -> io::Result<Self> {
        let (control, owner) = UnixStream::pair()?;
        let trial = match transaction {
            Some(transaction) => {
                let begin = trial_wire::frame(trial_wire::Event::Begin, transaction)?;
                let commit = trial_wire::frame(trial_wire::Event::Commit, transaction)?;
                (&control).write_all(&begin)?;
                Some(TrialControl {
                    transaction,
                    commit,
                    requested: false,
                    written: 0,
                    committed: false,
                    failed: false,
                })
            }
            None => None,
        };
        control.set_nonblocking(true)?;
        command.stdin(Stdio::from(OwnedFd::from(owner)));
        // Allocate/configure before launching. No fallible setup may lose the
        // only Child/control owner after successful spawn.
        let child = command.spawn()?;
        Ok(Self {
            child,
            control,
            ready: false,
            done_prefix: false,
            completion: None,
            eof: false,
            exit: None,
            stop_requested: false,
            stop_sent: false,
            invalid: false,
            guarded_eof: role == Role::Backend,
            trial,
        })
    }

    fn commit_trial(&mut self, transaction: [u8; 16]) -> io::Result<bool> {
        if self.poll() != Status::Running {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let trial = self.trial.as_mut().ok_or(io::ErrorKind::InvalidInput)?;
        if trial.transaction != transaction || trial.failed {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        trial.requested = true;
        trial.forward(&mut self.control)?;
        Ok(trial.committed)
    }

    fn stop(&mut self) {
        self.stop_requested = true;
        if self.stop_sent || self.eof || self.exit.is_some() {
            return;
        }
        if let Some(trial) = &mut self.trial
            && trial.written > 0
            && trial.written < trial.commit.len()
        {
            // Never insert S into a partially sent Commit frame. That would
            // turn an admitted Stop into invalid control/EOF, whose orphan
            // cleanup cannot acquire the update exclusion retained by us.
            match trial.forward(&mut self.control) {
                Ok(true) => {}
                Ok(false) => return,
                Err(_) => {
                    self.invalid = true;
                    let _ = self.control.shutdown(Shutdown::Write);
                    return;
                }
            }
        }
        match self.control.write(b"S") {
            Ok(1) => self.stop_sent = true,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            _ => {
                self.invalid = true;
                // Backend EOF waits for update admission in the owner. Retain
                // the read side and Child; transport loss is never a join.
                let _ = self.control.shutdown(Shutdown::Write);
            }
        }
    }

    fn byte(&mut self, byte: u8) {
        if self.invalid || self.completion.is_some() {
            self.invalid = true;
        } else if self.done_prefix {
            self.done_prefix = false;
            self.completion = Completion::decode(byte);
            self.invalid = self.completion.is_none()
                || (!self.ready
                    && self.trial.is_none()
                    && self.completion != Some(Completion::Stopped))
                || (!self.stop_requested && self.completion == Some(Completion::Stopped));
        } else if let Some(trial) = &mut self.trial
            && byte == b'F'
            && !trial.failed
        {
            trial.failed = true;
        } else if byte == b'K'
            && self.ready
            && let Some(trial) = &mut self.trial
            && trial.requested
            && trial.written == trial.commit.len()
            && !trial.committed
            && !trial.failed
        {
            trial.committed = true;
        } else if byte == b'R'
            && !self.ready
            && !self.trial.as_ref().is_some_and(|trial| trial.failed)
        {
            self.ready = true;
        } else if byte == b'D' {
            self.done_prefix = true;
        } else {
            self.invalid = true;
        }
    }

    fn poll(&mut self) -> Status {
        // A bounded read per tick keeps one faulty cell from starving siblings.
        let mut bytes = [0; 64];
        if !self.eof {
            match self.control.read(&mut bytes) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    for byte in &bytes[..n] {
                        self.byte(*byte);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => {
                    self.invalid = true;
                    self.eof = true;
                }
            }
        }
        if self.exit.is_none() {
            match self.child.try_wait() {
                Ok(status) => self.exit = status,
                Err(_) => self.invalid = true,
            }
        }
        if self.stop_requested || (self.invalid && !self.guarded_eof) {
            self.stop();
        } else if self.invalid && self.guarded_eof {
            // Only an admitted broker operation may send backend Stop. On
            // protocol failure use EOF, whose independent owner waits for the
            // update lock before terminating any backend descendants.
            let _ = self.control.shutdown(Shutdown::Write);
        }
        if self.invalid || (self.eof && (self.done_prefix || self.completion.is_none())) {
            return Status::Uncertain;
        }
        if let Some(exit) = self.exit
            && self.eof
        {
            return match self.completion {
                Some(done) if done.matches(exit) => Status::Closed(done),
                _ => Status::Uncertain,
            };
        }
        if self.stop_requested {
            Status::Stopping
        } else if self.trial.as_ref().is_some_and(|trial| trial.failed) {
            Status::TrialFailed
        } else if self.ready {
            Status::Running
        } else {
            Status::Starting
        }
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        // Never kill the subreaper to make a timeout look bounded. EOF asks it
        // to finish cleanup; dropping this controller forfeits closure evidence.
        if !self.guarded_eof {
            self.stop();
        }
        let _ = self.control.shutdown(Shutdown::Both);
    }
}

/// Owns sibling scopes, not scopes nested below a watchdog. Callers must retain
/// this object (and their durable maintenance intent) across their own deadlines.
#[derive(Default)]
pub struct Group {
    cells: [Option<Cell>; 4],
    uncertain: bool,
}

impl Group {
    /// Fixed production roles only. Runtime provenance and protected installation
    /// of this fixed owner path are requirements of the future broker integration.
    pub fn start(&mut self, role: Role) -> Result<(), StartError> {
        self.start_command(role, role.command())
    }

    pub(super) fn start_command(&mut self, role: Role, command: Command) -> Result<(), StartError> {
        self.start_kind(role, command, None)
    }

    pub(super) fn start_trial(
        &mut self,
        command: Command,
        transaction: [u8; 16],
    ) -> Result<(), StartError> {
        self.start_kind(Role::Backend, command, Some(transaction))
    }

    fn start_kind(
        &mut self,
        role: Role,
        command: Command,
        transaction: Option<[u8; 16]>,
    ) -> Result<(), StartError> {
        if self.ownership_uncertain() {
            return Err(StartError::UncertainOwnership);
        }
        if self.cells[role.index()]
            .as_mut()
            .is_some_and(|cell| !matches!(cell.poll(), Status::Closed(_)))
        {
            return Err(StartError::AlreadyOwned);
        }
        self.cells[role.index()] = Some(
            match transaction {
                Some(transaction) => Cell::spawn_kind(command, role, Some(transaction)),
                None => Cell::spawn(command, role),
            }
            .map_err(StartError::Spawn)?,
        );
        Ok(())
    }

    pub(super) fn commit_trial(&mut self, transaction: [u8; 16]) -> io::Result<bool> {
        self.cells[Role::Backend.index()]
            .as_mut()
            .ok_or(io::ErrorKind::NotFound)?
            .commit_trial(transaction)
    }

    pub fn poll(&mut self) -> [Option<Status>; 4] {
        let status = self
            .cells
            .each_mut()
            .map(|cell| cell.as_mut().map(Cell::poll));
        self.uncertain |= status.contains(&Some(Status::Uncertain));
        if self.uncertain {
            // Native uncertainty closes admission but must not send Stop to a
            // healthy backend that may own an active update. Full shutdown is
            // a separate, update-admitted operation.
            for role in Role::NATIVE {
                if let Some(cell) = self.cells[role.index()].as_mut() {
                    cell.stop();
                }
            }
        }
        status
    }

    /// Poll and preserve the latched lifetime uncertainty, not health/closure.
    /// A terminal install retry must not clear a later owner-loss failure.
    pub(super) fn ownership_uncertain(&mut self) -> bool {
        self.poll();
        self.uncertain
    }

    /// Read the latch from the preceding poll without consuming more protocol
    /// bytes. An IPC tick must not refresh hidden roles just to inspect it.
    pub(super) fn uncertainty_latched(&self) -> bool {
        self.uncertain
    }

    /// Moving the group closes admission before any stop. No Group/start API is
    /// accessible until the entire drain has a valid receipt and owner exit.
    ///
    /// ```compile_fail
    /// use nanokvm_rust_server::native_owner::controller::{Group, Role};
    /// let mut group = Group::default();
    /// let retained = group.begin_drain();
    /// group.start(Role::Hwmon); // group was moved into retained
    /// ```
    pub fn begin_drain(mut self) -> Drain {
        for cell in self.cells.iter_mut().flatten() {
            cell.stop();
        }
        Drain {
            group: self,
            keep_backend: false,
        }
    }

    /// Native-only maintenance retains the serving backend and its update job.
    /// This is NOT backend/all-writer quiescence or raw handoff authority.
    pub(super) fn begin_native_drain(mut self) -> Drain {
        for role in Role::NATIVE {
            if let Some(cell) = self.cells[role.index()].as_mut() {
                cell.stop();
            }
        }
        Drain {
            group: self,
            keep_backend: true,
        }
    }

    pub(super) fn stop_backend(&mut self) {
        if let Some(cell) = self.cells[Role::Backend.index()].as_mut() {
            cell.stop();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainStatus {
    Pending,
    Drained,
    Uncertain,
}

/// A retained, non-cloneable in-process admission/cleanup owner. Dropping it
/// never resumes services and cannot be interpreted as a quiescence receipt.
pub struct Drain {
    group: Group,
    keep_backend: bool,
}

pub enum Resume {
    Running(Group),
    Retained(Drain),
}

impl Drain {
    pub(super) fn backend_status(&mut self) -> Option<Status> {
        self.group.poll()[2]
    }
    /// Only the direct owner processes, NOT proof that their native descendants
    /// are gone. An uncertain drain remains uncertain even when this is true.
    pub fn all_owner_processes_reaped(&self) -> bool {
        self.group
            .cells
            .iter()
            .flatten()
            .all(|cell| cell.exit.is_some())
    }

    pub fn poll(&mut self) -> DrainStatus {
        let status = self.group.poll();
        if self.group.uncertain {
            DrainStatus::Uncertain
        } else if status
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.keep_backend || *index != Role::Backend.index())
            .all(|(_, s)| matches!(s, None | Some(Status::Closed(_))))
        {
            DrainStatus::Drained
        } else {
            DrainStatus::Pending
        }
    }

    /// Explicit reversible abort only after proven closure. No reset is offered
    /// for uncertain ownership; recovery requires the external broker journal.
    pub fn try_resume(mut self) -> Resume {
        if self.poll() == DrainStatus::Drained {
            Resume::Running(self.group)
        } else {
            Resume::Retained(self)
        }
    }
}

#[cfg(all(test, feature = "sandbox-test-fixture"))]
#[path = "controller_picoclaw_tests.rs"]
mod picoclaw_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertainty_snapshot_does_not_consume_pending_owner_protocol() {
        let (control, mut peer) = UnixStream::pair().unwrap();
        control.set_nonblocking(true).unwrap();
        let mut cell = Cell::spawn(Command::new("/bin/true"), Role::Picoclaw).unwrap();
        cell.control = control;
        let mut group = Group::default();
        group.cells[Role::Picoclaw.index()] = Some(cell);
        peer.write_all(b"X").unwrap();
        assert!(!group.uncertainty_latched());
        assert!(
            !group.cells[Role::Picoclaw.index()]
                .as_ref()
                .unwrap()
                .invalid
        );
        assert_eq!(
            group.poll()[Role::Picoclaw.index()],
            Some(Status::Uncertain)
        );
        assert!(group.uncertainty_latched());
        group.cells[Role::Picoclaw.index()]
            .as_mut()
            .unwrap()
            .child
            .wait()
            .unwrap();
    }

    #[test]
    fn admitted_stop_never_interleaves_a_partial_commit_frame() {
        for offset in [0, 1, 16, trial_wire::BYTES - 1] {
            let transaction = [0x31; 16];
            let commit = trial_wire::frame(trial_wire::Event::Commit, transaction).unwrap();
            let mut cell =
                Cell::spawn_kind(Command::new("/bin/true"), Role::Backend, Some(transaction))
                    .unwrap();
            let (control, mut peer) = UnixStream::pair().unwrap();
            control.set_nonblocking(true).unwrap();
            peer.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            cell.control = control;
            let trial = cell.trial.as_mut().unwrap();
            trial.requested = true;
            trial.written = offset;
            cell.control.write_all(&commit[..offset]).unwrap();
            cell.stop();
            assert!(cell.stop_sent && !cell.invalid);
            if offset > 0 {
                let mut received = [0; trial_wire::BYTES];
                peer.read_exact(&mut received).unwrap();
                assert_eq!(received, commit);
            }
            let mut stop = [0];
            peer.read_exact(&mut stop).unwrap();
            assert_eq!(stop, *b"S");
            cell.child.wait().unwrap();
        }
    }

    #[test]
    fn trial_failure_is_not_closure_and_commit_ack_is_never_unsolicited() {
        let transaction = [0x31; 16];
        let ready = trial_wire::frame(trial_wire::Event::Ready, transaction).unwrap();
        assert_eq!(
            trial_wire::parse(&ready, trial_wire::Event::Ready).unwrap(),
            transaction
        );
        assert!(trial_wire::parse(&ready, trial_wire::Event::Begin).is_err());
        let mut cell =
            Cell::spawn_kind(Command::new("/bin/true"), Role::Backend, Some(transaction)).unwrap();
        cell.byte(b'F');
        assert!(!cell.invalid && cell.completion.is_none());
        assert!(cell.trial.as_ref().unwrap().failed);
        cell.byte(b'R');
        assert!(cell.invalid, "failure cannot become later readiness");
        cell.child.wait().unwrap();
        let mut cell =
            Cell::spawn_kind(Command::new("/bin/true"), Role::Backend, Some(transaction)).unwrap();
        cell.byte(b'R');
        cell.byte(b'K');
        assert!(
            cell.invalid,
            "no commit acknowledgement before a complete request"
        );
        cell.child.wait().unwrap();
    }

    #[test]
    fn production_commands_have_only_fixed_role_arguments_and_environment() {
        for (role, name) in [
            (Role::KvmSystem, "kvm-system"),
            (Role::Hwmon, "hwmon"),
            (Role::Backend, "backend"),
            (Role::Picoclaw, "picoclaw"),
        ] {
            let command = role.command();
            assert_eq!(command.get_program(), "/usr/libexec/nanokvm-native-owner");
            assert_eq!(command.get_args().collect::<Vec<_>>(), ["--scope", name]);
            let env = command.get_envs().collect::<Vec<_>>();
            assert!(matches!(env.len(), 3 | 4));
            for (name, value) in env {
                assert!(matches!(
                    name.to_str(),
                    Some("HOME" | "LANG" | "PATH" | "PICOCLAW_HOME")
                ));
                if name == "PICOCLAW_HOME" {
                    assert!(matches!(role, Role::Backend | Role::Picoclaw));
                }
                assert!(value.is_some());
            }
        }
    }

    #[test]
    fn receipt_parser_handles_fragmentation_and_rejects_unsolicited_stop() {
        let mut command = Command::new("/bin/true");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let mut cell = Cell::spawn(command, Role::KvmSystem).unwrap();
        cell.byte(b'R');
        cell.byte(b'D');
        assert!(cell.done_prefix && cell.completion.is_none());
        cell.byte(1);
        assert_eq!(cell.completion, Some(Completion::SuccessfulExit));
        assert!(!cell.invalid);
        cell.child.wait().unwrap();

        let mut command = Command::new("/bin/true");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let mut cell = Cell::spawn(command, Role::KvmSystem).unwrap();
        cell.byte(b'R');
        cell.byte(b'D');
        cell.byte(0);
        assert!(cell.invalid);
        cell.child.wait().unwrap();
    }

    #[test]
    fn valid_receipt_and_matching_exit_still_require_control_eof() {
        let (control, mut peer) = UnixStream::pair().unwrap();
        control.set_nonblocking(true).unwrap();
        let mut child = Command::new("/bin/true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let exit = child.wait().unwrap();
        // Deliberately retain the peer independently of the already reaped
        // synthetic owner. Model a leaked alias without leaving orphan children.
        let mut cell = Cell {
            child,
            control,
            ready: false,
            done_prefix: false,
            completion: None,
            eof: false,
            exit: Some(exit),
            stop_requested: false,
            stop_sent: false,
            invalid: false,
            guarded_eof: false,
            trial: None,
        };
        peer.write_all(b"RD\x01").unwrap();
        assert_eq!(cell.poll(), Status::Running);
        assert_eq!(cell.poll(), Status::Running);
        drop(peer);
        // Other parallel fixture threads can fork with a transient CLOEXEC
        // alias until exec. EOF, rather than close(peer) timing, is authoritative.
        let start = std::time::Instant::now();
        loop {
            let status = cell.poll();
            if status == Status::Closed(Completion::SuccessfulExit) {
                break;
            }
            assert_eq!(status, Status::Running);
            assert!(start.elapsed() < std::time::Duration::from_secs(2));
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}
