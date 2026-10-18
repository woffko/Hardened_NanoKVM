//! Sibling native scopes for a future lifecycle broker. This is an in-process
//! ownership primitive, not a durable crash journal or an authenticated IPC API.

use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Child, Command, ExitStatus, Stdio},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    KvmSystem,
    Hwmon,
}

impl Role {
    fn index(self) -> usize {
        match self {
            Self::KvmSystem => 0,
            Self::Hwmon => 1,
        }
    }

    pub(super) fn command(self) -> Command {
        let role = match self {
            Self::KvmSystem => "kvm-system",
            Self::Hwmon => "hwmon",
        };
        let mut command = Command::new("/kvmapp/server/nanokvm-native-owner");
        command
            .args(["--scope", role])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("HOME", "/root")
            .env("LANG", "C")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        command
    }
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
}

impl Cell {
    fn spawn(mut command: Command) -> io::Result<Self> {
        let (control, owner) = UnixStream::pair()?;
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
        })
    }

    fn stop(&mut self) {
        self.stop_requested = true;
        if self.stop_sent || self.eof || self.exit.is_some() {
            return;
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
                // EOF is also Stop. Retain the read side and Child for cleanup;
                // a broken transport never becomes a successful join.
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
                || (!self.ready && self.completion != Some(Completion::Stopped))
                || (!self.stop_requested && self.completion == Some(Completion::Stopped));
        } else if byte == b'R' && !self.ready {
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
        if self.invalid || self.stop_requested {
            self.stop();
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
        self.stop();
        let _ = self.control.shutdown(Shutdown::Both);
    }
}

/// Owns sibling scopes, not scopes nested below a watchdog. Callers must retain
/// this object (and their durable maintenance intent) across their own deadlines.
#[derive(Default)]
pub struct Group {
    cells: [Option<Cell>; 2],
    uncertain: bool,
}

impl Group {
    /// Fixed production roles only. Runtime provenance and protected installation
    /// of this fixed owner path are requirements of the future broker integration.
    pub fn start(&mut self, role: Role) -> Result<(), StartError> {
        self.start_command(role, role.command())
    }

    pub(super) fn start_command(&mut self, role: Role, command: Command) -> Result<(), StartError> {
        self.poll();
        if self.uncertain {
            return Err(StartError::UncertainOwnership);
        }
        if self.cells[role.index()]
            .as_mut()
            .is_some_and(|cell| !matches!(cell.poll(), Status::Closed(_)))
        {
            return Err(StartError::AlreadyOwned);
        }
        self.cells[role.index()] = Some(Cell::spawn(command).map_err(StartError::Spawn)?);
        Ok(())
    }

    pub fn poll(&mut self) -> [Option<Status>; 2] {
        let status = self
            .cells
            .each_mut()
            .map(|cell| cell.as_mut().map(Cell::poll));
        self.uncertain |= status.contains(&Some(Status::Uncertain));
        if self.uncertain {
            for cell in self.cells.iter_mut().flatten() {
                cell.stop();
            }
        }
        status
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
        Drain { group: self }
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
}

impl Drain {
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
            .all(|s| matches!(s, None | Some(Status::Closed(_))))
        {
            DrainStatus::Drained
        } else {
            DrainStatus::Pending
        }
    }

    /// Explicit reversible abort only after proven closure. No reset is offered
    /// for uncertain ownership; recovery requires the external broker journal.
    pub fn try_resume(mut self) -> Result<Group, Self> {
        if self.poll() == DrainStatus::Drained {
            Ok(self.group)
        } else {
            Err(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_commands_have_only_fixed_role_arguments_and_environment() {
        for (role, name) in [(Role::KvmSystem, "kvm-system"), (Role::Hwmon, "hwmon")] {
            let command = role.command();
            assert_eq!(command.get_program(), "/kvmapp/server/nanokvm-native-owner");
            assert_eq!(command.get_args().collect::<Vec<_>>(), ["--scope", name]);
            let env = command.get_envs().collect::<Vec<_>>();
            assert_eq!(env.len(), 3);
            for (name, value) in env {
                assert!(matches!(name.to_str(), Some("HOME" | "LANG" | "PATH")));
                assert!(value.is_some());
            }
        }
    }

    #[test]
    fn receipt_parser_handles_fragmentation_and_rejects_unsolicited_stop() {
        let mut command = Command::new("/bin/true");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let mut cell = Cell::spawn(command).unwrap();
        cell.byte(b'R');
        cell.byte(b'D');
        assert!(cell.done_prefix && cell.completion.is_none());
        cell.byte(1);
        assert_eq!(cell.completion, Some(Completion::SuccessfulExit));
        assert!(!cell.invalid);
        cell.child.wait().unwrap();

        let mut command = Command::new("/bin/true");
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let mut cell = Cell::spawn(command).unwrap();
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
