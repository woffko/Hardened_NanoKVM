//! Single-threaded relay created only after the owner's inherited-FD audit.
use super::{Control, Error, STEP, trial_wire as wire};
use std::{
    io::{self, Read, Write},
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

enum Phase {
    WaitingReady,
    AwaitCommit,
    ForwardCommit(usize),
    Committed,
    Failed,
}

pub(super) struct Trial {
    channel: UnixStream,
    child: Option<UnixStream>,
    transaction: [u8; 16],
    phase: Phase,
    ready: [u8; wire::BYTES],
    used: usize,
    command: [u8; wire::BYTES],
    command_used: usize,
    commit: [u8; wire::BYTES],
    deadline: Instant,
}

fn idle(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

impl Trial {
    pub(super) fn prepare(control: &mut UnixStream) -> Result<Option<Self>, Error> {
        let mut begin = [0; wire::BYTES];
        let mut used = 0;
        let deadline = Instant::now() + Duration::from_secs(2);
        while used < begin.len() {
            if Instant::now() >= deadline {
                return Err(Error::Control);
            }
            match control.read(&mut begin[used..]) {
                Ok(0) => return Ok(None),
                Ok(1) if used == 0 && begin[0] == b'S' => return Ok(None),
                Ok(size) => used += size,
                Err(error) if idle(&error) => std::thread::sleep(STEP),
                Err(_) => return Err(Error::Control),
            }
        }
        let transaction = wire::parse(&begin, wire::Event::Begin).map_err(|_| Error::Control)?;
        // No new socket or inherited descriptor before scope::initialize.
        let (mut channel, child) = UnixStream::pair().map_err(|_| Error::Setup)?;
        channel
            .write_all(&wire::frame(wire::Event::Begin, transaction).map_err(|_| Error::Setup)?)
            .map_err(|_| Error::Setup)?;
        channel.set_nonblocking(true).map_err(|_| Error::Setup)?;
        Ok(Some(Self {
            channel,
            child: Some(child),
            transaction,
            phase: Phase::WaitingReady,
            ready: [0; wire::BYTES],
            used: 0,
            command: [0; wire::BYTES],
            command_used: 0,
            commit: wire::frame(wire::Event::Commit, transaction).map_err(|_| Error::Setup)?,
            deadline: Instant::now() + Duration::from_secs(30),
        }))
    }

    pub(super) fn configure(&mut self, command: &mut Command) -> Result<(), Error> {
        let child = self.child.take().ok_or(Error::Setup)?;
        command.stdin(Stdio::from(OwnedFd::from(child)));
        Ok(())
    }

    pub(super) fn committed(&self) -> bool {
        matches!(self.phase, Phase::Committed)
    }

    pub(super) fn fail(&mut self, control: &mut UnixStream) {
        if !matches!(self.phase, Phase::Failed) {
            self.phase = Phase::Failed;
            // F is failure, never a closure receipt. Keep both owned channels
            // and the tree until an admitted Stop and actual kernel ECHILD.
            let _ = control.write_all(b"F");
        }
    }

    pub(super) fn control(&mut self, control: &mut UnixStream) -> Result<Control, Error> {
        let end = if self.command_used == 0 {
            1
        } else {
            wire::BYTES
        };
        match control.read(&mut self.command[self.command_used..end]) {
            Ok(0) => return Ok(Control::Lost),
            Ok(1) if self.command_used == 0 && self.command[0] == b'S' => return Ok(Control::Stop),
            Ok(size) => self.command_used += size,
            Err(error) if idle(&error) => return Ok(Control::Idle),
            Err(_) => return Err(Error::Control),
        }
        if self.command_used == wire::BYTES {
            if !matches!(self.phase, Phase::AwaitCommit)
                || wire::parse(&self.command, wire::Event::Commit).map_err(|_| Error::Control)?
                    != self.transaction
            {
                return Err(Error::Control);
            }
            self.phase = Phase::ForwardCommit(0);
            self.command_used = 0;
        }
        Ok(Control::Idle)
    }

    pub(super) fn tick(&mut self, control: &mut UnixStream) -> Result<(), Error> {
        if matches!(self.phase, Phase::Failed | Phase::Committed) {
            return Ok(());
        }
        if Instant::now() >= self.deadline {
            return Err(Error::Runtime);
        }
        if let Phase::ForwardCommit(written) = self.phase {
            // New control input (including Stop) may overwrite command while
            // this stream write is partial; the validated frame is immutable.
            match self.channel.write(&self.commit[written..]) {
                Ok(0) => return Err(Error::Runtime),
                Ok(size) => {
                    let total = written + size;
                    self.phase = Phase::ForwardCommit(total);
                    if total == wire::BYTES {
                        self.phase = Phase::Committed;
                        control.write_all(b"K").map_err(|_| Error::Control)?;
                    }
                }
                Err(error) if idle(&error) => {}
                Err(_) => return Err(Error::Runtime),
            }
            return Ok(());
        }
        if matches!(self.phase, Phase::AwaitCommit) {
            // A backend may emit only one Ready frame before Commit.
            return match self.channel.read(&mut [0]) {
                Err(error) if idle(&error) => Ok(()),
                _ => Err(Error::Runtime),
            };
        }
        match self.channel.read(&mut self.ready[self.used..]) {
            Ok(0) => return Err(Error::Runtime),
            Ok(size) => self.used += size,
            Err(error) if idle(&error) => return Ok(()),
            Err(_) => return Err(Error::Runtime),
        }
        if self.used == wire::BYTES {
            if wire::parse(&self.ready, wire::Event::Ready).map_err(|_| Error::Runtime)?
                != self.transaction
            {
                return Err(Error::Runtime);
            }
            control.write_all(b"R").map_err(|_| Error::Control)?;
            self.phase = Phase::AwaitCommit;
            self.deadline = Instant::now() + Duration::from_secs(30);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_input_cannot_corrupt_a_partially_forwarded_backend_commit() {
        let transaction = [0x31; 16];
        let (mut controller, mut control) = UnixStream::pair().unwrap();
        control.set_nonblocking(true).unwrap();
        controller
            .write_all(&wire::frame(wire::Event::Begin, transaction).unwrap())
            .unwrap();
        let mut trial = Trial::prepare(&mut control).unwrap().unwrap();
        let mut backend = trial.child.take().unwrap();
        backend
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut begin = [0; wire::BYTES];
        backend.read_exact(&mut begin).unwrap();
        assert_eq!(
            wire::parse(&begin, wire::Event::Begin).unwrap(),
            transaction
        );
        trial.phase = Phase::AwaitCommit;
        controller.write_all(&trial.commit).unwrap();
        assert!(matches!(
            trial.control(&mut control).unwrap(),
            Control::Idle
        ));
        assert!(matches!(
            trial.control(&mut control).unwrap(),
            Control::Idle
        ));
        assert!(matches!(trial.phase, Phase::ForwardCommit(0)));
        // Deterministically model a stream partial write without depending on
        // socket-buffer sizing or a particular host scheduler.
        trial.channel.write_all(&trial.commit[..7]).unwrap();
        trial.phase = Phase::ForwardCommit(7);
        controller.write_all(b"S").unwrap();
        assert!(matches!(
            trial.control(&mut control).unwrap(),
            Control::Stop
        ));
        assert_eq!(trial.command[0], b'S');
        trial.tick(&mut control).unwrap();
        let mut received = [0; wire::BYTES];
        backend.read_exact(&mut received).unwrap();
        assert_eq!(received, trial.commit);
    }
}
