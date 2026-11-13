//! Terminal filesystem settlement retains native supervision on the broker.
use super::work::{InstallWork, Status};
use super::{AcceptedInstall, Broker, TerminalBoundary, controller};

pub(crate) enum Poll {
    Pending(Retirement),
    Failed(Retirement),
    Released(Box<Broker>),
}

pub(crate) struct Retirement {
    // Native handles drop first; work joins before accepted admission LAST.
    broker: Broker,
    work: InstallWork,
}

impl Retirement {
    pub(super) fn new(
        broker: Broker,
        install: AcceptedInstall,
        boundary: TerminalBoundary,
    ) -> Self {
        Self {
            broker,
            work: InstallWork::retire(install, boundary),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_fixture(&mut self, fixture: super::work::Fixture) {
        self.work.set_fixture(fixture);
    }

    #[cfg(test)]
    pub(crate) fn fixture_diagnostics(&mut self) -> String {
        // Observation only, without exposing or extracting the retained work.
        self.work.fixture_diagnostics()
    }

    pub(crate) fn observe(
        &mut self,
    ) -> ([Option<controller::Status>; 2], Option<controller::Status>) {
        let roles = self.broker.poll();
        (roles, self.broker.backend_status())
    }

    pub(crate) fn retry(&mut self) -> bool {
        !self.broker.group.ownership_uncertain() && self.work.retry_terminal()
    }

    pub(crate) fn poll(mut self) -> Poll {
        if self.broker.group.ownership_uncertain() {
            return Poll::Failed(self);
        }
        match self.work.poll(true) {
            Status::Pending => return Poll::Pending(self),
            // A terminal retirement never refuses; a refusal there is a failure.
            Status::Failed | Status::Refused => return Poll::Failed(self),
            Status::Complete => {}
        }
        if self.broker.group.ownership_uncertain() {
            return Poll::Failed(self);
        }
        let install = match self.work.into_install() {
            Ok(install) => install,
            Err(work) => return Poll::Failed(Self { work, ..self }),
        };
        let broker = Box::new(self.broker);
        drop(install);
        Poll::Released(broker)
    }
}
