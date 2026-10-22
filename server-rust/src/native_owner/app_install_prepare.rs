//! Main-thread closed-runtime supervision plus one fixed install I/O operation.
use super::work::{InstallWork, Status};
use super::{Session, controller, journal};

pub(crate) enum Poll {
    Pending {
        owner: PreparingInstall,
        uncertain: bool,
    },
    Ready {
        session: Session,
        kind: Kind,
    },
    Failed {
        session: Session,
        uncertain: bool,
    },
    Retained(PreparingInstall),
}

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Support,
    Publication,
    /// The pre-trial support check, with its directory syncs.
    TrialCheck,
}

pub(crate) struct PreparingInstall {
    group: controller::Drain,
    journal: journal::Store,
    enrollment: super::super::boot::Permit,
    #[cfg(test)]
    update_parent: Option<std::fs::File>,
    uncertain: bool,
    kind: Kind,
    // Native handles drop first; worker joins before accepted admission LAST.
    work: InstallWork,
}

impl PreparingInstall {
    pub(super) fn new(
        kind: Kind,
        group: controller::Drain,
        journal: journal::Store,
        enrollment: super::super::boot::Permit,
        #[cfg(test)] update_parent: Option<std::fs::File>,
        work: InstallWork,
    ) -> Self {
        Self {
            group,
            journal,
            enrollment,
            #[cfg(test)]
            update_parent,
            uncertain: false,
            kind,
            work,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_fixture(&mut self, fixture: super::work::Fixture) {
        self.work.set_fixture(fixture);
    }

    #[cfg(test)]
    pub(crate) fn fixture_failed_stopping_publication(&mut self) {
        // A real EXCL publication failure poisons the live journal; no fake
        // closure receipt or reset of the native group is introduced.
        assert!(self.journal.stopping().is_err());
    }

    pub(crate) fn poll(mut self) -> Poll {
        // Keep supervision/proof checks in the broker, never the filesystem
        // worker. Once uncertainty is seen, later I/O success cannot clear it.
        self.observe_closed();
        let status = self.work.poll(!self.uncertain);
        if status == Status::Pending {
            return Poll::Pending {
                uncertain: self.uncertain,
                owner: self,
            };
        }
        self.observe_closed();
        let install = match self.work.into_install() {
            Ok(install) => install,
            Err(work) => return Poll::Retained(Self { work, ..self }),
        };
        let session = Session {
            group: self.group,
            journal: self.journal,
            enrollment: self.enrollment,
            #[cfg(test)]
            update_parent: self.update_parent,
            support_checked: status == Status::Complete
                && !self.uncertain
                && matches!(self.kind, Kind::TrialCheck),
            install,
        };
        if status == Status::Failed || self.uncertain {
            Poll::Failed {
                session,
                uncertain: self.uncertain,
            }
        } else {
            Poll::Ready {
                session,
                kind: self.kind,
            }
        }
    }

    fn observe_closed(&mut self) {
        let scopes = self.group.poll();
        if self.journal.ready().is_err() || !matches!(scopes, controller::DrainStatus::Drained) {
            self.uncertain = true;
        }
    }
}
