//! Keep the live trial supervised while one fixed durable commit owns I/O.
use super::work::{InstallWork, Status};
use super::{TrialSession, TrialStatus, controller};

pub(crate) enum Poll {
    Pending {
        owner: CommittingTrial,
        uncertain: bool,
    },
    // One cold-path allocation only after successful joined commit I/O.
    Ready(Box<TrialSession>),
    Failed(CommittingTrial),
}

pub(crate) struct CommittingTrial {
    group: controller::Group,
    enrollment: super::super::boot::Permit,
    #[cfg(test)]
    update_parent: Option<std::fs::File>,
    failed: bool,
    uncertain: bool,
    // Drop native handles first; join before singleton/accepted leases LAST.
    work: InstallWork,
}

impl CommittingTrial {
    pub(super) fn new(
        group: controller::Group,
        enrollment: super::super::boot::Permit,
        #[cfg(test)] update_parent: Option<std::fs::File>,
        failed: bool,
        work: InstallWork,
    ) -> Self {
        Self {
            group,
            enrollment,
            #[cfg(test)]
            update_parent,
            failed,
            uncertain: false,
            work,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_fixture(&mut self, fixture: super::work::Fixture) {
        self.work.set_fixture(fixture);
    }

    #[cfg(test)]
    pub(crate) fn fixture_io_settled(&self) -> bool {
        self.work.fixture_settled()
    }

    pub(crate) fn poll(mut self) -> Poll {
        self.observe();
        let status = self.work.poll(!self.uncertain);
        if status == Status::Pending {
            return Poll::Pending {
                uncertain: self.uncertain,
                owner: self,
            };
        }
        self.observe();
        if status == Status::Failed || self.uncertain {
            // Unknown durable commit is never an ordinary rollback-capable
            // TrialSession. Keep journal+install together, even after path repair.
            self.uncertain = true;
            return Poll::Failed(self);
        }
        let state = match self.work.into_commit() {
            Ok(state) => state,
            Err(work) => {
                return Poll::Failed(Self {
                    work,
                    uncertain: true,
                    ..self
                });
            }
        };
        Poll::Ready(Box::new(TrialSession {
            group: self.group,
            journal: state.journal,
            enrollment: self.enrollment,
            #[cfg(test)]
            update_parent: self.update_parent,
            failed: self.failed,
            native_resumed: true,
            install: state.install,
        }))
    }

    fn observe(&mut self) {
        if super::trial_group_status(&mut self.group, self.failed) != TrialStatus::Ready {
            self.uncertain = true;
        }
    }
}
