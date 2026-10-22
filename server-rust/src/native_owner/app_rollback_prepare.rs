//! Retain native closure while one fixed worker restores both durable journals.
use super::work::{InstallWork, Status};
use super::{Rollback, Session, controller};

pub(crate) enum Poll {
    Pending { owner: RollingBack, uncertain: bool },
    // A cold-path allocation only after joined durable completion.
    Ready(Box<Rollback>),
    Failed(RollingBack),
}

pub(crate) struct RollingBack {
    group: controller::Drain,
    enrollment: super::super::boot::Permit,
    #[cfg(test)]
    update_parent: Option<std::fs::File>,
    uncertain: bool,
    // Native handles drop first; join before singleton/accepted leases LAST.
    work: InstallWork,
}

impl RollingBack {
    pub(super) fn new(
        group: controller::Drain,
        enrollment: super::super::boot::Permit,
        #[cfg(test)] update_parent: Option<std::fs::File>,
        work: InstallWork,
    ) -> Self {
        Self {
            group,
            enrollment,
            #[cfg(test)]
            update_parent,
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

    #[cfg(test)]
    pub(crate) fn fixture_forfeit_closed_proof(&mut self) {
        // Model lost main-thread authority AFTER a real complete drain. This
        // only removes permission; it neither fabricates a receipt nor models
        // a physical process loss after all scope owners have already reaped.
        assert_eq!(self.group.poll(), controller::DrainStatus::Drained);
        self.uncertain = true;
    }

    pub(crate) fn poll(mut self) -> Poll {
        self.observe_closed();
        let status = self.work.poll(!self.uncertain);
        if status == Status::Pending {
            return Poll::Pending {
                uncertain: self.uncertain,
                owner: self,
            };
        }
        self.observe_closed();
        if status == Status::Failed || self.uncertain {
            // Failure is sticky, including panic after successful I/O. Neither
            // observation nor another Cancel can obtain a retryable Session.
            self.uncertain = true;
            return Poll::Failed(self);
        }
        let state = match self.work.into_rollback() {
            Ok(state) => state,
            Err(work) => {
                return Poll::Failed(Self {
                    work,
                    uncertain: true,
                    ..self
                });
            }
        };
        Poll::Ready(Box::new(
            Session {
                group: self.group,
                journal: state.journal,
                enrollment: self.enrollment,
                #[cfg(test)]
                update_parent: self.update_parent,
                support_checked: false,
                install: state.install,
            }
            .finish_rollback(),
        ))
    }

    fn observe_closed(&mut self) {
        if self.group.poll() != controller::DrainStatus::Drained {
            self.uncertain = true;
        }
    }
}
