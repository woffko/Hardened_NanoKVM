use super::*;
use crate::native_owner::broker::ipc::{JobCode, JobReply};

fn reply(code: JobCode, receipt: [u8; 4]) -> JobReply {
    JobReply {
        code,
        epoch: [1; 16],
        sequence: 1,
        nonce: [2; 16],
        receipt,
    }
}

#[test]
fn only_a_changed_or_noop_startup_receipt_counts_as_done() {
    for receipt in [[3, 8, 1, 2], [3, 8, 1, 3], [3, 8, 2, 1], [3, 8, 2, 6]] {
        assert!(matches!(
            startup_job_outcome(reply(JobCode::Ok, receipt)),
            Ok(StartupJob::Done)
        ));
    }
    // Superseded before apply: Failed with NotRequested is retried once.
    assert!(matches!(
        startup_job_outcome(reply(JobCode::Ok, [3, 8, 3, 2])),
        Ok(StartupJob::Superseded)
    ));
    // A refusal is final and never reported as success.
    for receipt in [[3, 8, 3, 1], [3, 8, 3, 6]] {
        assert!(matches!(
            startup_job_outcome(reply(JobCode::Ok, receipt)),
            Err(AppError::Config(_))
        ));
    }
    for code in [JobCode::Busy, JobCode::RecoveryRequired] {
        assert!(matches!(
            startup_job_outcome(reply(code, [0; 4])),
            Err(AppError::Conflict(_))
        ));
    }
    // Any other kind, phase or reply is not a Startup result.
    for (code, receipt) in [
        (JobCode::Ok, [2, 8, 1, 2]),
        (JobCode::Ok, [3, 7, 1, 2]),
        (JobCode::Ok, [3, 8, 4, 2]),
        (JobCode::Pending, [0; 4]),
        (JobCode::Expired, [0; 4]),
        (JobCode::Rejected, [0; 4]),
        (JobCode::Invalid, [0; 4]),
        (JobCode::Unavailable, [0; 4]),
    ] {
        assert!(matches!(
            startup_job_outcome(reply(code, receipt)),
            Err(AppError::Internal(_))
        ));
    }
}
