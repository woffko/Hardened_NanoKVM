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
fn a_failed_onboarding_is_final_and_never_retried_as_superseded() {
    assert!(matches!(
        job_outcome(reply(JobCode::Ok, [1, 8, 1, 2]), ONBOARD_JOB_KIND),
        Ok(JobDone::Done)
    ));
    for runtime in [1, 2, 6] {
        assert!(matches!(
            job_outcome(reply(JobCode::Ok, [1, 8, 3, runtime]), ONBOARD_JOB_KIND),
            Err(AppError::Config(_))
        ));
    }
}

#[test]
fn only_a_changed_or_noop_receipt_of_the_same_kind_counts_as_done() {
    for (kind, other) in [
        (MODEL_JOB_KIND, STARTUP_JOB_KIND),
        (STARTUP_JOB_KIND, MODEL_JOB_KIND),
    ] {
        for (outcome, runtime) in [(1, 2), (1, 3), (1, 4), (1, 6), (2, 1), (2, 6)] {
            assert!(matches!(
                job_outcome(reply(JobCode::Ok, [kind, 8, outcome, runtime]), kind),
                Ok(JobDone::Done)
            ));
            // Another kind's receipt is never this job's result.
            assert!(matches!(
                job_outcome(reply(JobCode::Ok, [other, 8, outcome, runtime]), kind),
                Err(AppError::Internal(_))
            ));
        }
        // Superseded before apply: Failed with NotRequested is retried once.
        assert!(matches!(
            job_outcome(reply(JobCode::Ok, [kind, 8, 3, 2]), kind),
            Ok(JobDone::Superseded)
        ));
        // A refusal is final and never reported as success.
        for runtime in [1, 6] {
            assert!(matches!(
                job_outcome(reply(JobCode::Ok, [kind, 8, 3, runtime]), kind),
                Err(AppError::Config(_))
            ));
        }
        for code in [JobCode::Busy, JobCode::RecoveryRequired] {
            assert!(matches!(
                job_outcome(reply(code, [0; 4]), kind),
                Err(AppError::Conflict(_))
            ));
        }
        for (code, receipt) in [
            (JobCode::Ok, [kind, 7, 1, 2]),
            (JobCode::Ok, [kind, 8, 4, 2]),
            (JobCode::Pending, [0; 4]),
            (JobCode::Expired, [0; 4]),
            (JobCode::Rejected, [0; 4]),
            (JobCode::Invalid, [0; 4]),
            (JobCode::Unavailable, [0; 4]),
        ] {
            assert!(matches!(
                job_outcome(reply(code, receipt), kind),
                Err(AppError::Internal(_))
            ));
        }
    }
}
