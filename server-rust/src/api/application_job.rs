//! Authenticated, transaction-bound diagnostics only. No install/retry authority
//! or runtime-health assertion is obtained from a canonical phase observation.
use axum::{
    Json,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::{
    error::ApiResponse,
    state::AppState,
    update::app_slot::{self, JobStatus, SlotError},
};

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "camelCase")]
enum Observation {
    Observed {
        phase: &'static str,
        version: String,
        archived: bool,
        #[serde(rename = "inactivePayloadRetained")]
        inactive_payload_retained: bool,
    },
    Busy,
    UnknownOrExpired,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobResponse {
    transaction_id: String,
    #[serde(flatten)]
    observation: Observation,
}

fn parse_id(raw: &str) -> Option<[u8; 16]> {
    if raw.len() != 32 {
        return None;
    }
    let mut id = [0; 16];
    for (pair, byte) in raw.as_bytes().as_chunks::<2>().0.iter().zip(&mut id) {
        let digit = |b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        };
        *byte = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    (id != [0; 16]).then_some(id)
}

fn no_store<T: Serialize>(status: StatusCode, body: ApiResponse<T>) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

pub async fn status(State(state): State<AppState>, Path(transaction): Path<String>) -> Response {
    // Unit-only root injection exercises the real authenticated route against
    // disposable canonical records, never the host's fixed production root.
    #[cfg(test)]
    if let Some(root) = state.app_job_test_root {
        return query(transaction, state.app_job_reads, move |id| {
            app_slot::job_status_fixture(&root, id)
        })
        .await;
    }
    query(transaction, state.app_job_reads, app_slot::job_status).await
}

async fn query<F>(transaction: String, slots: Arc<Semaphore>, lookup: F) -> Response
where
    F: FnOnce([u8; 16]) -> std::result::Result<Option<JobStatus>, SlotError> + Send + 'static,
{
    let Some(id) = parse_id(&transaction) else {
        return no_store(
            StatusCode::BAD_REQUEST,
            ApiResponse::<()>::err(-1, "invalid app update transaction ID"),
        );
    };
    // No queue, update admission or writer permit is acquired for diagnostics.
    // The blocking read owns its permit even after the HTTP waiter disappears.
    let Ok(permit) = slots.try_acquire_owned() else {
        return no_store(
            StatusCode::TOO_MANY_REQUESTS,
            ApiResponse::<()>::err(-429, "app job status capacity is busy"),
        );
    };
    let read = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        lookup(id)
    })
    .await;
    let observation = match read {
        Ok(Ok(Some(status))) if status.transaction == id => Observation::Observed {
            phase: status.phase.label(),
            version: status.version,
            archived: status.archived,
            inactive_payload_retained: status.inactive_payload_retained,
        },
        Ok(Ok(None)) => Observation::UnknownOrExpired,
        Ok(Err(SlotError::Busy)) => Observation::Busy,
        // Do not turn corruption, an unsafe layout, I/O or worker loss into
        // absence/success. Never return private paths or raw error text.
        _ => {
            return no_store(
                StatusCode::SERVICE_UNAVAILABLE,
                ApiResponse::<()>::err(-503, "app job status is unavailable"),
            );
        }
    };
    no_store(
        StatusCode::OK,
        ApiResponse::ok(JobResponse {
            transaction_id: transaction,
            observation,
        }),
    )
}

#[cfg(test)]
#[path = "application_job_tests.rs"]
mod tests;
