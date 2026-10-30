//! Bounded best-effort publication of an already persisted outbox selection.
//!
//! A send error is uncertain: the durable ready row stays replayable. It must
//! not prevent unrelated references later in the same selection from getting a
//! send attempt. Callers retain the watchdog and return the first error after
//! attempting the remaining references. This is not a Queue delivery guarantee.
use std::future::Future;

pub const BATCH_SIZE: usize = 32;

/// Attempt each selected reference once, sequentially, even after a send error.
/// The ledger bounds each selection to `BATCH_SIZE`; publication budgets may
/// truncate it further before the snapshot is committed. This function neither
/// retries nor replenishes those budgets and never changes authoritative state.
pub async fn publish_batch<T, E, F, Fut>(messages: Vec<T>, mut send: F) -> Result<(), E>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Result<(), E>>,
{
    let mut first_error = None;
    for message in messages {
        if let Err(error) = send(message).await {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}
