//! Opt-in disposable staging policy. This is not arbitrary-destination SSRF protection.
use crate::{
    core::Create,
    security::{sign, verify},
};
use serde::Deserialize;
use subtle::ConstantTimeEq;
pub const MAX_TASKS: usize = 12;
pub const MAX_PUBLISH: u32 = 128;
pub const MAX_BODY: usize = 256;
pub const TIMEOUT_MS: u64 = 3000;
pub fn valid_secret(secret: &str) -> bool {
    secret.len() == 64
        && secret
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn gate(expected: &str, supplied: &str, expires_ms: i64, now: i64) -> bool {
    valid_secret(expected)
        && now < expires_ms
        && expires_ms > 0
        && expires_ms.saturating_sub(now) <= 900_000
        && supplied.len() == 64
        && expected.as_bytes().ct_eq(supplied.as_bytes()).unwrap_u8() == 1
}
pub fn run_id_valid(run: &str) -> bool {
    !run.is_empty()
        && run.len() <= 24
        && run
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Synthetic {
    pub run: String,
    pub case: String,
    pub synthetic: bool,
}
pub fn synthetic(body: &str, run: &str) -> Option<Synthetic> {
    if body.len() > MAX_BODY || !run_id_valid(run) {
        return None;
    }
    let s: Synthetic = serde_json::from_str(body).ok()?;
    if s.run != run
        || !s.synthetic
        || !matches!(
            s.case.as_str(),
            "initial" | "scheduled" | "receiver" | "retry" | "cancel"
        )
    {
        return None;
    }
    Some(s)
}
pub fn input_allowed(input: &Create, run: &str, now: i64) -> bool {
    let Some(body) = synthetic(&input.body, run) else {
        return false;
    };
    input.run_at_ms >= 0
        && input.run_at_ms <= now + 30_000
        && input.operation_key == format!("run_{run}_{}", body.case)
        && matches!(
            input.destination.as_str(),
            "fixture://success" | "fixture://retry" | "fixture://fail" | "staging://receiver"
        )
}
pub fn receiver_url_allowed(url: &str, host: &str, run: &str) -> bool {
    if !run_id_valid(run) {
        return false;
    }
    let prefix = format!("runlater-staging-{run}-receiver.");
    let Some(account) = host
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix(".workers.dev"))
    else {
        return false;
    };
    !account.is_empty()
        && account.len() <= 63
        && account
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && url == format!("https://{host}/callback")
}
pub fn receipt(secret: &str, timestamp: i64, task: &str, operation: &str, body: &[u8]) -> String {
    sign(
        secret.as_bytes(),
        timestamp,
        &format!("receipt:{task}"),
        operation,
        body,
    )
}
pub fn verify_receipt(
    secret: &str,
    timestamp: i64,
    task: &str,
    operation: &str,
    body: &[u8],
    value: &str,
    now: i64,
) -> bool {
    valid_secret(secret)
        && verify(
            secret.as_bytes(),
            timestamp,
            &format!("receipt:{task}"),
            operation,
            body,
            value,
            now,
        )
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageRoute {
    Enqueue,
    List,
    Task,
    Attempts,
    Cancel,
}
/// Staging accepts canonical paths only. Do not trim slashes or decode aliases here.
/// URL-layer normalization (for example dot segments) is still subject to typed command validation.
pub fn canonical_route(method: &str, path: &str) -> Option<StageRoute> {
    let segments: Vec<_> = path.strip_prefix('/')?.split('/').collect();
    match (method, segments.as_slice()) {
        ("POST", ["v1", "tasks"]) => Some(StageRoute::Enqueue),
        ("GET", ["v1", "tasks"]) => Some(StageRoute::List),
        ("GET", ["v1", "tasks", id]) if crate::security::task_id_valid(id) => {
            Some(StageRoute::Task)
        }
        ("GET", ["v1", "tasks", id, "attempts"]) if crate::security::task_id_valid(id) => {
            Some(StageRoute::Attempts)
        }
        ("POST", ["v1", "tasks", id, "cancel"]) if crate::security::task_id_valid(id) => {
            Some(StageRoute::Cancel)
        }
        _ => None,
    }
}
pub fn api_route(method: &str, path: &str) -> bool {
    canonical_route(method, path).is_some()
}
/// Enforce the campaign envelope on the parsed mutation, independent of route spelling.
pub fn command_allowed(command: &crate::application::Command, run: &str, now: i64) -> bool {
    match command {
        crate::application::Command::Enqueue { input, .. } => input_allowed(input, run, now),
        crate::application::Command::Cancel { .. } => true,
        _ => false,
    }
}

/// Fixed metadata only: never stores URLs, headers, receipts, signatures or bodies.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryDiagnostic {
    PolicyRejected,
    RedirectRejected,
    ResponseHeadersTooLarge,
    ResponseBodyTooLarge,
    ReceiverStatus(u16),
    ReceiptRejected,
    FetchError,
    Timeout,
    VerifiedReceipt,
}
