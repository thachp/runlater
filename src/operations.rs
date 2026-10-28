//! Payload-free operational views over one tenant's authoritative default queue.
use crate::core::{Ledger, Status, Task};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
pub const AUDIT_CAP: usize = 256;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    TransportObserved,
    TransportReconciled,
    AttemptBudgetExhausted,
    Accepted,
    Redriven,
    CancelRequested,
    Claimed,
    Finished,
    LeaseExpired,
    AgeExpired,
    Configured,
    Retention,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub sequence: u64,
    pub at_ms: i64,
    pub kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<FailureCategory>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    Timeout,
    LeaseExpiredUnknown,
    RetryableHttp,
    PermanentHttp,
    Unknown,
}
pub fn failure(outcome: &str) -> Option<FailureCategory> {
    match outcome {
        "timeout" | "http_408" => Some(FailureCategory::Timeout),
        "lease_expired_unknown" => Some(FailureCategory::LeaseExpiredUnknown),
        s => match s.strip_prefix("http_").and_then(|s| s.parse::<u16>().ok()) {
            Some(200..=299) => None,
            Some(425 | 429 | 500..=599) => Some(FailureCategory::RetryableHttp),
            Some(100..=599) => Some(FailureCategory::PermanentHttp),
            _ => Some(FailureCategory::Unknown),
        },
    }
}
pub fn inspection(t: &Task) -> Value {
    json!({"id":t.id,"status":t.status,"due_ms":t.due_ms,"initial_due_ms":t.initial_due_ms,"generation":t.generation,"fence":t.fence,"lease_until":t.lease_until,"cancel_requested":t.cancel_requested,"terminal_ms":t.terminal_ms,"parent":t.parent,"attempts":t.attempts})
}
pub fn health(l: &Ledger, now: i64) -> Value {
    let mut states: BTreeMap<&str, usize> = [
        "scheduled",
        "ready",
        "running",
        "retry_wait",
        "succeeded",
        "failed",
        "cancelled",
    ]
    .into_iter()
    .map(|s| (s, 0))
    .collect();
    let (
        mut eligible,
        mut retry_due,
        mut future,
        mut active_lease,
        mut expired_lease,
        mut missing_lease,
    ) = (0, 0, 0, 0, 0, 0);
    let mut oldest: Option<i64> = None;
    let mut failures: BTreeMap<FailureCategory, usize> = BTreeMap::new();
    let mut attempts = 0;
    let mut finished = 0;
    let mut failed_without_attempt = 0;
    for t in l.tasks.values() {
        let name = match t.status {
            Status::Scheduled => "scheduled",
            Status::Ready => "ready",
            Status::Running => "running",
            Status::RetryWait => "retry_wait",
            Status::Succeeded => "succeeded",
            Status::Failed => "failed",
            Status::Cancelled => "cancelled",
        };
        *states.get_mut(name).unwrap() += 1;
        if matches!(
            t.status,
            Status::Scheduled | Status::Ready | Status::RetryWait
        ) {
            if t.due_ms <= now {
                eligible += 1;
                oldest = Some(oldest.map_or(t.due_ms, |n| n.min(t.due_ms)));
                if !t.attempts.is_empty() {
                    retry_due += 1;
                }
            } else {
                future += 1;
            }
        }
        if t.status == Status::Running {
            match t.lease_until {
                Some(at) if at > now => active_lease += 1,
                Some(_) => expired_lease += 1,
                None => missing_lease += 1,
            }
        }
        if t.status == Status::Failed && t.attempts.is_empty() {
            failed_without_attempt += 1;
        }
        for a in &t.attempts {
            attempts += 1;
            if let Some(o) = &a.outcome {
                finished += 1;
                if let Some(c) = failure(o) {
                    *failures.entry(c).or_default() += 1;
                }
            }
        }
    }
    json!({"paused":l.limits.paused,"sampled_at_ms":now,"counts_by_state":states,"eligible_backlog":eligible,"due_retry_backlog":retry_due,"future_backlog":future,"oldest_eligible_due_ms":oldest,"oldest_eligible_age_ms":oldest.map(|at|now.saturating_sub(at).max(0)),"active_leases":active_lease,"expired_leases":expired_lease,"missing_leases":missing_lease,"retained_attempts":attempts,"finished_attempts":finished,"attempt_failures_by_category":failures,"failed_tasks_without_attempts":failed_without_attempt,"retained_tasks":l.tasks.len(),"retained_audit_events":l.audit.len()})
}
#[derive(Default, Debug, Serialize, PartialEq, Eq)]
pub struct RetentionReport {
    pub transport_records_removed: usize,
    pub tasks_removed: usize,
    pub enqueue_keys_removed: usize,
    pub redrive_keys_removed: usize,
    pub audit_events_removed: usize,
}
