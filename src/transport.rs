//! Diagnostic dead-letter references, never a second task ledger or payload replay queue.
use crate::{
    core::{Dispatch, Fault, Ledger, Status, DAY, MAX_ATTEMPTS, RETENTION},
    security::{digest, task_id_valid, tenant_valid},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
pub const CAPACITY: usize = 128;
pub const MAX_GENERATION: u64 = 9_007_199_254_740_991;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub task_id: String,
    pub generation: u64,
}
impl Reference {
    pub fn valid(&self) -> bool {
        task_id_valid(&self.task_id) && self.generation > 0 && self.generation <= MAX_GENERATION
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Missing,
    StaleGeneration,
    Succeeded,
    Failed,
    Cancelled,
    InFlight,
    LeaseAwaitingReconciliation,
    Waiting,
    ReadyOutbox,
    AgeExhausted,
    AttemptBudgetExhausted,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    OutboxConfirmed,
    LeasePreserved,
    SchedulePreserved,
    NoRecovery,
    BudgetExpired,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub at_ms: i64,
    pub actor_label: String,
    pub classification: Classification,
    pub action: Action,
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    record_id: String,
    tenant: String,
    reference: Reference,
    observed_at_ms: i64,
    operator_reported: bool,
    transport_observed: bool,
    observed_classification: Classification,
    reconciliation: Option<Receipt>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct State {
    records: BTreeMap<String, Record>,
    evicted: u64,
}
impl State {
    pub fn next_wake(&self) -> Option<i64> {
        self.records
            .values()
            .map(|r| r.observed_at_ms.saturating_add(RETENTION))
            .min()
    }
    pub fn purge(&mut self, now: i64) -> usize {
        let before = self.records.len();
        self.records
            .retain(|_, r| r.observed_at_ms.saturating_add(RETENTION) > now);
        before - self.records.len()
    }
}
pub fn valid_id(id: &str) -> bool {
    id.len() == 68
        && id.starts_with("dlq_")
        && id[4..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_dispatch(d: &Dispatch) -> bool {
    tenant_valid(&d.tenant)
        && Reference {
            task_id: d.id.clone(),
            generation: d.generation,
        }
        .valid()
}
fn label(tenant: &str, actor: &str) -> Result<String, Fault> {
    if !tenant_valid(tenant)
        || actor.is_empty()
        || actor.len() > 80
        || !actor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(Fault::Invalid);
    }
    Ok(digest(
        &serde_json::to_vec(&("transport_actor_v1", tenant, actor)).map_err(|_| Fault::Invalid)?,
    ))
}
pub fn classify(ledger: &Ledger, r: &Reference, now: i64) -> Classification {
    let Some(task) = ledger.tasks.get(&r.task_id) else {
        return Classification::Missing;
    };
    if task.generation != r.generation {
        return Classification::StaleGeneration;
    }
    match task.status {
        Status::Succeeded => Classification::Succeeded,
        Status::Failed => Classification::Failed,
        Status::Cancelled => Classification::Cancelled,
        Status::Running => {
            if task.lease_until.is_some_and(|at| at > now) {
                Classification::InFlight
            } else {
                Classification::LeaseAwaitingReconciliation
            }
        }
        _ => {
            if task.attempts.len() >= MAX_ATTEMPTS as usize {
                Classification::AttemptBudgetExhausted
            } else if now.saturating_sub(task.initial_due_ms) > DAY {
                Classification::AgeExhausted
            } else if task.due_ms > now {
                Classification::Waiting
            } else {
                Classification::ReadyOutbox
            }
        }
    }
}
impl Ledger {
    fn transport_view(&self, id: &str, now: i64) -> Result<Value, Fault> {
        let r = self.dead_letters.records.get(id).ok_or(Fault::NotFound)?;
        let task = self.tasks.get(&r.reference.task_id);
        Ok(
            json!({"record_id":r.record_id,"reference":r.reference,"observed_at_ms":r.observed_at_ms,"operator_reported":r.operator_reported,"transport_observed":r.transport_observed,"observed_classification":r.observed_classification,"reconciliation":r.reconciliation,"current_classification":classify(self,&r.reference,now),"current_status":task.map(|t|&t.status),"current_generation":task.map(|t|t.generation)}),
        )
    }
    pub fn transport_record(&self, id: &str, now: i64) -> Result<Value, Fault> {
        if !valid_id(id) {
            return Err(Fault::NotFound);
        }
        self.transport_view(id, now)
    }
    pub fn transport_records(&self, after: &str, now: i64) -> Result<Value, Fault> {
        if !after.is_empty() && !valid_id(after) {
            return Err(Fault::Invalid);
        }
        let ids: Vec<_> = self
            .dead_letters
            .records
            .keys()
            .filter(|id| id.as_str() > after)
            .take(51)
            .collect();
        let more = ids.len() > 50;
        let records: Vec<_> = ids
            .iter()
            .take(50)
            .map(|id| self.transport_view(id, now))
            .collect::<Result<_, _>>()?;
        let next = if more {
            ids.get(49).map(|s| s.to_string())
        } else {
            None
        };
        Ok(
            json!({"records":records,"next_after":next,"capacity":CAPACITY,"evicted_records":self.dead_letters.evicted,"sampled_at_ms":now}),
        )
    }
    pub fn report_transport(
        &mut self,
        tenant: &str,
        r: Reference,
        now: i64,
    ) -> Result<(Value, bool, bool), Fault> {
        self.observe_transport(tenant, r, false, now)
    }
    pub fn receive_dead_letter(
        &mut self,
        tenant: &str,
        d: &Dispatch,
        now: i64,
    ) -> Result<(Value, bool, bool), Fault> {
        if d.tenant != tenant {
            return Err(Fault::Forbidden);
        }
        self.observe_transport(
            tenant,
            Reference {
                task_id: d.id.clone(),
                generation: d.generation,
            },
            true,
            now,
        )
    }
    fn observe_transport(
        &mut self,
        tenant: &str,
        reference: Reference,
        transport: bool,
        now: i64,
    ) -> Result<(Value, bool, bool), Fault> {
        if !tenant_valid(tenant) || !reference.valid() || now < 0 {
            return Err(Fault::Invalid);
        }
        let id = format!(
            "dlq_{}",
            digest(
                &serde_json::to_vec(&(
                    "transport_ref_v1",
                    tenant,
                    &reference.task_id,
                    reference.generation
                ))
                .map_err(|_| Fault::Invalid)?
            )
        );
        let classification = classify(self, &reference, now);
        let created = !self.dead_letters.records.contains_key(&id);
        let changed;
        if let Some(record) = self.dead_letters.records.get_mut(&id) {
            if record.tenant != tenant {
                return Err(Fault::Forbidden);
            }
            changed = if transport {
                !record.transport_observed
            } else {
                !record.operator_reported
            };
            if transport {
                record.transport_observed = true
            } else {
                record.operator_reported = true
            }
        } else {
            if self.dead_letters.records.len() >= CAPACITY {
                let oldest = self
                    .dead_letters
                    .records
                    .values()
                    .min_by_key(|r| (r.observed_at_ms, &r.record_id))
                    .map(|r| r.record_id.clone())
                    .ok_or(Fault::Invalid)?;
                self.dead_letters.records.remove(&oldest);
                self.dead_letters.evicted = self
                    .dead_letters
                    .evicted
                    .saturating_add(1)
                    .min(crate::metrics::MAX_COUNT);
            }
            self.dead_letters.records.insert(
                id.clone(),
                Record {
                    record_id: id.clone(),
                    tenant: tenant.into(),
                    reference: reference.clone(),
                    observed_at_ms: now,
                    operator_reported: !transport,
                    transport_observed: transport,
                    observed_classification: classification,
                    reconciliation: None,
                },
            );
            changed = true;
        }
        if changed {
            self.record(
                now,
                crate::operations::EventKind::TransportObserved,
                Some(reference.task_id),
                None,
            );
        }
        Ok((self.transport_view(&id, now)?, created, !changed))
    }
    pub fn reconcile_transport(
        &mut self,
        tenant: &str,
        id: &str,
        actor: &str,
        now: i64,
    ) -> Result<(Value, bool), Fault> {
        let actor_label = label(tenant, actor)?;
        if !valid_id(id) || now < 0 {
            return Err(Fault::Invalid);
        }
        let record = self
            .dead_letters
            .records
            .get(id)
            .cloned()
            .ok_or(Fault::NotFound)?;
        if record.tenant != tenant {
            return Err(Fault::Forbidden);
        }
        if record.reconciliation.is_some() {
            return Ok((self.transport_view(id, now)?, true));
        }
        self.reconcile(now);
        let classification = classify(self, &record.reference, now);
        let action = match classification {
            Classification::ReadyOutbox => Action::OutboxConfirmed,
            Classification::InFlight | Classification::LeaseAwaitingReconciliation => {
                Action::LeasePreserved
            }
            Classification::Waiting => Action::SchedulePreserved,
            Classification::AgeExhausted | Classification::AttemptBudgetExhausted => {
                let task = self
                    .tasks
                    .get_mut(&record.reference.task_id)
                    .ok_or(Fault::NotFound)?;
                task.status = Status::Failed;
                task.terminal_ms = Some(now);
                self.record(
                    now,
                    if classification == Classification::AgeExhausted {
                        crate::operations::EventKind::AgeExpired
                    } else {
                        crate::operations::EventKind::AttemptBudgetExhausted
                    },
                    Some(record.reference.task_id.clone()),
                    None,
                );
                Action::BudgetExpired
            }
            _ => Action::NoRecovery,
        };
        self.dead_letters
            .records
            .get_mut(id)
            .ok_or(Fault::NotFound)?
            .reconciliation = Some(Receipt {
            at_ms: now,
            actor_label,
            classification,
            action,
        });
        self.record(
            now,
            crate::operations::EventKind::TransportReconciled,
            Some(record.reference.task_id),
            None,
        );
        Ok((self.transport_view(id, now)?, false))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueRole {
    Ready,
    DeadLetter,
}
pub fn queue_role(name: &str, ready: &str, dead: &str) -> Option<QueueRole> {
    if name.is_empty() || ready.is_empty() || ready == dead {
        return None;
    }
    if name == ready {
        Some(QueueRole::Ready)
    } else if !dead.is_empty() && name == dead {
        Some(QueueRole::DeadLetter)
    } else {
        None
    }
}
