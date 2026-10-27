//! Deterministic ledger transitions. Runtime persists one atomic SQLite snapshot per tenant.
use crate::security::digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const DAY: i64 = 86_400_000;
pub const LEASE: i64 = 30_000;
pub const RETENTION: i64 = 30 * DAY;
pub const MAX_ATTEMPTS: u32 = 5;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub destination: String,
    pub body: String,
    #[serde(default)]
    pub run_at_ms: i64,
    pub operation_key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Scheduled,
    Ready,
    Running,
    RetryWait,
    Succeeded,
    Failed,
    Cancelled,
}
impl Status {
    pub fn terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attempt {
    pub fence: u64,
    pub started_ms: i64,
    pub finished_ms: Option<i64>,
    pub outcome: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub input: Create,
    pub status: Status,
    pub due_ms: i64,
    #[serde(default)]
    pub initial_due_ms: i64,
    pub generation: u64,
    pub fence: u64,
    pub lease_until: Option<i64>,
    pub cancel_requested: bool,
    pub terminal_ms: Option<i64>,
    pub attempts: Vec<Attempt>,
    pub parent: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dedupe {
    pub fingerprint: String,
    pub task: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dispatch {
    pub tenant: String,
    pub id: String,
    pub generation: u64,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Ledger {
    pub tasks: BTreeMap<String, Task>,
    pub dedupe: BTreeMap<String, Dedupe>,
    pub sequence: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Fault {
    Invalid,
    Conflict,
    NotFound,
    Capacity,
    Stale,
}
#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Http(u16),
    Timeout,
    LeaseExpired,
}
impl Ledger {
    pub fn create(&mut self, key: &str, input: Create, now: i64) -> Result<(Task, bool), Fault> {
        if input.operation_key.is_empty()
            || input.operation_key.len() > 128
            || !input
                .operation_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || key.is_empty()
            || key.len() > 128
            || input.body.len() > 16 * 1024
            || input.run_at_ms < 0
            || input.run_at_ms > now + 365 * DAY
        {
            return Err(Fault::Invalid);
        }
        let fingerprint = digest(&serde_json::to_vec(&input).map_err(|_| Fault::Invalid)?);
        if let Some(d) = self.dedupe.get(key) {
            if d.fingerprint != fingerprint {
                return Err(Fault::Conflict);
            }
            return Ok((
                self.tasks.get(&d.task).ok_or(Fault::Conflict)?.clone(),
                false,
            ));
        }
        if self.tasks.len() >= 1000
            || self
                .tasks
                .values()
                .map(|t| t.input.body.len())
                .sum::<usize>()
                + input.body.len()
                > 128 * 1024
        {
            return Err(Fault::Capacity);
        }
        self.sequence += 1;
        let id = format!("task_{:016x}", self.sequence);
        let task = Task {
            id: id.clone(),
            due_ms: input.run_at_ms.max(now),
            initial_due_ms: input.run_at_ms.max(now),
            status: if input.run_at_ms > now {
                Status::Scheduled
            } else {
                Status::Ready
            },
            input,
            generation: 1,
            fence: 0,
            lease_until: None,
            cancel_requested: false,
            terminal_ms: None,
            attempts: vec![],
            parent: None,
        };
        self.dedupe.insert(
            key.into(),
            Dedupe {
                fingerprint,
                task: id.clone(),
            },
        );
        self.tasks.insert(id, task.clone());
        Ok((task, true))
    }
    pub fn get(&self, id: &str) -> Result<Task, Fault> {
        self.tasks.get(id).cloned().ok_or(Fault::NotFound)
    }
    pub fn cancel(&mut self, id: &str, now: i64) -> Result<Task, Fault> {
        let t = self.tasks.get_mut(id).ok_or(Fault::NotFound)?;
        if !t.status.terminal() {
            t.cancel_requested = true;
            if t.status != Status::Running {
                t.status = Status::Cancelled;
                t.terminal_ms = Some(now);
            }
        }
        Ok(t.clone())
    }
    pub fn redrive(&mut self, id: &str, key: &str, now: i64) -> Result<(Task, bool), Fault> {
        let old = self.get(id)?;
        if old.status != Status::Failed {
            return Err(Fault::Conflict);
        }
        if key.is_empty() || key.len() > 64 {
            return Err(Fault::Invalid);
        }
        let full_key = format!("redrive:{id}:{key}");
        if let Some(d) = self.dedupe.get(&full_key) {
            return Ok((self.get(&d.task)?, false));
        }
        // Include parent in the key namespace and fingerprint, preserving explicit execution identity.
        let (mut t, created) = self.create(
            &full_key,
            Create {
                run_at_ms: now,
                ..old.input
            },
            now,
        )?;
        if created {
            t.parent = Some(id.into());
            self.tasks.insert(t.id.clone(), t.clone());
        }
        Ok((t, created))
    }
    pub fn reconcile(&mut self, now: i64) {
        for t in self.tasks.values_mut() {
            if t.status == Status::Running && t.lease_until.is_some_and(|x| x <= now) {
                Self::settle(t, Outcome::LeaseExpired, now);
            }
            if matches!(t.status, Status::Scheduled | Status::RetryWait) && t.due_ms <= now {
                t.status = Status::Ready;
            }
        }
    }
    // The persisted eligible rows are the outbox. Republish until a claim, including uncertain sends.
    pub fn outbox(&mut self, tenant: &str, now: i64) -> Vec<Dispatch> {
        self.reconcile(now);
        self.tasks
            .values()
            .filter(|t| t.status == Status::Ready && t.due_ms <= now)
            .take(32)
            .map(|t| Dispatch {
                tenant: tenant.into(),
                id: t.id.clone(),
                generation: t.generation,
            })
            .collect()
    }
    pub fn claim(&mut self, d: &Dispatch, now: i64) -> Result<Option<Task>, Fault> {
        self.reconcile(now);
        // Conservative per-tenant concurrency cap. Every retry also needs this permit.
        let busy = self
            .tasks
            .values()
            .filter(|t| t.status == Status::Running)
            .count()
            >= 4;
        let t = self.tasks.get_mut(&d.id).ok_or(Fault::NotFound)?;
        if t.generation != d.generation || t.status != Status::Ready || t.due_ms > now {
            return Ok(None);
        }
        if busy {
            return Err(Fault::Capacity);
        }
        if now - t.initial_due_ms > DAY {
            t.status = Status::Failed;
            t.terminal_ms = Some(now);
            return Ok(None);
        }
        t.status = Status::Running;
        t.fence += 1;
        t.lease_until = Some(now + LEASE);
        t.attempts.push(Attempt {
            fence: t.fence,
            started_ms: now,
            finished_ms: None,
            outcome: None,
        });
        Ok(Some(t.clone()))
    }
    pub fn finish(
        &mut self,
        id: &str,
        fence: u64,
        outcome: Outcome,
        now: i64,
    ) -> Result<Task, Fault> {
        let t = self.tasks.get_mut(id).ok_or(Fault::NotFound)?;
        if t.status != Status::Running || t.fence != fence || t.lease_until.is_none_or(|x| x <= now)
        {
            return Err(Fault::Stale);
        }
        Self::settle(t, outcome, now);
        Ok(t.clone())
    }
    fn settle(t: &mut Task, outcome: Outcome, now: i64) {
        let success = matches!(outcome, Outcome::Http(200..=299));
        let retry = matches!(
            outcome,
            Outcome::Timeout | Outcome::LeaseExpired | Outcome::Http(408 | 425 | 429 | 500..=599)
        );
        if let Some(a) = t.attempts.last_mut() {
            a.finished_ms = Some(now);
            a.outcome = Some(match outcome {
                Outcome::Http(s) => format!("http_{s}"),
                Outcome::Timeout => "timeout".into(),
                Outcome::LeaseExpired => "lease_expired_unknown".into(),
            });
        }
        t.lease_until = None;
        t.status = if success {
            Status::Succeeded
        } else if t.cancel_requested {
            Status::Cancelled
        } else if retry
            && t.attempts.len() < (MAX_ATTEMPTS as usize)
            && now - t.initial_due_ms < DAY
        {
            Status::RetryWait
        } else {
            Status::Failed
        };
        if t.status == Status::RetryWait {
            let base = 1000i64 << t.attempts.len().min(10);
            let jitter = (t.fence as i64 * 137) % 1000;
            t.due_ms = now + base.min(60_000) + jitter;
            t.generation += 1;
        } else {
            t.terminal_ms = Some(now);
        }
    }
    pub fn next_wake(&self, now: i64) -> Option<i64> {
        self.tasks
            .values()
            .filter_map(|t| match t.status {
                Status::Running => t.lease_until,
                Status::Ready => Some(now + 1000),
                Status::Scheduled | Status::RetryWait => Some(t.due_ms.max(now + 1)),
                _ => t.terminal_ms.map(|x| x + RETENTION),
            })
            .min()
    }
    pub fn purge(&mut self, now: i64) {
        self.tasks
            .retain(|_, t| t.terminal_ms.is_none_or(|x| x + RETENTION > now));
        self.dedupe.retain(|_, d| self.tasks.contains_key(&d.task));
    }
}
