//! Disconnected fixture aggregate: task acceptance and finite funding share one commit.
//! No Worker dependency, HTTP route, identity issuer, payment adapter, or live activation.
use crate::{
    add, mul, positive, timestamp, Authority, Error, Intent, OfflineLedger, Policy, Receipt,
    SettlementVerifier,
};
use runlater::{
    core::{Create, Dispatch, Ledger, Outcome, Task},
    funding,
    security::tenant_valid,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const TRIAL_GRANT: &str = "trial_once";

/// Explicit fictional terms. No default duration, allowance, price, or currency.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrialTerms {
    pub task_allowance: u64,
    pub duration_ms: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Trial {
    terms: TrialTerms,
    started_at_ms: i64,
    grant: funding::GrantSpec,
    admitted_tasks: u64,
}
#[derive(Debug, Serialize)]
pub struct TaskAdmission {
    pub task_accepted: bool,
    pub funding_reserved: bool,
    pub created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<Task>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<AdmissionError>,
}
#[derive(Debug, Serialize)]
pub struct AdmissionError {
    pub code: &'static str,
}
impl TaskAdmission {
    fn payment_required() -> Self {
        Self {
            task_accepted: false,
            funding_reserved: false,
            created: false,
            task: None,
            error: Some(AdmissionError {
                code: "payment_required",
            }),
        }
    }
}
/// Sampled projection only. Never accepted as command authority or a reservation.
#[derive(Debug, Serialize)]
pub struct Balance {
    pub activation_enabled: bool,
    pub fixture_only: bool,
    pub revision: u64,
    pub sampled_at_ms: i64,
    pub available_attempt_units: u64,
    pub reserved_attempt_units: u64,
    pub spent_attempt_units: u64,
    pub retired_attempt_units: u64,
    pub admissible_tasks: u64,
    pub trial_tasks_remaining: u64,
}
/// Persist the ENTIRE snapshot with durable CAS on revision, not separate component writes.
/// Fields are private to prevent callers from committing funding or purchase state alone.
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "Snapshot")]
pub struct Entitlements {
    schema: u8,
    project_id: String,
    revision: u64,
    clock_ms: i64,
    trial: Option<Trial>,
    purchases: OfflineLedger,
    purchase_cursor: u64,
    funding_revision: u64,
    ledger: Ledger,
    funding: funding::State,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u8,
    project_id: String,
    revision: u64,
    clock_ms: i64,
    trial: Option<Trial>,
    purchases: OfflineLedger,
    purchase_cursor: u64,
    funding_revision: u64,
    ledger: Ledger,
    funding: funding::State,
}
impl TryFrom<Snapshot> for Entitlements {
    type Error = String;
    fn try_from(s: Snapshot) -> Result<Self, Self::Error> {
        let value = Self {
            schema: s.schema,
            project_id: s.project_id,
            revision: s.revision,
            clock_ms: s.clock_ms,
            trial: s.trial,
            purchases: s.purchases,
            purchase_cursor: s.purchase_cursor,
            funding_revision: s.funding_revision,
            ledger: s.ledger,
            funding: s.funding,
        };
        value
            .validate()
            .map_err(|_| "invalid entitlement snapshot".to_string())?;
        Ok(value)
    }
}

impl Entitlements {
    pub fn new(
        project: &str,
        trial: Option<TrialTerms>,
        purchase_policy: Option<Policy>,
        now: i64,
    ) -> Result<Self, Error> {
        if !tenant_valid(project) || !timestamp(now) {
            return Err(Error::Invalid);
        }
        let trial = trial
            .map(|terms| {
                if !positive(terms.task_allowance) || !timestamp(terms.duration_ms) {
                    return Err(Error::Invalid);
                }
                let expires = now
                    .checked_add(terms.duration_ms)
                    .filter(|t| timestamp(*t))
                    .ok_or(Error::Overflow)?;
                Ok(Trial {
                    started_at_ms: now,
                    grant: funding::GrantSpec {
                        grant_id: TRIAL_GRANT.into(),
                        total_attempt_units: mul(terms.task_allowance, funding::TASK_UNITS)?,
                        admission_expires_at_ms: expires,
                    },
                    terms,
                    admitted_tasks: 0,
                })
            })
            .transpose()?;
        let mut state = Self {
            schema: 1,
            project_id: project.into(),
            revision: 1,
            clock_ms: now,
            trial,
            purchases: OfflineLedger::new(project, purchase_policy)?,
            purchase_cursor: 0,
            funding_revision: 0,
            ledger: Ledger::default(),
            funding: funding::State::default(),
        };
        state.select(state.trial.as_ref().map(|t| t.grant.clone()), vec![], now)?;
        state.sync_purchases(now)?;
        state.validate()?;
        Ok(state)
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    fn check(&self, revision: u64, now: i64) -> Result<(), Error> {
        if revision != self.revision {
            return Err(Error::StaleRevision);
        }
        if !timestamp(now) || now < self.clock_ms {
            return Err(Error::ClockRegressed);
        }
        Ok(())
    }
    fn project(&self, project: &str) -> Result<(), Error> {
        if project != self.project_id {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    fn task_authority(&self, authority: Authority<'_>) -> Result<(), Error> {
        let Authority::Task { project, principal } = authority else {
            return Err(Error::Forbidden);
        };
        self.project(project)?;
        if !tenant_valid(principal) {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    fn commit(&mut self, mut next: Self, now: i64) -> Result<(), Error> {
        next.clock_ms = now;
        next.revision = add(self.revision, 1)?;
        next.validate()?;
        *self = next;
        Ok(())
    }
    fn select(
        &mut self,
        grant: Option<funding::GrantSpec>,
        revoked_grants: Vec<String>,
        now: i64,
    ) -> Result<(), Error> {
        self.funding_revision = add(self.funding_revision, 1)?;
        self.funding.apply(
            &funding::Policy {
                version: 1,
                project_id: self.project_id.clone(),
                revision: self.funding_revision,
                active_grant: grant,
                revoked_grants,
            },
            now,
        )?;
        Ok(())
    }
    /// Remap the purchase journal into this aggregate's own policy sequence. Trial installation
    /// and grant selection cannot collide with purchase revisions. Cursor and funding commit together.
    fn sync_purchases(&mut self, now: i64) -> Result<(), Error> {
        for update in self.purchases.funding_updates(self.purchase_cursor)? {
            self.select(update.active_grant, update.revoked_grants, now)?;
        }
        self.purchase_cursor = self.purchases.revision();
        self.funding.advance(now)?;
        Ok(())
    }
    fn grants(&self) -> BTreeMap<String, funding::GrantSpec> {
        let mut grants = BTreeMap::new();
        if let Some(t) = &self.trial {
            grants.insert(t.grant.grant_id.clone(), t.grant.clone());
        }
        for p in self.purchases.purchases.values() {
            if p.receipt.entitlement_order.is_some() {
                grants.insert(p.intent.id.clone(), p.intent.grant.clone());
            }
        }
        grants
    }
    fn candidate(&self) -> Option<funding::GrantSpec> {
        let usable = |spec: &funding::GrantSpec| {
            self.funding
                .grant(&spec.grant_id)
                .is_some_and(|g| !g.closed && g.available >= funding::TASK_UNITS)
        };
        if let Some(t) = &self.trial {
            if t.admitted_tasks < t.terms.task_allowance && usable(&t.grant) {
                return Some(t.grant.clone());
            }
        }
        self.grants()
            .into_values()
            .filter(|g| g.grant_id != TRIAL_GRANT && usable(g))
            .min_by(|a, b| {
                (a.admission_expires_at_ms, &a.grant_id)
                    .cmp(&(b.admission_expires_at_ms, &b.grant_id))
            })
    }
    fn admit(
        &mut self,
        revision: u64,
        authority: Authority<'_>,
        now: i64,
        command: impl FnOnce(&mut Ledger) -> Result<(Task, bool), runlater::core::Fault>,
    ) -> Result<TaskAdmission, Error> {
        self.check(revision, now)?;
        self.task_authority(authority)?;
        let mut next = self.clone();
        let (task, created) = command(&mut next.ledger)?;
        next.funding.advance(now)?;
        if created {
            let Some(grant) = next.candidate() else {
                // Remember observed expiry/monotonic time, but discard the attempted
                // task, sequence and deduplication change. A later clock rollback
                // must not reopen a trial observed expired before a restart.
                let mut observation = self.clone();
                observation.funding.advance(now)?;
                self.commit(observation, now)?;
                return Ok(TaskAdmission::payment_required());
            };
            if grant.grant_id == TRIAL_GRANT {
                next.trial.as_mut().ok_or(Error::Corrupt)?.admitted_tasks += 1;
            }
            next.select(Some(grant), vec![], now)?;
            next.funding.reserve(&next.project_id, &task.id, now)?;
        } else {
            next.funding.reservation(&task.id)?;
        }
        next.funding.settle_all(&next.ledger, now)?;
        self.commit(next, now)?;
        Ok(TaskAdmission {
            task_accepted: true,
            funding_reserved: true,
            created,
            task: Some(task),
            error: None,
        })
    }
    pub fn create(
        &mut self,
        revision: u64,
        authority: Authority<'_>,
        key: &str,
        input: Create,
        now: i64,
    ) -> Result<TaskAdmission, Error> {
        if !input
            .destination
            .strip_prefix("registered:")
            .is_some_and(tenant_valid)
        {
            return Err(Error::Invalid);
        }
        self.admit(revision, authority, now, |l| l.create(key, input, now))
    }
    pub fn redrive(
        &mut self,
        revision: u64,
        authority: Authority<'_>,
        id: &str,
        key: &str,
        now: i64,
    ) -> Result<TaskAdmission, Error> {
        self.admit(revision, authority, now, |l| l.redrive(id, key, now))
    }
    pub fn cancel(
        &mut self,
        revision: u64,
        authority: Authority<'_>,
        id: &str,
        now: i64,
    ) -> Result<Task, Error> {
        self.check(revision, now)?;
        self.task_authority(authority)?;
        let mut next = self.clone();
        next.funding.reservation(id)?;
        let task = next.ledger.cancel(id, now)?;
        next.funding.settle_all(&next.ledger, now)?;
        self.commit(next, now)?;
        Ok(task)
    }
    /// Trusted local driver only; this does not publish Queue work or perform an HTTP effect.
    /// Persist the resulting snapshot even on a task rate/concurrency error: reconciliation
    /// and terminal settlement may have committed before the claim was denied.
    pub fn claim(
        &mut self,
        revision: u64,
        dispatch: &Dispatch,
        now: i64,
    ) -> Result<Option<Task>, Error> {
        self.check(revision, now)?;
        self.project(&dispatch.tenant)?;
        self.ledger.get(&dispatch.id)?;
        let mut next = self.clone();
        next.ledger.reconcile(now);
        next.funding.settle_all(&next.ledger, now)?;
        let task = next.ledger.claim(dispatch, now);
        if let Ok(Some(t)) = &task {
            next.funding.spend(t, now)?;
        }
        next.funding.settle_all(&next.ledger, now)?;
        self.commit(next, now)?;
        Ok(task?)
    }
    pub fn finish(
        &mut self,
        revision: u64,
        project: &str,
        id: &str,
        fence: u64,
        outcome: Outcome,
        now: i64,
    ) -> Result<Task, Error> {
        self.check(revision, now)?;
        self.project(project)?;
        let mut next = self.clone();
        next.funding.reservation(id)?;
        let task = next.ledger.finish(id, fence, outcome, now)?;
        next.funding.settle_all(&next.ledger, now)?;
        self.commit(next, now)?;
        Ok(task)
    }
    pub fn create_intent(
        &mut self,
        revision: u64,
        authority: Authority<'_>,
        key: &str,
        packs: u64,
        now: i64,
    ) -> Result<Intent, Error> {
        self.check(revision, now)?;
        let mut next = self.clone();
        let intent =
            next.purchases
                .create_intent(next.purchases.revision(), authority, key, packs, now)?;
        // Reserve a lifetime funding identity before accepting a purchase intent.
        // An expired trial still consumes a slot; idempotent replay adds no slot.
        if next.purchases.purchases.len() + usize::from(next.trial.is_some()) > funding::MAX_GRANTS
        {
            return Err(Error::Capacity);
        }
        next.sync_purchases(now)?;
        self.commit(next, now)?;
        Ok(intent)
    }
    pub fn reconcile(
        &mut self,
        revision: u64,
        project: &str,
        id: &str,
        evidence: &[u8],
        verifier: &impl SettlementVerifier,
        now: i64,
    ) -> Result<Receipt, Error> {
        self.check(revision, now)?;
        self.project(project)?;
        let mut next = self.clone();
        let receipt = next.purchases.reconcile(
            next.purchases.revision(),
            project,
            id,
            evidence,
            verifier,
            now,
        )?;
        next.sync_purchases(now)?;
        self.commit(next, now)?;
        Ok(receipt)
    }
    pub fn task(&self, project: &str, id: &str) -> Result<Task, Error> {
        self.project(project)?;
        Ok(self.ledger.get(id)?)
    }
    pub fn reservation(&self, project: &str, id: &str) -> Result<&funding::Reservation, Error> {
        self.project(project)?;
        Ok(self.funding.reservation(id)?)
    }
    pub fn balance(&self, project: &str, now: i64) -> Result<Balance, Error> {
        self.project(project)?;
        self.check(self.revision, now)?;
        let mut view = self.funding.clone();
        view.advance(now)?;
        let mut b = Balance {
            activation_enabled: false,
            fixture_only: true,
            revision: self.revision,
            sampled_at_ms: now,
            available_attempt_units: 0,
            reserved_attempt_units: 0,
            spent_attempt_units: 0,
            retired_attempt_units: 0,
            admissible_tasks: 0,
            trial_tasks_remaining: 0,
        };
        for (id, _) in self.grants() {
            let g = view.grant(&id).ok_or(Error::Corrupt)?;
            b.available_attempt_units = add(b.available_attempt_units, g.available)?;
            b.reserved_attempt_units = add(b.reserved_attempt_units, g.reserved)?;
            b.spent_attempt_units = add(b.spent_attempt_units, g.spent)?;
            b.retired_attempt_units = add(b.retired_attempt_units, g.retired)?;
            let mut tasks = g.available / funding::TASK_UNITS;
            if id == TRIAL_GRANT {
                let t = self.trial.as_ref().ok_or(Error::Corrupt)?;
                tasks = tasks.min(t.terms.task_allowance - t.admitted_tasks);
                b.trial_tasks_remaining = tasks;
            }
            b.admissible_tasks = add(b.admissible_tasks, tasks)?;
        }
        Ok(b)
    }
    pub fn snapshot(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| Error::Corrupt)
    }
    /// Trusted storage only, never a client-provided balance, entitlement or payment proof.
    pub fn restore(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(Error::Capacity);
        }
        let state: Self = serde_json::from_slice(bytes).map_err(|_| Error::Corrupt)?;
        state.validate()?;
        Ok(state)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.schema != 1
            || !tenant_valid(&self.project_id)
            || !positive(self.revision)
            || !timestamp(self.clock_ms)
            || !positive(self.funding_revision)
            || self.purchases.project_id != self.project_id
            || self.purchase_cursor != self.purchases.revision()
            || self.ledger.tasks.len() > funding::MAX_RESERVATIONS
        {
            return Err(Error::Corrupt);
        }
        self.purchases.validate()?;
        self.funding.project(&self.project_id)?;
        self.funding.validate()?;
        let specs = self.grants();
        if specs.len() > funding::MAX_GRANTS {
            return Err(Error::Capacity);
        }
        let mut trial_tasks = 0;
        if self.purchases.purchases.len() + usize::from(self.trial.is_some()) > funding::MAX_GRANTS
        {
            return Err(Error::Capacity);
        }
        // Pending intents reserve numeric headroom too, before a future settlement.
        let mut total_units = self
            .trial
            .as_ref()
            .map_or(0, |t| t.grant.total_attempt_units);
        for p in self.purchases.purchases.values() {
            total_units = add(total_units, p.intent.grant.total_attempt_units)?;
        }
        for (id, spec) in &specs {
            let g = self.funding.grant(id).ok_or(Error::Corrupt)?;
            let reversed = self
                .purchases
                .purchases
                .get(id)
                .is_some_and(|p| p.receipt.reversed.is_some());
            if &g.spec != spec
                || !positive(spec.total_attempt_units)
                || !timestamp(spec.admission_expires_at_ms)
                || (self.clock_ms >= spec.admission_expires_at_ms || reversed) && !g.closed
                || !g.closed && g.retired != 0
            {
                return Err(Error::Corrupt);
            }
            // No retention pruning exists in this aggregate, so every spent fence
            // and outstanding reservation must still be backed by its task.
            let (mut spent, mut reserved) = (0, 0);
            for task_id in self.ledger.tasks.keys() {
                let r = self.funding.reservation(task_id)?;
                if &r.grant_id == id {
                    let units = r.spent_fences.len() as u64;
                    spent = add(spent, units)?;
                    if r.settlement.is_none() {
                        reserved = add(
                            reserved,
                            r.allocated_units.checked_sub(units).ok_or(Error::Corrupt)?,
                        )?;
                    }
                }
            }
            if (g.spent, g.reserved) != (spent, reserved) {
                return Err(Error::Corrupt);
            }
        }
        for (id, task) in &self.ledger.tasks {
            let r = self.funding.reservation(id)?;
            if task.id != *id
                || !specs.contains_key(&r.grant_id)
                || r.spent_fences != task.attempts.iter().map(|a| a.fence).collect()
                || task.status.terminal() != r.settlement.is_some()
            {
                return Err(Error::Corrupt);
            }
            if let Some(s) = &r.settlement {
                if s.spent_units != r.spent_fences.len() as u64
                    || s.unused_units
                        != r.allocated_units
                            .checked_sub(s.spent_units)
                            .ok_or(Error::Corrupt)?
                    || s.terminal_status != task.status
                    || Some(s.terminal_at_ms) != task.terminal_ms
                    || s.settled_at_ms < s.terminal_at_ms
                    || s.settled_at_ms > self.clock_ms
                {
                    return Err(Error::Corrupt);
                }
            }
            if r.grant_id == TRIAL_GRANT {
                trial_tasks += 1;
            }
        }
        if let Some(t) = &self.trial {
            if !positive(t.terms.task_allowance)
                || !timestamp(t.terms.duration_ms)
                || !timestamp(t.started_at_ms)
                || t.started_at_ms > self.clock_ms
                || t.started_at_ms.checked_add(t.terms.duration_ms)
                    != Some(t.grant.admission_expires_at_ms)
                || t.grant.grant_id != TRIAL_GRANT
                || t.grant.total_attempt_units != mul(t.terms.task_allowance, funding::TASK_UNITS)?
                || t.admitted_tasks > t.terms.task_allowance
                || t.admitted_tasks != trial_tasks
            {
                return Err(Error::Corrupt);
            }
        } else if trial_tasks != 0 {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}
