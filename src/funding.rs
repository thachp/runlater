//! Internal operator-alpha attempt units. No prices, trial terms, currency or payment integration.
use crate::{
    core::{Ledger, Status, Task, MAX_ATTEMPTS},
    security::{digest, tenant_valid},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_GRANTS: usize = 32;
pub const MAX_RESERVATIONS: usize = 1000;
pub const TASK_UNITS: u64 = 5;
const _: () = assert!(MAX_ATTEMPTS as u64 == TASK_UNITS);
const SAFE: u64 = 9_007_199_254_740_991;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    MissingPolicy,
    InvalidPolicy,
    Conflict,
    Expired,
    Insufficient,
    Capacity,
    Invariant,
    ClockRegressed,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantSpec {
    pub grant_id: String,
    pub total_attempt_units: u64,
    pub admission_expires_at_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u8,
    pub project_id: String,
    pub revision: u64,
    pub active_grant: Option<GrantSpec>,
    pub revoked_grants: Vec<String>,
}
impl Policy {
    fn validate(&self) -> Result<(), Error> {
        if self.version != 1
            || !tenant_valid(&self.project_id)
            || self.revision == 0
            || self.revision > SAFE
            || self.revoked_grants.len() > MAX_GRANTS
            || self.revoked_grants.iter().any(|id| !tenant_valid(id))
        {
            return Err(Error::InvalidPolicy);
        }
        if let Some(g) = &self.active_grant {
            if !tenant_valid(&g.grant_id)
                || g.total_attempt_units == 0
                || g.total_attempt_units > SAFE
                || g.admission_expires_at_ms <= 0
                || g.admission_expires_at_ms as u64 > SAFE
            {
                return Err(Error::InvalidPolicy);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub spec: GrantSpec,
    pub available: u64,
    pub reserved: u64,
    pub spent: u64,
    pub retired: u64,
    pub closed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    ReturnedToOpenSourceGrant,
    RetiredUnused,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settlement {
    pub spent_units: u64,
    pub unused_units: u64,
    pub disposition: Disposition,
    pub terminal_status: Status,
    pub terminal_at_ms: i64,
    pub settled_at_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub grant_id: String,
    pub unit_policy_version: u8,
    pub allocated_units: u64,
    pub spent_fences: BTreeSet<u64>,
    pub settlement: Option<Settlement>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    project_id: String,
    revision: u64,
    policy_hash: String,
    active_grant: Option<String>,
    grants: BTreeMap<String, Grant>,
    revoked: BTreeSet<String>,
    reservations: BTreeMap<String, Reservation>,
    clock_ms: i64,
}
fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Invariant)
}
fn sub(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_sub(b).ok_or(Error::Invariant)
}
impl State {
    pub fn advance(&mut self, now: i64) -> Result<(), Error> {
        if now < 0 || now < self.clock_ms {
            return Err(Error::ClockRegressed);
        }
        self.clock_ms = now;
        for (id, g) in &mut self.grants {
            if now >= g.spec.admission_expires_at_ms || self.revoked.contains(id) {
                g.closed = true;
            }
            if g.closed {
                g.retired = add(g.retired, g.available)?;
                g.available = 0;
            }
        }
        self.validate()
    }
    pub fn apply(&mut self, policy: &Policy, now: i64) -> Result<(), Error> {
        policy.validate()?;
        let hash = digest(&serde_json::to_vec(policy).map_err(|_| Error::InvalidPolicy)?);
        if !self.project_id.is_empty() && self.project_id != policy.project_id {
            return Err(Error::InvalidPolicy);
        }
        if policy.revision < self.revision
            || policy.revision == self.revision && hash != self.policy_hash
        {
            return Err(Error::Conflict);
        }
        let mut next = self.clone();
        if policy.revision > next.revision {
            if let Some(spec) = &policy.active_grant {
                match next.grants.get(&spec.grant_id) {
                    Some(g) if g.spec != *spec => return Err(Error::Conflict),
                    Some(_) => {}
                    None => {
                        if next.grants.len() >= MAX_GRANTS {
                            return Err(Error::Capacity);
                        }
                        next.grants.insert(
                            spec.grant_id.clone(),
                            Grant {
                                spec: spec.clone(),
                                available: spec.total_attempt_units,
                                reserved: 0,
                                spent: 0,
                                retired: 0,
                                closed: false,
                            },
                        );
                    }
                }
            }
            next.revoked.extend(policy.revoked_grants.clone());
            if next.revoked.len() > MAX_GRANTS {
                return Err(Error::Capacity);
            }
            next.active_grant = policy.active_grant.as_ref().map(|g| g.grant_id.clone());
            next.project_id = policy.project_id.clone();
            next.revision = policy.revision;
            next.policy_hash = hash;
        }
        next.advance(now)?;
        *self = next;
        Ok(())
    }
    pub fn reserve(&mut self, project: &str, task: &str, now: i64) -> Result<(), Error> {
        self.advance(now)?;
        self.project(project)?;
        if self.reservations.contains_key(task) {
            return Err(Error::Conflict);
        }
        if self.reservations.len() >= MAX_RESERVATIONS {
            return Err(Error::Capacity);
        }
        let id = self.active_grant.as_ref().ok_or(Error::MissingPolicy)?;
        let g = self.grants.get_mut(id).ok_or(Error::Invariant)?;
        if g.closed {
            return Err(Error::Expired);
        }
        if g.available < TASK_UNITS {
            return Err(Error::Insufficient);
        }
        g.available = sub(g.available, TASK_UNITS)?;
        g.reserved = add(g.reserved, TASK_UNITS)?;
        self.reservations.insert(
            task.into(),
            Reservation {
                grant_id: id.clone(),
                unit_policy_version: 1,
                allocated_units: TASK_UNITS,
                spent_fences: BTreeSet::new(),
                settlement: None,
            },
        );
        self.validate()
    }
    pub fn project(&self, project: &str) -> Result<(), Error> {
        if self.project_id != project {
            return Err(Error::Invariant);
        }
        Ok(())
    }
    pub fn reservation(&self, task: &str) -> Result<&Reservation, Error> {
        self.reservations.get(task).ok_or(Error::Invariant)
    }
    pub fn spend(&mut self, t: &Task, now: i64) -> Result<(), Error> {
        self.advance(now)?;
        let r = self.reservations.get_mut(&t.id).ok_or(Error::Invariant)?;
        if r.settlement.is_some()
            || t.status != Status::Running
            || t.attempts.last().is_none_or(|a| a.fence != t.fence)
        {
            return Err(Error::Invariant);
        }
        if r.spent_fences.contains(&t.fence) {
            return Ok(());
        }
        let expected: BTreeSet<_> = t
            .attempts
            .iter()
            .filter(|a| a.fence != t.fence)
            .map(|a| a.fence)
            .collect();
        if expected != r.spent_fences || r.spent_fences.len() as u64 >= r.allocated_units {
            return Err(Error::Invariant);
        }
        let g = self.grants.get_mut(&r.grant_id).ok_or(Error::Invariant)?;
        g.reserved = sub(g.reserved, 1)?;
        g.spent = add(g.spent, 1)?;
        r.spent_fences.insert(t.fence);
        self.validate()
    }
    pub fn settle(&mut self, t: &Task, now: i64) -> Result<(), Error> {
        self.advance(now)?;
        let r = self.reservations.get_mut(&t.id).ok_or(Error::Invariant)?;
        let fences: BTreeSet<_> = t.attempts.iter().map(|a| a.fence).collect();
        if fences != r.spent_fences {
            return Err(Error::Invariant);
        }
        if !t.status.terminal() || r.settlement.is_some() {
            return Ok(());
        }
        let spent = r.spent_fences.len() as u64;
        let unused = sub(r.allocated_units, spent)?;
        let g = self.grants.get_mut(&r.grant_id).ok_or(Error::Invariant)?;
        g.reserved = sub(g.reserved, unused)?;
        let disposition = if g.closed {
            g.retired = add(g.retired, unused)?;
            Disposition::RetiredUnused
        } else {
            g.available = add(g.available, unused)?;
            Disposition::ReturnedToOpenSourceGrant
        };
        r.settlement = Some(Settlement {
            spent_units: spent,
            unused_units: unused,
            disposition,
            terminal_status: t.status.clone(),
            terminal_at_ms: t.terminal_ms.ok_or(Error::Invariant)?,
            settled_at_ms: now,
        });
        self.validate()
    }
    pub fn settle_all(&mut self, ledger: &Ledger, now: i64) -> Result<(), Error> {
        let tasks: Vec<_> = self
            .reservations
            .keys()
            .filter_map(|id| ledger.tasks.get(id).cloned())
            .collect();
        for t in tasks {
            self.settle(&t, now)?;
        }
        Ok(())
    }
    pub fn purge_removed(&mut self, ledger: &Ledger) -> Result<(), Error> {
        if self
            .reservations
            .iter()
            .any(|(id, r)| !ledger.tasks.contains_key(id) && r.settlement.is_none())
        {
            return Err(Error::Invariant);
        }
        self.reservations
            .retain(|id, _| ledger.tasks.contains_key(id));
        self.validate()
    }
    pub fn grant(&self, id: &str) -> Option<&Grant> {
        self.grants.get(id)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.grants.len() > MAX_GRANTS
            || self.revoked.len() > MAX_GRANTS
            || self.reservations.len() > MAX_RESERVATIONS
        {
            return Err(Error::Invariant);
        }
        for (id, g) in &self.grants {
            if id != &g.spec.grant_id
                || add(add(g.available, g.reserved)?, add(g.spent, g.retired)?)?
                    != g.spec.total_attempt_units
                || g.closed && g.available != 0
            {
                return Err(Error::Invariant);
            }
            let mut reserved = 0;
            for r in self.reservations.values().filter(|r| r.grant_id == *id) {
                if r.unit_policy_version != 1
                    || r.allocated_units != TASK_UNITS
                    || r.spent_fences.len() as u64 > r.allocated_units
                {
                    return Err(Error::Invariant);
                }
                if r.settlement.is_none() {
                    reserved = add(
                        reserved,
                        sub(r.allocated_units, r.spent_fences.len() as u64)?,
                    )?;
                }
            }
            if reserved != g.reserved {
                return Err(Error::Invariant);
            }
        }
        if self
            .reservations
            .values()
            .any(|r| !self.grants.contains_key(&r.grant_id))
        {
            return Err(Error::Invariant);
        }
        Ok(())
    }
}
