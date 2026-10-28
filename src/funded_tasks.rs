//! Funded admission model and signed task commands. Production passes no admission context until delivery is ready.
use crate::{
    application::CommandResult,
    auth::Permission,
    core::{self, Create, Dispatch, Outcome, Task},
    funding,
    identity::{self, Policy as IdentityPolicy},
    security::task_id_valid,
    signed::{Envelope, Project},
};
use serde_json::{json, Value};
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Auth(identity::Error),
    Funding(funding::Error),
    Ledger(core::Fault),
    AdmissionUnavailable,
}
impl From<identity::Error> for Error {
    fn from(e: identity::Error) -> Self {
        Self::Auth(e)
    }
}
impl From<funding::Error> for Error {
    fn from(e: funding::Error) -> Self {
        Self::Funding(e)
    }
}
impl From<core::Fault> for Error {
    fn from(e: core::Fault) -> Self {
        Self::Ledger(e)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route<'a> {
    Create,
    Read(&'a str),
    Cancel(&'a str),
    Redrive(&'a str),
}
pub fn route<'a>(method: &str, path: &'a str) -> Option<Route<'a>> {
    let parts: Vec<_> = path.split('/').collect();
    match (method, parts.as_slice()) {
        ("POST", ["", "v1", "tasks"]) => Some(Route::Create),
        ("GET", ["", "v1", "tasks", id]) if task_id_valid(id) => Some(Route::Read(id)),
        ("POST", ["", "v1", "tasks", id, "cancel"]) if task_id_valid(id) => Some(Route::Cancel(id)),
        ("POST", ["", "v1", "tasks", id, "redrive"]) if task_id_valid(id) => {
            Some(Route::Redrive(id))
        }
        _ => None,
    }
}
impl Project {
    fn task_result(
        &self,
        e: &Envelope,
        t: &Task,
        created: bool,
        replayed: bool,
        now: i64,
    ) -> Result<Value, Error> {
        self.funding.reservation(&t.id)?;
        let can_read = self
            .catalog
            .authorize(&e.project_id, &e.public_key, Permission::Read, now)
            .is_ok();
        let result = CommandResult {
            status: if created { 201 } else { 200 },
            body: serde_json::to_value(t).map_err(|_| identity::Error::Invalid)?,
        }
        .scoped_body(can_read);
        Ok(
            json!({"result":result,"created":created,"replayed":replayed,"task_accepted":true,"funding_reserved":true,"funding":if can_read{Some(self.funding.reservation(&t.id)?)}else{None}}),
        )
    }
    pub fn task_query(
        &self,
        policy: &IdentityPolicy,
        e: &Envelope,
        signature: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Value, Error> {
        let Some(Route::Read(id)) = route(&e.method, &e.path) else {
            return Err(identity::Error::Invalid.into());
        };
        let mut snapshot = self.clone();
        snapshot.catalog.apply_policy(policy, now)?;
        e.authenticate(&snapshot.catalog, signature, body, now)?;
        let t = snapshot.ledger.get(id)?;
        let mut v = snapshot.task_result(e, &t, false, false, now)?;
        v["sampled_at_ms"] = now.into();
        Ok(v)
    }
    /// `admission` is trusted application context, never an HTTP field. Production always passes None in this slice.
    pub fn task_command(
        &mut self,
        policy: &IdentityPolicy,
        admission: Option<&funding::Policy>,
        e: &Envelope,
        signature: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Value, Error> {
        let action = route(&e.method, &e.path).ok_or(identity::Error::Invalid)?;
        if matches!(action, Route::Read(_)) {
            return Err(identity::Error::Invalid.into());
        }
        self.catalog.apply_policy(policy, now)?;
        e.authenticate(&self.catalog, signature, body, now)?;
        let mut next = self.clone();
        next.requests.check_nonce(e, now)?;
        let (task, created, replayed) = match action {
            Route::Create => {
                let input: Create =
                    serde_json::from_slice(body).map_err(|_| identity::Error::Invalid)?;
                if !input
                    .destination
                    .strip_prefix("registered:")
                    .is_some_and(crate::security::tenant_valid)
                {
                    return Err(core::Fault::DestinationDisabled.into());
                }
                let (t, created) = next.ledger.create(&e.idempotency_key, input, now)?;
                (t, created, !created)
            }
            Route::Redrive(id) => {
                let value: Value =
                    serde_json::from_slice(body).map_err(|_| identity::Error::Invalid)?;
                if !value.as_object().is_some_and(|m| m.is_empty()) {
                    return Err(identity::Error::Invalid.into());
                }
                let (t, created) = next.ledger.redrive(id, &e.idempotency_key, now)?;
                (t, created, !created)
            }
            Route::Cancel(id) => {
                let value: Value =
                    serde_json::from_slice(body).map_err(|_| identity::Error::Invalid)?;
                if !value.as_object().is_some_and(|m| m.is_empty()) {
                    return Err(identity::Error::Invalid.into());
                }
                next.funding.project(&e.project_id)?;
                next.funding.reservation(id)?;
                let prior = next.ledger.get(id)?;
                let replayed = prior.cancel_requested || prior.status.terminal();
                let t = next.ledger.cancel(id, now)?;
                (t, false, replayed)
            }
            Route::Read(_) => unreachable!(),
        };
        if created {
            let grant = admission.ok_or(Error::AdmissionUnavailable)?;
            if grant.project_id != e.project_id {
                return Err(funding::Error::InvalidPolicy.into());
            }
            next.funding.apply(grant, now)?;
            next.funding.reserve(&e.project_id, &task.id, now)?;
        } else {
            next.funding.project(&e.project_id)?;
            next.funding.reservation(&task.id)?;
            next.funding.advance(now)?;
        }
        next.funding.settle_all(&next.ledger, now)?;
        next.requests.record_nonce(e)?;
        let result = next.task_result(e, &task, created, replayed, now)?;
        *self = next;
        Ok(result)
    }
    /// Server-side attempt accounting model. No network effect or queue/consumer is implied.
    pub fn funded_claim(&mut self, d: &Dispatch, now: i64) -> Result<Option<Task>, Error> {
        self.ledger.get(&d.id)?;
        let mut next = self.clone();
        next.funding.project(&d.tenant)?;
        next.funding.advance(now)?;
        next.ledger.reconcile(now);
        next.funding.settle_all(&next.ledger, now)?;
        next.funding.reservation(&d.id)?;
        let result = next.ledger.claim(d, now);
        if let Ok(Some(t)) = &result {
            next.funding.spend(t, now)?;
        }
        next.funding.settle_all(&next.ledger, now)?;
        next.funding.validate()?;
        *self = next;
        Ok(result?)
    }
    pub fn funded_finish(
        &mut self,
        id: &str,
        fence: u64,
        outcome: Outcome,
        now: i64,
    ) -> Result<Task, Error> {
        let mut next = self.clone();
        next.funding.reservation(id)?;
        next.funding.advance(now)?;
        let result = next.ledger.finish(id, fence, outcome, now);
        next.funding.settle_all(&next.ledger, now)?;
        *self = next;
        Ok(result?)
    }
    pub fn funded_maintenance(&mut self, now: i64) -> Result<(), Error> {
        let mut next = self.clone();
        next.funding.advance(now)?;
        next.ledger.reconcile(now);
        next.funding.settle_all(&next.ledger, now)?;
        next.ledger.purge(now);
        next.funding.purge_removed(&next.ledger)?;
        *self = next;
        Ok(())
    }
}
