//! Invitation aggregate delivery integration. All network effects occur after a durable fenced claim.
use crate::{
    auth::Permission,
    callback::{Keyring, Material, Snapshot},
    core::{Dispatch, Outcome},
    destinations::{self, EgressPolicy},
    funded_tasks, identity,
    invitation::Enrollment,
    security::digest,
    signed::Envelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u8,
    #[serde(default)]
    beta_admissions: u32,
    destinations: Option<destinations::State>,
    versions: BTreeMap<String, u32>,
    selections: BTreeMap<String, destinations::Acceptance>,
    snapshots: BTreeMap<String, Snapshot>,
    keys: Option<Keyring>,
    material_hashes: BTreeMap<String, String>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            schema_version: 1,
            beta_admissions: 0,
            destinations: None,
            versions: BTreeMap::new(),
            selections: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            keys: None,
            material_hashes: BTreeMap::new(),
        }
    }
}
#[derive(Debug)]
pub enum Error {
    BetaCapacity,
    Auth(identity::Error),
    Task(funded_tasks::Error),
    Destination(destinations::Error),
    Unavailable,
}
impl From<identity::Error> for Error {
    fn from(e: identity::Error) -> Self {
        Self::Auth(e)
    }
}
impl From<funded_tasks::Error> for Error {
    fn from(e: funded_tasks::Error) -> Self {
        Self::Task(e)
    }
}
impl From<destinations::Error> for Error {
    fn from(e: destinations::Error) -> Self {
        Self::Destination(e)
    }
}
pub fn destination_route(method: &str, path: &str) -> bool {
    method == "POST"
        && matches!(
            path,
            "/v1/destinations/create"
                | "/v1/destinations/prepare"
                | "/v1/destinations/verify"
                | "/v1/destinations/revoke"
        )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationCommand {
    pub endpoint_id: String,
    pub version: u32,
    pub url: Option<String>,
}
impl State {
    pub(crate) fn validate(&self, project: Option<&str>) -> Result<(), Error> {
        if self.beta_admissions > 16
            || self.schema_version != 1
            || self.versions.len() > 64
            || self.selections.len() > 128
            || self.snapshots.len() > 128
            || self.material_hashes.len() > 16
        {
            return Err(Error::Unavailable);
        }
        if let Some(d) = &self.destinations {
            let p = project.ok_or(Error::Unavailable)?;
            destinations::State::decode(
                &serde_json::to_vec(d).map_err(|_| Error::Unavailable)?,
                p,
            )?;
        }
        if let Some(keys) = &self.keys {
            keys.validate().map_err(|_| Error::Unavailable)?;
            if Some(keys.tenant()) != project {
                return Err(Error::Unavailable);
            }
        }
        if self
            .selections
            .keys()
            .any(|id| !self.snapshots.contains_key(id))
            || self
                .snapshots
                .keys()
                .any(|id| !self.selections.contains_key(id))
        {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn registry(&mut self, project: &str) -> Result<&mut destinations::State, Error> {
        if self.destinations.is_none() {
            self.destinations = Some(destinations::State::new(project)?)
        }
        Ok(self.destinations.as_mut().unwrap())
    }
    pub fn sync_keys(
        &mut self,
        project: &str,
        keys: &Keyring,
        material: &impl Material,
    ) -> Result<(), Error> {
        keys.validate().map_err(|_| Error::Unavailable)?;
        if keys.tenant() != project {
            return Err(Error::Unavailable);
        }
        let mut next = self.clone();
        if let Some(old) = &mut next.keys {
            old.update(keys).map_err(|_| Error::Unavailable)?
        } else {
            next.keys = Some(keys.clone())
        }
        for id in keys.key_ids() {
            if let Some(bytes) = material.key(id) {
                if bytes.len() < 32 {
                    return Err(Error::Unavailable);
                }
                let h = digest(bytes);
                if next.material_hashes.get(id).is_some_and(|old| old != &h) {
                    return Err(Error::Unavailable);
                }
                next.material_hashes.insert(id.into(), h);
            }
        }
        *self = next;
        Ok(())
    }
}
impl Enrollment {
    pub fn destination_command(
        &mut self,
        e: &Envelope,
        signature: &str,
        body: &[u8],
        policy: &EgressPolicy,
        nonce: &str,
        now: i64,
    ) -> Result<Value, Error> {
        if !destination_route(&e.method, &e.path) || e.path.ends_with("/verify") {
            return Err(Error::Unavailable);
        }
        let p = self.identity_policy()?;
        let mut next = self.clone();
        next.project.catalog.apply_policy(&p, now)?;
        e.authenticate(&next.project.catalog, signature, body, now)?;
        next.project.catalog.authorize(
            &e.project_id,
            &e.public_key,
            Permission::ManageDestinations,
            now,
        )?;
        next.project.requests.check_nonce(e, now)?;
        let v: DestinationCommand =
            serde_json::from_slice(body).map_err(|_| identity::Error::Invalid)?;
        if !e.path.ends_with("/create") && v.url.is_some() {
            return Err(identity::Error::Invalid.into());
        }
        let result = if e.path.ends_with("/create") {
            let endpoint = next.outbound.registry(&e.project_id)?.create(
                &e.project_id,
                &v.endpoint_id,
                v.version,
                v.url.as_deref().ok_or(identity::Error::Invalid)?,
                policy,
                now,
            )?;
            next.outbound
                .versions
                .entry(v.endpoint_id)
                .and_modify(|x| *x = (*x).max(v.version))
                .or_insert(v.version);
            json!(endpoint)
        } else if e.path.ends_with("/prepare") {
            json!(next.outbound.registry(&e.project_id)?.prepare(
                &e.project_id,
                &v.endpoint_id,
                v.version,
                nonce,
                policy,
                now
            )?)
        } else {
            next.outbound
                .registry(&e.project_id)?
                .get(&e.project_id, &v.endpoint_id, v.version)?;
            next.outbound
                .registry(&e.project_id)?
                .revoke(&e.project_id, &v.endpoint_id, now)?;
            json!({"revoked":true})
        };
        next.project.requests.record_nonce(e)?;
        next.outbound.validate(next.project_id())?;
        *self = next;
        Ok(result)
    }
    pub fn destination_begin(
        &mut self,
        e: &Envelope,
        signature: &str,
        body: &[u8],
        policy: &EgressPolicy,
        now: i64,
    ) -> Result<destinations::Challenge, Error> {
        if e.path != "/v1/destinations/verify" {
            return Err(Error::Unavailable);
        }
        let p = self.identity_policy()?;
        let mut next = self.clone();
        next.project.catalog.apply_policy(&p, now)?;
        e.authenticate(&next.project.catalog, signature, body, now)?;
        next.project.requests.check_nonce(e, now)?;
        let v: DestinationCommand =
            serde_json::from_slice(body).map_err(|_| identity::Error::Invalid)?;
        if v.url.is_some() {
            return Err(identity::Error::Invalid.into());
        }
        let c = next.outbound.registry(&e.project_id)?.begin(
            &e.project_id,
            &v.endpoint_id,
            v.version,
            policy,
            now,
        )?;
        next.project.requests.record_nonce(e)?;
        *self = next;
        Ok(c)
    }
    pub fn destination_complete(
        &mut self,
        project: &str,
        public_key: &str,
        c: &destinations::Challenge,
        response: Result<(u16, &[u8]), ()>,
        policy: &EgressPolicy,
        now: i64,
    ) -> Result<Value, Error> {
        self.identity_policy()?;
        self.project
            .catalog
            .authorize(project, public_key, Permission::ManageDestinations, now)?;
        Ok(json!(self
            .outbound
            .registry(project)?
            .complete(project, c, response, policy, now)?))
    }
    pub fn registered_beta_task_command(
        &mut self,
        e: &Envelope,
        signature: &str,
        body: &[u8],
        policy: &EgressPolicy,
        keys: &Keyring,
        material: &impl Material,
        now: i64,
    ) -> Result<Value, Error> {
        let mut next = self.clone();
        let v = next.registered_task_command(e, signature, body, policy, keys, material, now)?;
        if v["created"] == true {
            if next.outbound.beta_admissions >= 16 {
                return Err(Error::BetaCapacity);
            }
            let id = v["result"]["id"].as_str().ok_or(Error::Unavailable)?;
            let t = next
                .project
                .ledger
                .get(id)
                .map_err(funded_tasks::Error::from)?;
            if t.due_ms > next.beta_expiry().ok_or(Error::Unavailable)? {
                return Err(crate::destinations::Error::Invalid.into());
            }
            next.outbound.beta_admissions += 1;
        }
        *self = next;
        Ok(v)
    }
    pub fn registered_task_command(
        &mut self,
        e: &Envelope,
        signature: &str,
        body: &[u8],
        policy: &EgressPolicy,
        keys: &Keyring,
        material: &impl Material,
        now: i64,
    ) -> Result<Value, Error> {
        let mut next = self.clone();
        let value = next.signed_task_command(e, signature, body, true, now)?;
        if value["created"] == true {
            next.outbound.sync_keys(&e.project_id, keys, material)?;
            let id = value["result"]["id"].as_str().ok_or(Error::Unavailable)?;
            let task = next
                .project
                .ledger
                .get(id)
                .map_err(funded_tasks::Error::from)?;
            if task.input.body.len() > 1024 {
                return Err(Error::Unavailable);
            }
            let endpoint = task
                .input
                .destination
                .strip_prefix("registered:")
                .ok_or(Error::Unavailable)?;
            let version = if let Some(parent) = &task.parent {
                next.outbound
                    .selections
                    .get(parent)
                    .filter(|a| a.endpoint_id == endpoint)
                    .map(|a| a.endpoint_version)
                    .ok_or(Error::Unavailable)?
            } else {
                *next
                    .outbound
                    .versions
                    .get(endpoint)
                    .ok_or(Error::Unavailable)?
            };
            let selection = next.outbound.registry(&e.project_id)?.snapshot(
                &e.project_id,
                id,
                endpoint,
                version,
                policy,
                now,
            )?;
            let snapshot = Snapshot::new(
                &e.project_id,
                keys.policy_id(),
                id,
                &task.input.operation_key,
                task.input.body.as_bytes(),
            )
            .map_err(|_| Error::Unavailable)?;
            keys.sign(&snapshot, task.input.body.as_bytes(), now / 1000, material)
                .map_err(|_| Error::Unavailable)?;
            next.outbound.selections.insert(id.into(), selection);
            next.outbound.snapshots.insert(id.into(), snapshot);
        }
        next.outbound.validate(next.project_id())?;
        *self = next;
        Ok(value)
    }
    pub fn registered_claim(
        &mut self,
        d: &Dispatch,
        policy: &EgressPolicy,
        now: i64,
        material: &impl Material,
    ) -> Result<Option<crate::delivery::Wire>, Error> {
        let mut next = self.clone();
        if next.identity_policy().is_err() {
            if let Ok(t) = next.project.ledger.get(&d.id) {
                if t.status != crate::core::Status::Running {
                    next.project
                        .ledger
                        .cancel(&d.id, now)
                        .map_err(funded_tasks::Error::from)?;
                    next.project.funded_maintenance(now)?;
                }
            }
            *self = next;
            return Ok(None);
        }
        let claimed = match next.project.funded_claim(d, now) {
            Ok(task) => task,
            Err(error @ funded_tasks::Error::Ledger(crate::core::Fault::Limited { .. })) => {
                // A handled denial commits observations, reconciliation and settlement in funded_claim.
                // Preserve that aggregate so the runtime's 429 save does not write the old snapshot.
                *self = next;
                return Err(error.into());
            }
            Err(error) => return Err(error.into()),
        };
        let Some(task) = claimed else {
            *self = next;
            return Ok(None);
        };
        let wire: Result<(crate::delivery::Wire, String), Error> = (|| {
            let target = next
                .outbound
                .destinations
                .as_ref()
                .ok_or(Error::Unavailable)?
                .dispatch(&d.tenant, &d.id, policy)?;
            let keys = next.outbound.keys.as_ref().ok_or(Error::Unavailable)?;
            let snapshot = next
                .outbound
                .snapshots
                .get(&d.id)
                .ok_or(Error::Unavailable)?;
            let envelope = keys
                .sign(snapshot, task.input.body.as_bytes(), now / 1000, material)
                .map_err(|_| Error::Unavailable)?;
            Ok((
                crate::delivery::Wire {
                    url: target.url().into(),
                    body: task.input.body.clone(),
                    headers: envelope.headers(),
                },
                envelope.key_id,
            ))
        })();
        match wire {
            Ok((w, key_id)) => {
                next.project
                    .delivery
                    .attempts
                    .entry(d.id.clone())
                    .or_default()
                    .push(crate::delivery::Metadata {
                        fence: task.fence,
                        protocol: crate::callback::VERSION.into(),
                        key_id: Some(key_id),
                        category: "pending".into(),
                    });
                *self = next;
                Ok(Some(w))
            }
            Err(_) => {
                next.project
                    .delivery
                    .attempts
                    .entry(d.id.clone())
                    .or_default()
                    .push(crate::delivery::Metadata {
                        fence: task.fence,
                        protocol: crate::callback::VERSION.into(),
                        key_id: None,
                        category: "policy_unavailable".into(),
                    });
                next.project
                    .funded_finish(&d.id, task.fence, Outcome::Http(400), now)?;
                *self = next;
                Ok(None)
            }
        }
    }
    pub fn registered_outbox(&mut self, project: &str, now: i64) -> Result<Vec<Dispatch>, Error> {
        if self.identity_policy().is_err() {
            let ids: Vec<_> = self
                .project
                .ledger
                .tasks
                .values()
                .filter(|t| !t.status.terminal() && t.status != crate::core::Status::Running)
                .map(|t| t.id.clone())
                .collect();
            for id in ids {
                self.project
                    .ledger
                    .cancel(&id, now)
                    .map_err(funded_tasks::Error::from)?;
            }
        }
        self.project.funded_maintenance(now)?;
        self.project.delivery.prune(&self.project.ledger);
        let mut refs = self.project.ledger.outbox(project, now);
        self.project.delivery.reserve_publications(&mut refs);
        Ok(refs)
    }
}
