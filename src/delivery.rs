//! Restricted operator-owned HTTPS endpoint registration and callback-v2 dispatch snapshots.
use crate::{
    callback::{self, Keyring, Material, Snapshot},
    core::{Dispatch, Outcome, Task},
    funding, identity,
    signed::{Envelope, Project},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const RECEIVER_URL: &str = "https://receiver-alpha.runlater.io/callback";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub project_id: String,
    pub revision: u64,
    pub endpoint_id: String,
    pub url: String,
    pub revoked: bool,
    pub keys: Keyring,
    pub grant: funding::Policy,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    endpoint_id: String,
    endpoint_revision: u64,
    url: String,
    callback: Snapshot,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub fence: u64,
    pub protocol: String,
    pub key_id: Option<String>,
    pub category: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub project_id: String,
    revision: u64,
    hash: String,
    endpoint_id: String,
    url: String,
    revoked: bool,
    keys: Option<Keyring>,
    material_hashes: BTreeMap<String, String>,
    registrations: BTreeMap<String, Registration>,
    pub attempts: BTreeMap<String, Vec<Metadata>>,
    clock_ms: i64,
    accepted: u32,
    publications: u32,
}
#[derive(Clone)]
pub struct Wire {
    pub url: String,
    pub body: String,
    pub headers: BTreeMap<String, String>,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Conflict,
    Unavailable,
    Clock,
    Task(crate::funded_tasks::Error),
}
impl From<crate::funded_tasks::Error> for Error {
    fn from(e: crate::funded_tasks::Error) -> Self {
        Self::Task(e)
    }
}
impl State {
    pub fn apply(&mut self, p: &Policy, now: i64) -> Result<(), Error> {
        let url = url::Url::parse(&p.url).map_err(|_| Error::Invalid)?;
        if p.url != RECEIVER_URL
            || url.as_str() != p.url
            || p.project_id != p.keys.tenant()
            || p.grant.project_id != p.project_id
            || !crate::security::tenant_valid(&p.endpoint_id)
            || p.revision == 0
            || p.revision > 9_007_199_254_740_991
        {
            return Err(Error::Invalid);
        }
        p.keys.validate().map_err(|_| Error::Invalid)?;
        if now < self.clock_ms {
            return Err(Error::Clock);
        }
        let hash = crate::security::digest(&serde_json::to_vec(p).map_err(|_| Error::Invalid)?);
        if !self.project_id.is_empty()
            && (self.project_id != p.project_id
                || self.endpoint_id != p.endpoint_id
                || self.url != p.url)
            || p.revision < self.revision
            || p.revision == self.revision && hash != self.hash
        {
            return Err(Error::Conflict);
        }
        let mut next = self.clone();
        if let Some(keys) = &mut next.keys {
            keys.update(&p.keys).map_err(|_| Error::Conflict)?;
        } else {
            next.keys = Some(p.keys.clone());
        }
        next.project_id = p.project_id.clone();
        next.endpoint_id = p.endpoint_id.clone();
        next.url = p.url.clone();
        next.revoked |= p.revoked;
        next.revision = p.revision;
        next.hash = hash;
        next.clock_ms = now;
        *self = next;
        Ok(())
    }
    pub fn bind_material(&mut self, material: &impl Material) -> Result<(), Error> {
        let mut hashes = self.material_hashes.clone();
        for id in self.keys.as_ref().ok_or(Error::Unavailable)?.key_ids() {
            if let Some(bytes) = material.key(id) {
                let hash = crate::security::digest(bytes);
                if hashes.get(id).is_some_and(|old| *old != hash) {
                    return Err(Error::Conflict);
                }
                hashes.insert(id.into(), hash);
            }
        }
        self.material_hashes = hashes;
        Ok(())
    }
    pub fn ready(&self, body: &str, material: &impl Material, now: i64) -> Result<(), Error> {
        if self.revoked {
            return Err(Error::Unavailable);
        }
        if body.len() > 1024
            || !serde_json::from_str::<serde_json::Value>(body).is_ok_and(|v| {
                v.get("synthetic").and_then(serde_json::Value::as_bool) == Some(true)
            })
        {
            return Err(Error::Invalid);
        }
        let keys = self.keys.as_ref().ok_or(Error::Unavailable)?;
        let id = &keys
            .issuer(now / 1000)
            .map_err(|_| Error::Unavailable)?
            .key_id;
        if material.key(id).is_none_or(|b| b.len() < 32) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    fn register(&mut self, t: &Task) -> Result<(), Error> {
        if self.accepted >= 16 {
            return Err(Error::Unavailable);
        }
        self.accepted += 1;
        let callback = Snapshot::new(
            &self.project_id,
            self.keys.as_ref().ok_or(Error::Unavailable)?.policy_id(),
            &t.id,
            &t.input.operation_key,
            t.input.body.as_bytes(),
        )
        .map_err(|_| Error::Invalid)?;
        self.registrations.insert(
            t.id.clone(),
            Registration {
                endpoint_id: self.endpoint_id.clone(),
                endpoint_revision: self.revision,
                url: self.url.clone(),
                callback,
            },
        );
        Ok(())
    }
    fn wire(&mut self, t: &Task, material: &impl Material, now: i64) -> Result<Wire, Error> {
        if now < self.clock_ms {
            return Err(Error::Clock);
        }
        self.clock_ms = now;
        self.ready(&t.input.body, material, now)?;
        let r = self.registrations.get(&t.id).ok_or(Error::Unavailable)?;
        if r.endpoint_id != self.endpoint_id || r.url != self.url {
            return Err(Error::Unavailable);
        }
        let e = self
            .keys
            .as_ref()
            .ok_or(Error::Unavailable)?
            .sign(&r.callback, t.input.body.as_bytes(), now / 1000, material)
            .map_err(|_| Error::Unavailable)?;
        self.attempts
            .entry(t.id.clone())
            .or_default()
            .push(Metadata {
                fence: t.fence,
                protocol: callback::VERSION.into(),
                key_id: Some(e.key_id.clone()),
                category: "claimed".into(),
            });
        Ok(Wire {
            url: r.url.clone(),
            body: t.input.body.clone(),
            headers: e.headers(),
        })
    }
    pub fn verify(
        &self,
        headers: &[(String, String)],
        body: &[u8],
        material: &impl Material,
        now: i64,
    ) -> Result<(), Error> {
        if self.revoked || now < self.clock_ms {
            return Err(Error::Unavailable);
        }
        let envelope = callback::Envelope::from_headers(headers).map_err(|_| Error::Invalid)?;
        let id = envelope
            .task_id
            .strip_prefix(&format!("{}:", self.project_id))
            .ok_or(Error::Invalid)?;
        let registered = self.registrations.get(id).ok_or(Error::Invalid)?;
        if !registered.callback.accepts(&envelope, body) {
            return Err(Error::Invalid);
        }
        self.keys
            .as_ref()
            .ok_or(Error::Unavailable)?
            .verify(&envelope, body, now / 1000, material)
            .map_err(|_| Error::Invalid)
    }
    pub fn reserve_publications(&mut self, refs: &mut Vec<Dispatch>) {
        refs.truncate(128u32.saturating_sub(self.publications) as usize);
        self.publications += refs.len() as u32;
    }
    pub fn publication_exhausted(&self) -> bool {
        self.publications >= 128
    }
    pub fn prune(&mut self, ledger: &crate::core::Ledger) {
        self.registrations
            .retain(|id, _| ledger.tasks.contains_key(id));
        self.attempts.retain(|id, _| ledger.tasks.contains_key(id));
    }
}
impl Project {
    pub fn delivery_command(
        &mut self,
        identity: &identity::Policy,
        p: &Policy,
        material: &impl Material,
        e: &Envelope,
        sig: &str,
        body: &[u8],
        now: i64,
    ) -> Result<serde_json::Value, Error> {
        let mut next = self.clone();
        // Replay/cancel needs existing funded identity, not a new grant or live destination.
        let v = next.task_command(identity, Some(&p.grant), e, sig, body, now)?;
        if v["created"] == true {
            next.delivery.apply(p, now)?;
            next.delivery.bind_material(material)?;
            let id = v["result"]["id"].as_str().ok_or(Error::Invalid)?;
            let t = next.ledger.get(id).map_err(|_| Error::Invalid)?;
            if t.input.destination != format!("registered:{}", p.endpoint_id) {
                return Err(Error::Invalid);
            }
            next.delivery.ready(&t.input.body, material, now)?;
            next.delivery.register(&t)?;
        }
        *self = next;
        Ok(v)
    }
    pub fn delivery_claim(
        &mut self,
        p: &Policy,
        d: &Dispatch,
        material: &impl Material,
        now: i64,
    ) -> Result<Option<Wire>, Error> {
        let mut next = self.clone();
        next.delivery.apply(p, now)?;
        next.delivery.bind_material(material)?;
        let t = match next.funded_claim(d, now) {
            Ok(t) => t,
            Err(e) => {
                *self = next;
                return Err(e.into());
            }
        };
        let wire = if let Some(t) = t {
            match next.delivery.wire(&t, material, now) {
                Ok(w) => Some(w),
                Err(_) => {
                    next.delivery
                        .attempts
                        .entry(t.id.clone())
                        .or_default()
                        .push(Metadata {
                            fence: t.fence,
                            protocol: callback::VERSION.into(),
                            key_id: None,
                            category: "policy_unavailable".into(),
                        });
                    next.funded_finish(&t.id, t.fence, Outcome::Http(400), now)?;
                    None
                }
            }
        } else {
            None
        };
        *self = next;
        Ok(wire)
    }
    pub fn delivery_finish(
        &mut self,
        id: &str,
        fence: u64,
        outcome: Outcome,
        category: &str,
        now: i64,
    ) -> Result<(), Error> {
        self.funded_finish(id, fence, outcome, now)?;
        if let Some(rows) = self.delivery.attempts.get_mut(id) {
            if let Some(row) = rows.iter_mut().find(|a| a.fence == fence) {
                row.category = category.into();
            }
        }
        Ok(())
    }
}
