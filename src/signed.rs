//! Signed project envelope, configuration receipts and authoritative identity/ledger/funding snapshot. No external I/O.
use crate::{
    auth::Permission,
    core::Ledger,
    identity::{Catalog, Error, Policy, ORIGIN},
    limits::QueueLimits,
    security::{digest, tenant_valid},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
pub const WINDOW_MS: i64 = 60_000;
pub const RECEIPT_TTL_MS: i64 = 86_400_000;
pub const CAPACITY: usize = 128;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub origin: String,
    pub project_id: String,
    pub public_key: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub body_sha256: String,
    pub idempotency_key: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: String,
}
fn hex_valid(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn key_valid(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
impl Envelope {
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = b"RunLater signed request v1\n".to_vec();
        bytes.extend(
            serde_json::to_vec(&(
                self.version,
                &self.origin,
                &self.project_id,
                &self.public_key,
                &self.method,
                &self.path,
                &self.query,
                &self.body_sha256,
                &self.idempotency_key,
                self.issued_at_ms,
                self.expires_at_ms,
                &self.nonce,
            ))
            .map_err(|_| Error::Invalid)?,
        );
        Ok(bytes)
    }
    fn permission(&self) -> Result<Permission, Error> {
        if crate::invitation_delivery::destination_route(&self.method, &self.path) {
            return Ok(Permission::ManageDestinations);
        }
        match (self.method.as_str(), self.path.as_str()) {
            ("GET", "/v1/queue" | "/v1/identity/me") => Ok(Permission::Read),
            ("PUT", "/v1/queue") => Ok(Permission::Configure),
            _ => match crate::funded_tasks::route(&self.method, &self.path) {
                Some(crate::funded_tasks::Route::Create) => Ok(Permission::Enqueue),
                Some(crate::funded_tasks::Route::Read(_)) => Ok(Permission::Read),
                Some(crate::funded_tasks::Route::Cancel(_)) => Ok(Permission::Cancel),
                Some(crate::funded_tasks::Route::Redrive(_)) => Ok(Permission::Redrive),
                None => Err(Error::Invalid),
            },
        }
    }
    pub(crate) fn authenticate(
        &self,
        catalog: &Catalog,
        signature: &str,
        body: &[u8],
        now: i64,
    ) -> Result<(), Error> {
        if self.version != 1
            || self.origin != ORIGIN
            || !tenant_valid(&self.project_id)
            || !self.query.is_empty()
            || !hex_valid(&self.nonce, 32)
            || !hex_valid(&self.public_key, 32)
            || !hex_valid(&self.body_sha256, 32)
            || body.len() > 2048
        {
            return Err(Error::Invalid);
        }
        if self.issued_at_ms < 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms.saturating_sub(self.issued_at_ms) > WINDOW_MS
            || self.issued_at_ms > now
            || now >= self.expires_at_ms
        {
            return Err(Error::Expired);
        }
        if self.method == "GET" && (!body.is_empty() || !self.idempotency_key.is_empty())
            || self.method == "PUT" && !key_valid(&self.idempotency_key)
        {
            return Err(Error::Invalid);
        }
        if self.method == "POST" {
            if crate::invitation_delivery::destination_route(&self.method, &self.path) {
                if !key_valid(&self.idempotency_key) {
                    return Err(Error::Invalid);
                }
            } else {
                match crate::funded_tasks::route(&self.method, &self.path) {
                    Some(crate::funded_tasks::Route::Cancel(_))
                        if self.idempotency_key.is_empty() => {}
                    Some(
                        crate::funded_tasks::Route::Create | crate::funded_tasks::Route::Redrive(_),
                    ) if key_valid(&self.idempotency_key) => {}
                    _ => return Err(Error::Invalid),
                }
            }
        }
        catalog.authorize(&self.project_id, &self.public_key, self.permission()?, now)?;
        if digest(body) != self.body_sha256
            || !crate::identity::verify_ed25519(&self.public_key, &self.bytes()?, signature)
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    fn fingerprint(&self) -> Result<String, Error> {
        Ok(digest(
            &serde_json::to_vec(&(
                "queue_configuration_v1",
                &self.project_id,
                &self.method,
                &self.path,
                &self.query,
                &self.body_sha256,
                &self.idempotency_key,
            ))
            .map_err(|_| Error::Invalid)?,
        ))
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Nonce {
    wire_hash: String,
    expires_at_ms: i64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Receipt {
    fingerprint: String,
    result: Value,
    committed_at_ms: i64,
    expires_at_ms: i64,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Receipts {
    nonces: BTreeMap<String, BTreeMap<String, Nonce>>,
    configuration: BTreeMap<String, Receipt>,
}
impl Receipts {
    fn prune(&mut self, now: i64) {
        for map in self.nonces.values_mut() {
            map.retain(|_, v| v.expires_at_ms > now);
        }
        self.nonces.retain(|_, v| !v.is_empty());
        self.configuration.retain(|_, v| v.expires_at_ms > now);
    }
    fn nonces(&self) -> usize {
        self.nonces.values().map(BTreeMap::len).sum()
    }
    pub(crate) fn check_nonce(&mut self, e: &Envelope, now: i64) -> Result<(), Error> {
        self.prune(now);
        let existing = self.nonces.get(&e.public_key).and_then(|m| m.get(&e.nonce));
        if let Some(n) = existing {
            if n.wire_hash != digest(&e.bytes()?) {
                return Err(Error::Conflict);
            }
        } else if self.nonces() >= CAPACITY {
            return Err(Error::Limited);
        }
        Ok(())
    }
    pub(crate) fn record_nonce(&mut self, e: &Envelope) -> Result<(), Error> {
        self.nonces.entry(e.public_key.clone()).or_default().insert(
            e.nonce.clone(),
            Nonce {
                wire_hash: digest(&e.bytes()?),
                expires_at_ms: e.expires_at_ms,
            },
        );
        Ok(())
    }
    fn commands(&self) -> usize {
        self.configuration.len()
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub project_state_version: u8,
    pub catalog: Catalog,
    pub ledger: Ledger,
    pub requests: Receipts,
    pub funding: crate::funding::State,
    pub delivery: crate::delivery::State,
}
impl Default for Project {
    fn default() -> Self {
        Self {
            project_state_version: 3,
            catalog: Catalog::default(),
            ledger: Ledger::default(),
            requests: Receipts::default(),
            funding: crate::funding::State::default(),
            delivery: crate::delivery::State::default(),
        }
    }
}
impl Project {
    pub fn decode(value: Value) -> Result<Self, Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Legacy {
            project_state_version: u8,
            catalog: Catalog,
            ledger: Ledger,
            requests: Receipts,
        }
        match value.get("project_state_version").and_then(Value::as_u64) {
            Some(1) => {
                let old: Legacy = serde_json::from_value(value).map_err(|_| Error::Invalid)?;
                if old.project_state_version != 1 {
                    return Err(Error::Invalid);
                }
                Ok(Self {
                    project_state_version: 3,
                    catalog: old.catalog,
                    ledger: old.ledger,
                    requests: old.requests,
                    funding: crate::funding::State::default(),
                    delivery: crate::delivery::State::default(),
                })
            }
            Some(2) => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct V2 {
                    project_state_version: u8,
                    catalog: Catalog,
                    ledger: Ledger,
                    requests: Receipts,
                    funding: crate::funding::State,
                }
                let old: V2 = serde_json::from_value(value).map_err(|_| Error::Invalid)?;
                if old.project_state_version != 2 {
                    return Err(Error::Invalid);
                }
                Ok(Self {
                    project_state_version: 3,
                    catalog: old.catalog,
                    ledger: old.ledger,
                    requests: old.requests,
                    funding: old.funding,
                    delivery: crate::delivery::State::default(),
                })
            }
            Some(3) => serde_json::from_value(value).map_err(|_| Error::Invalid),
            Some(_) => Err(Error::Invalid),
            None if value.get("project_state_version").is_some() => Err(Error::Invalid),
            None => Ok(Self {
                catalog: serde_json::from_value(value).map_err(|_| Error::Invalid)?,
                ..Self::default()
            }),
        }
    }
    /// Signed reads permit repeated valid signatures until expiry; they never consume nonce/receipt state.
    pub fn query(
        &self,
        policy: &Policy,
        e: &Envelope,
        signature: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Value, Error> {
        if e.method != "GET" {
            return Err(Error::Invalid);
        }
        let mut catalog = self.catalog.clone();
        catalog.apply_policy(policy, now)?;
        e.authenticate(&catalog, signature, body, now)?;
        let result = match e.path.as_str() {
            "/v1/queue" => serde_json::to_value(&self.ledger.limits).map_err(|_| Error::Invalid)?,
            "/v1/identity/me" => catalog.identity_view(&e.project_id, &e.public_key, now)?,
            _ => return Err(Error::Invalid),
        };
        Ok(json!({"result":result,"sampled_at_ms":now,"signed_read_window_ms":WINDOW_MS}))
    }
    /// No await or external authorization token is exposed: recheck policy, prove possession, commit effect+receipt together.
    pub fn command(
        &mut self,
        policy: &Policy,
        e: &Envelope,
        signature: &str,
        body: &[u8],
        now: i64,
    ) -> Result<Value, Error> {
        if e.method != "PUT" || e.path != "/v1/queue" {
            return Err(Error::Invalid);
        }
        self.catalog.apply_policy(policy, now)?;
        e.authenticate(&self.catalog, signature, body, now)?;
        let value: Value = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        if !value.get("paused").is_some_and(Value::is_boolean) {
            return Err(Error::Invalid);
        }
        let limits: QueueLimits = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        limits.validate().map_err(|_| Error::Invalid)?;
        let wire_hash = digest(&e.bytes()?);
        let fingerprint = e.fingerprint()?;
        self.requests.prune(now);
        if let Some(nonce) = self
            .requests
            .nonces
            .get(&e.public_key)
            .and_then(|m| m.get(&e.nonce))
        {
            if nonce.wire_hash != wire_hash {
                return Err(Error::Conflict);
            }
        }
        let receipt = self.requests.configuration.get(&e.idempotency_key).cloned();
        if receipt
            .as_ref()
            .is_some_and(|r| r.fingerprint != fingerprint)
        {
            return Err(Error::Conflict);
        }
        let nonce_exists = self
            .requests
            .nonces
            .get(&e.public_key)
            .is_some_and(|m| m.contains_key(&e.nonce));
        if nonce_exists && receipt.is_none() {
            return Err(Error::Conflict);
        }
        if !nonce_exists && self.requests.nonces() >= CAPACITY
            || receipt.is_none() && self.requests.commands() >= CAPACITY
        {
            return Err(Error::Limited);
        }
        let replayed = receipt.is_some();
        let receipt = match receipt {
            Some(r) => r,
            None => {
                self.ledger
                    .configure(limits, now)
                    .map_err(|_| Error::Invalid)?;
                Receipt {
                    fingerprint,
                    result: serde_json::to_value(&self.ledger.limits)
                        .map_err(|_| Error::Invalid)?,
                    committed_at_ms: now,
                    expires_at_ms: now.saturating_add(RECEIPT_TTL_MS),
                }
            }
        };
        self.requests
            .nonces
            .entry(e.public_key.clone())
            .or_default()
            .insert(
                e.nonce.clone(),
                Nonce {
                    wire_hash,
                    expires_at_ms: e.expires_at_ms,
                },
            );
        self.requests
            .configuration
            .insert(e.idempotency_key.clone(), receipt.clone());
        Ok(
            json!({"result":receipt.result,"replayed":replayed,"committed_at_ms":receipt.committed_at_ms}),
        )
    }
}
