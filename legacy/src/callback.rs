//! Opt-in v2 OFFLINE callback protocol. Separate from API authentication and legacy staging.
//! Keyring serialization contains metadata only. Production key administration is not exposed.
use crate::security::{digest, task_id_valid, tenant_valid};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
pub const VERSION: &str = "v2";
pub const WINDOW_SEC: i64 = 300;
pub const MAX_KEYS: usize = 16;
pub const MAX_TIME_SEC: i64 = 253_402_300_799;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    InvalidPolicy,
    Conflict,
    NoSigner,
    MissingMaterial,
    InvalidSnapshot,
    InvalidSignature,
    Capacity,
}
pub trait Material {
    fn key(&self, id: &str) -> Option<&[u8]>;
}
/// Public deterministic test material ONLY; never use it for real callbacks.
pub struct FixtureMaterial;
impl Material for FixtureMaterial {
    fn key(&self, id: &str) -> Option<&[u8]> {
        match id {
            "fixture_a" => Some(b"public-fixture-callback-a-not-production"),
            "fixture_b" => Some(b"public-fixture-callback-b-not-production"),
            "fixture_c" => Some(b"public-fixture-callback-c-not-production"),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub key_id: String,
    pub introduced_revision: u64,
    pub active_from_sec: i64,
    pub sign_until_sec: i64,
    pub verify_until_sec: i64,
    pub revoked_at_sec: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Rotation {
    source: String,
    cutover_sec: i64,
    sign_until_sec: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Keyring {
    version: String,
    tenant: String,
    policy_id: String,
    revision: u64,
    keys: BTreeMap<String, Key>,
    rotations: BTreeMap<String, Rotation>,
}
fn time(at: i64) -> bool {
    (0..=MAX_TIME_SEC).contains(&at)
}
fn identifier(s: &str) -> bool {
    tenant_valid(s)
}
fn operation(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn material_present(material: &impl Material, id: &str) -> bool {
    material.key(id).is_some_and(|k| k.len() >= 32)
}
impl Keyring {
    pub fn new(
        tenant: &str,
        policy: &str,
        id: &str,
        active: i64,
        end: i64,
        material: &impl Material,
    ) -> Result<Self, Fault> {
        if end <= active {
            return Err(Fault::InvalidPolicy);
        }
        if !material_present(material, id) {
            return Err(Fault::MissingMaterial);
        }
        let key = Key {
            key_id: id.into(),
            introduced_revision: 1,
            active_from_sec: active,
            sign_until_sec: end,
            verify_until_sec: end.checked_add(WINDOW_SEC).ok_or(Fault::InvalidPolicy)?,
            revoked_at_sec: None,
        };
        let ring = Self {
            version: VERSION.into(),
            tenant: tenant.into(),
            policy_id: policy.into(),
            revision: 1,
            keys: BTreeMap::from([(id.into(), key)]),
            rotations: BTreeMap::new(),
        };
        ring.validate()?;
        Ok(ring)
    }
    pub fn validate(&self) -> Result<(), Fault> {
        if self.version != VERSION
            || !tenant_valid(&self.tenant)
            || !identifier(&self.policy_id)
            || self.revision == 0
            || self.keys.is_empty()
            || self.keys.len() > MAX_KEYS
            || self.rotations.len() + 1 != self.keys.len()
            || self.revision
                != (self.keys.len()
                    + self
                        .keys
                        .values()
                        .filter(|k| k.revoked_at_sec.is_some())
                        .count()) as u64
        {
            return Err(Fault::InvalidPolicy);
        }
        let mut revisions = BTreeSet::new();
        for (id, k) in &self.keys {
            if !identifier(id)
                || id != &k.key_id
                || k.introduced_revision == 0
                || k.introduced_revision > self.revision
                || !revisions.insert(k.introduced_revision)
                || !time(k.active_from_sec)
                || !time(k.sign_until_sec)
                || !time(k.verify_until_sec)
                || k.sign_until_sec < k.active_from_sec
                || k.verify_until_sec < k.sign_until_sec
                || k.verify_until_sec - k.sign_until_sec > WINDOW_SEC
                || k.revoked_at_sec.is_some_and(|at| !time(at))
            {
                return Err(Fault::InvalidPolicy);
            }
        }
        if self
            .keys
            .values()
            .filter(|k| k.introduced_revision == 1)
            .count()
            != 1
            || self
                .keys
                .iter()
                .any(|(id, k)| k.introduced_revision != 1 && !self.rotations.contains_key(id))
        {
            return Err(Fault::InvalidPolicy);
        }
        let active: Vec<_> = self
            .keys
            .values()
            .filter(|k| k.revoked_at_sec.is_none())
            .collect();
        for (i, a) in active.iter().enumerate() {
            for b in active.iter().skip(i + 1) {
                if a.active_from_sec < b.sign_until_sec && b.active_from_sec < a.sign_until_sec {
                    return Err(Fault::InvalidPolicy);
                }
            }
        }
        for (id, r) in &self.rotations {
            let new = self.keys.get(id).ok_or(Fault::InvalidPolicy)?;
            let old = self.keys.get(&r.source).ok_or(Fault::InvalidPolicy)?;
            if id == &r.source
                || new.introduced_revision <= old.introduced_revision
                || new.active_from_sec != r.cutover_sec
                || new.sign_until_sec > r.sign_until_sec
                || old.sign_until_sec > r.cutover_sec
                || !time(r.sign_until_sec)
            {
                return Err(Fault::InvalidPolicy);
            }
        }
        Ok(())
    }
    pub fn issuer(&self, now: i64) -> Result<&Key, Fault> {
        self.validate()?;
        if !time(now) {
            return Err(Fault::InvalidPolicy);
        }
        self.keys
            .values()
            .find(|k| {
                k.revoked_at_sec.is_none() && k.active_from_sec <= now && now < k.sign_until_sec
            })
            .ok_or(Fault::NoSigner)
    }
    /// Atomic metadata rotation; caller must durably commit the returned state before use.
    /// Identical retries return current metadata, including later rotation/revocation.
    pub fn rotate(
        &mut self,
        id: &str,
        cutover: i64,
        end: i64,
        now: i64,
        material: &impl Material,
    ) -> Result<Key, Fault> {
        self.validate()?;
        if !time(now) {
            return Err(Fault::InvalidPolicy);
        }
        if let Some(r) = self.rotations.get(id) {
            if r.cutover_sec != cutover || r.sign_until_sec != end {
                return Err(Fault::Conflict);
            }
            return self.keys.get(id).cloned().ok_or(Fault::InvalidPolicy);
        }
        if self.keys.contains_key(id) {
            return Err(Fault::Conflict);
        }
        if self.keys.len() >= MAX_KEYS {
            return Err(Fault::Capacity);
        }
        if !identifier(id)
            || cutover < now
            || cutover > now.saturating_add(86400)
            || end <= cutover
            || end > MAX_TIME_SEC - WINDOW_SEC
        {
            return Err(Fault::InvalidPolicy);
        }
        if !material_present(material, id) {
            return Err(Fault::MissingMaterial);
        }
        if self
            .keys
            .values()
            .any(|k| k.revoked_at_sec.is_none() && k.active_from_sec > now)
        {
            return Err(Fault::Conflict);
        }
        // Explicit administrative recovery may replace a retired/revoked epoch immediately.
        // This metadata fallback is NOT a signing fallback: the old key remains unusable.
        let source = self
            .issuer(now)
            .ok()
            .or_else(|| {
                self.keys
                    .values()
                    .filter(|k| k.active_from_sec <= now)
                    .max_by_key(|k| k.introduced_revision)
            })
            .ok_or(Fault::NoSigner)?
            .clone();
        let usable = source.revoked_at_sec.is_none() && now < source.sign_until_sec;
        if (usable && cutover > source.sign_until_sec) || (!usable && cutover != now) {
            return Err(Fault::InvalidPolicy);
        }
        let mut next = self.clone();
        next.revision = next.revision.checked_add(1).ok_or(Fault::InvalidPolicy)?;
        let old = next
            .keys
            .get_mut(&source.key_id)
            .ok_or(Fault::InvalidPolicy)?;
        old.sign_until_sec = old.sign_until_sec.min(cutover);
        old.verify_until_sec = old.verify_until_sec.min(cutover + WINDOW_SEC);
        let key = Key {
            key_id: id.into(),
            introduced_revision: next.revision,
            active_from_sec: cutover,
            sign_until_sec: end,
            verify_until_sec: end + WINDOW_SEC,
            revoked_at_sec: None,
        };
        next.keys.insert(id.into(), key.clone());
        next.rotations.insert(
            id.into(),
            Rotation {
                source: source.key_id,
                cutover_sec: cutover,
                sign_until_sec: end,
            },
        );
        next.validate()?;
        *self = next;
        Ok(key)
    }
    /// Immediate and sticky, even after clock rollback. There is no un-revoke/delete operation.
    pub fn revoke(&mut self, id: &str, now: i64) -> Result<Key, Fault> {
        self.validate()?;
        if !time(now) {
            return Err(Fault::InvalidPolicy);
        }
        let key = self.keys.get(id).ok_or(Fault::Conflict)?;
        if key.revoked_at_sec.is_some() {
            return Ok(key.clone());
        }
        let mut next = self.clone();
        next.revision = next.revision.checked_add(1).ok_or(Fault::InvalidPolicy)?;
        let key = next.keys.get_mut(id).ok_or(Fault::Conflict)?;
        key.revoked_at_sec = Some(now);
        let view = key.clone();
        next.validate()?;
        *self = next;
        Ok(view)
    }
    pub fn key_ids(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }
    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    /// Accept operator metadata without allowing rollback, key removal or resurrection.
    pub fn update(&mut self, next: &Self) -> Result<(), Fault> {
        self.validate()?;
        next.validate()?;
        if self.tenant != next.tenant
            || self.policy_id != next.policy_id
            || next.revision < self.revision
        {
            return Err(Fault::Conflict);
        }
        if next.revision == self.revision {
            return if self == next {
                Ok(())
            } else {
                Err(Fault::Conflict)
            };
        }
        for (id, old) in &self.keys {
            let new = next.keys.get(id).ok_or(Fault::Conflict)?;
            if new.introduced_revision != old.introduced_revision
                || new.active_from_sec != old.active_from_sec
                || new.sign_until_sec > old.sign_until_sec
                || new.verify_until_sec > old.verify_until_sec
                || old.revoked_at_sec.is_some() && new.revoked_at_sec != old.revoked_at_sec
            {
                return Err(Fault::Conflict);
            }
        }
        if next.keys.iter().any(|(id, key)| {
            !self.keys.contains_key(id) && key.introduced_revision <= self.revision
        }) {
            return Err(Fault::Conflict);
        }
        for (id, old) in &self.rotations {
            if next.rotations.get(id) != Some(old) {
                return Err(Fault::Conflict);
            }
        }
        *self = next.clone();
        Ok(())
    }
    pub fn sign(
        &self,
        snapshot: &Snapshot,
        body: &[u8],
        now: i64,
        material: &impl Material,
    ) -> Result<Envelope, Fault> {
        if !snapshot.valid(body)
            || snapshot.tenant != self.tenant
            || snapshot.policy_id != self.policy_id
        {
            return Err(Fault::InvalidSnapshot);
        }
        let key = self.issuer(now)?;
        let bytes = material
            .key(&key.key_id)
            .filter(|k| k.len() >= 32)
            .ok_or(Fault::MissingMaterial)?;
        let mut envelope = Envelope {
            version: VERSION.into(),
            policy_id: self.policy_id.clone(),
            key_id: key.key_id.clone(),
            timestamp_sec: now,
            task_id: format!("{}:{}", snapshot.tenant, snapshot.task_id),
            operation_key: snapshot.operation_key.clone(),
            signature: String::new(),
        };
        envelope.signature = hex::encode(mac(bytes, &envelope, body).finalize().into_bytes());
        Ok(envelope)
    }
    pub fn verify(
        &self,
        envelope: &Envelope,
        body: &[u8],
        now: i64,
        material: &impl Material,
    ) -> Result<(), Fault> {
        self.validate()?;
        let e = envelope;
        let bare = e
            .task_id
            .strip_prefix(&format!("{}:", self.tenant))
            .ok_or(Fault::InvalidSignature)?;
        if e.version != VERSION
            || e.policy_id != self.policy_id
            || !task_id_valid(bare)
            || !operation(&e.operation_key)
            || body.len() > 16384
            || !time(now)
            || !time(e.timestamp_sec)
            || now.abs_diff(e.timestamp_sec) > WINDOW_SEC as u64
            || e.signature.len() != 64
            || !e
                .signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Fault::InvalidSignature);
        }
        let key = self.keys.get(&e.key_id).ok_or(Fault::InvalidSignature)?;
        if key.revoked_at_sec.is_some()
            || now < key.active_from_sec
            || now >= key.verify_until_sec
            || e.timestamp_sec < key.active_from_sec
            || e.timestamp_sec >= key.sign_until_sec
        {
            return Err(Fault::InvalidSignature);
        }
        let bytes = material
            .key(&e.key_id)
            .filter(|k| k.len() >= 32)
            .ok_or(Fault::InvalidSignature)?;
        mac(bytes, e, body)
            .verify_slice(&hex::decode(&e.signature).map_err(|_| Fault::InvalidSignature)?)
            .map_err(|_| Fault::InvalidSignature)
    }
}
/// Private acceptance snapshot, NOT a public diagnostic/log DTO. No secret material.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    version: String,
    tenant: String,
    policy_id: String,
    task_id: String,
    operation_key: String,
    body_sha256: String,
}
impl Snapshot {
    pub fn new(
        tenant: &str,
        policy: &str,
        task: &str,
        operation_key: &str,
        body: &[u8],
    ) -> Result<Self, Fault> {
        if !tenant_valid(tenant)
            || !identifier(policy)
            || !task_id_valid(task)
            || !operation(operation_key)
            || body.len() > 16384
        {
            return Err(Fault::InvalidSnapshot);
        }
        let s = Self {
            version: VERSION.into(),
            tenant: tenant.into(),
            policy_id: policy.into(),
            task_id: task.into(),
            operation_key: operation_key.into(),
            body_sha256: digest(body),
        };
        if !s.valid(body) {
            return Err(Fault::InvalidSnapshot);
        }
        Ok(s)
    }
    fn valid_metadata(&self) -> bool {
        self.version == VERSION
            && tenant_valid(&self.tenant)
            && identifier(&self.policy_id)
            && task_id_valid(&self.task_id)
            && operation(&self.operation_key)
            && self.body_sha256.len() == 64
            && self
                .body_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    pub(crate) fn accepts(&self, e: &Envelope, body: &[u8]) -> bool {
        self.valid(body)
            && e.version == self.version
            && e.policy_id == self.policy_id
            && e.task_id == format!("{}:{}", self.tenant, self.task_id)
            && e.operation_key == self.operation_key
    }
    fn valid(&self, body: &[u8]) -> bool {
        self.valid_metadata() && body.len() <= 16384 && self.body_sha256 == digest(body)
    }
    pub fn redrive(&self, new_task: &str) -> Result<Self, Fault> {
        if !self.valid_metadata() || !task_id_valid(new_task) || new_task == self.task_id {
            return Err(Fault::InvalidSnapshot);
        }
        let mut next = self.clone();
        next.task_id = new_task.into();
        Ok(next)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: String,
    pub policy_id: String,
    pub key_id: String,
    pub timestamp_sec: i64,
    pub task_id: String,
    pub operation_key: String,
    pub signature: String,
}
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallbackSnapshot(<redacted>)")
    }
}
impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallbackEnvelope(<redacted>)")
    }
}
impl Envelope {
    /// Parse canonical signed headers; duplicate case-insensitive names are rejected.
    pub fn from_headers(headers: &[(String, String)]) -> Result<Self, Fault> {
        let get = |name: &str| -> Result<String, Fault> {
            let mut values = headers
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name));
            let value = values.next().ok_or(Fault::InvalidSignature)?.1.clone();
            if values.next().is_some() {
                return Err(Fault::InvalidSignature);
            }
            Ok(value)
        };
        let timestamp = get("RunLater-Timestamp")?;
        let parsed: i64 = timestamp.parse().map_err(|_| Fault::InvalidSignature)?;
        if parsed.to_string() != timestamp {
            return Err(Fault::InvalidSignature);
        }
        Ok(Self {
            version: get("RunLater-Signature-Version")?,
            policy_id: get("RunLater-Signing-Policy")?,
            key_id: get("RunLater-Key-Id")?,
            timestamp_sec: parsed,
            task_id: get("RunLater-Task-Id")?,
            operation_key: get("RunLater-Operation-Key")?,
            signature: get("RunLater-Signature")?,
        })
    }
    pub fn headers(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("RunLater-Signature-Version".into(), self.version.clone()),
            ("RunLater-Signing-Policy".into(), self.policy_id.clone()),
            ("RunLater-Key-Id".into(), self.key_id.clone()),
            ("RunLater-Timestamp".into(), self.timestamp_sec.to_string()),
            ("RunLater-Task-Id".into(), self.task_id.clone()),
            ("RunLater-Operation-Key".into(), self.operation_key.clone()),
            ("RunLater-Signature".into(), self.signature.clone()),
        ])
    }
}
fn mac(key: &[u8], e: &Envelope, body: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(
        format!(
            "runlater.v2.{}.{}.{}.{}.{}.",
            e.policy_id, e.key_id, e.timestamp_sec, e.task_id, e.operation_key
        )
        .as_bytes(),
    );
    mac.update(body);
    mac
}
