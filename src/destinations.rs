//! Offline destination policy aggregate. Ownership is NOT network/SSRF authorization.
//! The caller must authenticate tenant/configure authority and atomically commit this state
//! with task acceptance. No production identity, funding or admission path uses this yet.
use crate::security::{digest, tenant_valid};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;

pub const MAX_VERSIONS: usize = 16;
pub const MAX_TASKS: usize = 16;
pub const MAX_PROOFS: u8 = 3;
pub const PROOF_TTL_MS: i64 = 60_000;
pub const TIMEOUT_MS: u64 = 3000;
pub const HEADER_BYTES: usize = 2048;
pub const BODY_BYTES: usize = 1024;
pub const BODY_CHUNKS: usize = 32;

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
    Expired,
    Limited,
    Clock,
}
/// Operator-owned input only, never inferred from a successful ownership proof.
/// Empty is closed. Exact hostnames only; no wildcard, suffix, IP, port or DNS safety claim.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicy {
    pub approved_hosts: BTreeSet<String>,
}
#[derive(Clone)]
pub struct Target(String);
impl Target {
    pub fn url(&self) -> &str {
        &self.0
    }
}
impl EgressPolicy {
    pub fn target(&self, raw: &str) -> Result<Target, Error> {
        if self.approved_hosts.len() > 8 || raw.len() > 256 {
            return Err(Error::Invalid);
        }
        for host in &self.approved_hosts {
            if host.len() > 253
                || host.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || !label
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                        || label.starts_with('-')
                        || label.ends_with('-')
                })
                || [".localhost", ".local", ".internal"]
                    .iter()
                    .any(|suffix| host.ends_with(suffix))
            {
                return Err(Error::Invalid);
            }
            let u = url::Url::parse(&format!("https://{host}/")).map_err(|_| Error::Invalid)?;
            if !matches!(u.host(), Some(url::Host::Domain(h)) if h == host)
                || host.ends_with('.')
                || !host.contains('.')
                || u.as_str() != format!("https://{host}/")
            {
                return Err(Error::Invalid);
            }
        }
        let u = url::Url::parse(raw).map_err(|_| Error::Invalid)?;
        if u.scheme() != "https"
            || u.as_str() != raw
            || !u.username().is_empty()
            || u.password().is_some()
            || u.port().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || !matches!(u.host(), Some(url::Host::Domain(h)) if self.approved_hosts.contains(h))
        {
            return Err(Error::Unavailable);
        }
        Ok(Target(raw.into()))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Verified,
    Revoked,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub endpoint_id: String,
    pub version: u32,
    pub url: String,
    pub status: Status,
    pub created_at_ms: i64,
    pub verified_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    id: String,
    response_hash: String,
    expires_at_ms: i64,
    started: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    endpoint: Endpoint,
    attempts: u8,
    pending: Option<Pending>,
}
/// Immutable acceptance selection. No callback credentials or proof nonce retained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acceptance {
    pub project_id: String,
    pub task_id: String,
    pub endpoint_id: String,
    pub endpoint_version: u32,
    pub url: String,
}
/// Show once to the authenticated owner, who configures their endpoint to return `response`.
/// The secret nonce is NOT included in the outbound request (echo servers cannot prove control).
#[derive(Clone, Serialize)]
pub struct Proof {
    pub id: String,
    pub response: String,
    pub expires_at_ms: i64,
}
/// Ephemeral nonsecret request. Only a response digest is retained in State.
#[derive(Clone, Serialize)]
pub struct Challenge {
    pub id: String,
    pub url: String,
    pub body: String,
    pub expires_at_ms: i64,
    endpoint_id: String,
    endpoint_version: u32,
}
impl Challenge {
    pub fn target(&self, policy: &EgressPolicy) -> Result<Target, Error> {
        policy.target(&self.url)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u8,
    project_id: String,
    clock_ms: i64,
    versions: BTreeMap<String, BTreeMap<u32, Record>>,
    revoked_ids: BTreeSet<String>,
    acceptances: BTreeMap<String, Acceptance>,
}
impl State {
    pub fn new(project: &str) -> Result<Self, Error> {
        if !tenant_valid(project) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            schema_version: 1,
            project_id: project.into(),
            clock_ms: 0,
            versions: BTreeMap::new(),
            revoked_ids: BTreeSet::new(),
            acceptances: BTreeMap::new(),
        })
    }
    pub fn decode(raw: &[u8], project: &str) -> Result<Self, Error> {
        if raw.len() > 65_536 {
            return Err(Error::Invalid);
        }
        let s: Self = serde_json::from_slice(raw).map_err(|_| Error::Invalid)?;
        s.tenant(project)?;
        if s.schema_version != 1
            || !tenant_valid(&s.project_id)
            || s.clock_ms < 0
            || s.versions.values().map(BTreeMap::len).sum::<usize>() > MAX_VERSIONS
            || s.acceptances.len() > MAX_TASKS
            || s.revoked_ids.iter().any(|id| !s.versions.contains_key(id))
        {
            return Err(Error::Invalid);
        }
        for (id, versions) in &s.versions {
            if !tenant_valid(id) || versions.is_empty() {
                return Err(Error::Invalid);
            }
            for (index, (version, r)) in versions.iter().enumerate() {
                let e = &r.endpoint;
                let host = url::Url::parse(&e.url)
                    .map_err(|_| Error::Invalid)?
                    .host_str()
                    .ok_or(Error::Invalid)?
                    .to_string();
                EgressPolicy {
                    approved_hosts: [host].into_iter().collect(),
                }
                .target(&e.url)?;
                if *version != index as u32 + 1
                    || e.version != *version
                    || e.endpoint_id != *id
                    || e.created_at_ms < 0
                    || e.created_at_ms > s.clock_ms
                    || r.attempts > MAX_PROOFS
                    || (e.status == Status::Revoked) != s.revoked_ids.contains(id)
                    || e.revoked_at_ms.is_some() != (e.status == Status::Revoked)
                    || (e.status == Status::Verified && e.verified_at_ms.is_none())
                    || (e.status == Status::Pending && e.verified_at_ms.is_some())
                    || [e.revoked_at_ms, e.verified_at_ms]
                        .into_iter()
                        .flatten()
                        .any(|at| at < e.created_at_ms || at > s.clock_ms)
                    || r.pending.as_ref().is_some_and(|p| {
                        e.status != Status::Pending
                            || r.attempts == 0
                            || p.id != p.response_hash
                            || !hex_digest(&p.id)
                            || p.expires_at_ms <= e.created_at_ms
                            || p.expires_at_ms > s.clock_ms.saturating_add(PROOF_TTL_MS)
                    })
                {
                    return Err(Error::Invalid);
                }
            }
        }
        for (task, a) in &s.acceptances {
            let r = s
                .record(&a.endpoint_id, a.endpoint_version)
                .map_err(|_| Error::Invalid)?;
            if !tenant_valid(task)
                || a.task_id != *task
                || a.project_id != s.project_id
                || a.url != r.endpoint.url
                || r.endpoint.status == Status::Pending
            {
                return Err(Error::Invalid);
            }
        }
        Ok(s)
    }
    fn tenant(&self, project: &str) -> Result<(), Error> {
        if self.project_id != project {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    fn clock(&self, now: i64) -> Result<(), Error> {
        if now < self.clock_ms || now < 0 {
            return Err(Error::Clock);
        }
        Ok(())
    }
    fn record(&self, id: &str, version: u32) -> Result<&Record, Error> {
        self.versions
            .get(id)
            .and_then(|v| v.get(&version))
            .ok_or(Error::NotFound)
    }
    fn record_mut(&mut self, id: &str, version: u32) -> Result<&mut Record, Error> {
        self.versions
            .get_mut(id)
            .and_then(|v| v.get_mut(&version))
            .ok_or(Error::NotFound)
    }
    /// Creation is idempotent for an identical immutable version, including after revocation.
    pub fn create(
        &mut self,
        project: &str,
        id: &str,
        version: u32,
        url: &str,
        policy: &EgressPolicy,
        now: i64,
    ) -> Result<Endpoint, Error> {
        self.tenant(project)?;
        self.clock(now)?;
        if let Ok(r) = self.record(id, version) {
            return if r.endpoint.url == url {
                Ok(r.endpoint.clone())
            } else {
                Err(Error::Conflict)
            };
        }
        if !tenant_valid(id) || version == 0 {
            return Err(Error::Invalid);
        }
        if self.revoked_ids.contains(id) {
            return Err(Error::Unavailable);
        }
        let expected = self.versions.get(id).map_or(1, |v| v.len() as u32 + 1);
        if version != expected {
            return Err(Error::Conflict);
        }
        if self.versions.values().map(BTreeMap::len).sum::<usize>() >= MAX_VERSIONS {
            return Err(Error::Limited);
        }
        policy.target(url)?;
        let endpoint = Endpoint {
            endpoint_id: id.into(),
            version,
            url: url.into(),
            status: Status::Pending,
            created_at_ms: now,
            verified_at_ms: None,
            revoked_at_ms: None,
        };
        self.versions.entry(id.into()).or_default().insert(
            version,
            Record {
                endpoint: endpoint.clone(),
                attempts: 0,
                pending: None,
            },
        );
        self.clock_ms = now;
        Ok(endpoint)
    }
    /// Reserve one of three lifetime proofs BEFORE network I/O; crashes never restore budget.
    /// `nonce` must come from 32 bytes of cryptographically secure randomness in the adapter.
    pub fn prepare(
        &mut self,
        project: &str,
        id: &str,
        version: u32,
        nonce: &str,
        policy: &EgressPolicy,
        now: i64,
    ) -> Result<Proof, Error> {
        self.tenant(project)?;
        self.clock(now)?;
        if !hex_digest(nonce) {
            return Err(Error::Invalid);
        }
        let r = self.record(id, version)?;
        if r.endpoint.status != Status::Pending {
            return Err(Error::Unavailable);
        }
        policy.target(&r.endpoint.url)?;
        if r.pending.as_ref().is_some_and(|p| p.expires_at_ms > now) {
            return Err(Error::Conflict);
        }
        if r.attempts >= MAX_PROOFS {
            return Err(Error::Limited);
        }
        let expires = now.checked_add(PROOF_TTL_MS).ok_or(Error::Invalid)?;
        let body = format!(
            "RunLater destination proof v1\n{}",
            serde_json::to_string(&(
                1,
                project,
                id,
                version,
                &r.endpoint.url,
                r.attempts + 1,
                expires,
                nonce
            ))
            .map_err(|_| Error::Invalid)?
        );
        if body.len() > BODY_BYTES {
            return Err(Error::Invalid);
        }
        let hash = digest(body.as_bytes());
        let proof = Proof {
            id: hash.clone(),
            response: body,
            expires_at_ms: expires,
        };
        let r = self.record_mut(id, version)?;
        r.attempts += 1;
        r.pending = Some(Pending {
            id: hash.clone(),
            response_hash: hash,
            expires_at_ms: expires,
            started: false,
        });
        self.clock_ms = now;
        Ok(proof)
    }
    /// One-use fetch lease, durably persisted before I/O. A retry cannot fetch again.
    pub fn begin(
        &mut self,
        project: &str,
        id: &str,
        version: u32,
        policy: &EgressPolicy,
        now: i64,
    ) -> Result<Challenge, Error> {
        self.tenant(project)?;
        self.clock(now)?;
        let r = self.record(id, version)?;
        if r.endpoint.status != Status::Pending {
            return Err(Error::Unavailable);
        }
        policy.target(&r.endpoint.url)?;
        let p = r.pending.as_ref().ok_or(Error::Conflict)?;
        if p.started {
            return Err(Error::Conflict);
        }
        if now >= p.expires_at_ms {
            return Err(Error::Expired);
        }
        let challenge = Challenge {
            id: p.id.clone(),
            url: r.endpoint.url.clone(),
            body: format!(
                "RunLater destination verification v1\n{}",
                serde_json::to_string(&(project, id, version, &p.id, p.expires_at_ms))
                    .map_err(|_| Error::Invalid)?
            ),
            expires_at_ms: p.expires_at_ms,
            endpoint_id: id.into(),
            endpoint_version: version,
        };
        self.record_mut(id, version)?
            .pending
            .as_mut()
            .ok_or(Error::Conflict)?
            .started = true;
        self.clock_ms = now;
        Ok(challenge)
    }
    /// Caller supplies only the response from trusted bounded egress, never client proof bytes.
    /// Reload state after I/O. Failure consumes the reserved proof; completion is one-use.
    pub fn complete(
        &mut self,
        project: &str,
        challenge: &Challenge,
        response: Result<(u16, &[u8]), ()>,
        policy: &EgressPolicy,
        now: i64,
    ) -> Result<Endpoint, Error> {
        self.tenant(project)?;
        self.clock(now)?;
        let r = self.record(&challenge.endpoint_id, challenge.endpoint_version)?;
        let p = r.pending.as_ref().ok_or(Error::Conflict)?;
        if !p.started || p.id != challenge.id || r.endpoint.url != challenge.url {
            return Err(Error::Conflict);
        }
        let outcome = if r.endpoint.status != Status::Pending {
            Err(Error::Unavailable)
        } else if now >= p.expires_at_ms {
            Err(Error::Expired)
        } else if policy.target(&r.endpoint.url).is_err() {
            Err(Error::Unavailable)
        } else {
            match response {
                Ok((200, body))
                    if body.len() <= BODY_BYTES
                        && bool::from(
                            digest(body).as_bytes().ct_eq(p.response_hash.as_bytes()),
                        ) =>
                {
                    Ok(())
                }
                _ => Err(Error::Unavailable),
            }
        };
        let r = self.record_mut(&challenge.endpoint_id, challenge.endpoint_version)?;
        r.pending = None;
        if outcome.is_ok() {
            r.endpoint.status = Status::Verified;
            r.endpoint.verified_at_ms = Some(now);
        }
        let endpoint = r.endpoint.clone();
        self.clock_ms = now;
        outcome.map(|_| endpoint)
    }
    /// Sticky endpoint-wide revocation includes all historical versions and future admission.
    pub fn revoke(&mut self, project: &str, id: &str, now: i64) -> Result<(), Error> {
        self.tenant(project)?;
        self.clock(now)?;
        let versions = self.versions.get_mut(id).ok_or(Error::NotFound)?;
        for r in versions.values_mut() {
            r.endpoint.status = Status::Revoked;
            r.endpoint.revoked_at_ms.get_or_insert(now);
            r.pending = None;
        }
        self.revoked_ids.insert(id.into());
        self.clock_ms = now;
        Ok(())
    }
    pub fn get(&self, project: &str, id: &str, version: u32) -> Result<Endpoint, Error> {
        self.tenant(project)?;
        Ok(self.record(id, version)?.endpoint.clone())
    }
    pub fn snapshot(
        &mut self,
        project: &str,
        task_id: &str,
        id: &str,
        version: u32,
        policy: &EgressPolicy,
        now: i64,
    ) -> Result<Acceptance, Error> {
        self.tenant(project)?;
        self.clock(now)?;
        if let Some(a) = self.acceptances.get(task_id) {
            return if a.endpoint_id == id && a.endpoint_version == version {
                Ok(a.clone())
            } else {
                Err(Error::Conflict)
            };
        }
        if !tenant_valid(task_id) {
            return Err(Error::Invalid);
        }
        if self.acceptances.len() >= MAX_TASKS {
            return Err(Error::Limited);
        }
        let r = self.record(id, version)?;
        if r.endpoint.status != Status::Verified {
            return Err(Error::Unavailable);
        }
        policy.target(&r.endpoint.url)?;
        let a = Acceptance {
            project_id: project.into(),
            task_id: task_id.into(),
            endpoint_id: id.into(),
            endpoint_version: version,
            url: r.endpoint.url.clone(),
        };
        self.acceptances.insert(task_id.into(), a.clone());
        self.clock_ms = now;
        Ok(a)
    }
    /// Revocation or operator host removal blocks the next dispatch, including accepted tasks.
    /// An already-issued network request cannot be undone. The snapshot is never rewritten.
    pub fn dispatch(
        &self,
        project: &str,
        task_id: &str,
        policy: &EgressPolicy,
    ) -> Result<Target, Error> {
        self.tenant(project)?;
        let a = self.acceptances.get(task_id).ok_or(Error::NotFound)?;
        let r = self.record(&a.endpoint_id, a.endpoint_version)?;
        if r.endpoint.status != Status::Verified || r.endpoint.url != a.url {
            return Err(Error::Unavailable);
        }
        policy.target(&a.url)
    }
}
