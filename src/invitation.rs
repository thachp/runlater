//! Disabled-by-default invitation admission. No issuer, HTTP transport, secrets or commercial defaults.
use crate::{
    auth::Permission,
    funding, identity,
    security::{digest, tenant_valid},
    signed::Project,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const MAX_PROJECTS: usize = 8;
pub const MAX_TICKETS: usize = 64;
pub const MAX_CHALLENGES: usize = 8;
pub const TTL: i64 = 300_000;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Closed,
    Invalid,
    Conflict,
    Forbidden,
    Expired,
    Limited,
    Clock,
}
fn hex64(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash<T: Serialize>(v: &T) -> Result<String, Error> {
    Ok(digest(&serde_json::to_vec(v).map_err(|_| Error::Invalid)?))
}
fn allowed(p: &BTreeSet<Permission>) -> bool {
    !p.is_empty()
        && p.iter().all(|p| {
            matches!(
                p,
                Permission::Enqueue | Permission::Read | Permission::Cancel | Permission::Redrive
            )
        })
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    pub attempt_units: u64,
    pub identity_ms: i64,
    pub permissions: BTreeSet<Permission>,
}
impl Terms {
    fn validate(&self) -> Result<(), Error> {
        if self.attempt_units < funding::TASK_UNITS
            || self.attempt_units > 1_000_000
            || !(1..=30 * crate::core::DAY).contains(&self.identity_ms)
            || !allowed(&self.permissions)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub revision: u64,
    pub terms: Option<Terms>,
    pub max_projects: usize,
    pub max_tickets: usize,
    pub requests_per_minute: u32,
}
impl Policy {
    fn validate(&self) -> Result<(), Error> {
        if self.revision == 0
            || self.revision > 9_007_199_254_740_991
            || !(1..=MAX_PROJECTS).contains(&self.max_projects)
            || !(1..=MAX_TICKETS).contains(&self.max_tickets)
            || !(1..=1024).contains(&self.requests_per_minute)
        {
            return Err(Error::Invalid);
        }
        if let Some(t) = &self.terms {
            t.validate()?
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub id: String,
    pub project_id: String,
    pub grant_id: String,
    pub terms: Terms,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub policy_revision: u64,
    pub revoked: bool,
}
impl Ticket {
    fn validate(&self) -> Result<(), Error> {
        self.terms.validate()?;
        if !hex64(&self.id)
            || self.project_id != format!("p_{}", &self.id[..60])
            || self.grant_id != format!("g_{}", &self.id[..60])
            || self.issued_at_ms < 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > crate::core::DAY
            || self.policy_revision == 0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    policy: Option<Policy>,
    policy_hash: String,
    tickets: BTreeMap<String, Ticket>,
    projects: BTreeSet<String>,
    completed: BTreeSet<String>,
    clock_ms: i64,
    bucket: i64,
    requests: u32,
}
impl Registry {
    fn time(&mut self, now: i64) -> Result<(), Error> {
        if now < 0 || now < self.clock_ms {
            return Err(Error::Clock);
        }
        self.clock_ms = now;
        Ok(())
    }
    pub fn apply(&mut self, p: &Policy, now: i64) -> Result<(), Error> {
        p.validate()?;
        let h = hash(p)?;
        if self.policy.as_ref().is_some_and(|old| {
            p.revision < old.revision || p.revision == old.revision && h != self.policy_hash
        }) {
            return Err(Error::Conflict);
        }
        self.time(now)?;
        self.policy = Some(p.clone());
        self.policy_hash = h;
        Ok(())
    }
    /// Operator-side issuance reserves the lifetime global project slot before any project lookup.
    /// A repeated issuance returns the original immutable reservation, including its original expiry.
    pub fn issue(&mut self, id: &str, expires: i64, now: i64) -> Result<Ticket, Error> {
        self.time(now)?;
        let p = self.policy.as_ref().ok_or(Error::Closed)?;
        let terms = p.terms.clone().ok_or(Error::Closed)?;
        if !hex64(id) {
            return Err(Error::Invalid);
        }
        if let Some(t) = self.tickets.get(id) {
            if t.terms != terms || t.expires_at_ms != expires {
                return Err(Error::Conflict);
            }
            return Ok(t.clone());
        }
        if expires <= now || expires - now > crate::core::DAY {
            return Err(Error::Invalid);
        }
        if self.tickets.len() >= p.max_tickets || self.projects.len() >= p.max_projects {
            return Err(Error::Limited);
        }
        let project_id = format!("p_{}", &id[..60]);
        if self.projects.contains(&project_id) {
            return Err(Error::Conflict);
        }
        let t = Ticket {
            id: id.into(),
            project_id: project_id.clone(),
            grant_id: format!("g_{}", &id[..60]),
            terms,
            issued_at_ms: now,
            expires_at_ms: expires,
            policy_revision: p.revision,
            revoked: false,
        };
        t.validate()?;
        self.projects.insert(project_id);
        self.tickets.insert(id.into(), t.clone());
        Ok(t)
    }
    /// Call only on the fixed registry object. Invalid input/rate denial cannot choose a project DO.
    pub fn resolve(&mut self, id: &str, now: i64) -> Result<Ticket, Error> {
        self.time(now)?;
        let p = self.policy.as_ref().ok_or(Error::Closed)?;
        if p.terms.is_none() {
            return Err(Error::Closed);
        }
        let bucket = now / 60_000;
        if bucket != self.bucket {
            self.bucket = bucket;
            self.requests = 0
        }
        if self.requests >= p.requests_per_minute {
            return Err(Error::Limited);
        }
        self.requests += 1;
        let t = self.tickets.get(id).ok_or(Error::Forbidden)?;
        if t.revoked {
            return Err(Error::Forbidden);
        }
        if now >= t.expires_at_ms {
            return Err(Error::Expired);
        }
        Ok(t.clone())
    }
    pub fn revoke(&mut self, id: &str, now: i64) -> Result<Ticket, Error> {
        self.time(now)?;
        let t = self.tickets.get_mut(id).ok_or(Error::Forbidden)?;
        t.revoked = true;
        Ok(t.clone())
    }
    pub fn acknowledge(&mut self, id: &str, now: i64) -> Result<(), Error> {
        self.time(now)?;
        if !self.tickets.contains_key(id) {
            return Err(Error::Forbidden);
        }
        self.completed.insert(id.into());
        Ok(())
    }
    pub fn view(&self) -> serde_json::Value {
        serde_json::json!({"issued":self.tickets.len(),"reserved_projects":self.projects.len(),"completed":self.completed.len(),"requests":self.requests})
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Mode {
    OperatorStatic,
    Invitation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub version: u8,
    pub origin: String,
    pub purpose: String,
    pub ticket: Ticket,
    pub public_key: String,
    pub nonce: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}
impl Challenge {
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut b = b"RunLater invitation proof v1\n".to_vec();
        b.extend(
            serde_json::to_vec(&(
                self.version,
                &self.origin,
                &self.purpose,
                hash(&self.ticket)?,
                &self.ticket.id,
                &self.ticket.project_id,
                &self.ticket.grant_id,
                &self.public_key,
                &self.nonce,
                self.issued_at_ms,
                self.expires_at_ms,
            ))
            .map_err(|_| Error::Invalid)?,
        );
        Ok(b)
    }
    pub fn id(&self) -> Result<String, Error> {
        Ok(digest(&self.bytes()?))
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    challenge: Challenge,
    failures: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub ticket_id: String,
    pub project_id: String,
    pub public_key: String,
    pub grant_id: String,
    pub enrolled_at_ms: i64,
    pub expires_at_ms: i64,
    pub attempt_units: u64,
    pub permissions: BTreeSet<Permission>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub version: u8,
    pub mode: Mode,
    pub project: Project,
    ticket: Option<Ticket>,
    pending: BTreeMap<String, Pending>,
    receipt: Option<Receipt>,
    consumed_proof: Option<String>,
    clock_ms: i64,
}
impl Enrollment {
    pub fn new(mode: Mode) -> Self {
        Self {
            version: 1,
            mode,
            project: Project::default(),
            ticket: None,
            pending: BTreeMap::new(),
            receipt: None,
            consumed_proof: None,
            clock_ms: 0,
        }
    }
    fn time(&mut self, now: i64) -> Result<(), Error> {
        if self.version != 1 || now < 0 || now < self.clock_ms {
            return Err(Error::Clock);
        }
        self.clock_ms = now;
        Ok(())
    }
    fn ticket(&mut self, t: &Ticket, now: i64) -> Result<(), Error> {
        if self.mode != Mode::Invitation {
            return Err(Error::Closed);
        }
        t.validate()?;
        self.time(now)?;
        if let Some(old) = &self.ticket {
            let mut normal = t.clone();
            normal.revoked = old.revoked;
            if &normal != old {
                return Err(Error::Conflict);
            }
            if old.revoked {
                return Err(Error::Forbidden);
            }
        }
        if t.revoked {
            self.ticket = Some(t.clone());
            return Err(Error::Forbidden);
        }
        if now >= t.expires_at_ms {
            return Err(Error::Expired);
        }
        self.ticket = Some(t.clone());
        Ok(())
    }
    pub fn challenge(
        &mut self,
        t: &Ticket,
        key: &str,
        nonce: &str,
        now: i64,
    ) -> Result<Challenge, Error> {
        self.ticket(t, now)?;
        if self.receipt.is_some() {
            return Err(Error::Conflict);
        }
        if !identity::key_valid(key) || !hex64(nonce) {
            return Err(Error::Invalid);
        }
        self.pending.retain(|_, p| p.challenge.expires_at_ms > now);
        if self.pending.len() >= MAX_CHALLENGES {
            return Err(Error::Limited);
        }
        let c = Challenge {
            version: 1,
            origin: identity::ORIGIN.into(),
            purpose: "invitation_enrollment".into(),
            ticket: t.clone(),
            public_key: key.into(),
            nonce: nonce.into(),
            issued_at_ms: now,
            expires_at_ms: now.saturating_add(TTL).min(t.expires_at_ms),
        };
        let id = c.id()?;
        if self.pending.contains_key(&id) {
            return Err(Error::Conflict);
        }
        self.pending.insert(
            id,
            Pending {
                challenge: c.clone(),
                failures: 0,
            },
        );
        Ok(c)
    }
    /// Single project commit: ticket consume, key authority, immutable finite grant and receipt.
    /// Registry acknowledgement is separate derived progress; it cannot mint or replenish a grant.
    pub fn complete(
        &mut self,
        t: &Ticket,
        id: &str,
        signature: &str,
        now: i64,
    ) -> Result<Receipt, Error> {
        self.ticket(t, now)?;
        let p = self.pending.get(id).cloned().ok_or(Error::Expired)?;
        let c = &p.challenge;
        if now < c.issued_at_ms || now >= c.expires_at_ms {
            return Err(Error::Expired);
        }
        if &c.ticket != t || p.failures >= 3 {
            return Err(Error::Conflict);
        }
        let bytes = c.bytes()?;
        if !identity::verify_ed25519(&c.public_key, &bytes, signature) {
            self.pending.get_mut(id).ok_or(Error::Expired)?.failures = p.failures.saturating_add(1);
            return Err(Error::Forbidden);
        }
        if let Some(r) = &self.receipt {
            if self.consumed_proof.as_deref() == Some(id) && r.public_key == c.public_key {
                return Ok(r.clone());
            }
            return Err(Error::Conflict);
        }
        let expires = now
            .checked_add(t.terms.identity_ms)
            .filter(|n| *n <= 9_007_199_254_740_991)
            .ok_or(Error::Invalid)?;
        let mut next = self.clone();
        next.project
            .catalog
            .enroll_invitation_verified(
                &t.project_id,
                &c.public_key,
                &t.terms.permissions,
                expires,
                &bytes,
                signature,
                now,
            )
            .map_err(|_| Error::Forbidden)?;
        next.project
            .funding
            .apply(
                &funding::Policy {
                    version: 1,
                    project_id: t.project_id.clone(),
                    revision: 1,
                    active_grant: Some(funding::GrantSpec {
                        grant_id: t.grant_id.clone(),
                        total_attempt_units: t.terms.attempt_units,
                        admission_expires_at_ms: expires,
                    }),
                    revoked_grants: vec![],
                },
                now,
            )
            .map_err(|_| Error::Conflict)?;
        let receipt = Receipt {
            ticket_id: t.id.clone(),
            project_id: t.project_id.clone(),
            public_key: c.public_key.clone(),
            grant_id: t.grant_id.clone(),
            enrolled_at_ms: now,
            expires_at_ms: expires,
            attempt_units: t.terms.attempt_units,
            permissions: t.terms.permissions.clone(),
        };
        next.receipt = Some(receipt.clone());
        next.consumed_proof = Some(id.into());
        *self = next;
        Ok(receipt)
    }
    /// Pure recovery projection; no expiry extension, nonce consumption or registry acknowledgement.
    pub fn recover(
        &self,
        key: &str,
        nonce: &str,
        issued: i64,
        expires: i64,
        signature: &str,
        now: i64,
    ) -> Result<Receipt, Error> {
        if now < self.clock_ms
            || issued > now
            || issued < 0
            || expires <= now
            || expires - issued > 60_000
            || !hex64(nonce)
        {
            return Err(Error::Expired);
        }
        let r = self.receipt.as_ref().ok_or(Error::Forbidden)?;
        if r.public_key != key
            || now >= r.expires_at_ms
            || self.ticket.as_ref().is_none_or(|t| t.revoked)
        {
            return Err(Error::Forbidden);
        }
        let wire = Self::recovery_bytes(&r.project_id, key, nonce, issued, expires)?;
        if !identity::verify_ed25519(key, &wire, signature) {
            return Err(Error::Forbidden);
        }
        Ok(r.clone())
    }
    pub fn recovery_bytes(
        project: &str,
        key: &str,
        nonce: &str,
        issued: i64,
        expires: i64,
    ) -> Result<Vec<u8>, Error> {
        if !tenant_valid(project) {
            return Err(Error::Invalid);
        }
        let mut b = b"RunLater invitation recovery v1\n".to_vec();
        b.extend(
            serde_json::to_vec(&(1, identity::ORIGIN, project, key, nonce, issued, expires))
                .map_err(|_| Error::Invalid)?,
        );
        Ok(b)
    }
    pub fn view(&self) -> serde_json::Value {
        serde_json::json!({"mode":self.mode,"enrolled":self.receipt.is_some(),"receipt":self.receipt,"funding":self.project.funding,"pending":self.pending.len()})
    }
}
