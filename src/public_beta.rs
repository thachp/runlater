//! Bounded public key-possession admission. No invitation or project object before proof.
use crate::{
    auth::Permission,
    core::DAY,
    identity,
    invitation::{Challenge, Error, Policy, Registry, Terms, Ticket},
    security::digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const PROJECTS: usize = 10;
pub const UNITS: u64 = 100;
pub const DURATION: i64 = 7 * DAY;
pub const PENDING: usize = 32;
pub const ANONYMOUS_OPERATIONS: u32 = 512;
pub const CLIENT_OPERATIONS: u32 = 1000;
pub const PURPOSE: &str = "public_beta_registration";
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub release_id: String,
    pub opens_at_ms: i64,
    pub closes_at_ms: i64,
    pub callback_end_sec: i64,
    pub self_host: String,
}
impl Profile {
    pub fn validate(&self) -> Result<(), Error> {
        if !managed_receiver_host(&self.self_host)
            || self.closes_at_ms > 9_007_199_254_740_991
            || !crate::security::tenant_valid(&self.release_id)
            || self.release_id.len() > 32
            || self.opens_at_ms < 0
            || self.closes_at_ms <= self.opens_at_ms
            || self.closes_at_ms - self.opens_at_ms > DURATION
            || self.callback_end_sec < (self.closes_at_ms + DURATION + DAY) / 1000 + 300
            || self.callback_end_sec > 253402300799
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn terms() -> Terms {
        Terms {
            attempt_units: UNITS,
            identity_ms: DURATION,
            permissions: [
                Permission::Enqueue,
                Permission::Read,
                Permission::Cancel,
                Permission::Redrive,
                Permission::ManageDestinations,
            ]
            .into_iter()
            .collect(),
        }
    }
    pub fn ticket_id(&self, key: &str) -> Result<String, Error> {
        if !identity::key_valid(key) {
            return Err(Error::Invalid);
        }
        Ok(digest(
            &serde_json::to_vec(&(
                "runlater.public-beta.registration.v1",
                &self.release_id,
                key,
            ))
            .map_err(|_| Error::Invalid)?,
        ))
    }
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub ticket: Ticket,
    pub public_key: String,
    pub admitted_at_ms: i64,
    pub expires_at_ms: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    challenge: Challenge,
    failures: u8,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    version: u8,
    profile: Profile,
    registry: Registry,
    pending: BTreeMap<String, Pending>,
    grants: BTreeMap<String, Grant>,
    clock_ms: i64,
    anonymous_operations: u32,
    client_operations: BTreeMap<String, u32>,
    minute: i64,
    minute_requests: u32,
}
impl State {
    pub fn check(&self) -> Result<(), Error> {
        self.validate(&self.profile)
    }
    pub fn recovery(
        &mut self,
        project: &str,
        key: &str,
        nonce: &str,
        issued: i64,
        expires: i64,
        signature: &str,
        now: i64,
    ) -> Result<Ticket, Error> {
        if now < self.clock_ms {
            return Err(Error::Clock);
        }
        if self
            .client_operations
            .get(project)
            .copied()
            .unwrap_or_default()
            >= CLIENT_OPERATIONS
        {
            return Err(Error::Limited);
        }
        let g = self.grants.get(project).ok_or(Error::Forbidden)?;
        if g.ticket.revoked
            || now >= g.expires_at_ms
            || nonce.len() != 64
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || g.public_key != key
            || issued < 0
            || issued > now
            || expires <= now
            || expires - issued > 60000
        {
            return Err(Error::Forbidden);
        }
        let wire =
            crate::invitation::Enrollment::recovery_bytes(project, key, nonce, issued, expires)?;
        if !identity::verify_ed25519(key, &wire, signature) {
            return Err(Error::Forbidden);
        }
        let ticket = g.ticket.clone();
        self.time(now)?;
        let n = self.client_operations.entry(project.into()).or_default();
        if *n >= CLIENT_OPERATIONS {
            return Err(Error::Limited);
        }
        *n += 1;
        Ok(ticket)
    }
    pub fn new(profile: &Profile) -> Result<Self, Error> {
        profile.validate()?;
        let mut registry = Registry::default();
        registry.apply_public(
            &Policy {
                revision: 1,
                terms: Some(Profile::terms()),
                max_projects: PROJECTS,
                max_tickets: PROJECTS,
                requests_per_minute: 1024,
            },
            profile.opens_at_ms,
        )?;
        Ok(Self {
            version: 1,
            profile: profile.clone(),
            registry,
            pending: BTreeMap::new(),
            grants: BTreeMap::new(),
            clock_ms: profile.opens_at_ms,
            anonymous_operations: 0,
            client_operations: BTreeMap::new(),
            minute: 0,
            minute_requests: 0,
        })
    }
    pub fn validate(&self, profile: &Profile) -> Result<(), Error> {
        profile.validate()?;
        if self.version != 1
            || &self.profile != profile
            || self.grants.len() > PROJECTS
            || self.pending.len() > PENDING
            || self.anonymous_operations > ANONYMOUS_OPERATIONS
            || self.client_operations.len() > PROJECTS
            || self
                .client_operations
                .values()
                .any(|n| *n > CLIENT_OPERATIONS)
        {
            return Err(Error::Conflict);
        }
        for (p, g) in &self.grants {
            if p != &g.ticket.project_id
                || g.ticket.id != profile.ticket_id(&g.public_key)?
                || g.ticket.terms != Profile::terms()
                || g.expires_at_ms
                    != g.admitted_at_ms
                        .checked_add(DURATION)
                        .ok_or(Error::Invalid)?
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
    fn time(&mut self, now: i64) -> Result<(), Error> {
        if now < self.clock_ms || now < 0 {
            return Err(Error::Clock);
        }
        self.clock_ms = now;
        self.pending.retain(|_, p| p.challenge.expires_at_ms > now);
        Ok(())
    }
    fn anonymous(&mut self, now: i64) -> Result<(), Error> {
        if self.anonymous_operations >= ANONYMOUS_OPERATIONS {
            return Err(Error::Limited);
        }
        if now / 60000 == self.minute && self.minute_requests >= 24 {
            return Err(Error::Limited);
        }
        self.time(now)?;
        let minute = now / 60000;
        if minute != self.minute {
            self.minute = minute;
            self.minute_requests = 0
        }
        if self.minute_requests >= 24 {
            return Err(Error::Limited);
        }
        self.anonymous_operations += 1;
        self.minute_requests += 1;
        Ok(())
    }
    pub fn challenge(&mut self, key: &str, nonce: &str, now: i64) -> Result<Challenge, Error> {
        self.anonymous(now)?;
        if !identity::key_valid(key)
            || nonce.len() != 64
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
        let ticket_id = self.profile.ticket_id(key)?;
        let project = format!("p_{}", &ticket_id[..60]);
        if let Some(p) = self
            .pending
            .values()
            .find(|p| p.challenge.public_key == key)
        {
            return Ok(p.challenge.clone());
        }
        let ticket = if let Some(g) = self.grants.get(&project) {
            if now >= g.expires_at_ms {
                return Err(Error::Expired);
            }
            g.ticket.clone()
        } else {
            if now < self.profile.opens_at_ms || now >= self.profile.closes_at_ms {
                return Err(Error::Closed);
            }
            if self.grants.len() >= PROJECTS {
                return Err(Error::Limited);
            }
            self.registry
                .preview_public(&ticket_id, now + crate::invitation::TTL, now)?
        };
        if self.pending.len() >= PENDING {
            return Err(Error::Limited);
        }
        let c = Challenge {
            version: 1,
            origin: identity::ORIGIN.into(),
            purpose: PURPOSE.into(),
            ticket,
            public_key: key.into(),
            nonce: nonce.into(),
            issued_at_ms: now,
            expires_at_ms: now + crate::invitation::TTL,
        };
        self.pending.insert(
            c.id()?,
            Pending {
                challenge: c.clone(),
                failures: 0,
            },
        );
        Ok(c)
    }
    pub fn complete(
        &mut self,
        id: &str,
        signature: &str,
        now: i64,
    ) -> Result<(Grant, Challenge), Error> {
        self.anonymous(now)?;
        let p = self.pending.get(id).cloned().ok_or(Error::Expired)?;
        if p.failures >= 3 {
            return Err(Error::Forbidden);
        }
        let c = p.challenge;
        if !identity::verify_ed25519(&c.public_key, &c.bytes()?, signature) {
            self.pending.get_mut(id).ok_or(Error::Expired)?.failures += 1;
            return Err(Error::Forbidden);
        }
        if let Some(g) = self.grants.get(&c.ticket.project_id) {
            if g.ticket.revoked {
                return Err(Error::Forbidden);
            }
            if g.public_key != c.public_key || now >= g.expires_at_ms {
                return Err(Error::Expired);
            }
            return Ok((g.clone(), c));
        }
        if now >= self.profile.closes_at_ms || self.grants.len() >= PROJECTS {
            return Err(Error::Limited);
        }
        let ticket = self.registry.commit_public(&c.ticket, now)?;
        let g = Grant {
            ticket,
            public_key: c.public_key.clone(),
            admitted_at_ms: now,
            expires_at_ms: now.checked_add(DURATION).ok_or(Error::Invalid)?,
        };
        self.grants.insert(g.ticket.project_id.clone(), g.clone());
        Ok((g, c))
    }
    pub fn revoke(&mut self, projects: &[String], now: i64) -> Result<(), Error> {
        if projects.len() > PROJECTS || projects.iter().any(|p| !crate::security::tenant_valid(p)) {
            return Err(Error::Invalid);
        }
        if projects
            .iter()
            .any(|p| self.grants.get(p).is_some_and(|g| !g.ticket.revoked))
        {
            self.time(now)?;
            for project in projects {
                if let Some(g) = self.grants.get_mut(project) {
                    g.ticket.revoked = true
                }
            }
        }
        Ok(())
    }
    pub fn route(&self, project: &str) -> Result<Ticket, Error> {
        self.grants
            .get(project)
            .map(|g| g.ticket.clone())
            .ok_or(Error::Forbidden)
    }
    pub fn client(
        &mut self,
        e: &crate::signed::Envelope,
        signature: &str,
        now: i64,
    ) -> Result<Ticket, Error> {
        if now < self.clock_ms {
            return Err(Error::Clock);
        }
        if self
            .client_operations
            .get(&e.project_id)
            .copied()
            .unwrap_or_default()
            >= CLIENT_OPERATIONS
        {
            return Err(Error::Limited);
        }
        let g = self.grants.get(&e.project_id).ok_or(Error::Forbidden)?;
        if g.public_key != e.public_key
            || e.origin != identity::ORIGIN
            || e.version != 1
            || e.issued_at_ms > now
            || e.expires_at_ms <= now
            || e.expires_at_ms - e.issued_at_ms > 60000
            || !identity::verify_ed25519(
                &e.public_key,
                &e.bytes().map_err(|_| Error::Invalid)?,
                signature,
            )
        {
            return Err(Error::Forbidden);
        }
        let ticket = g.ticket.clone();
        self.time(now)?;
        let n = self
            .client_operations
            .entry(e.project_id.clone())
            .or_default();
        if *n >= CLIENT_OPERATIONS {
            return Err(Error::Limited);
        }
        *n += 1;
        Ok(ticket)
    }
    pub fn view(&self, now: i64) -> serde_json::Value {
        serde_json::json!({"mode":"public_free_beta","registration_open":now>=self.profile.opens_at_ms&&now<self.profile.closes_at_ms&&self.grants.len()<PROJECTS&&self.anonymous_operations<ANONYMOUS_OPERATIONS,"remaining_projects":PROJECTS-self.grants.len(),"trial":{"duration_ms":DURATION,"attempt_units":UNITS,"units_reserved_per_task":5},"limits":{"lifetime_projects":PROJECTS,"lifetime_tasks_per_project":16,"lifetime_publications_per_project":128,"client_operations_per_project":CLIENT_OPERATIONS,"receiver":"worker.account.workers.dev"},"payments":false})
    }
    pub fn grant(&self, project: &str) -> Option<&Grant> {
        self.grants.get(project)
    }
}

/// Server-held only; no Debug/Serialize implementation. The runtime stores only derived-key hashes.
pub struct Master([u8; 32]);
pub struct TenantKey {
    key: [u8; 32],
}
impl crate::callback::Material for TenantKey {
    fn key(&self, id: &str) -> Option<&[u8]> {
        if id == "beta_v1" {
            Some(&self.key)
        } else {
            None
        }
    }
}
impl Master {
    pub fn from_hex(raw: &str) -> Result<Self, Error> {
        if raw.len() != 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
        let v = hex::decode(raw).map_err(|_| Error::Invalid)?;
        if v.iter().all(|b| *b == v[0]) {
            return Err(Error::Invalid);
        }
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&v);
        Ok(Self(bytes))
    }
    fn mac(&self, label: &str, parts: &[&str]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut h = Hmac::<Sha256>::new_from_slice(&self.0).expect("fixed valid HMAC key size");
        h.update(label.as_bytes());
        for part in parts {
            h.update(&(part.len() as u64).to_be_bytes());
            h.update(part.as_bytes())
        }
        h.finalize().into_bytes().into()
    }
    pub fn tenant(&self, release: &str, project: &str) -> Result<TenantKey, Error> {
        if !crate::security::tenant_valid(release) || !crate::security::tenant_valid(project) {
            return Err(Error::Invalid);
        }
        Ok(TenantKey {
            key: self.mac(
                "RunLater public beta callback KDF v1\n",
                &[release, project, "beta_v1"],
            ),
        })
    }
    pub fn ip_bucket(&self, release: &str, ip: &str, now: i64) -> Result<String, Error> {
        let ip: std::net::IpAddr = ip.parse().map_err(|_| Error::Invalid)?;
        let day = (now / DAY).to_string();
        Ok(hex::encode(self.mac(
            "RunLater public beta IP bucket v1\n",
            &[release, &day, &ip.to_string()],
        )))
    }
}
pub fn managed_receiver_host(host: &str) -> bool {
    let labels: Vec<_> = host.split('.').collect();
    labels.len() == 4
        && labels[2] == "workers"
        && labels[3] == "dev"
        && labels[..2].iter().all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
