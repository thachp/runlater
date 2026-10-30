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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    trials: BTreeMap<String, crate::anonymous_trial::Grant>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    trial_tombstones: BTreeMap<String, crate::anonymous_trial::Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    receiver_pins: BTreeMap<String, crate::receiver_pairing::Manifest>,
    clock_ms: i64,
    anonymous_operations: u32,
    client_operations: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    mcp_revocations: BTreeMap<String, crate::mcp_delegation::Revocations>,
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
            trials: BTreeMap::new(),
            trial_tombstones: BTreeMap::new(),
            receiver_pins: BTreeMap::new(),
            clock_ms: profile.opens_at_ms,
            anonymous_operations: 0,
            client_operations: BTreeMap::new(),
            mcp_revocations: BTreeMap::new(),
            minute: 0,
            minute_requests: 0,
        })
    }
    pub fn validate(&self, profile: &Profile) -> Result<(), Error> {
        profile.validate()?;
        if self.version != 1
            || &self.profile != profile
            || self.grants.len() + self.trials.len() > PROJECTS
            || self.trial_tombstones.len() > PENDING
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
        if self.mcp_revocations.len() > PROJECTS {
            return Err(Error::Invalid);
        }
        for (project, state) in &self.mcp_revocations {
            if !self.grants.contains_key(project) || state.validate().is_err() {
                return Err(Error::Invalid);
            }
        }
        if self.receiver_pins.len() > PROJECTS {
            return Err(Error::Invalid);
        }
        for (p, m) in &self.receiver_pins {
            m.check().map_err(|_| Error::Invalid)?;
            let g = self.trials.get(p).ok_or(Error::Invalid)?;
            m.authorize(&g.descriptor, m.issued_at_ms)
                .map_err(|_| Error::Invalid)?;
            if m.project_id != *p
                || m.release_id != profile.release_id
                || m.expires_at_ms > g.descriptor.expires_at_ms
                || !g.descriptor.allows(crate::auth::Permission::ReceiverSetup)
            {
                return Err(Error::Invalid);
            }
        }
        for (p, g) in &self.trials {
            g.check().map_err(|_| Error::Invalid)?;
            if p != &g.ticket.project_id
                || g.descriptor.release_id != profile.release_id
                || self.grants.contains_key(p)
            {
                return Err(Error::Invalid);
            }
        }
        for (p, d) in &self.trial_tombstones {
            d.validate().map_err(|_| Error::Invalid)?;
            if p != &d.project_id().map_err(|_| Error::Invalid)?
                || d.release_id != profile.release_id
                || self.trials.contains_key(p)
            {
                return Err(Error::Invalid);
            }
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
            if self.grants.len() + self.trials.len() >= PROJECTS {
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
        if now >= self.profile.closes_at_ms || self.grants.len() + self.trials.len() >= PROJECTS {
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
        if projects.iter().any(|p| {
            self.grants.get(p).is_some_and(|g| !g.ticket.revoked)
                || self.trials.get(p).is_some_and(|g| !g.ticket.revoked)
        }) {
            self.time(now)?;
            for project in projects {
                if let Some(g) = self.trials.get_mut(project) {
                    g.ticket.revoked = true;
                }
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
            .or_else(|| self.trials.get(project).map(|g| g.ticket.clone()))
            .ok_or(Error::Forbidden)
    }
    pub fn client(
        &mut self,
        e: &crate::signed::Envelope,
        signature: &str,
        now: i64,
    ) -> Result<Ticket, Error> {
        self.client_with_proof(e, crate::mcp_delegation::Proof::Owner(signature), now)
    }
    pub fn client_with_proof(
        &mut self,
        e: &crate::signed::Envelope,
        proof: crate::mcp_delegation::Proof<'_>,
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
        {
            return Err(Error::Forbidden);
        }
        match proof {
            crate::mcp_delegation::Proof::Trial { .. } => return Err(Error::Forbidden),
            crate::mcp_delegation::Proof::Owner(signature) => {
                if !identity::verify_ed25519(
                    &e.public_key,
                    &e.bytes().map_err(|_| Error::Invalid)?,
                    signature,
                ) {
                    return Err(Error::Forbidden);
                }
            }
            crate::mcp_delegation::Proof::Delegated {
                signature,
                certificate,
                trust,
                ..
            } => {
                if trust.release_id != self.profile.release_id
                    || g.ticket.revoked
                    || certificate.issued_at_ms < g.admitted_at_ms
                {
                    return Err(Error::Forbidden);
                }
                certificate
                    .verify(
                        e,
                        signature,
                        trust,
                        g.expires_at_ms,
                        self.mcp_revocations.get(&e.project_id).map(|r| r.floor_ms),
                        now,
                    )
                    .map_err(|_| Error::Forbidden)?;
            }
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
    /// Read-only routing for OAuth issuance: validates current real grant without spending a client operation.
    pub fn validate_mcp_delegation(
        &self,
        e: &crate::signed::Envelope,
        signature: &str,
        certificate: &crate::mcp_delegation::Certificate,
        trust: crate::mcp_delegation::Trust<'_>,
        now: i64,
    ) -> Result<Ticket, Error> {
        if now < self.clock_ms
            || e.method != "POST"
            || e.path != crate::mcp_delegation::VALIDATE_PATH
            || e.validate_request(b"{}", now).is_err()
        {
            return Err(Error::Invalid);
        }
        let grant = self.grants.get(&e.project_id).ok_or(Error::Forbidden)?;
        if trust.release_id != self.profile.release_id
            || grant.ticket.revoked
            || grant.public_key != e.public_key
            || now < grant.admitted_at_ms
            || now >= grant.expires_at_ms
            || certificate.issued_at_ms < grant.admitted_at_ms
        {
            return Err(Error::Forbidden);
        }
        certificate
            .verify(
                e,
                signature,
                trust,
                grant.expires_at_ms,
                self.mcp_revocations.get(&e.project_id).map(|r| r.floor_ms),
                now,
            )
            .map_err(|_| Error::Forbidden)?;
        Ok(grant.ticket.clone())
    }
    /// Registry-authoritative revoke: cutoff and receipt commit before subsequent delegated admission.
    /// Already-admitted requests may finish; no cross-object atomicity is claimed.
    pub fn revoke_mcp_delegations(
        &mut self,
        e: &crate::signed::Envelope,
        signature: &str,
        now: i64,
    ) -> Result<serde_json::Value, Error> {
        if now < self.clock_ms || now < 0 || now > 9_007_199_254_740_991 {
            return Err(Error::Clock);
        }
        if e.method != "POST"
            || e.path != crate::mcp_delegation::REVOKE_PATH
            || e.validate_request(b"{}", now).is_err()
        {
            return Err(Error::Invalid);
        }
        let grant = self.grants.get(&e.project_id).ok_or(Error::Forbidden)?;
        if grant.public_key != e.public_key
            || grant.ticket.revoked
            || now < grant.admitted_at_ms
            || now >= grant.expires_at_ms
            || !grant.ticket.terms.permissions.contains(&Permission::Cancel)
            || !identity::verify_ed25519(
                &e.public_key,
                &e.bytes().map_err(|_| Error::Invalid)?,
                signature,
            )
        {
            return Err(Error::Forbidden);
        }
        // Authenticated replay is read-only and never consumes more client operations or changes the cutoff.
        if let Some(cutoff) = self
            .mcp_revocations
            .get(&e.project_id)
            .and_then(|r| r.receipts.get(&e.idempotency_key))
        {
            return Ok(serde_json::json!({"revoked_before_ms":cutoff,"replayed":true}));
        }
        if self
            .mcp_revocations
            .get(&e.project_id)
            .is_some_and(|r| r.receipts.len() >= 128)
        {
            return Err(Error::Limited);
        }
        let mut next = self.clone();
        next.client(e, signature, now)?;
        let state = next
            .mcp_revocations
            .entry(e.project_id.clone())
            .or_default();
        state.floor_ms = state.floor_ms.max(now);
        state.receipts.insert(e.idempotency_key.clone(), now);
        *self = next;
        Ok(serde_json::json!({"revoked_before_ms":now,"replayed":false}))
    }
    /// Explicit provisioning only. The shared Registry is the single cohort reservation authority.
    pub fn trial_request(
        &mut self,
        e: &crate::signed::Envelope,
        d: &crate::anonymous_trial::Descriptor,
        secret: &str,
        signature: &str,
        trust: crate::mcp_delegation::Trust<'_>,
        body: &[u8],
        now: i64,
    ) -> Result<serde_json::Value, Error> {
        use crate::anonymous_trial::{PROVISION, REVOKE, STATUS, VALIDATE};
        e.validate_trial_request(body, now)
            .map_err(|_| Error::Forbidden)?;
        d.verify(e, secret, signature, trust, now)
            .map_err(|_| Error::Forbidden)?;
        if trust.release_id != self.profile.release_id || now < self.clock_ms {
            return Err(Error::Forbidden);
        }
        let lifecycle = matches!(e.path.as_str(), PROVISION | VALIDATE | STATUS | REVOKE);
        if lifecycle
            && (if e.path == STATUS {
                e.method != "GET" || !body.is_empty()
            } else {
                e.method != "POST" || body != b"{}"
            })
        {
            return Err(Error::Invalid);
        }
        let pairing = e.path == crate::receiver_pairing::PIN;
        if !lifecycle && !pairing {
            if !d.allows(crate::mcp_delegation::task_permission(e).map_err(|_| Error::Forbidden)?) {
                return Err(Error::Forbidden);
            }
        }
        if let Some(old) = self.trial_tombstones.get(&e.project_id) {
            if old != d {
                return Err(Error::Conflict);
            }
            return if e.path == REVOKE {
                Ok(serde_json::json!({"revoked":true,"provisioned":false}))
            } else {
                Err(Error::Forbidden)
            };
        }
        if let Some(g) = self.trials.get(&e.project_id) {
            if &g.descriptor != d {
                return Err(Error::Conflict);
            }
        }
        if e.path == REVOKE {
            if let Some(g) = self.trials.get_mut(&e.project_id) {
                if g.revoked_at_ms.is_none() {
                    g.revoked_at_ms = Some(now);
                }
                return Ok(serde_json::json!({"revoked":true,"provisioned":true}));
            }
            if self.trial_tombstones.len() >= PENDING {
                return Err(Error::Limited);
            }
            self.trial_tombstones
                .insert(e.project_id.clone(), d.clone());
            return Ok(serde_json::json!({"revoked":true,"provisioned":false}));
        }
        if e.path == PROVISION && !self.trials.contains_key(&e.project_id) {
            if now < self.profile.opens_at_ms
                || now >= self.profile.closes_at_ms
                || self.grants.len() + self.trials.len() >= PROJECTS
            {
                return Err(Error::Limited);
            }
            self.anonymous(now)?;
            let mut ticket = self.registry.preview_public(
                &d.ticket_id().map_err(|_| Error::Invalid)?,
                (now + 300_000).min(d.expires_at_ms),
                now,
            )?;
            ticket.terms = d.terms();
            let ticket = self.registry.commit_trial(&ticket, now)?;
            self.trials.insert(
                e.project_id.clone(),
                crate::anonymous_trial::Grant {
                    descriptor: d.clone(),
                    ticket,
                    revoked_at_ms: None,
                },
            );
        }
        let Some(g) = self.trials.get(&e.project_id) else {
            return if e.path == STATUS || e.path == VALIDATE {
                Ok(d.status(false))
            } else {
                Err(Error::Forbidden)
            };
        };
        g.active(now).map_err(|_| Error::Forbidden)?;
        let new_pairing = pairing && !self.receiver_pins.contains_key(&e.project_id);
        if !lifecycle
            && (!pairing || new_pairing)
            && self
                .client_operations
                .get(&e.project_id)
                .copied()
                .unwrap_or_default()
                >= CLIENT_OPERATIONS
        {
            return Err(Error::Limited);
        }
        if pairing {
            if e.method != "POST" {
                return Err(Error::Invalid);
            }
            let m: crate::receiver_pairing::Manifest =
                serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
            m.authorize(d, now).map_err(|_| Error::Forbidden)?;
            if e.idempotency_key != m.pairing_id {
                return Err(Error::Invalid);
            }
            if let Some(old) = self.receiver_pins.get(&e.project_id) {
                if old != &m {
                    return Err(Error::Conflict);
                }
            } else {
                self.receiver_pins.insert(e.project_id.clone(), m);
            }
        }
        if !lifecycle && (!pairing || new_pairing) {
            let n = self
                .client_operations
                .entry(e.project_id.clone())
                .or_default();
            if *n >= CLIENT_OPERATIONS {
                return Err(Error::Limited);
            }
            *n += 1;
        }
        Ok(serde_json::json!({"grant":g}))
    }
    pub fn receiver_route(
        &self,
        r: &crate::receiver_pairing::Request,
        now: i64,
    ) -> Result<serde_json::Value, Error> {
        if now < 0 || now > 9_007_199_254_740_991 || now < self.clock_ms {
            return Err(Error::Clock);
        }
        let m = self
            .receiver_pins
            .get(&r.project_id)
            .ok_or(Error::Forbidden)?;
        let g = self.trials.get(&r.project_id).ok_or(Error::Forbidden)?;
        g.active(now).map_err(|_| Error::Forbidden)?;
        m.authorize(&g.descriptor, now)
            .map_err(|_| Error::Forbidden)?;
        r.verify(m, now).map_err(|_| Error::Forbidden)?;
        Ok(serde_json::json!({"grant":g,"manifest":m}))
    }
    pub fn view(&self, now: i64) -> serde_json::Value {
        serde_json::json!({"mode":"public_free_beta","registration_open":now>=self.profile.opens_at_ms&&now<self.profile.closes_at_ms&&self.grants.len()+self.trials.len()<PROJECTS&&self.anonymous_operations<ANONYMOUS_OPERATIONS,"remaining_projects":PROJECTS-self.grants.len()-self.trials.len(),"trial":{"duration_ms":DURATION,"attempt_units":UNITS,"units_reserved_per_task":5},"limits":{"lifetime_projects":PROJECTS,"lifetime_tasks_per_project":16,"lifetime_publications_per_project":128,"client_operations_per_project":CLIENT_OPERATIONS,"receiver":"worker.account.workers.dev"},"payments":false})
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
