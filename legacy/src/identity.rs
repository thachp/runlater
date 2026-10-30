//! Operator-approved public-key possession. No bearer issuance, entitlement or payment authority.
use crate::{
    auth::Permission,
    security::{digest, tenant_valid},
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const ORIGIN: &str = "https://api.runlater.io";
pub const TTL: i64 = 300_000;
pub const MAX_CHALLENGES: usize = 64;
pub const MAX_KEYS: usize = 256;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Forbidden,
    Conflict,
    Expired,
    Limited,
    ClockRegressed,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub public_key: String,
    pub permissions: BTreeSet<Permission>,
    pub expires_at_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub project_id: String,
    pub revision: u64,
    pub revoked: bool,
    pub approvals: Vec<Approval>,
    pub revoked_keys: Vec<String>,
}
pub fn key_valid(key: &str) -> bool {
    decode::<32>(key)
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
        .is_some_and(|key| !key.is_weak())
}
fn decode<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}
impl Policy {
    pub fn validate(&self) -> Result<(), Error> {
        if !tenant_valid(&self.project_id)
            || self.revision == 0
            || self.revision > 9_007_199_254_740_991
            || self.approvals.len() > 8
            || self.revoked_keys.len() > MAX_KEYS
        {
            return Err(Error::Invalid);
        }
        let mut keys = BTreeSet::new();
        for a in &self.approvals {
            if !key_valid(&a.public_key)
                || !keys.insert(&a.public_key)
                || a.permissions.is_empty()
                || a.permissions.contains(&Permission::ManageKeys)
                || a.expires_at_ms <= 0
                || a.expires_at_ms > 9_007_199_254_740_991
            {
                return Err(Error::Invalid);
            }
        }
        if self.revoked_keys.iter().any(|k| !key_valid(k)) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn hash(&self) -> Result<String, Error> {
        Ok(digest(
            &serde_json::to_vec(self).map_err(|_| Error::Invalid)?,
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Challenge {
    pub version: u8,
    pub origin: String,
    pub purpose: String,
    pub project_id: String,
    pub public_key: String,
    pub nonce: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub policy_revision: u64,
    pub policy_hash: String,
    pub permissions: BTreeSet<Permission>,
    pub identity_expires_at_ms: i64,
}
impl Challenge {
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = b"RunLater enrollment proof v1\n".to_vec();
        bytes.extend(
            serde_json::to_vec(&(
                self.version,
                &self.origin,
                &self.purpose,
                &self.project_id,
                &self.public_key,
                &self.nonce,
                self.issued_at_ms,
                self.expires_at_ms,
                self.policy_revision,
                &self.policy_hash,
                &self.permissions,
                self.identity_expires_at_ms,
            ))
            .map_err(|_| Error::Invalid)?,
        );
        Ok(bytes)
    }
    pub fn id(&self) -> Result<String, Error> {
        Ok(digest(&self.bytes()?))
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Pending {
    challenge: Challenge,
    consumed: bool,
    failed_proofs: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub project_id: String,
    pub public_key: String,
    pub permissions: BTreeSet<Permission>,
    pub enrolled_at_ms: i64,
    pub expires_at_ms: i64,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) trial: Option<crate::anonymous_trial::Descriptor>,
    project_id: String,
    revision: u64,
    policy_hash: String,
    project_revoked: bool,
    revoked_keys: BTreeSet<String>,
    approvals: BTreeMap<String, Approval>,
    identities: BTreeMap<String, Identity>,
    challenges: BTreeMap<String, Pending>,
    clock_ms: i64,
}
impl Catalog {
    fn time(&mut self, now: i64) -> Result<(), Error> {
        if now < 0 || now < self.clock_ms {
            return Err(Error::ClockRegressed);
        }
        self.clock_ms = now;
        Ok(())
    }
    /// Immutable policy revisions and irreversible revocations survive restarts/redeploys.
    pub fn apply_policy(&mut self, policy: &Policy, now: i64) -> Result<(), Error> {
        policy.validate()?;
        if policy
            .approvals
            .iter()
            .any(|a| a.expires_at_ms.saturating_sub(now) > 30 * crate::core::DAY)
        {
            return Err(Error::Invalid);
        }
        let hash = policy.hash()?;
        if !self.project_id.is_empty() && self.project_id != policy.project_id {
            return Err(Error::Forbidden);
        }
        if policy.revision < self.revision
            || policy.revision == self.revision && hash != self.policy_hash
        {
            return Err(Error::Conflict);
        }
        let mut next = self.clone();
        next.time(now)?;
        if policy.revision > self.revision {
            let approvals: BTreeMap<_, _> = policy
                .approvals
                .iter()
                .map(|a| (a.public_key.clone(), a.clone()))
                .collect();
            for key in self.approvals.keys() {
                if !approvals.contains_key(key) {
                    next.revoked_keys.insert(key.clone());
                }
            }
            next.revoked_keys.extend(policy.revoked_keys.clone());
            if next.revoked_keys.len() + next.identities.len() + approvals.len() > MAX_KEYS {
                return Err(Error::Limited);
            }
            next.approvals = approvals;
            next.project_id = policy.project_id.clone();
            next.revision = policy.revision;
            next.policy_hash = hash;
        }
        next.project_revoked |= policy.revoked;
        *self = next;
        Ok(())
    }
    fn approval(&self, key: &str, now: i64) -> Result<&Approval, Error> {
        if self.project_revoked || self.revoked_keys.contains(key) {
            return Err(Error::Forbidden);
        }
        let a = self.approvals.get(key).ok_or(Error::Forbidden)?;
        if now >= a.expires_at_ms {
            return Err(Error::Expired);
        }
        Ok(a)
    }
    pub fn challenge(
        &mut self,
        project: &str,
        key: &str,
        nonce: &str,
        now: i64,
    ) -> Result<Challenge, Error> {
        self.time(now)?;
        if project != self.project_id || decode::<32>(nonce).is_none() {
            return Err(Error::Invalid);
        }
        let approval = self.approval(key, now)?.clone();
        if self.identities.contains_key(key) {
            return Err(Error::Conflict);
        }
        self.challenges
            .retain(|_, p| p.challenge.expires_at_ms > now);
        if self.challenges.len() >= MAX_CHALLENGES
            || self
                .challenges
                .values()
                .filter(|p| p.challenge.public_key == key)
                .count()
                >= 8
        {
            return Err(Error::Limited);
        }
        let challenge = Challenge {
            version: 1,
            origin: ORIGIN.into(),
            purpose: "operator_alpha_enrollment".into(),
            project_id: project.into(),
            public_key: key.into(),
            nonce: nonce.into(),
            issued_at_ms: now,
            expires_at_ms: now.saturating_add(TTL).min(approval.expires_at_ms),
            policy_revision: self.revision,
            policy_hash: self.policy_hash.clone(),
            permissions: approval.permissions,
            identity_expires_at_ms: approval.expires_at_ms,
        };
        let id = challenge.id()?;
        if self.challenges.contains_key(&id) {
            return Err(Error::Conflict);
        }
        self.challenges.insert(
            id,
            Pending {
                challenge: challenge.clone(),
                consumed: false,
                failed_proofs: 0,
            },
        );
        Ok(challenge)
    }
    /// Verification, one-time consumption and enrollment are synchronous; runtime commits one snapshot.
    pub fn enroll(
        &mut self,
        project: &str,
        id: &str,
        signature: &str,
        now: i64,
    ) -> Result<Identity, Error> {
        self.time(now)?;
        if project != self.project_id {
            return Err(Error::Forbidden);
        }
        let pending = self.challenges.get(id).cloned().ok_or(Error::Expired)?;
        let c = &pending.challenge;
        if pending.consumed || pending.failed_proofs >= 3 {
            return Err(Error::Conflict);
        }
        if now < c.issued_at_ms || now >= c.expires_at_ms {
            return Err(Error::Expired);
        }
        self.approval(&c.public_key, now)?;
        if c.policy_revision != self.revision || c.policy_hash != self.policy_hash {
            return Err(Error::Conflict);
        }
        if self.identities.contains_key(&c.public_key) {
            return Err(Error::Conflict);
        }
        let canonical = c.bytes()?;
        let valid = verify_ed25519(&c.public_key, &canonical, signature);
        if !valid {
            if let Some(p) = self.challenges.get_mut(id) {
                p.failed_proofs = p.failed_proofs.saturating_add(1);
            }
            return Err(Error::Forbidden);
        }
        let identity = Identity {
            project_id: project.into(),
            public_key: c.public_key.clone(),
            permissions: c.permissions.clone(),
            enrolled_at_ms: now,
            expires_at_ms: c.identity_expires_at_ms,
        };
        self.challenges.get_mut(id).ok_or(Error::Expired)?.consumed = true;
        self.identities
            .insert(c.public_key.clone(), identity.clone());
        Ok(identity)
    }
    /// Internal invitation completion only; runtime never accepts an Approval from public input.
    pub(crate) fn enroll_invitation_verified(
        &mut self,
        project: &str,
        key: &str,
        permissions: &BTreeSet<Permission>,
        expires: i64,
        proof: &[u8],
        signature: &str,
        now: i64,
    ) -> Result<Identity, Error> {
        if !proof.starts_with(b"RunLater invitation proof v1\n")
            || !verify_ed25519(key, proof, signature)
            || self.identities.contains_key(key)
        {
            return Err(Error::Forbidden);
        }
        let mut next = self.clone();
        let policy = Policy {
            project_id: project.into(),
            revision: 1,
            revoked: false,
            approvals: vec![Approval {
                public_key: key.into(),
                permissions: permissions.clone(),
                expires_at_ms: expires,
            }],
            revoked_keys: vec![],
        };
        next.apply_policy(&policy, now)?;
        next.approval(key, now)?;
        let identity = Identity {
            project_id: project.into(),
            public_key: key.into(),
            permissions: permissions.clone(),
            enrolled_at_ms: now,
            expires_at_ms: expires,
        };
        next.identities.insert(key.into(), identity.clone());
        *self = next;
        Ok(identity)
    }
    pub(crate) fn enroll_public_verified(
        &mut self,
        project: &str,
        key: &str,
        permissions: &BTreeSet<Permission>,
        expires: i64,
        proof: &[u8],
        signature: &str,
        now: i64,
    ) -> Result<Identity, Error> {
        if !proof.starts_with(b"RunLater public registration proof v1\n")
            || !verify_ed25519(key, proof, signature)
            || self.identities.contains_key(key)
        {
            return Err(Error::Forbidden);
        }
        let mut next = self.clone();
        let policy = Policy {
            project_id: project.into(),
            revision: 1,
            revoked: false,
            approvals: vec![Approval {
                public_key: key.into(),
                permissions: permissions.clone(),
                expires_at_ms: expires,
            }],
            revoked_keys: vec![],
        };
        next.apply_policy(&policy, now)?;
        next.approval(key, now)?;
        let identity = Identity {
            project_id: project.into(),
            public_key: key.into(),
            permissions: permissions.clone(),
            enrolled_at_ms: now,
            expires_at_ms: expires,
        };
        next.identities.insert(key.into(), identity.clone());
        *self = next;
        Ok(identity)
    }
    pub(crate) fn revoke_invitation(
        &mut self,
        project: &str,
        key: &str,
        now: i64,
    ) -> Result<(), Error> {
        if self.project_id != project {
            return Err(Error::Forbidden);
        }
        self.time(now)?;
        self.project_revoked = true;
        self.revoked_keys.insert(key.into());
        Ok(())
    }
    pub fn identity_view(
        &self,
        project: &str,
        key: &str,
        now: i64,
    ) -> Result<serde_json::Value, Error> {
        self.authorize(project, key, Permission::Read, now)?;
        let identity = self.identities.get(key).ok_or(Error::Forbidden)?;
        let approval = self.approval(key, now.max(self.clock_ms))?;
        let permissions: BTreeSet<_> = identity
            .permissions
            .intersection(&approval.permissions)
            .copied()
            .collect();
        Ok(
            serde_json::json!({"project_id":project,"public_key":key,"permissions":permissions,"expires_at_ms":identity.expires_at_ms.min(approval.expires_at_ms)}),
        )
    }
    pub(crate) fn authorized_expiry(
        &self,
        project: &str,
        key: &str,
        permission: Permission,
        now: i64,
    ) -> Result<i64, Error> {
        self.authorize(project, key, permission, now)?;
        Ok(self
            .identities
            .get(key)
            .ok_or(Error::Forbidden)?
            .expires_at_ms
            .min(self.approval(key, now.max(self.clock_ms))?.expires_at_ms))
    }
    /// Identity lookup only; callers must separately authenticate request possession. No task route uses this yet.
    pub(crate) fn authorize_trial(
        &self,
        project: &str,
        permission: Permission,
        now: i64,
    ) -> Result<(), Error> {
        let t = self.trial.as_ref().ok_or(Error::Forbidden)?;
        if self.project_revoked
            || project != self.project_id
            || project != t.project_id()?
            || now < t.issued_at_ms
            || now >= t.expires_at_ms
            || !t.allows(permission)
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub fn authorize(
        &self,
        project: &str,
        key: &str,
        permission: Permission,
        now: i64,
    ) -> Result<(), Error> {
        if project != self.project_id {
            return Err(Error::Forbidden);
        }
        let now = now.max(self.clock_ms);
        let a = self.approval(key, now)?;
        let identity = self.identities.get(key).ok_or(Error::Forbidden)?;
        if now < identity.enrolled_at_ms || now >= identity.expires_at_ms {
            return Err(Error::Expired);
        }
        if !a.permissions.contains(&permission) || !identity.permissions.contains(&permission) {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
}
pub fn forbidden_binding(name: &str) -> bool {
    name.starts_with("LOCAL_")
        || name.starts_with("STAGING_")
        || name.starts_with("TEST_")
        || matches!(
            name,
            "API_KEY_HASHES" | "LEDGER" | "READY" | "TRANSPORT_DLQ_NAME"
        )
}

pub fn verify_ed25519(public_key: &str, message: &[u8], signature: &str) -> bool {
    decode::<32>(public_key)
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .filter(|k| !k.is_weak())
        .zip(decode::<64>(signature))
        .is_some_and(|(key, sig)| {
            key.verify_strict(message, &Signature::from_bytes(&sig))
                .is_ok()
        })
}
