//! Distinct bounded bearer-capability principal. No owner signing key is generated or held.
use crate::{
    identity::{self, Error},
    mcp_delegation::Trust,
    security::digest,
    signed::Envelope,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
pub const PROVISION: &str = "/v1/mcp/trials/provision";
pub const VALIDATE: &str = "/v1/mcp/trials/validate";
pub const STATUS: &str = "/v1/mcp/trials/status";
pub const REVOKE: &str = "/v1/mcp/trials/revoke";
pub fn hex32(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub version: u8,
    pub release_id: String,
    pub bootstrap_id: String,
    pub capability_hash: String,
    pub revocation_hash: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub permissions: Vec<String>,
}
impl Descriptor {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version != 1
            || self.release_id.is_empty()
            || self.release_id.len() > 32
            || !self
                .release_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || !hex32(&self.bootstrap_id)
            || !hex32(&self.capability_hash)
            || !hex32(&self.revocation_hash)
            || self.issued_at_ms < 0
            || self.expires_at_ms > 9_007_199_254_740_991
            || self.issued_at_ms.checked_add(crate::public_beta::DURATION)
                != Some(self.expires_at_ms)
            || self.permissions.is_empty()
            || self.permissions.len() > 3
            || self
                .permissions
                .iter()
                .any(|p| !matches!(p.as_str(), "cancel" | "enqueue" | "read"))
            || self.permissions.windows(2).any(|p| p[0] >= p[1])
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn allows(&self, p: crate::auth::Permission) -> bool {
        self.permissions.iter().any(|s| {
            matches!(
                (s.as_str(), p),
                ("cancel", crate::auth::Permission::Cancel)
                    | ("enqueue", crate::auth::Permission::Enqueue)
                    | ("read", crate::auth::Permission::Read)
            )
        })
    }
    pub fn terms(&self) -> crate::invitation::Terms {
        let mut t = crate::public_beta::Profile::terms();
        t.permissions.retain(|p| self.allows(*p));
        t
    }
    pub fn status(&self, active: bool) -> serde_json::Value {
        serde_json::json!({"state":if active{"active"}else{"unprovisioned"},"project_id":self.project_id().unwrap_or_default(),"expires_at_ms":self.expires_at_ms,"permissions":self.permissions,"receiver_ready":false,"attempt_units":if active{100}else{0},"client_operations_limit":1000})
    }
    pub fn ticket_id(&self) -> Result<String, Error> {
        self.validate()?;
        Ok(digest(
            format!(
                "RunLater anonymous trial project v1\n{}",
                serde_json::to_string(&(1, &self.release_id, &self.bootstrap_id))
                    .map_err(|_| Error::Invalid)?
            )
            .as_bytes(),
        ))
    }
    pub fn project_id(&self) -> Result<String, Error> {
        Ok(format!("p_{}", &self.ticket_id()?[..60]))
    }
    pub fn capability_hash(&self, cap: &str) -> Result<String, Error> {
        if !hex32(cap) {
            return Err(Error::Forbidden);
        }
        Ok(digest(
            format!(
                "RunLater anonymous trial capability v1\n{}",
                serde_json::to_string(&(1, &self.release_id, &self.bootstrap_id, cap))
                    .map_err(|_| Error::Invalid)?
            )
            .as_bytes(),
        ))
    }
    pub fn revocation_hash(&self, secret: &str) -> Result<String, Error> {
        if !hex32(secret) {
            return Err(Error::Forbidden);
        }
        Ok(digest(
            format!(
                "RunLater anonymous trial revocation v1\n{}",
                serde_json::to_string(&(1, &self.release_id, &self.bootstrap_id, secret))
                    .map_err(|_| Error::Invalid)?
            )
            .as_bytes(),
        ))
    }
    pub fn bytes(&self, e: &Envelope) -> Result<Vec<u8>, Error> {
        let mut b = b"RunLater anonymous trial request v1\n".to_vec();
        let descriptor_hash = digest(&serde_json::to_vec(self).map_err(|_| Error::Invalid)?);
        // Explicit Value array avoids tuple arity limitations without changing wire order.
        b.extend(
            serde_json::to_vec(&serde_json::json!([
                1,
                identity::ORIGIN,
                self.release_id,
                e.project_id,
                self.bootstrap_id,
                self.capability_hash,
                descriptor_hash,
                e.method,
                e.path,
                e.query,
                e.body_sha256,
                e.idempotency_key,
                e.issued_at_ms,
                e.expires_at_ms,
                e.nonce
            ]))
            .map_err(|_| Error::Invalid)?,
        );
        Ok(b)
    }
    pub fn verify(
        &self,
        e: &Envelope,
        cap: &str,
        signature: &str,
        trust: Trust<'_>,
        now: i64,
    ) -> Result<(), Error> {
        self.validate()?;
        if trust.release_id != self.release_id
            || e.project_id != self.project_id()?
            || !e.public_key.is_empty()
            || now < self.issued_at_ms
            || now >= self.expires_at_ms
            || e.expires_at_ms > self.expires_at_ms
            || !if e.path == REVOKE {
                bool::from(
                    self.revocation_hash
                        .as_bytes()
                        .ct_eq(self.revocation_hash(cap)?.as_bytes()),
                )
            } else {
                bool::from(
                    self.capability_hash
                        .as_bytes()
                        .ct_eq(self.capability_hash(cap)?.as_bytes()),
                )
            }
            || !identity::verify_ed25519(trust.gateway_public_key, &self.bytes(e)?, signature)
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub fn from_header(header: &str) -> Result<Self, Error> {
        crate::mcp_delegation::canonical_header(header)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub descriptor: Descriptor,
    pub ticket: crate::invitation::Ticket,
    pub revoked_at_ms: Option<i64>,
}
impl Grant {
    pub fn check(&self) -> Result<(), Error> {
        self.descriptor.validate()?;
        self.ticket.validate().map_err(|_| Error::Invalid)?;
        if self.ticket.id != self.descriptor.ticket_id()?
            || self.ticket.project_id != self.descriptor.project_id()?
            || self.ticket.terms != self.descriptor.terms()
            || self
                .revoked_at_ms
                .is_some_and(|t| t < self.descriptor.issued_at_ms || t > 9_007_199_254_740_991)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn active(&self, now: i64) -> Result<(), Error> {
        self.check()?;
        if self.ticket.revoked
            || self.revoked_at_ms.is_some()
            || now < self.descriptor.issued_at_ms
            || now >= self.descriptor.expires_at_ms
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
}
