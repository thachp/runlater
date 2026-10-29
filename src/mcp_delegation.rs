//! Explicit task-only delegation. Owner keys remain local; no credential issuance or implicit trust.
use crate::{
    auth::Permission,
    identity::{self, Catalog, Error},
    signed::Envelope,
};
use serde::{Deserialize, Serialize};
pub const RESOURCE: &str = "https://mcp.runlater.io";
pub const MAX_TTL_MS: i64 = 3_600_000;
pub const VALIDATE_PATH: &str = "/v1/mcp/delegations/validate";
pub const REVOKE_PATH: &str = "/v1/mcp/delegations/revoke";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub version: u8,
    pub audience: String,
    pub resource: String,
    pub release_id: String,
    pub project_id: String,
    pub owner_public_key: String,
    pub gateway_public_key: String,
    pub delegation_id: String,
    pub permissions: Vec<String>,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub signature: String,
}
#[derive(Clone, Copy)]
pub struct Trust<'a> {
    pub gateway_public_key: &'a str,
    pub release_id: &'a str,
}
#[derive(Clone, Copy)]
pub enum Proof<'a> {
    Owner(&'a str),
    Delegated {
        signature: &'a str,
        certificate: &'a Certificate,
        trust: Trust<'a>,
    },
}
pub fn task_permission(e: &Envelope) -> Result<Permission, Error> {
    use crate::funded_tasks::{route, Route};
    match route(&e.method, &e.path) {
        Some(Route::Create) => Ok(Permission::Enqueue),
        Some(Route::Read(_)) => Ok(Permission::Read),
        Some(Route::Cancel(_)) => Ok(Permission::Cancel),
        _ => Err(Error::Forbidden),
    }
}
impl Certificate {
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut v = b"RunLater MCP task delegation v1\n".to_vec();
        v.extend(
            serde_json::to_vec(&(
                self.version,
                &self.audience,
                &self.resource,
                &self.release_id,
                &self.project_id,
                &self.owner_public_key,
                &self.gateway_public_key,
                &self.delegation_id,
                &self.permissions,
                self.issued_at_ms,
                self.expires_at_ms,
            ))
            .map_err(|_| Error::Invalid)?,
        );
        Ok(v)
    }
    pub fn allows(&self, permission: Permission) -> bool {
        let scope = match permission {
            Permission::Enqueue => "enqueue",
            Permission::Read => "read",
            Permission::Cancel => "cancel",
            _ => return false,
        };
        self.permissions.iter().any(|s| s == scope)
    }
    pub fn verify(
        &self,
        e: &Envelope,
        signature: &str,
        trust: Trust<'_>,
        identity_expiry: i64,
        revoked_before_ms: Option<i64>,
        now: i64,
    ) -> Result<(), Error> {
        if self.version != 1
            || self.audience != identity::ORIGIN
            || self.resource != RESOURCE
            || self.release_id != trust.release_id
            || self.gateway_public_key != trust.gateway_public_key
            || !identity::key_valid(trust.gateway_public_key)
            || self.gateway_public_key == self.owner_public_key
            || self.project_id != e.project_id
            || self.owner_public_key != e.public_key
            || self.delegation_id.len() != 64
            || !self
                .delegation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.permissions.is_empty()
            || self.permissions.len() > 3
            || self
                .permissions
                .iter()
                .any(|p| !matches!(p.as_str(), "cancel" | "enqueue" | "read"))
            || self.permissions.windows(2).any(|p| p[0] >= p[1])
            || (!(e.method == "POST" && e.path == VALIDATE_PATH)
                && !self.allows(task_permission(e)?))
        {
            return Err(Error::Forbidden);
        }
        if self.issued_at_ms < 0
            || self.issued_at_ms > now
            || self.expires_at_ms <= now
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_TTL_MS
            || self.expires_at_ms > identity_expiry
            || self.expires_at_ms > 9_007_199_254_740_991
            || revoked_before_ms.is_some_and(|at| self.issued_at_ms <= at)
            || e.issued_at_ms < self.issued_at_ms
            || e.expires_at_ms > self.expires_at_ms
        {
            return Err(Error::Expired);
        }
        if !identity::verify_ed25519(&self.owner_public_key, &self.bytes()?, &self.signature)
            || !identity::verify_ed25519(&self.gateway_public_key, &e.bytes()?, signature)
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    /// Unpadded base64url, bounded and canonical JSON: no alternate encodings/unknown fields.
    pub fn from_header(header: &str) -> Result<Self, Error> {
        if header.is_empty() || header.len() > 4096 || header.len() % 4 == 1 {
            return Err(Error::Invalid);
        }
        let mut bytes = Vec::new();
        let mut accumulator = 0u32;
        let mut bits = 0u32;
        for c in header.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => return Err(Error::Invalid),
            };
            accumulator = (accumulator << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                bytes.push((accumulator >> bits) as u8);
                accumulator &= (1 << bits) - 1;
            }
        }
        if accumulator != 0 || bytes.len() > 3072 {
            return Err(Error::Invalid);
        }
        let certificate: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if serde_json::to_vec(&certificate).map_err(|_| Error::Invalid)? != bytes {
            return Err(Error::Invalid);
        }
        Ok(certificate)
    }
}
impl Proof<'_> {
    pub(crate) fn verify(&self, e: &Envelope, catalog: &Catalog, now: i64) -> Result<(), Error> {
        match self {
            Self::Owner(signature) => {
                if identity::verify_ed25519(&e.public_key, &e.bytes()?, signature) {
                    Ok(())
                } else {
                    Err(Error::Forbidden)
                }
            }
            Self::Delegated {
                signature,
                certificate,
                trust,
            } => {
                let expiry = catalog.authorized_expiry(
                    &e.project_id,
                    &e.public_key,
                    task_permission(e)?,
                    now,
                )?;
                certificate.verify(e, signature, *trust, expiry, None, now)
            }
        }
    }
    pub(crate) fn permits_read(&self) -> bool {
        match self {
            Self::Owner(_) => true,
            Self::Delegated { certificate, .. } => certificate.allows(Permission::Read),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Revocations {
    pub floor_ms: i64,
    pub receipts: std::collections::BTreeMap<String, i64>,
}
impl Revocations {
    pub fn validate(&self) -> Result<(), Error> {
        if self.floor_ms < 0
            || self.floor_ms > 9_007_199_254_740_991
            || self.receipts.len() > 128
            || self
                .receipts
                .values()
                .any(|at| *at < 0 || *at > self.floor_ms)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
