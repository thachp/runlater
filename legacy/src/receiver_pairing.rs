//! Immutable, explicitly authorized receiver pairing. Never a callback protocol or owner-key replacement.
use crate::{
    identity::{self, Error},
    security::digest,
};
use serde::{Deserialize, Serialize};
pub const PIN: &str = "/v1/mcp/trials/receiver";
pub const PULL: &str = "/v1/mcp/receiver/pull";
pub const ACK: &str = "/v1/mcp/receiver/ack";
pub const ENDPOINT: &str = "receiver";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u8,
    pub release_id: String,
    pub project_id: String,
    pub url: String,
    pub receiver_public_key: String,
    pub pairing_id: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub signature: String,
}
impl Manifest {
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        let mut v = b"RunLater receiver manifest v1\n".to_vec();
        v.extend(
            serde_json::to_vec(&(
                1,
                &self.release_id,
                &self.project_id,
                &self.url,
                &self.receiver_public_key,
                &self.pairing_id,
                self.issued_at_ms,
                self.expires_at_ms,
            ))
            .map_err(|_| Error::Invalid)?,
        );
        Ok(v)
    }
    pub fn hash(&self) -> Result<String, Error> {
        Ok(digest(
            &serde_json::to_vec(self).map_err(|_| Error::Invalid)?,
        ))
    }
    pub fn check(&self) -> Result<(), Error> {
        let policy = crate::destinations::EgressPolicy {
            managed_workers_dev: true,
            approved_hosts: Default::default(),
        };
        if self.version != 1
            || !crate::security::tenant_valid(&self.project_id)
            || !identity::key_valid(&self.receiver_public_key)
            || !crate::anonymous_trial::hex32(&self.pairing_id)
            || self.issued_at_ms < 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > 300000
            || self.expires_at_ms > 9_007_199_254_740_991
            || self.release_id.is_empty()
            || self.release_id.len() > 32
            || !self
                .release_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || policy.target(&self.url).is_err()
            || url::Url::parse(&self.url)
                .map_err(|_| Error::Invalid)?
                .path()
                != "/callback"
            || !identity::verify_ed25519(&self.receiver_public_key, &self.bytes()?, &self.signature)
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub fn authorize(&self, d: &crate::anonymous_trial::Descriptor, now: i64) -> Result<(), Error> {
        self.check()?;
        if self.project_id != d.project_id()?
            || self.release_id != d.release_id
            || self.expires_at_ms > d.expires_at_ms
            || self.issued_at_ms < d.issued_at_ms
            || self.issued_at_ms > now
            || now >= self.expires_at_ms
            || !d.allows(crate::auth::Permission::ReceiverSetup)
        {
            return Err(Error::Forbidden);
        }
        Ok(())
    }
    pub fn probe(&self, nonce: &str) -> Result<String, Error> {
        if !crate::anonymous_trial::hex32(nonce) {
            return Err(Error::Invalid);
        }
        Ok(format!(
            "RunLater receiver probe v1\n{}",
            serde_json::to_string(&(
                1,
                &self.release_id,
                &self.project_id,
                &self.url,
                &self.receiver_public_key,
                &self.pairing_id,
                self.hash()?,
                nonce,
                self.expires_at_ms
            ))
            .map_err(|_| Error::Invalid)?
        ))
    }
    pub fn status(&self, ready: bool) -> serde_json::Value {
        serde_json::json!({"state":if ready{"ready"}else{"awaiting_receiver"},"project_id":self.project_id,"receiver_ready":ready,"endpoint_id":if ready{Some(ENDPOINT)}else{None}})
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub project_id: String,
    pub public_key: String,
    pub pairing_id: String,
    pub method: String,
    pub path: String,
    pub body: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: String,
    pub signature: String,
}
impl Request {
    pub fn bytes(&self, m: &Manifest) -> Result<Vec<u8>, Error> {
        let mut v = b"RunLater receiver setup request v1\n".to_vec();
        v.extend(
            serde_json::to_vec(&serde_json::json!([
                1,
                identity::ORIGIN,
                m.release_id,
                self.project_id,
                self.pairing_id,
                m.hash()?,
                self.method,
                self.path,
                digest(self.body.as_bytes()),
                self.issued_at_ms,
                self.expires_at_ms,
                self.nonce
            ]))
            .map_err(|_| Error::Invalid)?,
        );
        Ok(v)
    }
    pub fn verify(&self, m: &Manifest, now: i64) -> Result<(), Error> {
        m.check()?;
        if self.project_id != m.project_id
            || self.public_key != m.receiver_public_key
            || self.pairing_id != m.pairing_id
            || self.method != "POST"
            || !matches!(self.path.as_str(), PULL | ACK)
            || !crate::anonymous_trial::hex32(&self.nonce)
            || self.issued_at_ms > now
            || self.issued_at_ms < m.issued_at_ms
            || self.expires_at_ms <= now
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > 60000
            || self.expires_at_ms > m.expires_at_ms
            || self.body.len() > 256
            || !identity::verify_ed25519(&self.public_key, &self.bytes(m)?, &self.signature)
        {
            return Err(Error::Forbidden);
        }
        if self.path == PULL {
            if self.body != "{}" {
                return Err(Error::Invalid);
            }
        } else {
            let a: Ack = serde_json::from_str(&self.body).map_err(|_| Error::Invalid)?;
            if !crate::anonymous_trial::hex32(&a.installation_sha256) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub installation_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub manifest: Manifest,
    pub probe_nonce: String,
    pub probe_attempts: u8,
    pub endpoint_proved: bool,
    pub proof_response: Option<String>,
    pub proof_id: Option<String>,
    pub installation_sha256: Option<String>,
    pub verify_attempts: u8,
    pub ready: bool,
    pub request_nonces: std::collections::BTreeSet<String>,
}
impl State {
    pub fn consume(&mut self, r: &Request) -> Result<(), Error> {
        if self.request_nonces.contains(&r.nonce) {
            return Err(Error::Conflict);
        }
        if self.request_nonces.len() >= 32 {
            return Err(Error::Limited);
        }
        self.request_nonces.insert(r.nonce.clone());
        Ok(())
    }
    pub fn check(&self) -> Result<(), Error> {
        self.manifest.check()?;
        if self.request_nonces.len() > 32
            || self
                .request_nonces
                .iter()
                .any(|n| !crate::anonymous_trial::hex32(n))
            || !crate::anonymous_trial::hex32(&self.probe_nonce)
            || self.probe_attempts > 3
            || self.verify_attempts > 3
            || self.proof_response.as_ref().is_some_and(|v| v.len() > 1024)
            || self
                .proof_id
                .as_ref()
                .is_some_and(|v| !crate::anonymous_trial::hex32(v))
            || self
                .installation_sha256
                .as_ref()
                .is_some_and(|v| !crate::anonymous_trial::hex32(v))
            || self.endpoint_proved != self.proof_id.is_some()
            || self
                .proof_response
                .as_ref()
                .is_some_and(|v| self.proof_id.as_ref() != Some(&digest(v.as_bytes())))
            || self.installation_sha256.is_some() && !self.endpoint_proved
            || self.ready
                && (!self.endpoint_proved
                    || self.installation_sha256.is_none()
                    || self.proof_response.is_some())
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Serialize)]
pub struct ProofPayload {
    pub id: String,
    pub response: String,
    pub expires_at_ms: i64,
}
#[derive(Serialize)]
pub struct Installation<'a> {
    pub version: u8,
    pub project_id: &'a str,
    pub pairing_id: &'a str,
    pub manifest_sha256: String,
    pub installation_id: String,
    pub expires_at_ms: i64,
    pub callback_url: &'a str,
    pub callback_policy: &'a crate::callback::Keyring,
    pub callback_keys: std::collections::BTreeMap<String, String>,
    pub destination_proof: ProofPayload,
    pub endpoint_id: &'a str,
    pub endpoint_version: u64,
}
