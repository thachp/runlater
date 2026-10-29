//! General POST/JSON scheduling domain. URL syntax is NOT an SSRF/connected-peer guarantee.
//! Runtime admission requires an explicitly approved private binding and matching reviewed
//! adapter revision. Native Node source or a feature flag alone cannot authorize delivery.
use crate::{
    core, identity, invitation::Enrollment, mcp_delegation::Proof, security::digest,
    signed::Envelope,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
pub const CREATE: &str = "/v1/http/tasks";
pub const FEATURE_FLAG: &str = "GENERAL_HTTPS_ENABLED";
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_BODY_BYTES: usize = 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub url: String,
    pub payload: Value,
    pub run_at_ms: i64,
    pub operation_key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    version: u8,
    url: String,
    method: String,
    content_type: String,
}
impl Target {
    pub fn from_url(raw: &str) -> Result<Self, identity::Error> {
        if raw.len() > 2048
            || !raw.starts_with("https://")
            || !raw.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || raw.contains('\\')
        {
            return Err(identity::Error::Invalid);
        }
        let lower = raw.to_ascii_lowercase();
        for i in 0..lower.len().saturating_sub(2) {
            if lower.as_bytes()[i] == b'%' {
                if let Ok(n) = u8::from_str_radix(&lower[i + 1..i + 3], 16) {
                    if n < 32 || n == 127 {
                        return Err(identity::Error::Invalid);
                    }
                }
            }
        }
        let u = url::Url::parse(raw).map_err(|_| identity::Error::Invalid)?;
        let Some(url::Host::Domain(host)) = u.host() else {
            return Err(identity::Error::Invalid);
        };
        if u.as_str() != raw
            || u.scheme() != "https"
            || !u.username().is_empty()
            || u.password().is_some()
            || u.port().is_some()
            || u.fragment().is_some()
            || host.len() > 253
            || !host.contains('.')
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            || [
                "localhost",
                "local",
                "internal",
                "home",
                "onion",
                "arpa",
                "invalid",
                "test",
            ]
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
        {
            return Err(identity::Error::Invalid);
        }
        Ok(Self {
            version: 1,
            url: raw.into(),
            method: "POST".into(),
            content_type: "application/json".into(),
        })
    }
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn hash(&self) -> Result<String, identity::Error> {
        Ok(digest(
            &serde_json::to_vec(self).map_err(|_| identity::Error::Invalid)?,
        ))
    }
    fn validate(&self) -> Result<(), identity::Error> {
        if Self::from_url(&self.url)? != *self {
            return Err(identity::Error::Invalid);
        }
        Ok(())
    }
}
impl Schedule {
    pub fn parse(body: &[u8]) -> Result<(Self, Target, String), identity::Error> {
        if body.len() > MAX_REQUEST_BYTES {
            return Err(identity::Error::Invalid);
        }
        let input: Self = serde_json::from_slice(body).map_err(|_| identity::Error::Invalid)?;
        let target = Target::from_url(&input.url)?;
        let payload =
            serde_json::to_string(&input.payload).map_err(|_| identity::Error::Invalid)?;
        if payload.len() > MAX_BODY_BYTES
            || input.run_at_ms < 0
            || input.operation_key.is_empty()
            || input.operation_key.len() > 128
            || !input
                .operation_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(identity::Error::Invalid);
        }
        Ok((input, target, payload))
    }
}
/// Deliberately not Deserialize/Clone/Default; only trusted runtime readiness mints this.
/// This proves a reviewed adapter binding exists, NOT that a DNS preflight made a URL safe.
/// Every actual attempt must independently resolve, validate and connect the selected public
/// address with original-host TLS validation, without redirects or hidden retries.
pub struct AdmissionPermit {
    adapter_revision: String,
}
impl AdmissionPermit {
    pub(crate) fn from_reviewed_revision(revision: &str) -> Result<Self, identity::Error> {
        if revision.len() != 64 || revision.bytes().all(|b| b == b'0') || !revision.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err(identity::Error::Invalid); }
        Ok(Self { adapter_revision: revision.into() })
    }
    pub(crate) fn revision(&self) -> &str { &self.adapter_revision }
    fn validate(&self) -> Result<(), identity::Error> {
        if self.adapter_revision.is_empty() {
            Err(identity::Error::Forbidden)
        } else {
            Ok(())
        }
    }
}
pub fn unavailable() -> Value {
    json!({"error":{"code":"general_https_unavailable"},"task_accepted":false})
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    targets: BTreeMap<String, Target>,
}
/// Exact private adapter input; no caller-supplied or RunLater authentication headers.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterRequest {
    pub url: String,
    pub body: String,
    pub content_type: &'static str,
    pub operation_key: String,
}
impl State {
    pub fn adapter_request(
        &self,
        project: &crate::signed::Project,
        id: &str,
    ) -> Result<AdapterRequest, identity::Error> {
        self.validate(project)?;
        let target = self.targets.get(id).ok_or(identity::Error::Forbidden)?;
        let task = project
            .ledger
            .get(id)
            .map_err(|_| identity::Error::Forbidden)?;
        Ok(AdapterRequest {
            url: target.url.clone(),
            body: task.input.body.clone(),
            content_type: "application/json",
            operation_key: task.input.operation_key.clone(),
        })
    }
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
    pub fn validate(&self, project: &crate::signed::Project) -> Result<(), identity::Error> {
        if self.targets.len() > 16 {
            return Err(identity::Error::Invalid);
        }
        for (id, target) in &self.targets {
            target.validate()?;
            let task = project
                .ledger
                .get(id)
                .map_err(|_| identity::Error::Invalid)?;
            if task.input.destination != format!("general_http:{}", target.hash()?)
                || task.input.body.len() > MAX_BODY_BYTES
                || serde_json::from_str::<Value>(&task.input.body).is_err()
            {
                return Err(identity::Error::Invalid);
            }
        }
        Ok(())
    }
    pub fn target(&self, id: &str) -> Option<&Target> {
        self.targets.get(id)
    }
}
impl Enrollment {
    /// Pure admission seam; intentionally unreachable from production until a reviewed binding
    /// can mint AdmissionPermit. Authenticating original bytes precedes all internal translation.
    pub fn schedule_http(
        &mut self,
        e: &Envelope,
        proof: Proof<'_>,
        body: &[u8],
        permit: Option<&AdmissionPermit>,
        now: i64,
    ) -> Result<Value, crate::funded_tasks::Error> {
        if e.method != "POST" || e.path != CREATE || !matches!(proof, Proof::Trial { .. }) {
            return Err(identity::Error::Forbidden.into());
        }
        let mut next = self.clone();
        let policy = next.identity_policy()?;
        next.project.catalog.apply_policy(&policy, now)?;
        e.authenticate_with_proof(&next.project.catalog, proof, body, now)?;
        let permit = permit.ok_or(crate::funded_tasks::Error::AdmissionUnavailable)?;
        permit.validate()?;
        let (input, target, payload) = Schedule::parse(body)?;
        if input.run_at_ms > next.beta_expiry().ok_or(identity::Error::Forbidden)? {
            return Err(identity::Error::Invalid.into());
        }
        next.project.requests.check_nonce(e, now)?;
        let (task, created) = next.project.ledger.create(
            &e.idempotency_key,
            core::Create {
                destination: format!("general_http:{}", target.hash()?),
                body: payload,
                run_at_ms: input.run_at_ms,
                operation_key: input.operation_key,
            },
            now,
        )?;
        if created {
            next.outbound.reserve_beta_task()?;
            let funding = next.admission_policy()?;
            next.project.funding.apply(&funding, now)?;
            next.project.funding.reserve(&e.project_id, &task.id, now)?;
            next.http.targets.insert(task.id.clone(), target);
        } else {
            if next.http.targets.get(&task.id) != Some(&target) {
                return Err(identity::Error::Conflict.into());
            }
            next.project.funding.project(&e.project_id)?;
            next.project.funding.reservation(&task.id)?;
            next.project.funding.advance(now)?;
        }
        next.project.funding.settle_all(&next.project.ledger, now)?;
        next.project.requests.record_nonce(e)?;
        next.http.validate(&next.project)?;
        let result =
            next.project
                .task_result(e, &task, created, !created, proof.permits_read(), now)?;
        *self = next;
        Ok(result)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn setup(
        scopes: Vec<&str>,
    ) -> (
        Enrollment,
        crate::anonymous_trial::Descriptor,
        String,
        SigningKey,
        String,
    ) {
        let key = SigningKey::from_bytes(&[42; 32]);
        let public = hex::encode(key.verifying_key().to_bytes());
        let capability = "ab".repeat(32);
        let mut d = crate::anonymous_trial::Descriptor {
            version: 1,
            release_id: "http_test".into(),
            bootstrap_id: "cd".repeat(32),
            capability_hash: "00".repeat(32),
            revocation_hash: "ef".repeat(32),
            issued_at_ms: 10,
            expires_at_ms: 10 + crate::public_beta::DURATION,
            permissions: scopes.into_iter().map(str::to_owned).collect(),
        };
        d.capability_hash = d.capability_hash(&capability).unwrap();
        let profile = crate::public_beta::Profile {
            release_id: d.release_id.clone(),
            opens_at_ms: 0,
            closes_at_ms: crate::public_beta::DURATION,
            callback_end_sec: 1400000,
            self_host: "runlater-public-api.operator.workers.dev".into(),
        };
        let mut global = crate::public_beta::State::new(&profile).unwrap();
        let mut e = envelope(&d, b"{}", 20);
        e.path = crate::anonymous_trial::PROVISION.into();
        let signature = hex::encode(key.sign(&d.bytes(&e).unwrap()).to_bytes());
        let value = global
            .trial_request(
                &e,
                &d,
                &capability,
                &signature,
                crate::mcp_delegation::Trust {
                    gateway_public_key: &public,
                    release_id: &d.release_id,
                },
                b"{}",
                20,
            )
            .unwrap();
        let grant = serde_json::from_value(value["grant"].clone()).unwrap();
        let mut p = Enrollment::new(crate::invitation::Mode::Invitation);
        p.install_trial(&grant, 20).unwrap();
        (p, d, capability, key, public)
    }
    fn envelope(d: &crate::anonymous_trial::Descriptor, body: &[u8], now: i64) -> Envelope {
        Envelope {
            version: 1,
            origin: identity::ORIGIN.into(),
            project_id: d.project_id().unwrap(),
            public_key: String::new(),
            method: "POST".into(),
            path: CREATE.into(),
            query: String::new(),
            body_sha256: digest(body),
            idempotency_key: "stable".into(),
            issued_at_ms: now,
            expires_at_ms: now + 60000,
            nonce: format!("{now:064x}"),
        }
    }
    fn invoke(
        p: &mut Enrollment,
        d: &crate::anonymous_trial::Descriptor,
        cap: &str,
        key: &SigningKey,
        public: &str,
        body: &[u8],
        permit: Option<&AdmissionPermit>,
        now: i64,
    ) -> Result<Value, crate::funded_tasks::Error> {
        let e = envelope(d, body, now);
        let signature = hex::encode(key.sign(&d.bytes(&e).unwrap()).to_bytes());
        p.schedule_http(
            &e,
            Proof::Trial {
                signature: &signature,
                descriptor: d,
                capability: cap,
                trust: crate::mcp_delegation::Trust {
                    gateway_public_key: public,
                    release_id: &d.release_id,
                },
            },
            body,
            permit,
            now,
        )
    }
    fn body(url: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"url":url,"payload":{"message":"synthetic"},"run_at_ms":1000,"operation_key":"once"})).unwrap()
    }
    #[test]
    fn no_adapter_means_no_task_nonce_credit_or_target_mutation() {
        let (mut p, d, cap, key, public) = setup(vec!["cancel", "http_schedule", "read"]);
        let before = serde_json::to_value(&p).unwrap();
        assert!(matches!(
            invoke(
                &mut p,
                &d,
                &cap,
                &key,
                &public,
                &body("https://customer.example.com/hook"),
                None,
                21
            ),
            Err(crate::funded_tasks::Error::AdmissionUnavailable)
        ));
        assert_eq!(before, serde_json::to_value(&p).unwrap());
    }
    #[test]
    fn new_scope_required_and_original_url_bytes_authenticated() {
        let (mut p, d, cap, key, public) = setup(vec!["cancel", "enqueue", "read"]);
        let permit = AdmissionPermit {
            adapter_revision: "offline_test_only".into(),
        };
        let before = serde_json::to_value(&p).unwrap();
        assert!(invoke(
            &mut p,
            &d,
            &cap,
            &key,
            &public,
            &body("https://customer.example.com/hook"),
            Some(&permit),
            21
        )
        .is_err());
        assert_eq!(before, serde_json::to_value(&p).unwrap());
        let (mut p, d, cap, key, public) = setup(vec!["http_schedule"]);
        let original = body("https://customer.example.com/one");
        let altered = body("https://customer.example.com/two");
        let e = envelope(&d, &original, 21);
        let signature = hex::encode(key.sign(&d.bytes(&e).unwrap()).to_bytes());
        let before = serde_json::to_value(&p).unwrap();
        assert!(p
            .schedule_http(
                &e,
                Proof::Trial {
                    signature: &signature,
                    descriptor: &d,
                    capability: &cap,
                    trust: crate::mcp_delegation::Trust {
                        gateway_public_key: &public,
                        release_id: &d.release_id
                    }
                },
                &altered,
                Some(&permit),
                21
            )
            .is_err());
        assert_eq!(before, serde_json::to_value(&p).unwrap());
    }
    #[test]
    fn offline_admission_freezes_target_and_reuses_existing_status_cancel_and_budget() {
        let (mut p, d, cap, key, public) = setup(vec!["cancel", "http_schedule", "read"]);
        let permit = AdmissionPermit {
            adapter_revision: "offline_test_only".into(),
        };
        let raw = body("https://customer.example.com/hook");
        let first = invoke(&mut p, &d, &cap, &key, &public, &raw, Some(&permit), 21).unwrap();
        assert_eq!(first["created"], true);
        assert_eq!(
            invoke(&mut p, &d, &cap, &key, &public, &raw, Some(&permit), 22).unwrap()["replayed"],
            true
        );
        assert!(invoke(
            &mut p,
            &d,
            &cap,
            &key,
            &public,
            &body("https://other.example.com/hook"),
            Some(&permit),
            23
        )
        .is_err());
        let id = first["result"]["id"].as_str().unwrap();
        assert_eq!(
            p.http.target(id).unwrap().url(),
            "https://customer.example.com/hook"
        );
        p.http.validate(&p.project).unwrap();
        let dispatch =
            serde_json::to_value(p.http.adapter_request(&p.project, id).unwrap()).unwrap();
        assert_eq!(
            dispatch,
            json!({"url":"https://customer.example.com/hook","body":"{\"message\":\"synthetic\"}","contentType":"application/json","operationKey":"once"})
        );
        assert!(dispatch.get("headers").is_none());
        assert!(dispatch.get("privateHeaders").is_none());
        p = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
        let mut e = envelope(&d, b"{}", 24);
        e.path = format!("/v1/tasks/{id}/cancel");
        e.idempotency_key.clear();
        let signature = hex::encode(key.sign(&d.bytes(&e).unwrap()).to_bytes());
        let result = p
            .signed_task_command_with_proof(
                &e,
                Proof::Trial {
                    signature: &signature,
                    descriptor: &d,
                    capability: &cap,
                    trust: crate::mcp_delegation::Trust {
                        gateway_public_key: &public,
                        release_id: &d.release_id,
                    },
                },
                b"{}",
                false,
                24,
            )
            .unwrap();
        assert_eq!(result["result"]["status"], "cancelled");
        let mut stored = serde_json::to_value(&p).unwrap();
        stored["outbound"]["beta_admissions"] = 16.into();
        p = serde_json::from_value(stored.clone()).unwrap();
        let mut e = envelope(&d, &raw, 25);
        e.idempotency_key = "different".into();
        let signature = hex::encode(key.sign(&d.bytes(&e).unwrap()).to_bytes());
        assert!(p
            .schedule_http(
                &e,
                Proof::Trial {
                    signature: &signature,
                    descriptor: &d,
                    capability: &cap,
                    trust: crate::mcp_delegation::Trust {
                        gateway_public_key: &public,
                        release_id: &d.release_id
                    }
                },
                &raw,
                Some(&permit),
                25
            )
            .is_err());
        assert_eq!(stored, serde_json::to_value(&p).unwrap());
    }
    #[test]
    fn private_attempt_deadline_comes_from_persisted_claim_never_retry_clock() {
        let (mut p, d, cap, key, public) = setup(vec!["http_schedule"]);
        let permit = AdmissionPermit { adapter_revision: "offline_test_only".into() };
        let created = invoke(&mut p, &d, &cap, &key, &public, &body("https://customer.example.com/hook?"), Some(&permit), 21).unwrap();
        let id = created["result"]["id"].as_str().unwrap().to_owned();
        assert!(p.http.attempt_envelope(&p.project, &d.release_id, &d.project_id().unwrap(), &id, &AdmissionPermit::from_reviewed_revision(&"c".repeat(64)).unwrap(), 1000).is_err());
        // A structurally persisted running claim; network factory remains unavailable.
        let task = p.project.ledger.tasks.get_mut(&id).unwrap();
        task.status = core::Status::Running;
        task.fence = 1;
        task.lease_until = Some(31000);
        task.attempts.push(core::Attempt { fence:1, started_ms:1000, finished_ms:None, outcome:None, staging_diagnostic:None });
        let make = |p: &Enrollment, now| p.http.attempt_envelope(&p.project, &d.release_id, &d.project_id().unwrap(), &id, &AdmissionPermit::from_reviewed_revision(&"c".repeat(64)).unwrap(), now);
        let first = make(&p, 1000).unwrap();
        assert_eq!(first.deadline_ms(), 30000);
        assert_eq!(first.hash().unwrap(), make(&p, 29999).unwrap().hash().unwrap());
        assert!(make(&p, 999).is_err());
        assert!(make(&p, 30000).is_err());
        p.project.ledger.tasks.get_mut(&id).unwrap().lease_until = Some(32000);
        assert!(make(&p, 1000).is_err());
        let task = p.project.ledger.tasks.get_mut(&id).unwrap();
        task.lease_until = Some(31000);
        task.cancel_requested = true;
        assert!(make(&p, 1000).is_err());
    }
    #[test]
    fn no_unreviewed_revision_permit_or_implicit_network() {
        assert!(AdmissionPermit::from_reviewed_revision("").is_err());
        assert!(AdmissionPermit::from_reviewed_revision(&"0".repeat(64)).is_err());
        assert!(AdmissionPermit::from_reviewed_revision(&"A".repeat(64)).is_err());
        assert_eq!(unavailable()["task_accepted"], false);
    }
    #[test]
    fn profile_is_post_json_not_receiver_or_custom_auth() {
        let value = json!({"url":"https://customer.example.com/webhook?mode=one","payload":{"hello":"world"},"run_at_ms":0,"operation_key":"stable"});
        let (_, t, p) = Schedule::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(t.method, "POST");
        assert_eq!(t.content_type, "application/json");
        assert_eq!(p, "{\"hello\":\"world\"}");
        for field in ["headers", "auth", "credential_ref", "method"] {
            let mut v = value.clone();
            v[field] = json!("unsupported");
            assert!(Schedule::parse(&serde_json::to_vec(&v).unwrap()).is_err());
        }
    }
    #[test]
    fn url_syntax_gate_is_conservative_but_not_network_authorization() {
        for url in [
            "http://example.com/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://user:pass@example.com/",
            "https://example.com:8443/",
            "https://example.com/#fragment",
            "https://internal/",
            "https://x.local/",
            "https://example.com/%0aheader",
            "https://EXAMPLE.com/",
            "https://example.com",
        ] {
            assert!(Target::from_url(url).is_err(), "{url}");
        }
        assert!(Target::from_url("https://public.example.com/path?q=1").is_ok());
    }
}

#[cfg(test)]
#[path = "general_http_lane_tests.rs"]
mod lane_tests;
