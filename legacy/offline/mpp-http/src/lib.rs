//! Offline draft-profile codec. No HTTP client, secrets, payment verification, or runtime routes.
//! Parsed credentials/receipts are untrusted; an unexecuted plan never entitles service.
pub mod journal;
mod json;
pub mod stripe;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, SecondsFormat, Utc};
use runlater_offline_credit_purchases::{Intent, SAFE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};
pub use stripe::UnexecutedStripeRequest;

pub const AUTH_DRAFT: &str = "draft-httpauth-payment-01";
pub const STRIPE_DRAFT: &str = "draft-stripe-charge-00";
pub const MAX_HEADER: usize = 8192;
pub const MAX_BODY: usize = 2048;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Unsupported,
    Bounds,
    Binding,
    Expired,
    WrongHeader,
    DuplicateHeader,
    Disabled,
}
fn safe_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (32..=126).contains(&b))
}
fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn decode(s: &str) -> Result<Vec<u8>, Error> {
    if s.is_empty()
        || s.len() > MAX_HEADER
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(Error::Malformed);
    }
    let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::Malformed)?;
    if encode(&bytes) != s {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}
fn decoded_json<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, Error> {
    json::parse(&decode(s)?)
}
fn canonical_b64<T: Serialize>(v: &T) -> Result<String, Error> {
    Ok(encode(&json::canonical(
        &serde_json::to_value(v).map_err(|_| Error::Malformed)?,
    )?))
}
fn canonical_document(s: &str) -> Result<Value, Error> {
    let bytes = decode(s)?;
    let value: Value = json::parse(&bytes)?;
    if !value.is_object() || json::canonical(&value)? != bytes {
        return Err(Error::Malformed);
    }
    Ok(value)
}
fn timestamp(s: &str) -> Result<i64, Error> {
    let t = DateTime::parse_from_rfc3339(s)
        .map_err(|_| Error::Malformed)?
        .timestamp_millis();
    if t <= 0 || t as u64 > SAFE {
        return Err(Error::Bounds);
    }
    Ok(t)
}
fn format_time(ms: i64) -> Result<String, Error> {
    if ms <= 0 || ms as u64 > SAFE {
        return Err(Error::Bounds);
    }
    Ok(DateTime::<Utc>::from_timestamp_millis(ms)
        .ok_or(Error::Bounds)?
        .to_rfc3339_opts(SecondsFormat::Millis, true))
}
fn scheme(value: &str) -> Result<&str, Error> {
    if value.len() > MAX_HEADER || value.bytes().any(|b| b < 32 && b != b'\t' || b > 126) {
        return Err(Error::Bounds);
    }
    let (name, rest) = value.split_once(' ').ok_or(Error::Malformed)?;
    if !name.eq_ignore_ascii_case("Payment") {
        return Err(Error::Unsupported);
    }
    let rest = rest.trim_start_matches(' ');
    if rest.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(rest)
}

/// One field containing one challenge. HTTP field/challenge-list negotiation is out of scope.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Challenge {
    pub id: String,
    pub realm: String,
    pub method: String,
    pub intent: String,
    pub request: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opaque: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, String>,
}
impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Challenge(<redacted>)")
    }
}
impl Challenge {
    pub fn parse(value: &str) -> Result<Self, Error> {
        let s = scheme(value)?.as_bytes();
        let mut n = 0;
        let mut fields = BTreeMap::<String, String>::new();
        fn ows(s: &[u8], n: &mut usize) {
            while s.get(*n).is_some_and(|b| b" \t".contains(b)) {
                *n += 1;
            }
        }
        loop {
            ows(s, &mut n);
            let start = n;
            while s.get(n).is_some_and(|b| token(*b)) {
                n += 1;
            }
            if n == start {
                return Err(Error::Malformed);
            }
            let key = std::str::from_utf8(&s[start..n])
                .unwrap()
                .to_ascii_lowercase();
            ows(s, &mut n);
            if s.get(n) != Some(&b'=') {
                return Err(Error::Malformed);
            }
            n += 1;
            ows(s, &mut n);
            let value = if s.get(n) == Some(&b'"') {
                n += 1;
                let mut out = String::new();
                loop {
                    match s.get(n) {
                        Some(b'"') => {
                            n += 1;
                            break;
                        }
                        Some(b'\\') => {
                            n += 1;
                            let b = *s.get(n).ok_or(Error::Malformed)?;
                            if b < 32 || b > 126 {
                                return Err(Error::Malformed);
                            }
                            out.push(b as char);
                            n += 1;
                        }
                        Some(b) if *b >= 32 && *b <= 126 => {
                            out.push(*b as char);
                            n += 1;
                        }
                        _ => return Err(Error::Malformed),
                    }
                }
                out
            } else {
                let start = n;
                while s.get(n).is_some_and(|b| token(*b)) {
                    n += 1;
                }
                if n == start {
                    return Err(Error::Malformed);
                }
                std::str::from_utf8(&s[start..n]).unwrap().into()
            };
            if fields.len() >= 24 || fields.insert(key, value).is_some() {
                return Err(Error::Malformed);
            }
            ows(s, &mut n);
            if n == s.len() {
                break;
            }
            if s[n] != b',' {
                return Err(Error::Malformed);
            }
            n += 1;
        }
        let value = serde_json::to_value(fields).map_err(|_| Error::Malformed)?;
        let result: Self = serde_json::from_value(value).map_err(|_| Error::Malformed)?;
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<(), Error> {
        let optional_count = [
            &self.expires,
            &self.digest,
            &self.opaque,
            &self.header,
            &self.description,
        ]
        .into_iter()
        .filter(|v| v.is_some())
        .count();
        if self.extensions.len() + 5 + optional_count > 24 {
            return Err(Error::Bounds);
        }
        if !safe_text(&self.id, 256)
            || !safe_text(&self.realm, 256)
            || self.method.is_empty()
            || self.method.len() > 64
            || !self.method.bytes().all(|b| b.is_ascii_lowercase())
            || self.intent != "charge"
        {
            return Err(Error::Unsupported);
        }
        if self
            .header
            .as_deref()
            .is_some_and(|h| h != "Payment-Authorization")
        {
            return Err(Error::WrongHeader);
        }
        canonical_document(&self.request)?;
        if let Some(s) = &self.opaque {
            let v = canonical_document(s)?;
            if !v.as_object().unwrap().values().all(Value::is_string) {
                return Err(Error::Malformed);
            }
        }
        if let Some(s) = &self.expires {
            timestamp(s)?;
        }
        if let Some(s) = &self.digest {
            let raw = s
                .strip_prefix("sha-256=:")
                .and_then(|v| v.strip_suffix(':'))
                .ok_or(Error::Unsupported)?;
            let bytes = STANDARD.decode(raw).map_err(|_| Error::Malformed)?;
            if bytes.len() != 32 || STANDARD.encode(bytes) != raw {
                return Err(Error::Malformed);
            }
        }
        if self
            .description
            .as_ref()
            .is_some_and(|s| !safe_text(s, 512))
            || self.extensions.iter().any(|(k, v)| {
                k.is_empty()
                    || *k != k.to_ascii_lowercase()
                    || !k.bytes().all(token)
                    || !safe_text(v, 512)
                    || [
                        "id",
                        "realm",
                        "method",
                        "intent",
                        "request",
                        "expires",
                        "digest",
                        "opaque",
                        "header",
                        "description",
                    ]
                    .contains(&k.to_ascii_lowercase().as_str())
            })
        {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    pub fn to_header(&self) -> Result<String, Error> {
        self.validate()?;
        let fields = serde_json::to_value(self).map_err(|_| Error::Malformed)?;
        let mut parts = vec![];
        for (k, v) in fields.as_object().ok_or(Error::Malformed)? {
            if !k.bytes().all(token) {
                return Err(Error::Malformed);
            }
            let s = v.as_str().ok_or(Error::Malformed)?;
            if !s.bytes().all(|b| (32..=126).contains(&b)) {
                return Err(Error::Malformed);
            }
            parts.push(format!(
                "{k}=\"{}\"",
                s.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
        let out = format!("Payment {}", parts.join(", "));
        if out.len() > MAX_HEADER {
            return Err(Error::Bounds);
        }
        Ok(out)
    }
    pub fn credential_field(&self) -> &str {
        self.header.as_deref().unwrap_or("Authorization")
    }
    /// Draft §5.1.2.1.1 input only. No secret, HMAC generation or authentication.
    pub fn hmac_binding_input(&self) -> Result<String, Error> {
        self.validate()?;
        let mut parts = vec![
            self.realm.as_str(),
            &self.method,
            &self.intent,
            &self.request,
            self.expires.as_deref().unwrap_or(""),
            self.digest.as_deref().unwrap_or(""),
        ];
        if let Some(h) = &self.header {
            parts.push(h);
        }
        parts.push(self.opaque.as_deref().unwrap_or(""));
        if parts.iter().any(|s| s.contains('|')) {
            return Err(Error::Unsupported);
        }
        Ok(parts.join("|"))
    }
    fn bound_eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.realm == other.realm
            && self.method == other.method
            && self.intent == other.intent
            && self.request == other.request
            && self.expires == other.expires
            && self.digest == other.digest
            && self.opaque == other.opaque
            && self.header == other.header
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StripePayload {
    spt: String,
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    external_id: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    challenge: Challenge,
    payload: StripePayload,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OfflineMerchantContext {
    pub realm: String,
    pub network_id: String,
    pub payment_method_types: Vec<String>,
}
#[derive(Clone, Copy)]
pub enum CredentialField {
    Authorization,
    PaymentAuthorization,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MethodDetails {
    #[serde(rename = "networkId")]
    network_id: String,
    #[serde(rename = "paymentMethodTypes")]
    payment_method_types: Vec<String>,
    metadata: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StripeChargeRequest {
    amount: String,
    currency: String,
    #[serde(rename = "externalId")]
    external_id: String,
    #[serde(rename = "methodDetails")]
    method_details: MethodDetails,
}
/// Trusted offline issuance snapshot, to be stored and looked up by the future host.
/// Not serializable/deserializable request authority. `journal` adds a bounded
/// trusted-storage fixture contract, not a production challenge database.
pub struct IssuedChallenge {
    challenge: Challenge,
    intent: Intent,
    context: OfflineMerchantContext,
}
impl IssuedChallenge {
    pub fn offline(
        intent: &Intent,
        context: OfflineMerchantContext,
        id: &str,
        body: &[u8],
        field: CredentialField,
    ) -> Result<Self, Error> {
        if body.len() > MAX_BODY
            || !id.starts_with("offline_")
            || !safe_text(id, 128)
            || !safe_text(&context.realm, 256)
            || !context.network_id.starts_with("profile_")
            || !safe_text(&context.network_id, 128)
            || context.payment_method_types.is_empty()
            || context.payment_method_types.len() > 2
            || context
                .payment_method_types
                .iter()
                .any(|s| s != "card" && s != "link")
            || context
                .payment_method_types
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != context.payment_method_types.len()
            || intent.amount_minor == 0
            || intent.amount_minor > SAFE
            || intent.currency.len() != 3
            || !intent.currency.bytes().all(|b| b.is_ascii_lowercase())
            || !safe_text(&intent.project_id, 64)
            || !safe_text(&intent.id, 128)
            || intent.issued_at_ms <= 0
            || intent.expires_at_ms <= intent.issued_at_ms
        {
            return Err(Error::Bounds);
        }
        let correlation = BTreeMap::from([
            ("project_id".into(), intent.project_id.clone()),
            ("purchase_id".into(), intent.id.clone()),
            ("quote_digest".into(), intent.digest()),
        ]);
        let request = StripeChargeRequest {
            amount: intent.amount_minor.to_string(),
            currency: intent.currency.clone(),
            external_id: intent.id.clone(),
            method_details: MethodDetails {
                network_id: context.network_id.clone(),
                payment_method_types: context.payment_method_types.clone(),
                metadata: correlation.clone(),
            },
        };
        let challenge = Challenge {
            id: id.into(),
            realm: context.realm.clone(),
            method: "stripe".into(),
            intent: "charge".into(),
            request: canonical_b64(&request)?,
            expires: Some(format_time(intent.expires_at_ms)?),
            digest: Some(body_digest(body)?),
            opaque: Some(canonical_b64(&correlation)?),
            header: match field {
                CredentialField::Authorization => None,
                CredentialField::PaymentAuthorization => Some("Payment-Authorization".into()),
            },
            description: None,
            extensions: BTreeMap::new(),
        };
        challenge.validate()?;
        Ok(Self {
            challenge,
            intent: intent.clone(),
            context,
        })
    }
    pub fn challenge(&self) -> &Challenge {
        &self.challenge
    }
    /// Convenience composition of protocol binding and the separately pinned REST encoder.
    pub fn prepare(
        &self,
        current_intent: &Intent,
        project: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        now: i64,
    ) -> Result<UnexecutedStripeRequest, Error> {
        stripe::encode(&self.decode_credential(current_intent, project, headers, body, now)?)
    }
    /// Stateful quote checks only: neither credential authorization nor settled payment.
    /// Provider API versions and REST field names are deliberately absent here.
    pub fn decode_credential(
        &self,
        current_intent: &Intent,
        project: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        now: i64,
    ) -> Result<BoundStripeCredential, Error> {
        if project != self.intent.project_id || current_intent != &self.intent {
            return Err(Error::Binding);
        }
        if now < self.intent.issued_at_ms
            || now >= timestamp(self.challenge.expires.as_deref().ok_or(Error::Binding)?)?
        {
            return Err(Error::Expired);
        }
        if body.len() > MAX_BODY || Some(body_digest(body)?) != self.challenge.digest {
            return Err(Error::Binding);
        }
        if headers.len() > 32 {
            return Err(Error::Bounds);
        }
        let mut selected = None;
        for (name, value) in headers {
            if name.is_empty()
                || !name.bytes().all(token)
                || value.len() > MAX_HEADER
                || value.bytes().any(|b| b < 32 && b != b'\t' || b > 126)
            {
                return Err(Error::Bounds);
            }
            if name.eq_ignore_ascii_case(self.challenge.credential_field()) {
                if selected.replace(*value).is_some() {
                    return Err(Error::DuplicateHeader);
                }
            } else if (name.eq_ignore_ascii_case("Authorization")
                || name.eq_ignore_ascii_case("Payment-Authorization"))
                && scheme(value).is_ok()
            {
                return Err(Error::WrongHeader);
            }
        }
        let wire = selected.ok_or(Error::WrongHeader)?;
        // Parse echoed challenge before interpreting any credential payload material.
        let raw: Value = decoded_json(scheme(wire)?)?;
        let echo: Challenge =
            serde_json::from_value(raw.get("challenge").cloned().ok_or(Error::Malformed)?)
                .map_err(|_| Error::Malformed)?;
        echo.validate()?;
        if !self.challenge.bound_eq(&echo) {
            return Err(Error::Binding);
        }
        let credential: Credential = serde_json::from_value(raw).map_err(|_| Error::Malformed)?;
        if !credential.payload.spt.starts_with("spt_")
            || !safe_text(&credential.payload.spt, 512)
            || credential.payload.spt.len() <= 4
            || credential
                .payload
                .external_id
                .as_ref()
                .is_some_and(|s| !safe_text(s, 128))
            || credential
                .source
                .as_ref()
                .is_some_and(|s| !safe_text(s, 512))
        {
            return Err(Error::Malformed);
        }
        let request: StripeChargeRequest = decoded_json(&self.challenge.request)?;
        if request.method_details.network_id != self.context.network_id {
            return Err(Error::Binding);
        }
        let idempotency_key = format!(
            "runlater-offline-mpp-{}",
            hash(
                &serde_json::to_vec(&(
                    AUTH_DRAFT,
                    STRIPE_DRAFT,
                    self.intent.digest(),
                    &self.challenge.id,
                    &credential.payload.spt
                ))
                .map_err(|_| Error::Malformed)?
            )
        );
        let mut metadata = request.method_details.metadata;
        metadata.insert("challenge_id".into(), self.challenge.id.clone());
        Ok(BoundStripeCredential {
            amount_minor: self.intent.amount_minor,
            currency: self.intent.currency.clone(),
            spt: credential.payload.spt,
            metadata,
            idempotency_key,
        })
    }
}
pub fn body_digest(body: &[u8]) -> Result<String, Error> {
    if body.len() > MAX_BODY {
        return Err(Error::Bounds);
    }
    Ok(format!(
        "sha-256=:{}:",
        STANDARD.encode(Sha256::digest(body))
    ))
}
/// Protocol-bound but still unverified credential. Private fields prevent construction
/// from a caller-supplied success document. No provider API contract or entitlement.
/// ```compile_fail
/// use runlater_offline_mpp_http::BoundStripeCredential;
/// use runlater_offline_credit_purchases::VerifiedEvent;
/// fn fabricate(credential: BoundStripeCredential) -> VerifiedEvent { credential.into() }
/// ```
pub struct BoundStripeCredential {
    amount_minor: u64,
    currency: String,
    spt: String,
    metadata: BTreeMap<String, String>,
    idempotency_key: String,
}
impl fmt::Debug for BoundStripeCredential {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("BoundStripeCredential(<redacted>, unverified)")
    }
}

/// Syntax only. Even `success` and a 2xx response do not establish trusted provenance.
/// ```compile_fail
/// use runlater_offline_mpp_http::UntrustedReceipt;
/// use runlater_offline_credit_purchases::VerifiedEvent;
/// fn fabricate(receipt: UntrustedReceipt) -> VerifiedEvent { receipt.into() }
/// ```
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UntrustedReceipt {
    pub method: String,
    pub reference: String,
    pub status: String,
    pub timestamp: String,
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
}
impl UntrustedReceipt {
    pub fn parse(http_status: u16, value: &str) -> Result<Self, Error> {
        if !(200..300).contains(&http_status) {
            return Err(Error::Malformed);
        }
        let receipt: Self = decoded_json(value)?;
        receipt.validate()?;
        Ok(receipt)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.method != "stripe"
            || self.status != "success"
            || !self.reference.starts_with("pi_")
            || self.reference.len() <= 3
            || !safe_text(&self.reference, 256)
            || self
                .external_id
                .as_ref()
                .is_some_and(|s| !safe_text(s, 128))
        {
            return Err(Error::Malformed);
        }
        timestamp(&self.timestamp)?;
        Ok(())
    }
    pub fn to_fixture_header(&self) -> Result<String, Error> {
        self.validate()?;
        canonical_b64(self)
    }
}
impl fmt::Debug for UntrustedReceipt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("UntrustedReceipt(<redacted>)")
    }
}
