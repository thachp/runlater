//! Unexecuted Stripe REST descriptor, separate from the MPP wire profile.
//! Pins the documented SPT PaymentIntent preview example retrieved 2026-10-28.
//! No transport, account authority, response verification or activation is provided.
use crate::{BoundStripeCredential, Error};
use serde_json::{json, Value};
use std::fmt;

pub const API_VERSION: &str = "2026-09-30.preview";
pub const CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
pub const MAX_AMOUNT_MINOR: u64 = 99_999_999;

/// Encode the bound credential under this provider contract. Currency eligibility,
/// minimum amounts, token scope and account preview access remain unverified.
pub fn encode(credential: &BoundStripeCredential) -> Result<UnexecutedStripeRequest, Error> {
    if credential.amount_minor == 0 || credential.amount_minor > MAX_AMOUNT_MINOR {
        return Err(Error::Bounds);
    }
    let mut fields = vec![
        ("amount".into(), credential.amount_minor.to_string()),
        ("currency".into(), credential.currency.clone()),
        (
            "payment_method_data[shared_payment_granted_token]".into(),
            credential.spt.clone(),
        ),
        ("confirm".into(), "true".into()),
        ("automatic_payment_methods[enabled]".into(), "true".into()),
        (
            "automatic_payment_methods[allow_redirects]".into(),
            "never".into(),
        ),
    ];
    for (key, value) in &credential.metadata {
        fields.push((format!("metadata[{key}]"), value.clone()));
    }
    let form = fields
        .iter()
        .map(|(key, value)| format!("{}={}", component(key), component(value)))
        .collect::<Vec<_>>()
        .join("&");
    let body = json!({"amount":credential.amount_minor,"currency":credential.currency,
        "payment_method_data":{"shared_payment_granted_token":credential.spt},"confirm":true,
        "automatic_payment_methods":{"enabled":true,"allow_redirects":"never"},
        "metadata":credential.metadata});
    Ok(UnexecutedStripeRequest {
        body,
        form,
        idempotency_key: credential.idempotency_key.clone(),
    })
}

// application/x-www-form-urlencoded byte escaping; order is deterministic, not signed.
fn component(value: &str) -> String {
    let mut out = String::new();
    const HEX: &[u8] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'*' | b'-' | b'.' | b'_' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 15) as usize] as char);
            }
        }
    }
    out
}

/// Descriptive REST request only, deliberately lacking execution or entitlement capability.
/// ```compile_fail
/// use runlater_offline_mpp_http::UnexecutedStripeRequest;
/// use runlater_offline_credit_purchases::VerifiedEvent;
/// fn fabricate(plan: UnexecutedStripeRequest) -> VerifiedEvent { plan.into() }
/// ```
pub struct UnexecutedStripeRequest {
    body: Value,
    form: String,
    idempotency_key: String,
}
impl UnexecutedStripeRequest {
    pub fn operation(&self) -> &'static str {
        "POST /v1/payment_intents"
    }
    pub fn url(&self) -> &'static str {
        "https://api.stripe.com/v1/payment_intents"
    }
    pub fn api_version(&self) -> &'static str {
        API_VERSION
    }
    pub fn content_type(&self) -> &'static str {
        CONTENT_TYPE
    }
    /// No Authorization or account-routing header is supplied by an offline descriptor.
    pub fn headers_for_inspection(&self) -> [(&str, &str); 3] {
        [
            ("Stripe-Version", API_VERSION),
            ("Content-Type", CONTENT_TYPE),
            ("Idempotency-Key", &self.idempotency_key),
        ]
    }
    /// Semantic view, not the HTTP body. Contains untrusted credential material.
    pub fn body_for_inspection(&self) -> &Value {
        &self.body
    }
    /// Encoded HTTP body. Sensitive; never log it or mistake it for payment proof.
    pub fn form_body_for_inspection(&self) -> &str {
        &self.form
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub fn activation_enabled(&self) -> bool {
        false
    }
}
impl fmt::Debug for UnexecutedStripeRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("UnexecutedStripeRequest(<redacted>, activation=false)")
    }
}
