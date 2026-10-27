use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
/// This slice deliberately has NO network delivery path. Only in-process fixtures are accepted.
/// URL filtering alone cannot prove DNS-rebinding resistance in Workers.
pub fn destination_allowed(value: &str) -> bool {
    matches!(
        value,
        "fixture://success" | "fixture://retry" | "fixture://fail"
    )
}
pub fn sign(secret: &[u8], timestamp: i64, id: &str, operation: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(format!("{timestamp}.{id}.{operation}.").as_bytes());
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}
pub fn verify(
    secret: &[u8],
    timestamp: i64,
    id: &str,
    operation: &str,
    body: &[u8],
    signature: &str,
    now: i64,
) -> bool {
    if timestamp.abs_diff(now) > 300 {
        return false;
    }
    let Ok(bytes) = hex::decode(signature) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(format!("{timestamp}.{id}.{operation}.").as_bytes());
    mac.update(body);
    mac.verify_slice(&bytes).is_ok()
}

pub fn tenant_valid(tenant: &str) -> bool {
    !tenant.is_empty()
        && tenant.len() <= 64
        && tenant
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
pub fn task_id_valid(id: &str) -> bool {
    id.len() == 21
        && id.starts_with("task_")
        && id[5..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthFault {
    Unauthorized,
    InvalidConfiguration,
}
pub fn authenticate(config: &str, token: &str) -> Result<String, AuthFault> {
    let keys: std::collections::BTreeMap<String, String> =
        serde_json::from_str(config).map_err(|_| AuthFault::InvalidConfiguration)?;
    if keys.is_empty()
        || keys.iter().any(|(hash, tenant)| {
            hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || !tenant_valid(tenant)
        })
    {
        return Err(AuthFault::InvalidConfiguration);
    }
    if token.is_empty() || token.len() > 256 {
        return Err(AuthFault::Unauthorized);
    }
    keys.get(&digest(token.as_bytes()))
        .cloned()
        .ok_or(AuthFault::Unauthorized)
}
