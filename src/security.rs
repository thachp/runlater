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
