//! Offline canonical-byte oracle for the JS client tests. Input is public Challenge metadata only.
use runlater::invitation::Challenge;
use std::io::{self, Read};
fn main() {
    let mut raw = String::new();
    io::stdin().take(8193).read_to_string(&mut raw).unwrap();
    assert!(raw.len() <= 8192);
    let challenge: Challenge = serde_json::from_str(&raw).unwrap();
    println!(
        "{}",
        serde_json::json!({
            "challenge_id": challenge.id().unwrap(),
            "canonical_utf8": String::from_utf8(challenge.bytes().unwrap()).unwrap(),
            "challenge": challenge
        })
    );
}
