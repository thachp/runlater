//! Native byte oracle. Stdin/output contain public release/challenge metadata only.
use runlater::{invitation::Challenge, public_beta::Profile};
use serde::Deserialize;
use std::io::{self, Read};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    profile: Profile,
    challenge: Challenge,
}
fn main() {
    let mut raw = String::new();
    io::stdin().take(8193).read_to_string(&mut raw).unwrap();
    assert!(raw.len() <= 8192);
    let input: Input = serde_json::from_str(&raw).unwrap();
    input.profile.validate().unwrap();
    let ticket_id = input
        .profile
        .ticket_id(&input.challenge.public_key)
        .unwrap();
    println!(
        "{}",
        serde_json::json!({
            "ticket_id": ticket_id,
            "offer": {
                "challenge_id": input.challenge.id().unwrap(),
                "canonical_utf8": String::from_utf8(input.challenge.bytes().unwrap()).unwrap(),
                "challenge": input.challenge,
            }
        })
    );
}
