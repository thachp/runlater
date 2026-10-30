//! PUBLIC deterministic vectors only. This emits wire signatures, never real credentials.
use runlater::callback::{FixtureMaterial, Keyring, Snapshot};
fn main() {
    if std::env::args().nth(1).as_deref() == Some("verify") {
        use std::io::Read;
        #[derive(serde::Deserialize)]
        struct Input {
            policy: Keyring,
            body: String,
            headers: std::collections::BTreeMap<String, String>,
            now_sec: i64,
        }
        let mut text = String::new();
        std::io::stdin()
            .take(65536)
            .read_to_string(&mut text)
            .unwrap();
        let verified = serde_json::from_str::<Input>(&text)
            .ok()
            .is_some_and(|input| {
                runlater::callback::Envelope::from_headers(
                    &input.headers.into_iter().collect::<Vec<_>>(),
                )
                .ok()
                .is_some_and(|e| {
                    input
                        .policy
                        .verify(&e, input.body.as_bytes(), input.now_sec, &FixtureMaterial)
                        .is_ok()
                })
            });
        println!("{}", serde_json::json!({"verified":verified}));
        return;
    }
    let body = "{\"message\":\"héllo\",\"count\":1}";
    let mut ring = Keyring::new(
        "alpha",
        "default",
        "fixture_a",
        1000,
        10000,
        &FixtureMaterial,
    )
    .unwrap();
    ring.rotate("fixture_b", 2000, 9000, 1500, &FixtureMaterial)
        .unwrap();
    let snapshot = Snapshot::new(
        "alpha",
        "default",
        "task_0000000000000001",
        "invoice_42",
        body.as_bytes(),
    )
    .unwrap();
    let old = ring
        .sign(&snapshot, body.as_bytes(), 1999, &FixtureMaterial)
        .unwrap();
    let new = ring
        .sign(&snapshot, body.as_bytes(), 2000, &FixtureMaterial)
        .unwrap();
    let redrive = ring
        .sign(
            &snapshot.redrive("task_0000000000000002").unwrap(),
            body.as_bytes(),
            2001,
            &FixtureMaterial,
        )
        .unwrap();
    let mut revoked = ring.clone();
    revoked.revoke("fixture_a", 2001).unwrap();
    println!(
        "{}",
        serde_json::json!({"policy":ring,"revoked_policy":revoked,"body":body,"old_headers":old.headers(),"new_headers":new.headers(),"redrive_headers":redrive.headers()})
    );
}
