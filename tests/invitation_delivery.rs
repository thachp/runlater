use ed25519_dalek::{Signer, SigningKey};
use runlater::{
    auth::Permission,
    callback::{Envelope as Callback, FixtureMaterial, Keyring},
    destinations::EgressPolicy,
    invitation::{Enrollment, Mode, Policy, Registry, Terms},
    security::digest,
    signed::Envelope,
};
use serde_json::{json, Value};
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn signed(project: &str, path: &str, body: &Value, nonce: char) -> (Envelope, String, Vec<u8>) {
    let bytes = serde_json::to_vec(body).unwrap();
    let e = Envelope {
        version: 1,
        origin: runlater::identity::ORIGIN.into(),
        project_id: project.into(),
        public_key: hex::encode(key().verifying_key().to_bytes()),
        method: "POST".into(),
        path: path.into(),
        query: String::new(),
        body_sha256: digest(&bytes),
        idempotency_key: format!("request_{nonce}"),
        issued_at_ms: 10,
        expires_at_ms: 60000,
        nonce: nonce.to_string().repeat(64),
    };
    let sig = hex::encode(key().sign(&e.bytes().unwrap()).to_bytes());
    (e, sig, bytes)
}
fn fixture(manage: bool) -> (Enrollment, String, EgressPolicy, Keyring) {
    let mut permissions = [
        Permission::Enqueue,
        Permission::Read,
        Permission::Cancel,
        Permission::Redrive,
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>();
    if manage {
        permissions.insert(Permission::ManageDestinations);
    }
    let mut r = Registry::default();
    r.apply(
        &Policy {
            revision: 1,
            terms: Some(Terms {
                attempt_units: 20,
                identity_ms: 86400000,
                permissions,
            }),
            max_projects: 2,
            max_tickets: 4,
            requests_per_minute: 64,
        },
        0,
    )
    .unwrap();
    let t = r
        .issue(&digest(b"public-test-invitation"), 300000, 1)
        .unwrap();
    let mut e = Enrollment::new(Mode::Invitation);
    let c = e
        .challenge(
            &t,
            &hex::encode(key().verifying_key().to_bytes()),
            &"a".repeat(64),
            2,
        )
        .unwrap();
    e.complete(
        &t,
        &c.id().unwrap(),
        &hex::encode(key().sign(&c.bytes().unwrap()).to_bytes()),
        3,
    )
    .unwrap();
    let ring = Keyring::new(
        &t.project_id,
        "callbacks",
        "fixture_a",
        0,
        172800,
        &FixtureMaterial,
    )
    .unwrap();
    (
        e,
        t.project_id,
        EgressPolicy {
            approved_hosts: ["receiver.example.test".into()].into_iter().collect(),
        },
        ring,
    )
}
fn command(
    e: &mut Enrollment,
    p: &str,
    path: &str,
    body: Value,
    n: char,
    policy: &EgressPolicy,
) -> Value {
    let (a, s, b) = signed(p, path, &body, n);
    e.destination_command(
        &a,
        &s,
        &b,
        policy,
        &n.to_string().repeat(64),
        if path.ends_with("/revoke") { 20 } else { 10 },
    )
    .unwrap()
}
fn verify(e: &mut Enrollment, p: &str, policy: &EgressPolicy) {
    let proof = command(
        e,
        p,
        "/v1/destinations/prepare",
        json!({"endpoint_id":"receiver","version":1}),
        'c',
        policy,
    );
    let (a, s, b) = signed(
        p,
        "/v1/destinations/verify",
        &json!({"endpoint_id":"receiver","version":1}),
        'd',
    );
    let c = e.destination_begin(&a, &s, &b, policy, 11).unwrap();
    e.destination_complete(
        p,
        &hex::encode(key().verifying_key().to_bytes()),
        &c,
        Ok((200, proof["response"].as_str().unwrap().as_bytes())),
        policy,
        12,
    )
    .unwrap();
}
#[test]
fn verified_selection_funding_and_task_are_atomic_and_rotation_is_selected_at_dispatch() {
    let (mut e, p, policy, mut ring) = fixture(true);
    command(
        &mut e,
        &p,
        "/v1/destinations/create",
        json!({"endpoint_id":"receiver","version":1,"url":"https://receiver.example.test/callback"}),
        'b',
        &policy,
    );
    let body = json!({"destination":"registered:receiver","body":"synthetic","operation_key":"logical_once"});
    let (a, s, b) = signed(&p, "/v1/tasks", &body, 'e');
    let before = serde_json::to_value(&e).unwrap();
    assert!(e
        .registered_task_command(&a, &s, &b, &policy, &ring, &FixtureMaterial, 13)
        .is_err());
    assert_eq!(serde_json::to_value(&e).unwrap(), before);
    verify(&mut e, &p, &policy);
    let accepted = e
        .registered_task_command(&a, &s, &b, &policy, &ring, &FixtureMaterial, 14)
        .unwrap();
    let id = accepted["result"]["id"].as_str().unwrap().to_string();
    let replay = e
        .registered_task_command(&a, &s, &b, &policy, &ring, &FixtureMaterial, 15)
        .unwrap();
    assert_eq!(replay["replayed"], true);
    ring.rotate("fixture_b", 0, 86400, 0, &FixtureMaterial)
        .unwrap();
    let (a2, s2, b2) = signed(
        &p,
        "/v1/tasks",
        &json!({"destination":"registered:receiver","body":"synthetic","operation_key":"other"}),
        'f',
    );
    e.registered_task_command(&a2, &s2, &b2, &policy, &ring, &FixtureMaterial, 16)
        .unwrap();
    let mut e: Enrollment = serde_json::from_slice(&serde_json::to_vec(&e).unwrap()).unwrap();
    let refs = e.registered_outbox(&p, 17).unwrap();
    let d = refs.iter().find(|d| d.id == id).unwrap();
    let wire = e
        .registered_claim(d, &policy, 18, &FixtureMaterial)
        .unwrap()
        .unwrap();
    let envelope = Callback::from_headers(&wire.headers.into_iter().collect::<Vec<_>>()).unwrap();
    assert_eq!(envelope.key_id, "fixture_b");
    ring.verify(&envelope, wire.body.as_bytes(), 0, &FixtureMaterial)
        .unwrap();
    let fence = e.project.ledger.get(&id).unwrap().fence;
    e.project
        .funded_finish(&id, fence, runlater::core::Outcome::Http(200), 19)
        .unwrap();
    assert!(e
        .registered_claim(d, &policy, 20, &FixtureMaterial)
        .unwrap()
        .is_none());
}
#[test]
fn destination_permission_and_revocation_block_egress_without_refunding_spent_attempts() {
    let (mut no_scope, p, policy, _) = fixture(false);
    let (a, s, b) = signed(
        &p,
        "/v1/destinations/create",
        &json!({"endpoint_id":"receiver","version":1,"url":"https://receiver.example.test/callback"}),
        'b',
    );
    assert!(no_scope
        .destination_command(&a, &s, &b, &policy, &"a".repeat(64), 10)
        .is_err());
    let (mut e, p, policy, ring) = fixture(true);
    command(
        &mut e,
        &p,
        "/v1/destinations/create",
        json!({"endpoint_id":"receiver","version":1,"url":"https://receiver.example.test/callback"}),
        'b',
        &policy,
    );
    verify(&mut e, &p, &policy);
    let (a, s, b) = signed(
        &p,
        "/v1/tasks",
        &json!({"destination":"registered:receiver","body":"synthetic","operation_key":"revoked"}),
        'e',
    );
    let v = e
        .registered_task_command(&a, &s, &b, &policy, &ring, &FixtureMaterial, 13)
        .unwrap();
    let id = v["result"]["id"].as_str().unwrap();
    command(
        &mut e,
        &p,
        "/v1/destinations/revoke",
        json!({"endpoint_id":"receiver","version":1}),
        'f',
        &policy,
    );
    let refs = e.registered_outbox(&p, 21).unwrap();
    assert!(e
        .registered_claim(&refs[0], &policy, 22, &FixtureMaterial)
        .unwrap()
        .is_none());
    let task = e.project.ledger.get(id).unwrap();
    assert!(task.status.terminal());
    assert_eq!(
        e.project
            .funding
            .reservation(id)
            .unwrap()
            .spent_fences
            .len(),
        1
    );
}

#[test]
fn accepted_reservation_survives_identity_and_grant_expiry_and_exhausted_publications_age_out() {
    let (mut e, p, policy, ring) = fixture(true);
    command(
        &mut e,
        &p,
        "/v1/destinations/create",
        json!({"endpoint_id":"receiver","version":1,"url":"https://receiver.example.test/callback"}),
        'b',
        &policy,
    );
    verify(&mut e, &p, &policy);
    let (a, s, b) = signed(
        &p,
        "/v1/tasks",
        &json!({"destination":"registered:receiver","body":"synthetic","operation_key":"after_expiry"}),
        'e',
    );
    let v = e
        .registered_task_command(&a, &s, &b, &policy, &ring, &FixtureMaterial, 13)
        .unwrap();
    let id = v["result"]["id"].as_str().unwrap().to_string();
    let mut expiry: Enrollment = serde_json::from_slice(&serde_json::to_vec(&e).unwrap()).unwrap();
    let refs = expiry.registered_outbox(&p, 86400004).unwrap();
    let wire = expiry
        .registered_claim(&refs[0], &policy, 86400005, &FixtureMaterial)
        .unwrap();
    assert!(wire.is_some());
    let fence = expiry.project.ledger.get(&id).unwrap().fence;
    expiry
        .project
        .funded_finish(&id, fence, runlater::core::Outcome::Http(200), 86400006)
        .unwrap();
    assert_eq!(
        expiry
            .project
            .funding
            .reservation(&id)
            .unwrap()
            .spent_fences
            .len(),
        1
    );
    for n in 0..128 {
        assert_eq!(e.registered_outbox(&p, 14 + n).unwrap().len(), 1)
    }
    assert!(e.registered_outbox(&p, 200).unwrap().is_empty());
    let deadline = 13 + runlater::core::DAY + 1;
    assert_eq!(e.project.delivery_next_wake(200), Some(deadline));
    assert!(e.registered_outbox(&p, deadline).unwrap().is_empty());
    assert!(e.project.ledger.get(&id).unwrap().status.terminal());
    let after = e.project.funding.reservation(&id).unwrap().clone();
    assert!(e.registered_outbox(&p, deadline + 1).unwrap().is_empty());
    assert_eq!(
        serde_json::to_value(after).unwrap(),
        serde_json::to_value(e.project.funding.reservation(&id).unwrap()).unwrap()
    );
    assert!(e.project.delivery_next_wake(deadline + 1).unwrap() > deadline + 1);
}
