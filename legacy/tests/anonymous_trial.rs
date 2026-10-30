//! Disposable local keys and capabilities only. No external enrollment.
use ed25519_dalek::{Signer, SigningKey};
use runlater::{
    anonymous_trial::{Descriptor, Grant, PROVISION, REVOKE, STATUS, VALIDATE},
    invitation::{Enrollment, Mode},
    mcp_delegation::{Proof, Trust},
    public_beta::{Profile, State, DURATION},
    security::digest,
    signed::Envelope,
};
use serde_json::{json, Value};
const CAP: &str = "abababababababababababababababababababababababababababababababab";
const REVOKER: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
fn public() -> String {
    hex::encode(key().verifying_key().to_bytes())
}
fn trust(key: &str) -> Trust<'_> {
    Trust {
        gateway_public_key: key,
        release_id: "trial_test",
    }
}
fn descriptor(n: u8) -> Descriptor {
    let mut d = Descriptor {
        version: 1,
        release_id: "trial_test".into(),
        bootstrap_id: format!("{n:02x}").repeat(32),
        capability_hash: "00".repeat(32),
        revocation_hash: "00".repeat(32),
        issued_at_ms: 10,
        expires_at_ms: 10 + DURATION,
        permissions: vec!["cancel".into(), "enqueue".into(), "read".into()],
    };
    d.capability_hash = d.capability_hash(CAP).unwrap();
    d.revocation_hash = d.revocation_hash(REVOKER).unwrap();
    d
}
fn state() -> State {
    State::new(&Profile {
        release_id: "trial_test".into(),
        opens_at_ms: 0,
        closes_at_ms: DURATION,
        callback_end_sec: (2 * DURATION + runlater::core::DAY) / 1000 + 301,
        self_host: "runlater-public-api.operator.workers.dev".into(),
    })
    .unwrap()
}
fn envelope(d: &Descriptor, path: &str, body: &[u8], now: i64) -> Envelope {
    Envelope {
        version: 1,
        origin: runlater::identity::ORIGIN.into(),
        project_id: d.project_id().unwrap(),
        public_key: String::new(),
        method: if path == STATUS || path.starts_with("/v1/tasks/") && !path.ends_with("/cancel") {
            "GET"
        } else {
            "POST"
        }
        .into(),
        path: path.into(),
        query: String::new(),
        body_sha256: digest(body),
        idempotency_key: if matches!(path, PROVISION | REVOKE | "/v1/tasks") {
            "stable"
        } else {
            ""
        }
        .into(),
        issued_at_ms: now,
        expires_at_ms: (now + 60000).min(d.expires_at_ms),
        nonce: format!("{now:064x}"),
    }
}
fn sig(d: &Descriptor, e: &Envelope) -> String {
    hex::encode(key().sign(&d.bytes(e).unwrap()).to_bytes())
}
fn call(
    s: &mut State,
    d: &Descriptor,
    path: &str,
    now: i64,
) -> Result<Value, runlater::invitation::Error> {
    let body = if path == STATUS {
        b"".as_slice()
    } else {
        b"{}".as_slice()
    };
    let e = envelope(d, path, body, now);
    s.trial_request(
        &e,
        d,
        if path == REVOKE { REVOKER } else { CAP },
        &sig(d, &e),
        trust(&public()),
        body,
        now,
    )
}
fn provision(s: &mut State, d: &Descriptor, now: i64) -> Grant {
    serde_json::from_value(call(s, d, PROVISION, now).unwrap()["grant"].clone()).unwrap()
}
#[test]
fn lifecycle_is_explicit_idempotent_hash_only_and_never_refills() {
    let mut s = state();
    let d = descriptor(1);
    let before = serde_json::to_value(&s).unwrap();
    for route in [STATUS, VALIDATE] {
        assert_eq!(
            call(&mut s, &d, route, 20).unwrap()["state"],
            "unprovisioned"
        );
    }
    assert_eq!(before, serde_json::to_value(&s).unwrap());
    let g = provision(&mut s, &d, 21);
    assert_eq!(s.view(21)["remaining_projects"], 9);
    let committed = serde_json::to_value(&s).unwrap();
    s = serde_json::from_value(committed.clone()).unwrap();
    assert_eq!(provision(&mut s, &d, 30), g);
    assert_eq!(committed, serde_json::to_value(&s).unwrap());
    let snapshot = serde_json::to_string(&s).unwrap();
    assert!(!snapshot.contains(CAP));
    assert!(!snapshot.contains(REVOKER));
    let mut p = Enrollment::new(Mode::Invitation);
    p.install_trial(&g, 31).unwrap();
    let installed = serde_json::to_value(&p).unwrap();
    p.install_trial(&g, 32).unwrap();
    assert_eq!(installed, serde_json::to_value(&p).unwrap());
    let e = envelope(&d, STATUS, b"", 33);
    assert_eq!(
        p.validate_trial(&e, &d, CAP, &sig(&d, &e), trust(&public()), 33)
            .unwrap()["state"],
        "active"
    );
    for mutation in 0..5 {
        let mut malformed = envelope(&d, STATUS, b"", 34);
        match mutation {
            0 => malformed.query = "x=1".into(),
            1 => malformed.expires_at_ms = 34,
            2 => malformed.body_sha256 = digest(b"{}"),
            3 => malformed.path = PROVISION.into(),
            _ => malformed.idempotency_key = "not_allowed".into(),
        }
        assert!(p
            .validate_trial(
                &malformed,
                &d,
                CAP,
                &sig(&d, &malformed),
                trust(&public()),
                34
            )
            .is_err());
    }
    let mut changed = d.clone();
    changed.expires_at_ms += 1;
    let e = envelope(&d, PROVISION, b"{}", 34);
    assert!(s
        .trial_request(
            &e,
            &changed,
            CAP,
            &sig(&changed, &e),
            trust(&public()),
            b"{}",
            34
        )
        .is_err());
    let mut changed = d.clone();
    changed.capability_hash = changed.capability_hash(REVOKER).unwrap();
    assert!(call(&mut s, &changed, PROVISION, 34).is_err());
    assert!(call(&mut s, &d, PROVISION, d.expires_at_ms).is_err());
    assert_eq!(s.view(d.expires_at_ms)["remaining_projects"], 9);
}
#[test]
fn possession_scope_signature_and_envelope_binding_are_independent() {
    let mut s = state();
    let mut d = descriptor(2);
    d.permissions = vec!["enqueue".into()];
    provision(&mut s, &d, 20);
    let path = "/v1/tasks/task_0000000000000001";
    let e = envelope(&d, path, b"", 21);
    let before = serde_json::to_value(&s).unwrap();
    assert!(s
        .trial_request(&e, &d, CAP, &sig(&d, &e), trust(&public()), b"", 21)
        .is_err());
    for secret in [REVOKER, "", &d.capability_hash] {
        let e = envelope(&d, STATUS, b"", 22);
        assert!(s
            .trial_request(&e, &d, secret, &sig(&d, &e), trust(&public()), b"", 22)
            .is_err());
    }
    let mut e = envelope(&d, STATUS, b"", 22);
    let signature = sig(&d, &e);
    e.query = "changed=1".into();
    assert!(s
        .trial_request(&e, &d, CAP, &signature, trust(&public()), b"", 22)
        .is_err());
    let mut e = envelope(&d, STATUS, b"", 22);
    e.public_key = public();
    assert!(s
        .trial_request(&e, &d, CAP, &sig(&d, &e), trust(&public()), b"", 22)
        .is_err());
    let e = envelope(&d, STATUS, b"", 22);
    assert!(s
        .trial_request(&e, &d, CAP, &"00".repeat(64), trust(&public()), b"", 22)
        .is_err());
    assert_eq!(before, serde_json::to_value(&s).unwrap());
    for path in [
        "/v1/callback-key",
        "/v1/destinations/create",
        "/v1/registration/challenge",
        "/v1/tasks/task_0000000000000001/redrive",
    ] {
        assert!(call(&mut s, &d, path, 23).is_err());
    }
}
#[test]
fn revoke_before_or_after_provision_survives_reload_and_does_not_spend_owner_budget() {
    for first in [true, false] {
        let mut s = state();
        let d = descriptor(3);
        if first {
            provision(&mut s, &d, 20);
        }
        let r = call(&mut s, &d, REVOKE, 21).unwrap();
        assert_eq!(r["provisioned"], first);
        let saved = serde_json::to_value(&s).unwrap();
        s = serde_json::from_value(saved.clone()).unwrap();
        assert_eq!(call(&mut s, &d, REVOKE, 22).unwrap(), r);
        assert_eq!(saved, serde_json::to_value(&s).unwrap());
        for _ in 0..5 {
            assert!(call(&mut s, &d, PROVISION, 23).is_err());
            assert!(call(&mut s, &d, STATUS, 23).is_err());
        }
        assert_eq!(saved, serde_json::to_value(&s).unwrap());
    }
    let mut s = state();
    for n in 1..=32 {
        call(&mut s, &descriptor(n), REVOKE, 20).unwrap();
    }
    assert!(call(&mut s, &descriptor(33), REVOKE, 21).is_err());
    assert_eq!(s.view(21)["remaining_projects"], 10);
    let d = descriptor(34);
    provision(&mut s, &d, 22);
    assert!(call(&mut s, &d, REVOKE, 23).is_ok());
    // Full tombstone pool must not block legacy owner admission.
    let owner = SigningKey::from_bytes(&[91; 32]);
    let c = s
        .challenge(
            &hex::encode(owner.verifying_key().to_bytes()),
            &"11".repeat(32),
            24,
        )
        .unwrap();
    s.complete(
        &c.id().unwrap(),
        &hex::encode(owner.sign(&c.bytes().unwrap()).to_bytes()),
        25,
    )
    .unwrap();
}
#[test]
fn shared_cohort_and_per_project_budget_remain_finite() {
    let mut s = state();
    let owner = SigningKey::from_bytes(&[90; 32]);
    let c = s
        .challenge(
            &hex::encode(owner.verifying_key().to_bytes()),
            &"11".repeat(32),
            11,
        )
        .unwrap();
    s.complete(
        &c.id().unwrap(),
        &hex::encode(owner.sign(&c.bytes().unwrap()).to_bytes()),
        12,
    )
    .unwrap();
    for n in 1..=9 {
        provision(&mut s, &descriptor(n), 20 + i64::from(n));
    }
    assert_eq!(s.view(30)["remaining_projects"], 0);
    assert!(call(&mut s, &descriptor(10), PROVISION, 31).is_err());
    let d = descriptor(1);
    let mut saved = serde_json::to_value(&s).unwrap();
    saved["client_operations"][d.project_id().unwrap()] = json!(999);
    s = serde_json::from_value(saved).unwrap();
    s.check().unwrap();
    let e = envelope(&d, "/v1/tasks", b"{}", 32);
    s.trial_request(&e, &d, CAP, &sig(&d, &e), trust(&public()), b"{}", 32)
        .unwrap();
    assert!(s
        .trial_request(&e, &d, CAP, &sig(&d, &e), trust(&public()), b"{}", 32)
        .is_err());
    assert!(call(&mut s, &d, STATUS, 33).is_ok());
    assert!(call(&mut s, &d, REVOKE, 34).is_ok());
}
#[test]
fn project_auth_is_distinct_and_reinstall_never_resets_task_state() {
    let mut s = state();
    let d = descriptor(8);
    let g = provision(&mut s, &d, 20);
    let mut p = Enrollment::new(Mode::Invitation);
    p.install_trial(&g, 21).unwrap();
    let body=serde_json::to_vec(&json!({"destination":"registered:owned","body":"local","operation_key":"one","run_at_ms":0})).unwrap();
    let e = envelope(&d, "/v1/tasks", &body, 22);
    let signature = sig(&d, &e);
    let key = public();
    let proof = Proof::Trial {
        signature: &signature,
        descriptor: &d,
        capability: CAP,
        trust: trust(&key),
    };
    let v = p
        .signed_task_command_with_proof(&e, proof, &body, true, 22)
        .unwrap();
    assert_eq!(v["created"], true);
    let stored = serde_json::to_value(&p).unwrap();
    p.install_trial(&g, 23).unwrap();
    assert_eq!(stored, serde_json::to_value(&p).unwrap());
    assert!(
        p.signed_task_command(&e, &signature, &body, true, 24)
            .is_err(),
        "gateway is not an owner signing key"
    );
    let mut other = d.clone();
    other.bootstrap_id = "99".repeat(32);
    let e2 = envelope(&other, STATUS, b"", 24);
    assert!(p
        .validate_trial(&e2, &other, CAP, &sig(&other, &e2), trust(&key), 24)
        .is_err());
}
#[test]
fn javascript_wire_vector_matches_exact_rust_signature_and_canonical_header() {
    let v: Value =
        serde_json::from_str(include_str!("fixtures/anonymous-trial-vector.json")).unwrap();
    let d: Descriptor = serde_json::from_value(v["descriptor"].clone()).unwrap();
    let h = &v["headers"];
    assert_eq!(
        Descriptor::from_header(h["RunLater-Trial-Bootstrap"].as_str().unwrap()).unwrap(),
        d
    );
    assert_eq!(d.project_id().unwrap(), h["RunLater-Project-Id"]);
    assert_eq!(d.capability_hash(CAP).unwrap(), d.capability_hash);
    assert_eq!(d.revocation_hash(REVOKER).unwrap(), d.revocation_hash);
    let mut e = envelope(&d, STATUS, b"", 20);
    e.nonce = "ef".repeat(32);
    assert_eq!(sig(&d, &e), h["RunLater-Request-Signature"]);
    d.verify(
        &e,
        CAP,
        h["RunLater-Request-Signature"].as_str().unwrap(),
        trust(&public()),
        20,
    )
    .unwrap();
    assert!(Descriptor::from_header(
        &(h["RunLater-Trial-Bootstrap"].as_str().unwrap().to_string() + "=")
    )
    .is_err());
}
