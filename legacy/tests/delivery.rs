use ed25519_dalek::{Signer, SigningKey};
use runlater::{
    auth::Permission,
    core::{Create, Dispatch, Outcome, Status, DAY},
    funding::{GrantSpec, Policy},
    identity::{Approval, Policy as IdentityPolicy, ORIGIN},
    security::digest,
    signed::{Envelope, Project, WINDOW_MS},
};
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn identity() -> IdentityPolicy {
    IdentityPolicy {
        project_id: "alpha".into(),
        revision: 1,
        revoked: false,
        approvals: vec![Approval {
            public_key: hex::encode(key().verifying_key().to_bytes()),
            permissions: [
                Permission::Read,
                Permission::Configure,
                Permission::Enqueue,
                Permission::Cancel,
                Permission::Redrive,
            ]
            .into_iter()
            .collect(),
            expires_at_ms: 30 * DAY,
        }],
        revoked_keys: vec![],
    }
}
fn state() -> Project {
    let mut p = Project::default();
    let i = identity();
    p.catalog.apply_policy(&i, 0).unwrap();
    let c = p
        .catalog
        .challenge("alpha", &i.approvals[0].public_key, &"01".repeat(32), 1)
        .unwrap();
    p.catalog
        .enroll(
            "alpha",
            &c.id().unwrap(),
            &hex::encode(key().sign(&c.bytes().unwrap()).to_bytes()),
            2,
        )
        .unwrap();
    p
}
fn policy(units: u64, expiry: i64) -> Policy {
    Policy {
        version: 1,
        project_id: "alpha".into(),
        revision: 1,
        active_grant: Some(GrantSpec {
            grant_id: "grant_a".into(),
            total_attempt_units: units,
            admission_expires_at_ms: expiry,
        }),
        revoked_grants: vec![],
    }
}
fn input(at: i64) -> Create {
    Create {
        destination: "registered:receiver_a".into(),
        body: "synthetic".into(),
        operation_key: "op_a".into(),
        run_at_ms: at,
    }
}
fn envelope(path: &str, body: &[u8], key_id: &str, nonce: u64, now: i64) -> Envelope {
    Envelope {
        version: 1,
        origin: ORIGIN.into(),
        project_id: "alpha".into(),
        public_key: identity().approvals[0].public_key.clone(),
        method: "POST".into(),
        path: path.into(),
        query: String::new(),
        body_sha256: digest(body),
        idempotency_key: key_id.into(),
        issued_at_ms: now,
        expires_at_ms: now + WINDOW_MS,
        nonce: format!("{nonce:064x}"),
    }
}
fn sig(e: &Envelope) -> String {
    hex::encode(key().sign(&e.bytes().unwrap()).to_bytes())
}
fn reference(p: &Project, id: &str) -> Dispatch {
    let t = p.ledger.get(id).unwrap();
    Dispatch {
        tenant: "alpha".into(),
        id: id.into(),
        generation: t.generation,
    }
}
fn business(p: &Project) -> serde_json::Value {
    serde_json::to_value((&p.ledger, &p.funding, &p.requests)).unwrap()
}

use runlater::{
    callback::{Envelope as CallbackEnvelope, FixtureMaterial, Keyring},
    delivery::{Policy as DeliveryPolicy, RECEIVER_URL},
};
fn delivery_policy() -> DeliveryPolicy {
    DeliveryPolicy {
        project_id: "alpha".into(),
        revision: 1,
        endpoint_id: "receiver_a".into(),
        url: RECEIVER_URL.into(),
        revoked: false,
        keys: Keyring::new("alpha", "policy_a", "fixture_a", 0, 86400, &FixtureMaterial).unwrap(),
        grant: policy(20, 1000),
    }
}
fn accept(
    p: &mut Project,
    cfg: &DeliveryPolicy,
    idem: &str,
    now: i64,
    nonce: u64,
) -> serde_json::Value {
    let mut i = input(0);
    i.body = "{\"synthetic\":true}".into();
    let body = serde_json::to_vec(&i).unwrap();
    let e = envelope("/v1/tasks", &body, idem, nonce, now);
    p.delivery_command(&identity(), cfg, &FixtureMaterial, &e, &sig(&e), &body, now)
        .unwrap()
}
#[test]
fn wire_snapshot_and_dispatch_cutover_survive_restart() {
    let mut p = state();
    let cfg = delivery_policy();
    let a = accept(&mut p, &cfg, "a", 3, 1);
    let id = a["result"]["id"].as_str().unwrap();
    let mut rotated = cfg.clone();
    rotated.revision = 2;
    rotated
        .keys
        .rotate("fixture_b", 1, 86401, 0, &FixtureMaterial)
        .unwrap();
    let mut p = Project::decode(serde_json::to_value(&p).unwrap()).unwrap();
    let w = p
        .delivery_claim(&rotated, &reference(&p, id), &FixtureMaterial, 1001)
        .unwrap()
        .unwrap();
    let headers = w.headers.clone().into_iter().collect::<Vec<_>>();
    let signed = CallbackEnvelope::from_headers(&headers).unwrap();
    assert_eq!(signed.key_id, "fixture_b");
    rotated
        .keys
        .verify(&signed, w.body.as_bytes(), 1, &FixtureMaterial)
        .unwrap();
    assert!(p
        .delivery_claim(&rotated, &reference(&p, id), &FixtureMaterial, 1002)
        .unwrap()
        .is_none());
    assert_eq!(p.funding.grant("grant_a").unwrap().spent, 1);
    let fence = p.ledger.get(id).unwrap().fence;
    p.delivery_finish(id, fence, Outcome::Http(204), "http_success", 1003)
        .unwrap();
    assert!(p
        .delivery_finish(id, fence, Outcome::Http(204), "http_success", 1004)
        .is_err());
    assert_eq!(p.funding.grant("grant_a").unwrap().spent, 1);
}
#[test]
fn endpoint_revocation_is_sticky_and_consumes_only_bounded_failed_attempt() {
    let mut p = state();
    let cfg = delivery_policy();
    let a = accept(&mut p, &cfg, "a", 3, 1);
    let id = a["result"]["id"].as_str().unwrap();
    let mut revoked = cfg.clone();
    revoked.revision = 2;
    revoked.revoked = true;
    p.delivery.apply(&revoked, 4).unwrap();
    let mut p = Project::decode(serde_json::to_value(&p).unwrap()).unwrap();
    let mut restored = cfg.clone();
    restored.revision = 3;
    assert!(p
        .delivery_claim(&restored, &reference(&p, id), &FixtureMaterial, 5)
        .unwrap()
        .is_none());
    assert_eq!(p.ledger.get(id).unwrap().status, Status::Failed);
    assert_eq!(p.funding.grant("grant_a").unwrap().spent, 1);
}
#[test]
fn revoked_signer_cannot_reappear_on_rollback_or_later_revision() {
    let mut p = state();
    let cfg = delivery_policy();
    accept(&mut p, &cfg, "a", 3, 1);
    let mut revoked = cfg.clone();
    revoked.revision = 2;
    revoked.keys.revoke("fixture_a", 0).unwrap();
    p.delivery.apply(&revoked, 4).unwrap();
    let mut restored = cfg.clone();
    restored.revision = 3;
    assert!(p.delivery.apply(&restored, 5).is_err());
    assert!(p.delivery.apply(&cfg, 5).is_err());
}
#[test]
fn unapproved_endpoint_and_nonjson_body_never_accept_or_reserve() {
    let mut p = state();
    let cfg = delivery_policy();
    let before = business(&p);
    let mut bad = cfg.clone();
    bad.url = "https://example.com/callback".into();
    let mut i = input(0);
    i.body = "{}".into();
    let body = serde_json::to_vec(&i).unwrap();
    let e = envelope("/v1/tasks", &body, "a", 1, 3);
    assert!(p
        .delivery_command(&identity(), &bad, &FixtureMaterial, &e, &sig(&e), &body, 3)
        .is_err());
    assert_eq!(business(&p), before);
    i.body = "not-json".into();
    let body = serde_json::to_vec(&i).unwrap();
    let e = envelope("/v1/tasks", &body, "a", 1, 3);
    assert!(p
        .delivery_command(&identity(), &cfg, &FixtureMaterial, &e, &sig(&e), &body, 3)
        .is_err());
    assert_eq!(business(&p), before);
}
#[test]
fn material_identity_and_attempt_envelope_cannot_be_substituted() {
    use runlater::callback::Material;
    struct Changed;
    impl Material for Changed {
        fn key(&self, _: &str) -> Option<&[u8]> {
            Some(b"different-public-fixture-material-32-bytes")
        }
    }
    let mut p = state();
    let cfg = delivery_policy();
    let a = accept(&mut p, &cfg, "a", 3, 1);
    let id = a["result"]["id"].as_str().unwrap();
    let w = p
        .delivery_claim(&cfg, &reference(&p, id), &FixtureMaterial, 4)
        .unwrap()
        .unwrap();
    let headers = w.headers.clone().into_iter().collect::<Vec<_>>();
    p.delivery
        .verify(&headers, w.body.as_bytes(), &FixtureMaterial, 5)
        .unwrap();
    assert!(p.delivery.bind_material(&Changed).is_err());
    let forged = runlater::callback::Snapshot::new(
        "alpha",
        "policy_a",
        id,
        "other_operation",
        w.body.as_bytes(),
    )
    .unwrap();
    let envelope = cfg
        .keys
        .sign(&forged, w.body.as_bytes(), 0, &FixtureMaterial)
        .unwrap();
    assert!(p
        .delivery
        .verify(
            &envelope.headers().into_iter().collect::<Vec<_>>(),
            w.body.as_bytes(),
            &FixtureMaterial,
            5
        )
        .is_err());
}
#[test]
fn publication_reservations_survive_restart() {
    let mut p = state();
    let cfg = delivery_policy();
    let a = accept(&mut p, &cfg, "a", 3, 1);
    let d = reference(&p, a["result"]["id"].as_str().unwrap());
    let mut refs = vec![d.clone(); 100];
    p.delivery.reserve_publications(&mut refs);
    assert_eq!(refs.len(), 100);
    let mut p = Project::decode(serde_json::to_value(&p).unwrap()).unwrap();
    let mut refs = vec![d; 100];
    p.delivery.reserve_publications(&mut refs);
    assert_eq!(refs.len(), 28);
    assert!(p.delivery.publication_exhausted());
    let mut refs = refs.clone();
    p.delivery.reserve_publications(&mut refs);
    assert!(refs.is_empty());
}
#[test]
fn cancelled_tasks_cannot_refill_lifetime_admission_cap() {
    let mut p = state();
    let cfg = delivery_policy();
    for n in 0..16u64 {
        let now = 3 + n as i64 * 2;
        let a = accept(&mut p, &cfg, &format!("a{n}"), now, n * 2 + 1);
        let id = a["result"]["id"].as_str().unwrap();
        let e = envelope(
            &format!("/v1/tasks/{id}/cancel"),
            b"{}",
            "",
            n * 2 + 2,
            now + 1,
        );
        p.task_command(&identity(), None, &e, &sig(&e), b"{}", now + 1)
            .unwrap();
    }
    let mut p = Project::decode(serde_json::to_value(&p).unwrap()).unwrap();
    let mut i = input(0);
    i.body = "{\"synthetic\":true}".into();
    let body = serde_json::to_vec(&i).unwrap();
    let e = envelope("/v1/tasks", &body, "overflow", 40, 40);
    let before = business(&p);
    assert!(p
        .delivery_command(&identity(), &cfg, &FixtureMaterial, &e, &sig(&e), &body, 40)
        .is_err());
    assert_eq!(business(&p), before);
}
#[test]
fn unpaused_exhausted_publication_age_settles_before_future_rearm() {
    let mut p = state();
    let mut cfg = delivery_policy();
    cfg.grant = policy(5, 3 * DAY);
    let a = accept(&mut p, &cfg, "aged", 3, 1);
    let id = a["result"]["id"].as_str().unwrap();
    let mut refs = vec![reference(&p, id); 128];
    p.delivery.reserve_publications(&mut refs);
    assert!(!p.ledger.limits.paused);
    assert!(p.delivery.publication_exhausted());
    let boundary = 3 + DAY;
    p.funded_maintenance(boundary).unwrap();
    assert_eq!(p.ledger.get(id).unwrap().status, Status::Ready);
    assert_eq!(p.delivery_next_wake(boundary), Some(boundary + 1));
    p.funded_maintenance(boundary + 1).unwrap();
    let t = p.ledger.get(id).unwrap();
    assert_eq!(t.status, Status::Failed);
    assert!(t.attempts.is_empty());
    let receipt = p
        .funding
        .reservation(id)
        .unwrap()
        .settlement
        .clone()
        .unwrap();
    assert_eq!(receipt.unused_units, 5);
    assert_eq!(p.funding.grant("grant_a").unwrap().reserved, 0);
    assert_eq!(p.funding.grant("grant_a").unwrap().available, 5);
    assert!(p.delivery_next_wake(boundary + 1).unwrap() > boundary + 1);
    assert!(p.delivery_unavailable_wake(boundary + 1).unwrap() > boundary + 60000);
    let mut p = Project::decode(serde_json::to_value(&p).unwrap()).unwrap();
    p.funded_maintenance(boundary + 2).unwrap();
    assert_eq!(
        p.funding.reservation(id).unwrap().settlement.as_ref(),
        Some(&receipt)
    );
    assert!(p.ledger.outbox("alpha", boundary + 2).is_empty());
    assert_eq!(
        p.ledger.metrics.view(boundary + 2)["totals"]["counts"]["claim_age_expired"],
        1
    );
}
