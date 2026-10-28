use ed25519_dalek::{Signer, SigningKey};
use runlater::{
    auth::Permission,
    identity::{Approval, Error, Policy, ORIGIN},
    limits::QueueLimits,
    security::digest,
    signed::*,
};
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}
fn policy() -> Policy {
    Policy {
        project_id: "alpha".into(),
        revision: 1,
        revoked: false,
        approvals: vec![Approval {
            public_key: hex::encode(key().verifying_key().to_bytes()),
            permissions: [Permission::Read, Permission::Configure]
                .into_iter()
                .collect(),
            expires_at_ms: 5 * RECEIPT_TTL_MS,
        }],
        revoked_keys: vec![],
    }
}
fn state() -> Project {
    let mut p = Project::default();
    let policy = policy();
    p.catalog.apply_policy(&policy, 0).unwrap();
    let c = p
        .catalog
        .challenge(
            "alpha",
            &policy.approvals[0].public_key,
            &"01".repeat(32),
            1,
        )
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
fn body(paused: bool) -> Vec<u8> {
    serde_json::to_vec(&QueueLimits {
        paused,
        ..QueueLimits::default()
    })
    .unwrap()
}
fn request(method: &str, body: &[u8], nonce: u64, now: i64) -> Envelope {
    Envelope {
        version: 1,
        origin: ORIGIN.into(),
        project_id: "alpha".into(),
        public_key: policy().approvals[0].public_key.clone(),
        method: method.into(),
        path: "/v1/queue".into(),
        query: String::new(),
        body_sha256: digest(body),
        idempotency_key: if method == "PUT" {
            "config-a".into()
        } else {
            String::new()
        },
        issued_at_ms: now,
        expires_at_ms: now + WINDOW_MS,
        nonce: format!("{nonce:064x}"),
    }
}
fn signature(e: &Envelope) -> String {
    hex::encode(key().sign(&e.bytes().unwrap()).to_bytes())
}
fn restart(p: &Project) -> Project {
    Project::decode(serde_json::to_value(p).unwrap()).unwrap()
}
#[test]
fn pure_signed_reads_are_repeatable_until_expiry_and_do_not_migrate_or_prune() {
    let p = state();
    let e = request("GET", b"", 1, 3);
    let before = serde_json::to_value(&p).unwrap();
    for now in [3, 4, 500] {
        assert_eq!(
            p.query(&policy(), &e, &signature(&e), b"", now).unwrap()["result"]["paused"],
            false
        );
    }
    assert_eq!(serde_json::to_value(&p).unwrap(), before);
    assert_eq!(
        p.query(&policy(), &e, &signature(&e), b"", e.expires_at_ms)
            .err(),
        Some(Error::Expired)
    );
    let legacy = serde_json::to_value(&p.catalog).unwrap();
    let migrated = Project::decode(legacy).unwrap();
    assert_eq!(
        migrated
            .query(&policy(), &e, &signature(&e), b"", 4)
            .unwrap()["result"]["paused"],
        false
    );
}
#[test]
fn configuration_and_nonce_receipt_replay_survive_restart_without_double_effect() {
    let mut p = state();
    let b = body(true);
    let e = request("PUT", &b, 1, 3);
    let first = p.command(&policy(), &e, &signature(&e), &b, 3).unwrap();
    assert_eq!(first["replayed"], false);
    assert_eq!(
        p.command(&policy(), &e, &"00".repeat(64), &b, 3).err(),
        Some(Error::Forbidden)
    );
    let audit = p.ledger.audit.len();
    let mut p = restart(&p);
    let replay = p.command(&policy(), &e, &signature(&e), &b, 4).unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["committed_at_ms"], first["committed_at_ms"]);
    assert_eq!(p.ledger.audit.len(), audit);
    let fresh = request("PUT", &b, 2, 5);
    assert_eq!(
        p.command(&policy(), &fresh, &signature(&fresh), &b, 5)
            .unwrap()["replayed"],
        true
    );
    assert_eq!(p.ledger.audit.len(), audit);
}
#[test]
fn every_signed_field_and_exact_body_are_bound() {
    let p = state();
    let original = request("GET", b"", 1, 3);
    for field in 0..13 {
        let mut e = original.clone();
        match field {
            0 => e.version = 2,
            1 => e.origin = "https://evil.example".into(),
            2 => e.project_id = "beta".into(),
            3 => e.public_key = "00".repeat(32),
            4 => e.method = "PUT".into(),
            5 => e.path = "/v1/identity/me".into(),
            6 => e.query = "view=all".into(),
            7 => e.body_sha256 = "00".repeat(32),
            8 => e.idempotency_key = "altered".into(),
            9 => e.issued_at_ms += 1,
            10 => e.expires_at_ms += 1,
            11 => e.nonce = "02".repeat(32),
            _ => e.path = "/v1/queue/".into(),
        };
        assert!(
            p.query(&policy(), &e, &signature(&original), b"", 4)
                .is_err(),
            "field{field}"
        );
    }
    let mut p = state();
    let b = body(true);
    let e = request("PUT", &b, 1, 3);
    let mut changed = b.clone();
    changed.push(b' ');
    assert_eq!(
        p.command(&policy(), &e, &signature(&e), &changed, 4).err(),
        Some(Error::Forbidden)
    );
    assert!(!p.ledger.limits.paused);
}
#[test]
fn nonce_and_idempotency_namespace_conflicts_never_reconfigure() {
    let mut p = state();
    let b = body(true);
    let e = request("PUT", &b, 1, 3);
    p.command(&policy(), &e, &signature(&e), &b, 3).unwrap();
    let before = serde_json::to_value(&p.ledger).unwrap();
    let changed = body(false);
    let e2 = request("PUT", &changed, 1, 4);
    assert_eq!(
        p.command(&policy(), &e2, &signature(&e2), &changed, 4)
            .err(),
        Some(Error::Conflict)
    );
    let e3 = request("PUT", &changed, 2, 5);
    assert_eq!(
        p.command(&policy(), &e3, &signature(&e3), &changed, 5)
            .err(),
        Some(Error::Conflict)
    );
    let mut alias = request("PUT", &b, 1, 6);
    alias.idempotency_key = "different".into();
    assert_eq!(
        p.command(&policy(), &alias, &signature(&alias), &b, 6)
            .err(),
        Some(Error::Conflict)
    );
    assert_eq!(serde_json::to_value(&p.ledger).unwrap(), before);
}
#[test]
fn revocation_between_request_creation_and_atomic_execution_blocks_cached_and_new_commands() {
    let mut p = state();
    let b = body(true);
    let e = request("PUT", &b, 1, 3);
    p.command(&policy(), &e, &signature(&e), &b, 3).unwrap();
    let pending = request("PUT", &body(false), 2, 4);
    let mut revoked = policy();
    revoked.revision = 2;
    revoked
        .revoked_keys
        .push(revoked.approvals[0].public_key.clone());
    p.catalog.apply_policy(&revoked, 4).unwrap();
    let limits = p.ledger.limits.clone();
    assert_eq!(
        p.command(&revoked, &pending, &signature(&pending), &body(false), 5)
            .err(),
        Some(Error::Forbidden)
    );
    assert_eq!(
        p.command(&revoked, &e, &signature(&e), &b, 5).err(),
        Some(Error::Forbidden)
    );
    assert_eq!(p.ledger.limits, limits);
    let read = request("GET", b"", 3, 5);
    assert_eq!(
        p.query(&revoked, &read, &signature(&read), b"", 5).err(),
        Some(Error::Forbidden)
    );
}
#[test]
fn scope_policy_read_snapshot_and_clock_checks_precede_receipt_replay() {
    let mut p = state();
    let b = body(true);
    let e = request("PUT", &b, 1, 100);
    p.command(&policy(), &e, &signature(&e), &b, 100).unwrap();
    assert_eq!(
        p.command(&policy(), &e, &signature(&e), &b, 99).err(),
        Some(Error::ClockRegressed)
    );
    let read = request("GET", b"", 2, 99);
    assert_eq!(
        p.query(&policy(), &read, &signature(&read), b"", 99).err(),
        Some(Error::ClockRegressed)
    );
    let mut narrowed = policy();
    narrowed.revision = 2;
    narrowed.approvals[0]
        .permissions
        .remove(&Permission::Configure);
    assert_eq!(
        p.command(&narrowed, &e, &signature(&e), &b, 101).err(),
        Some(Error::Forbidden)
    );
    let before = serde_json::to_value(&p).unwrap();
    let read = request("GET", b"", 3, 102);
    assert!(p
        .query(&narrowed, &read, &signature(&read), b"", 102)
        .is_ok());
    assert_eq!(serde_json::to_value(&p).unwrap(), before);
}
#[test]
fn bounded_receipt_retention_and_signature_expiry_are_explicit() {
    let mut p = state();
    let b = body(false);
    for i in 0..CAPACITY {
        let mut e = request("PUT", &b, i as u64 + 1, 3 + i as i64);
        e.idempotency_key = format!("config-{i}");
        assert!(p
            .command(&policy(), &e, &signature(&e), &b, 3 + i as i64)
            .is_ok());
    }
    let mut full = request("PUT", &b, 999, 500);
    full.idempotency_key = "full".into();
    assert_eq!(
        p.command(&policy(), &full, &signature(&full), &b, 500)
            .err(),
        Some(Error::Limited)
    );
    let later = RECEIPT_TTL_MS + 1000;
    full.issued_at_ms = later;
    full.expires_at_ms = later + WINDOW_MS;
    assert!(p
        .command(&policy(), &full, &signature(&full), &b, later)
        .is_ok());
    assert_eq!(
        p.command(&policy(), &full, &signature(&full), &b, full.expires_at_ms)
            .err(),
        Some(Error::Expired)
    );
}
#[test]
fn malformed_new_snapshots_fail_closed_and_request_json_is_strict() {
    let p = state();
    let mut value = serde_json::to_value(&p).unwrap();
    value["project_state_version"] = 2.into();
    assert!(Project::decode(value).is_err());
    let mut value = serde_json::to_value(&p).unwrap();
    value.as_object_mut().unwrap().remove("requests");
    assert!(Project::decode(value).is_err());
    let mut p = state();
    let b=br#"{"paused":false,"paused":true,"max_active_tasks":1,"max_payload_bytes":100,"max_concurrent":1,"dispatch_per_second":1,"dispatch_burst":1}"#;
    let e = request("PUT", b, 1, 3);
    assert_eq!(
        p.command(&policy(), &e, &signature(&e), b, 3).err(),
        Some(Error::Invalid)
    );
    assert!(!p.ledger.limits.paused);
}
#[test]
fn authorized_key_rotation_replays_project_scoped_configuration_without_undoing_later_writes() {
    let mut p = state();
    let original_body = body(true);
    let old = request("PUT", &original_body, 1, 3);
    let receipt = p
        .command(&policy(), &old, &signature(&old), &original_body, 3)
        .unwrap();
    let other = SigningKey::from_bytes(&[8; 32]);
    let other_public = hex::encode(other.verifying_key().to_bytes());
    let mut updated = policy();
    updated.revision = 2;
    updated.approvals.push(Approval {
        public_key: other_public.clone(),
        permissions: [Permission::Read, Permission::Configure]
            .into_iter()
            .collect(),
        expires_at_ms: 5 * RECEIPT_TTL_MS,
    });
    p.catalog.apply_policy(&updated, 4).unwrap();
    let c = p
        .catalog
        .challenge("alpha", &other_public, &"03".repeat(32), 4)
        .unwrap();
    p.catalog
        .enroll(
            "alpha",
            &c.id().unwrap(),
            &hex::encode(other.sign(&c.bytes().unwrap()).to_bytes()),
            5,
        )
        .unwrap();
    let changed = body(false);
    let mut newer = request("PUT", &changed, 2, 6);
    newer.idempotency_key = "new-configuration".into();
    p.command(&updated, &newer, &signature(&newer), &changed, 6)
        .unwrap();
    let audit = p.ledger.audit.len();
    let mut rotated = request("PUT", &original_body, 3, 7);
    rotated.public_key = other_public;
    let rotated_signature = hex::encode(other.sign(&rotated.bytes().unwrap()).to_bytes());
    let replay = p
        .command(&updated, &rotated, &rotated_signature, &original_body, 7)
        .unwrap();
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["committed_at_ms"], receipt["committed_at_ms"]);
    assert!(!p.ledger.limits.paused);
    assert_eq!(p.ledger.audit.len(), audit);
}
