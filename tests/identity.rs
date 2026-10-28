use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use runlater::{auth::Permission, identity::*};
fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
} // Public deterministic test fixture only.
fn policy() -> Policy {
    Policy {
        project_id: "alpha".into(),
        revision: 1,
        revoked: false,
        approvals: vec![Approval {
            public_key: hex::encode(key().verifying_key().to_bytes()),
            permissions: [Permission::Enqueue, Permission::Read]
                .into_iter()
                .collect(),
            expires_at_ms: 10 * TTL,
        }],
        revoked_keys: vec![],
    }
}
fn catalog() -> Catalog {
    let mut c = Catalog::default();
    c.apply_policy(&policy(), 0).unwrap();
    c
}
fn challenge(c: &mut Catalog) -> Challenge {
    c.challenge(
        "alpha",
        &policy().approvals[0].public_key,
        &"01".repeat(32),
        1,
    )
    .unwrap()
}
fn sign(c: &Challenge) -> String {
    hex::encode(key().sign(&c.bytes().unwrap()).to_bytes())
}
fn restart(c: &Catalog) -> Catalog {
    serde_json::from_value(serde_json::to_value(c).unwrap()).unwrap()
}
#[test]
fn standard_rfc8032_empty_message_vector_and_strict_weak_key_rejection() {
    let pk = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        .unwrap()
        .try_into()
        .unwrap();
    let key = VerifyingKey::from_bytes(&pk).unwrap();
    let sig=Signature::from_slice(&hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b").unwrap()).unwrap();
    assert!(key.verify_strict(b"", &sig).is_ok());
    assert!(!key_valid(&"00".repeat(32)));
}
#[test]
fn valid_possession_consumes_once_across_restart_with_scoped_authorization() {
    let mut c = catalog();
    let ch = challenge(&mut c);
    let id = ch.id().unwrap();
    let mut c = restart(&c);
    let identity = c.enroll("alpha", &id, &sign(&ch), 2).unwrap();
    assert_eq!(identity.permissions, policy().approvals[0].permissions);
    assert!(c
        .authorize("alpha", &identity.public_key, Permission::Read, 2)
        .is_ok());
    assert_eq!(
        c.authorize("alpha", &identity.public_key, Permission::Cancel, 2),
        Err(Error::Forbidden)
    );
    assert_eq!(
        c.authorize("beta", &identity.public_key, Permission::Read, 2),
        Err(Error::Forbidden)
    );
    let mut c = restart(&c);
    assert_eq!(
        c.enroll("alpha", &id, &sign(&ch), 3).err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        c.challenge("alpha", &identity.public_key, &"03".repeat(32), 3)
            .err(),
        Some(Error::Conflict)
    );
}
#[test]
fn every_context_field_is_signed_and_wrong_project_cannot_consume() {
    let mut c = catalog();
    let original = challenge(&mut c);
    for field in 0..12 {
        let mut ch = original.clone();
        match field {
            0 => ch.version = 2,
            1 => ch.origin = "https://evil.example".into(),
            2 => ch.purpose = "purchase".into(),
            3 => ch.project_id = "beta".into(),
            4 => ch.public_key = "00".repeat(32),
            5 => ch.nonce = "02".repeat(32),
            6 => ch.issued_at_ms += 1,
            7 => ch.expires_at_ms += 1,
            8 => ch.policy_revision += 1,
            9 => ch.policy_hash = "00".repeat(32),
            10 => {
                ch.permissions.insert(Permission::Cancel);
            }
            _ => ch.identity_expires_at_ms += 1,
        };
        let mut cloned = restart(&c);
        assert_eq!(
            cloned
                .enroll("alpha", &original.id().unwrap(), &sign(&ch), 2)
                .err(),
            Some(Error::Forbidden)
        );
    }
    assert_eq!(
        c.enroll("beta", &original.id().unwrap(), &sign(&original), 2)
            .err(),
        Some(Error::Forbidden)
    );
    assert!(c
        .enroll("alpha", &original.id().unwrap(), &sign(&original), 2)
        .is_ok());
}
#[test]
fn expiry_clock_regression_and_failed_proof_budget_are_sticky() {
    let mut c = catalog();
    let ch = challenge(&mut c);
    assert_eq!(
        c.enroll("alpha", &ch.id().unwrap(), &sign(&ch), ch.expires_at_ms)
            .err(),
        Some(Error::Expired)
    );
    assert_eq!(
        c.enroll("alpha", &ch.id().unwrap(), &sign(&ch), 2).err(),
        Some(Error::ClockRegressed)
    );
    let mut c = catalog();
    let ch = challenge(&mut c);
    for _ in 0..3 {
        assert_eq!(
            c.enroll("alpha", &ch.id().unwrap(), "not-a-signature", 2)
                .err(),
            Some(Error::Forbidden)
        );
    }
    assert_eq!(
        restart(&c)
            .enroll("alpha", &ch.id().unwrap(), &sign(&ch), 3)
            .err(),
        Some(Error::Conflict)
    );
}
#[test]
fn immutable_revision_policy_and_revocation_never_bootstrap_resurrection() {
    let mut c = catalog();
    let ch = challenge(&mut c);
    let identity = c.enroll("alpha", &ch.id().unwrap(), &sign(&ch), 2).unwrap();
    let mut p = policy();
    p.approvals[0].permissions.insert(Permission::Cancel);
    assert_eq!(c.apply_policy(&p, 3), Err(Error::Conflict));
    p.revision = 2;
    p.revoked_keys.push(identity.public_key.clone());
    c.apply_policy(&p, 3).unwrap();
    let mut c = restart(&c);
    assert_eq!(
        c.authorize("alpha", &identity.public_key, Permission::Read, 3),
        Err(Error::Forbidden)
    );
    p.revision = 3;
    p.revoked_keys.clear();
    c.apply_policy(&p, 4).unwrap();
    assert_eq!(
        c.authorize("alpha", &identity.public_key, Permission::Read, 4),
        Err(Error::Forbidden)
    );
    assert_eq!(c.apply_policy(&policy(), 5), Err(Error::Conflict));
}
#[test]
fn policy_changes_invalidate_inflight_challenge_and_cannot_extend_enrolled_grant() {
    let mut c = catalog();
    let ch = challenge(&mut c);
    let mut p = policy();
    p.revision = 2;
    p.approvals[0].expires_at_ms += TTL;
    c.apply_policy(&p, 2).unwrap();
    assert_eq!(
        c.enroll("alpha", &ch.id().unwrap(), &sign(&ch), 3).err(),
        Some(Error::Conflict)
    );
    let new = c
        .challenge("alpha", &p.approvals[0].public_key, &"02".repeat(32), 3)
        .unwrap();
    let identity = c
        .enroll("alpha", &new.id().unwrap(), &sign(&new), 4)
        .unwrap();
    p.revision = 3;
    p.approvals[0].expires_at_ms += TTL;
    p.approvals[0].permissions.insert(Permission::Cancel);
    c.apply_policy(&p, 5).unwrap();
    assert_eq!(
        c.authorize("alpha", &identity.public_key, Permission::Cancel, 5),
        Err(Error::Forbidden)
    );
    assert_eq!(
        c.authorize(
            "alpha",
            &identity.public_key,
            Permission::Read,
            identity.expires_at_ms
        ),
        Err(Error::Expired)
    );
}
#[test]
fn challenge_capacity_ttl_unknown_keys_and_sticky_project_revocation() {
    let mut c = catalog();
    let key = policy().approvals[0].public_key.clone();
    for n in 0..8 {
        c.challenge("alpha", &key, &format!("{n:064x}"), 1).unwrap();
    }
    assert_eq!(
        c.challenge("alpha", &key, &"ff".repeat(32), 2).err(),
        Some(Error::Limited)
    );
    assert!(c
        .challenge("alpha", &key, &"ff".repeat(32), TTL + 1)
        .is_ok());
    assert_eq!(
        c.challenge("alpha", &"ee".repeat(32), &"aa".repeat(32), TTL + 2)
            .err(),
        Some(Error::Forbidden)
    );
    let mut p = policy();
    p.revision = 2;
    p.revoked = true;
    c.apply_policy(&p, TTL + 3).unwrap();
    p.revision = 3;
    p.revoked = false;
    c.apply_policy(&p, TTL + 4).unwrap();
    assert_eq!(
        c.challenge("alpha", &key, &"ab".repeat(32), TTL + 5).err(),
        Some(Error::Forbidden)
    );
}
#[test]
fn removal_is_permanent_and_configuration_validation_cannot_grant_key_admin() {
    let mut c = catalog();
    let mut p = policy();
    p.revision = 2;
    p.approvals.clear();
    c.apply_policy(&p, 1).unwrap();
    p = policy();
    p.revision = 3;
    c.apply_policy(&p, 2).unwrap();
    assert_eq!(
        c.challenge("alpha", &p.approvals[0].public_key, &"ff".repeat(32), 3)
            .err(),
        Some(Error::Forbidden)
    );
    p.approvals[0].permissions.insert(Permission::ManageKeys);
    assert_eq!(p.validate(), Err(Error::Invalid));
    for flag in [
        "LOCAL_FIXTURES",
        "API_KEY_HASHES",
        "STAGING_MODE",
        "STAGING_INGRESS",
        "TEST_CONTROL",
        "TEST_RUNTIME_ENABLED",
        "LEDGER",
        "READY",
    ] {
        assert!(forbidden_binding(flag));
    }
    assert!(!forbidden_binding("ALPHA_PROJECT_POLICIES"));
}
#[test]
fn global_challenge_capacity_and_query_purity_are_bounded() {
    let mut p = policy();
    p.approvals = (1..=8)
        .map(|n| Approval {
            public_key: hex::encode(SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes()),
            permissions: [Permission::Read].into_iter().collect(),
            expires_at_ms: 10 * TTL,
        })
        .collect();
    let mut c = Catalog::default();
    c.apply_policy(&p, 0).unwrap();
    for (i, a) in p.approvals.iter().enumerate() {
        for n in 0..8 {
            c.challenge("alpha", &a.public_key, &format!("{:064x}", i * 8 + n), 1)
                .unwrap();
        }
    }
    assert_eq!(
        c.challenge("alpha", &p.approvals[0].public_key, &"ff".repeat(32), 2)
            .err(),
        Some(Error::Limited)
    );
    let before = serde_json::to_value(&c).unwrap();
    assert_eq!(
        c.authorize("alpha", &p.approvals[0].public_key, Permission::Read, 2),
        Err(Error::Forbidden)
    );
    assert_eq!(serde_json::to_value(&c).unwrap(), before);
}
