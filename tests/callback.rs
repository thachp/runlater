use runlater::callback::*;
fn ring() -> Keyring {
    Keyring::new(
        "alpha",
        "default",
        "fixture_a",
        1000,
        10000,
        &FixtureMaterial,
    )
    .unwrap()
}
fn snapshot() -> Snapshot {
    Snapshot::new(
        "alpha",
        "default",
        "task_0000000000000001",
        "invoice_42",
        b"exact bytes",
    )
    .unwrap()
}
fn rotated() -> Keyring {
    let mut r = ring();
    r.rotate("fixture_b", 2000, 9000, 1500, &FixtureMaterial)
        .unwrap();
    r
}
#[test]
fn selects_at_dispatch_and_pins_protocol_identity_across_retry_redrive() {
    let r = rotated();
    let s = snapshot();
    let a = r.sign(&s, b"exact bytes", 1999, &FixtureMaterial).unwrap();
    let b = r.sign(&s, b"exact bytes", 2000, &FixtureMaterial).unwrap();
    assert_eq!(a.key_id, "fixture_a");
    assert_eq!(b.key_id, "fixture_b");
    assert_eq!(a.operation_key, b.operation_key);
    assert_eq!(a.task_id, b.task_id);
    assert_eq!(a.version, b.version);
    let redrive = s.redrive("task_0000000000000002").unwrap();
    let c = r
        .sign(&redrive, b"exact bytes", 2001, &FixtureMaterial)
        .unwrap();
    assert_eq!(c.key_id, "fixture_b");
    assert_ne!(c.task_id, a.task_id);
    assert_eq!(c.operation_key, a.operation_key);
    assert_eq!(c.policy_id, a.policy_id);
    assert_eq!(
        r.sign(&s, b"mutated bytes", 2000, &FixtureMaterial)
            .unwrap_err(),
        Fault::InvalidSnapshot
    );
    assert!(s.redrive("task_0000000000000001").is_err());
}
#[test]
fn overlap_timestamp_and_expiry_boundaries_are_separate() {
    let r = rotated();
    let a = r
        .sign(&snapshot(), b"exact bytes", 1999, &FixtureMaterial)
        .unwrap();
    assert!(r.verify(&a, b"exact bytes", 2299, &FixtureMaterial).is_ok());
    assert_eq!(
        r.verify(&a, b"exact bytes", 2300, &FixtureMaterial),
        Err(Fault::InvalidSignature)
    );
    let b = r
        .sign(&snapshot(), b"exact bytes", 2000, &FixtureMaterial)
        .unwrap();
    assert!(r
        .verify(&b, b"exact bytes", 1999, &FixtureMaterial)
        .is_err());
    assert!(r
        .sign(&snapshot(), b"exact bytes", 999, &FixtureMaterial)
        .is_err());
    assert!(r
        .sign(&snapshot(), b"exact bytes", 9000, &FixtureMaterial)
        .is_err());
    let last = r
        .sign(&snapshot(), b"exact bytes", 8999, &FixtureMaterial)
        .unwrap();
    assert!(r
        .verify(&last, b"exact bytes", 9299, &FixtureMaterial)
        .is_ok());
    assert!(r
        .verify(&last, b"exact bytes", 9300, &FixtureMaterial)
        .is_err());
}
#[test]
fn immediate_rotation_in_same_second_is_valid_without_overlapping_issuers() {
    let mut r = ring();
    r.rotate("fixture_b", 1000, 9000, 1000, &FixtureMaterial)
        .unwrap();
    assert_eq!(r.issuer(1000).unwrap().key_id, "fixture_b");
}
#[test]
fn revocation_is_irreversible_after_restart_clock_rollback_and_rotation_replay() {
    let mut r = rotated();
    let packet = r
        .sign(&snapshot(), b"exact bytes", 1999, &FixtureMaterial)
        .unwrap();
    r.revoke("fixture_a", 2001).unwrap();
    assert!(r
        .verify(&packet, b"exact bytes", 1999, &FixtureMaterial)
        .is_err());
    r.revoke("fixture_b", 2002).unwrap();
    let mut r: Keyring = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(r.issuer(2002).unwrap_err(), Fault::NoSigner);
    let before = serde_json::to_value(&r).unwrap();
    assert!(r
        .rotate("fixture_b", 2000, 9000, 2003, &FixtureMaterial)
        .unwrap()
        .revoked_at_sec
        .is_some());
    assert_eq!(serde_json::to_value(&r).unwrap(), before);
    assert_eq!(
        r.rotate("fixture_b", 2000, 9100, 2003, &FixtureMaterial)
            .unwrap_err(),
        Fault::Conflict
    );
    r.rotate("fixture_c", 2003, 9500, 2003, &FixtureMaterial)
        .unwrap();
    assert_eq!(r.issuer(2003).unwrap().key_id, "fixture_c");
    assert!(r
        .rotate("fixture_a", 2004, 9600, 2003, &FixtureMaterial)
        .is_err());
}
struct Empty;
impl Material for Empty {
    fn key(&self, _: &str) -> Option<&[u8]> {
        None
    }
}
#[test]
fn failed_rotation_is_atomic_and_missing_material_has_no_fallback() {
    let mut r = ring();
    let before = serde_json::to_value(&r).unwrap();
    assert_eq!(
        r.rotate("fixture_b", 2000, 9000, 1500, &Empty).unwrap_err(),
        Fault::MissingMaterial
    );
    assert_eq!(serde_json::to_value(&r).unwrap(), before);
    assert_eq!(
        r.sign(&snapshot(), b"exact bytes", 1500, &Empty)
            .unwrap_err(),
        Fault::MissingMaterial
    );
    assert!(r
        .rotate("fixture_b", 11000, 12000, 1500, &FixtureMaterial)
        .is_err());
    assert_eq!(serde_json::to_value(&r).unwrap(), before);
    r.rotate("fixture_b", 2000, 9000, 1500, &FixtureMaterial)
        .unwrap();
    let before = serde_json::to_value(&r).unwrap();
    assert!(r
        .rotate("fixture_c", 1900, 8000, 1600, &FixtureMaterial)
        .is_err());
    assert_eq!(serde_json::to_value(&r).unwrap(), before);
}
struct SameBytes;
impl Material for SameBytes {
    fn key(&self, _: &str) -> Option<&[u8]> {
        Some(b"public-fixture-identical-alias-material-000")
    }
}
#[test]
fn canonical_mac_binds_key_id_tenant_policy_operation_version_and_body() {
    let r = Keyring::new("alpha", "default", "fixture_a", 1000, 10000, &SameBytes).unwrap();
    let signed = r
        .sign(&snapshot(), b"exact bytes", 1500, &SameBytes)
        .unwrap();
    let alias = Keyring::new("alpha", "default", "fixture_b", 1000, 10000, &SameBytes).unwrap();
    let mut p = signed.clone();
    p.key_id = "fixture_b".into();
    assert!(alias.verify(&p, b"exact bytes", 1500, &SameBytes).is_err());
    let other = Keyring::new("alpha", "other", "fixture_a", 1000, 10000, &SameBytes).unwrap();
    let mut p = signed.clone();
    p.policy_id = "other".into();
    assert!(other.verify(&p, b"exact bytes", 1500, &SameBytes).is_err());
    let tenant = Keyring::new("beta", "default", "fixture_a", 1000, 10000, &SameBytes).unwrap();
    let mut p = signed.clone();
    p.task_id = "beta:task_0000000000000001".into();
    assert!(tenant.verify(&p, b"exact bytes", 1500, &SameBytes).is_err());
    let mut p = signed.clone();
    p.operation_key = "other".into();
    assert!(r.verify(&p, b"exact bytes", 1500, &SameBytes).is_err());
    let mut p = signed.clone();
    p.version = "v1".into();
    assert!(r.verify(&p, b"exact bytes", 1500, &SameBytes).is_err());
    assert!(r.verify(&signed, b"changed", 1500, &SameBytes).is_err());
}
#[test]
fn metadata_and_debug_views_do_not_disclose_material_signature_or_operation() {
    let r = rotated();
    let state = serde_json::to_string(&r).unwrap();
    for id in ["fixture_a", "fixture_b"] {
        assert!(!state.contains(std::str::from_utf8(FixtureMaterial.key(id).unwrap()).unwrap()));
    }
    let s = snapshot();
    let signed = r.sign(&s, b"exact bytes", 2000, &FixtureMaterial).unwrap();
    let debug = format!("{s:?} {signed:?}");
    for hidden in [&signed.signature, &signed.operation_key, "exact bytes"] {
        assert!(!debug.contains(hidden));
    }
}
#[test]
fn malformed_metadata_and_snapshot_fail_closed() {
    let mut state = serde_json::to_value(rotated()).unwrap();
    state["keys"]["fixture_b"]["introduced_revision"] = serde_json::json!(1);
    let r: Keyring = serde_json::from_value(state).unwrap();
    assert_eq!(r.issuer(2000).unwrap_err(), Fault::InvalidPolicy);
    let mut state = serde_json::to_value(snapshot()).unwrap();
    state["version"] = serde_json::json!("v1");
    let s: Snapshot = serde_json::from_value(state).unwrap();
    assert!(s.redrive("task_0000000000000002").is_err());
    assert!(Snapshot::new(
        "alpha",
        "default",
        "task_0000000000000001",
        "op",
        &vec![0; 16385]
    )
    .is_err());
    assert_eq!(
        ring()
            .sign(&s, b"exact bytes", 1500, &FixtureMaterial)
            .unwrap_err(),
        Fault::InvalidSnapshot
    );
}

#[test]
fn wire_header_parser_rejects_duplicates_noncanonical_timestamp_and_downgrade() {
    let r = ring();
    let e = r
        .sign(&snapshot(), b"exact bytes", 1500, &FixtureMaterial)
        .unwrap();
    let headers: Vec<_> = e.headers().into_iter().collect();
    assert!(r
        .verify(
            &Envelope::from_headers(&headers).unwrap(),
            b"exact bytes",
            1500,
            &FixtureMaterial
        )
        .is_ok());
    let mut h = headers.clone();
    h.push(("runlater-key-id".into(), "fixture_a".into()));
    assert!(Envelope::from_headers(&h).is_err());
    let mut duplicate = headers.clone();
    duplicate.push(("RunLater-Key-Id".into(), "fixture_a".into()));
    assert!(Envelope::from_headers(&duplicate).is_err());
    for ts in ["01500", "+1500", "1500 "] {
        let mut h = headers.clone();
        h.iter_mut()
            .find(|(k, _)| k == "RunLater-Timestamp")
            .unwrap()
            .1 = ts.into();
        assert!(Envelope::from_headers(&h).is_err());
    }
    let mut h = headers;
    h.retain(|(k, _)| k != "RunLater-Signature-Version");
    assert!(Envelope::from_headers(&h).is_err());
}
#[test]
fn retained_key_ids_and_revocations_are_bounded_without_recycling() {
    let mut r = Keyring::new("alpha", "default", "key_0", 1000, 10000, &SameBytes).unwrap();
    for i in 1..MAX_KEYS {
        r.rotate(
            &format!("key_{i}"),
            1000 + i as i64,
            10000,
            1000 + i as i64,
            &SameBytes,
        )
        .unwrap();
    }
    let before = serde_json::to_value(&r).unwrap();
    assert_eq!(
        r.rotate("overflow", 1020, 10000, 1020, &SameBytes)
            .unwrap_err(),
        Fault::Capacity
    );
    assert_eq!(serde_json::to_value(&r).unwrap(), before);
    for i in 0..MAX_KEYS {
        r.revoke(&format!("key_{i}"), 1020).unwrap();
    }
    r.validate().unwrap();
    assert_eq!(r.issuer(1020).unwrap_err(), Fault::NoSigner);
    assert_eq!(
        r.rotate("key_0", 1020, 10000, 1020, &SameBytes)
            .unwrap_err(),
        Fault::Conflict
    );
}
