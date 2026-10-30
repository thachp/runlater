//! Synthetic offline keys only. Never enroll these fixture identities.
use ed25519_dalek::{Signer, SigningKey};
use runlater::{
    auth::Permission,
    identity,
    invitation::{Enrollment, Mode, Policy, Registry, Terms},
    mcp_delegation::{Certificate, Proof, Trust, MAX_TTL_MS, RESOURCE, REVOKE_PATH},
    security::digest,
    signed::Envelope,
};
use serde_json::{json, Value};
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(n: u8) -> String {
    hex::encode(key(n).verifying_key().to_bytes())
}
fn sign(n: u8, bytes: &[u8]) -> String {
    hex::encode(key(n).sign(bytes).to_bytes())
}
fn fixture() -> (Enrollment, String) {
    let mut registry = Registry::default();
    registry
        .apply(
            &Policy {
                revision: 1,
                terms: Some(Terms {
                    attempt_units: 100,
                    identity_ms: 86_400_000,
                    permissions: [
                        Permission::Enqueue,
                        Permission::Read,
                        Permission::Cancel,
                        Permission::Redrive,
                        Permission::ManageDestinations,
                    ]
                    .into_iter()
                    .collect(),
                }),
                max_projects: 2,
                max_tickets: 4,
                requests_per_minute: 64,
            },
            0,
        )
        .unwrap();
    let ticket = registry
        .issue(&digest(b"offline-delegation-only"), 300_000, 1)
        .unwrap();
    let mut state = Enrollment::new(Mode::Invitation);
    let c = state
        .challenge(&ticket, &public(7), &"ab".repeat(32), 2)
        .unwrap();
    state
        .complete(&ticket, &c.id().unwrap(), &sign(7, &c.bytes().unwrap()), 3)
        .unwrap();
    (state, ticket.project_id)
}
fn certificate(project: &str, scopes: &[&str]) -> Certificate {
    let mut c = Certificate {
        version: 1,
        audience: identity::ORIGIN.into(),
        resource: RESOURCE.into(),
        release_id: "offline".into(),
        project_id: project.into(),
        owner_public_key: public(7),
        gateway_public_key: public(8),
        delegation_id: "ab".repeat(32),
        permissions: scopes.iter().map(|s| s.to_string()).collect(),
        issued_at_ms: 10,
        expires_at_ms: 3_600_010,
        signature: String::new(),
    };
    c.signature = sign(7, &c.bytes().unwrap());
    c
}
fn envelope(project: &str, method: &str, path: &str, body: &[u8], now: i64, n: u8) -> Envelope {
    Envelope {
        version: 1,
        origin: identity::ORIGIN.into(),
        project_id: project.into(),
        public_key: public(7),
        method: method.into(),
        path: path.into(),
        query: String::new(),
        body_sha256: digest(body),
        idempotency_key: if method == "POST" && !path.ends_with("/cancel") {
            format!("request_{n}")
        } else {
            String::new()
        },
        issued_at_ms: now,
        expires_at_ms: now + 60000,
        nonce: format!("{n:064x}"),
    }
}
fn proof<'a>(c: &'a Certificate, sig: &'a str, gateway: &'a str) -> Proof<'a> {
    Proof::Delegated {
        signature: sig,
        certificate: c,
        trust: Trust {
            gateway_public_key: gateway,
            release_id: "offline",
        },
    }
}
fn create() -> Vec<u8> {
    serde_json::to_vec(&json!({"destination":"registered:owned","body":"synthetic","operation_key":"stable","run_at_ms":0})).unwrap()
}
#[test]
fn public_js_vector_is_exactly_compatible() {
    let v: Value = serde_json::from_str(include_str!("../mcp/delegation-vector.json")).unwrap();
    let c: Certificate = serde_json::from_value(v["delegation"].clone()).unwrap();
    let e: Envelope = serde_json::from_value(v["envelope"].clone()).unwrap();
    assert_eq!(
        String::from_utf8(c.bytes().unwrap()).unwrap(),
        v["delegation_utf8"]
    );
    assert_eq!(
        String::from_utf8(e.bytes().unwrap()).unwrap(),
        v["envelope_utf8"]
    );
    assert_eq!(
        serde_json::to_value(
            Certificate::from_header(v["delegation_header"].as_str().unwrap()).unwrap()
        )
        .unwrap(),
        v["delegation"]
    );
    c.verify(
        &e,
        v["gateway_signature"].as_str().unwrap(),
        Trust {
            gateway_public_key: &c.gateway_public_key,
            release_id: &c.release_id,
        },
        v["receipt"]["expires_at_ms"].as_i64().unwrap(),
        None,
        v["now"].as_i64().unwrap(),
    )
    .unwrap();
    for h in [
        String::new(),
        format!("{}=", v["delegation_header"].as_str().unwrap()),
        "A".into(),
        "+///".into(),
        "A".repeat(4097),
    ] {
        assert!(Certificate::from_header(&h).is_err());
    }
}
#[test]
fn delegated_create_read_cancel_replay_and_scope_attenuation() {
    let (mut s, p) = fixture();
    let c = certificate(&p, &["cancel", "enqueue", "read"]);
    let gateway = public(8);
    let body = create();
    let e = envelope(&p, "POST", "/v1/tasks", &body, 20, 1);
    let sig = sign(8, &e.bytes().unwrap());
    let created = s
        .signed_task_command_with_proof(&e, proof(&c, &sig, &gateway), &body, true, 20)
        .unwrap();
    assert_eq!(created["created"], true);
    let id = created["result"]["id"].as_str().unwrap();
    assert_eq!(
        s.signed_task_command_with_proof(&e, proof(&c, &sig, &gateway), &body, true, 21)
            .unwrap()["replayed"],
        true
    );
    let read = envelope(&p, "GET", &format!("/v1/tasks/{id}"), b"", 22, 2);
    let rs = sign(8, &read.bytes().unwrap());
    assert_eq!(
        s.signed_query_with_proof(&read, proof(&c, &rs, &gateway), b"", 22)
            .unwrap()["result"]["id"],
        id
    );
    let cancel = envelope(&p, "POST", &format!("/v1/tasks/{id}/cancel"), b"{}", 23, 3);
    let cs = sign(8, &cancel.bytes().unwrap());
    assert_eq!(
        s.signed_task_command_with_proof(&cancel, proof(&c, &cs, &gateway), b"{}", false, 23)
            .unwrap()["result"]["status"],
        "cancelled"
    );
    let narrow = certificate(&p, &["enqueue"]);
    let e2 = envelope(&p, "POST", "/v1/tasks", &body, 24, 4);
    let sig2 = sign(8, &e2.bytes().unwrap());
    let value = s
        .signed_task_command_with_proof(&e2, proof(&narrow, &sig2, &gateway), &body, true, 24)
        .unwrap();
    assert!(value["funding"].is_null());
    assert!(value["result"].get("input").is_none());
    assert!(value["result"].get("attempts").is_none());
    assert!(s
        .signed_query_with_proof(&read, proof(&narrow, &rs, &gateway), b"", 24)
        .is_err());
    assert!(
        s.signed_task_command(&e2, &sig2, &body, true, 24).is_err(),
        "no delegation -> gateway signature rejected"
    );
}
#[test]
fn certificates_cannot_expand_authority_or_cross_contexts() {
    let (mut s, p) = fixture();
    let base = certificate(&p, &["cancel", "enqueue", "read"]);
    let gateway = public(8);
    let body = create();
    let e = envelope(&p, "POST", "/v1/tasks", &body, 20, 1);
    let sig = sign(8, &e.bytes().unwrap());
    for n in 0..14 {
        let mut c = base.clone();
        match n {
            0 => c.audience = "https://other.test".into(),
            1 => c.resource = "https://other.test".into(),
            2 => c.release_id = "other".into(),
            3 => c.project_id = "other".into(),
            4 => c.owner_public_key = public(9),
            5 => c.gateway_public_key = public(9),
            6 => c.permissions = vec!["redrive".into()],
            7 => c.permissions = vec!["read".into()],
            8 => c.permissions = vec!["read".into(), "enqueue".into()],
            9 => c.permissions = vec!["enqueue".into(), "enqueue".into()],
            10 => c.expires_at_ms = c.issued_at_ms + MAX_TTL_MS + 1,
            11 => c.issued_at_ms = 21,
            12 => c.expires_at_ms = 20,
            _ => c.delegation_id = "zz".repeat(32),
        };
        c.signature = sign(7, &c.bytes().unwrap());
        assert!(
            s.signed_task_command_with_proof(&e, proof(&c, &sig, &gateway), &body, true, 20)
                .is_err(),
            "case {n}"
        );
    }
    assert!(s
        .signed_task_command_with_proof(&e, proof(&base, &sig, &public(9)), &body, true, 20)
        .is_err());
    let mut changed = e.clone();
    changed.body_sha256 = digest(b"changed");
    assert!(s
        .signed_task_command_with_proof(&changed, proof(&base, &sig, &gateway), &body, true, 20)
        .is_err());
    for path in [
        "/v1/tasks/task_0000000000000001/redrive",
        "/v1/destinations/create",
        "/v1/callback-key",
        REVOKE_PATH,
    ] {
        let x = envelope(&p, "POST", path, b"{}", 20, 2);
        let xs = sign(8, &x.bytes().unwrap());
        assert!(base
            .verify(
                &x,
                &xs,
                Trust {
                    gateway_public_key: &gateway,
                    release_id: "offline"
                },
                86_400_003,
                None,
                20
            )
            .is_err());
    }
    assert!(base
        .verify(
            &e,
            &sig,
            Trust {
                gateway_public_key: &gateway,
                release_id: "offline"
            },
            30,
            None,
            20
        )
        .is_err());
}
#[test]
fn registry_revoke_is_complete_owner_auth_durable_idempotent_and_cannot_spend_on_stale_cert() {
    use runlater::public_beta::{Profile, State, DURATION};
    let profile = Profile {
        release_id: "offline".into(),
        opens_at_ms: 0,
        closes_at_ms: DURATION,
        callback_end_sec: (2 * DURATION + runlater::core::DAY) / 1000 + 301,
        self_host: "runlater-public-api.operator.workers.dev".into(),
    };
    let mut s = State::new(&profile).unwrap();
    let challenge = s.challenge(&public(7), &"ab".repeat(32), 1).unwrap();
    let (grant, _) = s
        .complete(
            &challenge.id().unwrap(),
            &sign(7, &challenge.bytes().unwrap()),
            2,
        )
        .unwrap();
    let p = grant.ticket.project_id;
    let raw = serde_json::to_value(&s).unwrap();
    assert!(raw.get("mcp_revocations").is_none());
    let e = envelope(&p, "POST", REVOKE_PATH, b"{}", 30, 1);
    for case in 0..10 {
        let mut invalid = e.clone();
        match case {
            0 => invalid.method = "GET".into(),
            1 => invalid.path = "/v1/tasks".into(),
            2 => invalid.query = "x=1".into(),
            3 => invalid.body_sha256 = digest(b"changed"),
            4 => invalid.idempotency_key = String::new(),
            5 => invalid.nonce = "x".into(),
            6 => invalid.issued_at_ms = 31,
            7 => invalid.expires_at_ms = 30,
            8 => invalid.expires_at_ms = invalid.issued_at_ms + 60_001,
            _ => invalid.public_key = public(9),
        };
        assert!(
            s.revoke_mcp_delegations(&invalid, &sign(7, &invalid.bytes().unwrap()), 30)
                .is_err(),
            "case {case}"
        );
        assert_eq!(serde_json::to_value(&s).unwrap(), raw);
    }
    assert!(s
        .revoke_mcp_delegations(&e, &sign(8, &e.bytes().unwrap()), 30)
        .is_err());
    // Near-capacity persisted fixture: a single erroneously charged stale request would block the owner.
    let mut near = serde_json::to_value(&s).unwrap();
    near["client_operations"][&p] = json!(998);
    s = serde_json::from_value(near).unwrap();
    s.check().unwrap();
    let c = certificate(&p, &["enqueue"]);
    let gateway = public(8);
    let result = s
        .revoke_mcp_delegations(&e, &sign(7, &e.bytes().unwrap()), 30)
        .unwrap();
    assert_eq!(result["revoked_before_ms"], 30);
    s = serde_json::from_value(serde_json::to_value(&s).unwrap()).unwrap();
    let mut replay = e.clone();
    replay.issued_at_ms = 40;
    replay.expires_at_ms = 60040;
    replay.nonce = "bc".repeat(32);
    let before = serde_json::to_value(&s).unwrap();
    let result = s
        .revoke_mcp_delegations(&replay, &sign(7, &replay.bytes().unwrap()), 40)
        .unwrap();
    assert_eq!(result, json!({"revoked_before_ms":30,"replayed":true}));
    assert_eq!(serde_json::to_value(&s).unwrap(), before);
    let body = create();
    let task = envelope(&p, "POST", "/v1/tasks", &body, 41, 2);
    let sig = sign(8, &task.bytes().unwrap());
    for _ in 0..10 {
        assert!(s
            .client_with_proof(&task, proof(&c, &sig, &gateway), 41)
            .is_err());
        assert_eq!(serde_json::to_value(&s).unwrap(), before);
    }
    s.client(&task, &sign(7, &task.bytes().unwrap()), 41)
        .unwrap();
    assert_eq!(
        serde_json::to_value(&s).unwrap()["client_operations"][&p],
        1000
    );
    // Even an old receipt replay must authenticate a currently active owner and unrevoked project.
    let mut expired = replay.clone();
    expired.issued_at_ms = grant.expires_at_ms;
    expired.expires_at_ms = grant.expires_at_ms + 60000;
    assert!(s
        .revoke_mcp_delegations(
            &expired,
            &sign(7, &expired.bytes().unwrap()),
            grant.expires_at_ms
        )
        .is_err());
    s.revoke(&[p.clone()], 42).unwrap();
    assert!(s
        .revoke_mcp_delegations(&replay, &sign(7, &replay.bytes().unwrap()), 42)
        .is_err());
}
#[test]
fn registry_rechecks_real_grant_release_key_and_revocation_before_routing() {
    use runlater::public_beta::{Profile, State, DURATION};
    let profile = Profile {
        release_id: "offline".into(),
        opens_at_ms: 0,
        closes_at_ms: DURATION,
        callback_end_sec: (2 * DURATION + runlater::core::DAY) / 1000 + 301,
        self_host: "runlater-public-api.operator.workers.dev".into(),
    };
    let mut state = State::new(&profile).unwrap();
    let c = state.challenge(&public(7), &"ab".repeat(32), 1).unwrap();
    let (g, _) = state
        .complete(&c.id().unwrap(), &sign(7, &c.bytes().unwrap()), 2)
        .unwrap();
    let cert = certificate(&g.ticket.project_id, &["enqueue"]);
    let body = create();
    let e = envelope(&g.ticket.project_id, "POST", "/v1/tasks", &body, 20, 1);
    let sig = sign(8, &e.bytes().unwrap());
    let gateway = public(8);
    assert!(state.client(&e, &sig, 20).is_err());
    assert_eq!(
        state
            .client_with_proof(&e, proof(&cert, &sig, &gateway), 20)
            .unwrap()
            .project_id,
        g.ticket.project_id
    );
    let mut swapped = e.clone();
    swapped.project_id = "p_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
    let signature = sign(8, &swapped.bytes().unwrap());
    assert!(state
        .client_with_proof(&swapped, proof(&cert, &signature, &gateway), 21)
        .is_err());
    state.revoke(&[g.ticket.project_id], 22).unwrap();
    assert!(state
        .client_with_proof(&e, proof(&cert, &sig, &gateway), 23)
        .is_err());
}
#[test]
fn introspection_is_read_only_enrollment_bound_and_scope_complete() {
    let (s, p) = fixture();
    let c = certificate(&p, &["enqueue"]);
    let gateway = public(8);
    let mut e = envelope(
        &p,
        "POST",
        runlater::mcp_delegation::VALIDATE_PATH,
        b"{}",
        20,
        1,
    );
    e.idempotency_key.clear();
    let signature = sign(8, &e.bytes().unwrap());
    let trust = Trust {
        gateway_public_key: &gateway,
        release_id: "offline",
    };
    let before = serde_json::to_value(&s).unwrap();
    assert_eq!(
        s.validate_mcp_delegation(&e, &signature, &c, trust, 20)
            .unwrap(),
        json!({"active":true,"project_id":p,"expires_at_ms":c.expires_at_ms,"permissions":["enqueue"]})
    );
    assert_eq!(serde_json::to_value(&s).unwrap(), before);
    assert!(Enrollment::new(Mode::Invitation)
        .validate_mcp_delegation(&e, &signature, &c, trust, 20)
        .is_err());
    let mut bad = e.clone();
    bad.idempotency_key = "forbidden".into();
    assert!(s
        .validate_mcp_delegation(&bad, &sign(8, &bad.bytes().unwrap()), &c, trust, 20)
        .is_err());
    assert!(s
        .validate_mcp_delegation(&e, &sign(9, &e.bytes().unwrap()), &c, trust, 20)
        .is_err());
}
