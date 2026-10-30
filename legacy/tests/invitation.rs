use ed25519_dalek::{Signer, SigningKey};
use runlater::{auth::Permission, invitation::*, security::digest};
use serde::{de::DeserializeOwned, Serialize};
fn restart<T: Serialize + DeserializeOwned>(s: &T) -> T {
    serde_json::from_slice(&serde_json::to_vec(s).unwrap()).unwrap()
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
} // Public fixture only.
fn pk(n: u8) -> String {
    hex::encode(key(n).verifying_key().to_bytes())
}
fn policy() -> Policy {
    Policy {
        revision: 1,
        terms: Some(Terms {
            attempt_units: 20,
            identity_ms: 86_400_000,
            permissions: [
                Permission::Enqueue,
                Permission::Read,
                Permission::Cancel,
                Permission::Redrive,
            ]
            .into_iter()
            .collect(),
        }),
        max_projects: 2,
        max_tickets: 4,
        requests_per_minute: 8,
    }
}
fn ticket() -> Ticket {
    let mut r = Registry::default();
    r.apply(&policy(), 0).unwrap();
    r.issue(&digest(b"private-fixture-invitation"), TTL, 1)
        .unwrap()
}
fn proof(c: &Challenge, n: u8) -> String {
    hex::encode(key(n).sign(&c.bytes().unwrap()).to_bytes())
}
#[test]
fn unset_policy_and_static_mode_are_closed() {
    let mut r = Registry::default();
    assert_eq!(r.issue(&digest(b"x"), 100, 0), Err(Error::Closed));
    let mut p = policy();
    p.terms = None;
    r.apply(&p, 0).unwrap();
    assert_eq!(r.issue(&digest(b"x"), 100, 0), Err(Error::Closed));
    let mut e = Enrollment::new(Mode::OperatorStatic);
    assert_eq!(
        e.challenge(&ticket(), &pk(7), &"a".repeat(64), 2).err(),
        Some(Error::Closed)
    );
}
#[test]
fn registry_reserves_once_globally_and_never_frees_on_expiry_restart_or_policy_revision() {
    let mut r = Registry::default();
    r.apply(&policy(), 0).unwrap();
    let id = digest(b"one");
    let a = r.issue(&id, 100, 1).unwrap();
    assert_eq!(restart(&r).issue(&id, 100, 50).unwrap(), a);
    assert_eq!(r.issue(&id, 101, 50), Err(Error::Conflict));
    r.issue(&digest(b"two"), 100, 50).unwrap();
    assert_eq!(r.issue(&digest(b"three"), 100, 50), Err(Error::Limited));
    let mut r: Registry = restart(&r);
    let mut p = policy();
    p.revision = 2;
    r.apply(&p, 101).unwrap();
    assert_eq!(r.issue(&digest(b"three"), 200, 101), Err(Error::Limited));
    assert_eq!(r.view()["reserved_projects"], 2);
    assert_eq!(r.apply(&policy(), 102), Err(Error::Conflict));
}
#[test]
fn invalid_references_are_rate_limited_without_project_identity_and_clock_rollback_cannot_reset() {
    let mut r = Registry::default();
    r.apply(&policy(), 0).unwrap();
    for _ in 0..8 {
        assert_eq!(r.resolve("foreign", 1), Err(Error::Forbidden))
    }
    let mut r: Registry = restart(&r);
    assert_eq!(r.resolve("foreign", 2), Err(Error::Limited));
    assert_eq!(r.resolve("foreign", 0), Err(Error::Clock));
    assert_eq!(r.resolve("foreign", 60001), Err(Error::Forbidden));
    assert_eq!(r.view()["reserved_projects"], 0);
}
#[test]
fn possession_commits_ticket_identity_grant_once_and_recovery_does_not_write() {
    let t = ticket();
    let mut e = Enrollment::new(Mode::Invitation);
    let c = e.challenge(&t, &pk(7), &"a".repeat(64), 2).unwrap();
    let id = c.id().unwrap();
    let r = e.complete(&t, &id, &proof(&c, 7), 3).unwrap();
    assert_eq!(r.expires_at_ms, 86_400_003);
    let mut e: Enrollment = restart(&e);
    assert_eq!(e.complete(&t, &id, &proof(&c, 7), 4).unwrap(), r);
    let grant = e.project.funding.grant(&r.grant_id).unwrap();
    assert_eq!((grant.available, grant.reserved, grant.spent), (20, 0, 0));
    let before = serde_json::to_value(&e).unwrap();
    let nonce = "b".repeat(64);
    let wire =
        Enrollment::recovery_bytes(&r.project_id, &pk(7), &nonce, TTL + 1, TTL + 1000).unwrap();
    let sig = hex::encode(key(7).sign(&wire).to_bytes());
    assert_eq!(
        e.recover(&pk(7), &nonce, TTL + 1, TTL + 1000, &sig, TTL + 2)
            .unwrap(),
        r
    );
    assert_eq!(serde_json::to_value(&e).unwrap(), before);
    assert!(e
        .project
        .catalog
        .authorize(&t.project_id, &pk(7), Permission::Read, 5)
        .is_ok());
}
#[test]
fn proof_binds_ticket_project_key_scope_and_grant_without_client_chosen_authority() {
    let t = ticket();
    let mut e = Enrollment::new(Mode::Invitation);
    let c = e.challenge(&t, &pk(7), &"a".repeat(64), 2).unwrap();
    for kind in 0..5 {
        let mut alt = c.clone();
        match kind {
            0 => alt.ticket.project_id = "other".into(),
            1 => alt.ticket.terms.attempt_units += 1,
            2 => alt
                .ticket
                .terms
                .permissions
                .insert(Permission::Configure)
                .then_some(())
                .unwrap(),
            3 => alt.public_key = pk(8),
            _ => alt.origin = "https://evil.example".into(),
        };
        let mut clone: Enrollment = restart(&e);
        assert_eq!(
            clone.complete(&t, &c.id().unwrap(), &proof(&alt, 7), 3),
            Err(Error::Forbidden)
        );
        assert_eq!(clone.view()["enrolled"], false);
    }
    assert_eq!(
        e.complete(&t, &c.id().unwrap(), &proof(&c, 8), 3),
        Err(Error::Forbidden)
    );
    assert!(e.complete(&t, &c.id().unwrap(), &proof(&c, 7), 4).is_ok());
}
#[test]
fn one_ticket_cannot_enroll_second_key_and_failed_proofs_lockout_persists() {
    let t = ticket();
    let mut e = Enrollment::new(Mode::Invitation);
    let a = e.challenge(&t, &pk(7), &"a".repeat(64), 2).unwrap();
    let b = e.challenge(&t, &pk(8), &"b".repeat(64), 2).unwrap();
    e.complete(&t, &a.id().unwrap(), &proof(&a, 7), 3).unwrap();
    assert_eq!(
        e.complete(&t, &b.id().unwrap(), &proof(&b, 8), 3),
        Err(Error::Conflict)
    );
    assert_eq!(e.project.funding.grant(&t.grant_id).unwrap().available, 20);
    let mut e = Enrollment::new(Mode::Invitation);
    let a = e.challenge(&t, &pk(7), &"c".repeat(64), 2).unwrap();
    for _ in 0..3 {
        assert_eq!(
            e.complete(&t, &a.id().unwrap(), "invalid", 3),
            Err(Error::Forbidden)
        );
    }
    let mut e: Enrollment = restart(&e);
    assert_eq!(
        e.complete(&t, &a.id().unwrap(), &proof(&a, 7), 4),
        Err(Error::Conflict)
    );
}
#[test]
fn grant_apply_failure_cannot_partially_consume_or_enroll_and_revocation_is_sticky() {
    let t = ticket();
    let mut e = Enrollment::new(Mode::Invitation);
    let c = e.challenge(&t, &pk(7), &"a".repeat(64), 2).unwrap();
    e.project
        .funding
        .apply(
            &runlater::funding::Policy {
                version: 1,
                project_id: t.project_id.clone(),
                revision: 2,
                active_grant: None,
                revoked_grants: vec![],
            },
            2,
        )
        .unwrap();
    assert_eq!(
        e.complete(&t, &c.id().unwrap(), &proof(&c, 7), 3),
        Err(Error::Conflict)
    );
    assert_eq!(e.view()["enrolled"], false);
    assert!(e
        .project
        .catalog
        .authorize(&t.project_id, &pk(7), Permission::Read, 3)
        .is_err());
    let mut revoked = t.clone();
    revoked.revoked = true;
    assert_eq!(
        e.challenge(&revoked, &pk(7), &"b".repeat(64), 4).err(),
        Some(Error::Forbidden)
    );
    let mut e: Enrollment = restart(&e);
    assert_eq!(
        e.complete(&t, &c.id().unwrap(), &proof(&c, 7), 5),
        Err(Error::Forbidden)
    );
}
#[test]
fn challenge_capacity_expiry_and_immutable_ticket_are_bounded() {
    let t = ticket();
    let mut e = Enrollment::new(Mode::Invitation);
    for n in 0..8 {
        e.challenge(&t, &pk(7), &format!("{n:064x}"), 2).unwrap();
    }
    assert_eq!(
        e.challenge(&t, &pk(7), &"f".repeat(64), 3).err(),
        Some(Error::Limited)
    );
    let mut alt = t.clone();
    alt.terms.identity_ms += 1;
    assert_eq!(
        e.challenge(&alt, &pk(7), &"f".repeat(64), 3).err(),
        Some(Error::Conflict)
    );
    assert_eq!(
        e.challenge(&t, &pk(7), &"f".repeat(64), t.expires_at_ms)
            .err(),
        Some(Error::Expired)
    );
}
#[test]
fn revocation_retires_only_unused_units_and_replay_never_refills_reserved_work() {
    let t = ticket();
    let mut e = Enrollment::new(Mode::Invitation);
    let c = e.challenge(&t, &pk(7), &"a".repeat(64), 2).unwrap();
    let r = e.complete(&t, &c.id().unwrap(), &proof(&c, 7), 3).unwrap();
    let (task, _) = e
        .project
        .ledger
        .create(
            "accepted",
            runlater::core::Create {
                destination: "fixture://success".into(),
                body: "fixture".into(),
                operation_key: "op".into(),
                run_at_ms: 0,
            },
            4,
        )
        .unwrap();
    e.project
        .funding
        .reserve(&t.project_id, &task.id, 4)
        .unwrap();
    assert_eq!(e.project.funding.grant(&r.grant_id).unwrap().available, 15);
    assert_eq!(
        e.complete(&t, &c.id().unwrap(), &proof(&c, 7), 5).unwrap(),
        r
    );
    assert_eq!(e.project.funding.grant(&r.grant_id).unwrap().available, 15);
    let mut revoked = t.clone();
    revoked.revoked = true;
    e.revoke(&revoked, 6).unwrap();
    let g = e.project.funding.grant(&r.grant_id).unwrap();
    assert_eq!((g.available, g.reserved, g.retired), (0, 5, 15));
    let mut e: Enrollment = restart(&e);
    e.revoke(&revoked, 7).unwrap();
    let g = e.project.funding.grant(&r.grant_id).unwrap();
    assert_eq!((g.available, g.reserved, g.retired), (0, 5, 15));
    assert!(e
        .project
        .catalog
        .authorize(&t.project_id, &pk(7), Permission::Read, 7)
        .is_err());
    e.project.funding.validate().unwrap();
}
#[test]
fn closed_new_admission_keeps_known_project_recovery_routing_and_receipts_require_read_scope() {
    let mut reg = Registry::default();
    reg.apply(&policy(), 0).unwrap();
    let t = reg.issue(&digest(b"fixture"), 100, 1).unwrap();
    let mut p = policy();
    p.revision = 2;
    p.terms = None;
    reg.apply(&p, 2).unwrap();
    assert_eq!(reg.resolve(&t.id, 3), Err(Error::Closed));
    assert!(reg.route_existing(&t.project_id, 101).is_ok());
    assert_eq!(reg.route_existing("foreign", 101), Err(Error::Forbidden));
    let mut only = ticket();
    only.terms.permissions = [Permission::Enqueue].into_iter().collect();
    let mut e = Enrollment::new(Mode::Invitation);
    let c = e.challenge(&only, &pk(7), &"b".repeat(64), 2).unwrap();
    let r = e
        .complete(&only, &c.id().unwrap(), &proof(&c, 7), 3)
        .unwrap();
    let nonce = "c".repeat(64);
    let wire = Enrollment::recovery_bytes(&r.project_id, &pk(7), &nonce, 4, 60004).unwrap();
    assert_eq!(
        e.recover(
            &pk(7),
            &nonce,
            4,
            60004,
            &hex::encode(key(7).sign(&wire).to_bytes()),
            5
        ),
        Err(Error::Forbidden)
    );
}

fn signed_task(
    t: &Ticket,
    path: &str,
    body: &[u8],
    method: &str,
    nonce: &str,
) -> (runlater::signed::Envelope, String) {
    let e = runlater::signed::Envelope {
        version: 1,
        origin: runlater::identity::ORIGIN.into(),
        project_id: t.project_id.clone(),
        public_key: pk(7),
        method: method.into(),
        path: path.into(),
        query: String::new(),
        body_sha256: digest(body),
        idempotency_key: if method == "GET" || path.ends_with("/cancel") {
            String::new()
        } else {
            "task-once".into()
        },
        issued_at_ms: 10,
        expires_at_ms: 60000,
        nonce: nonce.repeat(64),
    };
    let signature = hex::encode(key(7).sign(&e.bytes().unwrap()).to_bytes());
    (e, signature)
}
#[test]
fn invitation_authority_routes_signed_task_atomically_without_static_policy_or_grant_refill() {
    let t = ticket();
    let mut e = Enrollment::new(Mode::Invitation);
    let c = e.challenge(&t, &pk(7), &"a".repeat(64), 2).unwrap();
    e.complete(&t, &c.id().unwrap(), &proof(&c, 7), 3).unwrap();
    let body=br#"{"destination":"registered:fixture","body":"synthetic","operation_key":"signed-invitation"}"#;
    let (request, signature) = signed_task(&t, "/v1/tasks", body, "POST", "b");
    assert_eq!(
        e.signed_task_command(&request, &signature, body, false, 10)
            .unwrap_err(),
        runlater::funded_tasks::Error::AdmissionUnavailable
    );
    assert!(e.project.ledger.tasks.is_empty());
    let result = e
        .signed_task_command(&request, &signature, body, true, 10)
        .unwrap();
    assert_eq!(result["created"], true);
    let id = e.project.ledger.tasks.keys().next().unwrap().clone();
    let balance = e.project.funding.clone();
    let mut e: Enrollment = restart(&e);
    let replay = e
        .signed_task_command(&request, &signature, body, false, 11)
        .unwrap();
    assert_eq!(replay["replayed"], true);
    let after = serde_json::to_value(&e.project.funding).unwrap();
    let before = serde_json::to_value(balance).unwrap();
    assert_eq!(after["grants"], before["grants"]);
    assert_eq!(after["reservations"], before["reservations"]);
    let (read, sig) = signed_task(&t, &format!("/v1/tasks/{id}"), b"", "GET", "c");
    let snapshot = serde_json::to_value(&e).unwrap();
    e.signed_query(&read, &sig, b"", 12).unwrap();
    assert_eq!(serde_json::to_value(&e).unwrap(), snapshot);
    let mut unknown = e.clone();
    unknown.version = 2;
    assert!(unknown.signed_query(&read, &sig, b"", 12).is_err());
    let (cancel, sig) = signed_task(&t, &format!("/v1/tasks/{id}/cancel"), b"{}", "POST", "d");
    e.signed_task_command(&cancel, &sig, b"{}", false, 13)
        .unwrap();
    let mut revoked = t.clone();
    revoked.revoked = true;
    e.revoke(&revoked, 14).unwrap();
    assert!(e.signed_query(&read, &signature, b"", 15).is_err());
}
