use ed25519_dalek::{Signer, SigningKey};
use runlater::{
    auth::Permission,
    core::{Create, Dispatch, Outcome, Status, DAY, LEASE, RETENTION},
    funded_tasks::Error,
    funding::{self, Disposition, GrantSpec, Policy, TASK_UNITS},
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
fn create(
    p: &mut Project,
    g: Option<&Policy>,
    idem: &str,
    at: i64,
    now: i64,
    nonce: u64,
) -> Result<serde_json::Value, Error> {
    let body = serde_json::to_vec(&input(at)).unwrap();
    let e = envelope("/v1/tasks", &body, idem, nonce, now);
    p.task_command(&identity(), g, &e, &sig(&e), &body, now)
}
fn cancel(p: &mut Project, id: &str, now: i64, nonce: u64) -> serde_json::Value {
    let e = envelope(&format!("/v1/tasks/{id}/cancel"), b"{}", "", nonce, now);
    p.task_command(&identity(), None, &e, &sig(&e), b"{}", now)
        .unwrap()
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
#[test]
fn reserve_once_and_replay_after_grant_expiry_and_restart_without_delivery_context() {
    let mut p = state();
    let g = policy(10, 10);
    let accepted = create(&mut p, Some(&g), "same", 200 * DAY, 3, 1).unwrap();
    let id = accepted["result"]["id"].as_str().unwrap();
    assert_eq!(p.funding.grant("grant_a").unwrap().reserved, 5);
    let mut p = Project::decode(serde_json::to_value(&p).unwrap()).unwrap();
    let replay = create(&mut p, None, "same", 200 * DAY, 20, 2).unwrap();
    assert_eq!(replay["result"]["id"], id);
    assert_eq!(replay["created"], false);
    let balance = p.funding.grant("grant_a").unwrap();
    assert_eq!(
        (balance.available, balance.reserved, balance.retired),
        (0, 5, 5)
    );
    assert_eq!(
        p.funding.reservation(id).unwrap().allocated_units,
        TASK_UNITS
    );
}
#[test]
fn final_unit_validation_and_missing_policy_fail_without_partial_task_or_reservation() {
    let mut p = state();
    let before = business(&p);
    assert_eq!(
        create(&mut p, None, "missing", 0, 3, 1).err(),
        Some(Error::AdmissionUnavailable)
    );
    assert_eq!(business(&p), before);
    let g = policy(5, 100);
    create(&mut p, Some(&g), "first", 0, 4, 2).unwrap();
    let before = business(&p);
    assert_eq!(
        create(&mut p, Some(&g), "second", 0, 5, 3).err(),
        Some(Error::Funding(funding::Error::Insufficient))
    );
    assert_eq!(business(&p), before);
    let bad = serde_json::to_vec(&Create {
        destination: "https://unapproved.example".into(),
        ..input(0)
    })
    .unwrap();
    let e = envelope("/v1/tasks", &bad, "invalid", 4, 6);
    assert!(p
        .task_command(&identity(), Some(&g), &e, &sig(&e), &bad, 6)
        .is_err());
    assert_eq!(business(&p), before);
}
#[test]
fn duplicate_claims_and_uncertain_attempts_never_refund_or_double_spend() {
    let mut p = state();
    let g = policy(5, 1000);
    let a = create(&mut p, Some(&g), "task", 0, 3, 1).unwrap();
    let id = a["result"]["id"].as_str().unwrap();
    let d = reference(&p, id);
    let first = p.funded_claim(&d, 4).unwrap().unwrap();
    assert!(p.funded_claim(&d, 5).unwrap().is_none());
    assert_eq!(p.funding.grant("grant_a").unwrap().spent, 1);
    p.funded_finish(id, first.fence, Outcome::Timeout, 6)
        .unwrap();
    assert!(p.funding.reservation(id).unwrap().settlement.is_none());
    assert_eq!(p.funding.grant("grant_a").unwrap().reserved, 4);
    let due = p.ledger.get(id).unwrap().due_ms;
    let next = p.funded_claim(&reference(&p, id), due).unwrap().unwrap();
    assert!(p
        .funded_finish(id, first.fence, Outcome::Http(204), due)
        .is_err());
    assert_eq!(p.funding.grant("grant_a").unwrap().spent, 2);
    assert_eq!(next.attempts.len(), 2);
}
#[test]
fn cancellation_has_one_immutable_return_receipt_and_expired_unused_units_retire() {
    let mut p = state();
    let g = policy(10, 100);
    let a = create(&mut p, Some(&g), "a", 0, 3, 1).unwrap();
    let id = a["result"]["id"].as_str().unwrap();
    cancel(&mut p, id, 4, 2);
    let receipt = p
        .funding
        .reservation(id)
        .unwrap()
        .settlement
        .clone()
        .unwrap();
    assert_eq!(receipt.unused_units, 5);
    assert_eq!(receipt.disposition, Disposition::ReturnedToOpenSourceGrant);
    let balance = p.funding.grant("grant_a").unwrap().available;
    cancel(&mut p, id, 5, 3);
    assert_eq!(p.funding.grant("grant_a").unwrap().available, balance);
    assert_eq!(
        p.funding.reservation(id).unwrap().settlement.as_ref(),
        Some(&receipt)
    );
    let b = create(&mut p, Some(&g), "b", 0, 6, 4).unwrap();
    let bid = b["result"]["id"].as_str().unwrap();
    cancel(&mut p, bid, 101, 5);
    let receipt = p
        .funding
        .reservation(bid)
        .unwrap()
        .settlement
        .as_ref()
        .unwrap();
    assert_eq!(receipt.disposition, Disposition::RetiredUnused);
    assert_eq!(p.funding.grant("grant_a").unwrap().available, 0);
    p.funding.validate().unwrap();
}
#[test]
fn running_cancel_keeps_uncertain_spent_unit_and_releases_only_unstarted_budget() {
    let mut p = state();
    let g = policy(5, 100000);
    let a = create(&mut p, Some(&g), "a", 0, 3, 1).unwrap();
    let id = a["result"]["id"].as_str().unwrap();
    let claimed = p.funded_claim(&reference(&p, id), 4).unwrap().unwrap();
    cancel(&mut p, id, 5, 2);
    assert!(p.funding.reservation(id).unwrap().settlement.is_none());
    p.funded_maintenance(4 + LEASE).unwrap();
    assert_eq!(p.ledger.get(id).unwrap().status, Status::Cancelled);
    let receipt = p
        .funding
        .reservation(id)
        .unwrap()
        .settlement
        .as_ref()
        .unwrap();
    assert_eq!((receipt.spent_units, receipt.unused_units), (1, 4));
    assert!(p
        .funded_finish(id, claimed.fence, Outcome::Http(204), 5 + LEASE)
        .is_err());
    assert_eq!(p.funding.grant("grant_a").unwrap().spent, 1);
}
#[test]
fn accepted_future_task_executes_after_grant_expiry_and_all_retry_costs_stay_reserved() {
    let mut p = state();
    let g = policy(5, 10);
    let a = create(&mut p, Some(&g), "long", 200 * DAY, 3, 1).unwrap();
    let id = a["result"]["id"].as_str().unwrap();
    let mut now = 200 * DAY;
    for _ in 0..5 {
        let t = p.funded_claim(&reference(&p, id), now).unwrap().unwrap();
        p.funded_finish(id, t.fence, Outcome::Timeout, now + 1)
            .unwrap();
        now = p.ledger.get(id).unwrap().due_ms.max(now + 1);
    }
    assert_eq!(p.ledger.get(id).unwrap().status, Status::Failed);
    let g = p.funding.grant("grant_a").unwrap();
    assert_eq!((g.available, g.reserved, g.spent, g.retired), (0, 0, 5, 0));
    assert_eq!(p.funding.reservation(id).unwrap().spent_fences.len(), 5);
}
#[test]
fn redrive_is_new_funded_admission_but_replay_is_not() {
    let mut p = state();
    let g = policy(10, 100);
    let a = create(&mut p, Some(&g), "parent", 0, 3, 1).unwrap();
    let id = a["result"]["id"].as_str().unwrap();
    let t = p.funded_claim(&reference(&p, id), 4).unwrap().unwrap();
    p.funded_finish(id, t.fence, Outcome::Http(400), 5).unwrap();
    let path = format!("/v1/tasks/{id}/redrive");
    let e = envelope(&path, b"{}", "redrive", 2, 6);
    let child = p
        .task_command(&identity(), Some(&g), &e, &sig(&e), b"{}", 6)
        .unwrap();
    assert_ne!(child["result"]["id"], id);
    assert_eq!(child["result"]["input"]["operation_key"], "op_a");
    let reserved = p.funding.grant("grant_a").unwrap().reserved;
    let e = envelope(&path, b"{}", "redrive", 3, 101);
    let replay = p
        .task_command(&identity(), None, &e, &sig(&e), b"{}", 101)
        .unwrap();
    assert_eq!(replay["result"]["id"], child["result"]["id"]);
    assert_eq!(p.funding.grant("grant_a").unwrap().reserved, reserved);
    let other = envelope(&path, b"{}", "other", 4, 102);
    assert!(p
        .task_command(&identity(), Some(&g), &other, &sig(&other), b"{}", 102)
        .is_err());
}
#[test]
fn grant_restart_revision_rollback_and_spec_changes_cannot_replenish() {
    let mut f = funding::State::default();
    let g = policy(5, 100);
    f.apply(&g, 0).unwrap();
    f.reserve("alpha", "task_0000000000000001", 1).unwrap();
    let mut f: funding::State = serde_json::from_value(serde_json::to_value(&f).unwrap()).unwrap();
    f.apply(&g, 2).unwrap();
    assert_eq!(f.grant("grant_a").unwrap().available, 0);
    let mut newer = g.clone();
    newer.revision = 2;
    newer.active_grant.as_mut().unwrap().total_attempt_units = 10;
    assert_eq!(f.apply(&newer, 3), Err(funding::Error::Conflict));
    newer.active_grant = Some(GrantSpec {
        grant_id: "grant_b".into(),
        total_attempt_units: 5,
        admission_expires_at_ms: 100,
    });
    f.apply(&newer, 3).unwrap();
    assert_eq!(f.apply(&g, 4), Err(funding::Error::Conflict));
    f.advance(100).unwrap();
    assert_eq!(f.advance(99), Err(funding::Error::ClockRegressed));
    assert_eq!(f.grant("grant_a").unwrap().reserved, 5);
    f.validate().unwrap();
}
#[test]
fn terminal_retention_and_unknown_snapshot_cannot_discard_active_funding() {
    let mut p = state();
    let g = policy(5, 100);
    let a = create(&mut p, Some(&g), "a", 200 * DAY, 3, 1).unwrap();
    let id = a["result"]["id"].as_str().unwrap();
    p.funded_maintenance(RETENTION).unwrap();
    assert!(p.ledger.get(id).is_ok());
    assert_eq!(p.funding.reservation(id).unwrap().allocated_units, 5);
    let mut value = serde_json::to_value(&p).unwrap();
    value.as_object_mut().unwrap().remove("funding");
    assert!(Project::decode(value).is_err());
}
#[test]
fn sticky_revocation_preserves_accepted_budget_and_never_reopens() {
    let mut p = state();
    let g = policy(10, 100000);
    let a = create(&mut p, Some(&g), "a", 0, 3, 1).unwrap();
    let id = a["result"]["id"].as_str().unwrap();
    let mut revoked = g.clone();
    revoked.revision = 2;
    revoked.revoked_grants = vec!["grant_a".into()];
    p.funding.apply(&revoked, 4).unwrap();
    assert_eq!(p.funding.grant("grant_a").unwrap().retired, 5);
    let t = p.funded_claim(&reference(&p, id), 5).unwrap().unwrap();
    p.funded_finish(id, t.fence, Outcome::Http(204), 6).unwrap();
    assert_eq!(p.funding.grant("grant_a").unwrap().spent, 1);
    assert_eq!(p.funding.grant("grant_a").unwrap().retired, 9);
    let mut restored = g.clone();
    restored.revision = 3;
    let mut p = Project::decode(serde_json::to_value(&p).unwrap()).unwrap();
    p.funding.apply(&restored, 7).unwrap();
    assert_eq!(
        create(&mut p, Some(&restored), "b", 0, 8, 2),
        Err(Error::Funding(funding::Error::Expired))
    );
    p.funding.validate().unwrap();
}
#[test]
fn task_retention_purge_does_not_reset_grant_history() {
    let mut p = state();
    let g = policy(5, 100);
    let a = create(&mut p, Some(&g), "a", 0, 3, 1).unwrap();
    let id = a["result"]["id"].as_str().unwrap();
    cancel(&mut p, id, 4, 2);
    p.funded_maintenance(4 + RETENTION).unwrap();
    assert!(p.ledger.get(id).is_err());
    assert!(p.funding.reservation(id).is_err());
    let mut p = Project::decode(serde_json::to_value(&p).unwrap()).unwrap();
    let mut later = g.clone();
    later.revision = 2;
    p.funding.apply(&later, 5 + RETENTION).unwrap();
    let grant = p.funding.grant("grant_a").unwrap();
    assert!(grant.closed);
    assert_eq!((grant.available, grant.retired), (0, 5));
    assert_eq!(
        p.funding
            .reserve("alpha", "task_0000000000009999", 6 + RETENTION),
        Err(funding::Error::Expired)
    );
}
#[test]
fn authority_is_checked_before_funded_replay_without_business_changes() {
    let mut p = state();
    let g = policy(5, 100);
    create(&mut p, Some(&g), "a", 0, 3, 1).unwrap();
    let before = business(&p);
    let mut revoked = identity();
    revoked.revision = 2;
    revoked.revoked_keys = vec![revoked.approvals[0].public_key.clone()];
    let body = serde_json::to_vec(&input(0)).unwrap();
    let e = envelope("/v1/tasks", &body, "a", 2, 4);
    assert!(matches!(
        p.task_command(&revoked, None, &e, &sig(&e), &body, 4),
        Err(Error::Auth(_))
    ));
    assert_eq!(business(&p), before);
}
