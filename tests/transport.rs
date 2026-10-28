use runlater::{
    application::{self, Command},
    core::*,
    transport::*,
};
fn input(at: i64) -> Create {
    Create {
        destination: "fixture://success".into(),
        body: "private-body".into(),
        operation_key: "private-operation".into(),
        run_at_ms: at,
    }
}
fn reference(t: &Task) -> Reference {
    Reference {
        task_id: t.id.clone(),
        generation: t.generation,
    }
}
fn observe(l: &mut Ledger, t: &Task, now: i64) -> String {
    l.report_transport("alpha", reference(t), now).unwrap().0["record_id"]
        .as_str()
        .unwrap()
        .into()
}
#[test]
fn duplicate_capture_is_pure_and_restart_receipt_is_idempotent() {
    let mut l = Ledger::default();
    let (t, _) = l.create("key", input(0), 0).unwrap();
    let id = observe(&mut l, &t, 0);
    let before = serde_json::to_value(&l).unwrap();
    assert!(l.report_transport("alpha", reference(&t), 1).unwrap().2);
    assert_eq!(serde_json::to_value(&l).unwrap(), before);
    assert_eq!(
        l.transport_record(&id, DAY + 1).unwrap()["current_classification"],
        "age_exhausted"
    );
    assert_eq!(serde_json::to_value(&l).unwrap(), before);
    let (v, replay) = l.reconcile_transport("alpha", &id, "operator", 1).unwrap();
    assert!(!replay);
    assert_eq!(v["reconciliation"]["action"], "outbox_confirmed");
    assert_eq!(l.tasks.len(), 1);
    assert_eq!(l.get(&t.id).unwrap().attempts.len(), 0);
    let mut l: Ledger = serde_json::from_value(serde_json::to_value(&l).unwrap()).unwrap();
    let before = serde_json::to_value(&l).unwrap();
    assert!(
        l.reconcile_transport("alpha", &id, "operator", 2)
            .unwrap()
            .1
    );
    assert_eq!(serde_json::to_value(&l).unwrap(), before);
    let text = v.to_string();
    for secret in [
        "private-body",
        "private-operation",
        "fixture://success",
        "\"operator\"",
    ] {
        assert!(!text.contains(secret));
    }
}
#[test]
fn foreign_malformed_stale_and_terminal_never_replay() {
    let mut l = Ledger::default();
    let (t, _) = l.create("key", input(0), 0).unwrap();
    let id = observe(&mut l, &t, 0);
    let before = serde_json::to_value(&l).unwrap();
    let d = Dispatch {
        tenant: "beta".into(),
        id: t.id.clone(),
        generation: t.generation,
    };
    assert_eq!(
        l.receive_dead_letter("alpha", &d, 1).err(),
        Some(Fault::Forbidden)
    );
    assert_eq!(
        l.reconcile_transport("beta", &id, "operator", 1).err(),
        Some(Fault::Forbidden)
    );
    assert!(l
        .report_transport(
            "alpha",
            Reference {
                task_id: "bad".into(),
                generation: 0
            },
            1
        )
        .is_err());
    assert_eq!(serde_json::to_value(&l).unwrap(), before);
    let stale = Reference {
        generation: t.generation + 1,
        ..reference(&t)
    };
    let id = l.report_transport("alpha", stale, 1).unwrap().0["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        l.reconcile_transport("alpha", &id, "operator", 1)
            .unwrap()
            .0["reconciliation"]["action"],
        "no_recovery"
    );
    for status in [Status::Cancelled, Status::Succeeded, Status::Failed] {
        let mut l = Ledger::default();
        let (t, _) = l.create("key", input(0), 0).unwrap();
        l.tasks.get_mut(&t.id).unwrap().status = status.clone();
        let id = observe(&mut l, &t, 0);
        assert_eq!(
            l.reconcile_transport("alpha", &id, "operator", 1)
                .unwrap()
                .0["reconciliation"]["action"],
            "no_recovery"
        );
        assert_eq!(l.get(&t.id).unwrap().status, status);
    }
}
#[test]
fn preserves_schedule_live_lease_and_stale_result_fencing() {
    let mut l = Ledger::default();
    let (t, _) = l.create("future", input(5000), 0).unwrap();
    let id = observe(&mut l, &t, 0);
    assert_eq!(
        l.reconcile_transport("alpha", &id, "operator", 1)
            .unwrap()
            .0["reconciliation"]["action"],
        "schedule_preserved"
    );
    assert_eq!(l.get(&t.id).unwrap().due_ms, 5000);
    let d = l.outbox("alpha", 5000).remove(0);
    let claimed = l.claim(&d, 5000).unwrap().unwrap();
    let (v, _, _) = l.receive_dead_letter("alpha", &d, 5001).unwrap();
    assert_eq!(v["current_classification"], "in_flight");
    assert_eq!(l.get(&t.id).unwrap().fence, claimed.fence);
    l.reconcile(5000 + LEASE);
    assert_eq!(
        l.finish(&t.id, claimed.fence, Outcome::Http(204), 5000 + LEASE)
            .err(),
        Some(Fault::Stale)
    );
}
#[test]
fn recovery_expires_own_budgets_without_new_attempt() {
    let mut l = Ledger::default();
    let (t, _) = l.create("old", input(0), 0).unwrap();
    let id = observe(&mut l, &t, DAY + 1);
    let v = l
        .reconcile_transport("alpha", &id, "operator", DAY + 1)
        .unwrap()
        .0;
    assert_eq!(v["reconciliation"]["action"], "budget_expired");
    assert_eq!(l.get(&t.id).unwrap().status, Status::Failed);
    assert!(l.get(&t.id).unwrap().attempts.is_empty());
    let mut l = Ledger::default();
    let (t, _) = l.create("attempts", input(0), 0).unwrap();
    let mut now = 0;
    for _ in 0..MAX_ATTEMPTS {
        let d = l.outbox("alpha", now).remove(0);
        let c = l.claim(&d, now).unwrap().unwrap();
        l.finish(&t.id, c.fence, Outcome::Http(503), now).unwrap();
        now = l.get(&t.id).unwrap().due_ms;
    }
    // Defensive recovery from an inconsistent ready snapshot must never grant a sixth attempt.
    l.tasks.get_mut(&t.id).unwrap().status = Status::Ready;
    let current = l.get(&t.id).unwrap();
    let id = observe(&mut l, &current, now);
    assert_eq!(
        l.reconcile_transport("alpha", &id, "operator", now)
            .unwrap()
            .0["reconciliation"]["action"],
        "budget_expired"
    );
    assert_eq!(l.get(&t.id).unwrap().attempts.len(), MAX_ATTEMPTS as usize);
}
#[test]
fn bounded_diagnostics_retention_preserves_active_dedup() {
    let mut l = Ledger::default();
    let (t, _) = l.create("long", input(200 * DAY), 0).unwrap();
    let id = observe(&mut l, &t, 0);
    for i in 2..=130 {
        l.report_transport(
            "alpha",
            Reference {
                task_id: format!("task_{i:016x}"),
                generation: 1,
            },
            i as i64,
        )
        .unwrap();
    }
    assert!(l.transport_record(&id, 0).is_err());
    let list = l.transport_records("", 0).unwrap();
    assert_eq!(list["evicted_records"], 2);
    assert_eq!(list["records"].as_array().unwrap().len(), 50);
    let report = l.purge(RETENTION + 131);
    assert_eq!(report.transport_records_removed, 128);
    assert_eq!(
        l.create("long", input(200 * DAY), RETENTION + 131)
            .unwrap()
            .0
            .id,
        t.id
    );
}
#[test]
fn scopes_and_queue_roles_are_fail_closed() {
    use runlater::auth::{required_permission, Permission};
    assert_eq!(
        required_permission("POST", "/v1/queue/dead-letters"),
        Some(Permission::Configure)
    );
    assert_eq!(
        required_permission("GET", "/v1/queue/dead-letters/dlq_example"),
        Some(Permission::Read)
    );
    assert_eq!(queue_role("ready", "ready", ""), Some(QueueRole::Ready));
    assert_eq!(
        queue_role("dead", "ready", "dead"),
        Some(QueueRole::DeadLetter)
    );
    for (name, ready, dead) in [
        ("other", "ready", "dead"),
        ("ready", "ready", "ready"),
        ("dead", "", "dead"),
    ] {
        assert_eq!(queue_role(name, ready, dead), None);
    }
    let mut l = Ledger::default();
    let (t, _) = l.create("key", input(0), 0).unwrap();
    let result = application::command_in_tenant(
        &mut l,
        Command::ReportTransport {
            reference: reference(&t),
        },
        0,
        "alpha",
        "operator",
    )
    .unwrap();
    let view = result.scoped_body(false);
    assert!(view["dead_letter"].get("reference").is_none());
    assert!(view["dead_letter"]["record_id"].is_string());
}
#[test]
fn transport_provenance_merges_without_moving_deadline_or_repeating_audit() {
    let mut l = Ledger::default();
    let (t, _) = l.create("key", input(200 * DAY), 0).unwrap();
    let id = observe(&mut l, &t, 0);
    let d = Dispatch {
        tenant: "alpha".into(),
        id: t.id.clone(),
        generation: t.generation,
    };
    let (v, created, replayed) = l.receive_dead_letter("alpha", &d, 100).unwrap();
    assert!(!created && !replayed);
    assert_eq!(v["observed_at_ms"], 0);
    assert_eq!(v["operator_reported"], true);
    assert_eq!(v["transport_observed"], true);
    let before = serde_json::to_value(&l).unwrap();
    assert!(l.receive_dead_letter("alpha", &d, 101).unwrap().2);
    assert_eq!(serde_json::to_value(&l).unwrap(), before);
    assert_eq!(l.next_wake(102), Some(RETENTION));
    assert_eq!(l.purge(RETENTION - 1).transport_records_removed, 0);
    assert_eq!(l.purge(RETENTION).transport_records_removed, 1);
    assert!(l.transport_record(&id, RETENTION).is_err());
    assert_eq!(l.tasks.len(), 1);
    assert_eq!(
        l.create("key", input(200 * DAY), RETENTION).unwrap().0.id,
        t.id
    );
}
#[test]
fn exhausted_claim_guard_never_spends_a_sixth_attempt() {
    let mut l = Ledger::default();
    let (t, _) = l.create("key", input(0), 0).unwrap();
    let mut now = 0;
    for _ in 0..MAX_ATTEMPTS {
        let d = l.outbox("alpha", now).remove(0);
        let c = l.claim(&d, now).unwrap().unwrap();
        l.finish(&t.id, c.fence, Outcome::Http(503), now).unwrap();
        now = l.get(&t.id).unwrap().due_ms;
    }
    let task = l.tasks.get_mut(&t.id).unwrap();
    task.status = Status::Ready;
    let d = Dispatch {
        tenant: "alpha".into(),
        id: t.id.clone(),
        generation: task.generation,
    };
    assert!(l.claim(&d, now).unwrap().is_none());
    let terminal = l.get(&t.id).unwrap();
    assert_eq!(terminal.status, Status::Failed);
    assert_eq!(terminal.attempts.len(), MAX_ATTEMPTS as usize);
}
