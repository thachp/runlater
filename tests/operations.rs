use runlater::{
    application::{self, Command, Query},
    core::*,
    operations::{self, FailureCategory},
};
fn input(at: i64) -> Create {
    Create {
        destination: "fixture://success".into(),
        body: "DO_NOT_DISCLOSE_PAYLOAD".into(),
        operation_key: "DO_NOT_DISCLOSE_OPERATION".into(),
        run_at_ms: at,
    }
}
fn restart(l: &Ledger) -> Ledger {
    serde_json::from_str(&serde_json::to_string(l).unwrap()).unwrap()
}
#[test]
fn health_is_pure_even_for_overdue_work_expired_leases_and_bucket() {
    let mut l = Ledger::default();
    let (a, _) = l.create("private-key", input(0), 0).unwrap();
    let d = l.outbox("alpha", 0).remove(0);
    l.claim(&d, 0).unwrap();
    l.create("due", input(100), 0).unwrap();
    l.create("future", input(100000), 0).unwrap();
    let before = serde_json::to_value(&l).unwrap();
    let h = application::query(
        &l,
        Query::Health {
            sampled_at_ms: LEASE,
        },
    )
    .unwrap();
    assert_eq!(h["counts_by_state"]["running"], 1);
    assert_eq!(h["counts_by_state"]["scheduled"], 2);
    assert_eq!(h["eligible_backlog"], 1);
    assert_eq!(h["expired_leases"], 1);
    assert_eq!(h["active_leases"], 0);
    assert_eq!(h["oldest_eligible_due_ms"], 100);
    assert_eq!(h["oldest_eligible_age_ms"], LEASE - 100);
    assert_eq!(serde_json::to_value(&l).unwrap(), before);
    let inspect = application::query(&l, Query::Inspection { id: a.id }).unwrap();
    let audit = application::query(&l, Query::Audit).unwrap();
    for v in [h, inspect, audit] {
        let text = v.to_string();
        for secret in [
            "DO_NOT_DISCLOSE_PAYLOAD",
            "DO_NOT_DISCLOSE_OPERATION",
            "private-key",
            "fixture://success",
        ] {
            assert!(!text.contains(secret));
        }
    }
}
#[test]
fn failure_categories_and_journal_are_safe_and_replay_does_not_duplicate_events() {
    let mut l = Ledger::default();
    l.create("k", input(0), 0).unwrap();
    let n = l.audit.len();
    l.create("k", input(0), 1).unwrap();
    assert_eq!(l.audit.len(), n);
    let d = l.outbox("alpha", 0).remove(0);
    let t = l.claim(&d, 0).unwrap().unwrap();
    l.finish(&t.id, t.fence, Outcome::Http(503), 1).unwrap();
    let h = operations::health(&l, 2);
    assert_eq!(h["attempt_failures_by_category"]["retryable_http"], 1);
    assert_eq!(operations::failure("http_204"), None);
    assert_eq!(
        operations::failure("http_408"),
        Some(FailureCategory::Timeout)
    );
    assert_eq!(
        operations::failure("lease_expired_unknown"),
        Some(FailureCategory::LeaseExpiredUnknown)
    );
    assert_eq!(
        operations::failure("http_401"),
        Some(FailureCategory::PermanentHttp)
    );
    let due = l.get(&t.id).unwrap().due_ms;
    assert_eq!(operations::health(&l, due)["due_retry_backlog"], 1);
    l.reconcile(due);
    assert_eq!(operations::health(&l, due)["due_retry_backlog"], 1);
    let snapshot = restart(&l);
    assert_eq!(
        serde_json::to_value(&l.audit).unwrap(),
        serde_json::to_value(&snapshot.audit).unwrap()
    );
    assert_eq!(l.get(&t.id).unwrap().status, Status::Ready);
}
#[test]
fn retention_boundary_retains_active_payload_and_dedup_then_releases_terminal_together() {
    let mut l = Ledger::default();
    let (active, _) = l.create("active-key", input(365 * DAY), 0).unwrap();
    let (done, _) = l.create("done-key", input(0), 0).unwrap();
    l.cancel(&done.id, 1).unwrap();
    let before = l.purge(RETENTION);
    assert_eq!(before.tasks_removed, 0);
    let mut l = restart(&l);
    let report = application::command(&mut l, Command::MaintainRetention, RETENTION + 1)
        .unwrap()
        .body;
    assert_eq!(report["tasks_removed"], 1);
    assert_eq!(report["enqueue_keys_removed"], 1);
    assert_eq!(
        l.get(&active.id).unwrap().input.body,
        "DO_NOT_DISCLOSE_PAYLOAD"
    );
    assert!(l.dedupe.contains_key("active-key"));
    assert!(!l.dedupe.contains_key("done-key"));
    let (_, new) = l
        .create("active-key", input(365 * DAY), RETENTION + 2)
        .unwrap();
    assert!(!new);
    assert_eq!(l.purge(RETENTION + 1).tasks_removed, 0);
    assert_eq!(l.next_wake(RETENTION + 2), Some(2 * RETENTION + 1));
}
#[test]
fn redrive_mapping_follows_child_and_survives_source_retention() {
    let mut l = Ledger::default();
    let (source, _) = l.create("source", input(0), 0).unwrap();
    let d = l.outbox("alpha", 0).remove(0);
    let claim = l.claim(&d, 0).unwrap().unwrap();
    l.finish(&source.id, claim.fence, Outcome::Http(400), 1)
        .unwrap();
    let (child, _) = l.redrive(&source.id, "redrive-key", 29 * DAY).unwrap();
    let mut l = restart(&l);
    l.purge(RETENTION + 1);
    assert!(l.get(&source.id).is_err());
    let (replay, new) = l.redrive(&source.id, "redrive-key", RETENTION + 2).unwrap();
    assert!(!new);
    assert_eq!(replay.id, child.id);
    l.cancel(&child.id, RETENTION + 3).unwrap();
    l.purge(2 * RETENTION + 3);
    assert!(l.redrive_dedupe.is_empty());
}
#[test]
fn journal_is_bounded_and_retention_wake_eventually_clears_without_queries() {
    let mut l = Ledger::default();
    for i in 0..300 {
        l.configure(l.limits.clone(), i).unwrap();
    }
    assert_eq!(l.audit.len(), operations::AUDIT_CAP);
    assert_eq!(l.audit[0].sequence, 45);
    assert_eq!(l.next_wake(300), Some(44 + RETENTION));
    let mut l = restart(&l);
    l.purge(RETENTION + 300);
    assert!(l.audit.is_empty());
    assert_eq!(l.next_wake(RETENTION + 300), None);
}
#[test]
fn new_routes_are_scoped_and_snapshot_counts_are_tenant_local() {
    use runlater::auth::{required_permission, Permission};
    for path in [
        "/v1/queue/health",
        "/v1/queue/audit",
        "/v1/tasks/task_0000000000000001/inspection",
    ] {
        assert_eq!(required_permission("GET", path), Some(Permission::Read));
    }
    assert_eq!(
        required_permission("POST", "/v1/queue/maintenance"),
        Some(Permission::Configure)
    );
    let alpha = Ledger::default();
    let mut beta = Ledger::default();
    beta.create("beta", input(0), 0).unwrap();
    assert_eq!(operations::health(&alpha, 0)["retained_tasks"], 0);
    assert_eq!(operations::health(&beta, 0)["retained_tasks"], 1);
}
