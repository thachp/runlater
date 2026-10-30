use runlater::{
    application::{self, Command, Query},
    core::*,
    limits::QueueLimits,
};
fn input(at: i64) -> Create {
    Create {
        destination: "fixture://success".into(),
        body: "private_body".into(),
        operation_key: "private_operation".into(),
        run_at_ms: at,
    }
}
fn pause(l: &mut Ledger, paused: bool, now: i64) {
    let mut limits = l.limits.clone();
    limits.paused = paused;
    application::command(l, Command::ConfigureQueue { limits }, now).unwrap();
}
fn reference(t: &Task) -> Dispatch {
    Dispatch {
        tenant: "alpha".into(),
        id: t.id.clone(),
        generation: t.generation,
    }
}
fn restart(l: &Ledger) -> Ledger {
    serde_json::from_value(serde_json::to_value(l).unwrap()).unwrap()
}
#[test]
fn pause_wins_before_claim_and_old_references_spend_nothing() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    let d = l.outbox("alpha", 0).remove(0);
    pause(&mut l, true, 1);
    let bucket = serde_json::to_value(&l.bucket).unwrap();
    assert!(l.claim(&d, 2).unwrap().is_none());
    assert_eq!(serde_json::to_value(&l.bucket).unwrap(), bucket);
    assert!(l.outbox("alpha", 2).is_empty());
    assert!(l.get(&t.id).unwrap().attempts.is_empty());
    assert_eq!(l.metrics.view(2)["totals"]["counts"]["claim_paused"], 1);
    let mut l = restart(&l);
    assert!(l.limits.paused);
    pause(&mut l, false, 3);
    let claimed = l.claim(&d, 3).unwrap().unwrap();
    assert_eq!(claimed.id, t.id);
    assert_eq!(claimed.generation, t.generation);
    assert_eq!(claimed.attempts.len(), 1);
}
#[test]
fn claim_wins_before_pause_and_fenced_result_can_finish() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    let d = l.outbox("alpha", 0).remove(0);
    let claimed = l.claim(&d, 0).unwrap().unwrap();
    let bucket = serde_json::to_value(&l.bucket).unwrap();
    pause(&mut l, true, 1);
    assert_eq!(serde_json::to_value(&l.bucket).unwrap(), bucket);
    assert_eq!(l.get(&t.id).unwrap().fence, claimed.fence);
    assert_eq!(l.next_wake(1), Some(LEASE));
    assert!(l.claim(&d, 1).unwrap().is_none());
    l.finish(&t.id, claimed.fence, Outcome::Http(204), 2)
        .unwrap();
    pause(&mut l, false, 3);
    assert!(l.outbox("alpha", 3).is_empty());
    assert_eq!(l.get(&t.id).unwrap().status, Status::Succeeded);
}
#[test]
fn due_retry_is_quiet_then_resumes_same_attempt_budget() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    let d = l.outbox("alpha", 0).remove(0);
    let c = l.claim(&d, 0).unwrap().unwrap();
    pause(&mut l, true, 1);
    l.finish(&t.id, c.fence, Outcome::Http(503), 2).unwrap();
    let retry = l.get(&t.id).unwrap();
    assert_eq!(retry.status, Status::RetryWait);
    assert_eq!(l.next_wake(3), Some(DAY + 1));
    assert!(l.outbox("alpha", retry.due_ms).is_empty());
    assert!(l.claim(&reference(&retry), retry.due_ms).unwrap().is_none());
    assert!(l.claim(&d, retry.due_ms).unwrap().is_none());
    pause(&mut l, false, retry.due_ms);
    let refs = l.outbox("alpha", retry.due_ms);
    assert_eq!(refs[0], reference(&retry));
    let next = l.claim(&refs[0], retry.due_ms).unwrap().unwrap();
    assert_eq!(next.attempts.len(), 2);
    assert!(next.fence > c.fence);
}
#[test]
fn pause_expires_age_at_boundary_without_silent_extension_or_callback() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    pause(&mut l, true, 0);
    assert_eq!(l.next_wake(0), Some(DAY + 1));
    l.reconcile(DAY);
    assert!(!l.get(&t.id).unwrap().status.terminal());
    l.reconcile(DAY + 1);
    let terminal = l.get(&t.id).unwrap();
    assert_eq!(terminal.status, Status::Failed);
    assert_eq!(terminal.terminal_ms, Some(DAY + 1));
    assert!(terminal.attempts.is_empty());
    assert_eq!(
        l.metrics.view(DAY + 1)["totals"]["counts"]["paused_age_expired"],
        1
    );
    pause(&mut l, false, DAY + 2);
    assert!(l.outbox("alpha", DAY + 2).is_empty());
    let mut l = Ledger::default();
    let (t, _) = l.create("future", input(200 * DAY), 0).unwrap();
    pause(&mut l, true, 0);
    assert_eq!(l.next_wake(0), Some(RETENTION));
    l.purge(RETENTION);
    assert_eq!(l.next_wake(RETENTION), Some(201 * DAY + 1));
    assert_eq!(l.get(&t.id).unwrap().input.body, "private_body");
}
#[test]
fn expired_leases_cancel_and_retention_remain_live_during_pause() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    let d = l.outbox("alpha", 0).remove(0);
    let c = l.claim(&d, 0).unwrap().unwrap();
    pause(&mut l, true, 1);
    l.reconcile(LEASE);
    let retry = l.get(&t.id).unwrap();
    assert_eq!(retry.status, Status::RetryWait);
    assert_eq!(
        retry.attempts[0].outcome.as_deref(),
        Some("lease_expired_unknown")
    );
    assert_eq!(
        l.finish(&t.id, c.fence, Outcome::Http(204), LEASE).err(),
        Some(Fault::Stale)
    );
    l.cancel(&t.id, LEASE + 1).unwrap();
    pause(&mut l, false, LEASE + 2);
    assert!(l.outbox("alpha", LEASE + 2).is_empty());
    assert_eq!(l.get(&t.id).unwrap().status, Status::Cancelled);
    l.purge(LEASE + 1 + RETENTION);
    assert!(l.get(&t.id).is_err());
}
#[test]
fn same_config_and_pause_toggles_do_not_refund_tokens_or_mutate_queries() {
    let mut l = Ledger::default();
    let mut limits = l.limits.clone();
    limits.dispatch_burst = 1;
    limits.dispatch_per_second = 1;
    l.configure(limits, 0).unwrap();
    let (a, _) = l.create("a", input(0), 0).unwrap();
    let (b, _) = l.create("b", input(0), 0).unwrap();
    let c = l.claim(&reference(&a), 0).unwrap().unwrap();
    l.finish(&a.id, c.fence, Outcome::Http(204), 1).unwrap();
    let bucket = serde_json::to_value(&l.bucket).unwrap();
    let snapshot = serde_json::to_value(&l).unwrap();
    l.configure(l.limits.clone(), 500).unwrap();
    assert_eq!(serde_json::to_value(&l).unwrap(), snapshot);
    pause(&mut l, true, 500);
    pause(&mut l, false, 500);
    assert_eq!(serde_json::to_value(&l.bucket).unwrap(), bucket);
    assert!(matches!(
        l.claim(&reference(&b), 500),
        Err(Fault::Limited {
            reason: LimitReason::DispatchRate,
            ..
        })
    ));
    pause(&mut l, true, 501);
    let before = serde_json::to_value(&l).unwrap();
    assert_eq!(
        application::query(&l, Query::QueueConfig).unwrap()["paused"],
        true
    );
    application::query(
        &l,
        Query::Health {
            sampled_at_ms: DAY + 100,
        },
    )
    .unwrap();
    assert_eq!(serde_json::to_value(&l).unwrap(), before);
}
#[test]
fn legacy_snapshots_default_unpaused_but_no_terminal_task_resurrects() {
    let mut value = serde_json::to_value(QueueLimits::default()).unwrap();
    value.as_object_mut().unwrap().remove("paused");
    assert!(!serde_json::from_value::<QueueLimits>(value).unwrap().paused);
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    pause(&mut l, true, 0);
    pause(&mut l, false, DAY + 1);
    assert_eq!(l.get(&t.id).unwrap().status, Status::Failed);
    assert!(l.outbox("alpha", DAY + 2).is_empty());
}
#[test]
fn transport_reconciliation_cannot_override_pause_or_revive_expired_work() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    pause(&mut l, true, 0);
    let (record, _, _) = l
        .report_transport(
            "alpha",
            runlater::transport::Reference {
                task_id: t.id.clone(),
                generation: t.generation,
            },
            1,
        )
        .unwrap();
    let id = record["record_id"].as_str().unwrap();
    l.reconcile_transport("alpha", id, "operator", 2).unwrap();
    assert!(l.outbox("alpha", 2).is_empty());
    assert!(l.claim(&reference(&t), 2).unwrap().is_none());
    assert!(l.get(&t.id).unwrap().attempts.is_empty());
    pause(&mut l, false, DAY + 1);
    assert_eq!(l.get(&t.id).unwrap().status, Status::Failed);
    pause(&mut l, true, 1);
    pause(&mut l, false, 0);
    assert!(l.outbox("alpha", 3).is_empty());
    assert_eq!(l.get(&t.id).unwrap().status, Status::Failed);
}
