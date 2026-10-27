use runlater::{core::*, security::*};
fn input(at: i64) -> Create {
    Create {
        operation_key: "op_1".into(),
        destination: "fixture://success".into(),
        body: "hello".into(),
        run_at_ms: at,
    }
}
fn claim(l: &mut Ledger, now: i64) -> Task {
    let d = l.outbox("alpha", now).remove(0);
    l.claim(&d, now).unwrap().unwrap()
}
#[test]
fn durable_replay_and_idempotency() {
    let mut l = Ledger::default();
    let (t, c) = l.create("same", input(0), 0).unwrap();
    assert!(c);
    let mut l: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
    assert_eq!(l.create("same", input(0), 1).unwrap().0.id, t.id);
    assert_eq!(l.create("same", input(1), 1).unwrap_err(), Fault::Conflict);
    assert_eq!(l.outbox("alpha", 0), l.outbox("alpha", 0));
}
#[test]
fn duplicate_claim_and_fencing() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    let d = l.outbox("alpha", 0).remove(0);
    let first = l.claim(&d, 0).unwrap().unwrap();
    assert!(l.claim(&d, 1).unwrap().is_none());
    l.reconcile(LEASE);
    assert_eq!(l.get(&t.id).unwrap().status, Status::RetryWait);
    assert_eq!(
        l.finish(&t.id, first.fence, Outcome::Http(204), LEASE)
            .unwrap_err(),
        Fault::Stale
    );
    let due = l.get(&t.id).unwrap().due_ms;
    let second = claim(&mut l, due);
    assert!(second.fence > first.fence);
    assert!(l.claim(&d, due).unwrap().is_none());
    l.finish(&t.id, second.fence, Outcome::Http(200), due + 1)
        .unwrap();
}
#[test]
fn terminal_retention_starts_at_termination() {
    let mut l = Ledger::default();
    let at = 200 * DAY;
    let (t, _) = l.create("long", input(at), 0).unwrap();
    l.purge(100 * DAY);
    assert_eq!(l.create("long", input(at), 100 * DAY).unwrap().0.id, t.id);
    assert!(l.outbox("a", at - 1).is_empty());
    l.cancel(&t.id, at).unwrap();
    l.purge(at + RETENTION - 1);
    assert!(l.get(&t.id).is_ok());
    l.purge(at + RETENTION);
    assert!(l.get(&t.id).is_err());
    assert!(l.dedupe.is_empty());
}
#[test]
fn cancellation_races() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    l.cancel(&t.id, 0).unwrap();
    assert!(l.outbox("a", 0).is_empty());
    let (t, _) = l.create("b", input(0), 0).unwrap();
    let c = claim(&mut l, 0);
    l.cancel(&t.id, 1).unwrap();
    assert_eq!(
        l.finish(&t.id, c.fence, Outcome::Http(204), 2)
            .unwrap()
            .status,
        Status::Succeeded
    );
    let (t, _) = l.create("c", input(0), 0).unwrap();
    let c = claim(&mut l, 0);
    l.cancel(&t.id, 1).unwrap();
    assert_eq!(
        l.finish(&t.id, c.fence, Outcome::Http(503), 2)
            .unwrap()
            .status,
        Status::Cancelled
    );
}
#[test]
fn retry_budget_and_auditable_redrive() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    let mut now = 0;
    for _ in 0..MAX_ATTEMPTS {
        let c = claim(&mut l, now);
        let t = l
            .finish(&c.id, c.fence, Outcome::Http(429), now + 1)
            .unwrap();
        now = t.due_ms;
    }
    let old = l.get(&t.id).unwrap();
    assert_eq!(old.status, Status::Failed);
    assert_eq!(old.attempts.len(), MAX_ATTEMPTS as usize);
    let (n, _) = l.redrive(&t.id, "retry", now).unwrap();
    assert_ne!(n.id, t.id);
    assert_eq!(n.parent, Some(t.id.clone()));
    assert_eq!(l.redrive(&t.id, "retry", now + 1).unwrap().0.id, n.id);
    assert_eq!(l.get(&t.id).unwrap().attempts.len(), MAX_ATTEMPTS as usize);
}
#[test]
fn permits_recover_and_retries_count() {
    let mut l = Ledger::default();
    for i in 0..5 {
        l.create(&i.to_string(), input(0), 0).unwrap();
    }
    let ds = l.outbox("a", 0);
    for d in ds.iter().take(4) {
        assert!(l.claim(d, 0).unwrap().is_some());
    }
    assert_eq!(l.claim(&ds[4], 0).unwrap_err(), Fault::Capacity);
    l.reconcile(LEASE);
    assert!(l.claim(&ds[4], LEASE).unwrap().is_some());
}
#[test]
fn signature_tamper_and_replay() {
    let s = sign(b"fixture-key", 100, "alpha:task_1", "op_1", b"hi");
    assert!(verify(
        b"fixture-key",
        100,
        "alpha:task_1",
        "op_1",
        b"hi",
        &s,
        100
    ));
    assert!(!verify(
        b"fixture-key",
        100,
        "beta:task_1",
        "op_1",
        b"hi",
        &s,
        100
    ));
    assert!(!verify(
        b"fixture-key",
        100,
        "alpha:task_1",
        "op_1",
        b"changed",
        &s,
        100
    ));
    assert!(!verify(
        b"fixture-key",
        100,
        "alpha:task_1",
        "op_1",
        b"hi",
        &s,
        401
    ));
}
#[test]
fn outbound_fail_closed() {
    for url in [
        "http://127.0.0.1",
        "https://[::1]",
        "https://169.254.169.254",
        "https://2130706433",
        "https://example.com",
        "fixture://success.evil",
        "fixture://success/",
    ] {
        assert!(!destination_allowed(url));
    }
    assert!(destination_allowed("fixture://success"));
}
#[test]
fn cqrs_query_is_read_only_and_command_returns_committed_view() {
    use runlater::application::{self, Command, Query};
    let mut l = Ledger::default();
    let accepted = application::command(
        &mut l,
        Command::Enqueue {
            key: "cqrs".into(),
            input: input(0),
        },
        0,
    )
    .unwrap();
    let before = serde_json::to_string(&l).unwrap();
    let id = accepted.body["id"].as_str().unwrap();
    let read = application::query(&l, Query::Task { id: id.into() }).unwrap();
    assert_eq!(read, accepted.body);
    assert_eq!(serde_json::to_string(&l).unwrap(), before);
}
#[test]
fn operation_key_is_immutable_across_redrive() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(0), 0).unwrap();
    let c = claim(&mut l, 0);
    l.finish(&t.id, c.fence, Outcome::Http(400), 1).unwrap();
    let (n, _) = l.redrive(&t.id, "r", 2).unwrap();
    assert_eq!(n.input.operation_key, t.input.operation_key);
    assert_eq!(n.input.body, t.input.body);
}

#[test]
fn immediate_zero_uses_acceptance_time_for_age_budget() {
    let now = 1000 * DAY;
    let mut l = Ledger::default();
    l.create("immediate", input(0), now).unwrap();
    let t = claim(&mut l, now);
    assert_eq!(t.status, Status::Running);
    assert_eq!(
        l.finish(&t.id, t.fence, Outcome::Http(503), now + 1)
            .unwrap()
            .status,
        Status::RetryWait
    );
}

#[test]
fn enqueue_keys_cannot_shadow_redrive_namespace() {
    let mut l = Ledger::default();
    let (old, _) = l.create("original", input(0), 0).unwrap();
    let c = claim(&mut l, 0);
    l.finish(&old.id, c.fence, Outcome::Http(400), 1).unwrap();
    let malicious = format!("redrive:{}:chosen", old.id);
    let (other, _) = l.create(&malicious, input(0), 2).unwrap();
    let (redriven, created) = l.redrive(&old.id, "chosen", 3).unwrap();
    assert!(created);
    assert_ne!(redriven.id, other.id);
    assert_eq!(redriven.parent.as_deref(), Some(old.id.as_str()));
    assert_eq!(l.redrive(&old.id, "chosen", 4).unwrap().0.id, redriven.id);
    assert_eq!(l.create(&malicious, input(0), 4).unwrap().0.id, other.id);
}
#[test]
fn redrive_replay_rejects_corrupt_lineage_or_fingerprint() {
    let mut l = Ledger::default();
    let (old, _) = l.create("original", input(0), 0).unwrap();
    let c = claim(&mut l, 0);
    l.finish(&old.id, c.fence, Outcome::Http(400), 1).unwrap();
    let (new, _) = l.redrive(&old.id, "r", 2).unwrap();
    let mut wrong = l.clone();
    wrong.tasks.get_mut(&new.id).unwrap().parent = None;
    assert_eq!(wrong.redrive(&old.id, "r", 3).unwrap_err(), Fault::Conflict);
    l.redrive_dedupe
        .get_mut(&old.id)
        .unwrap()
        .get_mut("r")
        .unwrap()
        .fingerprint = "corrupt".into();
    assert_eq!(l.redrive(&old.id, "r", 3).unwrap_err(), Fault::Conflict);
}
#[test]
fn active_redrive_replay_survives_source_retention_expiry() {
    let mut l = Ledger::default();
    let (old, _) = l.create("original", input(0), 0).unwrap();
    let c = claim(&mut l, 0);
    l.finish(&old.id, c.fence, Outcome::Http(400), 1).unwrap();
    let (new, _) = l.redrive(&old.id, "late", 29 * DAY).unwrap();
    l.purge(31 * DAY);
    assert_eq!(l.get(&old.id).unwrap_err(), Fault::NotFound);
    let (replayed, created) = l.redrive(&old.id, "late", 31 * DAY).unwrap();
    assert!(!created);
    assert_eq!(replayed.id, new.id);
    assert_eq!(
        l.redrive(&old.id, "fresh", 31 * DAY).unwrap_err(),
        Fault::NotFound
    );
}
#[test]
fn legacy_redrive_migration_preserves_linked_execution_and_ordinary_keys() {
    let mut l = Ledger::default();
    let (old, _) = l.create("original", input(0), 0).unwrap();
    let c = claim(&mut l, 0);
    l.finish(&old.id, c.fence, Outcome::Http(400), 1).unwrap();
    let (new, _) = l.redrive(&old.id, "r", 2).unwrap();
    let legacy = format!("redrive:{}:r", old.id);
    let d = l
        .redrive_dedupe
        .remove(&old.id)
        .unwrap()
        .remove("r")
        .unwrap();
    l.dedupe.insert(legacy.clone(), d);
    let ordinary = "redrive:arbitrary:enqueue";
    let (other, _) = l.create(ordinary, input(0), 2).unwrap();
    l.migrate_legacy_redrive_keys().unwrap();
    assert!(!l.dedupe.contains_key(&legacy));
    assert_eq!(l.redrive(&old.id, "r", 3).unwrap().0.id, new.id);
    assert_eq!(l.create(ordinary, input(0), 3).unwrap().0.id, other.id);
}
