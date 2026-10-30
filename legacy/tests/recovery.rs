//! Deterministic persisted-ledger fault boundaries; these are NOT live Cloudflare crash proofs.
use runlater::core::*;
fn restart(l: &Ledger) -> Ledger {
    serde_json::from_str(&serde_json::to_string(l).unwrap()).unwrap()
}
fn accepted() -> Ledger {
    let mut l = Ledger::default();
    l.create(
        "request",
        Create {
            destination: "fixture://success".into(),
            body: "unchanged".into(),
            run_at_ms: 0,
            operation_key: "business_identity".into(),
        },
        0,
    )
    .unwrap();
    l
}
#[test]
fn crash_after_acceptance_before_queue_send_preserves_outbox() {
    let mut l = restart(&accepted());
    let a = l.outbox("project", 0);
    let mut l = restart(&l);
    assert_eq!(l.outbox("project", 0), a);
    assert_eq!(a.len(), 1);
}
#[test]
fn uncertain_queue_publish_can_replay_without_conflicting_claim() {
    let mut l = accepted();
    let sent = l.outbox("project", 0).remove(0);
    let mut l = restart(&l);
    let resent = l.outbox("project", 1).remove(0);
    assert_eq!(sent, resent);
    let task = l.claim(&sent, 1).unwrap().unwrap();
    let mut l = restart(&l);
    assert!(l.claim(&resent, 2).unwrap().is_none());
    assert_eq!(l.get(&task.id).unwrap().attempts.len(), 1);
}
#[test]
fn callback_success_before_commit_can_duplicate_but_keeps_business_identity() {
    let mut l = accepted();
    let first = l.outbox("project", 0).remove(0);
    let claimed = l.claim(&first, 0).unwrap().unwrap();
    let mut receiver_operations = vec![claimed.input.operation_key]; /* callback succeeded, process crashes before outcome commit */
    let mut l = restart(&l);
    l.reconcile(LEASE);
    let due = l.get(&first.id).unwrap().due_ms;
    let retry = l.outbox("project", due).remove(0);
    let claimed = l.claim(&retry, due).unwrap().unwrap();
    receiver_operations.push(claimed.input.operation_key.clone());
    assert_eq!(
        receiver_operations,
        vec!["business_identity", "business_identity"]
    );
    l.finish(&claimed.id, claimed.fence, Outcome::Http(204), due + 1)
        .unwrap();
    assert_eq!(l.get(&claimed.id).unwrap().attempts.len(), 2);
}
#[test]
fn committed_success_before_queue_ack_never_starts_another_attempt() {
    let mut l = accepted();
    let d = l.outbox("project", 0).remove(0);
    let t = l.claim(&d, 0).unwrap().unwrap();
    l.finish(&t.id, t.fence, Outcome::Http(204), 1).unwrap();
    let mut l = restart(&l);
    assert!(l.claim(&d, 2).unwrap().is_none());
    assert!(l.outbox("project", 2).is_empty());
    assert_eq!(l.get(&t.id).unwrap().attempts.len(), 1);
}
#[test]
fn cancelled_crashed_lease_never_retries() {
    let mut l = accepted();
    let d = l.outbox("project", 0).remove(0);
    l.claim(&d, 0).unwrap();
    l.cancel(&d.id, 1).unwrap();
    let mut l = restart(&l);
    assert!(l.outbox("project", LEASE).is_empty());
    let t = l.get(&d.id).unwrap();
    assert_eq!(t.status, Status::Cancelled);
    assert_eq!(
        t.attempts[0].outcome.as_deref(),
        Some("lease_expired_unknown")
    );
}
