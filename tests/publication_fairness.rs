//! Bounded ledger publication proofs, not a Cloudflare delivery scheduling guarantee.
use runlater::core::*;
use std::collections::BTreeSet;

fn restart(l: &Ledger) -> Ledger {
    serde_json::from_slice(&serde_json::to_vec(l).unwrap()).unwrap()
}
fn backlog(count: usize) -> Ledger {
    let mut l = Ledger::default();
    for i in 0..count {
        l.create(
            &format!("request_{i}"),
            Create {
                destination: "fixture://success".into(),
                body: String::new(),
                run_at_ms: 0,
                operation_key: format!("operation_{i}"),
            },
            0,
        )
        .unwrap();
    }
    l
}
#[test]
fn unclaimed_head_cannot_starve_later_publications_across_restarts() {
    let mut l = backlog(97);
    let mut seen = BTreeSet::new();
    // Every publish can be uncertain; none of the references is claimed.
    for now in 0..4 {
        let batch = l.outbox("noisy", now);
        assert_eq!(batch.len(), 32);
        seen.extend(batch.into_iter().map(|d| d.id));
        l = restart(&l);
    }
    assert_eq!(seen.len(), 97);
    // The retained head remains replayable, without spending rate or attempts.
    let mut replayed = BTreeSet::new();
    for now in 4..8 {
        replayed.extend(l.outbox("noisy", now).into_iter().map(|d| d.id));
        l = restart(&l);
    }
    assert_eq!(replayed, seen);
    assert!(l.bucket.is_none());
    assert!(l.tasks.values().all(|t| t.attempts.is_empty()));
}
#[test]
fn prolonged_outage_expires_backlog_and_crashed_permits_without_capacity_leak() {
    let mut noisy = backlog(1000);
    let mut quiet = backlog(1);
    let first = noisy.outbox("noisy", 0).remove(0);
    let crashed = noisy.claim(&first, 0).unwrap().unwrap();
    let quiet_ref = quiet.outbox("quiet", 0).remove(0);
    let quiet_task = quiet.claim(&quiet_ref, 0).unwrap().unwrap();
    quiet
        .finish(&quiet_task.id, quiet_task.fence, Outcome::Http(204), 1)
        .unwrap();
    noisy = restart(&noisy);
    // Transport unavailable for longer than the delivery age, with no intervening alarm.
    assert!(noisy.outbox("noisy", DAY + LEASE).is_empty());
    assert!(noisy.tasks.values().all(|t| t.status.terminal()));
    assert_eq!(
        noisy
            .finish(&crashed.id, crashed.fence, Outcome::Http(204), DAY + LEASE)
            .unwrap_err(),
        Fault::Stale
    );
    noisy.purge(RETENTION + DAY + LEASE);
    assert!(noisy.tasks.is_empty());
    let now = RETENTION + DAY + LEASE;
    noisy
        .create(
            "recovered",
            Create {
                destination: "fixture://success".into(),
                body: String::new(),
                run_at_ms: now,
                operation_key: "recovered".into(),
            },
            now,
        )
        .unwrap();
    let d = noisy.outbox("noisy", now).remove(0);
    assert!(noisy.claim(&d, now).unwrap().is_some());
}
#[test]
fn legacy_snapshot_deleted_cursor_and_small_cohort_remain_replayable() {
    let l = backlog(65);
    let mut value = serde_json::to_value(&l).unwrap();
    value.as_object_mut().unwrap().remove("publication_cursor");
    let mut l: Ledger = serde_json::from_value(value).unwrap();
    let first = l.outbox("tenant", 0);
    let last = first.last().unwrap().id.clone();
    l.cancel(&last, 1).unwrap();
    let next = restart(&l).outbox("tenant", 1);
    assert!(next.iter().all(|d| d.id > last));
    for id in l.tasks.clone().keys() {
        if !next.iter().any(|d| &d.id == id) {
            l.cancel(id, 2).unwrap();
        }
    }
    let small = l.outbox("tenant", 2);
    assert_eq!(small.len(), 32);
    assert_eq!(restart(&l).outbox("tenant", 3), small);
    // Old references still refer to the same generations, never to new work.
    assert!(l.claim(&first[0], 3).unwrap().is_none());
}
