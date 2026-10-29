//! Bounded ledger publication proofs, not a Cloudflare delivery scheduling guarantee.
use runlater::core::*;
use runlater::publication::{publish_batch, BATCH_SIZE};
use std::collections::BTreeSet;
use std::future::{ready, Future};
use std::task::{Context, Poll, Waker};

// These mocked sends complete synchronously; no executor or external I/O.
fn complete<T>(future: impl Future<Output = T>) -> T {
    match std::pin::pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("unexpected pending mocked publication"),
    }
}

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

#[test]
fn selective_send_failures_do_not_hide_batch_tails_and_all_rows_remain_replayable() {
    for count in [1, 2, 32, 33, 64, 97, 1000] {
        let mut l = backlog(count);
        let expected: BTreeSet<_> = l.tasks.keys().cloned().collect();
        // A permanent send error at each original batch head catches both the
        // small stable-order cohort and exactly-divisible rotating cohorts.
        let failing: BTreeSet<_> = expected.iter().step_by(BATCH_SIZE).cloned().collect();
        let mut attempted = BTreeSet::new();
        let mut accepted = BTreeSet::new();
        let passes = count.div_ceil(BATCH_SIZE);
        for now in 0..passes {
            let batch = l.outbox("noisy", now as i64);
            assert!(batch.len() <= BATCH_SIZE);
            let selected = batch.len();
            // Exactly as in the pumps, persist selection before Queue I/O.
            l = restart(&l);
            let mut calls = 0;
            let result = complete(publish_batch(batch, |d| {
                calls += 1;
                attempted.insert(d.id.clone());
                ready(if failing.contains(&d.id) {
                    Err("uncertain send")
                } else {
                    accepted.insert(d.id);
                    Ok(())
                })
            }));
            assert_eq!(calls, selected, "each selected reference gets one attempt");
            assert!(result.is_err());
        }
        assert_eq!(attempted, expected);
        assert_eq!(accepted, expected.difference(&failing).cloned().collect());
        assert!(l.bucket.is_none());
        assert!(l
            .tasks
            .values()
            .all(|t| t.status == Status::Ready && t.attempts.is_empty()));

        // Fault recovery still republishes *all* retained rows, including
        // successful-but-unclaimed references and uncertain failed sends.
        let mut replayed = BTreeSet::new();
        for now in passes..2 * passes {
            let batch = l.outbox("noisy", now as i64);
            l = restart(&l);
            complete(publish_batch(batch, |d| {
                replayed.insert(d.id);
                ready(Ok::<(), &str>(()))
            }))
            .unwrap();
        }
        assert_eq!(replayed, expected);
    }
}

#[test]
fn publication_reports_first_error_after_bounded_single_attempts() {
    let mut attempted = Vec::new();
    assert_eq!(
        complete(publish_batch(vec![1, 2, 3, 4], |id| {
            attempted.push(id);
            ready(match id {
                2 => Err("first uncertainty"),
                3 => Err("later uncertainty"),
                _ => Ok(()),
            })
        })),
        Err("first uncertainty")
    );
    assert_eq!(attempted, vec![1, 2, 3, 4]);
    complete(publish_batch(Vec::<u8>::new(), |_| {
        panic!("empty selections must not send");
        #[allow(unreachable_code)]
        ready(Ok::<(), &str>(()))
    }))
    .unwrap();
}

#[test]
fn pending_publications_stay_sequential_without_immediate_retries() {
    use std::cell::RefCell;
    use std::rc::Rc;

    let events = Rc::new(RefCell::new(Vec::new()));
    let future = publish_batch(vec![1, 2, 3], |id| {
        let events = events.clone();
        events.borrow_mut().push((id, "started"));
        let mut pending = true;
        std::future::poll_fn(move |context| {
            if pending {
                pending = false;
                context.waker().wake_by_ref();
                return Poll::Pending;
            }
            events.borrow_mut().push((id, "finished"));
            Poll::Ready(if id == 1 { Err("uncertain") } else { Ok(()) })
        })
    });
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    for id in 1..=3 {
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert_eq!(events.borrow().last(), Some(&(id, "started")));
        assert_eq!(events.borrow().len(), 2 * id - 1);
    }
    assert_eq!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Err("uncertain"))
    );
    assert_eq!(
        *events.borrow(),
        vec![
            (1, "started"),
            (1, "finished"),
            (2, "started"),
            (2, "finished"),
            (3, "started"),
            (3, "finished")
        ]
    );
}
