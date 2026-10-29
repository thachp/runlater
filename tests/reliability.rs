//! Bounded deterministic acceptance campaigns, not throughput/SLO or live fault proofs.
use runlater::{core::*, limits::QueueLimits};

fn input(at: i64) -> Create {
    Create {
        destination: "fixture://success".into(),
        body: "reliability_fixture".into(),
        operation_key: "unchanged_business_identity".into(),
        run_at_ms: at,
    }
}
fn restart(ledger: &Ledger) -> Ledger {
    serde_json::from_slice(&serde_json::to_vec(ledger).unwrap()).unwrap()
}
fn snapshot(ledger: &Ledger) -> serde_json::Value {
    serde_json::to_value(ledger).unwrap()
}

#[test]
fn bounded_429_storm_preserves_retry_budget_and_independent_tenant_capacity() {
    const TASKS: usize = 32;
    let mut noisy = Ledger::default();
    noisy
        .configure(
            QueueLimits {
                max_concurrent: 2,
                dispatch_per_second: 4,
                dispatch_burst: 2,
                ..QueueLimits::default()
            },
            0,
        )
        .unwrap();
    let mut quiet = restart(&noisy);
    let quiet_task = quiet.create("quiet", input(0), 0).unwrap().0;
    let quiet_before = snapshot(&quiet);
    for i in 0..TASKS {
        noisy.create(&format!("noisy_{i}"), input(0), 0).unwrap();
    }
    // Identical task IDs intentionally exercise separate tenant-local ledgers.
    assert!(noisy.tasks.contains_key(&quiet_task.id));
    let mut started = 0;
    let mut completed_at = None;
    for tick in 0..1000 {
        let now = tick * 250;
        noisy = restart(&noisy);
        let mut running = Vec::new();
        for reference in noisy.outbox("noisy", now) {
            let before = noisy.get(&reference.id).unwrap().attempts.len();
            match noisy.claim(&reference, now) {
                Ok(Some(task)) => {
                    assert!(noisy.claim(&reference, now).unwrap().is_none());
                    running.push(task);
                    started += 1;
                }
                Err(Fault::Limited {
                    reason,
                    retry_after_ms,
                }) => {
                    assert!(matches!(
                        reason,
                        LimitReason::Concurrency | LimitReason::DispatchRate
                    ));
                    assert!(retry_after_ms > 0);
                    assert_eq!(noisy.get(&reference.id).unwrap().attempts.len(), before);
                }
                result => panic!("Unexpected storm claim: {result:?}"),
            }
        }
        assert!(running.len() <= 2, "Configured simultaneous lease bound");
        assert!(
            started <= 2 + now * 4 / 1000,
            "Persisted token-bucket envelope"
        );
        noisy = restart(&noisy);
        for task in running {
            let finished = noisy
                .finish(&task.id, task.fence, Outcome::Http(429), now)
                .unwrap();
            assert_eq!(finished.input, task.input);
            if finished.status == Status::RetryWait {
                assert!(finished.due_ms > now, "No hot-loop retry after 429");
                assert!(finished.generation > task.generation);
                assert!(finished.due_ms - now <= 60_999);
            }
            assert_eq!(
                noisy
                    .finish(&task.id, task.fence, Outcome::Http(204), now)
                    .unwrap_err(),
                Fault::Stale
            );
        }
        if noisy.tasks.values().all(|task| task.status.terminal()) {
            completed_at = Some(now);
            break;
        }
    }
    let now = completed_at.expect("Bounded simulated storm must terminate");
    assert_eq!(started as usize, TASKS * MAX_ATTEMPTS as usize);
    for task in noisy.tasks.values() {
        assert_eq!(task.status, Status::Failed);
        assert_eq!(task.attempts.len(), MAX_ATTEMPTS as usize);
        assert!(task
            .attempts
            .iter()
            .all(|attempt| attempt.outcome.as_deref() == Some("http_429")));
    }
    assert!(restart(&noisy).outbox("noisy", now + DAY).is_empty());
    assert_eq!(
        snapshot(&quiet),
        quiet_before,
        "Storm cannot mutate another ledger"
    );
    let reference = quiet.outbox("quiet", now).remove(0);
    let task = quiet.claim(&reference, now).unwrap().unwrap();
    assert_eq!(
        quiet
            .finish(&task.id, task.fence, Outcome::Http(204), now)
            .unwrap()
            .status,
        Status::Succeeded
    );
    // This proves ledger-local budget separation, not provider CPU/noisy-neighbor fairness.
}

#[test]
fn year_long_schedule_replay_survives_purge_and_starts_age_at_due_time() {
    let mut ledger = Ledger::default();
    let due = 365 * DAY;
    let task = ledger.create("year", input(due), 0).unwrap().0;
    assert_eq!(
        ledger.create("too_far", input(due + 1), 0).unwrap_err(),
        Fault::Invalid
    );
    for now in [RETENTION, 200 * DAY, due - 1] {
        ledger = restart(&ledger);
        ledger.purge(now);
        assert!(ledger.outbox("tenant", now).is_empty());
        let (replayed, created) = ledger.create("year", input(due), now).unwrap();
        assert!(!created);
        assert_eq!(replayed.id, task.id);
        assert!(replayed.attempts.is_empty());
        assert_eq!(replayed.initial_due_ms, due);
    }
    let mut late = restart(&ledger);
    assert!(late.outbox("tenant", due + DAY + 1).is_empty());
    assert_eq!(late.get(&task.id).unwrap().status, Status::Failed);
    assert!(late.get(&task.id).unwrap().attempts.is_empty());
    let reference = ledger.outbox("tenant", due).remove(0);
    let claimed = ledger.claim(&reference, due).unwrap().unwrap();
    let completed = ledger
        .finish(&task.id, claimed.fence, Outcome::Http(204), due + 1)
        .unwrap();
    assert_eq!(completed.status, Status::Succeeded);
    ledger = restart(&ledger);
    ledger.purge(due + RETENTION);
    assert_eq!(
        ledger
            .create("year", input(due), due + RETENTION)
            .unwrap()
            .0
            .id,
        task.id
    );
    ledger.purge(due + 1 + RETENTION);
    assert_eq!(ledger.get(&task.id).unwrap_err(), Fault::NotFound);
    assert!(!ledger.dedupe.contains_key("year"));
}

#[test]
fn clock_regression_never_resurrects_a_reconciled_lease_or_old_generation() {
    let mut ledger = Ledger::default();
    ledger.create("clock", input(0), 0).unwrap();
    let reference = ledger.outbox("tenant", 1000).remove(0);
    let first = ledger.claim(&reference, 1000).unwrap().unwrap();
    ledger = restart(&ledger);
    ledger.reconcile(500);
    assert_eq!(
        ledger.get(&first.id).unwrap().lease_until,
        Some(1000 + LEASE)
    );
    assert!(ledger.claim(&reference, 500).unwrap().is_none());
    let mut before_deadline = restart(&ledger);
    assert_eq!(
        before_deadline
            .finish(&first.id, first.fence, Outcome::Http(204), 1000 + LEASE - 1)
            .unwrap()
            .status,
        Status::Succeeded
    );
    assert_eq!(
        ledger
            .finish(&first.id, first.fence, Outcome::Http(204), 1000 + LEASE)
            .unwrap_err(),
        Fault::Stale
    );
    ledger.reconcile(1000 + LEASE);
    ledger = restart(&ledger);
    let due = ledger.get(&first.id).unwrap().due_ms;
    ledger.reconcile(500);
    assert_eq!(
        ledger
            .finish(&first.id, first.fence, Outcome::Http(204), 500)
            .unwrap_err(),
        Fault::Stale
    );
    assert!(ledger.outbox("tenant", due - 1).is_empty());
    let retry = ledger.outbox("tenant", due).remove(0);
    let second = ledger.claim(&retry, due).unwrap().unwrap();
    assert!(second.fence > first.fence);
    assert!(ledger.claim(&reference, due).unwrap().is_none());
    assert_eq!(
        ledger
            .finish(&first.id, first.fence, Outcome::Http(204), due)
            .unwrap_err(),
        Fault::Stale
    );
    assert_eq!(
        ledger
            .finish(&second.id, second.fence, Outcome::Http(204), due)
            .unwrap()
            .status,
        Status::Succeeded
    );
}

#[test]
fn cancellation_at_each_persisted_attempt_boundary_never_reopens_terminal_work() {
    for outcome in [
        Outcome::Http(204),
        Outcome::Http(429),
        Outcome::Timeout,
        Outcome::LeaseExpired,
    ] {
        for cancel_before_claim in [true, false] {
            let mut ledger = Ledger::default();
            let task = ledger.create("cancel", input(0), 0).unwrap().0;
            let reference = ledger.outbox("tenant", 0).remove(0);
            if cancel_before_claim {
                ledger.cancel(&task.id, 1).unwrap();
                ledger = restart(&ledger);
                assert!(ledger.claim(&reference, 2).unwrap().is_none());
            } else {
                let claimed = ledger.claim(&reference, 0).unwrap().unwrap();
                ledger = restart(&ledger);
                ledger.cancel(&task.id, 1).unwrap();
                ledger = restart(&ledger);
                match outcome {
                    Outcome::LeaseExpired => ledger.reconcile(LEASE),
                    _ => {
                        ledger.finish(&task.id, claimed.fence, outcome, 2).unwrap();
                    }
                }
            }
            ledger = restart(&ledger);
            let terminal = ledger.get(&task.id).unwrap();
            let expected = if !cancel_before_claim && matches!(outcome, Outcome::Http(204)) {
                Status::Succeeded
            } else {
                Status::Cancelled
            };
            assert_eq!(terminal.status, expected);
            assert!(terminal.lease_until.is_none());
            let before = serde_json::to_value(&terminal).unwrap();
            ledger.cancel(&task.id, LEASE + 1).unwrap();
            assert!(ledger.outbox("tenant", LEASE + 1).is_empty());
            assert!(ledger.claim(&reference, LEASE + 1).unwrap().is_none());
            assert_eq!(
                serde_json::to_value(ledger.get(&task.id).unwrap()).unwrap(),
                before
            );
        }
    }
}

#[test]
fn repeated_pre_callback_crashes_exhaust_attempts_without_resetting_history() {
    let mut ledger = Ledger::default();
    let original = ledger.create("crash_loop", input(0), 0).unwrap().0;
    let mut now = 0;
    let mut references = Vec::new();
    let mut fences = Vec::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let reference = ledger.outbox("tenant", now).remove(0);
        let claimed = ledger.claim(&reference, now).unwrap().unwrap();
        references.push(reference.clone());
        fences.push(claimed.fence);
        assert_eq!(claimed.attempts.len(), attempt as usize);
        assert_eq!(claimed.input, original.input);
        // The process dies after persisting the claim, without invoking a receiver.
        ledger = restart(&ledger);
        let deadline = claimed.lease_until.unwrap();
        assert!(ledger.outbox("tenant", deadline - 1).is_empty());
        assert!(ledger.claim(&reference, deadline - 1).unwrap().is_none());
        assert_eq!(
            ledger
                .finish(&original.id, claimed.fence, Outcome::Http(204), deadline)
                .unwrap_err(),
            Fault::Stale
        );
        ledger.reconcile(deadline);
        ledger = restart(&ledger);
        let recovered = ledger.get(&original.id).unwrap();
        assert!(recovered.lease_until.is_none());
        assert!(recovered.attempts.iter().all(|a| {
            a.outcome.as_deref() == Some("lease_expired_unknown") && a.finished_ms.is_some()
        }));
        assert_eq!(recovered.initial_due_ms, original.initial_due_ms);
        assert_eq!(
            ledger
                .create("crash_loop", input(0), deadline)
                .unwrap()
                .0
                .id,
            original.id
        );
        for old in &references {
            assert!(ledger.claim(old, deadline).unwrap().is_none());
        }
        if attempt < MAX_ATTEMPTS {
            assert_eq!(recovered.status, Status::RetryWait);
            assert!(recovered.due_ms > deadline);
            assert!(ledger.outbox("tenant", recovered.due_ms - 1).is_empty());
            now = recovered.due_ms;
        } else {
            assert_eq!(recovered.status, Status::Failed);
            now = deadline;
        }
    }
    let exhausted = serde_json::to_value(ledger.get(&original.id).unwrap()).unwrap();
    ledger = restart(&ledger);
    now += DAY;
    assert!(ledger.outbox("tenant", now).is_empty());
    for fence in fences {
        assert_eq!(
            ledger
                .finish(&original.id, fence, Outcome::Http(204), now)
                .unwrap_err(),
            Fault::Stale
        );
    }
    // Explicit redrive is the only new budget, with new identity and retained lineage.
    let (redriven, created) = ledger
        .redrive(&original.id, "operator_redrive", now)
        .unwrap();
    assert!(created);
    assert_ne!(redriven.id, original.id);
    assert_eq!(redriven.parent.as_deref(), Some(original.id.as_str()));
    assert_eq!(redriven.input.operation_key, original.input.operation_key);
    assert!(redriven.attempts.is_empty());
    assert_eq!(
        serde_json::to_value(ledger.get(&original.id).unwrap()).unwrap(),
        exhausted
    );
}
