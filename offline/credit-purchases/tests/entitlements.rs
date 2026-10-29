use runlater::{
    core::{Create, Dispatch, Outcome, Status},
    funding,
};
use runlater_offline_credit_purchases::{
    entitlements::{Entitlements, TrialTerms},
    *,
};
use std::sync::{Arc, Barrier, Mutex};

fn task_auth() -> Authority<'static> {
    Authority::Task {
        project: "alpha",
        principal: "scheduler",
    }
}
fn buyer() -> Authority<'static> {
    Authority::Purchase {
        project: "alpha",
        principal: "buyer",
    }
}
fn terms() -> TrialTerms {
    TrialTerms {
        task_allowance: 1,
        duration_ms: 100,
    }
}
fn policy() -> Policy {
    Policy {
        version: 1,
        offer: Offer {
            id: "fictional".into(),
            amount_minor: 100,
            currency: "xxx".into(),
            attempt_units: 5,
            quote_ttl_ms: 100,
            admission_ttl_ms: 1000,
        },
        starts_at_ms: 1,
        ends_at_ms: 10000,
        project_window_minor: 400,
        purchasers: [(
            "buyer".into(),
            DelegateCap {
                per_purchase_minor: 100,
                window_minor: 400,
            },
        )]
        .into(),
    }
}
fn state(trial: bool) -> Entitlements {
    Entitlements::new("alpha", trial.then(terms), Some(policy()), 1).unwrap()
}
fn input() -> Create {
    Create {
        destination: "registered:fixture".into(),
        body: "fiction".into(),
        operation_key: "operation".into(),
        run_at_ms: 0,
    }
}
fn create(
    s: &mut Entitlements,
    key: &str,
    now: i64,
) -> runlater_offline_credit_purchases::entitlements::TaskAdmission {
    s.create(s.revision(), task_auth(), key, input(), now)
        .unwrap()
}
fn intent(s: &mut Entitlements, key: &str) -> Intent {
    s.create_intent(s.revision(), buyer(), key, 1, 10).unwrap()
}
struct Fixture(VerifiedEvent);
impl SettlementVerifier for Fixture {
    fn verify(&self, _: &Intent, evidence: &[u8]) -> Result<VerifiedEvent, Error> {
        if evidence != b"test-only-proof" {
            return Err(Error::Unverified);
        }
        Ok(self.0.clone())
    }
}
fn fact(i: &Intent, reversed: bool, now: i64) -> Fixture {
    Fixture(VerifiedEvent {
        fixture_only: true,
        event_id: format!("{}_{}", if reversed { "reverse" } else { "settle" }, i.id),
        project_id: "alpha".into(),
        intent_id: i.id.clone(),
        intent_digest: i.digest(),
        amount_minor: i.amount_minor,
        currency: i.currency.clone(),
        observed_at_ms: if reversed { now } else { 20 },
        kind: if reversed {
            EventKind::Reversed {
                payment_id: i.id.clone(),
                reason: Reversal::FullRefund,
            }
        } else {
            EventKind::Settled {
                payment_id: i.id.clone(),
                paid_at_ms: 15,
            }
        },
    })
}
fn reconcile(s: &mut Entitlements, i: &Intent, reversed: bool, now: i64) {
    s.reconcile(
        s.revision(),
        "alpha",
        &i.id,
        b"test-only-proof",
        &fact(i, reversed, now),
        now,
    )
    .unwrap();
}
fn dispatch(s: &Entitlements, id: &str) -> Dispatch {
    Dispatch {
        tenant: "alpha".into(),
        id: id.into(),
        generation: s.task("alpha", id).unwrap().generation,
    }
}

#[test]
fn disabled_terms_payment_required_is_exact_and_atomic() {
    let mut s = Entitlements::new("alpha", None, None, 1).unwrap();
    let before = s.snapshot().unwrap();
    let denied = serde_json::to_value(create(&mut s, "same", 2)).unwrap();
    assert_eq!(
        denied,
        serde_json::json!({"task_accepted":false,"funding_reserved":false,"created":false,"error":{"code":"payment_required"}})
    );
    unchanged_admission(&before, &s.snapshot().unwrap());
    let balance = s.balance("alpha", 2).unwrap();
    assert_eq!(balance.admissible_tasks, 0);
    assert!(!balance.activation_enabled);
    assert!(balance.fixture_only);
    assert_eq!(
        s.create_intent(s.revision(), buyer(), "buy", 1, 2),
        Err(Error::Disabled)
    );
}
#[test]
fn cancellation_cannot_refill_trial_task_allowance_and_restart_cannot_reset_it() {
    let mut s = state(true);
    let accepted = create(&mut s, "first", 2).task.unwrap();
    s.cancel(s.revision(), task_auth(), &accepted.id, 3)
        .unwrap();
    let receipt = s
        .reservation("alpha", &accepted.id)
        .unwrap()
        .settlement
        .clone()
        .unwrap();
    assert_eq!(receipt.unused_units, 5);
    let b = s.balance("alpha", 3).unwrap();
    assert_eq!(b.available_attempt_units, 5);
    assert_eq!((b.trial_tasks_remaining, b.admissible_tasks), (0, 0));
    let mut s = Entitlements::restore(&s.snapshot().unwrap()).unwrap();
    assert!(!create(&mut s, "second", 4).task_accepted);
    s.cancel(s.revision(), task_auth(), &accepted.id, 4)
        .unwrap();
    assert_eq!(
        s.reservation("alpha", &accepted.id)
            .unwrap()
            .settlement
            .as_ref(),
        Some(&receipt)
    );
    let replay = create(&mut s, "first", 5);
    assert!(!replay.created);
    assert_eq!(replay.task.unwrap().id, accepted.id);
}
#[test]
fn once_only_trial_then_fixture_purchase_retry_original_denial_key() {
    let mut s = state(true);
    create(&mut s, "trial", 2);
    let before = s.snapshot().unwrap();
    assert!(!create(&mut s, "original", 3).task_accepted);
    unchanged_admission(&before, &s.snapshot().unwrap());
    let i = intent(&mut s, "purchase");
    assert!(!create(&mut s, "original", 11).task_accepted);
    reconcile(&mut s, &i, false, 20);
    let accepted = create(&mut s, "original", 21);
    assert!(accepted.created);
    let task = accepted.task.unwrap();
    assert_eq!(s.reservation("alpha", &task.id).unwrap().grant_id, i.id);
    let mut s = Entitlements::restore(&s.snapshot().unwrap()).unwrap();
    reconcile(&mut s, &i, false, 22);
    assert_eq!(s.balance("alpha", 22).unwrap().reserved_attempt_units, 10);
    let replay = create(&mut s, "original", 23);
    assert_eq!(replay.task.unwrap().id, task.id);
    assert!(!replay.created);
    assert_eq!(s.balance("alpha", 23).unwrap().reserved_attempt_units, 10);
}
#[test]
fn multiple_purchase_journal_updates_do_not_hide_older_available_balance() {
    let mut s = state(false);
    let a = intent(&mut s, "a");
    let b = intent(&mut s, "b");
    reconcile(&mut s, &a, false, 20);
    reconcile(&mut s, &b, false, 21);
    let mut s = Entitlements::restore(&s.snapshot().unwrap()).unwrap();
    let one = create(&mut s, "one", 22).task.unwrap();
    let two = create(&mut s, "two", 23).task.unwrap();
    let first = &s.reservation("alpha", &one.id).unwrap().grant_id;
    let second = &s.reservation("alpha", &two.id).unwrap().grant_id;
    assert_ne!(first, second);
    assert!(first == &a.id || first == &b.id);
    assert!(second == &a.id || second == &b.id);
    assert!(!create(&mut s, "three", 24).task_accepted);
    assert_eq!(s.balance("alpha", 24).unwrap().reserved_attempt_units, 10);
}
#[test]
fn concurrent_last_trial_admission_uses_one_revision_and_one_reservation() {
    let s = Arc::new(Mutex::new(state(true)));
    let revision = s.lock().unwrap().revision();
    let barrier = Arc::new(Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let s = s.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                s.lock()
                    .unwrap()
                    .create(revision, task_auth(), &format!("key_{i}"), input(), 2)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_ok_and(|a| a.task_accepted))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::StaleRevision)))
            .count(),
        15
    );
    let mut s = s.lock().unwrap();
    assert!(!create(&mut s, "another", 3).task_accepted);
    assert_eq!(s.balance("alpha", 3).unwrap().reserved_attempt_units, 5);
}
#[test]
fn accepted_tasks_survive_expiry_reversal_and_spend_once_after_restore() {
    let mut s = state(false);
    let i = intent(&mut s, "buy");
    reconcile(&mut s, &i, false, 20);
    let task = create(&mut s, "task", 21).task.unwrap();
    reconcile(&mut s, &i, true, 22);
    assert!(!create(&mut s, "new", 23).task_accepted);
    let mut s = Entitlements::restore(&s.snapshot().unwrap()).unwrap();
    let d = dispatch(&s, &task.id);
    let running = s.claim(s.revision(), &d, 2000).unwrap().unwrap();
    assert!(s.claim(s.revision(), &d, 2001).unwrap().is_none());
    assert_eq!(s.balance("alpha", 2001).unwrap().spent_attempt_units, 1);
    s.finish(
        s.revision(),
        "alpha",
        &task.id,
        running.fence,
        Outcome::Http(204),
        2002,
    )
    .unwrap();
    let receipt = s
        .reservation("alpha", &task.id)
        .unwrap()
        .settlement
        .as_ref()
        .unwrap();
    assert_eq!(receipt.disposition, funding::Disposition::RetiredUnused);
    assert_eq!((receipt.spent_units, receipt.unused_units), (1, 4));
    let b = s.balance("alpha", 2002).unwrap();
    assert_eq!(
        (
            b.reserved_attempt_units,
            b.spent_attempt_units,
            b.retired_attempt_units
        ),
        (0, 1, 4)
    );
    assert_eq!(
        create(&mut s, "task", 2003).task.unwrap().status,
        Status::Succeeded
    );
}
#[test]
fn trial_expiry_is_independent_of_accepted_task_schedule() {
    let mut s = state(true);
    let mut request = input();
    request.run_at_ms = 2000;
    let t = s
        .create(s.revision(), task_auth(), "scheduled", request.clone(), 2)
        .unwrap()
        .task
        .unwrap();
    assert!(!create(&mut s, "expired", 102).task_accepted);
    let replay = s
        .create(s.revision(), task_auth(), "scheduled", request, 102)
        .unwrap();
    assert_eq!(replay.task.unwrap().id, t.id);
    let d = dispatch(&s, &t.id);
    assert!(s.claim(s.revision(), &d, 2000).unwrap().is_some());
}
#[test]
fn read_projection_cannot_reserve_and_foreign_authority_or_unverified_payment_fails() {
    let mut s = state(true);
    let before = s.snapshot().unwrap();
    s.balance("alpha", 5000).unwrap();
    assert_eq!(s.snapshot().unwrap(), before);
    assert!(matches!(s.balance("beta", 2), Err(Error::Forbidden)));
    assert!(matches!(
        s.create(s.revision(), buyer(), "wrong", input(), 2),
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        s.create(
            s.revision(),
            Authority::Task {
                project: "beta",
                principal: "scheduler"
            },
            "wrong",
            input(),
            2
        ),
        Err(Error::Forbidden)
    ));
    assert_eq!(
        s.create_intent(s.revision(), task_auth(), "wrong", 1, 2),
        Err(Error::Forbidden)
    );
    assert_eq!(s.snapshot().unwrap(), before);
    let i = intent(&mut s, "buy");
    let before = s.snapshot().unwrap();
    assert_eq!(
        s.reconcile(
            s.revision(),
            "alpha",
            &i.id,
            br#"{"paid":true}"#,
            &DisabledVerifier,
            20
        ),
        Err(Error::Disabled)
    );
    assert_eq!(s.snapshot().unwrap(), before);
}
#[test]
fn redrive_gets_new_reservation_and_cannot_reset_trial_or_replay_spend() {
    let mut s = state(true);
    let t = create(&mut s, "first", 2).task.unwrap();
    let d = dispatch(&s, &t.id);
    let running = s.claim(s.revision(), &d, 3).unwrap().unwrap();
    s.finish(
        s.revision(),
        "alpha",
        &t.id,
        running.fence,
        Outcome::Http(400),
        4,
    )
    .unwrap();
    assert!(
        !s.redrive(s.revision(), task_auth(), &t.id, "again", 5)
            .unwrap()
            .task_accepted
    );
    let i = intent(&mut s, "buy");
    reconcile(&mut s, &i, false, 20);
    let child = s
        .redrive(s.revision(), task_auth(), &t.id, "again", 21)
        .unwrap()
        .task
        .unwrap();
    assert_eq!(child.parent.as_deref(), Some(t.id.as_str()));
    assert_ne!(child.id, t.id);
    let replay = s
        .redrive(s.revision(), task_auth(), &t.id, "again", 22)
        .unwrap();
    assert!(!replay.created);
    assert_eq!(replay.task.unwrap().id, child.id);
    assert_eq!(s.balance("alpha", 22).unwrap().reserved_attempt_units, 5);
}
#[test]
fn invalid_terms_stale_revision_and_clock_rollback_fail_without_changes() {
    for t in [
        TrialTerms {
            task_allowance: 0,
            duration_ms: 10,
        },
        TrialTerms {
            task_allowance: SAFE,
            duration_ms: 10,
        },
        TrialTerms {
            task_allowance: 1,
            duration_ms: i64::MAX,
        },
    ] {
        assert!(Entitlements::new("alpha", Some(t), None, 1).is_err());
    }
    let mut s = state(true);
    create(&mut s, "task", 20);
    let before = s.snapshot().unwrap();
    assert!(matches!(
        s.create(1, task_auth(), "stale", input(), 21),
        Err(Error::StaleRevision)
    ));
    assert!(matches!(
        s.create(s.revision(), task_auth(), "rollback", input(), 19),
        Err(Error::ClockRegressed)
    ));
    let mut different = input();
    different.body = "changed".into();
    assert!(matches!(
        s.create(s.revision(), task_auth(), "task", different, 21),
        Err(Error::Task(_))
    ));
    assert_eq!(s.snapshot().unwrap(), before);
}

fn unchanged_admission(before: &[u8], after: &[u8]) {
    let before: serde_json::Value = serde_json::from_slice(before).unwrap();
    let after: serde_json::Value = serde_json::from_slice(after).unwrap();
    for field in [
        "ledger",
        "trial",
        "purchases",
        "purchase_cursor",
        "funding_revision",
    ] {
        assert_eq!(before[field], after[field], "changed {field}");
    }
    assert_eq!(
        before["funding"]["reservations"],
        after["funding"]["reservations"]
    );
}
#[test]
fn denied_expiry_is_sticky_after_restore_and_clock_rollback() {
    let mut s = state(true);
    let before = s.snapshot().unwrap();
    assert!(!create(&mut s, "expired", 102).task_accepted);
    unchanged_admission(&before, &s.snapshot().unwrap());
    assert_eq!(s.balance("alpha", 102).unwrap().retired_attempt_units, 5);
    let mut s = Entitlements::restore(&s.snapshot().unwrap()).unwrap();
    assert!(matches!(
        s.create(s.revision(), task_auth(), "early", input(), 2),
        Err(Error::ClockRegressed)
    ));
    assert!(!create(&mut s, "expired", 103).task_accepted);
}
#[test]
fn invalid_snapshot_cannot_bypass_validation_or_reopen_reversed_credits() {
    let mut s = state(false);
    let i = intent(&mut s, "purchase");
    reconcile(&mut s, &i, false, 20);
    reconcile(&mut s, &i, true, 21);
    let mut v: serde_json::Value = serde_json::from_slice(&s.snapshot().unwrap()).unwrap();
    let g = &mut v["funding"]["grants"][&i.id];
    g["closed"] = false.into();
    g["available"] = 5.into();
    g["retired"] = 0.into();
    assert!(Entitlements::restore(&serde_json::to_vec(&v).unwrap()).is_err());
    assert!(serde_json::from_value::<Entitlements>(v).is_err());
    let s = state(true);
    let mut v: serde_json::Value = serde_json::from_slice(&s.snapshot().unwrap()).unwrap();
    v["trial"]["grant"]["admission_expires_at_ms"] = 999.into();
    v["funding"]["grants"]["trial_once"]["spec"]["admission_expires_at_ms"] = 999.into();
    assert!(serde_json::from_value::<Entitlements>(v).is_err());
}
#[test]
fn limited_claim_still_commits_reconciliation_of_other_tasks() {
    let mut s = Entitlements::new(
        "alpha",
        Some(TrialTerms {
            task_allowance: 6,
            duration_ms: 2 * runlater::core::DAY,
        }),
        None,
        1,
    )
    .unwrap();
    let aged = create(&mut s, "aged", 2).task.unwrap();
    let mut request = input();
    request.run_at_ms = runlater::core::DAY + 2;
    let mut fresh = Vec::new();
    for i in 0..5 {
        fresh.push(
            s.create(
                s.revision(),
                task_auth(),
                &format!("new{i}"),
                request.clone(),
                2,
            )
            .unwrap()
            .task
            .unwrap(),
        );
    }
    // Trusted fixture sets the already-supported ledger token bucket to empty at
    // this instant, without pre-reconciling the older task through a claim.
    let mut v: serde_json::Value = serde_json::from_slice(&s.snapshot().unwrap()).unwrap();
    v["ledger"]["bucket"] =
        serde_json::json!({"available_milli":0,"refilled_ms":runlater::core::DAY+3});
    let mut s = Entitlements::restore(&serde_json::to_vec(&v).unwrap()).unwrap();
    let d = dispatch(&s, &fresh[0].id);
    assert!(matches!(
        s.claim(s.revision(), &d, runlater::core::DAY + 3),
        Err(Error::Task(runlater::core::Fault::Limited { .. }))
    ));
    assert_eq!(s.task("alpha", &aged.id).unwrap().status, Status::Failed);
    assert!(s
        .reservation("alpha", &aged.id)
        .unwrap()
        .settlement
        .is_some());
    assert_eq!(
        s.balance("alpha", runlater::core::DAY + 3)
            .unwrap()
            .reserved_attempt_units,
        25
    );
}

#[test]
fn trial_reserves_lifetime_grant_slot_before_purchase_intent_acceptance() {
    let mut p = policy();
    p.project_window_minor = 4000;
    p.purchasers.get_mut("buyer").unwrap().window_minor = 4000;
    let mut s = Entitlements::new("alpha", Some(terms()), Some(p), 1).unwrap();
    for i in 0..31 {
        intent(&mut s, &format!("purchase{i}"));
    }
    let before = s.snapshot().unwrap();
    assert_eq!(
        s.create_intent(s.revision(), buyer(), "overflow", 1, 10),
        Err(Error::Capacity)
    );
    assert_eq!(s.snapshot().unwrap(), before);
    // Replaying the 31st accepted intent remains possible at the lifetime bound.
    assert!(s
        .create_intent(s.revision(), buyer(), "purchase30", 1, 10)
        .is_ok());
}
#[test]
fn trial_units_are_counted_before_accepting_purchase_numeric_headroom() {
    let mut p = policy();
    p.offer.attempt_units = SAFE - 5;
    let mut s = Entitlements::new(
        "alpha",
        Some(TrialTerms {
            task_allowance: 2,
            duration_ms: 100,
        }),
        Some(p),
        1,
    )
    .unwrap();
    let before = s.snapshot().unwrap();
    assert_eq!(
        s.create_intent(s.revision(), buyer(), "too_many", 1, 10),
        Err(Error::Overflow)
    );
    assert_eq!(s.snapshot().unwrap(), before);
}

#[test]
fn fragmented_grants_are_not_pooled_or_misreported_as_admissible() {
    let mut p = policy();
    p.offer.attempt_units = 4;
    let mut s = Entitlements::new("alpha", None, Some(p), 1).unwrap();
    let a = intent(&mut s, "a");
    let b = intent(&mut s, "b");
    reconcile(&mut s, &a, false, 20);
    reconcile(&mut s, &b, false, 21);
    let balance = s.balance("alpha", 21).unwrap();
    assert_eq!(
        (balance.available_attempt_units, balance.admissible_tasks),
        (8, 0)
    );
    assert!(!create(&mut s, "task", 22).task_accepted);
}
#[test]
fn purchased_cancel_returns_once_until_reversal_without_affecting_trial_slots() {
    let mut s = state(false);
    let i = intent(&mut s, "buy");
    reconcile(&mut s, &i, false, 20);
    let t = create(&mut s, "first", 21).task.unwrap();
    s.cancel(s.revision(), task_auth(), &t.id, 22).unwrap();
    s.cancel(s.revision(), task_auth(), &t.id, 23).unwrap();
    assert_eq!(s.balance("alpha", 23).unwrap().admissible_tasks, 1);
    let t = create(&mut s, "second", 24).task.unwrap();
    reconcile(&mut s, &i, true, 25);
    s.cancel(s.revision(), task_auth(), &t.id, 26).unwrap();
    s.cancel(s.revision(), task_auth(), &t.id, 27).unwrap();
    let balance = s.balance("alpha", 27).unwrap();
    assert_eq!(
        (balance.admissible_tasks, balance.retired_attempt_units),
        (0, 5)
    );
    assert!(!create(&mut s, "third", 28).task_accepted);
}
