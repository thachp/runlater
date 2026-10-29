use runlater::{
    core::{Create, Ledger, Outcome},
    funding,
};
use runlater_offline_credit_purchases::*;
use serde_json::{json, Value};
use std::sync::{Arc, Barrier, Mutex};

fn policy() -> Policy {
    Policy {
        version: 7,
        offer: Offer {
            id: "fictional_offer".into(),
            amount_minor: 100,
            currency: "xxx".into(),
            attempt_units: 10,
            quote_ttl_ms: 100,
            admission_ttl_ms: 1000,
        },
        starts_at_ms: 1,
        ends_at_ms: 10000,
        project_window_minor: 500,
        purchasers: [
            (
                "buyer_a".into(),
                DelegateCap {
                    per_purchase_minor: 300,
                    window_minor: 400,
                },
            ),
            (
                "buyer_b".into(),
                DelegateCap {
                    per_purchase_minor: 300,
                    window_minor: 400,
                },
            ),
        ]
        .into(),
    }
}
fn state() -> OfflineLedger {
    OfflineLedger::new("alpha", Some(policy())).unwrap()
}
fn authority() -> Authority<'static> {
    Authority::Purchase {
        project: "alpha",
        principal: "buyer_a",
    }
}
fn intent(s: &mut OfflineLedger, key: &str) -> Intent {
    s.create_intent(s.revision(), authority(), key, 1, 10)
        .unwrap()
}
/// Test-local fake adapter. Only exact allowlisted fiction bytes can yield facts.
/// Nothing in the library can construct this implementation from HTTP input.
struct Fixture {
    proof: Vec<u8>,
    event: VerifiedEvent,
}
impl SettlementVerifier for Fixture {
    fn verify(&self, _: &Intent, evidence: &[u8]) -> Result<VerifiedEvent, Error> {
        if evidence != self.proof {
            return Err(Error::Unverified);
        }
        Ok(self.event.clone())
    }
}
fn fixture(i: &Intent, name: &str) -> Fixture {
    let source: Value = serde_json::from_str(include_str!("../fixtures/events.json")).unwrap();
    assert_eq!(source["format"], "runlater-synthetic-events-v1");
    let f = &source[name];
    Fixture {
        proof: f["proof"].as_str().unwrap().as_bytes().to_vec(),
        event: VerifiedEvent {
            fixture_only: true,
            event_id: f["event_id"].as_str().unwrap().into(),
            project_id: i.project_id.clone(),
            intent_id: i.id.clone(),
            intent_digest: i.digest(),
            amount_minor: i.amount_minor,
            currency: i.currency.clone(),
            observed_at_ms: 20,
            kind: match name {
                "settled" => EventKind::Settled {
                    payment_id: f["payment_id"].as_str().unwrap().into(),
                    paid_at_ms: 15,
                },
                "reversed" => EventKind::Reversed {
                    payment_id: f["payment_id"].as_str().unwrap().into(),
                    reason: Reversal::FullRefund,
                },
                "unpaid" => EventKind::NoPaymentFinal,
                _ => panic!("unknown fixture"),
            },
        },
    }
}
fn apply(s: &mut OfflineLedger, i: &Intent, f: &Fixture, now: i64) -> Result<Receipt, Error> {
    s.reconcile(s.revision(), "alpha", &i.id, &f.proof, f, now)
}
fn settle(s: &mut OfflineLedger, i: &Intent) {
    apply(s, i, &fixture(i, "settled"), 20).unwrap();
}
fn unchanged<T: std::fmt::Debug>(
    s: &mut OfflineLedger,
    expected: Error,
    f: impl FnOnce(&mut OfflineLedger) -> Result<T, Error>,
) {
    let before = s.snapshot().unwrap();
    assert_eq!(f(s).unwrap_err(), expected);
    assert_eq!(s.snapshot().unwrap(), before);
}
fn input() -> Create {
    Create {
        destination: "registered:offline_receiver".into(),
        body: "fiction".into(),
        operation_key: "offline_op".into(),
        run_at_ms: 2000,
    }
}

#[test]
fn no_terms_no_activation_and_no_shipped_verifier() {
    let mut s = OfflineLedger::new("alpha", None).unwrap();
    unchanged(&mut s, Error::Disabled, |s| {
        s.create_intent(s.revision(), authority(), "a", 1, 10)
    });
    let balance = s
        .balance("alpha", &funding::State::default(), 0, 10)
        .unwrap();
    assert!(!balance.activation_enabled);
    assert!(balance.fixture_only);
    assert_eq!(balance.available, 0);
    let mut s = state();
    let i = intent(&mut s, "a");
    unchanged(&mut s, Error::Disabled, |s| {
        s.reconcile(
            s.revision(),
            "alpha",
            &i.id,
            br#"{"status":"paid","amount":100}"#,
            &DisabledVerifier,
            20,
        )
    });
}
#[test]
fn separate_authority_and_foreign_tenant_rejected() {
    let mut s = state();
    unchanged(&mut s, Error::Forbidden, |s| {
        s.create_intent(
            s.revision(),
            Authority::Task {
                project: "alpha",
                principal: "buyer_a",
            },
            "a",
            1,
            10,
        )
    });
    unchanged(&mut s, Error::Forbidden, |s| {
        s.create_intent(
            s.revision(),
            Authority::Purchase {
                project: "other",
                principal: "buyer_a",
            },
            "a",
            1,
            10,
        )
    });
    unchanged(&mut s, Error::Forbidden, |s| {
        s.create_intent(
            s.revision(),
            Authority::Purchase {
                project: "alpha",
                principal: "scheduler",
            },
            "a",
            1,
            10,
        )
    });
    let i = intent(&mut s, "a");
    let f = fixture(&i, "settled");
    unchanged(&mut s, Error::Forbidden, |s| {
        s.reconcile(s.revision(), "other", &i.id, &f.proof, &f, 20)
    });
    assert_eq!(s.receipt("other", &i.id), Err(Error::Forbidden));
    assert_eq!(
        s.balance("other", &funding::State::default(), 0, 20),
        Err(Error::Forbidden)
    );
}
#[test]
fn immutable_intent_replay_after_settlement_expiry_and_restart() {
    let mut s = state();
    let i = intent(&mut s, "a");
    let bytes = s.snapshot().unwrap();
    assert_eq!(
        s.create_intent(s.revision(), authority(), "a", 1, 50)
            .unwrap(),
        i
    );
    assert_eq!(s.snapshot().unwrap(), bytes);
    unchanged(&mut s, Error::Conflict, |s| {
        s.create_intent(s.revision(), authority(), "a", 2, 50)
    });
    settle(&mut s, &i);
    let bytes = s.snapshot().unwrap();
    let mut restored = OfflineLedger::restore(&bytes).unwrap();
    assert_eq!(
        restored
            .create_intent(restored.revision(), authority(), "a", 1, 20000)
            .unwrap(),
        i
    );
    let old = restored.receipt("alpha", &i.id).unwrap().clone();
    assert_eq!(
        apply(&mut restored, &i, &fixture(&i, "settled"), 20000).unwrap(),
        old
    );
    assert_eq!(restored.snapshot().unwrap(), bytes);
}
#[test]
fn fabricated_and_nonfixture_evidence_are_rejected() {
    let mut s = state();
    let i = intent(&mut s, "a");
    let f = fixture(&i, "settled");
    unchanged(&mut s, Error::Unverified, |s| {
        s.reconcile(s.revision(), "alpha", &i.id, br#"{"paid":true}"#, &f, 20)
    });
    let mut f = fixture(&i, "settled");
    f.event.fixture_only = false;
    unchanged(&mut s, Error::Disabled, |s| apply(s, &i, &f, 20));
}
#[test]
fn every_settlement_binding_is_checked_before_issuance() {
    for field in [
        "project",
        "intent",
        "digest",
        "amount",
        "currency",
        "future",
        "before_issue",
    ] {
        let mut s = state();
        let i = intent(&mut s, "a");
        let mut f = fixture(&i, "settled");
        match field {
            "project" => f.event.project_id = "other".into(),
            "intent" => f.event.intent_id = "other".into(),
            "digest" => f.event.intent_digest = "fabricated".into(),
            "amount" => f.event.amount_minor = 99,
            "currency" => f.event.currency = "usd".into(),
            "future" => f.event.observed_at_ms = 21,
            "before_issue" => f.event.observed_at_ms = 9,
            _ => unreachable!(),
        }
        unchanged(&mut s, Error::Binding, |s| apply(s, &i, &f, 20));
    }
}
#[test]
fn same_payment_cannot_fund_two_quotes_or_tenants() {
    let mut s = state();
    let a = intent(&mut s, "a");
    let b = intent(&mut s, "b");
    settle(&mut s, &a);
    let mut f = fixture(&b, "settled");
    f.event.event_id = "different_event".into();
    unchanged(&mut s, Error::Conflict, |s| apply(s, &b, &f, 20));
    let mut f = fixture(&a, "settled");
    f.event.amount_minor = 101;
    unchanged(&mut s, Error::Binding, |s| apply(s, &a, &f, 20));
    let mut f = fixture(&a, "settled");
    f.event.kind = EventKind::Settled {
        payment_id: "other_payment".into(),
        paid_at_ms: 15,
    };
    unchanged(&mut s, Error::Conflict, |s| apply(s, &a, &f, 20));
}
#[test]
fn duplicate_provider_events_issue_one_immutable_grant() {
    let mut s = state();
    let i = intent(&mut s, "a");
    settle(&mut s, &i);
    let receipt = s.receipt("alpha", &i.id).unwrap().clone();
    let mut f = fixture(&i, "settled");
    f.event.event_id = "new_delivery_same_payment".into();
    assert_eq!(apply(&mut s, &i, &f, 20).unwrap(), receipt);
    let mut funding = funding::State::default();
    let cursor = s.sync_funding(&mut funding, 0, 20).unwrap();
    funding.reserve("alpha", "accepted_task", 20).unwrap();
    let before = serde_json::to_vec(&funding).unwrap();
    s.sync_funding(&mut funding, cursor, 20).unwrap();
    assert_eq!(serde_json::to_vec(&funding).unwrap(), before);
    let g = funding.grant(&i.id).unwrap();
    assert_eq!((g.available, g.reserved), (5, 5));
}
#[test]
fn caps_include_pending_and_all_delegates_and_reject_stale_reads() {
    let mut s = state();
    let old = s.revision();
    let _ = intent(&mut s, "a");
    unchanged(&mut s, Error::StaleRevision, |s| {
        s.create_intent(old, authority(), "b", 1, 10)
    });
    s.create_intent(s.revision(), authority(), "b", 3, 10)
        .unwrap();
    unchanged(&mut s, Error::CapExceeded, |s| {
        s.create_intent(s.revision(), authority(), "c", 1, 10)
    });
    let b = Authority::Purchase {
        project: "alpha",
        principal: "buyer_b",
    };
    s.create_intent(s.revision(), b.clone(), "c", 1, 10)
        .unwrap();
    unchanged(&mut s, Error::CapExceeded, |s| {
        s.create_intent(s.revision(), b, "d", 1, 10)
    });
    assert_eq!(s.cap_balance(None).unwrap().pending_minor, 500);
    assert_eq!(s.cap_balance(Some("buyer_a")).unwrap().pending_minor, 400);
}
#[test]
fn concurrent_last_cap_uses_revision_compare_and_swap() {
    let mut p = policy();
    p.project_window_minor = 100;
    let s = Arc::new(Mutex::new(OfflineLedger::new("alpha", Some(p)).unwrap()));
    let start = Arc::new(Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|n| {
            let s = s.clone();
            let start = start.clone();
            std::thread::spawn(move || {
                let revision = s.lock().unwrap().revision();
                start.wait();
                s.lock().unwrap().create_intent(
                    revision,
                    authority(),
                    &format!("concurrent_{n}"),
                    1,
                    10,
                )
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::StaleRevision)))
            .count(),
        15
    );
    let mut s = s.lock().unwrap();
    unchanged(&mut s, Error::CapExceeded, |s| {
        s.create_intent(s.revision(), authority(), "retry", 1, 10)
    });
}
#[test]
fn expiry_keeps_uncertain_hold_until_definitive_unpaid() {
    let mut p = policy();
    p.project_window_minor = 100;
    let mut s = OfflineLedger::new("alpha", Some(p)).unwrap();
    let i = intent(&mut s, "a");
    unchanged(&mut s, Error::CapExceeded, |s| {
        s.create_intent(s.revision(), authority(), "b", 1, 500)
    });
    let mut f = fixture(&i, "unpaid");
    f.event.observed_at_ms = 500;
    apply(&mut s, &i, &f, 500).unwrap();
    assert_eq!(s.cap_balance(None).unwrap().pending_minor, 0);
    s.create_intent(s.revision(), authority(), "b", 1, 500)
        .unwrap();
    let mut f = fixture(&i, "settled");
    f.event.observed_at_ms = 500;
    unchanged(&mut s, Error::Conflict, |s| apply(s, &i, &f, 500));
}
#[test]
fn late_delivery_reconciles_paid_in_time_without_extending_expiry() {
    let mut s = state();
    let i = intent(&mut s, "a");
    let mut f = fixture(&i, "settled");
    f.event.observed_at_ms = 2000;
    apply(&mut s, &i, &f, 2000).unwrap();
    let b = s
        .balance("alpha", &funding::State::default(), 0, 2000)
        .unwrap();
    assert_eq!((b.available, b.retired), (0, 10));
    let mut other = state();
    let j = intent(&mut other, "a");
    let mut f = fixture(&j, "settled");
    f.event.kind = EventKind::Settled {
        payment_id: "fictional_payment_a".into(),
        paid_at_ms: j.expires_at_ms,
    };
    f.event.observed_at_ms = 2000;
    unchanged(&mut other, Error::Expired, |s| apply(s, &j, &f, 2000));
}
#[test]
fn full_refund_and_reversal_preserve_accepted_task_funding() {
    for reason in [Reversal::FullRefund, Reversal::FullReversal] {
        let mut s = state();
        let i = intent(&mut s, "a");
        settle(&mut s, &i);
        let mut funding = funding::State::default();
        let cursor = s.sync_funding(&mut funding, 0, 20).unwrap();
        let mut tasks = Ledger::default();
        let (t, created) = tasks.create("task", input(), 20).unwrap();
        assert!(created);
        funding.reserve("alpha", &t.id, 20).unwrap();
        let mut f = fixture(&i, "reversed");
        f.event.kind = EventKind::Reversed {
            payment_id: "fictional_payment_a".into(),
            reason,
        };
        apply(&mut s, &i, &f, 20).unwrap();
        let cursor = s.sync_funding(&mut funding, cursor, 20).unwrap();
        assert_eq!(s.cap_balance(None).unwrap().gross_committed_minor, 100);
        let g = funding.grant(&i.id).unwrap();
        assert_eq!((g.available, g.reserved, g.retired), (0, 5, 5));
        assert!(g.closed);
        assert_eq!(
            funding.reserve("alpha", "new_task", 20),
            Err(funding::Error::MissingPolicy)
        );
        // Accepted task idempotency survives entitlement expiry and a purchase reversal.
        let (replay, created) = tasks.create("task", input(), 2000).unwrap();
        assert!(!created);
        assert_eq!(replay.id, t.id);
        let dispatch = tasks.outbox("alpha", 2000).pop().unwrap();
        let running = tasks.claim(&dispatch, 2000).unwrap().unwrap();
        funding.spend(&running, 2000).unwrap();
        funding.spend(&running, 2000).unwrap();
        let done = tasks
            .finish(&t.id, running.fence, Outcome::Http(200), 2001)
            .unwrap();
        funding.settle(&done, 2001).unwrap();
        funding.settle(&done, 2001).unwrap();
        let before = serde_json::to_vec(&funding).unwrap();
        apply(&mut s, &i, &fixture(&i, "settled"), 2001).unwrap();
        s.sync_funding(&mut funding, cursor, 2001).unwrap();
        assert_eq!(serde_json::to_vec(&funding).unwrap(), before);
        let g = funding.grant(&i.id).unwrap();
        assert_eq!((g.available, g.reserved, g.spent, g.retired), (0, 0, 1, 9));
    }
}
#[test]
fn reversal_first_never_issues_entitlement_and_partial_refund_fails_closed() {
    let mut s = state();
    let i = intent(&mut s, "a");
    apply(&mut s, &i, &fixture(&i, "reversed"), 20).unwrap();
    settle(&mut s, &i);
    assert!(s
        .receipt("alpha", &i.id)
        .unwrap()
        .entitlement_order
        .is_none());
    let b = s
        .balance("alpha", &funding::State::default(), 0, 20)
        .unwrap();
    assert_eq!((b.available, b.retired), (0, 0));
    assert_eq!(b.spending.gross_committed_minor, 100);
    let mut s = state();
    let i = intent(&mut s, "a");
    settle(&mut s, &i);
    let mut f = fixture(&i, "reversed");
    f.event.amount_minor = 50;
    unchanged(&mut s, Error::Binding, |s| apply(s, &i, &f, 20));
    assert_eq!(
        s.balance("alpha", &funding::State::default(), 0, 20)
            .unwrap()
            .available,
        10
    );
}
#[test]
fn grant_journal_recovers_every_settlement_after_crash() {
    let mut s = state();
    let a = intent(&mut s, "a");
    let b = intent(&mut s, "b");
    settle(&mut s, &a);
    let mut f = fixture(&b, "settled");
    f.event.event_id = "fixture_b".into();
    f.event.kind = EventKind::Settled {
        payment_id: "fictional_payment_b".into(),
        paid_at_ms: 15,
    };
    apply(&mut s, &b, &f, 20).unwrap();
    let restored = OfflineLedger::restore(&s.snapshot().unwrap()).unwrap();
    let mut funding = funding::State::default();
    let cursor = restored.sync_funding(&mut funding, 0, 20).unwrap();
    assert_eq!(funding.grant(&a.id).unwrap().available, 10);
    assert_eq!(funding.grant(&b.id).unwrap().available, 10);
    let before = serde_json::to_vec(&funding).unwrap();
    assert_eq!(
        restored
            .balance("alpha", &funding, cursor, 20)
            .unwrap()
            .available,
        20
    );
    assert_eq!(serde_json::to_vec(&funding).unwrap(), before);
    // An old cursor with newer funding must fail closed, never overwrite/refill it.
    assert!(restored.sync_funding(&mut funding, 0, 20).is_err());
    assert_eq!(serde_json::to_vec(&funding).unwrap(), before);
}
#[test]
fn refund_does_not_replenish_a_purchase_cap() {
    let mut p = policy();
    p.project_window_minor = 100;
    let mut s = OfflineLedger::new("alpha", Some(p)).unwrap();
    let i = intent(&mut s, "a");
    settle(&mut s, &i);
    apply(&mut s, &i, &fixture(&i, "reversed"), 20).unwrap();
    unchanged(&mut s, Error::CapExceeded, |s| {
        s.create_intent(s.revision(), authority(), "b", 1, 20)
    });
}
#[test]
fn overflow_clock_rollback_and_invalid_policy_are_atomic() {
    let mut s = state();
    unchanged(&mut s, Error::Overflow, |s| {
        s.create_intent(s.revision(), authority(), "a", u64::MAX, 10)
    });
    let mut p = policy();
    p.offer.attempt_units = SAFE;
    let mut s = OfflineLedger::new("alpha", Some(p)).unwrap();
    unchanged(&mut s, Error::Overflow, |s| {
        s.create_intent(s.revision(), authority(), "a", 2, 10)
    });
    let _ = intent(&mut s, "b");
    unchanged(&mut s, Error::ClockRegressed, |s| {
        s.create_intent(s.revision(), authority(), "a", 1, 9)
    });
    let mut p = policy();
    p.ends_at_ms = SAFE as i64;
    p.offer.admission_ttl_ms = SAFE as i64;
    let mut s = OfflineLedger::new("alpha", Some(p)).unwrap();
    unchanged(&mut s, Error::Overflow, |s| {
        s.create_intent(s.revision(), authority(), "a", 1, 10)
    });
    for currency in ["", "USD", "usd\n"] {
        let mut p = policy();
        p.offer.currency = currency.into();
        assert_eq!(
            OfflineLedger::new("alpha", Some(p)).unwrap_err(),
            Error::Invalid
        );
    }
}
#[test]
fn corrupted_snapshots_and_future_cursors_fail_closed() {
    let mut s = state();
    let _ = intent(&mut s, "a");
    let mut bytes: Value = serde_json::from_slice(&s.snapshot().unwrap()).unwrap();
    bytes["project_id"] = json!("other");
    assert!(OfflineLedger::restore(&serde_json::to_vec(&bytes).unwrap()).is_err());
    assert_eq!(
        s.funding_updates(s.revision() + 1).unwrap_err(),
        Error::StaleRevision
    );
    let mut funding = funding::State::default();
    let foreign = funding::Policy {
        version: 1,
        project_id: "other".into(),
        revision: 1,
        active_grant: None,
        revoked_grants: vec![],
    };
    funding.apply(&foreign, 20).unwrap();
    assert!(s.balance("alpha", &funding, 1, 20).is_err());
}
#[test]
fn bounded_intent_tombstones_survive_unpaid_resolution() {
    let mut s = state();
    for n in 0..MAX_INTENTS {
        let i = intent(&mut s, &format!("intent_{n}"));
        let mut f = fixture(&i, "unpaid");
        f.event.event_id = format!("unpaid_{n}");
        f.event.observed_at_ms = 10;
        apply(&mut s, &i, &f, 10).unwrap();
    }
    unchanged(&mut s, Error::Capacity, |s| {
        s.create_intent(s.revision(), authority(), "too_many", 1, 10)
    });
}

#[test]
fn event_id_conflicts_and_concurrent_settlement_cannot_duplicate_credits() {
    let mut s = state();
    let i = intent(&mut s, "a");
    let revision = s.revision();
    let state = Arc::new(Mutex::new(s));
    let start = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let state = state.clone();
            let start = start.clone();
            let i = i.clone();
            std::thread::spawn(move || {
                let f = fixture(&i, "settled");
                start.wait();
                state
                    .lock()
                    .unwrap()
                    .reconcile(revision, "alpha", &i.id, &f.proof, &f, 20)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::StaleRevision)))
            .count(),
        1
    );
    let mut s = state.lock().unwrap();
    let mut f = fixture(&i, "settled");
    f.event.observed_at_ms = 19;
    unchanged(&mut s, Error::Conflict, |s| apply(s, &i, &f, 20));
    apply(&mut s, &i, &fixture(&i, "settled"), 20).unwrap();
    assert_eq!(
        s.balance("alpha", &funding::State::default(), 0, 20)
            .unwrap()
            .available,
        10
    );
}
#[test]
fn event_capacity_and_project_credit_counter_never_wrap() {
    let mut s = state();
    let i = intent(&mut s, "a");
    settle(&mut s, &i);
    for n in 1..MAX_EVENTS {
        let mut f = fixture(&i, "settled");
        f.event.event_id = format!("repeat_{n}");
        apply(&mut s, &i, &f, 20).unwrap();
    }
    let mut f = fixture(&i, "settled");
    f.event.event_id = "over_capacity".into();
    unchanged(&mut s, Error::Capacity, |s| apply(s, &i, &f, 20));
    // A previously recorded event remains replayable at capacity.
    apply(&mut s, &i, &fixture(&i, "settled"), 20).unwrap();
    let mut p = policy();
    p.offer.attempt_units = SAFE;
    let mut s = OfflineLedger::new("alpha", Some(p)).unwrap();
    let _ = intent(&mut s, "a");
    unchanged(&mut s, Error::Overflow, |s| {
        s.create_intent(s.revision(), authority(), "b", 1, 10)
    });
}

#[test]
fn immutable_quote_lookup_is_project_scoped_and_read_only_after_restore() {
    let mut s = state();
    let i = intent(&mut s, "quote_lookup");
    let restored = OfflineLedger::restore(&s.snapshot().unwrap()).unwrap();
    let before = restored.snapshot().unwrap();
    assert_eq!(restored.intent("alpha", &i.id), Ok(&i));
    assert_eq!(restored.intent("foreign", &i.id), Err(Error::Forbidden));
    assert_eq!(restored.intent("foreign", "missing"), Err(Error::Forbidden));
    assert_eq!(restored.intent("alpha", "missing"), Err(Error::Invalid));
    assert_eq!(restored.snapshot().unwrap(), before);
}
