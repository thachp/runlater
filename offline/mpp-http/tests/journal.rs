use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use runlater_offline_credit_purchases::{self as credit, Authority, Intent, OfflineLedger};
use runlater_offline_mpp_http::{journal::*, *};
use serde_json::{json, Value};
use std::sync::{Arc, Barrier, Mutex};

fn fixture() -> Value {
    let v: Value =
        serde_json::from_str(include_str!("../fixtures/reconciliation-fiction.json")).unwrap();
    assert_eq!(v["fixture_only"], true);
    v
}
fn text(key: &str) -> String {
    fixture()[key].as_str().unwrap().into()
}
fn time(key: &str) -> i64 {
    fixture()[key].as_i64().unwrap()
}
fn context() -> OfflineMerchantContext {
    OfflineMerchantContext {
        realm: "offline.example.invalid".into(),
        network_id: "profile_OFFLINE_FICTION".into(),
        payment_method_types: vec!["card".into()],
    }
}
fn ledger(project: &str) -> OfflineLedger {
    OfflineLedger::new(
        project,
        Some(credit::Policy {
            version: 7,
            offer: credit::Offer {
                id: "offline_offer".into(),
                amount_minor: 100,
                currency: "xxx".into(),
                attempt_units: 10,
                quote_ttl_ms: 60_000,
                admission_ttl_ms: 600_000,
            },
            starts_at_ms: time("issued_at_ms"),
            ends_at_ms: time("issued_at_ms") + 3_600_000,
            project_window_minor: 100_000,
            purchasers: [(
                text("principal"),
                credit::DelegateCap {
                    per_purchase_minor: 1000,
                    window_minor: 100_000,
                },
            )]
            .into(),
        }),
    )
    .unwrap()
}
fn purchase(ledger: &mut OfflineLedger, project: &str, key: &str) -> Intent {
    ledger
        .create_intent(
            ledger.revision(),
            Authority::Purchase {
                project,
                principal: &text("principal"),
            },
            key,
            1,
            time("issued_at_ms"),
        )
        .unwrap()
}
fn issue(j: &mut OfflineJournal, ledger: &OfflineLedger, q: &Intent, id: &str) -> Challenge {
    j.issue(
        j.revision(),
        ledger,
        &q.project_id,
        &q.id,
        context(),
        id,
        text("body").as_bytes(),
        CredentialField::Authorization,
        time("issued_at_ms"),
    )
    .unwrap()
}
fn wire(challenge: &Challenge, token: &str) -> String {
    format!(
        "Payment {}",
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "challenge": challenge, "payload": {"spt": token},
            }))
            .unwrap()
        )
    )
}
fn bind(j: &mut OfflineJournal, ledger: &OfflineLedger, q: &Intent, c: &Challenge) -> Submission {
    j.bind(
        j.revision(),
        ledger,
        &q.project_id,
        &c.id,
        &[("Authorization", &wire(c, &text("token")))],
        text("body").as_bytes(),
        time("bound_at_ms"),
    )
    .unwrap()
}
fn setup() -> (OfflineLedger, Intent, OfflineJournal, Challenge) {
    let mut l = ledger(&text("project"));
    let q = purchase(&mut l, &text("project"), "offline_key_a");
    let mut j = OfflineJournal::new();
    let c = issue(&mut j, &l, &q, &text("challenge_id"));
    (l, q, j, c)
}
fn unchanged<T: std::fmt::Debug>(
    j: &mut OfflineJournal,
    expected: JournalError,
    f: impl FnOnce(&mut OfflineJournal) -> Result<T, JournalError>,
) {
    let before = j.snapshot().unwrap();
    assert_eq!(f(j).unwrap_err(), expected);
    assert_eq!(j.snapshot().unwrap(), before);
}
// Only this integration-test-local allowlist can produce the synthetic facts.
// Production code still ships only DisabledVerifier; neither journal nor codec verifies.
struct FixtureVerifier {
    proof: Vec<u8>,
    event: credit::VerifiedEvent,
}
impl credit::SettlementVerifier for FixtureVerifier {
    fn verify(
        &self,
        intent: &Intent,
        evidence: &[u8],
    ) -> Result<credit::VerifiedEvent, credit::Error> {
        if evidence != self.proof || intent.digest() != self.event.intent_digest {
            return Err(credit::Error::Unverified);
        }
        Ok(self.event.clone())
    }
}
fn event(q: &Intent, kind: &str) -> FixtureVerifier {
    let f = fixture();
    FixtureVerifier {
        proof: f["events"][kind]["proof"]
            .as_str()
            .unwrap()
            .as_bytes()
            .to_vec(),
        event: credit::VerifiedEvent {
            fixture_only: true,
            event_id: f["events"][kind]["id"].as_str().unwrap().into(),
            project_id: q.project_id.clone(),
            intent_id: q.id.clone(),
            intent_digest: q.digest(),
            amount_minor: q.amount_minor,
            currency: q.currency.clone(),
            observed_at_ms: time("reconciled_at_ms"),
            kind: match kind {
                "settled" => credit::EventKind::Settled {
                    payment_id: text("payment_id"),
                    paid_at_ms: time("paid_at_ms"),
                },
                "reversed" => credit::EventKind::Reversed {
                    payment_id: text("payment_id"),
                    reason: credit::Reversal::FullRefund,
                },
                "unpaid" => credit::EventKind::NoPaymentFinal,
                _ => panic!("not an allowlisted fixture"),
            },
        },
    }
}
fn reconcile(l: &mut OfflineLedger, q: &Intent, kind: &str) -> credit::Receipt {
    let f = event(q, kind);
    l.reconcile(
        l.revision(),
        &q.project_id,
        &q.id,
        &f.proof,
        &f,
        time("reconciled_at_ms"),
    )
    .unwrap()
}

#[test]
fn restart_retains_challenge_and_first_provider_identity_without_credential_material() {
    let (l, q, mut j, c) = setup();
    assert_eq!(
        j.recovery(&l, &q.project_id, &c.id).unwrap().state,
        RecoveryState::Unbound
    );
    j = OfflineJournal::restore(&j.snapshot().unwrap()).unwrap();
    assert_eq!(issue(&mut j, &l, &q, &c.id), c);
    let s = bind(&mut j, &l, &q, &c);
    let standalone = IssuedChallenge::offline(
        &q,
        context(),
        &c.id,
        text("body").as_bytes(),
        CredentialField::Authorization,
    )
    .unwrap()
    .prepare(
        &q,
        &q.project_id,
        &[("Authorization", &wire(&c, &text("token")))],
        text("body").as_bytes(),
        time("bound_at_ms"),
    )
    .unwrap();
    assert_eq!(s.provider_idempotency_key, standalone.idempotency_key());
    let snapshot = j.snapshot().unwrap();
    let encoded = std::str::from_utf8(&snapshot).unwrap();
    assert!(!encoded.contains(&text("token")));
    assert!(!encoded.contains(&text("body")));
    assert!(!format!("{j:?}").contains(&q.id));
    j = OfflineJournal::restore(&snapshot).unwrap();
    assert_eq!(bind(&mut j, &l, &q, &c), s);
    assert_eq!(j.snapshot().unwrap(), snapshot);
    let recovery = j.recovery(&l, &q.project_id, &c.id).unwrap();
    assert_eq!(recovery.state, RecoveryState::ReconcileRequired);
    assert_eq!(recovery.submission.unwrap(), s);
    assert!(recovery.fixture_only);
    assert!(!recovery.activation_enabled);
}

#[test]
fn one_challenge_per_cap_reserved_purchase_and_exact_replay_never_rotates_it() {
    let (l, q, mut j, c) = setup();
    unchanged(&mut j, JournalError::Conflict, |j| {
        j.issue(
            j.revision(),
            &l,
            &q.project_id,
            &q.id,
            context(),
            "offline_different_id",
            text("body").as_bytes(),
            CredentialField::Authorization,
            time("issued_at_ms"),
        )
    });
    unchanged(&mut j, JournalError::Conflict, |j| {
        j.issue(
            j.revision(),
            &l,
            &q.project_id,
            &q.id,
            context(),
            &c.id,
            b"changed body",
            CredentialField::Authorization,
            time("issued_at_ms"),
        )
    });
    let mut different_context = context();
    different_context.network_id = "profile_OTHER_OFFLINE".into();
    unchanged(&mut j, JournalError::Conflict, |j| {
        j.issue(
            j.revision(),
            &l,
            &q.project_id,
            &q.id,
            different_context,
            &c.id,
            text("body").as_bytes(),
            CredentialField::Authorization,
            time("issued_at_ms"),
        )
    });
    unchanged(&mut j, JournalError::Conflict, |j| {
        j.issue(
            j.revision(),
            &l,
            &q.project_id,
            &q.id,
            context(),
            &c.id,
            text("body").as_bytes(),
            CredentialField::PaymentAuthorization,
            time("issued_at_ms"),
        )
    });
    let before = j.snapshot().unwrap();
    assert_eq!(
        j.issue(
            j.revision(),
            &l,
            &q.project_id,
            &q.id,
            context(),
            &c.id,
            text("body").as_bytes(),
            CredentialField::Authorization,
            q.expires_at_ms + 1
        )
        .unwrap(),
        c
    );
    assert_eq!(j.snapshot().unwrap(), before);
    let mut fresh = OfflineJournal::new();
    unchanged(&mut fresh, JournalError::Codec(Error::Expired), |j| {
        j.issue(
            j.revision(),
            &l,
            &q.project_id,
            &q.id,
            context(),
            &c.id,
            text("body").as_bytes(),
            CredentialField::Authorization,
            q.expires_at_ms,
        )
    });
    unchanged(
        &mut fresh,
        JournalError::Purchase(credit::Error::Forbidden),
        |j| {
            j.issue(
                j.revision(),
                &l,
                "foreign_project",
                &q.id,
                context(),
                &c.id,
                b"",
                CredentialField::Authorization,
                time("issued_at_ms"),
            )
        },
    );
}

#[test]
fn changed_credentials_and_cross_project_token_reuse_conflict_even_after_restart() {
    let (l, q, mut j, c) = setup();
    let mut other = ledger("offline_other_project");
    let q2 = purchase(&mut other, "offline_other_project", "offline_key_a");
    // Both reservations must exist before binding advances the journal's clock.
    let c2 = issue(&mut j, &other, &q2, "offline_challenge_b");
    bind(&mut j, &l, &q, &c);
    j = OfflineJournal::restore(&j.snapshot().unwrap()).unwrap();
    unchanged(&mut j, JournalError::Conflict, |j| {
        j.bind(
            j.revision(),
            &l,
            &q.project_id,
            &c.id,
            &[("Authorization", &wire(&c, "spt_DIFFERENT_OFFLINE_FICTION"))],
            text("body").as_bytes(),
            time("bound_at_ms"),
        )
    });
    unchanged(&mut j, JournalError::Conflict, |j| {
        j.bind(
            j.revision(),
            &other,
            &q2.project_id,
            &c2.id,
            &[("Authorization", &wire(&c2, &text("token")))],
            text("body").as_bytes(),
            time("bound_at_ms"),
        )
    });
    assert_eq!(
        j.recovery(&other, &q2.project_id, &c2.id).unwrap().state,
        RecoveryState::Unbound
    );
    assert!(j.recovery(&other, &q2.project_id, &c.id).is_err());
}

#[test]
fn expired_unknown_outcome_keeps_hold_and_uses_original_key_for_late_reconciliation() {
    let (mut l, q, mut j, c) = setup();
    let submission = bind(&mut j, &l, &q, &c);
    // Crash after the durable handoff; provider outcome is deliberately not in
    // either snapshot. This is the same state for timeout or lost response.
    l = OfflineLedger::restore(&l.snapshot().unwrap()).unwrap();
    j = OfflineJournal::restore(&j.snapshot().unwrap()).unwrap();
    assert_eq!(l.cap_balance(None).unwrap().pending_minor, q.amount_minor);
    unchanged(&mut j, JournalError::Codec(Error::Expired), |j| {
        j.bind(
            j.revision(),
            &l,
            &q.project_id,
            &c.id,
            &[("Authorization", &wire(&c, &text("token")))],
            text("body").as_bytes(),
            time("reconciled_at_ms"),
        )
    });
    assert_eq!(
        j.recovery(&l, &q.project_id, &c.id)
            .unwrap()
            .submission
            .unwrap(),
        submission
    );
    let r = reconcile(&mut l, &q, "settled");
    assert!(r.entitlement_order.is_some());
    let before = l.snapshot().unwrap();
    assert_eq!(reconcile(&mut l, &q, "settled"), r);
    assert_eq!(l.snapshot().unwrap(), before);
    let recovery = j.recovery(&l, &q.project_id, &c.id).unwrap();
    assert_eq!(recovery.state, RecoveryState::LedgerRecorded);
    assert_eq!(recovery.receipt, r);
    assert_eq!(recovery.submission.unwrap(), submission);
    assert!(!recovery.activation_enabled);
    assert_eq!(l.cap_balance(None).unwrap().pending_minor, 0);
    assert_eq!(
        l.cap_balance(None).unwrap().gross_committed_minor,
        q.amount_minor
    );
    unchanged(&mut j, JournalError::Completed, |j| {
        j.bind(
            j.revision(),
            &l,
            &q.project_id,
            &c.id,
            &[("Authorization", &wire(&c, &text("token")))],
            text("body").as_bytes(),
            time("reconciled_at_ms"),
        )
    });
}

#[test]
fn reversal_before_settlement_survives_restart_and_never_issues_an_entitlement() {
    let (mut l, q, mut j, c) = setup();
    bind(&mut j, &l, &q, &c);
    reconcile(&mut l, &q, "reversed");
    l = OfflineLedger::restore(&l.snapshot().unwrap()).unwrap();
    let r = reconcile(&mut l, &q, "settled");
    assert!(r.entitlement_order.is_none());
    assert_eq!(r.reversed, Some(credit::Reversal::FullRefund));
    let recovery = j.recovery(&l, &q.project_id, &c.id).unwrap();
    assert_eq!(recovery.state, RecoveryState::LedgerRecorded);
    assert!(!recovery.activation_enabled);
    assert_eq!(recovery.receipt, r);
    assert!(l
        .funding_updates(0)
        .unwrap()
        .iter()
        .all(|p| p.active_grant.is_none()));
}

#[test]
fn no_payment_finality_does_not_erase_the_used_credential_or_allow_reissuance() {
    let (mut l, q, mut j, c) = setup();
    let mut other = ledger("offline_other_project");
    let q2 = purchase(&mut other, "offline_other_project", "offline_key_a");
    let c2 = issue(&mut j, &other, &q2, "offline_challenge_b");
    bind(&mut j, &l, &q, &c);
    let r = reconcile(&mut l, &q, "unpaid");
    assert!(r.no_payment_final);
    assert_eq!(l.cap_balance(None).unwrap().pending_minor, 0);
    j = OfflineJournal::restore(&j.snapshot().unwrap()).unwrap();
    unchanged(&mut j, JournalError::Conflict, |j| {
        j.bind(
            j.revision(),
            &other,
            &q2.project_id,
            &c2.id,
            &[("Authorization", &wire(&c2, &text("token")))],
            text("body").as_bytes(),
            time("bound_at_ms"),
        )
    });
    let mut fresh = OfflineJournal::new();
    unchanged(&mut fresh, JournalError::Completed, |j| {
        j.issue(
            j.revision(),
            &l,
            &q.project_id,
            &q.id,
            context(),
            "offline_reissue",
            text("body").as_bytes(),
            CredentialField::Authorization,
            time("reconciled_at_ms"),
        )
    });
    let f = event(&q, "settled");
    assert_eq!(
        l.reconcile(
            l.revision(),
            &q.project_id,
            &q.id,
            &f.proof,
            &f,
            time("reconciled_at_ms")
        ),
        Err(credit::Error::Conflict)
    );
}

#[test]
fn disabled_verifier_rejects_journal_and_fabricated_success_without_granting_credit() {
    let (mut l, q, mut j, c) = setup();
    bind(&mut j, &l, &q, &c);
    for evidence in [
        j.snapshot().unwrap(),
        br#"{"status":"succeeded","paid":true}"#.to_vec(),
    ] {
        let before = l.snapshot().unwrap();
        assert_eq!(
            l.reconcile(
                l.revision(),
                &q.project_id,
                &q.id,
                &evidence,
                &credit::DisabledVerifier,
                time("reconciled_at_ms")
            ),
            Err(credit::Error::Disabled)
        );
        assert_eq!(l.snapshot().unwrap(), before);
    }
    assert!(l
        .funding_updates(0)
        .unwrap()
        .iter()
        .all(|p| p.active_grant.is_none()));
    assert_eq!(
        j.recovery(&l, &q.project_id, &c.id).unwrap().state,
        RecoveryState::ReconcileRequired
    );
}

#[test]
fn concurrent_credentials_get_one_durable_winner_and_stale_writers_cannot_replace_it() {
    let (l, q, j, c) = setup();
    let expected = j.revision();
    let state = Arc::new(Mutex::new(j));
    let barrier = Arc::new(Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let state = state.clone();
            let barrier = barrier.clone();
            let l = l.clone();
            let q = q.clone();
            let c = c.clone();
            std::thread::spawn(move || {
                let token = format!("spt_OFFLINE_RACING_FIXTURE_{i}");
                let wire = wire(&c, &token);
                barrier.wait();
                state.lock().unwrap().bind(
                    expected,
                    &l,
                    &q.project_id,
                    &c.id,
                    &[("Authorization", &wire)],
                    text("body").as_bytes(),
                    time("bound_at_ms"),
                )
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == Err(JournalError::StaleRevision))
            .count(),
        15
    );
    let j = state.lock().unwrap();
    assert_eq!(j.revision(), expected + 1);
    let restored = OfflineJournal::restore(&j.snapshot().unwrap()).unwrap();
    assert_eq!(
        restored
            .recovery(&l, &q.project_id, &c.id)
            .unwrap()
            .submission,
        results.into_iter().find_map(Result::ok)
    );
}

#[test]
fn malformed_bindings_stale_revisions_and_clock_regression_leave_no_tombstone() {
    let (l, q, mut j, c) = setup();
    unchanged(&mut j, JournalError::StaleRevision, |j| {
        j.bind(1, &l, &q.project_id, &c.id, &[], b"", time("bound_at_ms"))
    });
    unchanged(&mut j, JournalError::ClockRegressed, |j| {
        j.bind(
            j.revision(),
            &l,
            &q.project_id,
            &c.id,
            &[],
            b"",
            time("issued_at_ms") - 1,
        )
    });
    unchanged(&mut j, JournalError::Codec(Error::Binding), |j| {
        j.bind(
            j.revision(),
            &l,
            &q.project_id,
            &c.id,
            &[("Authorization", &wire(&c, &text("token")))],
            b"wrong body",
            time("bound_at_ms"),
        )
    });
    unchanged(&mut j, JournalError::Codec(Error::WrongHeader), |j| {
        j.bind(
            j.revision(),
            &l,
            &q.project_id,
            &c.id,
            &[("Payment-Authorization", &wire(&c, &text("token")))],
            text("body").as_bytes(),
            time("bound_at_ms"),
        )
    });
    assert_eq!(
        j.recovery(&l, &q.project_id, &c.id).unwrap().state,
        RecoveryState::Unbound
    );
    bind(&mut j, &l, &q, &c);
}

#[test]
fn trusted_snapshot_restore_rejects_corrupt_bindings_and_bounds() {
    let (l, q, mut j, c) = setup();
    bind(&mut j, &l, &q, &c);
    let original: Value = serde_json::from_slice(&j.snapshot().unwrap()).unwrap();
    let mutations: Vec<Box<dyn Fn(&mut Value)>> = vec![
        Box::new(|s| s["schema"] = json!(2)),
        Box::new(|s| s["fixture_only"] = json!(false)),
        Box::new(|s| s["revision"] = json!(100)),
        Box::new(|s| s["clock_ms"] = json!(0)),
        Box::new(|s| s["extra"] = json!(true)),
        Box::new(|s| {
            s["entries"][text("challenge_id")]["challenge"]["realm"] = json!("changed.invalid")
        }),
        Box::new(|s| s["entries"][text("challenge_id")]["intent"]["amount_minor"] = json!(101)),
        Box::new(|s| s["entries"][text("challenge_id")]["intent"]["policy_version"] = json!(8)),
        Box::new(|s| s["entries"][text("challenge_id")]["challenge"]["digest"] = Value::Null),
        Box::new(|s| {
            s["entries"][text("challenge_id")]["submission"]["provider_idempotency_key"] =
                json!("changed_key")
        }),
        Box::new(|s| {
            s["entries"][text("challenge_id")]["submission"]["credential_fingerprint"] =
                json!("not_a_digest")
        }),
        Box::new(|s| {
            s["entries"][text("challenge_id")]["submission"]["bound_at_ms"] =
                json!(time("reconciled_at_ms"))
        }),
    ];
    for mutation in mutations {
        let mut s = original.clone();
        mutation(&mut s);
        assert_eq!(
            OfflineJournal::restore(&serde_json::to_vec(&s).unwrap()).unwrap_err(),
            JournalError::Corrupt
        );
    }
    let mut duplicate = original.clone();
    duplicate["entries"] = json!({});
    let prefix = serde_json::to_string(&duplicate).unwrap();
    let entry = serde_json::to_string(&original["entries"][text("challenge_id")]).unwrap();
    let entries = format!(
        "\"entries\":{{\"{}\":{},\"{}\":{}}}",
        text("challenge_id"),
        entry,
        text("challenge_id"),
        entry
    );
    let duplicated = prefix.replace("\"entries\":{}", &entries);
    assert_eq!(
        OfflineJournal::restore(duplicated.as_bytes()).unwrap_err(),
        JournalError::Corrupt
    );
    assert_eq!(
        OfflineJournal::restore(&vec![0; MAX_SNAPSHOT + 1]).unwrap_err(),
        JournalError::Capacity
    );
    assert_eq!(
        OfflineJournal::restore(b"{").unwrap_err(),
        JournalError::Corrupt
    );
}

#[test]
fn lifetime_capacity_never_recycles_old_quotes() {
    let project = text("project");
    let mut l = ledger(&project);
    let mut j = OfflineJournal::new();
    for n in 0..MAX_CHALLENGES {
        let q = purchase(&mut l, &project, &format!("offline_key_{n}"));
        issue(&mut j, &l, &q, &format!("offline_challenge_{n}"));
    }
    let mut other = ledger("offline_other_project");
    let q = purchase(&mut other, "offline_other_project", "offline_key_overflow");
    unchanged(&mut j, JournalError::Capacity, |j| {
        j.issue(
            j.revision(),
            &other,
            &q.project_id,
            &q.id,
            context(),
            "offline_overflow",
            text("body").as_bytes(),
            CredentialField::Authorization,
            time("issued_at_ms"),
        )
    });
    assert!(OfflineJournal::restore(&j.snapshot().unwrap()).is_ok());
}

#[test]
fn lost_issuance_response_recovers_by_purchase_key_without_allocating_a_new_challenge() {
    let (l, q, j, c) = setup();
    let ledger_bytes = l.snapshot().unwrap();
    let journal_bytes = j.snapshot().unwrap();
    let expected_header = c.to_header().unwrap();
    // Drop the original live state and challenge ID, as on process restart before
    // returning the issuance response. Only the caller's purchase key is known.
    drop((l, j, c, q));
    let mut l = OfflineLedger::restore(&ledger_bytes).unwrap();
    let j = OfflineJournal::restore(&journal_bytes).unwrap();
    let q = l
        .create_intent(
            l.revision(),
            Authority::Purchase {
                project: &text("project"),
                principal: &text("principal"),
            },
            "offline_key_a",
            1,
            time("reconciled_at_ms"),
        )
        .unwrap();
    let recovered = j.challenge_for_purchase(&l, &q.project_id, &q.id).unwrap();
    assert_eq!(recovered.to_header().unwrap(), expected_header);
    assert_eq!(
        j.recovery(&l, &q.project_id, &recovered.id).unwrap().state,
        RecoveryState::Unbound
    );
    assert_eq!(j.snapshot().unwrap(), journal_bytes);
    assert_eq!(
        j.challenge_for_purchase(&l, "foreign_project", &q.id),
        Err(JournalError::Purchase(credit::Error::Forbidden))
    );
    assert_eq!(
        OfflineJournal::new().challenge_for_purchase(&l, &q.project_id, &q.id),
        Err(JournalError::Missing)
    );
}
