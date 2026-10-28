use runlater::{
    application::{self, Query},
    core::*,
    metrics::{Kind, Metrics, MAX_COUNT, MINUTE_MS},
};
fn input() -> Create {
    Create {
        destination: "fixture://success".into(),
        body: "private_payload".into(),
        operation_key: "private_operation".into(),
        run_at_ms: 0,
    }
}
fn count(l: &Ledger, key: &str) -> u64 {
    l.metrics.view(0)["totals"]["counts"][key].as_u64().unwrap()
}
fn reference(t: &Task) -> Dispatch {
    Dispatch {
        tenant: "alpha".into(),
        id: t.id.clone(),
        generation: t.generation,
    }
}
#[test]
fn quotas_do_not_create_tasks_or_spend_dispatch_capacity_and_replays_bypass_denial() {
    let mut l = Ledger::default();
    let mut limits = l.limits.clone();
    limits.max_active_tasks = 1;
    l.configure(limits, 0).unwrap();
    let (t, _) = l.create("a", input(), 0).unwrap();
    let task_state = serde_json::to_value((&l.tasks, &l.dedupe, l.sequence, &l.bucket)).unwrap();
    assert!(l.create("b", input(), 0).is_err());
    assert_eq!(count(&l, "admission_active_tasks_denied"), 1);
    assert_eq!(
        serde_json::to_value((&l.tasks, &l.dedupe, l.sequence, &l.bucket)).unwrap(),
        task_state
    );
    assert_eq!(l.create("a", input(), 0).unwrap().0.id, t.id);
    assert_eq!(count(&l, "admission_active_tasks_denied"), 1);
    let mut p = Ledger::default();
    let mut limits = p.limits.clone();
    limits.max_payload_bytes = 1;
    p.configure(limits, 0).unwrap();
    assert!(p.create("payload", input(), 0).is_err());
    assert_eq!(count(&p, "admission_payload_denied"), 1);
    assert!(p.tasks.is_empty());
    assert!(p.dedupe.is_empty());
    let mut full = Ledger::default();
    for i in 0..1000 {
        full.create(&format!("k{i}"), input(), 0).unwrap();
    }
    assert!(full.create("extra", input(), 0).is_err());
    assert_eq!(count(&full, "admission_retained_tasks_denied"), 1);
}
#[test]
fn duplicate_claims_concurrency_and_stale_results_are_not_logical_attempt_errors() {
    let mut l = Ledger::default();
    let mut limits = l.limits.clone();
    limits.max_concurrent = 1;
    l.configure(limits, 0).unwrap();
    let (a, _) = l.create("a", input(), 0).unwrap();
    let (b, _) = l.create("b", input(), 0).unwrap();
    let running = l.claim(&reference(&a), 0).unwrap().unwrap();
    let tokens = serde_json::to_value(&l.bucket).unwrap();
    assert!(l.claim(&reference(&a), 0).unwrap().is_none());
    assert!(l.claim(&reference(&b), 0).is_err());
    assert_eq!(serde_json::to_value(&l.bucket).unwrap(), tokens);
    assert!(l.finish(&a.id, 0, Outcome::Http(503), 1).is_err());
    l.finish(&a.id, running.fence, Outcome::Http(204), 1)
        .unwrap();
    let v = l.metrics.view(1);
    assert_eq!(v["totals"]["attempt_completed"], 1);
    assert_eq!(v["totals"]["attempt_error_ratio"], 0.0);
    for (k, n) in [
        ("claim_references", 3),
        ("claim_ignored", 1),
        ("claim_concurrency_denied", 1),
        ("attempt_started", 1),
        ("attempt_succeeded", 1),
        ("stale_results_ignored", 1),
    ] {
        assert_eq!(count(&l, k), n);
    }
}
#[test]
fn dispatch_rate_rejection_has_no_attempt_or_extra_token_debit() {
    let mut l = Ledger::default();
    let mut limits = l.limits.clone();
    limits.dispatch_burst = 1;
    limits.dispatch_per_second = 1;
    l.configure(limits, 0).unwrap();
    let (a, _) = l.create("a", input(), 0).unwrap();
    let (b, _) = l.create("b", input(), 0).unwrap();
    l.claim(&reference(&a), 0).unwrap();
    let before = serde_json::to_value(&l.bucket).unwrap();
    assert!(l.claim(&reference(&b), 0).is_err());
    assert_eq!(serde_json::to_value(&l.bucket).unwrap(), before);
    assert!(l.get(&b.id).unwrap().attempts.is_empty());
    assert_eq!(count(&l, "claim_rate_denied"), 1);
    assert_eq!(count(&l, "attempt_started"), 1);
}
#[test]
fn lease_reconciliation_records_one_unknown_outcome_and_age_expiry_is_not_an_attempt() {
    let mut l = Ledger::default();
    let (t, _) = l.create("a", input(), 0).unwrap();
    let running = l.claim(&reference(&t), 0).unwrap().unwrap();
    let before = serde_json::to_value(&l).unwrap();
    let v = application::query(
        &l,
        Query::Metrics {
            sampled_at_ms: LEASE,
        },
    )
    .unwrap();
    assert_eq!(v["totals"]["attempt_completed"], 0);
    assert_eq!(serde_json::to_value(&l).unwrap(), before);
    l.reconcile(LEASE);
    l.reconcile(LEASE + 1);
    assert_eq!(count(&l, "attempt_lease_expired_unknown"), 1);
    assert!(l
        .finish(&t.id, running.fence, Outcome::Http(204), LEASE + 1)
        .is_err());
    assert_eq!(l.metrics.view(LEASE)["totals"]["attempt_completed"], 1);
    let mut age = Ledger::default();
    let (t, _) = age.create("old", input(), 0).unwrap();
    assert!(age.claim(&reference(&t), DAY + 1).unwrap().is_none());
    assert_eq!(count(&age, "claim_age_expired"), 1);
    assert_eq!(age.metrics.view(DAY + 1)["totals"]["attempt_completed"], 0);
    let missing = Dispatch {
        tenant: "alpha".into(),
        id: "task_ffffffffffffffff".into(),
        generation: 1,
    };
    assert!(age.claim(&missing, DAY + 1).is_err());
    assert_eq!(count(&age, "claim_missing"), 1);
}
#[test]
fn fixed_window_boundaries_expire_logically_and_queries_are_pure() {
    let mut m = Metrics::default();
    m.observe(Kind::AttemptSucceeded, MINUTE_MS - 1);
    m.observe(Kind::AttemptRetryableHttp, MINUTE_MS);
    let before = serde_json::to_value(&m).unwrap();
    let view = m.view(MINUTE_MS);
    assert_eq!(view["windows"][0]["start_inclusive_ms"], MINUTE_MS);
    assert_eq!(
        view["windows"][0]["observations"]["counts"]["attempt_succeeded"],
        0
    );
    assert_eq!(
        view["windows"][1]["observations"]["attempt_error_ratio"],
        0.5
    );
    assert_eq!(
        m.view(5 * MINUTE_MS)["windows"][1]["observations"]["counts"]["attempt_succeeded"],
        0
    );
    assert_eq!(
        m.view(61 * MINUTE_MS)["windows"][2]["observations"]["attempt_completed"],
        0
    );
    assert_eq!(serde_json::to_value(&m).unwrap(), before);
    m.observe(Kind::ClaimMissing, 61 * MINUTE_MS);
    assert_eq!(
        serde_json::to_value(&m).unwrap()["buckets"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(m.view(61 * MINUTE_MS)["totals"]["attempt_completed"], 2);
}
#[test]
fn rollback_restart_bounded_storage_and_saturation_are_explicit() {
    let mut m = Metrics::default();
    m.observe(Kind::AttemptSucceeded, 2 * MINUTE_MS);
    m.observe(Kind::AttemptTimeout, MINUTE_MS);
    let before = serde_json::to_value(&m).unwrap();
    let m: Metrics = serde_json::from_value(before.clone()).unwrap();
    let view = m.view(MINUTE_MS);
    assert_eq!(view["sampled_at_ms"], MINUTE_MS);
    assert_eq!(view["effective_sample_ms"], 2 * MINUTE_MS);
    assert_eq!(view["clock_regressed"], true);
    assert_eq!(view["totals"]["counts"]["clock_regressed_observations"], 1);
    assert_eq!(serde_json::to_value(&m).unwrap(), before);
    let mut m = Metrics::default();
    for i in 0..200 {
        m.observe(Kind::ClaimReferences, i * MINUTE_MS);
    }
    assert_eq!(
        serde_json::to_value(&m).unwrap()["buckets"]
            .as_array()
            .unwrap()
            .len(),
        60
    );
    let mut v = serde_json::to_value(&m).unwrap();
    v["totals"]["values"]["attempt_succeeded"] = serde_json::json!(MAX_COUNT);
    let mut m: Metrics = serde_json::from_value(v).unwrap();
    m.observe(Kind::AttemptSucceeded, 200 * MINUTE_MS);
    assert_eq!(m.view(200 * MINUTE_MS)["totals"]["saturated"], true);
    assert!(m.view(200 * MINUTE_MS)["totals"]["attempt_error_ratio"].is_null());
}
#[test]
fn migration_tenant_isolation_redaction_and_read_scope() {
    let mut alpha = Ledger::default();
    alpha.metrics.observe(Kind::ClaimRateDenied, 0);
    let beta = Ledger::default();
    assert_eq!(count(&beta, "claim_rate_denied"), 0);
    let mut state = serde_json::to_value(&alpha).unwrap();
    state.as_object_mut().unwrap().remove("metrics");
    let migrated: Ledger = serde_json::from_value(state).unwrap();
    assert_eq!(count(&migrated, "claim_rate_denied"), 0);
    let view = application::query(&alpha, Query::Metrics { sampled_at_ms: 0 })
        .unwrap()
        .to_string();
    for private in [
        "private_payload",
        "private_operation",
        "fixture://success",
        "alpha",
    ] {
        assert!(!view.contains(private));
    }
    assert_eq!(
        runlater::auth::required_permission("GET", "/v1/queue/metrics"),
        Some(runlater::auth::Permission::Read)
    );
}
