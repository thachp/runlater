use runlater::{
    application::{self, Command, Query},
    core::*,
    limits::QueueLimits,
    security::{task_id_valid, tenant_valid},
};
fn input() -> Create {
    Create {
        destination: "fixture://success".into(),
        body: "data".into(),
        run_at_ms: 0,
        operation_key: "op".into(),
    }
}
fn restart(l: &Ledger) -> Ledger {
    serde_json::from_str(&serde_json::to_string(l).unwrap()).unwrap()
}
fn configured() -> Ledger {
    let mut l = Ledger::default();
    l.configure(
        QueueLimits {
            max_active_tasks: 10,
            max_payload_bytes: 1024,
            max_concurrent: 1,
            dispatch_per_second: 1,
            dispatch_burst: 1,
        },
        0,
    )
    .unwrap();
    l
}
#[test]
fn admission_is_configurable_but_idempotent_replays_bypass_new_limits() {
    let mut l = configured();
    let (t, _) = l.create("one", input(), 0).unwrap();
    l.configure(
        QueueLimits {
            max_active_tasks: 1,
            ..l.limits.clone()
        },
        0,
    )
    .unwrap();
    assert!(!l.create("one", input(), 1).unwrap().1);
    assert_eq!(
        l.create("two", input(), 1).unwrap_err(),
        Fault::Limited {
            reason: LimitReason::ActiveTasks,
            retry_after_ms: 1000
        }
    );
    l.cancel(&t.id, 1).unwrap();
    assert!(l.create("two", input(), 1).is_ok());
}
#[test]
fn retained_payload_counts_against_admission() {
    let mut l = configured();
    l.configure(
        QueueLimits {
            max_payload_bytes: 4,
            ..l.limits.clone()
        },
        0,
    )
    .unwrap();
    let (t, _) = l.create("one", input(), 0).unwrap();
    l.cancel(&t.id, 1).unwrap();
    assert_eq!(
        l.create("two", input(), 1).unwrap_err(),
        Fault::Limited {
            reason: LimitReason::PayloadBytes,
            retry_after_ms: 1000
        }
    );
    l.purge(RETENTION + 1);
    assert!(l.create("two", input(), RETENTION + 1).is_ok());
}
#[test]
fn limiter_survives_restart_does_not_refund_on_finish_or_duplicate() {
    let mut l = configured();
    l.create("one", input(), 0).unwrap();
    l.create("two", input(), 0).unwrap();
    let d = l.outbox("a", 0);
    let t = l.claim(&d[0], 0).unwrap().unwrap();
    l.finish(&t.id, t.fence, Outcome::Http(204), 1).unwrap();
    let mut l = restart(&l);
    assert!(l.claim(&d[0], 2).unwrap().is_none());
    assert_eq!(
        l.claim(&d[1], 2).unwrap_err(),
        Fault::Limited {
            reason: LimitReason::DispatchRate,
            retry_after_ms: 998
        }
    );
    assert!(l.claim(&d[1], 1000).unwrap().is_some());
}
#[test]
fn retries_also_require_rate_capacity() {
    let mut l = configured();
    l.create("one", input(), 0).unwrap();
    l.create("two", input(), 0).unwrap();
    let ds = l.outbox("a", 0);
    let one = l.claim(&ds[0], 0).unwrap().unwrap();
    let one = l.finish(&one.id, one.fence, Outcome::Http(503), 1).unwrap();
    let two = l.claim(&ds[1], one.due_ms - 1).unwrap().unwrap();
    l.finish(&two.id, two.fence, Outcome::Http(204), one.due_ms - 1)
        .unwrap();
    let retry = l
        .outbox("a", one.due_ms)
        .into_iter()
        .find(|d| d.id == one.id)
        .unwrap();
    assert_eq!(
        l.claim(&retry, one.due_ms).unwrap_err(),
        Fault::Limited {
            reason: LimitReason::DispatchRate,
            retry_after_ms: 999
        }
    );
    assert_eq!(l.get(&one.id).unwrap().attempts.len(), 1);
    assert!(l.claim(&retry, one.due_ms + 999).unwrap().is_some());
}
#[test]
fn concurrency_permits_expire_and_old_outcomes_are_fenced() {
    let mut l = configured();
    for key in ["one", "two"] {
        l.create(key, input(), 0).unwrap();
    }
    let ds = l.outbox("a", 0);
    let first = l.claim(&ds[0], 0).unwrap().unwrap();
    assert_eq!(
        l.claim(&ds[1], 1).unwrap_err(),
        Fault::Limited {
            reason: LimitReason::Concurrency,
            retry_after_ms: LEASE - 1
        }
    );
    let mut l = restart(&l);
    assert!(l.claim(&ds[1], LEASE).unwrap().is_some());
    assert_eq!(
        l.finish(&first.id, first.fence, Outcome::Http(204), LEASE + 1)
            .unwrap_err(),
        Fault::Stale
    );
}
#[test]
fn noisy_tenant_cannot_spend_another_tenants_budget() {
    let mut noisy = configured();
    let mut quiet = configured();
    noisy.create("a", input(), 0).unwrap();
    quiet.create("a", input(), 0).unwrap();
    let n = noisy.outbox("noisy", 0).remove(0);
    let q = quiet.outbox("quiet", 0).remove(0);
    noisy.claim(&n, 0).unwrap();
    assert!(quiet.claim(&q, 0).unwrap().is_some());
    assert_eq!(quiet.get(&q.id).unwrap().attempts.len(), 1);
}
#[test]
fn reconfiguration_cannot_mint_tokens_and_clock_regression_cannot_refill() {
    let mut l = configured();
    for k in ["a", "b"] {
        l.create(k, input(), 0).unwrap();
    }
    let ds = l.outbox("a", 0);
    let first = l.claim(&ds[0], 1000).unwrap().unwrap();
    l.finish(&first.id, first.fence, Outcome::Http(204), 1001)
        .unwrap();
    l.configure(l.limits.clone(), 1001).unwrap();
    l.configure(
        QueueLimits {
            dispatch_burst: 100,
            ..l.limits.clone()
        },
        1001,
    )
    .unwrap();
    assert_eq!(
        l.claim(&ds[1], 500).unwrap_err(),
        Fault::Limited {
            reason: LimitReason::DispatchRate,
            retry_after_ms: 1500
        }
    );
    assert!(l.claim(&ds[1], 2000).unwrap().is_some());
}
#[test]
fn queue_config_query_is_read_only_and_invalid_config_does_not_mutate() {
    let mut l = configured();
    let before = serde_json::to_string(&l).unwrap();
    application::query(&l, Query::QueueConfig).unwrap();
    assert_eq!(serde_json::to_string(&l).unwrap(), before);
    let invalid = QueueLimits {
        dispatch_per_second: 0,
        ..l.limits.clone()
    };
    assert!(application::command(&mut l, Command::ConfigureQueue { limits: invalid }, 1).is_err());
    assert_eq!(serde_json::to_string(&l).unwrap(), before);
}
#[test]
fn identifier_validation_rejects_ambiguous_names() {
    for name in ["", "../tenant", "a:b", "a.b", "a/b", "a b", "é", "a\n"] {
        assert!(!tenant_valid(name));
    }
    assert!(tenant_valid("project_A-1"));
    assert!(!tenant_valid(&"a".repeat(65)));
    assert!(task_id_valid("task_0000000000000001"));
    assert!(!task_id_valid("task_000000000000000G"));
}
#[test]
fn config_limits_and_unknown_fields_are_rejected() {
    for limits in [
        QueueLimits {
            max_active_tasks: 0,
            ..QueueLimits::default()
        },
        QueueLimits {
            max_concurrent: 65,
            ..QueueLimits::default()
        },
        QueueLimits {
            dispatch_burst: 101,
            ..QueueLimits::default()
        },
        QueueLimits {
            max_payload_bytes: 128 * 1024 + 1,
            ..QueueLimits::default()
        },
    ] {
        assert_eq!(limits.validate(), Err(Fault::Invalid));
    }
    let mut value = serde_json::to_value(QueueLimits::default()).unwrap();
    value["unknown"] = true.into();
    assert!(serde_json::from_value::<QueueLimits>(value).is_err());
}
#[test]
fn authentication_checks_entire_keyring_and_scopes_tokens_without_header_tenant_override() {
    use runlater::security::{authenticate, digest, AuthFault};
    let token = "public-local-test-token";
    let mut keys = std::collections::BTreeMap::new();
    keys.insert(digest(token.as_bytes()), "project_a".to_string());
    let config = serde_json::to_string(&keys).unwrap();
    assert_eq!(authenticate(&config, token).unwrap(), "project_a");
    assert_eq!(authenticate(&config, "wrong"), Err(AuthFault::Unauthorized));
    keys.insert(digest(b"other"), "../escape".into());
    assert_eq!(
        authenticate(&serde_json::to_string(&keys).unwrap(), token),
        Err(AuthFault::InvalidConfiguration)
    );
    for config in ["{}", "not-json", "[]", "{\"plaintext-token\":\"project\"}"] {
        assert_eq!(
            authenticate(config, token),
            Err(AuthFault::InvalidConfiguration)
        );
    }
}
