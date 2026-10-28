use runlater::destinations::*;

const URL: &str = "https://receiver-alpha.runlater.io/callback";
fn policy() -> EgressPolicy {
    EgressPolicy {
        managed_workers_dev: false,
        approved_hosts: ["receiver-alpha.runlater.io".into()].into_iter().collect(),
    }
}
fn state() -> State {
    let mut s = State::new("alpha").unwrap();
    s.create("alpha", "receiver", 1, URL, &policy(), 0).unwrap();
    s
}
fn proof(s: &mut State, version: u32, now: i64) -> (Proof, Challenge) {
    let p = s
        .prepare(
            "alpha",
            "receiver",
            version,
            &"01".repeat(32),
            &policy(),
            now,
        )
        .unwrap();
    let c = s
        .begin("alpha", "receiver", version, &policy(), now)
        .unwrap();
    assert!(
        !c.body.contains(&"01".repeat(32)),
        "secret proof nonce leaked to receiver"
    );
    assert_ne!(c.body, p.response);
    (p, c)
}
fn verified() -> State {
    let mut s = state();
    let (p, c) = proof(&mut s, 1, 1);
    s.complete("alpha", &c, Ok((200, p.response.as_bytes())), &policy(), 2)
        .unwrap();
    s
}
fn restart(s: &State) -> State {
    State::decode(&serde_json::to_vec(s).unwrap(), "alpha").unwrap()
}
#[test]
fn closed_policy_and_url_aliases_never_authorize_egress() {
    assert!(EgressPolicy::default().target(URL).is_err());
    for url in [
        "http://receiver-alpha.runlater.io/callback",
        "https://receiver-alpha.runlater.io:443/callback",
        "https://receiver-alpha.runlater.io:444/callback",
        "https://user@receiver-alpha.runlater.io/callback",
        "https://receiver-alpha.runlater.io/callback?token=x",
        "https://receiver-alpha.runlater.io/callback#x",
        "https://receiver-alpha.runlater.io.evil.test/callback",
        "https://RECEIVER-ALPHA.runlater.io/callback",
        "https://receiver-alpha.runlater.io./callback",
        "https://%72eceiver-alpha.runlater.io/callback",
        "https://127.0.0.1/callback",
        "https://2130706433/callback",
        "https://0x7f000001/callback",
        "https://[::1]/callback",
        "https://[::ffff:127.0.0.1]/callback",
        "https://169.254.169.254/",
        "https://receiver-alpha.runlater.io/a/../callback",
    ] {
        assert!(policy().target(url).is_err(), "accepted {url}");
    }
    for host in [
        "127.0.0.1",
        "[::1]",
        "*.runlater.io",
        "receiver-alpha.runlater.io:443",
        "user@receiver-alpha.runlater.io",
        "receiver-alpha.runlater.io.",
        "localhost",
        "metadata.google.internal",
        "host.localhost",
        "-receiver.runlater.io",
        "receiver..runlater.io",
    ] {
        let p = EgressPolicy {
            managed_workers_dev: false,
            approved_hosts: [host.into()].into_iter().collect(),
        };
        assert!(p.target(URL).is_err(), "invalid policy {host}");
        assert!(
            p.target(&format!("https://{host}/callback")).is_err(),
            "policy allowed invalid exact host {host}"
        );
    }
}
#[test]
fn pending_verified_revoked_are_distinct_and_queries_are_pure() {
    let mut s = state();
    assert_eq!(
        s.get("alpha", "receiver", 1).unwrap().status,
        Status::Pending
    );
    assert_eq!(
        s.snapshot("alpha", "task_a", "receiver", 1, &policy(), 1),
        Err(Error::Unavailable)
    );
    let before = serde_json::to_vec(&s).unwrap();
    assert_eq!(s.get("beta", "receiver", 1), Err(Error::Forbidden));
    assert!(s.dispatch("alpha", "task_a", &policy()).is_err());
    assert_eq!(before, serde_json::to_vec(&s).unwrap());
    let (p, c) = proof(&mut s, 1, 1);
    let bytes = serde_json::to_string(&s).unwrap();
    assert!(!bytes.contains(&"01".repeat(32)));
    assert!(!bytes.contains(&p.response));
    assert_eq!(
        s.complete("alpha", &c, Ok((200, p.response.as_bytes())), &policy(), 2)
            .unwrap()
            .status,
        Status::Verified
    );
    s.revoke("alpha", "receiver", 3).unwrap();
    assert_eq!(
        s.get("alpha", "receiver", 1).unwrap().status,
        Status::Revoked
    );
}
#[test]
fn reflected_request_is_not_ownership_and_fetch_can_start_only_once() {
    let mut s = state();
    let (_, c) = proof(&mut s, 1, 1);
    assert!(matches!(
        s.begin("alpha", "receiver", 1, &policy(), 1),
        Err(Error::Conflict)
    ));
    assert_eq!(
        s.complete("alpha", &c, Ok((200, c.body.as_bytes())), &policy(), 2),
        Err(Error::Unavailable)
    );
    assert_eq!(
        s.complete("alpha", &c, Ok((200, c.body.as_bytes())), &policy(), 2),
        Err(Error::Conflict)
    );
    assert_eq!(
        s.get("alpha", "receiver", 1).unwrap().status,
        Status::Pending
    );
}
#[test]
fn proof_binds_tenant_endpoint_version_url_and_completion_receipt() {
    let mut a = state();
    let (p, c) = proof(&mut a, 1, 1);
    let mut b = State::new("beta").unwrap();
    b.create("beta", "receiver", 1, URL, &policy(), 0).unwrap();
    b.prepare("beta", "receiver", 1, &"01".repeat(32), &policy(), 1)
        .unwrap();
    let bc = b.begin("beta", "receiver", 1, &policy(), 1).unwrap();
    assert_eq!(
        a.complete("beta", &c, Ok((200, p.response.as_bytes())), &policy(), 2),
        Err(Error::Forbidden)
    );
    assert_eq!(
        b.complete("beta", &bc, Ok((200, p.response.as_bytes())), &policy(), 2),
        Err(Error::Unavailable)
    );
    a.create(
        "alpha",
        "receiver",
        2,
        "https://receiver-alpha.runlater.io/new",
        &policy(),
        1,
    )
    .unwrap();
    let (_, c2) = proof(&mut a, 2, 1);
    assert_eq!(
        a.complete("alpha", &c2, Ok((200, p.response.as_bytes())), &policy(), 2),
        Err(Error::Unavailable)
    );
    let mut changed = c.clone();
    changed.url.push_str("-other");
    assert_eq!(
        a.complete(
            "alpha",
            &changed,
            Ok((200, p.response.as_bytes())),
            &policy(),
            2
        ),
        Err(Error::Conflict)
    );
    assert!(a
        .complete("alpha", &c, Ok((200, p.response.as_bytes())), &policy(), 2)
        .is_ok());
    assert_eq!(
        a.complete("alpha", &c, Ok((200, p.response.as_bytes())), &policy(), 2),
        Err(Error::Conflict)
    );
}
#[test]
fn expiry_is_exact_and_clock_rollback_cannot_extend_a_proof() {
    let mut s = state();
    let (p, c) = proof(&mut s, 1, 10);
    assert_eq!(
        s.complete("alpha", &c, Ok((200, p.response.as_bytes())), &policy(), 9),
        Err(Error::Clock)
    );
    assert_eq!(
        s.complete(
            "alpha",
            &c,
            Ok((200, p.response.as_bytes())),
            &policy(),
            10 + PROOF_TTL_MS
        ),
        Err(Error::Expired)
    );
    let p = s
        .prepare(
            "alpha",
            "receiver",
            1,
            &"02".repeat(32),
            &policy(),
            10 + PROOF_TTL_MS,
        )
        .unwrap();
    assert!(matches!(
        s.begin("alpha", "receiver", 1, &policy(), p.expires_at_ms),
        Err(Error::Expired)
    ));
}
#[test]
fn failed_and_interrupted_proofs_keep_lifetime_budget_after_restart() {
    let mut s = state();
    for n in 0..MAX_PROOFS {
        let at = i64::from(n) * PROOF_TTL_MS;
        let (p, c) = proof(&mut s, 1, at);
        s = restart(&s);
        assert!(matches!(
            s.begin("alpha", "receiver", 1, &policy(), at),
            Err(Error::Conflict)
        ));
        if n != 0 {
            let result = if n == 1 {
                Ok((302, p.response.as_bytes()))
            } else {
                Err(())
            };
            assert_eq!(
                s.complete("alpha", &c, result, &policy(), at),
                Err(Error::Unavailable)
            );
        }
    }
    s = restart(&s);
    assert!(matches!(
        s.prepare(
            "alpha",
            "receiver",
            1,
            &"01".repeat(32),
            &policy(),
            3 * PROOF_TTL_MS
        ),
        Err(Error::Limited)
    ));
}
#[test]
fn accepted_version_is_immutable_and_new_versions_do_not_retarget_it() {
    let mut s = verified();
    let accepted = s
        .snapshot("alpha", "task_a", "receiver", 1, &policy(), 3)
        .unwrap();
    s.create(
        "alpha",
        "receiver",
        2,
        "https://receiver-alpha.runlater.io/new",
        &policy(),
        4,
    )
    .unwrap();
    let (p, c) = proof(&mut s, 2, 4);
    s.complete("alpha", &c, Ok((200, p.response.as_bytes())), &policy(), 5)
        .unwrap();
    assert_eq!(s.dispatch("alpha", "task_a", &policy()).unwrap().url(), URL);
    assert_eq!(
        s.snapshot("alpha", "task_a", "receiver", 2, &policy(), 6),
        Err(Error::Conflict)
    );
    s.revoke("alpha", "receiver", 6).unwrap();
    s = restart(&s);
    assert_eq!(
        s.snapshot(
            "alpha",
            "task_a",
            "receiver",
            1,
            &EgressPolicy::default(),
            7
        )
        .unwrap(),
        accepted
    );
    assert!(s.dispatch("alpha", "task_a", &policy()).is_err());
    assert_eq!(
        s.create("alpha", "receiver", 3, URL, &policy(), 7),
        Err(Error::Unavailable)
    );
    assert_eq!(
        s.create("alpha", "receiver", 1, URL, &policy(), 7)
            .unwrap()
            .status,
        Status::Revoked
    );
    assert_eq!(
        s.create(
            "alpha",
            "receiver",
            1,
            "https://receiver-alpha.runlater.io/new",
            &policy(),
            7
        ),
        Err(Error::Conflict)
    );
}
#[test]
fn revocation_during_io_cannot_be_overwritten_by_a_valid_response() {
    let mut s = state();
    let (p, c) = proof(&mut s, 1, 1);
    s.revoke("alpha", "receiver", 2).unwrap();
    s = restart(&s);
    assert_eq!(
        s.complete("alpha", &c, Ok((200, p.response.as_bytes())), &policy(), 3),
        Err(Error::Conflict)
    );
    assert_eq!(
        s.get("alpha", "receiver", 1).unwrap().status,
        Status::Revoked
    );
}
#[test]
fn host_policy_removal_blocks_proof_completion_and_existing_task_dispatch() {
    let mut s = state();
    let (p, c) = proof(&mut s, 1, 1);
    assert_eq!(
        s.complete(
            "alpha",
            &c,
            Ok((200, p.response.as_bytes())),
            &EgressPolicy::default(),
            2
        ),
        Err(Error::Unavailable)
    );
    let mut s = verified();
    s.snapshot("alpha", "task_a", "receiver", 1, &policy(), 3)
        .unwrap();
    assert!(s
        .dispatch("alpha", "task_a", &EgressPolicy::default())
        .is_err());
}
#[test]
fn version_task_limits_and_revocation_cannot_recycle_capacity() {
    let mut s = verified();
    for i in 2..=MAX_VERSIONS {
        s.create("alpha", "receiver", i as u32, URL, &policy(), 3)
            .unwrap();
    }
    assert_eq!(
        s.create("alpha", "other", 1, URL, &policy(), 3),
        Err(Error::Limited)
    );
    for i in 0..MAX_TASKS {
        s.snapshot("alpha", &format!("task_{i}"), "receiver", 1, &policy(), 3)
            .unwrap();
    }
    assert_eq!(
        s.snapshot("alpha", "overflow", "receiver", 1, &policy(), 3),
        Err(Error::Limited)
    );
    s.revoke("alpha", "receiver", 4).unwrap();
    s = restart(&s);
    assert_eq!(
        s.create("alpha", "other", 1, URL, &policy(), 5),
        Err(Error::Limited)
    );
}
#[test]
fn unknown_schema_and_cross_tenant_restart_fail_closed() {
    let s = state();
    let mut v = serde_json::to_value(&s).unwrap();
    assert!(matches!(
        State::decode(&serde_json::to_vec(&v).unwrap(), "beta"),
        Err(Error::Forbidden)
    ));
    v["schema_version"] = 99.into();
    assert!(matches!(
        State::decode(&serde_json::to_vec(&v).unwrap(), "alpha"),
        Err(Error::Invalid)
    ));
    for (field, value) in [
        ("version", 2.into()),
        ("endpoint_id", "other".into()),
        ("status", "verified".into()),
    ] {
        let mut v = serde_json::to_value(&s).unwrap();
        v["versions"]["receiver"]["1"]["endpoint"][field] = value;
        assert!(State::decode(&serde_json::to_vec(&v).unwrap(), "alpha").is_err());
    }
}

#[test]
fn expired_inflight_completion_cannot_consume_or_verify_a_replacement_proof() {
    let mut s = state();
    let (old, old_attempt) = proof(&mut s, 1, 1);
    let now = 1 + PROOF_TTL_MS;
    let (new, new_attempt) = proof(&mut s, 1, now);
    assert_ne!(old.id, new.id);
    assert_eq!(
        s.complete(
            "alpha",
            &old_attempt,
            Ok((200, old.response.as_bytes())),
            &policy(),
            now
        ),
        Err(Error::Conflict)
    );
    s = restart(&s);
    assert!(s
        .complete(
            "alpha",
            &new_attempt,
            Ok((200, new.response.as_bytes())),
            &policy(),
            now
        )
        .is_ok());
}
