use runlater::{
    auth::*,
    core::{Fault, DAY},
    security::{digest, AuthFault},
};
use std::collections::{BTreeMap, BTreeSet};
fn config() -> String {
    let mut m = BTreeMap::new();
    m.insert(digest(b"local-alpha"), "alpha");
    m.insert(digest(b"local-beta"), "beta");
    serde_json::to_string(&m).unwrap()
}
fn fixture() -> (Keyring, Actor) {
    let ring = Keyring::bootstrap(&config(), "alpha").unwrap();
    let c = route_credential(&config(), "local-alpha").unwrap();
    let actor = ring.authorize(&c, Permission::ManageKeys, 100).unwrap();
    (ring, actor)
}
fn token(id: &str) -> String {
    format!("rl_local.alpha.{id}.public_fixture_secret_for_tests")
}
fn spec(id: &str, permissions: &[Permission]) -> NewKey {
    NewKey {
        key_id: id.into(),
        token_sha256: digest(token(id).as_bytes()),
        permissions: permissions.iter().copied().collect(),
        not_before_ms: 0,
        expires_at_ms: 10 * DAY,
    }
}
fn cred(id: &str) -> Credential {
    route_credential(&config(), &token(id)).unwrap()
}
#[test]
fn bootstrap_compatibility_and_project_scope() {
    let (a, _) = fixture();
    assert!(a
        .authorize(
            &route_credential(&config(), "local-alpha").unwrap(),
            Permission::Read,
            100
        )
        .is_ok());
    assert!(matches!(
        a.authorize(
            &route_credential(&config(), "local-beta").unwrap(),
            Permission::Read,
            100
        ),
        Err(AccessFault::Unauthorized)
    ));
}
#[test]
fn scoped_key_cannot_gain_other_capabilities() {
    let (mut ring, admin) = fixture();
    ring.command(
        &admin,
        KeyCommand::Create(spec("reader", &[Permission::Read])),
        100,
    )
    .unwrap();
    let c = cred("reader");
    assert!(ring.authorize(&c, Permission::Read, 101).is_ok());
    for p in [
        Permission::Enqueue,
        Permission::Cancel,
        Permission::Redrive,
        Permission::Configure,
        Permission::ManageKeys,
    ] {
        assert!(matches!(
            ring.authorize(&c, p, 101),
            Err(AccessFault::Forbidden)
        ));
    }
}
#[test]
fn every_operation_has_a_distinct_permission() {
    for (method, path, p) in [
        ("POST", "/v1/tasks", Permission::Enqueue),
        ("GET", "/v1/tasks/a/attempts", Permission::Read),
        ("POST", "/v1/tasks/a/cancel", Permission::Cancel),
        ("POST", "/v1/tasks/a/redrive", Permission::Redrive),
        ("PUT", "/v1/queue", Permission::Configure),
        ("POST", "/v1/keys/a/rotate", Permission::ManageKeys),
    ] {
        assert_eq!(required_permission(method, path), Some(p));
    }
    assert_eq!(required_permission("POST", "/v1/tasks-typo"), None);
}
#[test]
fn revoked_keys_stay_revoked_across_restart_and_create_replay() {
    let (mut r, admin) = fixture();
    let s = spec("reader", &[Permission::Read]);
    r.command(&admin, KeyCommand::Create(s.clone()), 100)
        .unwrap();
    r.command(
        &admin,
        KeyCommand::Revoke {
            key_id: "reader".into(),
        },
        101,
    )
    .unwrap();
    let mut r: Keyring = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    let (v, created) = r.command(&admin, KeyCommand::Create(s), 102).unwrap();
    assert!(!created);
    assert_eq!(v.revoked_at_ms, Some(101));
    assert!(matches!(
        r.authorize(&cred("reader"), Permission::Read, 102),
        Err(AccessFault::Unauthorized)
    ));
    assert!(r
        .command(
            &admin,
            KeyCommand::Create(spec("reader", &[Permission::Enqueue])),
            103
        )
        .is_err());
}
#[test]
fn validity_boundaries_are_exact_and_queries_do_not_refresh() {
    let (mut r, admin) = fixture();
    let mut s = spec("timed", &[Permission::Read]);
    s.not_before_ms = 200;
    s.expires_at_ms = 300;
    r.command(&admin, KeyCommand::Create(s), 100).unwrap();
    let c = cred("timed");
    assert!(matches!(
        r.authorize(&c, Permission::Read, 199),
        Err(AccessFault::Unauthorized)
    ));
    assert!(r.authorize(&c, Permission::Read, 200).is_ok());
    assert!(r.authorize(&c, Permission::Read, 299).is_ok());
    assert!(matches!(
        r.authorize(&c, Permission::Read, 300),
        Err(AccessFault::Unauthorized)
    ));
    let before = serde_json::to_string(&r).unwrap();
    r.query(KeyQuery::List);
    r.query(KeyQuery::Audit);
    assert_eq!(serde_json::to_string(&r).unwrap(), before);
}
#[test]
fn rotation_overlap_cutover_and_replay_are_atomic() {
    let (mut r, admin) = fixture();
    r.command(
        &admin,
        KeyCommand::Create(spec("old", &[Permission::Read])),
        100,
    )
    .unwrap();
    let new = spec("new", &[Permission::Read]);
    let (v, created) = r
        .command(
            &admin,
            KeyCommand::Rotate {
                key_id: "old".into(),
                new_key: new.clone(),
                revoke_old_at_ms: 200,
            },
            101,
        )
        .unwrap();
    assert!(created);
    assert_eq!(v.rotated_from.as_deref(), Some("old"));
    assert!(r.authorize(&cred("old"), Permission::Read, 199).is_ok());
    assert!(r.authorize(&cred("new"), Permission::Read, 199).is_ok());
    assert!(matches!(
        r.authorize(&cred("old"), Permission::Read, 200),
        Err(AccessFault::Unauthorized)
    ));
    assert!(r.authorize(&cred("new"), Permission::Read, 200).is_ok());
    let mut r: Keyring = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert!(
        !r.command(
            &admin,
            KeyCommand::Rotate {
                key_id: "old".into(),
                new_key: new.clone(),
                revoke_old_at_ms: 200
            },
            300
        )
        .unwrap()
        .1
    );
    assert!(r
        .command(
            &admin,
            KeyCommand::Rotate {
                key_id: "old".into(),
                new_key: new,
                revoke_old_at_ms: 201
            },
            300
        )
        .is_err());
}
#[test]
fn failed_rotation_does_not_partially_revoke_or_create() {
    let (mut r, admin) = fixture();
    r.command(
        &admin,
        KeyCommand::Create(spec("old", &[Permission::Read])),
        100,
    )
    .unwrap();
    let before = serde_json::to_string(&r).unwrap();
    assert!(r
        .command(
            &admin,
            KeyCommand::Rotate {
                key_id: "old".into(),
                new_key: spec("new", &[Permission::Read]),
                revoke_old_at_ms: 99
            },
            101
        )
        .is_err());
    assert_eq!(serde_json::to_string(&r).unwrap(), before);
}
#[test]
fn delegated_managers_cannot_escalate_or_revoke_stronger_keys() {
    let (mut r, admin) = fixture();
    r.command(
        &admin,
        KeyCommand::Create(spec("manager", &[Permission::ManageKeys, Permission::Read])),
        100,
    )
    .unwrap();
    let manager = r
        .authorize(&cred("manager"), Permission::ManageKeys, 100)
        .unwrap();
    assert!(matches!(
        r.command(
            &manager,
            KeyCommand::Create(spec("writer", &[Permission::Enqueue])),
            101
        ),
        Err(Fault::Forbidden)
    ));
    assert!(matches!(
        r.command(
            &manager,
            KeyCommand::Revoke {
                key_id: admin.key_id
            },
            101
        ),
        Err(Fault::Forbidden)
    ));
    r.command(
        &manager,
        KeyCommand::Create(spec("reader", &[Permission::Read])),
        101,
    )
    .unwrap();
}
#[test]
fn views_and_audit_redact_verifiers_and_tokens() {
    let (mut r, admin) = fixture();
    let s = spec("reader", &[Permission::Read]);
    let verifier = s.token_sha256.clone();
    r.command(&admin, KeyCommand::Create(s), 100).unwrap();
    let public = format!("{}{}", r.query(KeyQuery::List), r.query(KeyQuery::Audit));
    assert!(!public.contains(&verifier));
    for record in r.keys.values() {
        assert!(!public.contains(&record.spec.token_sha256));
    }
    assert!(!public.contains(&token("reader")));
    assert!(!public.contains("token_sha256"));
    let stored = serde_json::to_string(&r).unwrap();
    assert!(stored.contains(&verifier));
    assert!(!stored.contains(&token("reader")));
}
#[test]
fn bootstrap_is_not_resurrected_after_all_keys_revoked() {
    let (mut r, admin) = fixture();
    r.command(
        &admin,
        KeyCommand::Revoke {
            key_id: admin.key_id.clone(),
        },
        100,
    )
    .unwrap();
    let r: Keyring = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert!(matches!(
        r.authorize(
            &route_credential(&config(), "local-alpha").unwrap(),
            Permission::Read,
            101
        ),
        Err(AccessFault::Unauthorized)
    ));
}
#[test]
fn malformed_tokens_and_mutated_tenant_or_secret_fail() {
    for t in [
        "rl_local.alpha.id.short",
        "rl_local...abcdefghijklmnop",
        "rl_local.alpha.id.abcdefghijklmnop.extra",
        "rl_local.bad/tenant.id.abcdefghijklmnop",
        "rl_local.unknown.id.abcdefghijklmnop",
    ] {
        assert!(matches!(
            route_credential(&config(), t),
            Err(AuthFault::Unauthorized)
        ));
    }
    let (mut r, admin) = fixture();
    r.command(
        &admin,
        KeyCommand::Create(spec("reader", &[Permission::Read])),
        100,
    )
    .unwrap();
    let changed = token("reader").replace(".alpha.", ".beta.");
    assert!(matches!(
        r.authorize(
            &route_credential(&config(), &changed).unwrap(),
            Permission::Read,
            100
        ),
        Err(AccessFault::Unauthorized)
    ));
    let changed = token("reader").replace("tests", "wrong");
    assert!(matches!(
        r.authorize(
            &route_credential(&config(), &changed).unwrap(),
            Permission::Read,
            100
        ),
        Err(AccessFault::Unauthorized)
    ));
}
#[test]
fn policy_bounds_and_reserved_ids_are_validated() {
    let (mut r, admin) = fixture();
    for mut s in [
        spec("x", &[]),
        spec("bootstrap_fake", &[Permission::Read]),
        spec("invalid/id", &[Permission::Read]),
    ] {
        assert!(r
            .command(&admin, KeyCommand::Create(s.clone()), 100)
            .is_err());
        s.permissions = BTreeSet::new();
    }
    let mut s = spec("far", &[Permission::Read]);
    s.expires_at_ms = 31 * DAY;
    assert!(r.command(&admin, KeyCommand::Create(s), 100).is_err());
}

#[test]
fn stale_actor_and_forged_permission_snapshot_cannot_mutate_keyring() {
    let (mut r, admin) = fixture();
    r.command(
        &admin,
        KeyCommand::Create(spec("manager", &[Permission::ManageKeys, Permission::Read])),
        100,
    )
    .unwrap();
    let mut actor = r
        .authorize(&cred("manager"), Permission::ManageKeys, 100)
        .unwrap();
    actor.permissions.insert(Permission::Enqueue);
    assert!(matches!(
        r.command(
            &actor,
            KeyCommand::Create(spec("escalated", &[Permission::Enqueue])),
            101
        ),
        Err(Fault::Forbidden)
    ));
    let actor = r
        .authorize(&cred("manager"), Permission::ManageKeys, 100)
        .unwrap();
    r.command(
        &admin,
        KeyCommand::Revoke {
            key_id: "manager".into(),
        },
        101,
    )
    .unwrap();
    assert!(matches!(
        r.command(
            &actor,
            KeyCommand::Create(spec("new", &[Permission::Read])),
            102
        ),
        Err(Fault::Forbidden)
    ));
}
#[test]
fn rotation_cannot_introduce_a_gap_before_source_expiry() {
    let (mut r, admin) = fixture();
    let mut old = spec("old", &[Permission::Read]);
    old.expires_at_ms = 150;
    r.command(&admin, KeyCommand::Create(old), 100).unwrap();
    let mut new = spec("new", &[Permission::Read]);
    new.not_before_ms = 200;
    assert!(matches!(
        r.command(
            &admin,
            KeyCommand::Rotate {
                key_id: "old".into(),
                new_key: new,
                revoke_old_at_ms: 200
            },
            101
        ),
        Err(Fault::Invalid)
    ));
}
#[test]
fn mutation_only_receipts_do_not_disclose_payload_or_attempt_history() {
    use runlater::{
        application::{self, Command},
        core::{Create, Ledger},
    };
    let mut l = Ledger::default();
    let r = application::command(
        &mut l,
        Command::Enqueue {
            key: "key".into(),
            input: Create {
                destination: "fixture://success".into(),
                body: "sensitive-fixture-payload".into(),
                operation_key: "business_identity".into(),
                run_at_ms: 1000,
            },
        },
        0,
    )
    .unwrap();
    let scoped = r.scoped_body(false);
    assert_eq!(scoped["id"], r.body["id"]);
    assert_eq!(scoped["generation"], r.body["generation"]);
    assert!(scoped.get("input").is_none());
    assert!(scoped.get("attempts").is_none());
    assert!(!scoped.to_string().contains("sensitive-fixture-payload"));
    assert_eq!(r.scoped_body(true), r.body);
    let cancel = application::command(
        &mut l,
        Command::Cancel {
            id: r.body["id"].as_str().unwrap().into(),
        },
        1,
    )
    .unwrap();
    assert!(cancel.scoped_body(false).get("input").is_none());
}
#[test]
fn actor_authority_is_bound_to_project_even_with_coincident_key_ids() {
    let (mut alpha, a_admin) = fixture();
    let mut beta = Keyring::bootstrap(&config(), "beta").unwrap();
    let b_admin = beta
        .authorize(
            &route_credential(&config(), "local-beta").unwrap(),
            Permission::ManageKeys,
            100,
        )
        .unwrap();
    let a_spec = spec("manager", &[Permission::Read, Permission::ManageKeys]);
    let mut b_spec = a_spec.clone();
    b_spec.token_sha256 = digest(token("manager").replace(".alpha.", ".beta.").as_bytes());
    alpha
        .command(&a_admin, KeyCommand::Create(a_spec), 100)
        .unwrap();
    beta.command(&b_admin, KeyCommand::Create(b_spec), 100)
        .unwrap();
    let a_actor = alpha
        .authorize(&cred("manager"), Permission::ManageKeys, 100)
        .unwrap();
    assert!(matches!(
        beta.command(
            &a_actor,
            KeyCommand::Revoke {
                key_id: "manager".into()
            },
            101
        ),
        Err(Fault::Forbidden)
    ));
}
