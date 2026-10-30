use ed25519_dalek::{Signer, SigningKey};
use runlater::{callback::Material, invitation::Error, public_beta::*};
fn profile() -> Profile {
    Profile {
        release_id: "beta_1".into(),
        opens_at_ms: 0,
        closes_at_ms: DURATION,
        callback_end_sec: (2 * DURATION + runlater::core::DAY) / 1000 + 301,
        self_host: "runlater-public-api.operator.workers.dev".into(),
    }
}
fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}
fn public(n: u8) -> String {
    hex::encode(key(n).verifying_key().to_bytes())
}
fn signature(c: &runlater::invitation::Challenge, n: u8) -> String {
    hex::encode(key(n).sign(&c.bytes().unwrap()).to_bytes())
}
#[test]
fn only_proof_reserves_slot_and_recovery_does_not_refill() {
    let p = profile();
    let mut s = State::new(&p).unwrap();
    let c = s.challenge(&public(1), &"a".repeat(64), 1).unwrap();
    assert_eq!(s.view(1)["remaining_projects"], 10);
    assert!(s.complete(&c.id().unwrap(), &signature(&c, 2), 2).is_err());
    assert_eq!(s.view(2)["remaining_projects"], 10);
    let (g, _) = s.complete(&c.id().unwrap(), &signature(&c, 1), 3).unwrap();
    assert_eq!(g.ticket.terms.attempt_units, 100);
    assert_eq!(s.view(3)["remaining_projects"], 9);
    let mut s: State = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
    let c2 = s.challenge(&public(1), &"b".repeat(64), 600_001).unwrap();
    let (g2, _) = s
        .complete(&c2.id().unwrap(), &signature(&c2, 1), 600_002)
        .unwrap();
    assert!(g == g2);
    s.validate(&p).unwrap();
    assert!(s
        .challenge(&public(1), &"c".repeat(64), g.expires_at_ms)
        .is_err());
}
#[test]
fn first_cohort_capacity_is_lifetime_and_restart_stable() {
    let p = profile();
    let mut s = State::new(&p).unwrap();
    for n in 1..=10 {
        let c = s
            .challenge(&public(n), &format!("{n:064x}"), n as i64 * 100)
            .unwrap();
        s.complete(&c.id().unwrap(), &signature(&c, n), n as i64 * 100 + 1)
            .unwrap();
    }
    assert_eq!(s.view(1002)["remaining_projects"], 0);
    assert_eq!(
        s.challenge(&public(11), &"d".repeat(64), 1003).err(),
        Some(Error::Limited)
    );
    let s: State = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
    assert_eq!(s.view(DURATION + 1)["remaining_projects"], 0);
}
#[test]
fn proof_lockout_expiry_cross_context_and_clock() {
    let p = profile();
    let mut s = State::new(&p).unwrap();
    let c = s.challenge(&public(3), &"a".repeat(64), 10).unwrap();
    for _ in 0..3 {
        assert_eq!(
            s.complete(&c.id().unwrap(), &signature(&c, 4), 11).err(),
            Some(Error::Forbidden)
        )
    }
    assert_eq!(
        s.complete(&c.id().unwrap(), &signature(&c, 3), 12).err(),
        Some(Error::Forbidden)
    );
    assert_eq!(
        s.challenge(&public(5), &"b".repeat(64), 9).err(),
        Some(Error::Clock)
    );
    let mut changed = p.clone();
    changed.release_id = "beta_2".into();
    assert_eq!(s.validate(&changed), Err(Error::Conflict));
}
#[test]
fn derivation_is_project_release_and_ip_day_separated() {
    let m = Master::from_hex(&hex::encode((0..32).collect::<Vec<_>>())).unwrap();
    let a = m.tenant("release_1", "project_1").unwrap();
    assert_ne!(
        a.key("beta_v1"),
        m.tenant("release_1", "project_2").unwrap().key("beta_v1")
    );
    assert_ne!(
        a.key("beta_v1"),
        m.tenant("release_2", "project_1").unwrap().key("beta_v1")
    );
    assert!(a.key("unknown").is_none());
    assert_eq!(
        m.ip_bucket("release_1", "2001:db8::1", 0).unwrap(),
        m.ip_bucket("release_1", "2001:0db8::1", 0).unwrap()
    );
    assert_ne!(
        m.ip_bucket("release_1", "192.0.2.1", 0).unwrap(),
        m.ip_bucket("release_1", "192.0.2.1", runlater::core::DAY)
            .unwrap()
    );
    assert!(Master::from_hex(&"00".repeat(32)).is_err());
}
#[test]
fn only_exact_managed_worker_hosts() {
    for h in [
        "worker.account.workers.dev",
        "worker-1.account-1.workers.dev",
    ] {
        assert!(managed_receiver_host(h))
    }
    for h in [
        "account.workers.dev",
        "a.b.c.workers.dev",
        "worker.account.workers.dev.evil.test",
        "127.0.0.1",
        "worker.account.workers.dev.",
        "-worker.account.workers.dev",
        "worker.Account.workers.dev",
    ] {
        assert!(!managed_receiver_host(h), "{h}")
    }
}
#[test]
fn pending_challenges_are_bounded_without_allocating_projects() {
    let p = profile();
    let mut s = State::new(&p).unwrap();
    for n in 1..=32 {
        s.challenge(
            &public(n),
            &format!("{n:064x}"),
            if n <= 24 { 1 } else { 60_001 },
        )
        .unwrap();
    }
    assert_eq!(
        s.challenge(&public(33), &"d".repeat(64), 60_002).err(),
        Some(Error::Limited)
    );
    assert_eq!(s.view(60_002)["remaining_projects"], 10);
    s.challenge(&public(33), &"d".repeat(64), 360_002).unwrap();
}
#[test]
fn revocation_is_sticky_after_configuration_rollback() {
    let p = profile();
    let mut s = State::new(&p).unwrap();
    let c = s.challenge(&public(1), &"a".repeat(64), 1).unwrap();
    let (g, _) = s.complete(&c.id().unwrap(), &signature(&c, 1), 2).unwrap();
    s.revoke(&[g.ticket.project_id.clone()], 3).unwrap();
    s.revoke(&[], 4).unwrap();
    let s: State = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
    assert!(s.route(&g.ticket.project_id).unwrap().revoked);
}
#[test]
fn signed_ingress_replay_has_finite_durable_budget() {
    let p = profile();
    let mut s = State::new(&p).unwrap();
    let c = s.challenge(&public(1), &"a".repeat(64), 1).unwrap();
    let (g, _) = s.complete(&c.id().unwrap(), &signature(&c, 1), 2).unwrap();
    let e = runlater::signed::Envelope {
        version: 1,
        origin: runlater::identity::ORIGIN.into(),
        project_id: g.ticket.project_id,
        public_key: public(1),
        method: "GET".into(),
        path: "/v1/identity/me".into(),
        query: String::new(),
        body_sha256: runlater::security::digest(b""),
        idempotency_key: String::new(),
        issued_at_ms: 2,
        expires_at_ms: 60_002,
        nonce: "a".repeat(64),
    };
    let sig = hex::encode(key(1).sign(&e.bytes().unwrap()).to_bytes());
    for _ in 0..CLIENT_OPERATIONS {
        s.client(&e, &sig, 3).unwrap();
    }
    let mut s: State = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
    assert_eq!(s.client(&e, &sig, 3).err(), Some(Error::Limited));
}
