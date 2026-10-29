//! Disposable local keys and capabilities only. No external enrollment.
use ed25519_dalek::{Signer, SigningKey};
use runlater::{
    anonymous_trial::{Descriptor, Grant, PROVISION, REVOKE, STATUS, VALIDATE},
    invitation::{Enrollment, Mode},
    mcp_delegation::{Proof, Trust},
    public_beta::{Profile, State, DURATION},
    security::digest,
    signed::Envelope,
};
use serde_json::{json, Value};
const CAP: &str = "abababababababababababababababababababababababababababababababab";
const REVOKER: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
fn public() -> String {
    hex::encode(key().verifying_key().to_bytes())
}
fn trust(key: &str) -> Trust<'_> {
    Trust {
        gateway_public_key: key,
        release_id: "trial_test",
    }
}
fn descriptor(n: u8) -> Descriptor {
    let mut d = Descriptor {
        version: 1,
        release_id: "trial_test".into(),
        bootstrap_id: format!("{n:02x}").repeat(32),
        capability_hash: "00".repeat(32),
        revocation_hash: "00".repeat(32),
        issued_at_ms: 10,
        expires_at_ms: 10 + DURATION,
        permissions: vec!["cancel".into(), "enqueue".into(), "read".into()],
    };
    d.capability_hash = d.capability_hash(CAP).unwrap();
    d.revocation_hash = d.revocation_hash(REVOKER).unwrap();
    d
}
fn state() -> State {
    State::new(&Profile {
        release_id: "trial_test".into(),
        opens_at_ms: 0,
        closes_at_ms: DURATION,
        callback_end_sec: (2 * DURATION + runlater::core::DAY) / 1000 + 301,
        self_host: "runlater-public-api.operator.workers.dev".into(),
    })
    .unwrap()
}
fn envelope(d: &Descriptor, path: &str, body: &[u8], now: i64) -> Envelope {
    Envelope {
        version: 1,
        origin: runlater::identity::ORIGIN.into(),
        project_id: d.project_id().unwrap(),
        public_key: String::new(),
        method: if path == STATUS || path.starts_with("/v1/tasks/") && !path.ends_with("/cancel") {
            "GET"
        } else {
            "POST"
        }
        .into(),
        path: path.into(),
        query: String::new(),
        body_sha256: digest(body),
        idempotency_key: if matches!(path, PROVISION | REVOKE | "/v1/tasks") {
            "stable"
        } else {
            ""
        }
        .into(),
        issued_at_ms: now,
        expires_at_ms: (now + 60000).min(d.expires_at_ms),
        nonce: format!("{now:064x}"),
    }
}
fn sig(d: &Descriptor, e: &Envelope) -> String {
    hex::encode(key().sign(&d.bytes(e).unwrap()).to_bytes())
}
fn call(
    s: &mut State,
    d: &Descriptor,
    path: &str,
    now: i64,
) -> Result<Value, runlater::invitation::Error> {
    let body = if path == STATUS {
        b"".as_slice()
    } else {
        b"{}".as_slice()
    };
    let e = envelope(d, path, body, now);
    s.trial_request(
        &e,
        d,
        if path == REVOKE { REVOKER } else { CAP },
        &sig(d, &e),
        trust(&public()),
        body,
        now,
    )
}
fn provision(s: &mut State, d: &Descriptor, now: i64) -> Grant {
    serde_json::from_value(call(s, d, PROVISION, now).unwrap()["grant"].clone()).unwrap()
}
use runlater::{
    callback::{Keyring, Material},
    destinations::EgressPolicy,
    receiver_pairing::{Manifest, Request, ACK, PIN, PULL},
};
fn receiver() -> SigningKey {
    SigningKey::from_bytes(&[43; 32])
}
fn manifest(d: &Descriptor) -> Manifest {
    let mut m = Manifest {
        version: 1,
        release_id: d.release_id.clone(),
        project_id: d.project_id().unwrap(),
        url: "https://receiver.account.workers.dev/callback".into(),
        receiver_public_key: hex::encode(receiver().verifying_key().to_bytes()),
        pairing_id: "ef".repeat(32),
        issued_at_ms: 20,
        expires_at_ms: 300020,
        signature: String::new(),
    };
    m.signature = hex::encode(receiver().sign(&m.bytes().unwrap()).to_bytes());
    m
}
fn pin(s: &mut State, d: &Descriptor, m: &Manifest, now: i64) -> (Envelope, Vec<u8>) {
    let body = serde_json::to_vec(m).unwrap();
    let mut e = envelope(d, PIN, &body, now);
    e.idempotency_key = m.pairing_id.clone();
    s.trial_request(&e, d, CAP, &sig(d, &e), trust(&public()), &body, now)
        .unwrap();
    (e, body)
}
fn request(m: &Manifest, path: &str, body: &str, now: i64) -> Request {
    let mut r = Request {
        project_id: m.project_id.clone(),
        public_key: m.receiver_public_key.clone(),
        pairing_id: m.pairing_id.clone(),
        method: "POST".into(),
        path: path.into(),
        body: body.into(),
        issued_at_ms: now,
        expires_at_ms: (now + 60000).min(m.expires_at_ms),
        nonce: format!("{now:064x}"),
        signature: String::new(),
    };
    r.signature = hex::encode(receiver().sign(&r.bytes(m).unwrap()).to_bytes());
    r
}
fn fixture() -> (
    State,
    Descriptor,
    Manifest,
    Enrollment,
    Keyring,
    runlater::public_beta::TenantKey,
    EgressPolicy,
) {
    let mut s = state();
    let mut d = descriptor(1);
    d.permissions.push("receiver_setup".into());
    let g = provision(&mut s, &d, 20);
    let m = manifest(&d);
    let (e, body) = pin(&mut s, &d, &m, 21);
    let mut p = Enrollment::new(Mode::Invitation);
    p.install_trial(&g, 21).unwrap();
    let signature = sig(&d, &e);
    let k = public();
    p.pairing_pin(
        &e,
        Proof::Trial {
            signature: &signature,
            descriptor: &d,
            capability: CAP,
            trust: trust(&k),
        },
        &body,
        &"ab".repeat(32),
        21,
    )
    .unwrap();
    let material =
        runlater::public_beta::Master::from_hex(&hex::encode((0u8..32).collect::<Vec<_>>()))
            .unwrap()
            .tenant(&d.release_id, &m.project_id)
            .unwrap();
    let keys = Keyring::new(
        &m.project_id,
        "public_beta_trial_test",
        "beta_v1",
        0,
        1500000,
        &material,
    )
    .unwrap();
    (
        s,
        d,
        m,
        p,
        keys,
        material,
        EgressPolicy {
            managed_workers_dev: true,
            approved_hosts: Default::default(),
        },
    )
}
fn prove(p: &mut Enrollment, policy: &EgressPolicy, now: i64) {
    let (_, body) = p.pairing_probe_begin(now).unwrap().unwrap();
    let signature = hex::encode(receiver().sign(body.as_bytes()).to_bytes());
    p.pairing_probe_complete(&signature, &"cd".repeat(32), policy, now + 1)
        .unwrap();
}
#[test]
fn pairing_explicit_scope_and_manifest_do_not_broaden_existing_credentials() {
    let mut s = state();
    let d = descriptor(2);
    provision(&mut s, &d, 20);
    let m = manifest(&d);
    let body = serde_json::to_vec(&m).unwrap();
    let mut e = envelope(&d, PIN, &body, 21);
    e.idempotency_key = m.pairing_id.clone();
    let before = serde_json::to_value(&s).unwrap();
    assert!(s
        .trial_request(&e, &d, CAP, &sig(&d, &e), trust(&public()), &body, 21)
        .is_err());
    assert_eq!(before, serde_json::to_value(&s).unwrap());
    assert!(!runlater::public_beta::Profile::terms()
        .permissions
        .contains(&runlater::auth::Permission::ReceiverSetup));
}
#[test]
fn private_pull_ack_nonreflection_and_actual_registered_task_admission() {
    let (mut global, d, m, mut p, keys, material, policy) = fixture();
    prove(&mut p, &policy, 22);
    let r = request(&m, PULL, "{}", 24);
    assert!(global.receiver_route(&r, 24).is_ok());
    let payload = p.pairing_pull(&r, &keys, &material, 24).unwrap();
    assert!(p.pairing_pull(&r, &keys, &material, 24).is_err());
    let second = p
        .pairing_pull(&request(&m, PULL, "{}", 25), &keys, &material, 25)
        .unwrap();
    assert_eq!(payload, second);
    assert_eq!(
        payload["installation_sha256"],
        digest(&serde_json::to_vec(&payload["installation"]).unwrap())
    );
    let serialized = serde_json::to_string(&p).unwrap();
    assert!(!serialized.contains(&hex::encode(material.key("beta_v1").unwrap())));
    let ackbody =
        serde_json::to_string(&json!({"installation_sha256":payload["installation_sha256"]}))
            .unwrap();
    let ack = request(&m, ACK, &ackbody, 26);
    let challenge = p.pairing_ack_begin(&ack, &policy, 26).unwrap().unwrap();
    let hidden = payload["installation"]["destination_proof"]["response"]
        .as_str()
        .unwrap();
    assert_ne!(challenge.body, hidden);
    assert!(p
        .pairing_ack_complete(
            &ack,
            &challenge,
            200,
            challenge.body.as_bytes(),
            &policy,
            27
        )
        .is_err());
    let ready = p
        .pairing_ack_complete(&ack, &challenge, 200, hidden.as_bytes(), &policy, 27)
        .unwrap();
    assert_eq!(ready["receiver_ready"], true);
    assert!(p
        .pairing_ack_begin(&request(&m, ACK, &ackbody, 28), &policy, 28)
        .unwrap()
        .is_none());
    assert!(!serde_json::to_string(&p).unwrap().contains(hidden));
    let status = envelope(&d, STATUS, b"", 29);
    assert_eq!(
        p.validate_trial(&status, &d, CAP, &sig(&d, &status), trust(&public()), 29)
            .unwrap()["endpoint_id"],
        "receiver"
    );
    let body=serde_json::to_vec(&json!({"destination":"registered:receiver","body":"fixture","operation_key":"paired","run_at_ms":0})).unwrap();
    let e = envelope(&d, "/v1/tasks", &body, 30);
    let sign = sig(&d, &e);
    let k = public();
    let proof = Proof::Trial {
        signature: &sign,
        descriptor: &d,
        capability: CAP,
        trust: trust(&k),
    };
    assert_eq!(
        p.registered_beta_task_command_with_proof(&e, proof, &body, &policy, &keys, &material, 30)
            .unwrap()["task_accepted"],
        true
    );
    call(&mut global, &d, REVOKE, 31).unwrap();
    assert!(global
        .receiver_route(&request(&m, PULL, "{}", 32), 32)
        .is_err());
}
#[test]
fn public_probe_cannot_authorize_private_pull_and_context_tampering_is_rejected() {
    let (s, _d, m, mut p, keys, material, policy) = fixture();
    prove(&mut p, &policy, 22);
    let mut r = request(&m, PULL, "{}", 24);
    r.signature = hex::encode(
        receiver()
            .sign(m.probe(&"ab".repeat(32)).unwrap().as_bytes())
            .to_bytes(),
    );
    assert!(s.receiver_route(&r, 24).is_err());
    assert!(p.pairing_pull(&r, &keys, &material, 24).is_err());
    for n in 0..5 {
        let mut r = request(&m, PULL, "{}", 24);
        match n {
            0 => r.path = ACK.into(),
            1 => r.project_id = "p_other".into(),
            2 => r.body = "{ }".into(),
            3 => r.pairing_id = "aa".repeat(32),
            _ => r.expires_at_ms = 24,
        }
        assert!(s.receiver_route(&r, 24).is_err());
    }
}
#[test]
fn immutable_binding_and_retry_budgets_survive_snapshot_reload() {
    let (mut s, d, m, mut p, keys, material, policy) = fixture();
    let mut changed = m.clone();
    changed.url = "https://other.account.workers.dev/callback".into();
    changed.signature = hex::encode(receiver().sign(&changed.bytes().unwrap()).to_bytes());
    let body = serde_json::to_vec(&changed).unwrap();
    let mut e = envelope(&d, PIN, &body, 22);
    e.idempotency_key = m.pairing_id.clone();
    assert!(s
        .trial_request(&e, &d, CAP, &sig(&d, &e), trust(&public()), &body, 22)
        .is_err());
    for _ in 0..3 {
        assert!(p.pairing_probe_begin(23).unwrap().is_some());
    }
    let value = serde_json::to_value(&p).unwrap();
    p = serde_json::from_value(value).unwrap();
    assert!(p.pairing_probe_begin(24).is_err());
    // A separately configured project can prove and resume a lost acknowledgement with the same hidden proof.
    let (_, _, m, mut p, keys2, material2, policy2) = fixture();
    prove(&mut p, &policy2, 22);
    let payload = p
        .pairing_pull(&request(&m, PULL, "{}", 24), &keys2, &material2, 24)
        .unwrap();
    let body =
        serde_json::to_string(&json!({"installation_sha256":payload["installation_sha256"]}))
            .unwrap();
    let first = p
        .pairing_ack_begin(&request(&m, ACK, &body, 25), &policy2, 25)
        .unwrap()
        .unwrap();
    p = serde_json::from_value(serde_json::to_value(&p).unwrap()).unwrap();
    let second = p
        .pairing_ack_begin(&request(&m, ACK, &body, 26), &policy2, 26)
        .unwrap()
        .unwrap();
    assert_eq!(first.body, second.body);
    assert!(p
        .pairing_ack_begin(&request(&m, ACK, &body, 27), &policy2, 27)
        .unwrap()
        .is_some());
    assert!(p
        .pairing_ack_begin(&request(&m, ACK, &body, 28), &policy2, 28)
        .is_err());
    assert!(p
        .pairing_pull(
            &request(&m, PULL, "{}", m.expires_at_ms),
            &keys,
            &material,
            m.expires_at_ms
        )
        .is_err());
    let _ = policy;
}

#[test]
fn trusted_queue_routes_trial_tickets_without_reenrollment_or_expiry_extension() {
    let (mut s, d, m, _p, _keys, _material, _policy) = fixture();
    let original = s.route(&m.project_id).unwrap();
    assert!(!original.revoked);
    call(&mut s, &d, REVOKE, 31).unwrap();
    assert_eq!(
        s.route(&m.project_id).unwrap(),
        original,
        "capability revocation does not recall admitted tasks"
    );
    s.revoke(&[m.project_id.clone()], 32).unwrap();
    let ticket = s.route(&m.project_id).unwrap();
    assert!(
        ticket.revoked,
        "operator project revocation remains authoritative for queue"
    );
    s = serde_json::from_value(serde_json::to_value(&s).unwrap()).unwrap();
    assert!(s.route(&m.project_id).unwrap().revoked);
}

#[test]
fn receiver_registry_time_regression_fails_closed_without_state_changes() {
    let (s, _d, m, _p, _keys, _material, _policy) = fixture();
    let mut stored = serde_json::to_value(&s).unwrap();
    stored["clock_ms"] = 100.into();
    let s: State = serde_json::from_value(stored.clone()).unwrap();
    s.check().unwrap();
    let r = request(&m, PULL, "{}", 40);
    for now in [40, -1, 9_007_199_254_740_992] {
        assert!(matches!(
            s.receiver_route(&r, now),
            Err(runlater::invitation::Error::Clock)
        ));
        assert_eq!(serde_json::to_value(&s).unwrap(), stored);
    }
}
