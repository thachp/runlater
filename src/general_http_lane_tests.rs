//! Disposable local keys and capabilities only. No external enrollment.
use crate::{
    anonymous_trial::{Descriptor, Grant, PROVISION, REVOKE, STATUS, VALIDATE},
    invitation::{Enrollment, Mode},
    mcp_delegation::{Proof, Trust},
    public_beta::{Profile, State, DURATION},
    security::digest,
    signed::Envelope,
};
use ed25519_dalek::{Signer, SigningKey};
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
        callback_end_sec: (2 * DURATION + crate::core::DAY) / 1000 + 301,
        self_host: "runlater-public-api.operator.workers.dev".into(),
    })
    .unwrap()
}
fn envelope(d: &Descriptor, path: &str, body: &[u8], now: i64) -> Envelope {
    Envelope {
        version: 1,
        origin: crate::identity::ORIGIN.into(),
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
) -> Result<Value, crate::invitation::Error> {
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
use crate::{
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
    crate::public_beta::TenantKey,
    EgressPolicy,
) {
    let mut s = state();
    let mut d = descriptor(1);
    d.permissions = vec![
        "cancel".into(),
        "enqueue".into(),
        "http_schedule".into(),
        "read".into(),
        "receiver_setup".into(),
    ];
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
        crate::public_beta::Master::from_hex(&hex::encode((0u8..32).collect::<Vec<_>>()))
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
fn mixed_lanes_reserve_only_publishable_references_without_quota_reset() {
    let (_, d, m, mut p, keys, material, policy) = fixture();
    prove(&mut p, &policy, 22);
    let payload = p
        .pairing_pull(&request(&m, PULL, "{}", 24), &keys, &material, 24)
        .unwrap();
    let ackbody =
        serde_json::to_string(&json!({"installation_sha256":payload["installation_sha256"]}))
            .unwrap();
    let ack = request(&m, ACK, &ackbody, 26);
    let challenge = p.pairing_ack_begin(&ack, &policy, 26).unwrap().unwrap();
    p.pairing_ack_complete(
        &ack,
        &challenge,
        200,
        payload["installation"]["destination_proof"]["response"]
            .as_str()
            .unwrap()
            .as_bytes(),
        &policy,
        27,
    )
    .unwrap();
    let body=serde_json::to_vec(&json!({"destination":"registered:receiver","body":"fixture","operation_key":"paired","run_at_ms":0})).unwrap();
    let e = envelope(&d, "/v1/tasks", &body, 30);
    let sign = sig(&d, &e);
    let k = public();
    let callback = p
        .registered_beta_task_command_with_proof(
            &e,
            Proof::Trial {
                signature: &sign,
                descriptor: &d,
                capability: CAP,
                trust: trust(&k),
            },
            &body,
            &policy,
            &keys,
            &material,
            30,
        )
        .unwrap();
    let callback_id = callback["result"]["id"].as_str().unwrap().to_owned();
    let raw=serde_json::to_vec(&json!({"url":"https://customer.example.com/hook","payload":{"test":true},"run_at_ms":0,"operation_key":"general"})).unwrap();
    let mut e = envelope(&d, crate::general_http::CREATE, &raw, 31);
    e.idempotency_key = "general".into();
    let sign = sig(&d, &e);
    let permit = super::AdmissionPermit::from_reviewed_revision(&"c".repeat(64)).unwrap();
    let general = p
        .schedule_http(
            &e,
            Proof::Trial {
                signature: &sign,
                descriptor: &d,
                capability: CAP,
                trust: trust(&k),
            },
            &raw,
            Some(&permit),
            31,
        )
        .unwrap();
    let general_id = general["result"]["id"].as_str().unwrap().to_owned();
    let count = |p: &Enrollment| {
        serde_json::to_value(p).unwrap()["project"]["delivery"]["publications"]
            .as_u64()
            .unwrap()
    };
    let before = count(&p);
    let refs = p
        .registered_outbox_lanes(&d.project_id().unwrap(), 32, false, true)
        .unwrap();
    assert_eq!(
        refs.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
        vec![general_id.as_str()]
    );
    assert_eq!(count(&p), before + 1);
    assert!(!p
        .project
        .ledger
        .get(&callback_id)
        .unwrap()
        .status
        .terminal());
    let refs = p
        .registered_outbox_lanes(&d.project_id().unwrap(), 33, true, false)
        .unwrap();
    assert_eq!(
        refs.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
        vec![callback_id.as_str()]
    );
    assert_eq!(count(&p), before + 2);
    assert!(p
        .registered_outbox_lanes(&d.project_id().unwrap(), 34, false, false)
        .unwrap()
        .is_empty());
    assert_eq!(count(&p), before + 2);
    let refs = p
        .registered_outbox_lanes(&d.project_id().unwrap(), 35, true, true)
        .unwrap();
    assert_eq!(refs.len(), 2);
    assert_eq!(count(&p), before + 4);
    assert_eq!(
        serde_json::to_value(&p).unwrap()["outbound"]["beta_admissions"],
        2
    );
}
