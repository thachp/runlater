use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use runlater_offline_credit_purchases::{self as credit, Intent, SettlementVerifier};
use runlater_offline_mpp_http::*;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::BTreeMap;

fn fixtures() -> Value {
    serde_json::from_str(include_str!("../fixtures/stripe-charge-fiction.json")).unwrap()
}
fn rest_fixtures() -> Value {
    serde_json::from_str(include_str!("../fixtures/stripe-rest-contract.json")).unwrap()
}
fn quote() -> Intent {
    serde_json::from_value(fixtures()["quote"].clone()).unwrap()
}
fn context() -> OfflineMerchantContext {
    serde_json::from_value(fixtures()["context"].clone()).unwrap()
}
fn body() -> String {
    fixtures()["body"].as_str().unwrap().into()
}
fn now() -> i64 {
    fixtures()["now_ms"].as_i64().unwrap()
}
fn issued(alternate: bool) -> IssuedChallenge {
    IssuedChallenge::offline(
        &quote(),
        context(),
        "offline_fixture_challenge_a",
        body().as_bytes(),
        if alternate {
            CredentialField::PaymentAuthorization
        } else {
            CredentialField::Authorization
        },
    )
    .unwrap()
}
fn encoded(v: &Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
}
fn credential(v: &Value) -> String {
    format!("Payment {}", encoded(v))
}
fn wire(alternate: bool) -> String {
    fixtures()["variants"][usize::from(alternate)]["credential_header"]
        .as_str()
        .unwrap()
        .into()
}
fn headers<'a>(value: &'a str, alternate: bool) -> Vec<(&'a str, &'a str)> {
    vec![(
        if alternate {
            "Payment-Authorization"
        } else {
            "Authorization"
        },
        value,
    )]
}
fn plan(alternate: bool) -> UnexecutedStripeRequest {
    issued(alternate)
        .prepare(
            &quote(),
            &quote().project_id,
            &headers(&wire(alternate), alternate),
            body().as_bytes(),
            now(),
        )
        .unwrap()
}

#[test]
fn pinned_drafts_match_current_retrieved_fixture_manifest() {
    let v: Value =
        serde_json::from_str(include_str!("../fixtures/drafts-and-vectors.json")).unwrap();
    assert_eq!(v["auth"]["id"], AUTH_DRAFT);
    assert_eq!(v["stripe"]["id"], STRIPE_DRAFT);
    assert!(fixtures()["fixture_only"].as_bool().unwrap());
}
#[test]
fn stripe_rest_descriptor_nests_the_spt_independently_of_the_mpp_draft() {
    let p = plan(false);
    assert_eq!(
        p.body_for_inspection()["payment_method_data"]["shared_payment_granted_token"],
        "spt_OFFLINE_NOT_A_PAYMENT_TOKEN"
    );
    assert!(p
        .body_for_inspection()
        .get("shared_payment_granted_token")
        .is_none());
}
#[test]
fn independent_python_golden_challenges_credentials_and_unexecuted_plans() {
    for alternate in [false, true] {
        let f = fixtures();
        let v = &f["variants"][usize::from(alternate)];
        let issued = issued(alternate);
        assert_eq!(quote().digest(), f["quote_digest"].as_str().unwrap());
        assert_eq!(
            serde_json::to_value(issued.challenge()).unwrap(),
            v["challenge"]
        );
        assert_eq!(
            issued.challenge().to_header().unwrap(),
            v["challenge_header"]
        );
        assert_eq!(
            Challenge::parse(v["challenge_header"].as_str().unwrap()).unwrap(),
            *issued.challenge()
        );
        let p = plan(alternate);
        // The protocol draft's SDK illustration is not the REST wire contract.
        assert!(v["draft_sdk_example"]
            .get("shared_payment_granted_token")
            .is_some());
        let rest = rest_fixtures();
        let golden = &rest["variants"][usize::from(alternate)];
        assert_eq!(p.body_for_inspection(), &golden["expected_semantics"]);
        assert_eq!(p.form_body_for_inspection(), golden["expected_form_body"]);
        assert_eq!(p.api_version(), rest["api_version"]);
        assert_eq!(p.content_type(), rest["content_type"]);
        assert_eq!(p.url(), rest["url"]);
        assert_eq!(p.api_version(), stripe::API_VERSION);
        assert_eq!(p.content_type(), stripe::CONTENT_TYPE);
        assert_eq!(p.idempotency_key(), v["expected_idempotency_key"]);
        assert_eq!(
            p.headers_for_inspection(),
            [
                ("Stripe-Version", stripe::API_VERSION),
                ("Content-Type", stripe::CONTENT_TYPE),
                ("Idempotency-Key", p.idempotency_key()),
            ]
        );
        assert_eq!(p.operation(), "POST /v1/payment_intents");
        assert!(!p.activation_enabled());
        for key in [
            "payment_method_types",
            "stripe_account",
            "on_behalf_of",
            "transfer_data",
            "application_fee_amount",
        ] {
            assert!(p.body_for_inspection().get(key).is_none());
        }
    }
}
#[test]
fn protocol_decoding_and_provider_encoding_are_separate_and_repeatable() {
    let bound = issued(true)
        .decode_credential(
            &quote(),
            &quote().project_id,
            &headers(&wire(true), true),
            body().as_bytes(),
            now(),
        )
        .unwrap();
    assert_eq!(
        format!("{bound:?}"),
        "BoundStripeCredential(<redacted>, unverified)"
    );
    let a = stripe::encode(&bound).unwrap();
    let b = stripe::encode(&bound).unwrap();
    assert_eq!(a.form_body_for_inspection(), b.form_body_for_inspection());
    assert_eq!(a.idempotency_key(), plan(true).idempotency_key());
    assert!(!a.activation_enabled());
}
#[test]
fn form_values_cannot_inject_parameters_and_preserve_sensitive_ascii_bytes() {
    let f = rest_fixtures();
    let q: Intent = serde_json::from_value(f["escaping"]["quote"].clone()).unwrap();
    let issuer = IssuedChallenge::offline(
        &q,
        context(),
        "offline_fixture_challenge_a",
        body().as_bytes(),
        CredentialField::Authorization,
    )
    .unwrap();
    let mut value = fixtures()["variants"][0]["credential"].clone();
    value["challenge"] = serde_json::to_value(issuer.challenge()).unwrap();
    value["payload"]["spt"] = f["escaping"]["spt"].clone();
    let wire = credential(&value);
    let p = issuer
        .prepare(
            &q,
            &q.project_id,
            &headers(&wire, false),
            body().as_bytes(),
            now(),
        )
        .unwrap();
    assert_eq!(
        p.form_body_for_inspection(),
        f["escaping"]["expected_form_body"]
    );
    assert_eq!(p.form_body_for_inspection().split('&').count(), 10);
    assert!(!p.form_body_for_inspection().contains("&x="));
    assert!(!format!("{p:?}").contains("spt_"));
}
#[test]
fn provider_amount_limit_does_not_redefine_the_protocol_or_credit_model() {
    assert_eq!(
        rest_fixtures()["max_amount_minor"],
        stripe::MAX_AMOUNT_MINOR
    );
    for (amount, accepted) in [
        (1, true),
        (stripe::MAX_AMOUNT_MINOR, true),
        (stripe::MAX_AMOUNT_MINOR + 1, false),
        (credit::SAFE, false),
    ] {
        let mut q = quote();
        q.amount_minor = amount;
        let issuer = IssuedChallenge::offline(
            &q,
            context(),
            "offline_fixture_bounds",
            body().as_bytes(),
            CredentialField::Authorization,
        )
        .unwrap();
        let mut c = fixtures()["variants"][0]["credential"].clone();
        c["challenge"] = serde_json::to_value(issuer.challenge()).unwrap();
        let wire = credential(&c);
        let h = headers(&wire, false);
        let bound = issuer
            .decode_credential(&q, &q.project_id, &h, body().as_bytes(), now())
            .unwrap();
        let result = stripe::encode(&bound);
        assert_eq!(result.is_ok(), accepted);
        assert_eq!(
            issuer
                .prepare(&q, &q.project_id, &h, body().as_bytes(), now())
                .is_ok(),
            accepted
        );
        if !accepted {
            assert_eq!(result.unwrap_err(), Error::Bounds);
        }
    }
}
#[test]
fn all_three_published_public_hmac_binding_vectors() {
    let f: Value =
        serde_json::from_str(include_str!("../fixtures/drafts-and-vectors.json")).unwrap();
    let v = &f["public_hmac_vectors"];
    for vector in v["vectors"].as_array().unwrap() {
        let ch = Challenge {
            id: vector["expected_id"].as_str().unwrap().into(),
            realm: v["realm"].as_str().unwrap().into(),
            method: v["method"].as_str().unwrap().into(),
            intent: v["intent"].as_str().unwrap().into(),
            request: v["request"].as_str().unwrap().into(),
            expires: None,
            digest: None,
            opaque: vector["opaque"].as_str().map(Into::into),
            header: vector["header"].as_str().map(Into::into),
            description: None,
            extensions: BTreeMap::new(),
        };
        let mut hmac =
            Hmac::<Sha256>::new_from_slice(v["public_test_secret"].as_str().unwrap().as_bytes())
                .unwrap();
        hmac.update(ch.hmac_binding_input().unwrap().as_bytes());
        assert_eq!(
            URL_SAFE_NO_PAD.encode(hmac.finalize().into_bytes()),
            vector["expected_id"]
        );
        assert_eq!(Challenge::parse(&ch.to_header().unwrap()).unwrap(), ch);
    }
}
#[test]
fn challenge_http_quoting_case_and_unknown_extensions() {
    let mut ch = issued(true).challenge().clone();
    ch.description = Some("fiction, with \"quotes\" and \\ slash".into());
    ch.extensions
        .insert("x-future".into(), "fiction, extension".into());
    let wire = ch.to_header().unwrap();
    assert_eq!(Challenge::parse(&wire).unwrap(), ch);
    assert_eq!(
        Challenge::parse(&wire.replacen("Payment ", "pAyMeNt   ", 1)).unwrap(),
        ch
    );
    let v = wire.replacen("id=", "ID \t=\t", 1);
    assert_eq!(Challenge::parse(&v).unwrap(), ch);
    let mut duplicate = ch.clone();
    duplicate.extensions.insert("ID".into(), "other".into());
    assert!(duplicate.to_header().is_err());
}
#[test]
fn malformed_duplicate_missing_and_injected_challenges_reject() {
    let good = issued(true).challenge().to_header().unwrap();
    for bad in [
        "Payment".into(),
        "Basic abc".into(),
        format!("{good}, id=other"),
        format!("{good}, ID=other"),
        format!("{good},"),
        format!("{good}, Bearer abc"),
        format!("{good}\r\nX: injected"),
        good.replace("id=\"offline_fixture_challenge_a\"", "id=\"\""),
        good.replace("intent=\"charge\"", "intent=\"session\""),
        good.replace("header=\"Payment-Authorization\"", "header=\"Cookie\""),
        good.replace("method=\"stripe\"", "method=\"Stripe\""),
        good.replace("id=\"offline_fixture_challenge_a\", ", ""),
        format!("Payment {}", "a".repeat(MAX_HEADER)),
    ] {
        assert!(
            Challenge::parse(&bad).is_err(),
            "unexpected challenge acceptance"
        );
    }
}
#[test]
fn base64_and_jcs_are_canonical_bounded_and_duplicate_free() {
    let original = issued(true).challenge().clone();
    for raw in [
        r#"{"amount":"100","amount":"200"}"#,
        r#"{ "amount":"100"}"#,
        r#"{"z":"last","a":"first"}"#,
        r#"{"amount":100}"#,
        r#"[]"#,
        r#"{"x":true}"#,
    ] {
        let mut ch = original.clone();
        ch.request = URL_SAFE_NO_PAD.encode(raw);
        assert!(ch.to_header().is_err());
    }
    for encoded in ["e30=", "e30+", "e30/", "e31", "a", "_w"] {
        let mut ch = original.clone();
        ch.request = encoded.into();
        assert!(ch.to_header().is_err());
    }
    // JCS key ordering is UTF-16; supplementary characters sort before U+E000.
    let mut ch = original.clone();
    ch.request = URL_SAFE_NO_PAD.encode("{\"😀\":\"first\",\"\u{e000}\":\"second\"}");
    assert!(ch.to_header().is_ok());
    ch.request = URL_SAFE_NO_PAD.encode("{\"\u{e000}\":\"second\",\"😀\":\"first\"}");
    assert!(ch.to_header().is_err());
    let mut ch = original;
    ch.opaque = Some(URL_SAFE_NO_PAD.encode(r#"{"a":{"nested":"no"}}"#));
    assert!(ch.to_header().is_err());
}
#[test]
fn both_selected_header_modes_and_duplicate_fields_are_enforced() {
    for alternate in [false, true] {
        let issued = issued(alternate);
        let wire = wire(alternate);
        let correct = if alternate {
            "Payment-Authorization"
        } else {
            "Authorization"
        };
        let wrong = if alternate {
            "Authorization"
        } else {
            "Payment-Authorization"
        };
        assert!(issued
            .prepare(
                &quote(),
                &quote().project_id,
                &[(correct, &wire)],
                body().as_bytes(),
                now()
            )
            .is_ok());
        assert_eq!(
            issued
                .prepare(
                    &quote(),
                    &quote().project_id,
                    &[(wrong, &wire)],
                    body().as_bytes(),
                    now()
                )
                .unwrap_err(),
            Error::WrongHeader
        );
        assert_eq!(
            issued
                .prepare(
                    &quote(),
                    &quote().project_id,
                    &[(correct, &wire), (wrong, &wire)],
                    body().as_bytes(),
                    now()
                )
                .unwrap_err(),
            Error::WrongHeader
        );
        assert_eq!(
            issued
                .prepare(
                    &quote(),
                    &quote().project_id,
                    &[(correct, &wire), (correct, &wire)],
                    body().as_bytes(),
                    now()
                )
                .unwrap_err(),
            Error::DuplicateHeader
        );
        if alternate {
            assert!(issued
                .prepare(
                    &quote(),
                    &quote().project_id,
                    &[
                        (correct, &wire),
                        ("Authorization", "Bearer ordinary-task-authority")
                    ],
                    body().as_bytes(),
                    now()
                )
                .is_ok());
        }
    }
}
#[test]
fn every_critical_echo_binding_is_checked() {
    let f = fixtures();
    let original = f["variants"][1]["credential"].clone();
    let issued = issued(true);
    for field in [
        "id", "realm", "method", "intent", "request", "expires", "digest", "opaque", "header",
    ] {
        let mut c = original.clone();
        match field {
            "method" => c["challenge"][field] = json!("tempo"),
            "intent" => c["challenge"][field] = json!("session"),
            "request" => {
                let mut r = f["request"].clone();
                r["amount"] = json!("101");
                c["challenge"][field] = json!(encoded(&r));
            }
            "expires" => c["challenge"][field] = json!("2027-01-15T08:02:00.000Z"),
            "digest" => c["challenge"][field] = json!(body_digest(b"other").unwrap()),
            "opaque" => {
                c["challenge"][field] = json!(URL_SAFE_NO_PAD.encode(r#"{"project_id":"other"}"#))
            }
            "header" => {
                c["challenge"].as_object_mut().unwrap().remove("header");
            }
            _ => c["challenge"][field] = json!("other"),
        }
        assert!(
            issued
                .prepare(
                    &quote(),
                    &quote().project_id,
                    &headers(&credential(&c), true),
                    body().as_bytes(),
                    now()
                )
                .is_err(),
            "binding was accepted"
        );
    }
    let mut c = original.clone();
    let mut r = f["request"].clone();
    r["methodDetails"]["networkId"] = json!("profile_other");
    c["challenge"]["request"] = json!(encoded(&r));
    assert_eq!(
        issued
            .prepare(
                &quote(),
                &quote().project_id,
                &headers(&credential(&c), true),
                body().as_bytes(),
                now()
            )
            .unwrap_err(),
        Error::Binding
    );
}
#[test]
fn foreign_tenant_mutated_quote_body_and_expiry_reject() {
    let issued = issued(true);
    let wire = wire(true);
    let headers = headers(&wire, true);
    assert_eq!(
        issued
            .prepare(&quote(), "other", &headers, body().as_bytes(), now())
            .unwrap_err(),
        Error::Binding
    );
    let mut q = quote();
    q.amount_minor += 1;
    assert_eq!(
        issued
            .prepare(&q, &q.project_id, &headers, body().as_bytes(), now())
            .unwrap_err(),
        Error::Binding
    );
    assert_eq!(
        issued
            .prepare(&quote(), &quote().project_id, &headers, b"other", now())
            .unwrap_err(),
        Error::Binding
    );
    for t in [quote().issued_at_ms - 1, quote().expires_at_ms] {
        assert_eq!(
            issued
                .prepare(
                    &quote(),
                    &quote().project_id,
                    &headers,
                    body().as_bytes(),
                    t
                )
                .unwrap_err(),
            Error::Expired
        );
    }
}
#[test]
fn descriptive_metadata_source_and_client_reference_never_change_authoritative_amount() {
    let mut c = fixtures()["variants"][1]["credential"].clone();
    c["challenge"]["description"] = json!("fiction says free; has no authority");
    c["challenge"]["x-future"] = json!("ignored");
    c["source"] = json!("did:example:other");
    c["payload"]["externalId"] = json!("untrusted_client_ref");
    let p = issued(true)
        .prepare(
            &quote(),
            &quote().project_id,
            &headers(&credential(&c), true),
            body().as_bytes(),
            now(),
        )
        .unwrap();
    assert_eq!(p.body_for_inspection(), plan(true).body_for_inspection());
    assert_eq!(p.idempotency_key(), plan(true).idempotency_key());
}
#[test]
fn malformed_credential_payloads_duplicates_injection_and_bounds_fail() {
    let good = fixtures()["variants"][1]["credential"].clone();
    let issued = issued(true);
    for bad in [
        json!({"status":"succeeded","id":"pi_fake"}),
        json!({"challenge":good["challenge"],"payload":{"spt":"not_spt"}}),
        json!({"challenge":good["challenge"],"payload":{"spt":"spt_"}}),
        json!({"challenge":good["challenge"],"payload":{"spt":"spt_FICTION","application_fee_amount":"1"}}),
        json!({"challenge":good["challenge"],"payload":{"spt":"spt_FICTION"},"stripeAccount":"acct_fake"}),
    ] {
        assert!(issued
            .prepare(
                &quote(),
                &quote().project_id,
                &headers(&credential(&bad), true),
                body().as_bytes(),
                now()
            )
            .is_err());
    }
    let duplicate = format!(
        "{{\"challenge\":{},\"payload\":{{\"spt\":\"spt_FIRST\",\"spt\":\"spt_SECOND\"}}}}",
        good["challenge"]
    );
    assert!(issued
        .prepare(
            &quote(),
            &quote().project_id,
            &headers(
                &format!("Payment {}", URL_SAFE_NO_PAD.encode(duplicate)),
                true
            ),
            body().as_bytes(),
            now()
        )
        .is_err());
    for bad in [
        format!("{}=", wire(true)),
        format!("{}\r\nX: injected", wire(true)),
        format!("Payment {}", "a".repeat(MAX_HEADER)),
    ] {
        assert!(issued
            .prepare(
                &quote(),
                &quote().project_id,
                &headers(&bad, true),
                body().as_bytes(),
                now()
            )
            .is_err());
    }
}
#[test]
fn retries_keep_idempotency_and_other_token_quote_changes_it() {
    assert_eq!(plan(true).idempotency_key(), plan(true).idempotency_key());
    assert!(!plan(true).idempotency_key().contains("spt_"));
    let mut c = fixtures()["variants"][1]["credential"].clone();
    c["payload"]["spt"] = json!("spt_OTHER_FICTION");
    let other = issued(true)
        .prepare(
            &quote(),
            &quote().project_id,
            &headers(&credential(&c), true),
            body().as_bytes(),
            now(),
        )
        .unwrap();
    assert_ne!(other.idempotency_key(), plan(true).idempotency_key());
    let mut q = quote();
    q.project_id = "other_project".into();
    let issued = IssuedChallenge::offline(
        &q,
        context(),
        "offline_fixture_challenge_a",
        body().as_bytes(),
        CredentialField::PaymentAuthorization,
    )
    .unwrap();
    let mut c = fixtures()["variants"][1]["credential"].clone();
    c["challenge"] = serde_json::to_value(issued.challenge()).unwrap();
    let other = issued
        .prepare(
            &q,
            &q.project_id,
            &headers(&credential(&c), true),
            body().as_bytes(),
            now(),
        )
        .unwrap();
    assert_ne!(other.idempotency_key(), plan(true).idempotency_key());
}
#[test]
fn receipt_codec_is_syntax_only_and_rejects_error_status_or_failure_receipt() {
    let f = fixtures();
    let r = UntrustedReceipt::parse(200, f["receipt_header"].as_str().unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&r).unwrap(), f["receipt"]);
    assert_eq!(r.to_fixture_header().unwrap(), f["receipt_header"]);
    assert!(UntrustedReceipt::parse(402, f["receipt_header"].as_str().unwrap()).is_err());
    for change in [
        json!({"status":"pending"}),
        json!({"timestamp":"tomorrow"}),
        json!({"method":"Stripe"}),
        json!({"reference":""}),
    ] {
        let mut raw = f["receipt"].clone();
        for (k, v) in change.as_object().unwrap() {
            raw[k] = v.clone();
        }
        assert!(UntrustedReceipt::parse(200, &encoded(&raw)).is_err());
    }
}
#[test]
fn fabricated_success_receipt_and_paymentintent_cannot_mint_any_credit() {
    let p = credit::Policy {
        version: 1,
        offer: credit::Offer {
            id: "fictional_offer".into(),
            amount_minor: 100,
            currency: "xxx".into(),
            attempt_units: 10,
            quote_ttl_ms: 1000,
            admission_ttl_ms: 10000,
        },
        starts_at_ms: 1,
        ends_at_ms: 20000,
        project_window_minor: 100,
        purchasers: BTreeMap::from([(
            "buyer".into(),
            credit::DelegateCap {
                per_purchase_minor: 100,
                window_minor: 100,
            },
        )]),
    };
    let mut ledger = credit::OfflineLedger::new("fictional_project", Some(p)).unwrap();
    let q = ledger
        .create_intent(
            ledger.revision(),
            credit::Authority::Purchase {
                project: "fictional_project",
                principal: "buyer",
            },
            "fictional_key",
            1,
            10,
        )
        .unwrap();
    let receipt = fixtures()["receipt_header"].as_str().unwrap().to_owned();
    assert!(UntrustedReceipt::parse(200, &receipt).is_ok());
    let before = ledger.snapshot().unwrap();
    for fake in [
        receipt.as_bytes(),
        br#"{"id":"pi_fake","status":"succeeded","amount":100,"currency":"xxx"}"#.as_slice(),
    ] {
        assert_eq!(
            credit::DisabledVerifier.verify(&q, fake),
            Err(credit::Error::Disabled)
        );
        assert_eq!(
            ledger.reconcile(
                ledger.revision(),
                &q.project_id,
                &q.id,
                fake,
                &credit::DisabledVerifier,
                20
            ),
            Err(credit::Error::Disabled)
        );
        assert_eq!(ledger.snapshot().unwrap(), before);
        assert!(ledger
            .receipt(&q.project_id, &q.id)
            .unwrap()
            .entitlement_order
            .is_none());
    }
}
#[test]
fn no_defaults_and_safe_amount_timestamp_body_context_limits() {
    let mut q = quote();
    q.amount_minor = credit::SAFE + 1;
    assert!(IssuedChallenge::offline(
        &q,
        context(),
        "offline_id",
        b"",
        CredentialField::Authorization
    )
    .is_err());
    let mut ctx = context();
    ctx.network_id.clear();
    assert!(IssuedChallenge::offline(
        &quote(),
        ctx,
        "offline_id",
        b"",
        CredentialField::Authorization
    )
    .is_err());
    let mut ctx = context();
    ctx.payment_method_types = vec!["card".into(), "card".into()];
    assert!(IssuedChallenge::offline(
        &quote(),
        ctx,
        "offline_id",
        b"",
        CredentialField::Authorization
    )
    .is_err());
    let mut q = quote();
    q.expires_at_ms = credit::SAFE as i64 + 1;
    assert!(IssuedChallenge::offline(
        &q,
        context(),
        "offline_id",
        b"",
        CredentialField::Authorization
    )
    .is_err());
    assert!(IssuedChallenge::offline(
        &quote(),
        context(),
        "real_challenge",
        b"",
        CredentialField::Authorization
    )
    .is_err());
    assert!(body_digest(&vec![b'a'; MAX_BODY + 1]).is_err());
}
#[test]
fn debug_does_not_print_payment_material() {
    let f = fixtures();
    let receipt = UntrustedReceipt::parse(200, f["receipt_header"].as_str().unwrap()).unwrap();
    assert_eq!(format!("{receipt:?}"), "UntrustedReceipt(<redacted>)");
    assert_eq!(
        format!("{:?}", plan(true)),
        "UnexecutedStripeRequest(<redacted>, activation=false)"
    );
    assert_eq!(
        format!("{:?}", issued(true).challenge()),
        "Challenge(<redacted>)"
    );
}

#[test]
fn nested_duplicate_json_depth_and_collection_limits_reject() {
    let original = fixtures()["variants"][1]["credential"].clone();
    let issuer = issued(true);
    let mut bad = original.clone();
    bad["payload"]["spt"] = json!("a".repeat(513));
    assert!(issuer
        .prepare(
            &quote(),
            &quote().project_id,
            &headers(&credential(&bad), true),
            body().as_bytes(),
            now()
        )
        .is_err());
    let mut bad = original.clone();
    bad["extra"] = json!(vec!["x"; 33]);
    assert!(issuer
        .prepare(
            &quote(),
            &quote().project_id,
            &headers(&credential(&bad), true),
            body().as_bytes(),
            now()
        )
        .is_err());
    let mut nested = json!("leaf");
    for _ in 0..10 {
        nested = json!({"nested":nested});
    }
    let mut bad = original;
    bad["extra"] = nested;
    assert!(issuer
        .prepare(
            &quote(),
            &quote().project_id,
            &headers(&credential(&bad), true),
            body().as_bytes(),
            now()
        )
        .is_err());
    let mut ch = issued(true).challenge().clone();
    for n in 0..24 {
        ch.extensions.insert(format!("x-{n}"), "x".into());
    }
    assert!(ch.to_header().is_err());
    let valid_receipt = fixtures()["receipt"].clone();
    let duplicate=format!("{{\"method\":\"stripe\",\"reference\":\"pi_fake\",\"status\":\"failure\",\"status\":\"success\",\"timestamp\":{}}}",valid_receipt["timestamp"]);
    assert!(UntrustedReceipt::parse(200, &URL_SAFE_NO_PAD.encode(duplicate)).is_err());
}
