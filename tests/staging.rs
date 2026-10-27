use runlater::{core::Create, staging::*};
#[test]
fn gate_is_fail_closed_for_missing_wrong_expired_and_public_fixtures() {
    let secret = "a".repeat(64);
    assert!(gate(&secret, &secret, 1001, 1000));
    for candidate in ["", "local-alpha", "local-beta", &"b".repeat(64)] {
        assert!(!gate(&secret, candidate, 1001, 1000));
    }
    assert!(!gate("", &secret, 1001, 1000));
    assert!(!gate(&secret, &secret, 1000, 1000));
    assert!(!gate(&secret, &secret, 0, 1000));
    assert!(!gate(&secret, &secret, 901001, 1000));
}
#[test]
fn receiver_policy_permits_one_canonical_operator_host_only() {
    let host = "runlater-staging-review-receiver.thachp.workers.dev";
    assert!(receiver_url_allowed(
        &format!("https://{host}/callback"),
        host,
        "review"
    ));
    for url in [
        format!("http://{host}/callback"),
        format!("https://{host}:443/callback"),
        format!("https://{host}/callback?url=https://evil.example"),
        format!("https://{host}/callback#x"),
        format!("https://{host}@127.0.0.1/callback"),
        "https://127.0.0.1/callback".into(),
        "https://169.254.169.254/callback".into(),
        "https://[::1]/callback".into(),
        "https://example.com/callback".into(),
    ] {
        assert!(!receiver_url_allowed(&url, host, "review"));
    }
    assert!(!receiver_url_allowed(
        "https://runlater-staging-review-receiver.evil.example.workers.dev/callback",
        "runlater-staging-review-receiver.evil.example.workers.dev",
        "review"
    ));
}
#[test]
fn staging_tasks_are_small_synthetic_and_near_term() {
    let body = r#"{"run":"review","case":"receiver","synthetic":true}"#;
    let mut c = Create {
        destination: "staging://receiver".into(),
        body: body.into(),
        operation_key: "run_review_receiver".into(),
        run_at_ms: 0,
    };
    assert!(input_allowed(&c, "review", 1000));
    c.destination = "https://example.com".into();
    assert!(!input_allowed(&c, "review", 1000));
    c.destination = "staging://receiver".into();
    c.run_at_ms = 31_001;
    assert!(!input_allowed(&c, "review", 1000));
    c.run_at_ms = 0;
    c.body = r#"{"run":"review","case":"receiver","synthetic":true,"customer":"data"}"#.into();
    assert!(!input_allowed(&c, "review", 1000));
}
#[test]
fn receipt_is_domain_separated_and_authenticates_context() {
    let secret = "b".repeat(64);
    let receipt = receipt(
        &secret,
        100,
        "alpha:task_0000000000000001",
        "run_review_receiver",
        b"synthetic",
    );
    assert!(verify_receipt(
        &secret,
        100,
        "alpha:task_0000000000000001",
        "run_review_receiver",
        b"synthetic",
        &receipt,
        100
    ));
    let request_signature = runlater::security::sign(
        secret.as_bytes(),
        100,
        "alpha:task_0000000000000001",
        "run_review_receiver",
        b"synthetic",
    );
    assert!(!verify_receipt(
        &secret,
        100,
        "alpha:task_0000000000000001",
        "run_review_receiver",
        b"synthetic",
        &request_signature,
        100
    ));
}
#[test]
fn staging_surface_disables_key_and_configuration_mutations() {
    assert!(api_route("POST", "/v1/tasks"));
    assert!(api_route("GET", "/v1/tasks/task_0000000000000001/attempts"));
    assert!(!api_route("POST", "/v1/keys"));
    assert!(!api_route("PUT", "/v1/queue"));
    assert!(!api_route("POST", "/v1/tasks/x/redrive"));
}

#[test]
fn staging_rejects_noncanonical_route_aliases() {
    assert_eq!(
        canonical_route("POST", "/v1/tasks"),
        Some(StageRoute::Enqueue)
    );
    for path in [
        "/v1/tasks/",
        "//v1/tasks",
        "/v1//tasks",
        "/v1/tasks//",
        "/v1/./tasks",
        "/v1/x/../tasks",
        "/v1/%74asks",
        "/v1/tasks%2f",
        "/V1/tasks",
    ] {
        assert_eq!(
            canonical_route("POST", path),
            None,
            "alias accepted: {path}"
        );
    }
    assert!(!api_route(
        "GET",
        "/v1/tasks/task_0000000000000001/attempts/"
    ));
    assert!(!api_route(
        "POST",
        "/v1/tasks/task_0000000000000001/cancel/"
    ));
}
#[test]
fn parsed_enqueue_always_obeys_payload_content_size_and_horizon() {
    use runlater::application::Command;
    let valid = Create {
        destination: "fixture://success".into(),
        body: r#"{"run":"review","case":"initial","synthetic":true}"#.into(),
        operation_key: "run_review_initial".into(),
        run_at_ms: 0,
    };
    assert!(command_allowed(
        &Command::Enqueue {
            key: "k".into(),
            input: valid.clone()
        },
        "review",
        1000
    ));
    for input in [
        Create {
            body: "not-synthetic".into(),
            ..valid.clone()
        },
        Create {
            body: "x".repeat(257),
            ..valid.clone()
        },
        Create {
            run_at_ms: 31_001,
            ..valid.clone()
        },
        Create {
            run_at_ms: 365 * runlater::core::DAY,
            ..valid.clone()
        },
    ] {
        assert!(!command_allowed(
            &Command::Enqueue {
                key: "k".into(),
                input
            },
            "review",
            1000
        ));
    }
    assert!(!command_allowed(
        &Command::Redrive {
            id: "task_0000000000000001".into(),
            key: "k".into()
        },
        "review",
        1000
    ));
}
