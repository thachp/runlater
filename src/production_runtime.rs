#[cfg(feature = "production")]
#[path = "production_delivery.rs"]
mod delivery_runtime;
// Production boundary. Optional restricted-alpha delivery requires explicit server configuration.
use crate::{
    identity::{self, Policy},
    signed::{Envelope, Project},
};
use serde::Deserialize;
use serde_json::json;
use worker::{
    wasm_bindgen::{JsCast, JsValue},
    *,
};
fn now() -> i64 {
    Date::now().as_millis() as i64
}
fn availability(env: &Env) -> &'static str {
    #[cfg(feature = "production")]
    if env
        .var("ALPHA_DELIVERY_ENABLED")
        .map(|v| v.to_string())
        .unwrap_or_default()
        == "operator-approved"
    {
        return "restricted_alpha_opt_in";
    }
    let _ = env;
    "unavailable"
}
fn response(code: &str, status: u16) -> Result<Response> {
    let mut r = Response::from_json(&json!({"error":{"code":code},"task_accepted":false}))?
        .with_status(status);
    r.headers_mut().set("Cache-Control", "no-store")?;
    Ok(r)
}
fn reject(e: identity::Error) -> Result<Response> {
    match e {
        identity::Error::Invalid => response("invalid_identity_request", 400),
        identity::Error::Forbidden => response("identity_forbidden", 403),
        identity::Error::Conflict => response("identity_conflict_or_consumed", 409),
        identity::Error::Expired => response("identity_expired", 410),
        identity::Error::Limited => response("identity_limit", 429),
        identity::Error::ClockRegressed => response("identity_clock_unavailable", 503),
    }
}
fn policies(env: &Env) -> std::result::Result<Vec<Policy>, ()> {
    #[cfg(feature = "funding-tests")]
    env.service("TEST_FUNDING_CONTROL").map_err(|_| ())?;
    let names = js_sys::Reflect::own_keys(env.as_ref()).map_err(|_| ())?;
    if names.iter().filter_map(|n| n.as_string()).any(|n| {
        #[cfg(feature = "funding-tests")]
        if n == "TEST_FUNDING_CONTROL" {
            return false;
        }
        identity::forbidden_binding(&n)
    }) {
        return Err(());
    }
    if env.var("ALPHA_ENROLLMENT").map_err(|_| ())?.to_string() != "operator-approved" {
        return Err(());
    }
    let raw = env
        .var("ALPHA_PROJECT_POLICIES")
        .map_err(|_| ())?
        .to_string();
    if raw.len() > 4096 {
        return Err(());
    }
    let list: Vec<Policy> = serde_json::from_str(&raw).map_err(|_| ())?;
    if list.is_empty() || list.len() > 8 {
        return Err(());
    }
    let mut projects = std::collections::BTreeSet::new();
    for policy in &list {
        policy.validate().map_err(|_| ())?;
        if !projects.insert(&policy.project_id) {
            return Err(());
        }
    }
    env.durable_object("IDENTITIES").map_err(|_| ())?;
    Ok(list)
}
async fn bytes(req: &mut Request, limit: usize) -> Result<Option<Vec<u8>>> {
    use futures_util::{
        future::{select, Either},
        pin_mut, StreamExt,
    };
    let reader = async {
        let mut bytes = Vec::new();
        let mut chunks = 0;
        if let Ok(mut stream) = req.stream() {
            while let Some(part) = stream.next().await {
                let part = part?;
                chunks += 1;
                if chunks > 32 || bytes.len() + part.len() > limit {
                    return Ok(None);
                }
                bytes.extend(part);
            }
        }
        Ok::<_, worker::Error>(Some(bytes))
    };
    let deadline = Delay::from(std::time::Duration::from_secs(5));
    pin_mut!(reader, deadline);
    match select(reader, deadline).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => Ok(None),
    }
}
async fn body(req: &mut Request) -> Result<Option<serde_json::Value>> {
    Ok(bytes(req, 2048)
        .await?
        .and_then(|b| serde_json::from_slice(&b).ok()))
}
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedInput {
    envelope: Envelope,
    signature: String,
    body_hex: String,
}
fn signed_error(e: identity::Error) -> Result<Response> {
    let (code, status) = match e {
        identity::Error::Invalid => ("request_invalid", 400),
        identity::Error::Forbidden => ("request_forbidden", 403),
        identity::Error::Conflict => ("request_conflict", 409),
        identity::Error::Expired => ("request_expired", 410),
        identity::Error::Limited => ("request_limit", 429),
        identity::Error::ClockRegressed => ("request_clock_unavailable", 503),
    };
    response(code, status)
}
fn task_error(e: crate::funded_tasks::Error) -> Result<Response> {
    use crate::{core::Fault as C, funded_tasks::Error as E, funding::Error as F};
    match e {
        E::Auth(e) => signed_error(e),
        E::AdmissionUnavailable => response("delivery_not_ready", 503),
        E::Funding(e) => match e {
            F::Insufficient => response("operator_grant_exhausted", 429),
            F::Expired => response("operator_grant_expired", 503),
            F::Conflict => response("funding_policy_conflict", 409),
            F::Capacity => response("funding_capacity", 429),
            F::ClockRegressed => response("funding_clock_unavailable", 503),
            _ => response("funding_unavailable", 503),
        },
        E::Ledger(e) => match e {
            C::NotFound => response("task_not_found", 404),
            C::Conflict | C::Stale => response("task_conflict", 409),
            C::Capacity | C::Limited { .. } => response("task_limit", 429),
            C::DestinationDisabled => response("registered_destination_required", 400),
            _ => response("task_invalid", 400),
        },
    }
}
#[cfg(feature = "funding-tests")]
async fn fixture_policy(env: &Env, project: &str) -> Result<Option<crate::funding::Policy>> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(
        serde_json::to_string(&json!({"project_id":project}))?.into(),
    ));
    let mut r = env
        .service("TEST_FUNDING_CONTROL")?
        .fetch("http://control.invalid/funding", Some(init))
        .await?;
    if r.status_code() == 204 {
        return Ok(None);
    }
    if r.status_code() != 200 {
        return Err(Error::RustError(
            "Funding fixture policy unavailable".into(),
        ));
    }
    Ok(Some(r.json().await?))
}
fn decimal(value: &str) -> Option<i64> {
    let n = value.parse::<i64>().ok()?;
    if n >= 0 && n.to_string() == value {
        Some(n)
    } else {
        None
    }
}
async fn signed_forward(req: &mut Request, env: &Env, list: &[Policy]) -> Result<Response> {
    let Some(project) = req.headers().get("RunLater-Project-Id")? else {
        return response("request_signature_required", 401);
    };
    if !list.iter().any(|p| p.project_id == project) {
        return response("request_forbidden", 403);
    }
    let public_key = req
        .headers()
        .get("RunLater-Public-Key")?
        .unwrap_or_default();
    let signature = req
        .headers()
        .get("RunLater-Request-Signature")?
        .unwrap_or_default();
    let nonce = req.headers().get("RunLater-Nonce")?.unwrap_or_default();
    let Some(issued) = req
        .headers()
        .get("RunLater-Issued-At")?
        .and_then(|v| decimal(&v))
    else {
        return response("request_invalid", 400);
    };
    let Some(expires) = req
        .headers()
        .get("RunLater-Expires-At")?
        .and_then(|v| decimal(&v))
    else {
        return response("request_invalid", 400);
    };
    if matches!(req.method(), Method::Put | Method::Post)
        && req
            .headers()
            .get("Content-Type")?
            .as_deref()
            .and_then(|v| v.split(';').next())
            != Some("application/json")
    {
        return response("json_required", 415);
    }
    let Some(body) = bytes(req, 2048).await? else {
        return response("invalid_or_oversized_signed_body", 400);
    };
    let envelope = Envelope {
        version: 1,
        origin: identity::ORIGIN.into(),
        project_id: project.clone(),
        public_key,
        method: req.method().to_string(),
        path: req.path(),
        query: String::new(),
        body_sha256: crate::security::digest(&body),
        idempotency_key: req.headers().get("Idempotency-Key")?.unwrap_or_default(),
        issued_at_ms: issued,
        expires_at_ms: expires,
        nonce,
    };
    let input = SignedInput {
        envelope,
        signature,
        body_hex: hex::encode(body),
    };
    let ns = env.durable_object("IDENTITIES")?;
    let stub = ns.id_from_name(&project)?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(serde_json::to_string(&input)?.into()));
    let mut forwarded = Request::new_with_init("https://identity/signed", &init)?;
    forwarded.headers_mut()?.set("x-project", &project)?;
    let result = stub.fetch_with_request(forwarded).await?;
    let headers = Headers::new();
    for (key, value) in result.headers().entries() {
        headers.append(&key, &value)?;
    }
    headers.set("Cache-Control", "no-store")?;
    Ok(result.with_headers(headers))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    project_id: String,
    public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncPolicy {
    project_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enroll {
    project_id: String,
    challenge_id: String,
    signature: String,
}
#[event(fetch)]
pub async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    #[cfg(feature = "funding-tests")]
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || env.service("TEST_FUNDING_CONTROL").is_err()
    {
        return response("funding_fixture_requires_loopback_harness", 403);
    }
    #[cfg(feature = "production")]
    if url.scheme() != "https"
        || url.host_str() != Some("api.runlater.io")
        || url.port().is_some_and(|p| p != 443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return response("production_origin_required", 421);
    }
    let list = match policies(&env) {
        Ok(p) => p,
        Err(_) => return response("production_configuration_unavailable", 503),
    };
    if req.headers().entries().any(|(name, _)| {
        let name = name.to_ascii_lowercase();
        name.starts_with("x-runlater-staging")
            || name.starts_with("x-runlater-test")
            || name == "x-tenant"
    }) {
        return response("nonproduction_header_forbidden", 403);
    }
    if req.headers().get("Authorization")?.is_some() {
        return response("bearer_credentials_not_supported", 401);
    }
    if req
        .headers()
        .get("Origin")?
        .is_some_and(|o| o != identity::ORIGIN)
    {
        return response("origin_forbidden", 403);
    }
    if url.query().is_some() {
        return response("query_not_supported", 400);
    }
    let path = req.path();
    if req.method() == Method::Get && path == "/health" {
        let mode = if cfg!(feature = "funding-tests") {
            "loopback_funding_model_fixture"
        } else {
            "production"
        };
        return Response::from_json(
            &json!({"mode":mode,"identity":"signed_read_config_only","task_api":availability(&env),"outbound":if availability(&env)=="unavailable"{"disabled"}else{"restricted_exact_receiver"}}),
        );
    }
    if (path == "/v1/queue" && matches!(req.method(), Method::Get | Method::Put))
        || (path == "/v1/identity/me" && req.method() == Method::Get)
    {
        return signed_forward(&mut req, &env, &list).await;
    }
    if let Some(_action) = crate::funded_tasks::route(req.method().as_ref(), &path) {
        #[cfg(feature = "production")]
        if matches!(
            _action,
            crate::funded_tasks::Route::Create | crate::funded_tasks::Route::Redrive(_)
        ) && req.headers().get("RunLater-Project-Id")?.is_none()
        {
            return response("delivery_not_ready", 503);
        }
        return signed_forward(&mut req, &env, &list).await;
    }
    if !matches!(
        path.as_str(),
        "/v1/identity/challenges" | "/v1/identity/enroll" | "/v1/identity/sync"
    ) {
        return response("functional_task_api_unavailable", 503);
    }
    if req.method() != Method::Post {
        return response("method_not_supported", 405);
    }
    if req
        .headers()
        .get("Content-Type")?
        .as_deref()
        .and_then(|s| s.split(';').next())
        != Some("application/json")
    {
        return response("json_required", 415);
    }
    let Some(value) = body(&mut req).await? else {
        return response("invalid_or_oversized_identity_body", 400);
    };
    let project = if path.ends_with("/challenges") {
        match serde_json::from_value::<Issue>(value.clone()) {
            Ok(v) => v.project_id,
            Err(_) => return response("invalid_identity_request", 400),
        }
    } else if path.ends_with("/sync") {
        match serde_json::from_value::<SyncPolicy>(value.clone()) {
            Ok(v) => v.project_id,
            Err(_) => return response("invalid_identity_request", 400),
        }
    } else {
        match serde_json::from_value::<Enroll>(value.clone()) {
            Ok(v) => v.project_id,
            Err(_) => return response("invalid_identity_request", 400),
        }
    };
    if !list.iter().any(|p| p.project_id == project) {
        return response("identity_forbidden", 403);
    }
    let ns = env.durable_object("IDENTITIES")?;
    let stub = ns.id_from_name(&project)?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(serde_json::to_string(&value)?.into()));
    let mut forwarded = Request::new_with_init(&format!("https://identity{path}"), &init)?;
    forwarded.headers_mut()?.set("x-project", &project)?;
    stub.fetch_with_request(forwarded).await
}
#[derive(Deserialize)]
struct Row {
    data: String,
}
#[durable_object]
pub struct ProjectIdentity {
    state: State,
    env: Env,
}
impl ProjectIdentity {
    fn load(&self) -> Result<Project> {
        let sql = self.state.storage().sql();
        #[derive(Deserialize)]
        struct Count {
            count: i64,
        }
        let exists:Vec<Count>=sql.exec("SELECT count(*) AS count FROM sqlite_master WHERE type='table' AND name='identity_catalog'",None)?.to_array()?;
        if exists.first().is_none_or(|n| n.count == 0) {
            return Ok(Project::default());
        }
        let rows: Vec<Row> = sql
            .exec("SELECT data FROM identity_catalog WHERE id=1", None)?
            .to_array()?;
        match rows.first() {
            Some(r) => Project::decode(serde_json::from_str(&r.data)?)
                .map_err(|_| Error::RustError("Invalid project state".into())),
            None => Ok(Project::default()),
        }
    }
    fn save(&self, c: &Project) -> Result<()> {
        let sql = self.state.storage().sql();
        sql.exec("CREATE TABLE IF NOT EXISTS identity_catalog(id INTEGER PRIMARY KEY CHECK(id=1),data TEXT NOT NULL)",None)?;
        sql.exec("INSERT INTO identity_catalog(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",vec![serde_json::to_string(c)?.into()])?;
        Ok(())
    }
}
fn nonce() -> Result<String> {
    let crypto = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))?;
    let random = js_sys::Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| Error::RustError("Secure randomness unavailable".into()))?;
    let bytes = js_sys::Uint8Array::new_with_length(32);
    random.call1(&crypto, &bytes)?;
    Ok(hex::encode(bytes.to_vec()))
}
impl DurableObject for ProjectIdentity {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let list = match policies(&self.env) {
            Ok(p) => p,
            Err(_) => return response("production_configuration_unavailable", 503),
        };
        let project = req.headers().get("x-project")?.unwrap_or_default();
        let Some(policy) = list.iter().find(|p| p.project_id == project) else {
            return response("identity_forbidden", 403);
        };
        #[cfg(feature = "funding-tests")]
        if req.path().starts_with("/funding-fixture/") {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Finish {
                id: String,
                fence: u64,
                status: Option<u16>,
                timeout: bool,
            }
            let Some(value) = body(&mut req).await? else {
                return response("fixture_invalid", 400);
            };
            let mut stored = self.load()?;
            let result = if req.path() == "/funding-fixture/sync" {
                let Some(policy) = fixture_policy(&self.env, &project).await? else {
                    return response("fixture_policy_missing", 503);
                };
                // Reload after the private policy await; do not commit the earlier snapshot.
                stored = self.load()?;
                if policy.project_id != project {
                    return response("fixture_invalid", 400);
                }
                stored
                    .funding
                    .apply(&policy, now())
                    .map(|_| json!({"applied":true}))
                    .map_err(crate::funded_tasks::Error::Funding)
            } else if req.path() == "/funding-fixture/claim" {
                let d: crate::core::Dispatch = serde_json::from_value(value)?;
                if d.tenant != project {
                    return response("request_forbidden", 403);
                }
                stored.funded_claim(&d, now()).and_then(|t| {
                    serde_json::to_value(t)
                        .map_err(|_| crate::funded_tasks::Error::Auth(identity::Error::Invalid))
                })
            } else if req.path() == "/funding-fixture/finish" {
                let f: Finish = serde_json::from_value(value)?;
                let outcome = if f.timeout {
                    crate::core::Outcome::Timeout
                } else {
                    match f.status {
                        Some(v) if (100..=599).contains(&v) => crate::core::Outcome::Http(v),
                        _ => return response("fixture_invalid", 400),
                    }
                };
                stored
                    .funded_finish(&f.id, f.fence, outcome, now())
                    .and_then(|t| {
                        serde_json::to_value(t)
                            .map_err(|_| crate::funded_tasks::Error::Auth(identity::Error::Invalid))
                    })
            } else {
                return response("fixture_invalid", 404);
            };
            self.save(&stored)?;
            return match result {
                Ok(v) => Response::from_json(&v),
                Err(e) => task_error(e),
            };
        }
        #[cfg(feature = "production")]
        if req.path() == "/verify-callback" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Verify {
                headers: Vec<(String, String)>,
                body_hex: String,
            }
            let Some(raw_input) = bytes(&mut req, 4096).await? else {
                return response("invalid_callback", 400);
            };
            let v: serde_json::Value = match serde_json::from_slice(&raw_input) {
                Ok(v) => v,
                Err(_) => return response("invalid_callback", 400),
            };
            let v: Verify = match serde_json::from_value(v) {
                Ok(v) => v,
                Err(_) => return response("invalid_callback", 400),
            };
            if v.headers.len() > 8 || v.body_hex.len() > 2048 {
                return response("invalid_callback", 400);
            }
            let raw = match hex::decode(v.body_hex) {
                Ok(b) => b,
                Err(_) => return response("invalid_callback", 400),
            };
            let Some((p, material)) = delivery_runtime::configuration(&self.env, &project)? else {
                return response("delivery_not_ready", 503);
            };
            let mut stored = self.load()?;
            delivery_runtime::apply(&mut stored, &p, &material, now())?;
            self.save(&stored)?;
            return if stored
                .delivery
                .verify(&v.headers, &raw, &material, now())
                .is_ok()
            {
                let attempt = crate::callback::Envelope::from_headers(&v.headers)
                    .ok()
                    .and_then(|e| e.task_id.split_once(':').map(|(_, id)| id.to_string()))
                    .and_then(|id| stored.ledger.get(&id).ok())
                    .map(|t| t.attempts.len())
                    .unwrap_or_default();
                Response::from_json(&json!({"verified":true,"attempt":attempt}))
            } else {
                response("callback_forbidden", 403)
            };
        }
        #[cfg(feature = "production")]
        if req.path() == "/deliver" {
            let Some(value) = body(&mut req).await? else {
                return response("invalid_dispatch", 400);
            };
            let d = match serde_json::from_value(value) {
                Ok(d) => d,
                Err(_) => return response("invalid_dispatch", 400),
            };
            return self.deliver_reference(&project, d).await;
        }
        if req.path() == "/signed" {
            if req.method() != Method::Post {
                return response("method_not_supported", 405);
            }
            let Some(raw) = bytes(&mut req, 8192).await? else {
                return response("invalid_signed_input", 400);
            };
            let input: SignedInput = match serde_json::from_slice(&raw) {
                Ok(v) => v,
                Err(_) => return response("invalid_signed_input", 400),
            };
            if input.envelope.project_id != project {
                return response("request_forbidden", 403);
            }
            let raw_body = match hex::decode(&input.body_hex) {
                Ok(v) if v.len() <= 2048 => v,
                _ => return response("invalid_signed_input", 400),
            };
            #[cfg(feature = "funding-tests")]
            let admission = if matches!(
                crate::funded_tasks::route(&input.envelope.method, &input.envelope.path),
                Some(crate::funded_tasks::Route::Create | crate::funded_tasks::Route::Redrive(_))
            ) {
                fixture_policy(&self.env, &project).await?
            } else {
                None
            };
            #[cfg(feature = "production")]
            let mut delivery = if input.envelope.method == "GET" {
                None
            } else {
                delivery_runtime::configuration(&self.env, &project)
                    .ok()
                    .flatten()
            };
            #[cfg(feature = "production")]
            if input.envelope.method != "GET" {
                self.state.storage().set_alarm(1000).await?;
            }
            let mut stored = self.load()?;
            if crate::funded_tasks::route(&input.envelope.method, &input.envelope.path).is_some() {
                if input.envelope.method == "GET" {
                    return match stored.task_query(
                        policy,
                        &input.envelope,
                        &input.signature,
                        &raw_body,
                        now(),
                    ) {
                        Ok(v) => Response::from_json(&v),
                        Err(e) => task_error(e),
                    };
                }
                if let Err(e) = stored.catalog.apply_policy(policy, now()) {
                    return signed_error(e);
                }
                self.save(&stored)?;
                #[cfg(feature = "production")]
                if let Some((p, material)) = &delivery {
                    if delivery_runtime::apply(&mut stored, p, material, now()).is_err() {
                        delivery = None;
                    } else {
                        self.save(&stored)?;
                    }
                }
                #[cfg(feature = "production")]
                let result = match stored.task_command(
                    policy,
                    None,
                    &input.envelope,
                    &input.signature,
                    &raw_body,
                    now(),
                ) {
                    Err(crate::funded_tasks::Error::AdmissionUnavailable) => {
                        if let Some((p, material)) = &delivery {
                            stored
                                .delivery_command(
                                    policy,
                                    p,
                                    material,
                                    &input.envelope,
                                    &input.signature,
                                    &raw_body,
                                    now(),
                                )
                                .map_err(|e| match e {
                                    crate::delivery::Error::Task(e) => e,
                                    crate::delivery::Error::Invalid => {
                                        crate::funded_tasks::Error::Ledger(
                                            crate::core::Fault::Invalid,
                                        )
                                    }
                                    _ => crate::funded_tasks::Error::AdmissionUnavailable,
                                })
                        } else {
                            Err(crate::funded_tasks::Error::AdmissionUnavailable)
                        }
                    }
                    result => result,
                };
                #[cfg(feature = "funding-tests")]
                let result = stored.task_command(
                    policy,
                    admission.as_ref(),
                    &input.envelope,
                    &input.signature,
                    &raw_body,
                    now(),
                );
                self.save(&stored)?;
                #[cfg(feature = "production")]
                self.delivery_rearm().await?;
                return match result {
                    Ok(v) => Ok(
                        Response::from_json(&v)?.with_status(if v["created"] == true {
                            201
                        } else {
                            200
                        }),
                    ),
                    Err(e) => task_error(e),
                };
            }
            if input.envelope.method == "GET" {
                return match stored.query(
                    policy,
                    &input.envelope,
                    &input.signature,
                    &raw_body,
                    now(),
                ) {
                    Ok(v) => Response::from_json(&v),
                    Err(e) => signed_error(e),
                };
            }
            // Persist monotonic policy independently; effect + nonce + receipt share the final upsert.
            if let Err(e) = stored.catalog.apply_policy(policy, now()) {
                return signed_error(e);
            }
            self.save(&stored)?;
            let result =
                stored.command(policy, &input.envelope, &input.signature, &raw_body, now());
            #[cfg(feature = "production")]
            {
                stored
                    .funded_maintenance(now())
                    .map_err(|_| Error::RustError("Funding maintenance rejected".into()))?;
                stored.delivery.prune(&stored.ledger);
            }
            self.save(&stored)?;
            #[cfg(feature = "production")]
            self.delivery_rearm().await?;
            return match result {
                Ok(v) => Response::from_json(&v),
                Err(e) => signed_error(e),
            };
        }
        let Some(value) = body(&mut req).await? else {
            return response("invalid_or_oversized_identity_body", 400);
        };
        #[cfg(feature = "production")]
        let delivery = if req.path() == "/v1/identity/sync" {
            match delivery_runtime::configuration(&self.env, &project) {
                Ok(v) => v,
                Err(_) => return response("delivery_configuration_unavailable", 503),
            }
        } else {
            None
        };
        #[cfg(feature = "production")]
        if delivery.is_some() {
            self.state.storage().set_alarm(1000).await?;
        }
        // All awaits precede authoritative load and policy/effect persistence.
        let mut stored = self.load()?;
        #[cfg(feature = "production")]
        if let Some((p, material)) = &delivery {
            if delivery_runtime::apply(&mut stored, p, material, now()).is_err() {
                return response("delivery_policy_rejected", 503);
            }
        }

        if let Err(e) = stored.catalog.apply_policy(policy, now()) {
            return reject(e);
        }
        // Configuration revocation is durable even if later proof processing fails.
        self.save(&stored)?;
        #[cfg(feature = "production")]
        let delivery_policy_applied = delivery.is_some();
        #[cfg(feature = "funding-tests")]
        let delivery_policy_applied = false;
        let catalog = &mut stored.catalog;
        let result = match req.path().as_str() {
            "/v1/identity/sync" => match serde_json::from_value::<SyncPolicy>(value) {
                Ok(v) if v.project_id == project => Response::from_json(&json!({"configured_policy_applied":true,"delivery_policy_applied":delivery_policy_applied,"funding_policy_applied":delivery_policy_applied,"task_api":availability(&self.env)})),
                _ => response("invalid_identity_request",400),
            },
            "/v1/identity/challenges" => match serde_json::from_value::<Issue>(value) {
                Ok(v) if v.project_id == project => {
                    let random=nonce()?;
                    match catalog.challenge(&project,&v.public_key,&random,now()) {
                        Ok(c) => {
                            let id=c.id().map_err(|_|Error::RustError("Challenge encoding".into()))?;
                            let canonical=String::from_utf8(c.bytes().map_err(|_|Error::RustError("Challenge encoding".into()))?).map_err(|_|Error::RustError("Challenge encoding".into()))?;
                            Response::from_json(&json!({"challenge_id":id,"canonical_utf8":canonical,"challenge":c}))
                        },
                        Err(e)=>reject(e),
                    }
                },
                _=>response("invalid_identity_request",400),
            },
            "/v1/identity/enroll" => match serde_json::from_value::<Enroll>(value) {
                Ok(v) if v.project_id==project => match catalog.enroll(&project,&v.challenge_id,&v.signature,now()) {
                    Ok(identity)=>Ok(Response::from_json(&json!({"identity":identity,"credential_issued":false,"task_api":availability(&self.env),"entitlement_granted":false}))?.with_status(201)),
                    Err(e)=>reject(e),
                },
                _=>response("invalid_identity_request",400),
            },
            _=>response("not_found",404),
        };
        self.save(&stored)?;
        #[cfg(feature = "production")]
        if delivery.is_some() {
            self.delivery_rearm().await?;
        }
        result
    }
    #[cfg(feature = "production")]
    async fn alarm(&self) -> Result<Response> {
        match self.delivery_pump().await {
            Ok(()) => Response::ok("disposed"),
            Err(_) => {
                self.state.storage().set_alarm(1000).await?;
                Err(Error::RustError("Delivery pump retry armed".into()))
            }
        }
    }
}
