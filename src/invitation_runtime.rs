#[path = "invitation_transport.rs"]
pub(crate) mod delivery_transport;
// Explicit invitation mode; defaults closed.
use crate::invitation::{self as inv, Enrollment, Mode, Policy, Registry, Ticket};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use worker::{
    wasm_bindgen::{JsCast, JsValue},
    *,
};
fn now() -> i64 {
    Date::now().as_millis() as i64
}
fn json_response(v: &Value, status: u16) -> Result<Response> {
    let mut r = Response::from_json(v)?.with_status(status);
    r.headers_mut().set("Cache-Control", "no-store")?;
    Ok(r)
}
fn rejected(e: inv::Error) -> Result<Response> {
    let (status, code) = match e {
        inv::Error::Closed => (503, "invitation_policy_unset"),
        inv::Error::Invalid => (400, "invalid_invitation_input"),
        inv::Error::Conflict => (409, "invitation_conflict"),
        inv::Error::Forbidden => (403, "invitation_forbidden"),
        inv::Error::Expired => (410, "invitation_expired"),
        inv::Error::Limited => (429, "invitation_limit"),
        inv::Error::Clock => (503, "invitation_clock_unavailable"),
    };
    json_response(
        &json!({"error":{"code":code},"task_accepted":false}),
        status,
    )
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored<T> {
    version: u8,
    data: T,
}
#[derive(Deserialize)]
struct Count {
    n: u64,
}
#[derive(Deserialize)]
struct Row {
    data: String,
}
trait Checked {
    fn checked(&self) -> Result<()>;
}
impl Checked for Registry {
    fn checked(&self) -> Result<()> {
        Ok(())
    }
}
impl Checked for Enrollment {
    fn checked(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::RustError("Unknown enrollment schema".into()));
        }
        self.outbound
            .validate(self.project_id())
            .map_err(|_| Error::RustError("Invalid invitation outbound state".into()))
    }
}
fn load<T: DeserializeOwned + Checked>(state: &State) -> Result<Option<T>> {
    let sql = state.storage().sql();
    let c:Vec<Count>=sql.exec("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='invitation_snapshot'",None)?.to_array()?;
    if c.first().is_some_and(|r| r.n == 0) {
        return Ok(None);
    }
    let rows: Vec<Row> = sql
        .exec("SELECT data FROM invitation_snapshot WHERE id=1", None)?
        .to_array()?;
    let row = rows
        .first()
        .ok_or_else(|| Error::RustError("Missing invitation row; refuse reset".into()))?;
    let s: Stored<T> = serde_json::from_str(&row.data)?;
    if s.version != 1 {
        return Err(Error::RustError("Unknown invitation snapshot".into()));
    }
    s.data.checked()?;
    Ok(Some(s.data))
}
fn save<T: Serialize + Checked>(state: &State, value: &T) -> Result<()> {
    value.checked()?;
    let sql = state.storage().sql();
    sql.exec("CREATE TABLE IF NOT EXISTS invitation_snapshot(id INTEGER PRIMARY KEY CHECK(id=1),data TEXT NOT NULL)",None)?;
    sql.exec("INSERT INTO invitation_snapshot(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",vec![serde_json::to_string(&Stored{version:1,data:value})?.into()])?;
    Ok(())
}
fn nonce() -> Result<String> {
    let c = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))?;
    let f = js_sys::Reflect::get(&c, &JsValue::from_str("getRandomValues"))?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| Error::RustError("No secure nonce".into()))?;
    let b = js_sys::Uint8Array::new_with_length(32);
    f.call1(&c, &b)?;
    Ok(hex::encode(b.to_vec()))
}
#[cfg(feature = "invitation-tests")]
async fn point(env: &Env, name: &str) -> Result<()> {
    let mut r = env
        .service("TEST_INVITATION_CONTROL")?
        .fetch(&format!("http://control.invalid/{name}"), None)
        .await?;
    let _ = r.text().await?;
    if r.status_code() != 204 {
        return Err(Error::RustError(
            "Injected invitation fixture interruption".into(),
        ));
    }
    Ok(())
}
#[cfg(feature = "production")]
async fn point(_env: &Env, _name: &str) -> Result<()> {
    Ok(())
}
fn guard(env: &Env) -> bool {
    #[cfg(feature = "invitation-tests")]
    {
        env.service("TEST_INVITATION_CONTROL").is_ok()
    }
    #[cfg(feature = "production")]
    {
        env.var("INVITATION_ENROLLMENT")
            .map(|v| v.to_string())
            .unwrap_or_default()
            == "operator-approved"
            && js_sys::Reflect::own_keys(env.as_ref())
                .map(|keys| {
                    !keys
                        .iter()
                        .filter_map(|k| k.as_string())
                        .any(|k| crate::identity::forbidden_binding(&k) || k.starts_with("ALPHA_"))
                })
                .unwrap_or(false)
            && env.durable_object("ADMISSION").is_ok()
            && env.durable_object("PROJECTS").is_ok()
    }
}
fn policy(env: &Env) -> Result<Policy> {
    #[cfg(feature = "invitation-tests")]
    let name = "TEST_INVITATION_POLICY";
    #[cfg(feature = "production")]
    let name = "INVITATION_POLICY";
    let raw = env.var(name)?.to_string();
    if raw.len() > 4096 {
        return Err(Error::RustError(
            "Invitation configuration too large".into(),
        ));
    }
    Ok(serde_json::from_str(&raw)?)
}
#[cfg(feature = "production")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    id: String,
    expires_at_ms: i64,
    revoked: bool,
}
#[cfg(feature = "production")]
fn sync_seeds(env: &Env, s: &mut Registry, admission_open: bool) -> Result<()> {
    let raw = env.var("INVITATION_SEEDS")?.to_string();
    if raw.len() > 16384 {
        return Err(Error::RustError("Invitation seeds too large".into()));
    }
    let seeds: Vec<Seed> = serde_json::from_str(&raw)?;
    if seeds.len() > inv::MAX_TICKETS {
        return Err(Error::RustError("Too many invitation seeds".into()));
    }
    for seed in seeds {
        if admission_open {
            s.issue(&seed.id, seed.expires_at_ms, now())
                .map_err(|_| Error::RustError("Invalid immutable invitation seed".into()))?;
        }
        if seed.revoked {
            s.revoke(&seed.id, now())
                .map_err(|_| Error::RustError("Invalid invitation revocation".into()))?;
        }
    }
    Ok(())
}
async fn read_body(req: &mut Request) -> Result<Option<Value>> {
    Ok(read_raw(req)
        .await?
        .and_then(|v| serde_json::from_slice(&v).ok()))
}
async fn read_raw(req: &mut Request) -> Result<Option<Vec<u8>>> {
    use futures_util::{
        future::{select, Either},
        pin_mut, StreamExt,
    };
    let read = async {
        let mut all = Vec::new();
        let mut chunks = 0;
        let Ok(mut stream) = req.stream() else {
            return Ok(Some(all));
        };
        while let Some(v) = stream.next().await {
            let v = v?;
            chunks += 1;
            if all.len() + v.len() > 4096 || chunks > 32 {
                return Ok(None);
            }
            all.extend(v);
        }
        Ok::<_, Error>(Some(all))
    };
    let deadline = Delay::from(std::time::Duration::from_secs(5));
    pin_mut!(read, deadline);
    match select(read, deadline).await {
        Either::Left((v, _)) => v,
        Either::Right(_) => Ok(None),
    }
}
async fn internal(env: &Env, binding: &str, name: &str, path: &str, v: &Value) -> Result<Response> {
    let ns = env.durable_object(binding)?;
    let stub = ns.id_from_name(name)?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(serde_json::to_string(v)?.into()));
    let mut r = Request::new_with_init(&format!("http://internal{path}"), &init)?;
    r.headers_mut()?.set("x-project-id", name)?;
    stub.fetch_with_request(r).await
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signed {
    ticket: Ticket,
    envelope: crate::signed::Envelope,
    signature: String,
    body_hex: String,
}
async fn signed_forward(req: &mut Request, env: &Env) -> Result<Response> {
    let project = req
        .headers()
        .get("RunLater-Project-Id")?
        .unwrap_or_default();
    if !crate::security::tenant_valid(&project) {
        return rejected(inv::Error::Forbidden);
    }
    let mut gate = internal(
        env,
        "ADMISSION",
        "admission_registry_v1",
        "/signed-route",
        &json!({"project_id":project}),
    )
    .await?;
    if gate.status_code() != 200 {
        return Ok(gate);
    }
    let ticket: Ticket = gate.json().await?;
    if req.method() != Method::Get
        && req.headers().get("Content-Type")?.as_deref() != Some("application/json")
    {
        return json_response(&json!({"error":"json_required"}), 415);
    }
    let Some(raw) = read_raw(req).await? else {
        return rejected(inv::Error::Invalid);
    };
    let h = req.headers();
    let issued = h.get("RunLater-Issued-At")?.and_then(|v| decimal(&v));
    let expires = h.get("RunLater-Expires-At")?.and_then(|v| decimal(&v));
    let (Some(issued), Some(expires)) = (issued, expires) else {
        return rejected(inv::Error::Invalid);
    };
    let e = crate::signed::Envelope {
        version: 1,
        origin: crate::identity::ORIGIN.into(),
        project_id: project.clone(),
        public_key: h.get("RunLater-Public-Key")?.unwrap_or_default(),
        method: req.method().to_string(),
        path: req.path(),
        query: String::new(),
        body_sha256: crate::security::digest(&raw),
        idempotency_key: h.get("Idempotency-Key")?.unwrap_or_default(),
        issued_at_ms: issued,
        expires_at_ms: expires,
        nonce: h.get("RunLater-Nonce")?.unwrap_or_default(),
    };
    let input = Signed {
        ticket,
        envelope: e,
        signature: h.get("RunLater-Request-Signature")?.unwrap_or_default(),
        body_hex: hex::encode(raw),
    };
    internal(
        env,
        "PROJECTS",
        &project,
        "/signed",
        &serde_json::to_value(input)?,
    )
    .await
}
fn decimal(v: &str) -> Option<i64> {
    if v.is_empty() || v.len() > 16 || !v.bytes().all(|b| b.is_ascii_digit()) {
        None
    } else {
        v.parse().ok()
    }
}
fn task_result(v: serde_json::Value) -> Result<Response> {
    let status = if v["created"] == true { 201 } else { 200 };
    json_response(&v, status)
}
fn task_error(e: crate::funded_tasks::Error) -> Result<Response> {
    use crate::funded_tasks::Error as E;
    let (status, code) = match e {
        E::AdmissionUnavailable => (503, "delivery_not_ready"),
        E::Auth(crate::identity::Error::Forbidden) => (403, "request_forbidden"),
        E::Auth(crate::identity::Error::Expired) => (410, "request_expired"),
        E::Auth(crate::identity::Error::Conflict) => (409, "request_conflict"),
        E::Auth(crate::identity::Error::Limited) => (429, "request_limit"),
        E::Auth(crate::identity::Error::ClockRegressed) => (503, "clock_unavailable"),
        E::Auth(_) => (400, "invalid_signed_request"),
        E::Funding(crate::funding::Error::Insufficient) => (402, "funding_required"),
        E::Funding(_) => (409, "funding_conflict"),
        E::Ledger(crate::core::Fault::NotFound) => (404, "task_not_found"),
        E::Ledger(_) => (409, "task_conflict"),
    };
    json_response(
        &json!({"error":{"code":code},"task_accepted":false}),
        status,
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Issue {
    token: String,
    expires_at_ms: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    token: String,
    public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    token: String,
    challenge_id: String,
    signature: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    project_id: String,
    public_key: String,
    nonce: String,
    issued_at_ms: i64,
    expires_at_ms: i64,
    signature: String,
}
fn token(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[cfg_attr(feature = "invitation-tests", event(fetch))]
pub async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    if !guard(&env) {
        return json_response(
            &json!({"error":"invitation_configuration_unavailable"}),
            403,
        );
    }
    let url = req.url()?;
    #[cfg(feature = "invitation-tests")]
    if url.scheme() != "http" || url.host_str() != Some("127.0.0.1") {
        return json_response(&json!({"error":"invitation_fixture_loopback_only"}), 421);
    }
    #[cfg(feature = "production")]
    if url.scheme() != "https" || url.host_str() != Some("api.runlater.io") || url.port().is_some()
    {
        return json_response(&json!({"error":"production_origin_required"}), 421);
    }
    if url.query().is_some()
        || req.headers().get("Authorization")?.is_some()
        || req
            .headers()
            .get("Origin")?
            .is_some_and(|o| o != crate::identity::ORIGIN)
        || req.headers().entries().any(|(n, _)| {
            n.to_ascii_lowercase().starts_with("x-runlater-test")
                || n.to_ascii_lowercase().starts_with("x-runlater-staging")
                || n.eq_ignore_ascii_case("x-tenant")
        })
    {
        return rejected(inv::Error::Forbidden);
    }
    #[cfg(feature = "production")]
    if req.path().starts_with("/fixture/") {
        return json_response(&json!({"error":"not_found"}), 404);
    }
    if req.method() == Method::Get && req.path() == "/health" {
        let enabled = env
            .var("INVITATION_DELIVERY_ENABLED")
            .map(|v| v.to_string())
            .unwrap_or_default()
            == "operator-approved";
        return json_response(
            &json!({"mode":"invitation","fresh_task_admission":if enabled{"conditional_operator_opt_in"}else{"unavailable"},"outbound":if enabled{"operator_allowlist_required"}else{"disabled"}}),
            200,
        );
    }
    if crate::invitation_delivery::destination_route(req.method().as_ref(), &req.path())
        || crate::funded_tasks::route(req.method().as_ref(), &req.path()).is_some()
        || (req.method() == Method::Get
            && matches!(req.path().as_str(), "/v1/identity/me" | "/v1/queue"))
    {
        return signed_forward(&mut req, &env).await;
    }
    let path = req.path();
    if path == "/fixture/registry" && req.method() == Method::Get {
        return internal(
            &env,
            "ADMISSION",
            "admission_registry_v1",
            "/view",
            &json!({}),
        )
        .await;
    }
    if req.method() != Method::Post {
        return rejected(inv::Error::Invalid);
    }
    if req.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return json_response(&json!({"error":"json_required"}), 415);
    }
    let Some(value) = read_body(&mut req).await? else {
        return rejected(inv::Error::Invalid);
    };
    if path == "/fixture/revoke" {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Revoke {
            token: String,
        }
        let Ok(v) = serde_json::from_value::<Revoke>(value) else {
            return rejected(inv::Error::Invalid);
        };
        if !token(&v.token) {
            return rejected(inv::Error::Invalid);
        }
        let mut r = internal(
            &env,
            "ADMISSION",
            "admission_registry_v1",
            "/revoke",
            &json!({"id":crate::security::digest(v.token.as_bytes())}),
        )
        .await?;
        if r.status_code() != 200 {
            return Ok(r);
        }
        let ticket: Ticket = r.json().await?;
        return internal(
            &env,
            "PROJECTS",
            &ticket.project_id,
            "/revoke",
            &serde_json::to_value(&ticket)?,
        )
        .await;
    }
    if path == "/fixture/issue" {
        let Ok(v) = serde_json::from_value::<Issue>(value) else {
            return rejected(inv::Error::Invalid);
        };
        if !token(&v.token) {
            return rejected(inv::Error::Invalid);
        }
        return internal(
            &env,
            "ADMISSION",
            "admission_registry_v1",
            "/issue",
            &json!({"id":crate::security::digest(v.token.as_bytes()),"expires":v.expires_at_ms}),
        )
        .await;
    }
    if path == "/registration/recover" {
        let Ok(v) = serde_json::from_value::<Recovery>(value.clone()) else {
            return rejected(inv::Error::Invalid);
        };
        let mut gate = internal(
            &env,
            "ADMISSION",
            "admission_registry_v1",
            "/signed-route",
            &json!({"project_id":v.project_id}),
        )
        .await?;
        if gate.status_code() != 200 {
            return Ok(gate);
        }
        let ticket: Ticket = gate.json().await?;
        return internal(
            &env,
            "PROJECTS",
            &v.project_id,
            "/recover",
            &json!({"ticket":ticket,"recovery":value}),
        )
        .await;
    }
    let (raw, key, id, signature) = if path == "/registration/challenge" {
        let Ok(v) = serde_json::from_value::<Start>(value) else {
            return rejected(inv::Error::Invalid);
        };
        if !crate::identity::key_valid(&v.public_key) {
            return rejected(inv::Error::Invalid);
        }
        (v.token, Some(v.public_key), None, None)
    } else if path == "/registration/complete" {
        let Ok(v) = serde_json::from_value::<Finish>(value) else {
            return rejected(inv::Error::Invalid);
        };
        if !token(&v.challenge_id)
            || v.signature.len() != 128
            || !v
                .signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return rejected(inv::Error::Invalid);
        }
        (v.token, None, Some(v.challenge_id), Some(v.signature))
    } else {
        return rejected(inv::Error::Invalid);
    };
    if !token(&raw) {
        return rejected(inv::Error::Invalid);
    }
    let mut gate = internal(
        &env,
        "ADMISSION",
        "admission_registry_v1",
        "/resolve",
        &json!({"id":crate::security::digest(raw.as_bytes())}),
    )
    .await?;
    if gate.status_code() != 200 {
        return Ok(gate);
    }
    let ticket: Ticket = gate.json().await?;
    point(&env, "after_resolve").await?; // Registry saved before any per-project namespace lookup.
    if let Some(key) = key {
        let r = internal(
            &env,
            "PROJECTS",
            &ticket.project_id,
            "/challenge",
            &json!({"ticket":ticket,"key":key,"nonce":nonce()?}),
        )
        .await?;
        point(&env, "after_challenge").await?;
        return Ok(r);
    }
    let result = internal(
        &env,
        "PROJECTS",
        &ticket.project_id,
        "/complete",
        &json!({"ticket":ticket,"id":id,"signature":signature}),
    )
    .await?;
    if result.status_code() == 201 {
        point(&env, "after_commit").await?;
        let ack = internal(
            &env,
            "ADMISSION",
            "admission_registry_v1",
            "/ack",
            &json!({"id":ticket.id}),
        )
        .await?;
        if ack.status_code() != 200 {
            return Ok(ack);
        }
        point(&env, "after_ack").await?;
    }
    Ok(result)
}
#[durable_object]
pub struct AdmissionRegistry {
    state: State,
    env: Env,
}
impl DurableObject for AdmissionRegistry {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if !guard(&self.env)
            || self.state.id().to_string()
                != self
                    .env
                    .durable_object("ADMISSION")?
                    .id_from_name("admission_registry_v1")?
                    .to_string()
        {
            return rejected(inv::Error::Forbidden);
        }
        if req.path() == "/view" {
            let s: Registry = load(&self.state)?.unwrap_or_default();
            return Response::from_json(&s.view());
        }
        let v: Value = req.json().await?;
        let mut s: Registry = load(&self.state)?.unwrap_or_default();
        let Ok(policy) = policy(&self.env) else {
            return rejected(inv::Error::Closed);
        };
        if let Err(e) = s.apply(&policy, now()) {
            return rejected(e);
        }
        #[cfg(feature = "production")]
        if sync_seeds(&self.env, &mut s, policy.terms.is_some()).is_err() {
            return rejected(inv::Error::Closed);
        }
        let outcome = match req.path().as_str() {
            "/issue" => s
                .issue(
                    v["id"].as_str().unwrap_or_default(),
                    v["expires"].as_i64().unwrap_or_default(),
                    now(),
                )
                .and_then(|t| serde_json::to_value(t).map_err(|_| inv::Error::Invalid)),
            "/resolve" => s
                .resolve(v["id"].as_str().unwrap_or_default(), now())
                .and_then(|t| serde_json::to_value(t).map_err(|_| inv::Error::Invalid)),
            "/revoke" => s
                .revoke(v["id"].as_str().unwrap_or_default(), now())
                .and_then(|t| serde_json::to_value(t).map_err(|_| inv::Error::Invalid)),
            "/signed-route" => s
                .existing_ticket(v["project_id"].as_str().unwrap_or_default(), now())
                .and_then(|t| serde_json::to_value(t).map_err(|_| inv::Error::Invalid)),
            "/route" => s
                .route_existing(v["project_id"].as_str().unwrap_or_default(), now())
                .map(|_| json!({"routable":true})),
            "/ack" => s
                .acknowledge(v["id"].as_str().unwrap_or_default(), now())
                .map(|_| json!({"acknowledged":true})),
            _ => Err(inv::Error::Invalid),
        };
        save(&self.state, &s)?;
        match outcome {
            Ok(v) => Response::from_json(&v),
            Err(e) => rejected(e),
        }
    }
}
#[durable_object]
pub struct InvitationProject {
    state: State,
    env: Env,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeInput {
    ticket: Ticket,
    key: String,
    nonce: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteInput {
    ticket: Ticket,
    id: String,
    signature: String,
}
impl DurableObject for InvitationProject {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }
    async fn alarm(&self) -> Result<Response> {
        self.pump().await?;
        Response::from_json(&json!({"alarm":true}))
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if !guard(&self.env) {
            return rejected(inv::Error::Forbidden);
        }
        let project = req.headers().get("x-project-id")?.unwrap_or_default();
        if !crate::security::tenant_valid(&project)
            || self.state.id().to_string()
                != self
                    .env
                    .durable_object("PROJECTS")?
                    .id_from_name(&project)?
                    .to_string()
        {
            return rejected(inv::Error::Forbidden);
        }
        let value: Value = req.json().await?;
        let mut s: Enrollment =
            load(&self.state)?.unwrap_or_else(|| Enrollment::new(Mode::Invitation));
        if req.path() == "/deliver" {
            let d: crate::core::Dispatch = serde_json::from_value(value)?;
            return self.deliver(&project, d).await;
        }
        if req.path() == "/signed" {
            let input: Signed = serde_json::from_value(value)?;
            if input.ticket.project_id != project || input.envelope.project_id != project {
                return rejected(inv::Error::Forbidden);
            }
            if input.ticket.revoked {
                if input.envelope.method == "GET" {
                    return rejected(inv::Error::Forbidden);
                }
                let r = s.revoke(&input.ticket, now());
                save(&self.state, &s)?;
                return match r {
                    Ok(()) => rejected(inv::Error::Forbidden),
                    Err(e) => rejected(e),
                };
            }
            let Ok(raw) = hex::decode(&input.body_hex) else {
                return rejected(inv::Error::Invalid);
            };
            if input.envelope.method == "GET" {
                return match s.signed_query(&input.envelope, &input.signature, &raw, now()) {
                    Ok(v) => task_result(v),
                    Err(e) => task_error(e),
                };
            }
            if self.env.var("INVITATION_DELIVERY_ENABLED").is_ok() {
                return self.signed_delivery(s, input, raw).await;
            }
            // Fresh production admission is deliberately unavailable until registered delivery is integrated.
            let ready = cfg!(feature = "invitation-tests");
            let result =
                s.signed_task_command(&input.envelope, &input.signature, &raw, ready, now());
            save(&self.state, &s)?;
            if result.is_ok() {
                point(&self.env, "after_task_commit").await?;
            }
            return match result {
                Ok(v) => task_result(v),
                Err(e) => task_error(e),
            };
        }
        if req.path() == "/revoke" {
            let ticket: Ticket = serde_json::from_value(value)?;
            if ticket.project_id != project {
                return rejected(inv::Error::Forbidden);
            }
            let r = s.revoke(&ticket, now());
            save(&self.state, &s)?;
            return match r {
                Ok(()) => Response::from_json(&json!({"revoked":true})),
                Err(e) => rejected(e),
            };
        }
        if req.path() == "/recover" {
            let ticket: Ticket = serde_json::from_value(value["ticket"].clone())?;
            if ticket.project_id != project {
                return rejected(inv::Error::Forbidden);
            }
            if ticket.revoked {
                return rejected(inv::Error::Forbidden);
            }
            let v: Recovery = serde_json::from_value(value["recovery"].clone())?;
            if v.project_id != project {
                return rejected(inv::Error::Forbidden);
            }
            return match s.recover(
                &v.public_key,
                &v.nonce,
                v.issued_at_ms,
                v.expires_at_ms,
                &v.signature,
                now(),
            ) {
                Ok(r) => Response::from_json(&r),
                Err(e) => rejected(e),
            };
        }
        let result = if req.path() == "/challenge" {
            let v: ChallengeInput = serde_json::from_value(value)?;
            if v.ticket.project_id != project {
                return rejected(inv::Error::Forbidden);
            }
            s.challenge(&v.ticket,&v.key,&v.nonce,now()).and_then(|c|Ok(json!({"challenge_id":c.id()?,"canonical_utf8":String::from_utf8(c.bytes()?).map_err(|_|inv::Error::Invalid)?,"challenge":c})))
        } else if req.path() == "/complete" {
            let v: CompleteInput = serde_json::from_value(value)?;
            if v.ticket.project_id != project {
                return rejected(inv::Error::Forbidden);
            }
            s.complete(&v.ticket, &v.id, &v.signature, now())
                .and_then(|r| serde_json::to_value(r).map_err(|_| inv::Error::Invalid))
        } else {
            Err(inv::Error::Invalid)
        };
        save(&self.state, &s)?;
        match result {
            Ok(v) => json_response(&v, if req.path() == "/complete" { 201 } else { 200 }),
            Err(e) => rejected(e),
        }
    }
}
