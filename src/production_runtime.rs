//! Production-only boundary. Enrollment is operator-approved; task acceptance/delivery remains disabled.
use crate::identity::{self, Catalog, Policy};
use serde::Deserialize;
use serde_json::json;
use worker::{
    wasm_bindgen::{JsCast, JsValue},
    *,
};
fn now() -> i64 {
    Date::now().as_millis() as i64
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
    let names = js_sys::Reflect::own_keys(env.as_ref()).map_err(|_| ())?;
    if names
        .iter()
        .filter_map(|n| n.as_string())
        .any(|n| identity::forbidden_binding(&n))
    {
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
async fn body(req: &mut Request) -> Result<Option<serde_json::Value>> {
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
                if chunks > 32 || bytes.len() + part.len() > 2048 {
                    return Ok(None);
                }
                bytes.extend(part);
            }
        }
        Ok::<_, worker::Error>(serde_json::from_slice(&bytes).ok())
    };
    let deadline = Delay::from(std::time::Duration::from_secs(5));
    pin_mut!(reader, deadline);
    match select(reader, deadline).await {
        Either::Left((result, _)) => result,
        Either::Right(_) => Ok(None),
    }
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
        return Response::from_json(
            &json!({"mode":"production","identity":"operator_approved_enrollment_only","task_api":"unavailable","outbound":"disabled"}),
        );
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
    fn load(&self) -> Result<Catalog> {
        let sql = self.state.storage().sql();
        #[derive(Deserialize)]
        struct Count {
            count: i64,
        }
        let exists:Vec<Count>=sql.exec("SELECT count(*) AS count FROM sqlite_master WHERE type='table' AND name='identity_catalog'",None)?.to_array()?;
        if exists.first().is_none_or(|n| n.count == 0) {
            return Ok(Catalog::default());
        }
        let rows: Vec<Row> = sql
            .exec("SELECT data FROM identity_catalog WHERE id=1", None)?
            .to_array()?;
        match rows.first() {
            Some(r) => Ok(serde_json::from_str(&r.data)?),
            None => Ok(Catalog::default()),
        }
    }
    fn save(&self, c: &Catalog) -> Result<()> {
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
        let Some(value) = body(&mut req).await? else {
            return response("invalid_or_oversized_identity_body", 400);
        };
        // All awaits precede authoritative load, policy application, proof/consume and one atomic SQL upsert.
        let mut catalog = self.load()?;
        if let Err(e) = catalog.apply_policy(policy, now()) {
            return reject(e);
        }
        // Configuration revocation is durable even if later proof processing fails.
        self.save(&catalog)?;
        let result = match req.path().as_str() {
            "/v1/identity/sync" => match serde_json::from_value::<SyncPolicy>(value) {
                Ok(v) if v.project_id == project => Response::from_json(&json!({"configured_policy_applied":true,"task_api":"unavailable"})),
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
                    Ok(identity)=>Ok(Response::from_json(&json!({"identity":identity,"credential_issued":false,"task_api":"unavailable","entitlement_granted":false}))?.with_status(201)),
                    Err(e)=>reject(e),
                },
                _=>response("invalid_identity_request",400),
            },
            _=>response("not_found",404),
        };
        self.save(&catalog)?;
        result
    }
}
