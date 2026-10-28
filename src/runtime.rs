//! workers-rs released API adapter. No customer-controlled network requests exist here.
use crate::auth::Permission;
use crate::auth::{self, AccessFault, Actor, Credential, KeyCommand, KeyQuery, Keyring};
use crate::{core::*, security::*};
use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::*;
fn staging_mode(env: &Env) -> bool {
    cfg!(feature = "staging")
        || env
            .var("STAGING_MODE")
            .map(|v| v.to_string() == "true")
            .unwrap_or(false)
}
fn stage_expiry(env: &Env) -> i64 {
    env.var("STAGING_EXPIRES_MS")
        .ok()
        .and_then(|v| v.to_string().parse().ok())
        .unwrap_or(0)
}
fn stage_active(env: &Env) -> bool {
    now() < stage_expiry(env)
        && stage_expiry(env) > 0
        && stage_expiry(env).saturating_sub(now()) <= 900_000
}
fn stage_run(env: &Env) -> String {
    env.var("STAGING_RUN_ID")
        .map(|v| v.to_string())
        .unwrap_or_default()
}
fn now() -> i64 {
    Date::now().as_millis() as i64
}
// Explicit media type for the existing plain-text error contract.
fn text_error(message: impl Into<String>, status: u16) -> Result<Response> {
    let mut response = Response::error(message, status)?;
    response
        .headers_mut()
        .set("Content-Type", "text/plain; charset=utf-8")?;
    Ok(response)
}
// Test builds only: private service binding, never a request-selected fault route.
// Default and staging artifacts contain neither this function nor its call sites.
#[cfg(feature = "runtime-tests")]
async fn test_point(env: &Env, point: &str, metadata: serde_json::Value) -> Result<()> {
    if env.var("TEST_RUNTIME_ENABLED")?.to_string() != "true"
        || env.var("LOCAL_FIXTURES")?.to_string() != "true"
    {
        return Err(Error::RustError("Local test harness disabled".into()));
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(
        serde_json::to_string(&json!({"point":point,"metadata":metadata}))?.into(),
    ));
    let response = env
        .service("TEST_CONTROL")?
        .fetch("http://control.invalid/point", Some(init))
        .await?;
    if response.status_code() != 204 {
        return Err(Error::RustError("Injected local runtime failure".into()));
    }
    Ok(())
}
fn fault(e: Fault) -> Result<Response> {
    if let Fault::Limited {
        reason,
        retry_after_ms,
    } = e
    {
        let seconds = (retry_after_ms.max(1) as u64).div_ceil(1000);
        let mut r = Response::from_json(
            &json!({"error":"tenant_limited","reason":reason,"retry_after_ms":retry_after_ms}),
        )?
        .with_status(429);
        r.headers_mut().set("Retry-After", &seconds.to_string())?;
        return Ok(r);
    }
    let (code, label) = match e {
        Fault::Invalid => (400, "invalid_request"),
        Fault::Forbidden => (403, "forbidden"),
        Fault::DestinationDisabled => (422, "destination_disabled"),
        Fault::Conflict => (409, "idempotency_conflict"),
        Fault::NotFound => (404, "not_found"),
        Fault::Capacity => (429, "tenant_capacity"),
        Fault::Stale => (409, "stale_lease"),
        Fault::Limited { .. } => unreachable!("handled above"),
    };
    let mut r = Response::from_json(&json!({"error":label}))?.with_status(code);
    if code == 429 {
        r.headers_mut().set("Retry-After", "1")?;
    }
    Ok(r)
}
async fn call(
    env: &Env,
    tenant: &str,
    path: &str,
    body: serde_json::Value,
    auth_token: Option<&str>,
) -> Result<Response> {
    if !tenant_valid(tenant) {
        return text_error("Invalid tenant", 400);
    }
    let ns = env.durable_object("LEDGER")?;
    let stub = ns.id_from_name(tenant)?.get_stub()?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(serde_json::to_string(&body)?.into()));
    let mut req = Request::new_with_init(&format!("https://ledger{path}"), &init)?;
    req.headers_mut()?.set("x-tenant", tenant)?;
    if let Some(token) = auth_token {
        req.headers_mut()?
            .set("Authorization", &format!("Bearer {token}"))?;
    }
    stub.fetch_with_request(req).await
}
#[event(fetch)]
pub async fn fetch(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    #[cfg(feature = "runtime-tests")]
    {
        let url = req.url()?;
        if url.scheme() != "http"
            || url.host_str() != Some("127.0.0.1")
            || env
                .var("TEST_RUNTIME_ENABLED")
                .map(|v| v.to_string())
                .unwrap_or_default()
                != "true"
            || env
                .var("LOCAL_FIXTURES")
                .map(|v| v.to_string())
                .unwrap_or_default()
                != "true"
            || env.service("TEST_CONTROL").is_err()
        {
            return text_error("Local test artifact: loopback harness required", 403);
        }
    }
    // FIRST boundary on every hostname/route, including health and version/preview URLs.
    if staging_mode(&env) {
        let expected = env
            .secret("STAGING_INGRESS")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let supplied = req
            .headers()
            .get("X-RunLater-Staging-Gate")?
            .unwrap_or_default();
        if !crate::staging::gate(&expected, &supplied, stage_expiry(&env), now()) {
            return text_error("Staging gate denied", 403);
        }
        let header_bytes: usize = req
            .headers()
            .entries()
            .map(|(k, v)| k.len() + v.len())
            .sum();
        if header_bytes > 2048 {
            return text_error("Staging headers too large", 431);
        }
        if req.path() != "/health" && !crate::staging::api_route(req.method().as_ref(), &req.path())
        {
            return text_error("Staging route disabled", 403);
        }
    }
    if req.path() == "/health" {
        return Response::from_json(&json!({"status":"prototype","outbound":"disabled"}));
    }
    if env
        .var("LOCAL_FIXTURES")
        .map(|v| v.to_string())
        .unwrap_or_default()
        != "true"
    {
        return text_error("Prototype disabled; no production configuration", 503);
    }
    let auth = req.headers().get("Authorization")?.unwrap_or_default();
    let Some(token) = auth.strip_prefix("Bearer ") else {
        return text_error("Unauthorized", 401);
    };
    let tenant = match auth::route_credential(&env.var("API_KEY_HASHES")?.to_string(), token) {
        Ok(c) => c.tenant,
        Err(AuthFault::Unauthorized) => return text_error("Unauthorized", 401),
        Err(AuthFault::InvalidConfiguration) => {
            return text_error("Invalid authentication configuration", 503)
        }
    };
    if staging_mode(&env) && tenant != "alpha" {
        return text_error("Staging tenant disabled", 403);
    }
    let path = req.path();
    if !(path == "/v1/queue"
        || matches!(
            path.as_str(),
            "/v1/queue/health" | "/v1/queue/metrics" | "/v1/queue/audit" | "/v1/queue/maintenance"
        )
        || path == "/v1/tasks"
        || path.starts_with("/v1/tasks/")
        || path == "/v1/keys"
        || path.starts_with("/v1/keys/"))
    {
        return text_error("Not found", 404);
    }
    if matches!(req.method(), Method::Post | Method::Put) {
        if let Some(content_type) = req.headers().get("Content-Type")? {
            if content_type.split(';').next().unwrap_or("").trim() != "application/json" {
                return text_error("Expected application/json", 415);
            }
        } else if path == "/v1/tasks" || path == "/v1/queue" || path == "/v1/keys" {
            return text_error("Expected application/json", 415);
        }
    }
    // Read at most 24KiB even when Content-Length is absent or untrusted.
    use futures_util::StreamExt;
    let mut bytes = Vec::new();
    let read_body = async {
        if let Ok(mut reader) = req.stream() {
            while let Some(chunk) = reader.next().await {
                let chunk = chunk?;
                if bytes.len() + chunk.len() > 24 * 1024 {
                    return Ok(false);
                }
                bytes.extend_from_slice(&chunk);
            }
        }
        Ok::<bool, worker::Error>(true)
    };
    if staging_mode(&env) {
        use futures_util::{
            future::{select, Either},
            pin_mut,
        };
        use std::time::Duration;
        let timeout = Delay::from(Duration::from_millis(3000));
        pin_mut!(read_body);
        pin_mut!(timeout);
        match select(read_body, timeout).await {
            Either::Left((result, _)) => {
                if !result? {
                    return text_error("Payload too large", 413);
                }
            }
            Either::Right((_done, _pending)) => return text_error("Staging body deadline", 408),
        }
    } else {
        if !read_body.await? {
            return text_error("Payload too large", 413);
        }
    }
    let body = if bytes.is_empty() {
        json!(null)
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(b) => b,
            Err(_) => return text_error("Invalid JSON", 400),
        }
    };
    let key = req.headers().get("Idempotency-Key")?.unwrap_or_default();
    let url = req.url()?;
    let query = url.query().unwrap_or("");
    call(
        &env,
        &tenant,
        "/api",
        json!({"method":req.method().to_string(),"path":path,"query":query,"key":key,"body":body}),
        Some(token),
    )
    .await
}
#[derive(Deserialize)]
struct Api {
    method: String,
    path: String,
    query: String,
    key: String,
    body: serde_json::Value,
}
#[derive(Default, Serialize, Deserialize)]
struct Stored {
    tenant: String,
    ledger: Ledger,
    #[serde(default)]
    staging_published: u32,
    #[serde(default)]
    keys: Option<Keyring>,
}
#[derive(Deserialize)]
struct Row {
    data: String,
}
#[durable_object]
pub struct TaskLedger {
    state: State,
    env: Env,
}
impl TaskLedger {
    fn effective_keys(&self, s: &Stored, tenant: &str) -> Result<Keyring> {
        match &s.keys {
            Some(keys) => Ok(keys.clone()),
            None => Keyring::bootstrap(&self.env.var("API_KEY_HASHES")?.to_string(), tenant)
                .map_err(|_| Error::RustError("Invalid authentication configuration".into())),
        }
    }
    fn load(&self) -> Result<Stored> {
        let sql = self.state.storage().sql();
        #[derive(Deserialize)]
        struct Exists {
            count: i64,
        }
        let exists: Vec<Exists> = sql
            .exec(
                "SELECT count(*) AS count FROM sqlite_master WHERE type='table' AND name='ledger'",
                None,
            )?
            .to_array()?;
        if exists.first().is_none_or(|row| row.count == 0) {
            return Ok(Stored::default());
        }
        let rows: Vec<Row> = sql
            .exec("SELECT data FROM ledger WHERE id=1", None)?
            .to_array()?;
        match rows.first() {
            Some(r) => Ok(serde_json::from_str(&r.data)?),
            None => Ok(Stored::default()),
        }
    }
    fn initialize_schema(&self) -> Result<()> {
        self.state.storage().sql().exec("CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL CHECK(version=1), data TEXT NOT NULL)",None)?;
        Ok(())
    }
    fn save(&self, s: &Stored) -> Result<()> {
        self.state.storage().sql().exec("INSERT INTO ledger(id,version,data) VALUES(1,1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",vec![serde_json::to_string(s)?.into()])?;
        Ok(())
    }
    async fn rearm(&self, preserve_earlier: bool) -> Result<()> {
        #[cfg(feature = "runtime-tests")]
        test_point(
            &self.env,
            "before_rearm",
            json!({"preserve_earlier":preserve_earlier}),
        )
        .await?;
        let existing = self.state.storage().get_alarm().await?;
        let s = self.load()?;
        if staging_mode(&self.env)
            && (!stage_active(&self.env) || s.staging_published >= crate::staging::MAX_PUBLISH)
        {
            self.state.storage().delete_alarm().await?;
            return Ok(());
        }
        if let Some(mut at) = s.ledger.next_wake(now()) {
            if staging_mode(&self.env) {
                at = at.min(stage_expiry(&self.env))
            }
            let target = if preserve_earlier {
                existing.map_or(at, |old| old.min(at))
            } else {
                at
            };
            // Released workers-rs i64 is a relative offset, NOT an absolute timestamp.
            self.state
                .storage()
                .set_alarm((target - now()).max(1))
                .await?;
        } else {
            self.state.storage().delete_alarm().await?;
        }
        Ok(())
    }
    async fn pump(&self) -> Result<()> {
        // A durable watchdog exists before work and throughout queue I/O.
        self.state.storage().set_alarm(1000).await?;
        self.initialize_schema()?;
        let mut s = self.load()?;
        s.ledger
            .migrate_legacy_redrive_keys()
            .map_err(|_| Error::RustError("Invalid legacy redrive state".into()))?;
        s.ledger.purge(now());
        let mut messages = s.ledger.outbox(&s.tenant, now());
        if staging_mode(&self.env) {
            messages.truncate(
                (crate::staging::MAX_PUBLISH.saturating_sub(s.staging_published)) as usize,
            );
            // Reserve attempts before Queue I/O; uncertainty spends budget rather than amplifying it.
            s.staging_published += messages.len() as u32;
        }
        self.save(&s)?;
        for d in messages {
            #[cfg(feature = "runtime-tests")]
            let reference = d.clone();
            #[cfg(feature = "runtime-tests")]
            test_point(
                &self.env,
                "before_publish",
                serde_json::to_value(&reference)?,
            )
            .await?;
            self.env.queue("READY")?.send(d).await?;
            #[cfg(feature = "runtime-tests")]
            test_point(&self.env, "after_publish", serde_json::to_value(reference)?).await?;
        }
        self.rearm(false).await
    }
}
impl DurableObject for TaskLedger {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let tenant = req.headers().get("x-tenant")?.unwrap_or_default();
        if tenant.is_empty() {
            return text_error("Missing tenant", 400);
        }
        if !tenant_valid(&tenant) {
            return text_error("Invalid tenant", 400);
        }
        let path = req.path();
        if staging_mode(&self.env) && !stage_active(&self.env) {
            return text_error("Staging expired", 403);
        }
        let raw: serde_json::Value = req.json().await?;
        // Parse and authenticate API requests before watchdog or business effects.
        let mut credential: Option<Credential> = None;
        let mut permission = None;
        let mut key_command = None;
        let command = if path == "/api" {
            let a: Api = serde_json::from_value(raw.clone())?;
            if staging_mode(&self.env)
                && (!stage_active(&self.env)
                    || tenant != "alpha"
                    || crate::staging::canonical_route(&a.method, &a.path).is_none())
            {
                return text_error("Staging request disabled", 403);
            }

            let Some(required) = auth::required_permission(&a.method, &a.path) else {
                return text_error("Not found", 404);
            };
            let header = req.headers().get("Authorization")?.unwrap_or_default();
            let Some(token) = header.strip_prefix("Bearer ") else {
                return text_error("Unauthorized", 401);
            };
            let c =
                match auth::route_credential(&self.env.var("API_KEY_HASHES")?.to_string(), token) {
                    Ok(c) if c.tenant == tenant => c,
                    _ => return text_error("Unauthorized", 401),
                };
            let snapshot = self.load()?;
            if !snapshot.tenant.is_empty() && snapshot.tenant != tenant {
                return text_error("Tenant mismatch", 403);
            }
            let keys = self.effective_keys(&snapshot, &tenant)?;
            if let Err(e) = keys.authorize(&c, required, now()) {
                return access_fault(e);
            }
            if a.method == "GET" {
                if a.path == "/v1/keys" {
                    return Response::from_json(&keys.query(KeyQuery::List));
                }
                if a.path == "/v1/keys/audit" {
                    return Response::from_json(&keys.query(KeyQuery::Audit));
                }
                return query_response(&snapshot.ledger, a);
            }
            permission = Some(required);
            credential = Some(c);
            if a.path.starts_with("/v1/keys") {
                key_command = match parse_key_command(a) {
                    Ok(Some(c)) => Some(c),
                    Ok(None) => return text_error("Not found", 404),
                    Err(e) => return fault(e),
                };
                None
            } else {
                match parse_command(a, staging_mode(&self.env)) {
                    Ok(Some(c)) => {
                        if staging_mode(&self.env)
                            && !crate::staging::command_allowed(&c, &stage_run(&self.env), now())
                        {
                            return fault(Fault::Invalid);
                        }
                        Some(c)
                    }
                    Ok(None) => return text_error("Not found", 404),
                    Err(e) => return fault(e),
                }
            }
        } else {
            None
        };
        let dispatch = if path == "/claim" {
            let d: Dispatch = match serde_json::from_value(raw.clone()) {
                Ok(d) => d,
                Err(_) => return fault(Fault::Invalid),
            };
            if d.tenant != tenant || !task_id_valid(&d.id) || d.generation == 0 {
                return fault(Fault::Invalid);
            }
            Some(d)
        } else {
            None
        };
        let finish = if path == "/finish" {
            let f: Finish = match serde_json::from_value(raw) {
                Ok(f) => f,
                Err(_) => return fault(Fault::Invalid),
            };
            if !task_id_valid(&f.id) || f.fence == 0 || !(100..=599).contains(&f.status) {
                return fault(Fault::Invalid);
            }
            Some(f)
        } else {
            None
        };
        if command.is_none() && key_command.is_none() && dispatch.is_none() && finish.is_none() {
            return text_error("Not found", 404);
        }
        // Arm before acceptance without postponing already due work. Reload after all awaits.
        let existing = self.state.storage().get_alarm().await?;
        if existing.is_none_or(|at| at > now() + 1000) {
            self.state.storage().set_alarm(1000).await?;
        }
        self.initialize_schema()?;
        let mut s = self.load()?;
        if s.tenant.is_empty() {
            s.tenant = tenant.clone()
        }
        if s.tenant != tenant {
            return text_error("Tenant mismatch", 403);
        }
        // Storage awaits above may interleave revocation. Recheck the authoritative keyring
        // immediately before the synchronous mutation/commit section, without another await.
        let actor: Option<Actor> =
            if let (Some(c), Some(required)) = (credential.as_ref(), permission) {
                let keys = self.effective_keys(&s, &tenant)?;
                let actor = match keys.authorize(c, required, now()) {
                    Ok(a) => a,
                    Err(e) => return access_fault(e),
                };
                s.keys = Some(keys);
                Some(actor)
            } else {
                None
            };
        s.ledger
            .migrate_legacy_redrive_keys()
            .map_err(|_| Error::RustError("Invalid legacy redrive state".into()))?;
        s.ledger.reconcile(now());
        #[cfg(feature = "runtime-tests")]
        let enqueuing = matches!(&command, Some(crate::application::Command::Enqueue { .. }));
        let result = if let Some(d) = dispatch {
            match s.ledger.claim(&d, now()) {
                Ok(t) => Response::from_json(&t),
                Err(e) => fault(e),
            }
        } else if let Some(f) = finish {
            match s
                .ledger
                .finish(&f.id, f.fence, Outcome::Http(f.status), now())
            {
                Ok(mut t) => {
                    if staging_mode(&self.env) {
                        if let Some(a) = t.attempts.last_mut() {
                            a.staging_diagnostic = f.diagnostic;
                        }
                        s.ledger.tasks.insert(t.id.clone(), t.clone());
                    }
                    Response::from_json(&t)
                }
                Err(e) => fault(e),
            }
        } else if let Some(c) = key_command {
            let keys = s
                .keys
                .as_mut()
                .ok_or_else(|| Error::RustError("Missing project keys".into()))?;
            match keys.command(
                actor
                    .as_ref()
                    .ok_or_else(|| Error::RustError("Missing key actor".into()))?,
                c,
                now(),
            ) {
                Ok((view, created)) => {
                    Ok(Response::from_json(&view)?.with_status(if created { 201 } else { 200 }))
                }
                Err(e) => fault(e),
            }
        } else if let Some(c) = command {
            match crate::application::command(&mut s.ledger, c, now()) {
                Ok(r) => Ok(Response::from_json(
                    &r.scoped_body(
                        actor
                            .as_ref()
                            .is_some_and(|a| a.permissions.contains(&Permission::Read)),
                    ),
                )?
                .with_status(r.status)),
                Err(e) => fault(e),
            }
        } else {
            text_error("Not found", 404)
        };
        if staging_mode(&self.env) && s.ledger.tasks.len() > crate::staging::MAX_TASKS {
            return text_error("Staging task budget exhausted", 429);
        }
        self.save(&s)?;
        #[cfg(feature = "runtime-tests")]
        if enqueuing && result.as_ref().is_ok_and(|r| r.status_code() == 201) {
            test_point(
                &self.env,
                "accepted_commit",
                json!({"id":format!("task_{:016x}",s.ledger.sequence)}),
            )
            .await?;
        }
        self.rearm(true).await?;
        result
    }
    async fn alarm(&self) -> Result<Response> {
        if staging_mode(&self.env) && !stage_active(&self.env) {
            self.state.storage().delete_alarm().await?;
            return Response::ok("staging expired");
        }
        self.pump().await?;
        Response::ok("reconciled")
    }
}
#[event(queue)]
pub async fn consume(batch: MessageBatch<Dispatch>, env: Env, _ctx: Context) -> Result<()> {
    for message in batch.messages()? {
        if staging_mode(&env) && !stage_active(&env) {
            message.ack();
            continue;
        }
        let d = message.body();
        if staging_mode(&env) && d.tenant != "alpha" {
            message.ack();
            continue;
        }
        #[cfg(feature = "runtime-tests")]
        test_point(&env, "before_claim", serde_json::to_value(d)?).await?;
        let mut claim = call(&env, &d.tenant, "/claim", serde_json::to_value(d)?, None).await?;
        if claim.status_code() == 429 {
            // A durable ready/outbox disposition and alarm were committed before this response.
            // Admission deferral does not start an independent transport retry loop.
            message.ack();
            continue;
        }
        if claim.status_code() != 200 {
            message.retry();
            continue;
        }
        let Some(task) = claim.json::<Option<Task>>().await? else {
            message.ack();
            continue;
        };
        // In-process receiver: never fetches URLs, follows redirects, resolves DNS, or touches external systems.
        let enabled = env
            .var("LOCAL_FIXTURES")
            .map(|v| v.to_string())
            .unwrap_or_default()
            == "true";
        let mut diagnostic = None;
        let status = if staging_mode(&env) && task.input.destination == "staging://receiver" {
            let result = controlled_delivery(&env, &d.tenant, &task).await;
            diagnostic = Some(result.1);
            result.0
        } else if enabled && destination_allowed(&task.input.destination) {
            let key = b"public-local-fixture-signing-key-not-for-production";
            let ts = now() / 1000;
            let delivery_id = format!("{}:{}", d.tenant, task.id);
            let signature = sign(
                key,
                ts,
                &delivery_id,
                &task.input.operation_key,
                task.input.body.as_bytes(),
            );
            if !verify(
                key,
                ts,
                &delivery_id,
                &task.input.operation_key,
                task.input.body.as_bytes(),
                &signature,
                ts,
            ) {
                500
            } else {
                match task.input.destination.as_str() {
                    "fixture://success" => 204,
                    "fixture://retry" if task.attempts.len() < 2 => 503,
                    _ => 400,
                }
            }
        } else {
            400
        };
        #[cfg(feature = "runtime-tests")]
        test_point(
            &env,
            "callback_complete",
            json!({"id":task.id,"fence":task.fence,"status":status}),
        )
        .await?;
        let done = call(
            &env,
            &d.tenant,
            "/finish",
            json!({"id":task.id,"fence":task.fence,"status":status,"diagnostic":diagnostic}),
            None,
        )
        .await?;
        if done.status_code() == 200 || done.status_code() == 409 {
            message.ack()
        } else {
            message.retry()
        }
    }
    Ok(())
}

fn query_response(ledger: &Ledger, a: Api) -> Result<Response> {
    use crate::application::{self, Query};
    let parts: Vec<&str> = a.path.trim_matches('/').split('/').collect();
    let q = match parts.as_slice() {
        ["v1", "queue"] => Some(Query::QueueConfig),
        ["v1", "queue", "metrics"] => Some(Query::Metrics {
            sampled_at_ms: now(),
        }),
        ["v1", "queue", "health"] => Some(Query::Health {
            sampled_at_ms: now(),
        }),
        ["v1", "queue", "audit"] => Some(Query::Audit),
        ["v1", "tasks", id, "inspection"] => Some(Query::Inspection { id: (*id).into() }),
        ["v1", "tasks"] => {
            let params: std::collections::BTreeMap<_, _> =
                url::form_urlencoded::parse(a.query.as_bytes())
                    .into_owned()
                    .collect();
            Some(Query::List {
                after: params.get("after").cloned().unwrap_or_default(),
            })
        }
        ["v1", "tasks", id] => Some(Query::Task { id: (*id).into() }),
        ["v1", "tasks", id, "attempts"] => Some(Query::Attempts { id: (*id).into() }),
        _ => None,
    };
    match q {
        Some(q) => match application::query(ledger, q) {
            Ok(v) => Response::from_json(&v),
            Err(e) => fault(e),
        },
        None => text_error("Not found", 404),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    id: String,
    fence: u64,
    status: u16,
    #[serde(default)]
    diagnostic: Option<crate::staging::DeliveryDiagnostic>,
}
fn parse_command(
    a: Api,
    staging: bool,
) -> std::result::Result<Option<crate::application::Command>, Fault> {
    use crate::application::Command;
    let parts: Vec<&str> = a.path.trim_matches('/').split('/').collect();
    let c = match (a.method.as_str(), parts.as_slice()) {
        ("POST", ["v1", "tasks"]) => {
            let input: Create = serde_json::from_value(a.body).map_err(|_| Fault::Invalid)?;
            if !destination_allowed(&input.destination)
                && !(staging && input.destination == "staging://receiver")
            {
                return Err(Fault::DestinationDisabled);
            }
            Some(Command::Enqueue { key: a.key, input })
        }
        ("POST", ["v1", "tasks", id, "cancel"]) if task_id_valid(id) => {
            Some(Command::Cancel { id: (*id).into() })
        }
        ("POST", ["v1", "tasks", id, "redrive"]) if task_id_valid(id) => Some(Command::Redrive {
            id: (*id).into(),
            key: a.key,
        }),
        ("POST", ["v1", "queue", "maintenance"]) => {
            if !a.query.is_empty() || !a.body.as_object().is_some_and(|m| m.is_empty()) {
                return Err(Fault::Invalid);
            }
            Some(Command::MaintainRetention)
        }
        ("PUT", ["v1", "queue"]) => {
            let limits: crate::limits::QueueLimits =
                serde_json::from_value(a.body).map_err(|_| Fault::Invalid)?;
            limits.validate()?;
            Some(Command::ConfigureQueue { limits })
        }
        _ => None,
    };
    Ok(c)
}

fn access_fault(e: AccessFault) -> Result<Response> {
    match e {
        AccessFault::Unauthorized => text_error("Unauthorized", 401),
        AccessFault::Forbidden => fault(Fault::Forbidden),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateBody {
    new_key: auth::NewKey,
    revoke_old_at_ms: i64,
}
fn parse_key_command(a: Api) -> std::result::Result<Option<KeyCommand>, Fault> {
    let parts: Vec<&str> = a.path.trim_matches('/').split('/').collect();
    match (a.method.as_str(), parts.as_slice()) {
        ("POST", ["v1", "keys"]) => Ok(Some(KeyCommand::Create(
            serde_json::from_value(a.body).map_err(|_| Fault::Invalid)?,
        ))),
        ("POST", ["v1", "keys", id, "revoke"]) if auth::key_id_valid(id) => {
            if !a.body.is_null() {
                return Err(Fault::Invalid);
            }
            Ok(Some(KeyCommand::Revoke {
                key_id: (*id).into(),
            }))
        }
        ("POST", ["v1", "keys", id, "rotate"]) if auth::key_id_valid(id) => {
            let body: RotateBody = serde_json::from_value(a.body).map_err(|_| Fault::Invalid)?;
            Ok(Some(KeyCommand::Rotate {
                key_id: (*id).into(),
                new_key: body.new_key,
                revoke_old_at_ms: body.revoke_old_at_ms,
            }))
        }
        _ => Ok(None),
    }
}

async fn controlled_delivery(
    env: &Env,
    tenant: &str,
    task: &Task,
) -> (u16, crate::staging::DeliveryDiagnostic) {
    use crate::staging::DeliveryDiagnostic as D;
    use futures_util::{
        future::{select, Either},
        pin_mut, StreamExt,
    };
    use std::time::Duration;
    let enabled = env
        .var("STAGING_DELIVERY_ENABLED")
        .map(|v| v.to_string() == "true")
        .unwrap_or(false);
    let url = env
        .var("STAGING_RECEIVER_URL")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let host = env
        .var("STAGING_RECEIVER_HOST")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let run = stage_run(env);
    let gate = env
        .secret("STAGING_INGRESS")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let secret = env
        .secret("STAGING_CALLBACK_HMAC")
        .map(|v| v.to_string())
        .unwrap_or_default();
    if !enabled
        || !stage_active(env)
        || !crate::staging::receiver_url_allowed(&url, &host, &run)
        || !crate::staging::valid_secret(&gate)
        || !crate::staging::valid_secret(&secret)
        || crate::staging::synthetic(&task.input.body, &run).is_none()
    {
        return (400, D::PolicyRejected);
    }
    let task_id = format!("{tenant}:{}", task.id);
    let timestamp = now() / 1000;
    let signature = sign(
        secret.as_bytes(),
        timestamp,
        &task_id,
        &task.input.operation_key,
        task.input.body.as_bytes(),
    );
    let controller = AbortController::default();
    let signal = controller.signal();
    let operation = async {
        let headers = Headers::new();
        headers.set("Content-Type", "application/json")?;
        headers.set("X-RunLater-Staging-Gate", &gate)?;
        headers.set("RunLater-Task-Id", &task_id)?;
        headers.set("RunLater-Operation-Key", &task.input.operation_key)?;
        headers.set("RunLater-Timestamp", &timestamp.to_string())?;
        headers.set("RunLater-Signature", &signature)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_redirect(RequestRedirect::Manual)
            .with_headers(headers)
            .with_body(Some(task.input.body.clone().into()));
        let req = Request::new_with_init(&url, &init)?;
        let mut response = Fetch::Request(req).send_with_signal(&signal).await?;
        let status = response.status_code();
        if (300..=399).contains(&status) {
            return Ok::<_, worker::Error>((400, D::RedirectRejected));
        }
        let header_bytes: usize = response
            .headers()
            .entries()
            .map(|(k, v)| k.len() + v.len())
            .sum();
        if header_bytes > 2048 {
            return Ok((400, D::ResponseHeadersTooLarge));
        }
        let receipt = response
            .headers()
            .get("RunLater-Receipt")?
            .unwrap_or_default();
        let mut size = 0;
        if let Ok(mut body) = response.stream() {
            while let Some(chunk) = body.next().await {
                size += chunk?.len();
                if size > 1024 {
                    return Ok((400, D::ResponseBodyTooLarge));
                }
            }
        }
        if status != 204 {
            return Ok((400, D::ReceiverStatus(status)));
        }
        if crate::staging::verify_receipt(
            &secret,
            timestamp,
            &task_id,
            &task.input.operation_key,
            task.input.body.as_bytes(),
            &receipt,
            now() / 1000,
        ) {
            Ok((204, D::VerifiedReceipt))
        } else {
            Ok((400, D::ReceiptRejected))
        }
    };
    let timeout = Delay::from(Duration::from_millis(crate::staging::TIMEOUT_MS));
    pin_mut!(operation);
    pin_mut!(timeout);
    let status = match select(operation, timeout).await {
        Either::Left((result, _)) => result.unwrap_or((408, D::FetchError)),
        Either::Right((_done, _pending)) => (408, D::Timeout),
    };
    controller.abort();
    status
}
