//! LOCAL TEST ENTRYPOINT ONLY. No public authentication/admission contract or deployed binding.
use crate::destinations::{self, EgressPolicy, State as Registry};
use serde::Deserialize;
use serde_json::json;
use worker::{
    wasm_bindgen::{JsCast, JsValue},
    *,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    action: String,
    endpoint_id: String,
    version: u32,
    url: Option<String>,
    task_id: Option<String>,
    // Deterministic clock injection belongs exclusively to this isolated test artifact.
    at_ms: i64,
    complete_at_ms: Option<i64>,
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
fn reject(e: destinations::Error) -> Result<Response> {
    let status = match e {
        destinations::Error::Invalid => 400,
        destinations::Error::Forbidden => 403,
        destinations::Error::NotFound => 404,
        destinations::Error::Conflict => 409,
        destinations::Error::Expired => 410,
        destinations::Error::Limited => 429,
        _ => 503,
    };
    Ok(Response::from_json(&json!({"error":format!("{e:?}")}))?.with_status(status))
}
#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    // Mandatory local fixture capability; absent in all normal production/default configs.
    env.service("TEST_DESTINATION_CONTROL")?;
    let path = req.path();
    if req.method() != Method::Post || !matches!(path.as_str(), "/alpha" | "/beta") {
        return Response::error("fixture route only", 404);
    }
    let stub = env
        .durable_object("DESTINATIONS")?
        .id_from_name(&path[1..])?
        .get_stub()?;
    stub.fetch_with_request(req).await
}
#[durable_object]
pub struct DestinationFixture {
    state: worker::State,
    env: Env,
}
impl DestinationFixture {
    fn load(&self, project: &str) -> Result<Registry> {
        #[derive(Deserialize)]
        struct Count {
            count: u32,
        }
        #[derive(Deserialize)]
        struct Row {
            data: String,
        }
        let sql = self.state.storage().sql();
        let exists: Vec<Count> = sql
            .exec(
                "SELECT count(*) AS count FROM sqlite_master WHERE name='destination_fixture'",
                None,
            )?
            .to_array()?;
        if exists.first().is_none_or(|n| n.count == 0) {
            return Registry::new(project)
                .map_err(|_| Error::RustError("Invalid fixture tenant".into()));
        }
        let rows: Vec<Row> = sql
            .exec("SELECT data FROM destination_fixture WHERE id=1", None)?
            .to_array()?;
        Registry::decode(
            rows.first()
                .ok_or_else(|| Error::RustError("Missing fixture state".into()))?
                .data
                .as_bytes(),
            project,
        )
        .map_err(|_| Error::RustError("Invalid fixture state".into()))
    }
    fn save(&self, registry: &Registry) -> Result<()> {
        let sql = self.state.storage().sql();
        // No await between schema and single-row upsert: atomic synchronous SQL writes.
        sql.exec("CREATE TABLE IF NOT EXISTS destination_fixture(id INTEGER PRIMARY KEY CHECK(id=1),data TEXT NOT NULL)", None)?;
        sql.exec("INSERT INTO destination_fixture(id,data) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", vec![serde_json::to_string(registry)?.into()])?;
        Ok(())
    }
}
impl DurableObject for DestinationFixture {
    fn new(state: worker::State, env: Env) -> Self {
        Self { state, env }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        use futures_util::{
            future::{select, Either},
            pin_mut, StreamExt,
        };
        let project = req.path()[1..].to_string();
        if !matches!(project.as_str(), "alpha" | "beta") {
            return Response::error("fixture tenant only", 403);
        }
        let reader = async {
            let mut bytes = Vec::new();
            let mut chunks = 0;
            if let Ok(mut stream) = req.stream() {
                while let Some(part) = stream.next().await {
                    let part = part?;
                    chunks += 1;
                    if bytes.len() + part.len() > 2048 || chunks > 32 {
                        return Ok(None);
                    }
                    bytes.extend_from_slice(&part);
                }
            }
            Ok::<_, worker::Error>(serde_json::from_slice::<Input>(&bytes).ok())
        };
        let deadline = Delay::from(std::time::Duration::from_millis(3000));
        pin_mut!(reader, deadline);
        let input = match select(reader, deadline).await {
            Either::Left((Ok(Some(v)), _)) => v,
            _ => return Response::error("Invalid bounded fixture input", 400),
        };
        let raw = self.env.var("TEST_APPROVED_HOSTS")?.to_string();
        if raw.len() > 2048 {
            return Response::error("Invalid fixture policy", 503);
        }
        let policy: EgressPolicy = serde_json::from_str(&raw)?;
        let mut registry = self.load(&project)?;
        let result = match input.action.as_str() {
            "get" => registry
                .get(&project, &input.endpoint_id, input.version)
                .map(|v| json!(v)),
            "create" => registry
                .create(
                    &project,
                    &input.endpoint_id,
                    input.version,
                    input.url.as_deref().unwrap_or_default(),
                    &policy,
                    input.at_ms,
                )
                .map(|v| json!(v)),
            "revoke" => registry
                .revoke(&project, &input.endpoint_id, input.at_ms)
                .map(|_| json!({"revoked":true})),
            "snapshot" => registry
                .snapshot(
                    &project,
                    input.task_id.as_deref().unwrap_or_default(),
                    &input.endpoint_id,
                    input.version,
                    &policy,
                    input.at_ms,
                )
                .map(|v| json!(v)),
            "dispatch" => registry
                .dispatch(
                    &project,
                    input.task_id.as_deref().unwrap_or_default(),
                    &policy,
                )
                .map(|v| json!({"url":v.url()})),
            "prepare" => registry
                .prepare(
                    &project,
                    &input.endpoint_id,
                    input.version,
                    &nonce()?,
                    &policy,
                    input.at_ms,
                )
                .map(|v| json!(v)),
            "verify" => {
                let challenge = match registry.begin(
                    &project,
                    &input.endpoint_id,
                    input.version,
                    &policy,
                    input.at_ms,
                ) {
                    Ok(c) => c,
                    Err(e) => return reject(e),
                };
                self.save(&registry)?; // durable reservation before fetch; restart preserves it
                let target = challenge
                    .target(&policy)
                    .map_err(|_| Error::RustError("Target unavailable".into()))?;
                let response = crate::safe_egress::fetch(
                    target,
                    challenge.body.clone(),
                    "text/plain; charset=utf-8",
                    Default::default(),
                )
                .await;
                registry = self.load(&project)?; // revocation/newer state may interleave with fetch
                let category = response.as_ref().err().map(|e| e.category);
                let proof = response
                    .as_ref()
                    .map(|r| (r.status, r.body.as_slice()))
                    .map_err(|_| ());
                let result = registry.complete(
                    &project,
                    &challenge,
                    proof,
                    &policy,
                    input.complete_at_ms.unwrap_or(input.at_ms),
                );
                self.save(&registry)?; // failed proof consumption is durable too
                return match result {
                    Ok(v) => Response::from_json(&json!({"endpoint":v})),
                    Err(e) => Ok(Response::from_json(
                        &json!({"error":format!("{e:?}"),"category":category}),
                    )?
                    .with_status(match e {
                        destinations::Error::Expired => 410,
                        destinations::Error::Conflict => 409,
                        _ => 503,
                    })),
                };
            }
            _ => Err(destinations::Error::Invalid),
        };
        match result {
            Ok(v) => {
                if !matches!(input.action.as_str(), "get" | "dispatch") {
                    self.save(&registry)?;
                }
                Response::from_json(&v)
            }
            Err(e) => reject(e),
        }
    }
}
