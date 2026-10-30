//! Production-only restricted alpha transport. No fixture/alternate URL branch.
use super::*;
use crate::{
    callback::Material,
    core::{Dispatch, Outcome},
    delivery::{Policy, Wire},
};
use std::collections::BTreeMap;
pub(super) struct Secrets(BTreeMap<String, Vec<u8>>);
impl Material for Secrets {
    fn key(&self, id: &str) -> Option<&[u8]> {
        self.0.get(id).map(Vec::as_slice)
    }
}
pub(super) fn configuration(env: &Env, project: &str) -> Result<Option<(Policy, Secrets)>> {
    if env
        .var("ALPHA_DELIVERY_ENABLED")
        .map(|v| v.to_string())
        .unwrap_or_default()
        != "operator-approved"
    {
        return Ok(None);
    }
    env.queue("ALPHA_READY")?;
    let queue = env.var("ALPHA_READY_QUEUE")?.to_string();
    if queue != "runlater-alpha-ready" {
        return Err(Error::RustError("Invalid alpha queue".into()));
    }
    let raw = env.var("ALPHA_DELIVERY_POLICIES")?.to_string();
    if raw.len() > 16384 {
        return Err(Error::RustError("Invalid alpha policies".into()));
    }
    let list: Vec<Policy> = serde_json::from_str(&raw)?;
    if list.is_empty() || list.len() > 8 {
        return Err(Error::RustError("Invalid alpha policy count".into()));
    }
    let mut ids = std::collections::BTreeSet::new();
    for p in &list {
        if !ids.insert(p.project_id.clone()) {
            return Err(Error::RustError("Duplicate alpha policy".into()));
        }
    }
    let Some(p) = list.into_iter().find(|p| p.project_id == project) else {
        return Ok(None);
    };
    let raw = env.secret("ALPHA_CALLBACK_KEYS")?.to_string();
    if raw.len() > 4096 {
        return Err(Error::RustError("Invalid callback material".into()));
    }
    let entries: BTreeMap<String, String> = serde_json::from_str(&raw)?;
    if entries.is_empty() || entries.len() > 16 {
        return Err(Error::RustError("Invalid callback key count".into()));
    }
    let mut material = BTreeMap::new();
    for (id, value) in entries {
        if !crate::security::tenant_valid(&id)
            || id.starts_with("fixture")
            || value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::RustError("Invalid callback key material".into()));
        }
        let key =
            hex::decode(value).map_err(|_| Error::RustError("Invalid callback material".into()))?;
        if key.iter().all(|b| *b == key[0]) {
            return Err(Error::RustError("Degenerate callback material".into()));
        }
        material.insert(id, key);
    }
    Ok(Some((p, Secrets(material))))
}
pub(super) fn apply(stored: &mut Project, p: &Policy, material: &Secrets, at: i64) -> Result<()> {
    let mut next = stored.clone();
    next.delivery
        .apply(p, at)
        .map_err(|_| Error::RustError("Delivery policy rejected".into()))?;
    next.delivery
        .bind_material(material)
        .map_err(|_| Error::RustError("Callback material identity rejected".into()))?;
    next.funding
        .apply(&p.grant, at)
        .map_err(|_| Error::RustError("Funding policy rejected".into()))?;
    *stored = next;
    Ok(())
}
impl ProjectIdentity {
    pub(super) async fn delivery_rearm(&self) -> Result<()> {
        let s = self.load()?;
        let wake = s.delivery_next_wake(now());
        if let Some(at) = wake {
            self.state.storage().set_alarm((at - now()).max(1)).await?;
        } else {
            self.state.storage().delete_alarm().await?;
        }
        Ok(())
    }
    async fn unavailable_rearm(&self) -> Result<()> {
        let s = self.load()?;
        if let Some(at) = s.delivery_unavailable_wake(now()) {
            self.state.storage().set_alarm((at - now()).max(1)).await?;
        } else {
            self.state.storage().delete_alarm().await?;
        }
        Ok(())
    }
    pub(super) async fn delivery_pump(&self) -> Result<()> {
        self.state.storage().set_alarm(1000).await?;
        let mut s = self.load()?;
        s.funded_maintenance(now())
            .map_err(|_| Error::RustError("Funding maintenance rejected".into()))?;
        s.delivery.prune(&s.ledger);
        let project = s.delivery.project_id.clone();
        if project.is_empty() {
            self.save(&s)?;
            return self.delivery_rearm().await;
        }
        let configured = configuration(&self.env, &project);
        let Some((p, material)) = configured.unwrap_or(None) else {
            self.save(&s)?;
            self.unavailable_rearm().await?;
            return Ok(());
        };
        if apply(&mut s, &p, &material, now()).is_err() {
            self.save(&s)?;
            self.unavailable_rearm().await?;
            return Ok(());
        }
        let mut refs = s.ledger.outbox(&project, now());
        s.delivery.reserve_publications(&mut refs);
        s.funding
            .settle_all(&s.ledger, now())
            .map_err(|_| Error::RustError("Funding settlement rejected".into()))?;
        self.save(&s)?;
        if crate::publication::publish_batch(refs, |d| async move {
            self.env.queue("ALPHA_READY")?.send(d).await
        })
        .await
        .is_err()
        {
            self.state.storage().set_alarm(1000).await?;
            return Err(Error::RustError("Queue publication uncertain".into()));
        }
        self.delivery_rearm().await
    }
    pub(super) async fn deliver_reference(&self, project: &str, d: Dispatch) -> Result<Response> {
        if d.tenant != project || !crate::transport::valid_dispatch(&d) {
            return response("invalid_dispatch", 400);
        }
        self.state.storage().set_alarm(1000).await?;
        let Some((p, material)) = configuration(&self.env, project)? else {
            return response("delivery_not_ready", 503);
        };
        let mut s = self.load()?;
        apply(&mut s, &p, &material, now())?;
        // Persist operator revocations even if this reference is missing, stale or denied.
        self.save(&s)?;
        let wire = match s.delivery_claim(&p, &d, &material, now()) {
            Ok(w) => w,
            Err(crate::delivery::Error::Task(crate::funded_tasks::Error::Ledger(
                crate::core::Fault::NotFound,
            ))) => {
                self.delivery_rearm().await?;
                return response("task_not_found", 404);
            }
            Err(crate::delivery::Error::Task(crate::funded_tasks::Error::Ledger(
                crate::core::Fault::Limited { .. },
            ))) => {
                self.save(&s)?;
                self.delivery_rearm().await?;
                return response("task_deferred", 429);
            }
            Err(_) => return response("delivery_claim_unavailable", 503),
        };
        let fence = s
            .ledger
            .get(&d.id)
            .map_err(|_| Error::RustError("Missing claimed task".into()))?
            .fence;
        self.save(&s)?;
        let Some(wire) = wire else {
            self.delivery_rearm().await?;
            return Response::from_json(&json!({"disposed":true}));
        };
        let (outcome, category) = fetch_wire(wire).await;
        // Never reuse the pre-fetch snapshot. Cancellation/config/lease recovery may interleave.
        let mut latest = self.load()?;
        let finish = latest.delivery_finish(&d.id, fence, outcome, category, now());
        self.save(&latest)?;
        self.delivery_rearm().await?;
        match finish {
            Ok(()) => Response::from_json(&json!({"disposed":true})),
            Err(crate::delivery::Error::Task(crate::funded_tasks::Error::Ledger(
                crate::core::Fault::Stale,
            ))) => response("stale_result", 409),
            Err(_) => response("result_unavailable", 503),
        }
    }
}
async fn fetch_wire(w: Wire) -> (Outcome, &'static str) {
    // The live alpha remains restricted to its one exact owned endpoint.
    if w.url != crate::delivery::RECEIVER_URL {
        return (Outcome::Http(400), "policy_unavailable");
    }
    let policy = crate::destinations::EgressPolicy {
        managed_workers_dev: false,
        approved_hosts: ["receiver-alpha.runlater.io".into()].into_iter().collect(),
    };
    let Ok(target) = policy.target(&w.url) else {
        return (Outcome::Http(400), "policy_unavailable");
    };
    let r = match crate::safe_egress::fetch(target, w.body, "application/json", w.headers).await {
        Ok(r) => r,
        Err(e) => return (e.outcome, e.category),
    };
    let category = if (200..300).contains(&r.status) {
        "http_success"
    } else {
        let code = serde_json::from_slice::<serde_json::Value>(&r.body)
            .ok()
            .and_then(|v| {
                v.get("code")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            });
        match code.as_deref() {
            Some("callback_forbidden") => "receiver_callback_forbidden",
            Some("callback_policy_rejected") => "receiver_policy_rejected",
            Some("synthetic_failure") => "receiver_synthetic_failure",
            Some("synthetic_retry") => "receiver_synthetic_retry",
            Some("receiver_unconfigured") => "receiver_unconfigured",
            Some("body_limit") => "receiver_body_limit",
            Some("synthetic_required") | Some("invalid_synthetic_body") => {
                "receiver_invalid_synthetic"
            }
            _ => "http_error",
        }
    };
    (Outcome::Http(r.status), category)
}
#[event(queue)]
pub async fn consume(
    batch: MessageBatch<serde_json::Value>,
    env: Env,
    _ctx: Context,
) -> Result<()> {
    if env.var("INVITATION_ENROLLMENT").is_ok() || env.var("PUBLIC_BETA_ENABLED").is_ok() {
        return crate::invitation_runtime::delivery_transport::consume(batch, env, _ctx).await;
    }
    if batch.queue() != "runlater-alpha-ready" {
        return Err(Error::RustError("Unknown alpha queue".into()));
    }
    for message in batch.messages()? {
        let d: Dispatch = match serde_json::from_value(message.body().clone()) {
            Ok(d) if crate::transport::valid_dispatch(&d) => d,
            _ => {
                message.ack();
                continue;
            }
        };
        let mut init = RequestInit::new();
        let headers = Headers::new();
        headers.set("x-project", &d.tenant)?;
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(serde_json::to_string(&d)?.into()));
        let ns = env.durable_object("IDENTITIES")?;
        let stub = ns.id_from_name(&d.tenant)?.get_stub()?;
        let req = Request::new_with_init("https://identity/deliver", &init)?;
        match stub.fetch_with_request(req).await {
            Ok(r) if matches!(r.status_code(), 200 | 400 | 403 | 404 | 409 | 429) => message.ack(),
            _ => message.retry(),
        };
    }
    Ok(())
}
