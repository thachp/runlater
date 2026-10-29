//! Invitation-mode network adapter. No defaults, provider provisioning or alpha receiver fallback.
use super::*;
use crate::{
    callback::{Keyring, Material},
    core::Dispatch,
    destinations::EgressPolicy,
};
use std::collections::BTreeMap;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    keys: Keyring,
    egress: EgressPolicy,
}
pub(super) struct Configuration {
    pub public_beta: bool,
    self_host: Option<String>,
    pub keys: Keyring,
    pub egress: EgressPolicy,
    material: BTreeMap<String, Vec<u8>>,
}
impl Material for Configuration {
    fn key(&self, id: &str) -> Option<&[u8]> {
        self.material.get(id).map(Vec::as_slice)
    }
}
fn queue_binding(env: &Env) -> &'static str {
    if public_runtime::mode(env) {
        "BETA_READY"
    } else {
        "INVITATION_READY"
    }
}
impl Configuration {
    fn target(
        &self,
        raw: &str,
    ) -> std::result::Result<crate::destinations::Target, crate::destinations::Error> {
        let target = self.egress.target(raw)?;
        let host = url::Url::parse(raw)
            .map_err(|_| crate::destinations::Error::Invalid)?
            .host_str()
            .unwrap_or_default()
            .to_owned();
        if self.self_host.as_deref() == Some(&host)
            || host == "runlater.io"
            || host.ends_with(".runlater.io")
        {
            return Err(crate::destinations::Error::Forbidden);
        }
        Ok(target)
    }
}
fn configuration(env: &Env, project: &str) -> Result<Option<Configuration>> {
    if public_runtime::mode(env) {
        if !public_runtime::configured(env) {
            return Ok(None);
        }
        env.queue("BETA_READY")?;
        if env.var("BETA_READY_QUEUE")?.to_string() != "runlater-public-ready" {
            return Err(Error::RustError("Invalid beta queue".into()));
        }
        let p = public_runtime::profile(env)?;
        let material = public_runtime::master(env)?
            .tenant(&p.release_id, project)
            .map_err(|_| Error::RustError("Invalid beta material".into()))?;
        let keys = Keyring::new(
            project,
            &format!("public_beta_{}", p.release_id),
            "beta_v1",
            p.opens_at_ms / 1000,
            p.callback_end_sec,
            &material,
        )
        .map_err(|_| Error::RustError("Invalid beta signing policy".into()))?;
        let mut map = BTreeMap::new();
        map.insert(
            "beta_v1".into(),
            material
                .key("beta_v1")
                .ok_or_else(|| Error::RustError("Missing beta material".into()))?
                .to_vec(),
        );
        return Ok(Some(Configuration {
            public_beta: true,
            self_host: Some(p.self_host),
            keys,
            egress: EgressPolicy {
                managed_workers_dev: true,
                approved_hosts: Default::default(),
            },
            material: map,
        }));
    }

    if env
        .var("INVITATION_DELIVERY_ENABLED")
        .map(|v| v.to_string())
        .unwrap_or_default()
        != "operator-approved"
    {
        return Ok(None);
    }
    env.queue("INVITATION_READY")?;
    if env.var("INVITATION_READY_QUEUE")?.to_string() != "runlater-invitation-ready" {
        return Err(Error::RustError("Invalid invitation queue".into()));
    }
    let raw = env.var("INVITATION_DELIVERY_POLICIES")?.to_string();
    if raw.len() > 16384 {
        return Err(Error::RustError("Invitation policies too large".into()));
    }
    let list: Vec<Config> = serde_json::from_str(&raw)?;
    if list.is_empty() || list.len() > 8 {
        return Err(Error::RustError("Invalid invitation policy count".into()));
    }
    let mut ids = std::collections::BTreeSet::new();
    for p in &list {
        p.keys
            .validate()
            .map_err(|_| Error::RustError("Invalid callback policy".into()))?;
        if !ids.insert(p.keys.tenant()) {
            return Err(Error::RustError("Duplicate callback tenant".into()));
        }
    }
    let Some(p) = list.into_iter().find(|p| p.keys.tenant() == project) else {
        return Ok(None);
    };
    let raw = env.secret("INVITATION_CALLBACK_KEYS")?.to_string();
    if raw.len() > 4096 {
        return Err(Error::RustError("Callback material too large".into()));
    }
    let entries: BTreeMap<String, String> = serde_json::from_str(&raw)?;
    if entries.is_empty() || entries.len() > 16 {
        return Err(Error::RustError("Invalid material count".into()));
    }
    let mut material = BTreeMap::new();
    for (id, v) in entries {
        if !crate::security::tenant_valid(&id)
            || v.len() != 64
            || !v
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::RustError("Invalid callback material".into()));
        }
        let bytes =
            hex::decode(v).map_err(|_| Error::RustError("Invalid callback material".into()))?;
        if id.starts_with("fixture") || bytes.iter().all(|b| *b == bytes[0]) {
            return Err(Error::RustError(
                "Nonproduction callback material forbidden".into(),
            ));
        }
        material.insert(id, bytes);
    }
    Ok(Some(Configuration {
        public_beta: false,
        self_host: None,
        keys: p.keys,
        egress: p.egress,
        material,
    }))
}
fn fail(e: crate::invitation_delivery::Error) -> Result<Response> {
    match e {
        crate::invitation_delivery::Error::ReceiverRequired => json_response(
            &json!({"error":{"code":"receiver_required"},"task_accepted":false,"receiver_ready":false}),
            409,
        ),
        crate::invitation_delivery::Error::BetaCapacity => json_response(
            &json!({"error":{"code":"beta_lifetime_task_capacity"},"task_accepted":false,"retryable":false,"payments":false}),
            429,
        ),
        crate::invitation_delivery::Error::Auth(e) => task_error(e.into()),
        crate::invitation_delivery::Error::Task(e) => task_error(e),
        crate::invitation_delivery::Error::Destination(e) => {
            let status = match e {
                crate::destinations::Error::Invalid => 400,
                crate::destinations::Error::Forbidden => 403,
                crate::destinations::Error::NotFound => 404,
                crate::destinations::Error::Conflict => 409,
                crate::destinations::Error::Limited => 429,
                crate::destinations::Error::Expired => 410,
                _ => 503,
            };
            json_response(
                &json!({"error":"destination_unavailable","task_accepted":false}),
                status,
            )
        }
        _ => json_response(
            &json!({"error":"delivery_not_ready","task_accepted":false}),
            503,
        ),
    }
}
impl InvitationProject {
    pub(super) async fn signed_delivery(
        &self,
        mut s: Enrollment,
        input: Signed,
        raw: Vec<u8>,
    ) -> Result<Response> {
        let project = input.envelope.project_id.clone();
        let trust = if input.trial.is_some() {
            public_runtime::trial_trust(&self.env)?
        } else if input.delegation.is_some() {
            public_runtime::mcp_trust(&self.env)?
        } else {
            None
        };
        let proof = match input.proof(trust.as_ref()) {
            Ok(v) => v,
            Err(e) => return task_error(e.into()),
        };
        if (input.delegation.is_some() || input.trial.is_some())
            && crate::mcp_delegation::task_permission(&input.envelope).is_err()
        {
            return rejected(inv::Error::Forbidden);
        };
        let configured = configuration(&self.env, &project).ok().flatten();
        if crate::invitation_delivery::destination_route(
            &input.envelope.method,
            &input.envelope.path,
        ) {
            let Some(c) = configured else {
                return fail(crate::invitation_delivery::Error::Unavailable);
            };
            if input.envelope.path.ends_with("/verify") {
                let challenge = match s.destination_begin(
                    &input.envelope,
                    &input.signature,
                    &raw,
                    &c.egress,
                    now(),
                ) {
                    Ok(v) => v,
                    Err(e) => return fail(e),
                };
                save(&self.state, &s)?;
                let target = match c.target(&challenge.url) {
                    Ok(t) => t,
                    Err(e) => return fail(e.into()),
                };
                let fetched = crate::safe_egress::fetch(
                    target,
                    challenge.body.clone(),
                    "text/plain; charset=utf-8",
                    BTreeMap::new(),
                )
                .await;
                let mut latest: Enrollment = load(&self.state)?
                    .ok_or_else(|| Error::RustError("Missing enrolled project".into()))?;
                let response = fetched
                    .as_ref()
                    .map(|r| (r.status, r.body.as_slice()))
                    .map_err(|_| ());
                let result = latest.destination_complete(
                    &project,
                    &input.envelope.public_key,
                    &challenge,
                    response,
                    &c.egress,
                    now(),
                );
                save(&self.state, &latest)?;
                return match result {
                    Ok(v) => json_response(&v, 200),
                    Err(e) => fail(e),
                };
            }
            if c.public_beta
                && serde_json::from_slice::<Value>(&raw)
                    .ok()
                    .and_then(|v| v.get("url").and_then(Value::as_str).map(str::to_owned))
                    .is_some_and(|url| c.target(&url).is_err())
            {
                return fail(crate::destinations::Error::Forbidden.into());
            }
            let result = s.destination_command(
                &input.envelope,
                &input.signature,
                &raw,
                &c.egress,
                &nonce()?,
                now(),
            );
            save(&self.state, &s)?;
            if result.is_ok() {
                self.pump().await?;
            }
            return match result {
                Ok(v) => json_response(&v, 200),
                Err(e) => fail(e),
            };
        }
        self.state.storage().set_alarm(1000).await?;
        // The watchdog await may interleave; reload before applying the signed mutation.
        s = load(&self.state)?
            .ok_or_else(|| Error::RustError("Missing enrolled project".into()))?;
        let result = if let Some(c) = configured {
            // Persist monotonic callback revocations/material identities independently of admission rollback.
            if s.outbound.sync_keys(&project, &c.keys, &c).is_err() {
                let replay =
                    s.signed_task_command_with_proof(&input.envelope, proof, &raw, false, now());
                save(&self.state, &s)?;
                self.rearm().await?;
                return match replay {
                    Ok(v) => task_result(v),
                    Err(e) => task_error(e),
                };
            }
            save(&self.state, &s)?;
            if c.public_beta {
                s.registered_beta_task_command_with_proof(
                    &input.envelope,
                    proof,
                    &raw,
                    &c.egress,
                    &c.keys,
                    &c,
                    now(),
                )
            } else {
                s.registered_task_command(
                    &input.envelope,
                    &input.signature,
                    &raw,
                    &c.egress,
                    &c.keys,
                    &c,
                    now(),
                )
            }
        } else {
            s.signed_task_command_with_proof(&input.envelope, proof, &raw, false, now())
                .map_err(Into::into)
        };
        save(&self.state, &s)?;
        if result.is_ok() {
            point(&self.env, "after_task_commit").await?;
        }
        self.pump().await?;
        match result {
            Ok(v) => task_result(v),
            Err(e) => fail(e),
        }
    }
    pub(super) async fn rearm(&self) -> Result<()> {
        let Some(mut s) = load::<Enrollment>(&self.state)? else {
            return Ok(());
        };
        let enabled = s
            .project_id()
            .and_then(|p| configuration(&self.env, p).ok().flatten())
            .is_some_and(|c| s.outbound.sync_keys(c.keys.tenant(), &c.keys, &c).is_ok());
        let wake = if enabled {
            s.project.delivery_next_wake(now())
        } else {
            s.project
                .ledger
                .tasks
                .values()
                .filter_map(|t| match t.status {
                    crate::core::Status::Running => t.lease_until,
                    _ if t.status.terminal() => t
                        .terminal_ms
                        .map(|at| at.saturating_add(crate::core::RETENTION)),
                    _ => Some(
                        t.initial_due_ms
                            .saturating_add(crate::core::DAY)
                            .saturating_add(1),
                    ),
                })
                .chain(
                    s.project
                        .ledger
                        .audit
                        .iter()
                        .map(|e| e.at_ms.saturating_add(crate::core::RETENTION)),
                )
                .min()
        };
        if let Some(at) = wake {
            self.state.storage().set_alarm((at - now()).max(1)).await?
        } else {
            self.state.storage().delete_alarm().await?
        }
        Ok(())
    }
    pub(super) async fn pump(&self) -> Result<()> {
        self.state.storage().set_alarm(1000).await?;
        let Some(mut s) = load::<Enrollment>(&self.state)? else {
            return self.state.storage().delete_alarm().await.map(|_| ());
        };
        s.project
            .funded_maintenance(now())
            .map_err(|_| Error::RustError("Funding maintenance rejected".into()))?;
        let Some(project) = s.project_id().map(str::to_owned) else {
            save(&self.state, &s)?;
            return self.rearm().await;
        };
        let Some(c) = configuration(&self.env, &project).ok().flatten() else {
            save(&self.state, &s)?;
            return self.rearm().await;
        };
        if s.outbound.sync_keys(&project, &c.keys, &c).is_err() {
            save(&self.state, &s)?;
            return self.rearm().await;
        }
        let refs = s
            .registered_outbox(&project, now())
            .map_err(|_| Error::RustError("Outbox rejected".into()))?;
        save(&self.state, &s)?;
        if crate::publication::publish_batch(refs, |d| async move {
            self.env.queue(queue_binding(&self.env))?.send(d).await
        })
        .await
        .is_err()
        {
            self.state.storage().set_alarm(1000).await?;
            return Err(Error::RustError("Invitation publication uncertain".into()));
        }
        self.rearm().await
    }
    pub(super) async fn deliver(&self, project: &str, d: Dispatch) -> Result<Response> {
        if d.tenant != project || !crate::transport::valid_dispatch(&d) {
            return json_response(&json!({"error":"invalid_dispatch"}), 400);
        }
        self.state.storage().set_alarm(1000).await?;
        let Some(c) = configuration(&self.env, project).ok().flatten() else {
            return json_response(&json!({"error":"delivery_not_ready"}), 503);
        };
        let Some(mut s) = load::<Enrollment>(&self.state)? else {
            return json_response(&json!({"error":"task_not_found"}), 404);
        };
        s.outbound
            .sync_keys(project, &c.keys, &c)
            .map_err(|_| Error::RustError("Callback policy rejected".into()))?;
        save(&self.state, &s)?;
        let wire = match s.registered_claim(&d, &c.egress, now(), &c) {
            Ok(w) => w,
            Err(crate::invitation_delivery::Error::Task(crate::funded_tasks::Error::Ledger(
                crate::core::Fault::NotFound,
            ))) => return json_response(&json!({"error":"task_not_found"}), 404),
            Err(crate::invitation_delivery::Error::Task(crate::funded_tasks::Error::Ledger(
                crate::core::Fault::Limited { .. },
            ))) => {
                save(&self.state, &s)?;
                self.rearm().await?;
                return json_response(&json!({"error":"deferred"}), 429);
            }
            Err(e) => return fail(e),
        };
        let fence = s
            .project
            .ledger
            .get(&d.id)
            .map_err(|_| Error::RustError("Missing task".into()))?
            .fence;
        save(&self.state, &s)?;
        let Some(w) = wire else {
            self.rearm().await?;
            return json_response(&json!({"disposed":true}), 200);
        };
        let (outcome, category) = match c.target(&w.url) {
            Ok(target) => {
                match crate::safe_egress::fetch(target, w.body, "application/json", w.headers).await
                {
                    Ok(r) => (
                        crate::core::Outcome::Http(r.status),
                        if (200..300).contains(&r.status) {
                            "http_success"
                        } else {
                            "http_error"
                        },
                    ),
                    Err(e) => (e.outcome, e.category),
                }
            }
            Err(_) => (crate::core::Outcome::Http(400), "policy_unavailable"),
        };
        let mut latest: Enrollment =
            load(&self.state)?.ok_or_else(|| Error::RustError("Missing task snapshot".into()))?;
        let result = latest.project.funded_finish(&d.id, fence, outcome, now());
        if result.is_ok() {
            if let Some(rows) = latest.project.delivery.attempts.get_mut(&d.id) {
                if let Some(row) = rows.iter_mut().find(|r| r.fence == fence) {
                    row.category = category.into();
                }
            }
        }
        save(&self.state, &latest)?;
        self.rearm().await?;
        match result {
            Ok(_) => json_response(&json!({"disposed":true}), 200),
            Err(crate::funded_tasks::Error::Ledger(crate::core::Fault::Stale)) => {
                json_response(&json!({"error":"stale_result"}), 409)
            }
            Err(_) => json_response(&json!({"error":"result_unavailable"}), 503),
        }
    }
}
#[cfg_attr(feature = "invitation-tests", event(queue))]
pub async fn consume(batch: MessageBatch<Value>, env: Env, _ctx: Context) -> Result<()> {
    if batch.queue()
        != (if public_runtime::mode(&env) {
            "runlater-public-ready"
        } else {
            "runlater-invitation-ready"
        })
        || !guard(&env)
    {
        return Err(Error::RustError("Invalid invitation queue".into()));
    }
    for message in batch.messages()? {
        let d: Dispatch = match serde_json::from_value(message.body().clone()) {
            Ok(d) if crate::transport::valid_dispatch(&d) => d,
            _ => {
                message.ack();
                continue;
            }
        };
        let mut gate = internal(
            &env,
            "ADMISSION",
            if public_runtime::mode(&env) {
                "public_beta_registry_v1"
            } else {
                "admission_registry_v1"
            },
            "/signed-route",
            &json!({"project_id":d.tenant}),
        )
        .await?;
        if gate.status_code() == 403 {
            message.ack();
            continue;
        }
        if gate.status_code() != 200 {
            message.retry();
            continue;
        }
        let ticket: Ticket = gate.json().await?;
        if ticket.revoked {
            let r = internal(
                &env,
                "PROJECTS",
                &d.tenant,
                "/revoke",
                &serde_json::to_value(&ticket)?,
            )
            .await?;
            if r.status_code() != 200 {
                message.retry();
                continue;
            }
        }
        match internal(
            &env,
            "PROJECTS",
            &d.tenant,
            "/deliver",
            &serde_json::to_value(&d)?,
        )
        .await
        {
            Ok(r) if matches!(r.status_code(), 200 | 400 | 403 | 404 | 409 | 429) => message.ack(),
            _ => message.retry(),
        };
    }
    Ok(())
}
