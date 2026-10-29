//! Default-off private service adapter. Never performs customer-origin Fetch.
use super::*;
use crate::general_http::AdmissionPermit;
use futures_util::{
    future::{select, Either},
    pin_mut, StreamExt,
};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Readiness {
    ready: bool,
    protocol: u8,
    revision: String,
    capacity_remaining: u32,
}
fn unavailable() -> Result<Response> {
    json_response(&crate::general_http::unavailable(), 503)
}
async fn private_call(
    env: &Env,
    path: &str,
    body: Option<String>,
    timeout_ms: u64,
) -> Result<Value> {
    let service = env.service("GENERAL_HTTPS_EGRESS")?;
    let controller = AbortController::default();
    let signal = controller.signal();
    let action = async {
        let init = web_sys::RequestInit::new();
        init.set_method(if body.is_some() { "POST" } else { "GET" });
        init.set_redirect(web_sys::RequestRedirect::Manual);
        init.set_signal(Some(&signal));
        if let Some(body) = body {
            init.set_body(&worker::wasm_bindgen::JsValue::from_str(&body));
        }
        let request = web_sys::Request::new_with_str_and_init(
            &format!("https://egress.internal{path}"),
            &init,
        )?;
        request.headers().set("Content-Type", "application/json")?;
        let mut response = service.fetch_request(Request::from(request)).await?;
        if response.status_code() != 200
            || response
                .headers()
                .entries()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                > 2048
        {
            return Err(Error::RustError("Private adapter unavailable".into()));
        }
        let mut bytes = Vec::new();
        let mut chunks = 0;
        let mut stream = response.stream()?;
        while let Some(part) = stream.next().await {
            let part = part?;
            chunks += 1;
            if chunks > 32 || bytes.len() + part.len() > 1024 {
                return Err(Error::RustError("Private adapter response rejected".into()));
            }
            bytes.extend(part);
        }
        serde_json::from_slice(&bytes).map_err(Into::into)
    };
    let deadline = Delay::from(std::time::Duration::from_millis(timeout_ms));
    pin_mut!(action, deadline);
    let result = match select(action, deadline).await {
        Either::Left((v, _)) => v,
        Either::Right(_) => Err(Error::RustError("Private adapter deadline".into())),
    };
    controller.abort();
    result
}
pub(super) async fn admission(env: &Env) -> Option<AdmissionPermit> {
    if env.var("GENERAL_HTTPS_ENABLED").ok()?.to_string() != "operator-approved" {
        return None;
    }
    let expected = env
        .var("GENERAL_HTTPS_EGRESS_REVIEW_REVISION")
        .ok()?
        .to_string();
    let permit = AdmissionPermit::from_reviewed_revision(&expected).ok()?;
    let value = private_call(env, "/ready", None, 1000).await.ok()?;
    if serde_json::to_vec(&value).ok()?.len() > 512 {
        return None;
    }
    let ready: Readiness = serde_json::from_value(value).ok()?;
    if !ready.ready
        || ready.protocol != 1
        || ready.revision != expected
        || ready.capacity_remaining == 0
        || ready.capacity_remaining > 10000
    {
        return None;
    }
    Some(permit)
}
impl InvitationProject {
    pub(super) async fn schedule_general(&self, input: Signed, raw: Vec<u8>) -> Result<Response> {
        let Some(permit) = admission(&self.env).await else {
            return unavailable();
        };
        // Reload after readiness await; never overwrite concurrent project updates.
        let mut s: Enrollment =
            load(&self.state)?.ok_or_else(|| Error::RustError("Missing project".into()))?;
        let trust = public_runtime::trial_trust(&self.env)?;
        let proof = match input.proof(trust.as_ref()) {
            Ok(v) => v,
            Err(e) => return task_error(e.into()),
        };
        let result = s.schedule_http(&input.envelope, proof, &raw, Some(&permit), now());
        save(&self.state, &s)?;
        if result.is_ok() {
            self.pump().await?;
        }
        match result {
            Ok(v) => task_result(v),
            Err(e) => task_error(e),
        }
    }
    pub(super) async fn deliver_general(
        &self,
        project: &str,
        d: crate::core::Dispatch,
    ) -> Result<Response> {
        let Some(permit) = admission(&self.env).await else {
            return unavailable();
        };
        let mut s: Enrollment =
            load(&self.state)?.ok_or_else(|| Error::RustError("Missing project".into()))?;
        if s.identity_policy().is_err() {
            return rejected(inv::Error::Forbidden);
        }
        let claimed = match s.project.funded_claim(&d, now()) {
            Ok(v) => v,
            Err(e) => {
                save(&self.state, &s)?;
                return task_error(e);
            }
        };
        let Some(task) = claimed else {
            save(&self.state, &s)?;
            self.rearm().await?;
            return json_response(&json!({"disposed":true}), 200);
        };
        let release = public_runtime::profile(&self.env)?.release_id;
        let envelope = s
            .http
            .attempt_envelope(&s.project, &release, project, &d.id, &permit, now())
            .map_err(|_| Error::RustError("Private attempt rejected".into()))?;
        save(&self.state, &s)?; // Claim and credit spend durable before any private dispatch.
        let remaining = (envelope.deadline_ms() - now()).max(0) as u64;
        let result = if remaining == 0 {
            None
        } else {
            private_call(
                &self.env,
                "/dispatch",
                Some(serde_json::to_string(&envelope)?),
                remaining,
            )
            .await
            .ok()
        };
        let (outcome, rate_limited) = result
            .as_ref()
            .map(crate::general_http_attempt::outcome)
            .unwrap_or((crate::core::Outcome::Timeout, false));
        let mut latest: Enrollment =
            load(&self.state)?.ok_or_else(|| Error::RustError("Missing project".into()))?;
        let result = latest
            .project
            .funded_finish(&d.id, task.fence, outcome, now());
        if result.is_ok() && rate_limited {
            if let Some(t) = latest.project.ledger.tasks.get_mut(&d.id) {
                if t.status == crate::core::Status::RetryWait {
                    t.due_ms = t.due_ms.max(now() + 10_000);
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
            Err(e) => task_error(e),
        }
    }
}
