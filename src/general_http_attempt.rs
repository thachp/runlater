//! Private immutable dispatch envelope. This does not authorize network I/O or mint admission.
use crate::{
    core,
    general_http::{AdapterRequest, AdmissionPermit, State},
    identity::Error,
    security::digest,
    signed::Project,
};
use serde::Serialize;
const JS_SAFE: i64 = 9_007_199_254_740_991;
pub const FINISH_MARGIN_MS: i64 = 1000;
#[derive(Debug, Serialize)]
pub struct AttemptEnvelope {
    version: u8,
    adapter_revision: String,
    release_id: String,
    project_id: String,
    task_id: String,
    fence: u64,
    attempt_started_at_ms: i64,
    deadline_ms: i64,
    target_sha256: String,
    request: AdapterRequest,
}
fn hex_id(value: &str, prefix: &str, digits: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|v| {
        v.len() == digits
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
impl State {
    /// Caller must persist the funded claim before sending this envelope. Reconstructing it
    /// cannot extend the lease: all timing and request fields come from the stored task.
    pub fn attempt_envelope(
        &self,
        project: &Project,
        release: &str,
        project_id: &str,
        id: &str,
        permit: &AdmissionPermit,
        now: i64,
    ) -> Result<AttemptEnvelope, Error> {
        let task = project.ledger.get(id).map_err(|_| Error::Forbidden)?;
        let attempt = task.attempts.last().ok_or(Error::Forbidden)?;
        let lease = task.lease_until.ok_or(Error::Forbidden)?;
        if release.is_empty()
            || release.len() > 32
            || !release
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || !hex_id(project_id, "p_", 60)
            || !hex_id(id, "task_", 16)
            || task.status != core::Status::Running
            || task.cancel_requested
            || task.fence == 0
            || task.fence > JS_SAFE as u64
            || task.fence != attempt.fence
            || attempt.finished_ms.is_some()
            || attempt.outcome.is_some()
            || attempt.started_ms < 0
            || attempt.started_ms > JS_SAFE - core::LEASE
            || lease != attempt.started_ms + core::LEASE
            || now < attempt.started_ms
            || now >= lease - FINISH_MARGIN_MS
        {
            return Err(Error::Forbidden);
        }
        Ok(AttemptEnvelope {
            version: 1,
            adapter_revision: permit.revision().into(),
            release_id: release.into(),
            project_id: project_id.into(),
            task_id: id.into(),
            fence: task.fence,
            attempt_started_at_ms: attempt.started_ms,
            deadline_ms: lease - FINISH_MARGIN_MS,
            target_sha256: self.target(id).ok_or(Error::Forbidden)?.hash()?,
            request: self.adapter_request(project, id)?,
        })
    }
}
impl AttemptEnvelope {
    pub fn deadline_ms(&self) -> i64 {
        self.deadline_ms
    }
    pub fn canonical(&self) -> Result<String, Error> {
        serde_json::to_string(&(
            self.version,
            &self.adapter_revision,
            &self.release_id,
            &self.project_id,
            &self.task_id,
            self.fence,
            self.attempt_started_at_ms,
            self.deadline_ms,
            &self.target_sha256,
            (
                &self.request.url,
                &self.request.body,
                self.request.content_type,
                &self.request.operation_key,
            ),
        ))
        .map_err(|_| Error::Invalid)
    }
    pub fn hash(&self) -> Result<String, Error> {
        Ok(digest(self.canonical()?.as_bytes()))
    }
    pub fn receipt_key(&self) -> Result<String, Error> {
        Ok(digest(
            serde_json::to_string(&(
                &self.release_id,
                &self.project_id,
                &self.task_id,
                self.fence,
            ))
            .map_err(|_| Error::Invalid)?
            .as_bytes(),
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn node_cross_language_vector_exact_target_empty_query_and_envelope() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../egress/controller/envelope-vector.json"))
                .unwrap();
        let e = &v["envelope"];
        let request = &e["request"];
        let target =
            crate::general_http::Target::from_url(request["url"].as_str().unwrap()).unwrap();
        let x = AttemptEnvelope {
            version: 1,
            adapter_revision: e["adapter_revision"].as_str().unwrap().into(),
            release_id: e["release_id"].as_str().unwrap().into(),
            project_id: e["project_id"].as_str().unwrap().into(),
            task_id: e["task_id"].as_str().unwrap().into(),
            fence: 1,
            attempt_started_at_ms: e["attempt_started_at_ms"].as_i64().unwrap(),
            deadline_ms: e["deadline_ms"].as_i64().unwrap(),
            target_sha256: target.hash().unwrap(),
            request: AdapterRequest {
                url: target.url().into(),
                body: request["body"].as_str().unwrap().into(),
                content_type: "application/json",
                operation_key: request["operationKey"].as_str().unwrap().into(),
            },
        };
        assert_eq!(serde_json::to_value(&x).unwrap(), *e);
        assert_eq!(x.canonical().unwrap(), v["canonical"]);
        assert_eq!(x.hash().unwrap(), v["envelope_sha256"]);
        assert_eq!(x.receipt_key().unwrap(), v["receipt_key"]);
    }
}

/// Strict bounded private result. Never expose adapter detail/body to task callers.
pub fn outcome(value: &serde_json::Value) -> (core::Outcome, bool) {
    let unknown = (core::Outcome::Timeout, false);
    let Some(v) = value.as_object() else {
        return unknown;
    };
    if v.get("automatic_retry") != Some(&serde_json::Value::Bool(false))
        || !v
            .get("request_may_have_been_sent")
            .is_some_and(serde_json::Value::is_boolean)
    {
        return unknown;
    }
    if v.get("ok") == Some(&serde_json::Value::Bool(false))
        && v.len() == 4
        && v.get("error").and_then(|x| x.as_str()) == Some("rate_limited")
        && v["request_may_have_been_sent"] == false
    {
        return (core::Outcome::Http(429), true);
    }
    if v.len() != 6 || v.get("ok") != Some(&serde_json::Value::Bool(true)) {
        return unknown;
    }
    let Some(status) = v.get("http_status").and_then(|x| x.as_u64()) else {
        return unknown;
    };
    let Some(bytes) = v.get("response_bytes").and_then(|x| x.as_u64()) else {
        return unknown;
    };
    let kind = v.get("outcome").and_then(|x| x.as_str());
    if !(200..=599).contains(&status)
        || bytes > 16384
        || v["request_may_have_been_sent"] != true
        || !matches!(kind, Some("http_response" | "redirect_rejected"))
        || (kind == Some("redirect_rejected") && !(300..=399).contains(&status))
    {
        return unknown;
    }
    (core::Outcome::Http(status as u16), false)
}

#[cfg(test)]
mod result_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn strict_private_results_never_echo_body_or_accept_malformed_success() {
        let success=json!({"ok":true,"http_status":204,"outcome":"http_response","response_bytes":0,"request_may_have_been_sent":true,"automatic_retry":false});
        assert!(matches!(outcome(&success),(core::Outcome::Http(204),false)));
        let mut bad=success.clone(); bad["body"]=json!("private"); assert!(matches!(outcome(&bad),(core::Outcome::Timeout,false)));
        let mut bad=success.clone(); bad["automatic_retry"]=json!(true); assert!(matches!(outcome(&bad),(core::Outcome::Timeout,false)));
        let mut redirect=success; redirect["http_status"]=json!(302);redirect["outcome"]=json!("redirect_rejected");assert!(matches!(outcome(&redirect),(core::Outcome::Http(302),false)));
        let rate=json!({"ok":false,"error":"rate_limited","request_may_have_been_sent":false,"automatic_retry":false});assert!(matches!(outcome(&rate),(core::Outcome::Http(429),true)));
        let mut uncertain=rate;uncertain["request_may_have_been_sent"]=json!(true);assert!(matches!(outcome(&uncertain),(core::Outcome::Timeout,false)));
    }
}
