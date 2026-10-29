//! Public-beta production adapter. No issuer token, payment or implicit credential activation.
use super::*;
use crate::public_beta::{Grant, Master, Profile, State as Global};
fn revocations(env: &Env) -> Result<Vec<String>> {
    let raw = env
        .var("BETA_REVOKED_PROJECTS")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "[]".into());
    if raw.len() > 1024 {
        return Err(Error::RustError("Invalid beta revocations".into()));
    }
    let p: Vec<String> = serde_json::from_str(&raw)?;
    if p.len() > 10 || p.iter().any(|p| !crate::security::tenant_valid(p)) {
        return Err(Error::RustError("Invalid beta revocations".into()));
    }
    Ok(p)
}
const REGISTRY: &str = "public_beta_registry_v1";
pub(super) fn mode(env: &Env) -> bool {
    env.var("PUBLIC_BETA_ENABLED").is_ok()
}
pub(super) fn profile(env: &Env) -> Result<Profile> {
    let raw = env.var("PUBLIC_BETA_PROFILE")?.to_string();
    if raw.len() > 2048 {
        return Err(Error::RustError("Invalid beta profile".into()));
    }
    let p: Profile = serde_json::from_str(&raw)?;
    p.validate()
        .map_err(|_| Error::RustError("Invalid beta profile".into()))?;
    Ok(p)
}
pub(super) fn mcp_trust(env: &Env) -> Result<Option<(String, String)>> {
    if !mode(env) {
        return Ok(None);
    }
    let Ok(value) = env.var("MCP_DELEGATION_GATEWAY_PUBLIC_KEY") else {
        return Ok(None);
    };
    let key = value.to_string();
    if !crate::identity::key_valid(&key) {
        return Err(Error::RustError("Invalid MCP delegation trust".into()));
    }
    Ok(Some((key, profile(env)?.release_id)))
}
pub(super) fn trial_trust(env: &Env) -> Result<Option<(String, String)>> {
    if env
        .var("MCP_ANONYMOUS_TRIAL_ENABLED")
        .map(|v| v.to_string())
        .unwrap_or_default()
        != "operator-approved"
    {
        return Ok(None);
    }
    mcp_trust(env)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrialRequest {
    envelope: crate::signed::Envelope,
    descriptor: crate::anonymous_trial::Descriptor,
    secret: String,
    signature: String,
    body_hex: String,
}
pub(super) fn master(env: &Env) -> Result<Master> {
    Master::from_hex(&env.secret("BETA_CALLBACK_MASTER")?.to_string())
        .map_err(|_| Error::RustError("Invalid beta master".into()))
}
pub(super) fn configured(env: &Env) -> bool {
    env.var("PUBLIC_BETA_ENABLED")
        .map(|v| v.to_string())
        .unwrap_or_default()
        == "operator-approved"
        && revocations(env).is_ok()
        && env.queue("BETA_READY").is_ok()
        && env
            .var("BETA_READY_QUEUE")
            .map(|v| v.to_string() == "runlater-public-ready")
            .unwrap_or(false)
        && profile(env).is_ok()
        && master(env).is_ok()
        && env.durable_object("ADMISSION").is_ok()
        && env.durable_object("PROJECTS").is_ok()
        && env.rate_limiter("BETA_IP_RATE").is_ok()
        && env.rate_limiter("BETA_REG_IP_RATE").is_ok()
        && js_sys::Reflect::own_keys(env.as_ref())
            .map(|keys| {
                !keys.iter().filter_map(|k| k.as_string()).any(|k| {
                    crate::identity::forbidden_binding(&k)
                        || k.starts_with("ALPHA_")
                        || k.starts_with("INVITATION_")
                })
            })
            .unwrap_or(false)
}
fn err(e: inv::Error) -> Result<Response> {
    let (status, code) = match e {
        inv::Error::Invalid => (400, "beta_invalid_request"),
        inv::Error::Forbidden => (403, "beta_forbidden"),
        inv::Error::Expired => (410, "beta_expired"),
        inv::Error::Limited => (429, "beta_limit"),
        inv::Error::Conflict => (409, "beta_conflict"),
        inv::Error::Clock => (503, "beta_clock_unavailable"),
        inv::Error::Closed => (503, "beta_registration_closed"),
    };
    let mut r = json_response(
        &json!({"error":{"code":code},"task_accepted":false,"payments":false}),
        status,
    )?;
    if status == 429 {
        r.headers_mut().set("Retry-After", "60")?
    }
    Ok(r)
}
async fn ip_gate(req: &Request, env: &Env) -> Result<bool> {
    let raw = req.headers().get("CF-Connecting-IP")?.unwrap_or_default();
    let p = profile(env)?;
    let m = master(env)?;
    let key = m
        .ip_bucket(&p.release_id, &raw, now())
        .map_err(|_| Error::RustError("Trusted client IP required".into()))?;
    let binding = if req.path().starts_with("/v1/registration/") {
        "BETA_REG_IP_RATE"
    } else {
        "BETA_IP_RATE"
    };
    Ok(env.rate_limiter(binding)?.limit(key).await?.success)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Complete {
    challenge_id: String,
    signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    grant: Grant,
    challenge: inv::Challenge,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Install {
    grant: Grant,
    challenge: inv::Challenge,
    signature: String,
}
async fn global(env: &Env, path: &str, v: &Value) -> Result<Response> {
    internal(env, "ADMISSION", REGISTRY, path, v).await
}
pub(super) async fn front(mut req: Request, env: Env) -> Result<Response> {
    if !ip_gate(&req, &env).await.unwrap_or(false) {
        return err(inv::Error::Limited);
    }
    let path = req.path();
    if req.method() == Method::Get && path == "/health" {
        return json_response(
            &json!({"mode":"public_free_beta","configured":true,"receiver":"workers.dev_only","payments":false,"version_id":env.object_var::<Value>("RELEASE_VERSION").ok().and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_owned))}),
            200,
        );
    }
    if req.method() == Method::Get && path == "/v1/beta" {
        return global(&env, "/public/view", &json!({})).await;
    }
    if path.starts_with("/v1/mcp/trials/")
        || req.headers().get("RunLater-Trial-Bootstrap")?.is_some()
        || req.headers().get("RunLater-Trial-Capability")?.is_some()
        || req.headers().get("RunLater-Trial-Revocation")?.is_some()
    {
        return trial_front(req, &env).await;
    }
    if crate::funded_tasks::route(req.method().as_ref(), &path).is_some()
        || crate::invitation_delivery::destination_route(req.method().as_ref(), &path)
        || (req.method() == Method::Get && matches!(path.as_str(), "/v1/identity/me" | "/v1/queue"))
        || (req.method() == Method::Post
            && (path == "/v1/callback-key"
                || path == crate::mcp_delegation::REVOKE_PATH
                || path == crate::mcp_delegation::VALIDATE_PATH))
    {
        return signed(req, &env).await;
    }
    if req.method() != Method::Post
        || !matches!(
            path.as_str(),
            "/v1/registration/challenge" | "/v1/registration/complete" | "/v1/registration/recover"
        )
    {
        return json_response(&json!({"error":{"code":"not_found"}}), 404);
    }
    if req.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return json_response(&json!({"error":{"code":"json_required"}}), 415);
    }
    let Some(v) = read_body(&mut req).await? else {
        return err(inv::Error::Invalid);
    };
    if path.ends_with("/challenge") {
        let Ok(v) = serde_json::from_value::<Start>(v) else {
            return err(inv::Error::Invalid);
        };
        if !crate::identity::key_valid(&v.public_key) {
            return err(inv::Error::Invalid);
        }
        return global(
            &env,
            "/public/challenge",
            &json!({"public_key":v.public_key,"nonce":nonce()?}),
        )
        .await;
    }
    if path.ends_with("/recover") {
        let Ok(r) = serde_json::from_value::<Recovery>(v.clone()) else {
            return err(inv::Error::Invalid);
        };
        let mut gate = global(&env, "/public/recovery-route", &v).await?;
        if gate.status_code() != 200 {
            return Ok(gate);
        }
        let ticket: Ticket = gate.json().await?;
        return internal(
            &env,
            "PROJECTS",
            &r.project_id,
            "/recover",
            &json!({"ticket":ticket,"recovery":v}),
        )
        .await;
    }
    let Ok(v) = serde_json::from_value::<Complete>(v) else {
        return err(inv::Error::Invalid);
    };
    if !token(&v.challenge_id)
        || v.signature.len() != 128
        || !v
            .signature
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return err(inv::Error::Invalid);
    }
    let mut result = global(
        &env,
        "/public/complete",
        &json!({"challenge_id":v.challenge_id,"signature":v.signature}),
    )
    .await?;
    if result.status_code() != 200 {
        return Ok(result);
    }
    let proof: Proof = result.json().await?;
    internal(
        &env,
        "PROJECTS",
        &proof.grant.ticket.project_id,
        "/public/enroll",
        &json!({"grant":proof.grant,"challenge":proof.challenge,"signature":v.signature}),
    )
    .await
}
async fn signed(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Get
        && req.headers().get("Content-Type")?.as_deref() != Some("application/json")
    {
        return json_response(&json!({"error":{"code":"json_required"}}), 415);
    }
    let Some(raw) = read_raw(&mut req).await? else {
        return err(inv::Error::Invalid);
    };
    if raw.len() > 2048 {
        return err(inv::Error::Invalid);
    }
    let h = req.headers();
    let (Some(issued), Some(expires)) = (
        h.get("RunLater-Issued-At")?.and_then(|v| decimal(&v)),
        h.get("RunLater-Expires-At")?.and_then(|v| decimal(&v)),
    ) else {
        return err(inv::Error::Invalid);
    };
    let e = crate::signed::Envelope {
        version: 1,
        origin: crate::identity::ORIGIN.into(),
        project_id: h.get("RunLater-Project-Id")?.unwrap_or_default(),
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
    let signature = h.get("RunLater-Request-Signature")?.unwrap_or_default();
    let delegation = match h.get("RunLater-MCP-Delegation")? {
        None => None,
        Some(header) => {
            if mcp_trust(env)?.is_none() {
                return err(inv::Error::Forbidden);
            }
            match crate::mcp_delegation::Certificate::from_header(&header) {
                Ok(c) => Some(c),
                Err(_) => return err(inv::Error::Invalid),
            }
        }
    };
    if e.path == crate::mcp_delegation::REVOKE_PATH {
        if delegation.is_some() || raw != b"{}" {
            return err(inv::Error::Forbidden);
        }
        return global(
            env,
            "/public/mcp-revoke",
            &json!({"envelope":e,"signature":signature}),
        )
        .await;
    }
    let validation = e.path == crate::mcp_delegation::VALIDATE_PATH;
    if validation && (delegation.is_none() || raw != b"{}") {
        return err(inv::Error::Forbidden);
    }
    let mut gate = global(
        env,
        if validation {
            "/public/mcp-validate"
        } else {
            "/public/client-route"
        },
        &json!({"envelope":e,"signature":signature,"delegation":delegation}),
    )
    .await?;
    if gate.status_code() != 200 {
        return Ok(gate);
    }
    let ticket: Ticket = gate.json().await?;
    let input = Signed {
        ticket,
        envelope: e,
        signature,
        body_hex: hex::encode(raw),
        delegation,
        trial: None,
        trial_capability: None,
    };
    internal(
        env,
        "PROJECTS",
        &input.envelope.project_id,
        if validation {
            "/public/mcp-validate"
        } else {
            "/signed"
        },
        &serde_json::to_value(&input)?,
    )
    .await
}
async fn trial_front(mut req: Request, env: &Env) -> Result<Response> {
    use crate::anonymous_trial::{PROVISION, REVOKE, STATUS, VALIDATE};
    if trial_trust(env)?.is_none()
        || req.url()?.query().is_some()
        || req.headers().get("RunLater-Public-Key")?.is_some()
        || req.headers().get("RunLater-MCP-Delegation")?.is_some()
    {
        return err(inv::Error::Forbidden);
    }
    if req.method() != Method::Get
        && req.headers().get("Content-Type")?.as_deref() != Some("application/json")
    {
        return err(inv::Error::Invalid);
    }
    let Some(raw) = read_raw(&mut req).await? else {
        return err(inv::Error::Invalid);
    };
    if raw.len() > 2048 {
        return err(inv::Error::Invalid);
    }
    let h = req.headers();
    let descriptor = match crate::anonymous_trial::Descriptor::from_header(
        &h.get("RunLater-Trial-Bootstrap")?.unwrap_or_default(),
    ) {
        Ok(v) => v,
        Err(_) => return err(inv::Error::Invalid),
    };
    let revoke = req.path() == REVOKE;
    if h.get(if revoke {
        "RunLater-Trial-Capability"
    } else {
        "RunLater-Trial-Revocation"
    })?
    .is_some()
    {
        return err(inv::Error::Forbidden);
    }
    let (Some(issued), Some(expires)) = (
        h.get("RunLater-Issued-At")?.and_then(|v| decimal(&v)),
        h.get("RunLater-Expires-At")?.and_then(|v| decimal(&v)),
    ) else {
        return err(inv::Error::Invalid);
    };
    let input = TrialRequest {
        envelope: crate::signed::Envelope {
            version: 1,
            origin: crate::identity::ORIGIN.into(),
            project_id: h.get("RunLater-Project-Id")?.unwrap_or_default(),
            public_key: String::new(),
            method: req.method().to_string(),
            path: req.path(),
            query: String::new(),
            body_sha256: crate::security::digest(&raw),
            idempotency_key: h.get("Idempotency-Key")?.unwrap_or_default(),
            issued_at_ms: issued,
            expires_at_ms: expires,
            nonce: h.get("RunLater-Nonce")?.unwrap_or_default(),
        },
        descriptor,
        secret: h
            .get(if revoke {
                "RunLater-Trial-Revocation"
            } else {
                "RunLater-Trial-Capability"
            })?
            .unwrap_or_default(),
        signature: h.get("RunLater-Request-Signature")?.unwrap_or_default(),
        body_hex: hex::encode(&raw),
    };
    let mut gate = global(env, "/public/trial-request", &serde_json::to_value(&input)?).await?;
    if gate.status_code() != 200 {
        return Ok(gate);
    }
    let v: Value = gate.json().await?;
    let Some(grant) = v.get("grant") else {
        return json_response(&v, 200);
    };
    let grant: crate::anonymous_trial::Grant = serde_json::from_value(grant.clone())?;
    if input.envelope.path == PROVISION {
        return internal(
            env,
            "PROJECTS",
            &input.envelope.project_id,
            "/public/trial-install",
            &json!({"grant":grant,"request":input}),
        )
        .await;
    }
    let validation = matches!(input.envelope.path.as_str(), VALIDATE | STATUS);
    let signed = Signed {
        ticket: grant.ticket,
        envelope: input.envelope,
        signature: input.signature,
        body_hex: input.body_hex,
        delegation: None,
        trial: Some(input.descriptor),
        trial_capability: Some(input.secret),
    };
    internal(
        env,
        "PROJECTS",
        &signed.envelope.project_id,
        if validation {
            "/public/trial-validate"
        } else {
            "/signed"
        },
        &serde_json::to_value(&signed)?,
    )
    .await
}
impl Checked for Global {
    fn checked(&self) -> Result<()> {
        self.check()
            .map_err(|_| Error::RustError("Invalid public beta state".into()))
    }
}
impl AdmissionRegistry {
    pub(super) async fn public_fetch(&self, mut req: Request) -> Result<Response> {
        if !configured(&self.env)
            || self.state.id().to_string()
                != self
                    .env
                    .durable_object("ADMISSION")?
                    .id_from_name(REGISTRY)?
                    .to_string()
        {
            return err(inv::Error::Forbidden);
        }
        let p = profile(&self.env)?;
        if req.path() == "/public/view" {
            let s: Global = load(&self.state)?.unwrap_or(
                Global::new(&p).map_err(|_| Error::RustError("Invalid public policy".into()))?,
            );
            s.validate(&p)
                .map_err(|_| Error::RustError("Public policy conflict".into()))?;
            return json_response(&s.view(now()), 200);
        }
        let v: Value = req.json().await?;
        let mut s: Global = load(&self.state)?.unwrap_or(
            Global::new(&p).map_err(|_| Error::RustError("Invalid public policy".into()))?,
        );
        s.validate(&p)
            .map_err(|_| Error::RustError("Public policy conflict".into()))?;
        if req.path() == "/public/trial-request" {
            let input: TrialRequest = serde_json::from_value(v)?;
            let Some((gateway, release)) = trial_trust(&self.env)? else {
                return err(inv::Error::Forbidden);
            };
            let raw = hex::decode(&input.body_hex)
                .map_err(|_| Error::RustError("Invalid trial request".into()))?;
            let before = serde_json::to_string(&s)?;
            s.revoke(&revocations(&self.env)?, now())
                .map_err(|_| Error::RustError("Invalid revocation config".into()))?;
            let result = s.trial_request(
                &input.envelope,
                &input.descriptor,
                &input.secret,
                &input.signature,
                crate::mcp_delegation::Trust {
                    gateway_public_key: &gateway,
                    release_id: &release,
                },
                &raw,
                now(),
            );
            let readonly = matches!(
                input.envelope.path.as_str(),
                crate::anonymous_trial::STATUS | crate::anonymous_trial::VALIDATE
            );
            if !readonly && before != serde_json::to_string(&s)? {
                save(&self.state, &s)?;
            }
            return match result {
                Ok(v) => json_response(&v, 200),
                Err(e) => err(e),
            };
        }
        if req.path() == "/public/mcp-validate" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Validate {
                envelope: crate::signed::Envelope,
                signature: String,
                delegation: crate::mcp_delegation::Certificate,
            }
            let c: Validate = serde_json::from_value(v)?;
            // Honor current configured revocations on a read-only snapshot; never persist on introspection.
            s.revoke(&revocations(&self.env)?, now())
                .map_err(|_| Error::RustError("Invalid beta revocations".into()))?;
            let Some((gateway, release)) = mcp_trust(&self.env)? else {
                return err(inv::Error::Forbidden);
            };
            return match s.validate_mcp_delegation(
                &c.envelope,
                &c.signature,
                &c.delegation,
                crate::mcp_delegation::Trust {
                    gateway_public_key: &gateway,
                    release_id: &release,
                },
                now(),
            ) {
                Ok(ticket) => json_response(&json!(ticket), 200),
                Err(error) => err(error),
            };
        }
        let before = serde_json::to_string(&s)?;
        s.revoke(&revocations(&self.env)?, now())
            .map_err(|_| Error::RustError("Invalid beta revocation update".into()))?;
        let result=match req.path().as_str(){
   "/public/challenge"=>s.challenge(v["public_key"].as_str().unwrap_or_default(),v["nonce"].as_str().unwrap_or_default(),now()).and_then(|c|Ok(json!({"challenge_id":c.id()?,"canonical_utf8":String::from_utf8(c.bytes()?).map_err(|_|inv::Error::Invalid)?,"challenge":c}))),
   "/public/complete"=>s.complete(v["challenge_id"].as_str().unwrap_or_default(),v["signature"].as_str().unwrap_or_default(),now()).map(|(grant,challenge)|json!({"grant":grant,"challenge":challenge})),
   "/public/mcp-revoke"=>{#[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Revoke{envelope:crate::signed::Envelope,signature:String}let c:Revoke=serde_json::from_value(v)?;s.revoke_mcp_delegations(&c.envelope,&c.signature,now())},
   "/public/client-route"=>{#[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Client{envelope:crate::signed::Envelope,signature:String,#[serde(default)]delegation:Option<crate::mcp_delegation::Certificate>}let c:Client=serde_json::from_value(v)?;
       let trust=if c.delegation.is_some(){mcp_trust(&self.env)?}else{None};
       let proof=match (&c.delegation,&trust){(None,_)=>crate::mcp_delegation::Proof::Owner(&c.signature),(Some(certificate),Some((gateway,release)))=>crate::mcp_delegation::Proof::Delegated{signature:&c.signature,certificate,trust:crate::mcp_delegation::Trust{gateway_public_key:gateway,release_id:release}},_=>return err(inv::Error::Forbidden)};
       s.client_with_proof(&c.envelope,proof,now()).map(|t|json!(t))},
   "/public/recovery-route"=>{let r:Recovery=serde_json::from_value(v)?;s.recovery(&r.project_id,&r.public_key,&r.nonce,r.issued_at_ms,r.expires_at_ms,&r.signature,now()).map(|t|json!(t))},
   "/signed-route"=>s.route(v["project_id"].as_str().unwrap_or_default()).map(|t|json!(t)),
   _=>Err(inv::Error::Invalid)
  };
        if before != serde_json::to_string(&s)? {
            save(&self.state, &s)?
        }
        match result {
            Ok(v) => json_response(&v, 200),
            Err(e) => err(e),
        }
    }
}
impl InvitationProject {
    pub(super) fn trial_install(&self, value: Value, project: &str) -> Result<Response> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct InstallTrial {
            grant: crate::anonymous_trial::Grant,
            request: TrialRequest,
        }
        let v: InstallTrial = serde_json::from_value(value)?;
        let Some((gateway, release)) = trial_trust(&self.env)? else {
            return err(inv::Error::Forbidden);
        };
        if v.request.envelope.method != "POST"
            || v.request.body_hex != "7b7d"
            || v.request
                .envelope
                .validate_trial_request(b"{}", now())
                .is_err()
        {
            return err(inv::Error::Forbidden);
        }
        if v.grant.descriptor != v.request.descriptor
            || v.grant.ticket.project_id != project
            || v.request.envelope.path != crate::anonymous_trial::PROVISION
        {
            return err(inv::Error::Forbidden);
        }
        if v.request
            .descriptor
            .verify(
                &v.request.envelope,
                &v.request.secret,
                &v.request.signature,
                crate::mcp_delegation::Trust {
                    gateway_public_key: &gateway,
                    release_id: &release,
                },
                now(),
            )
            .is_err()
        {
            return err(inv::Error::Forbidden);
        }
        let mut s: Enrollment =
            load(&self.state)?.unwrap_or_else(|| Enrollment::new(Mode::Invitation));
        match s.install_trial(&v.grant, now()) {
            Ok(()) => {
                save(&self.state, &s)?;
                json_response(&v.grant.descriptor.status(true), 200)
            }
            Err(e) => err(e),
        }
    }
    pub(super) fn public_install(&self, value: Value, project: &str) -> Result<Response> {
        let v: Install = serde_json::from_value(value)?;
        let p = profile(&self.env)?;
        if v.grant.ticket.id
            != p.ticket_id(&v.grant.public_key)
                .map_err(|_| Error::RustError("Invalid proof binding".into()))?
            || v.grant.ticket.project_id != project
            || v.grant.ticket.terms != Profile::terms()
        {
            return err(inv::Error::Forbidden);
        }
        let mut s: Enrollment =
            load(&self.state)?.unwrap_or_else(|| Enrollment::new(Mode::Invitation));
        let result = s.install_public(&v.grant, &v.challenge, &v.signature, now());
        save(&self.state, &s)?;
        match result {
            Ok(r) => json_response(&serde_json::to_value(r)?, 201),
            Err(e) => err(e),
        }
    }
    pub(super) fn public_key(
        &self,
        mut s: Enrollment,
        input: &Signed,
        raw: &[u8],
    ) -> Result<Response> {
        if raw != b"{}" {
            return err(inv::Error::Invalid);
        }
        let p = profile(&self.env)?;
        let m = master(&self.env)?;
        let material = m
            .tenant(&p.release_id, &input.envelope.project_id)
            .map_err(|_| Error::RustError("Invalid callback context".into()))?;
        let keys = crate::callback::Keyring::new(
            &input.envelope.project_id,
            &format!("public_beta_{}", p.release_id),
            "beta_v1",
            p.opens_at_ms / 1000,
            p.callback_end_sec,
            &material,
        )
        .map_err(|_| Error::RustError("Invalid callback context".into()))?;
        let result = s.verifier_key(
            &input.envelope,
            &input.signature,
            raw,
            &keys,
            &material,
            now(),
        );
        save(&self.state, &s)?;
        match result {
            Ok(v) => {
                let mut r = json_response(&v, 200)?;
                r.headers_mut().set("Cache-Control", "no-store, private")?;
                Ok(r)
            }
            Err(e) => task_error(e.into()),
        }
    }
}
