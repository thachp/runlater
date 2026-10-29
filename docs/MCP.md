# RunLater MCP server

**Required legacy endpoint: `https://mcp.runlater.io/sse`. Streamable HTTP: `https://mcp.runlater.io/mcp`.**

The existing delegated gateway has been deployed, but its genuine-client live
end-to-end proof is incomplete. Deployment is not a verified, everyday-user launch.
The no-account agent trial described below is a **new, default-off source milestone**;
this change does not activate it or create production credentials or projects.

## Agent-first onboarding — staged, not active

The [anonymous trial design](MCP-ANONYMOUS-TRIAL.md) removes mandatory human accounts,
sign-in and private-key handling from the new-project flow. A standard OAuth client
would display **Start free agent project**, receive ordinary scoped OAuth credentials,
and explicitly invoke `provision_trial` only when requested. Connect, initialization,
discovery and status never allocate a project. Existing owner-key projects remain a
separate, locally approved linking option.

**Connected does not mean ready to schedule.** This source milestone does not install
a receiver or transfer its callback secret. It reports **receiver setup required**
and refuses scheduling. A separately reviewed runtime setup path and authorized live
proof are launch gates, not tasks to push onto the user as JSON/key instructions.
No recovery mechanism is configured: losing all OAuth credentials can lose access.

The [hosted design](MCP-HOSTING.md) covers the existing owner-delegation path, true
legacy SSE and separate Streamable HTTP. The remainder of this guide describes the
**local single-project Node option**, not the hosted multi-tenant implementation.
Never publish one owner's signer as a public service.

## Transport and distribution

This repository contains a Node.js 22+ server using the pinned official MCP TypeScript SDK. It supports **legacy HTTP+SSE**: a client opens `GET /sse`, receives the relative `/messages?sessionId=…` endpoint, and sends JSON-RPC messages there with POST. This is an actual MCP transport, separate from the custom discovery/tool-schema artifacts. The hosted Worker supports Streamable HTTP at `/mcp`; this local Node option does not. For this local option, legacy SSE was chosen for the issue's requested endpoint/client contract. Clients must support SSE and header-based credentials on both GET and POST. The local Node option has no OAuth issuer or dynamic client registration; OAuth-only clients must use the separately reviewed hosted Worker.

The Node process binds only `127.0.0.1` (default port 8790). A future separately reviewed deployment must terminate TLS at `mcp.runlater.io`, forward `/sse` and `/messages` to this process, preserve `Host: mcp.runlater.io`, disable buffering and request/authorization/body logging, and enforce edge rate and connection limits. The server rejects other Host/Origin values and does not trust forwarded headers. Do not expose its raw HTTP port. Sessions are process-local: use one instance or sticky routing. A restart loses sessions, **not** the authoritative API's idempotency records. Reconnect, then explicitly recover any uncertain command using the original key and identical input.

The process bounds sessions (32), session lifetime (15 minutes), messages (512/session), request bodies (8192 bytes), signed API concurrency (four shared in-flight tool calls) and API timeouts (five seconds). These are local safety bounds, not measured capacity, service guarantees or substitutes for API limits. A public deployment needs an abuse review; anonymous discovery can consume the bounded session pool.

## Identity and configuration

**One dedicated project and trusted principal per process.** This is a signing gateway, not a public multi-tenant credential broker. Anyone holding its access token receives only the configured subset of that project's existing API authority. Do not put different customers behind a shared token or let model arguments select projects, keys, origins, scopes, receipts or credentials. Multi-tenant hosting needs a separate reviewed identity-to-project authorization design.

Anonymous connections can list tools, read setup/service resources and call `service_status`. They cannot inspect or mutate tasks. Configuring a signer does not authorize anonymous sessions. Every authenticated GET and POST checks the existing bearer token; a session ID never replaces authentication. The Ed25519 signer is server-side and reuses `PublicBetaClientV1`, its exact signed-request envelope and its enrolled receipt validation. API-side expiry, revocation, scope, project isolation, destination verification and finite grant/admission checks remain authoritative. The MCP scope list can reduce, never expand, authority. Rotate/revoke the gateway token by replacing the owner-controlled configuration and restarting; existing sessions end on restart.

Install and run discovery-only (no credentials or network requests on startup):

```sh
npm ci
npm run test:mcp
npm run mcp
```

Connect a compatible client to `http://127.0.0.1:8790/sse`. This is the MCP server running locally, **not** the Rust loopback bearer/fixture API. This adapter never selects fixture transport and never creates credentials, registers a project, enrolls a receiver, retrieves callback keys or purchases credits.

To enable authorized tools, the owner must already have a valid public-beta Ed25519 key, receipt, reviewed release ID and a separate gateway access token. Keep these in owner-only regular files (POSIX mode 0600; symlinks refused). A token must be 32–256 URL-safe alphanumeric/underscore/hyphen characters. No secret appears in command-line arguments or model-visible tools. Keep all files under ignored `private/` or an external secret mount. Example **non-secret configuration shape**, with paths substituted by the owner:

```json
{
  "key_file": "/owner-secret-mount/existing-ed25519.pem",
  "receipt_file": "/owner-secret-mount/existing-receipt.json",
  "token_file": "/owner-secret-mount/existing-mcp-access-token",
  "release_id": "EXISTING_REVIEWED_RELEASE_ID",
  "scopes": ["enqueue", "read", "cancel"]
}
```

```sh
RUNLATER_MCP_CONFIG=/owner-secret-mount/mcp-config.json npm run mcp
# Future authorized hosting only: also set RUNLATER_MCP_ORIGIN=https://mcp.runlater.io
```

In the MCP client's secure configuration, set the SSE URL and `Authorization: Bearer <token from secure storage>` on both transport requests. Do not paste a token or private key into chat or a tool call. The server does not forward the bearer to RunLater; it signs a project-bound request to the fixed `https://api.runlater.io` origin instead. A read-only process with no config works without a token. An incomplete, expired or mismatched receipt/key/release configuration fails closed at startup.

## Exposed operations and semantics

| Tool | Effect and existing API route |
| --- | --- |
| `service_status` | Public read of `/v1/beta`; a sampled capability/capacity result, not entitlement. |
| `schedule_task` | Signed POST `/v1/tasks`, `enqueue` scope; reserves finite attempts and creates one task. Only a registered, already ownership-verified Workers.dev endpoint ID; no arbitrary URL. |
| `task_status` | Signed GET `/v1/tasks/{id}`, `read` scope; status and redacted attempt history from the same hosted response. |
| `cancel_task` | Signed POST `/v1/tasks/{id}/cancel`, `cancel` scope; suppresses future attempts, never promises to undo an external callback. |

Resources: `runlater://service` distinguishes intended hosting, supported profile and omitted capabilities; `runlater://setup` contains this guide. `tools/list` describes mutations and strict JSON input schemas. Unknown fields, including credentials/project overrides, are rejected. Structured results preserve task IDs, replay status and uncertainty but exclude payloads, destination URLs, keys, signed headers and raw upstream errors. Callback bodies are deliberately supplied by the requesting client, never echoed back. Tool/schema/resource discovery causes no task mutation.

The hosted signed API has no task-list route, so list is omitted rather than borrowed from the unrelated local contract. Hosted redrive exists but is deliberately not exposed: it creates a newly funded execution with a new task ID and can repeat earlier effects. Registration, destination management, payments and automatic top-up are likewise not tools.

Supported profile is `public_free_beta`: existing seven-day identity/grant, 100 attempt units, five reserved per task, 16 lifetime tasks and 128 publications per project, first ten lifetime projects. These are a published source snapshot; call `service_status` and consult current API status before assuming availability. No arbitrary destinations, payments, SLA, ordering, exactly-once or exact-time guarantees. Older restricted-alpha README text is historical, not the live capability contract.

## End-to-end agent example

1. Connect, initialize MCP, `resources/read` the setup and service resources, then `tools/list` and `service_status` with `{}`. These are discovery reads only.
2. Outside the model, the owner connects the already-authorized project gateway. The owner must already have registered and verified the permitted Workers.dev receiver. Do not treat this setup as permission to schedule anything.
3. **Only after an explicit user scheduling request**, retain the stable key and exact arguments in the client's own durable operation record, then call `schedule_task`:

```json
{"idempotency_key":"owner-approved-job-001","endpoint_id":"existing_verified_receiver","body":"{\"synthetic\":true}","operation_key":"owner-approved-job-001","run_at_ms":0}
```

4. Record the returned `task_id`. `task_accepted: true` means admission, **not delivery**. Call `task_status` with that ID to inspect status/attempts. A `succeeded` task means an HTTP success was recorded, not downstream business completion.
5. **Only when cancellation is requested**, call `cancel_task` with the same ID. Cancellation can race an active callback; check status rather than promising that nothing happened.
6. On timeout, connection loss, malformed success or service failure, a mutation's outcome can be unknown. There is **no automatic retry**. If explicitly retrying creation, use the same persisted key and byte-equivalent arguments, within API deduplication retention. Do not generate a new key, extend the schedule or silently change the payload. After API retention expires, seek owner review rather than assuming replay is safe. A 409 requires inspection, not a new key to bypass it. A 429 does not authorize buying capacity or registering another project.

## Verification and remaining gates

`npm run test:mcp` uses the real SDK client over loopback HTTP+SSE and a deterministic fake signed API. It covers initialization/resources/tool discovery; create → inspect attempts → cancel; strict inputs; credentials/expiry/scopes/project substitution; bounded errors and exhausted limits; unavailable operations; bearer binding on both channels; stable idempotency recovery after a lost response; and output redaction. Fake success is **not** hosted integration evidence. Existing public-beta client tests cover canonical signing/receipt boundaries and remain part of the relevant regression suite.

This source change does not itself change DNS, TLS, proxy, resource, credential, receiver, release workflow, service policy or deployment. Hosted connection at the exact required URL and an authorized live create/status/cancel using an already verified permitted receiver are **pending**. Do not check those issue acceptance boxes or close #57 from this source/local result. A deployment reviewer must also assess multi-principal needs, token lifecycle, proxy logging/redaction, abuse limits, long-lived SSE/reconnect behavior, resource budget and rollback before publication.

Protocol references: [official TypeScript SDK server documentation](https://ts.sdk.modelcontextprotocol.io/server) and [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports). The pinned SDK retains legacy SSE compatibility. The local Node option is SSE-only; the hosted Worker separately implements Streamable HTTP.
