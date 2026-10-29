# Hosted MCP delegated authorization — source milestone

**The existing delegated gateway is deployed; genuine-client live end-to-end verification remains incomplete.** This document describes its source and rollout gates, not proof of a task-capable launch. `https://mcp.runlater.io/sse` remains the required publication
endpoint. Do not activate discovery alone and call it a task-capable launch.

## Separate no-account trial milestone

[Anonymous agent trials](MCP-ANONYMOUS-TRIAL.md) are newly staged and disabled by
default. They do not require human accounts or owner-key generation, but they use a
**distinct capability principal**, not the owner-local key boundary below. Trial
provisioning is explicit, bounded and immutable; receiver runtime setup and recovery
are not implemented. Enabling that new authority requires separate security review,
activation approval and live verification. The owner-delegation path remains intact.

## Identity boundary — existing owner projects

The local single-project gateway in [MCP.md](MCP.md) is not the public hosting model.
The hosted source uses a separate OAuth access token for every owner/client grant:

1. A compatible remote client starts OAuth authorization-code + PKCE S256 for the
   `https://mcp.runlater.io` resource. The authorization page displays the exact
   client identifier, redirect, scopes and public challenge. Client names alone
   are self-asserted, not verified identity.
2. The owner reviews and signs that exact request **on their own device**, using an
   already enrolled project key and receipt. The existing private key is never
   uploaded. The helper also signs a distinct, bounded API delegation certificate
   naming the reviewed gateway public key, project, release, scopes and expiration.
3. The owner pastes only the signed approval into the same browser consent page.
   Browser binding and one-use consent prevent a copied approval from being attached
   to a different client, redirect, PKCE challenge or authorization transaction.
4. The official Cloudflare OAuth provider exchanges the one-use code for an opaque,
   MCP-audience token valid no longer than the explicit delegation (at most one hour). It is checked on **every** transport request. The initial
   milestone issues short-lived access tokens, with no refresh grant or automatic
   extension of the owner's consent. Reauthorization requires another local approval.
5. A task call uses the gateway's own signing key plus the separate owner-signed API
   delegation certificate. The MCP OAuth token is **never** forwarded to the API.
   Before OAuth grant creation and again before token issuance, a read-only API
   validation proves the project is actually enrolled and the delegation is still
   active; a self-signed fake project is not enough. It creates no task, registration
   or client-operation charge. The API independently verifies the owner certificate, gateway signature, trusted
   gateway configuration, original project identity, scopes, expiry and revocation,
   before applying unchanged destination, idempotency, admission and budget checks.

Only `enqueue`, `read` and `cancel` may be delegated. Certificates last at most one
hour and cannot exceed the enrolled identity's expiration. Task list, redrive,
registration, receiver management, callback-key retrieval, payment and top-up are
not delegated tools. A delegated client does not receive the owner's key or a
`manage_destinations` capability. No credential may appear in tool arguments,
results, URLs, normal logs or error bodies.

**Authority expiry is not cancellation.** A task admitted while authority is valid
can execute later, within existing project scheduling/retention rules. Revoking
MCP access blocks new commands but cannot recall a callback already underway.

## Transports and client compatibility

- **`/sse`: true legacy HTTP+SSE.** GET opens the event stream; its endpoint event
  provides `/messages?sessionId=...` for JSON-RPC POSTs. Both requests must carry
  the current OAuth bearer. The session ID is routing metadata, never authority.
- **`/mcp`: stateless Streamable HTTP.** POST requests use the official MCP SDK
  transport and JSON responses. There is no resumable server-side stream or
  protocol session on this lane. GET returns 405; this is not legacy SSE.
- Both lanes expose the same strict tools/resources and project-bound behavior.
  Header-capable clients are required. OAuth clients must support PKCE S256,
  resource indicators and Client ID Metadata Documents in this initial source;
  no dynamic client registration endpoint is enabled. The initial OAuth challenge
  requests the three task scopes explicitly; the owner sees and approves them.
  Configure a narrower client scope request for read-only use. Missing tool scope
  returns an HTTP 403 OAuth scope challenge before execution. Streamable clients
  may perform step-up; legacy SSE clients must reauthorize and reconnect (a new
  token cannot inherit an old session).
- Native clients without a browser Origin header and same-origin browser requests
  are supported. Cross-origin browser MCP requests are not silently allowed;
  an explicit reviewed CORS/origin policy would be a separate addition.

Initialization, resources and tool listing do not create tasks. A user still must
request scheduling or cancellation explicitly; OAuth consent is capability, not
permission to invent jobs. SDK async task execution, batches and hidden retries
are not supported. Persist the original idempotency key and exact input before
scheduling. On an unknown result, inspect/recover deliberately with that same key
and input; never create a replacement key to bypass an uncertain result or 409.

## Owner authorization helper (after a reviewed deployment)

Install the pinned repository dependencies. Keep the existing key, receipt and
copied public challenge in regular owner-only files (`0600`, no symlinks). Obtain
the current reviewed release ID and gateway public key from a trusted publication;
**do not blindly trust a key supplied only by an untrusted client or challenge**.

```sh
# Review only: no key creation, registration or network request.
node examples/mcp-authorize.mjs --help
```

Use the helper's explicit approval mode only after reviewing the client, exact
redirect, requested scopes, gateway key and project. It writes the signed approval
to a new exclusive `0600` file; private keys are not printed. Follow the current
CLI help for arguments. Paste only that approval JSON into the same consent page.
Never paste a private key or bearer token into a conversation or model tool call.

The published endpoint/client recipe must be verified against at least one real
OAuth-capable legacy SSE client and one Streamable HTTP client before claiming
compatibility. The local tests below do not establish public DNS/TLS availability.

## Revocation

OAuth token/grant revocation at the advertised revocation endpoint (the pinned
provider uses `/oauth/token`, with `token` and `client_id` form fields, without
`grant_type`) takes effect at the serialized
OAuth store and is rechecked on the next transport request. Existing SSE streams
cannot submit a message using a session ID alone. A changed token, project,
certificate, scope set or expiry requires reconnecting rather than reusing a
session with stale authority.

The owner also has a separate **owner-signed** API command:
`POST /v1/mcp/delegations/revoke`, body `{}`, with a stable `Idempotency-Key`.
It revokes all project MCP certificates issued at or before the API's recorded
cutoff. It does not revoke the original owner key. A replay of the same command
returns the original cutoff; it must not revoke a later fresh grant. This command
is not an MCP tool. The admission registry has a finite 128 distinct revocation-command
receipt budget per project; do not retry with new keys. Use the owner revocation helper, not a
hand-crafted unsigned request, and inspect uncertainty before retrying.

## Hosting and abuse controls

`mcp/wrangler.example.jsonc` is a **disabled template**, not a deploy profile.
The proposed Cloudflare deployment has one new `runlater-mcp` Worker and one fixed
`MCP_HUB` Durable Object (`mcp-hub-v1`) holding bounded OAuth records and transient
legacy SSE sessions. Caller input cannot create arbitrary Durable Object names.
It does not bind the API's task namespace, Queue, admission registry or callback
master; all task operations cross the independently authenticated API boundary.

Local bounds: 32 legacy sessions total, four per project, 15-minute maximum session
lifetime (also capped by token expiry), 512 messages/session, 8 KiB protocol bodies,
64 KiB SSE output queues, four shared in-flight tool calls, five-second API timeout.
OAuth storage is finite and expires records, with separate consent and authority
capacity. Network-bearing client discovery is bounded separately from existing
token validation; slow metadata must not block unrelated authenticated traffic.
One-use state transitions remain serialized by their client/consent identity. Edge rate-limit bindings
limit requests per ingress IP and authorization attempts separately. Reserved revocation
network capacity requires an already valid token for the exact requesting client;
anonymous stalled metadata work cannot occupy those reserved slots. These are
abuse controls, **not billing hard caps or measured capacity/SLA guarantees**.
Long-lived SSE can keep the object active and incur duration charges.

The production bundle is built with `node scripts/build-mcp.mjs`, which strips
console calls from dependencies as well as application code; publishing raw source
instead would retain third-party warning paths. `npm run build:mcp` builds and
checks the disabled-profile bundle without deploying it.

All public requests use the canonical HTTPS host. No tokens in query strings,
no arbitrary proxy URLs, no forwarded-header trust, no automatic redirect-following
for task API calls. Observability, workers.dev and preview URLs are disabled in
the template. OAuth metadata fetches require strict-public egress; untrusted client
metadata remains an SSRF review surface and is covered by local tests.

## Activation requires explicit approvals and evidence

Source implementation and local synthetic credentials do not authorize production
credential creation. Before publication, independently review the full diff and:

1. Approve creation of **one MCP gateway Ed25519 signing credential**, custody only
   in the new Worker secret `MCP_GATEWAY_PRIVATE_KEY`, its expiration/rotation and
   incident process. Publish only its public key. This key alone must never grant
   access to any project; a valid owner delegation is additionally required.
2. Approve the API's nonsecret trusted gateway-public-key configuration and the
   source deployment enabling delegated verification via
   `MCP_DELEGATION_GATEWAY_PUBLIC_KEY`, after the existing release
   observation ends. Preserve the beta release/cohort, identities, budget and
   receiver restrictions. The default absent trust config rejects all delegations.
   Updating this setting intentionally changes the existing release drift baseline;
   review and refresh the guarded baseline rather than bypassing its checks.
3. Approve first provisioning of the Worker, bounded Durable Object namespace,
   rate-limit bindings and the `mcp.runlater.io` Custom Domain (Cloudflare manages
   its DNS/TLS), plus activation of OAuth access-token issuance. No new CI token is
   necessary for a supervised connector deployment. Persistent autodeploy access,
   if desired later, is a separate least-privilege approval.
4. Confirm deployment identity and `/health` provider `version_id`/source SHA,
   code/settings fingerprint, missing unintended
   bindings, logs off, no workers.dev/previews, TLS and endpoint ownership. Start
   with activation flags disabled; do not publish live metadata before verification.
5. Run an explicitly authorized finite live smoke against an existing enrolled
   project and already ownership-verified permitted Workers.dev receiver: both
   client transports, consent, create, status, cancellation, revocation and denied
   cross-project/scope cases. Record exact versions and results, including any
   unknown mutation outcome. Do not register extra projects or buy capacity.
6. Only after proof, publish the docs/discovery bundle with exact tested client
   configuration and measured verification date; remove source-only warnings only
   for the claims that were actually established. Issue #57 stays open until its
   hosted acceptance gates pass.

Rollback first disables new MCP ingress/issuance and removes API gateway trust;
accepted API task maintenance remains intact. **After the first persisted MCP
revocation record, use a delegation-aware API binary.** Older `deny_unknown_fields`
admission-registry state readers can reject the extended snapshot. Do not erase state or assume a
blind old-version promotion is a safe rollback. A Worker restart ends SSE sessions,
not API idempotency records; reconnect without inventing replacement task keys.

## Verification

```sh
npm run test:mcp
node scripts/mcp-validators.mjs --check
# Compiled API + OAuth + both official MCP clients, entirely local:
npm run test:mcp-delegation
```

Tests use disposable synthetic local owner/gateway keys, fake or intercepted
upstreams and local workerd only. They do not spend a real grant, issue a live OAuth
token, create provider resources or establish public network/DNS safety.

References: [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization),
[MCP security guidance](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices),
[Cloudflare OAuth provider](https://github.com/cloudflare/workers-oauth-provider),
[Cloudflare MCP transports](https://developers.cloudflare.com/agents/model-context-protocol/protocol/transport/),
[Workers Custom Domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/).
