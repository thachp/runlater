# MCP OAuth boundary — source review notes

This is source/local verification, **not a hosted availability or production security approval**.

## Authority

The gateway never receives an owner's private key. The owner uses the local helper to
sign two different proofs: a bounded API delegation to the gateway's pinned public key,
and consent bound to one exact OAuth request and browser transaction. The consent binds
client ID, callback URI, requested scopes, state, PKCE challenge, issuer, resource, handle
and delegation bytes. The CLI requires independently pinned gateway key/release and an
explicit approval before signing; the signed output is saved to an exclusive owner-only
file and pasted into the originating consent page. A consent page is not permission to
enqueue a task.

`@cloudflare/workers-oauth-provider` is pinned to **1.2.4**. It validates OAuth clients,
redirects, PKCE, codes and opaque access tokens. The application requires S256 even for
confidential clients. CIMD clients are supported with `global_fetch_strictly_public`;
dynamic client registration, private-use callback schemes, refresh tokens, token exchange
and remembered consent are not enabled in this milestone. Clients requiring those
features are not supported. HTTPS and HTTP loopback callback URIs remain supported.
Token requests support CIMD public-client (`none`) or `private_key_jwt` authentication;
Basic/shared-secret client authentication is not enabled. New authorization/token work
can fail closed when its network slots are full; those slots do not gate validation of
already-issued access tokens. Two additional revocation network slots require local
proof of a currently active MCP token issued to the exact requesting client; unknown,
expired or wrong-client tokens stay in ordinary admission. The provider still verifies
client authentication before revocation. This prevents anonymous metadata requests from
occupying every revocation slot, not malicious authorized tenants or distributed overload.
A request validated before concurrent revocation may
already be in flight; requests beginning after completed token deletion fail validation.

Opaque access tokens have the sole audience `https://mcp.runlater.io`, covering both
protocol endpoints. They are not sent to the API. The separately owner-signed API
certificate and gateway-signed exact API request are the only downstream authority.
The API remains responsible for enrolled identity, revocation, project isolation,
receiver restrictions, idempotency and finite budgets. OAuth acceptance alone is not
proof that an API project currently remains eligible.

Access tokens expire within one hour, never after their certificate or the API's
confirmed effective expiry. No refresh
token is issued; reauthorization requires a fresh explicit local signature. The API
certificate has at most one hour of validity, further bounded by owner identity expiry.
This intentionally favors a short initial authorization window over unattended access.

## Storage and replay

The fixed MCP Durable Object uses bounded per-client state-transition lanes and
per-handle one-use consent lanes. Token validation is an independent bounded local-read
path: slow or attacker-controlled client metadata cannot hold the lock for existing
task traffic. Setup and token-endpoint network work have separate four-operation bounds;
slow request bodies are read before acquiring any transition lane. Reserved revocation
uses the same per-client transition lane as issuance to preserve grant ordering. Its KV-shaped adapter
uses Durable Object storage, not eventually consistent Workers KV, and a short network-free
write queue makes capacity admission atomic. Concurrent consent completion and code
exchange cannot both succeed. The library revokes a grant when code replay is
detected, so a client must not automatically retry an uncertain code exchange.

The adapter stores at most 512 records of 16 KiB each and caps retention at 4,200 seconds.
Consent transactions have a separate 64-record partition, authority records 384, and
other records 64. Each project may hold at most 32 grant/token records, so one enrolled
project cannot occupy the whole authority partition. Authoritative read-only API
validation must establish active enrollment, project/scopes and effective expiry before
both grant completion and token issuance; a self-signed key-possession proof alone is
insufficient. Validation failure or an absent validator fails closed.
Expired records are pruned during bounded writes/listing. The library stores tokens/codes
by hash and encrypts grant properties. No owner private key is stored. Admission queue
capacity is 32 OAuth operations; request bodies are bounded to 16 KiB, 32 chunks and five
seconds. These are operational bounds, not cost caps or a capacity/SLO claim.

RFC 7009 revocation uses the advertised **`/oauth/token`** endpoint with `token` and
`client_id`, without `grant_type`. There is no `/oauth/revoke` route. Every new protocol
request revalidates the token and delegation; active streams are independently bounded
by their authorization lifetime. Owner/API delegation revocation is a separate control
and must remain authoritative for every downstream operation.

## Privacy and deployment gate

The authorization page has no JavaScript, blocks framing, uses a browser-bound secure
consent cookie, requires a same-origin approval POST and escapes client metadata. Error
responses contain only bounded OAuth codes, not input values or library exception text.
The application has no credential/body logging. The pinned provider has unconditional
warning paths; production bundling **must remove console calls**, then inspect the
emitted bundle. Disabling observability alone is not the redaction control.

Without the exact `MCP_OAUTH_ENABLED=operator-approved`, approved release and gateway
public-key configuration, authorization stays unavailable. Production gateway signer
creation/installation and authority activation still require specific approval. No
live OAuth token, project, receiver or provider resource was created by these tests.

## Local evidence

`node --test mcp/oauth.test.mjs mcp/oauth-runtime.test.mjs` passes. The runtime test uses
the actual pinned provider in workerd and real local Durable Object storage, with only
synthetic CIMD metadata supplied by a deny-all-by-default local outbound service.
Every test request uses `redirect: manual`; callback redirects are inspected, not
followed. The suite covers exact consent binding, malformed input, wrong signer/expiry,
metadata escaping, missing browser cookie, concurrent one-use consent, PKCE mismatch,
wrong audience, concurrent code exchange and replay revocation, a fresh valid token,
scope/project context and immediate OAuth revocation. Separate owner-helper and API
delegation suites cover their own boundaries. `npm run test:mcp-delegation` also
composes the actual provider, both official SSE/Streamable SDK clients, the bundled
hosted Worker and the compiled Rust API for create/status/cancel, with independent
owner verification and strictly local intercepted egress. Neither test establishes
public hosted availability or real-client compatibility.

References: [provider documentation](https://github.com/cloudflare/workers-oauth-provider),
[MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization),
[MCP security guidance](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices).
