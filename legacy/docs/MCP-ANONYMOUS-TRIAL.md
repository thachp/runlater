# Agent-owned finite trials — OAuth Connect

No mandatory human account, sign-in or passkey is introduced. Public MCP health and OAuth discovery on 2026-10-30 report anonymous trials and
general HTTPS enabled with `http_schedule`. Configuration readback is not proof
of delivery or support in a particular chatbot UI. Existing owner
projects and their locally signed approval path are unchanged.

## Connect experience

1. Add the hosted MCP endpoint in a compatible standard OAuth client. The existing
   paths remain true legacy SSE at `/sse` and Streamable HTTP at `/mcp`.
2. RunLater shows the client identifier, return destination and requested task
   permissions. Choose **Start free agent project**, without an account or a key
   copied into chat. The existing-project option is separate and still needs the
   actual owner's local approval.
3. The client securely stores ordinary OAuth access and refresh credentials. Merely
   connecting, initializing, listing tools, reading setup or requesting status does
   **not** allocate an API project.
4. Only when explicitly requested, `provision_trial({"accept_finite_trial":true})`
   allocates that connection's one immutable trial. Repeating it after an uncertain
   result uses the same bootstrap identity; it cannot refill or extend the project.
5. With explicitly consented `http_schedule`, use the [general HTTPS path](GENERAL-HTTPS-DESTINATIONS.md) when the reviewed transport is available; no special receiver is required. For the separate legacy `enqueue` path, the result says **connected; receiver setup required**, not “ready to schedule.”
   The separate default-off [receiver pairing path](RECEIVER-PAIRING-WIRE.md) can bind
   one privately configured beta runtime, but only with explicitly consented
   `receiver_setup` authority. `pair_receiver({confirm:true,manifest:...})` never
   deploys infrastructure or returns secret material. The receiver privately pulls
   its installation and completes ownership verification; only then does status
   report readiness. Task permissions and finite budgets still apply.

The seven-day deadline starts at OAuth consent, not at a later provisioning call.
No payment, account creation, external identity service or automatic replacement
project is involved. OAuth consent grants a capability; it does not instruct the
agent to invent jobs or consume a trial slot without an explicit provisioning request.

## Credentials and trust boundary

A generic OAuth client cannot be assumed to generate or sign with a RunLater
Ed25519 owner key. The trial therefore has a distinct **capability principal**, not
a fabricated owner key or a claim of non-custody:

- Each trial has a random 256-bit task capability and an independent random
  256-bit revocation-only secret. Immutable, domain-separated hashes bind both to
  the release and bootstrap identity. The API stores those hashes, not raw secrets.
- The task capability is in the OAuth provider's token-bound encrypted grant
  properties. It is not stored in plaintext grant metadata, URLs, logs or tools.
  A storage-only dump without a token/code cannot directly decrypt it. The active
  gateway nevertheless sees the capability at creation and authenticated use;
  a gateway/operator compromise can steal it. This is **not owner-local-key security**.
- The revocation-only secret is retained privately by the gateway so replay cleanup
  can disable a trial after the old refresh credential no longer decrypts the grant.
  It cannot schedule, read tasks, recover access, replace a capability or reset quota.
- Existing-project API calls require both the task capability and an exact,
  gateway-signed request. Revocation requires the separate revocation proof and the
  gateway signature. Neither the global signer alone nor an API database hash alone
  is sufficient. There is no signer-only reset, replacement or destructive revoke.
- A compromised trusted gateway can still bootstrap new trials up to the independent
  API cohort limits. The API cannot cryptographically prove that a real person clicked
  consent. Client metadata is not a unique-person identity or a Sybil defense.

MCP bearer credentials are never passed through to the task API. No task capability,
callback HMAC key, private signing key or refresh token is returned in model-visible
tool output. A public project ID is identification, never authority or recovery proof.

## Lifetime, rotation and revocation

Access tokens last at most one hour. Refresh keeps the same project, exact scopes,
capability, quota and absolute seven-day deadline; it does not renew the free trial.
The pinned OAuth provider normally accepts current **and previous** refresh tokens.
This source adds a separately tested, strongly consistent wrapper: only the current
refresh token rotates successfully; reuse of a recognized consumed token by the
authenticated client durably disables the entire family and queues API revocation.
Unknown token hashes and wrong-client requests must not revoke a legitimate family.

Each successful rotation also invalidates superseded trial access tokens immediately.
SSE clients must reconnect with the new bearer; old session routing IDs do not transfer
authority. Owner-delegation token behavior is unchanged.

Strict rotation has a real cost: if the successful refresh response is lost, retrying
the consumed credential revokes the family. Concurrent duplicate refreshes have the
same result. Clients must serialize refresh and persist the returned pair securely.
There is no claimed transparent recovery. Rotation history is bounded to 192 successful refreshes per family (enough for
168 hourly renewals across seven days); exhausting it
revokes access rather than minting a fresh trial or extending expiry.

The gateway commits code consumption, token issuance and rotation state atomically
before returning success. Conflicting snapshots fail closed rather than overwriting
another client. API provisioning is a separate explicit operation, so losing an OAuth
issuance response does not consume a project slot. An uncertain provisioning response
must be recovered with the same immutable descriptor and idempotency key.

`revoke_trial({"confirm":true})` disables local access first and reports whether API
revocation is confirmed or cleanup remains pending. Cleanup uses at most 32 durable attempts with 30-second to one-hour backoff,
at most two due attempts per sweep, and stops at the original deadline; it never creates a token, project or task. **Revocation does not
cancel accepted jobs, recall an in-flight callback or refund a slot.** Cancel known
pending jobs before revoking when appropriate.

## Admission and abuse limits

Trials share the existing release's ten lifetime project slots, 100 attempt units per
project, 1,000 lifetime counted task API operations, 16 lifetime tasks and 128 publications. No
second anonymous pool, top-up, automatic retry or reset is added. Provisioning and
revocation serialize in the admission registry; revoke-before-provision leaves an
immutable bounded tombstone so a delayed provision cannot resurrect authority.
The 1,000-operation counter does not cap all HTTP traffic: lifecycle status/validation,
idempotent provisioning replay and revocation are exempt. Those paths and cleanup
instead have admission, storage, concurrency and rate bounds; these are not a hard
spending cap.

Pending OAuth trial families are bounded to 32 globally and eight per client
identifier; active families are bounded to ten. A shared client identifier (such as
one used by all users of a hosted agent) is not a person identity. Abandoned
unexchanged consent expires after ten minutes. Separate pending/active trial OAuth
partitions protect existing owner grants.
Trial SSE sessions and tool concurrency also have smaller partitions, leaving owner
capacity reserved. Public ingress and consent limits remain in force. These controls
bound exposure; they do **not** guarantee one trial per person, stop distributed
slot exhaustion or impose a hard Cloudflare spending cap.

## Receiver and recovery gates

General HTTPS does not need a verified managed receiver. A new project has no
registered receiver destination. The optional managed-beta receiver path
privately pulls callback material from the fixed API origin after capability-scoped
binding and receiver-key proof. It needs a separately authorized, privately
configured runtime; it never creates infrastructure or adds provider permissions.
The five-minute immutable setup window can expire, with no automatic replacement
or quota refund. `MCP_RECEIVER_PAIRING_ENABLED` is a separate default-off admission
gate on API and gateway; old credentials do not acquire `receiver_setup` via refresh.
Disabling new pairing does not undo installed receivers or already accepted callbacks.
Showing “connected” alone must not be marketed as a functioning scheduler.

The general profile delivers to public customer-provided HTTPS endpoints, not a
bot-specific or Workers.dev-only architecture. Third-party endpoints need not support
RunLater's HMAC/proof protocol in the general profile. Its separate
`http_schedule` scope and `schedule_http_request` tool support fixed POST/JSON
without endpoint auth or custom headers; an unavailable secure adapter causes
explicit task non-admission; a mid-request readiness loss can still consume one
counted registry operation. See [general HTTPS safety
and authorization contract](GENERAL-HTTPS-DESTINATIONS.md).

Optional human recovery/management is a future extension. **None is configured here.**
Losing all client credentials can permanently lose access. A client name, browser
cookie, public project ID or reconnect is not recovery, and must not silently consume
a replacement slot. Connecting an agent to an existing project still requires its
owner's explicit approval. Payment or broader access needs separate authorization.

## Verification and activation checklist — retained review template

This checklist records source-review and pre-activation requirements, not a claim
that every hosted experiment below has been run. The enabled configuration was
independently verified on 2026-10-30; no production canary was performed. Future
hosted experiments need separate explicit authorization and finite capacity.
Native connected-peer checks refer to the alternative native transport, not the
selected Worker public Fetch boundary.

- Local tests must prove zero allocation on consent/connection/discovery/status;
  explicit idempotent provisioning; lost responses and registry/project-install
  interruption recovery; mixed owner/trial shared capacity; immutable expiry/quota;
  signer-only/capability-only rejection; revocation races and partition isolation.
- Run actual pinned OAuth library tests for authenticated oldest-refresh replay,
  wrong-client/fake-token non-revocation, concurrent refresh, transaction rollback,
  persistence, queue backoff and plaintext-capability absence.
- Exercise both official SDK transports against the bundled gateway, compiled
  Rust API and ordinary HTTPS fixture locally for the general path. No proprietary
  receiver proof/HMAC may be required. Test secret redaction, dedicated scope,
  connected-IP/TLS policy, absolute deadlines and uncertain attempt recovery.
  The optional managed-beta path has separate reference-receiver composition tests.
- Measure worst-case storage/refresh/cleanup CPU with full bounded partitions
  against the existing 50 ms Worker ceiling before activation. Functional workerd
  wall-clock timings are not production CPU evidence. Do not raise limits silently.
- Obtain independent exact-source security QA and CI, then separately approve new
  credential generation/custody, API trust expansion, durable data compatibility,
  budgets, the private egress host/binding, rollout/rollback and a finite genuine-client
  live proof. Optional receiver setup is not a general-HTTPS prerequisite.
- `MCP_ANONYMOUS_TRIAL_ENABLED` must remain absent or `disabled` in both the API and
  MCP Worker until that approval. The example MCP configuration defaults to disabled.
  Enabling one side alone must fail closed. No existing credentials are broadened
  merely by merging this source.
- Rollback must retain a reader compatible with the new optional trial grants,
  tombstones and OAuth family records. Do not deploy an older parser that rejects
  already persisted authority state. The feature flag is a full trial-path kill
  switch, not admission-only: disabling it rejects existing trial access as well
  as new trials. Already-revoked gateway families retain bounded cleanup-only
  retries with persisted backoff; no new trial family or credential may be issued
  while disabled. If the API trial path is also disabled, API revocation cannot be
  confirmed until a compatible handler is available; local tombstones still reject
  access. Reconcile pending revocation and preserve records rather than deleting them.

References: [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
and [OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700.html).
