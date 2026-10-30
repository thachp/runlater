# Inactive project-control and source-quota bridge

This source-only component extends PR85. It adds no public route, deployment
configuration, hosted identity, credential, real grant, quota allocation or active
scheduling integration. `ProjectLinkAuthority` is used only by the local test
entry point. The replacement candidate does not import it. Missing controllers
fail closed. The current candidate still returns410 for standard OAuth/MCP routes;
Agent Auth plus this bridge is **not a compatible drop-in** for MCPJam or OAuth MCP.

## Fixed conservative policy

**Revoking a source OAuth family revokes every linked replacement authority
record.** The SQLite transaction writes a permanent source-family tombstone,
marks all links revoked and records cleanup work before acknowledging revocation.
Repeated revocation does not clear pending cleanup. Successful cleanup does not
remove tombstones or free identity/trial slots. No configuration flag allows
linked authority to survive source-family revocation; changing that policy needs
an explicit future decision and implementation review.

## What the implementation proves

- A persisted five-minute challenge binds origin, release, original project and
  family, exact permissions, new host/agent IDs and both public-key digests.
  Fresh signatures from both replacement keys are checked against active D1
  identity records. Completion consumes the challenge exactly once.
- Owner proof reuses existing `verifyDelegation`, requires the existing enrollment
  receipt and a fresh owner signature over that same challenge. The helper alone
  does not establish family activity or current API authority: the old controller
  must additionally validate authoritative family state and the current API.
- The accepted source snapshot freezes project, namespace, opaque authority
  reference, original issue/expiry, permission ceiling, source epoch and identity
  digest. No secret/capability/bearer credential or quota balance is copied.
  Trial snapshots must retain exactly seven days from original issuance. Owner
  links retain the existing delegation expiry, not a new seven-day grant. A fresh
  challenge may outlive a short delegation, but both must still be valid when
  completion is checked. Current delegation validation, the original source
  expiry and final commit/execute checks continue to bound authority.
- Every operation needs a fresh authenticated Agent Auth controller assertion
  bound to the selected link, immutable source-project context, exact operation
  and actor, active replacement identity, active source family and unchanged snapshot. Permission names are never aliased;
  old `enqueue`/`read`/`cancel` cannot silently become `http_schedule`.
- Only the source API adapter can execute an operation. It receives the original
  project/namespace and unchanged idempotency/operation keys. This component has
  no budget column, debit/refill method, project provision operation or task
  rewrite. Original task IDs, execution state, delivery deadlines and API quota
  continue to belong to the existing API.
- Source validation is not sufficient by itself: the dispatch adapter must check
  the expected family epoch again under the same ordering as source revocation.
  If an API response is lost after commit, retry uses the same original key;
  it never creates a replacement project or assumes a refund/new budget.
- Links, source-family tombstones and cleanup records survive full local workerd
  restarts. Expired challenge rows are pruned; linked authority/tombstones remain.
  Pending intents, lifetime links, tombstones, queued operations, body sizes and
  response chunks are bounded. Internal controller calls have five-second
  deadlines, abort signals, bounded streaming JSON reads and no redirect following.

## Required controller interfaces (unimplemented and unbound)

`LEGACY_LINK_CONTROLLER` is an authenticated internal service binding, not a
public network URL or a caller-supplied JSON attestation. `verify-control` must
validate the fresh challenge, original control proof, source family/epoch,
original identity/permissions/expiry and current signed API validation. It returns
only the strict redacted snapshot shape in `worker.mjs`. `validate-source` must
recheck that authority on every operation. Revoked/inactive families return an
inactive verdict and cause durable family-wide tombstoning in the link owner.
The old controller must route its revocation acknowledgement through this owner
before acknowledging a source-family revoke, so linked access cannot lag it.

**Trial ceremony remains undefined and therefore denied.** A public descriptor,
bootstrap/project ID or a fresh Agent Auth key is insufficient. Implementing an
explicit authenticated rebinding from the retained old grant/family is required;
it must prove the old authority without forwarding/exporting legacy bearer
credentials or secrets into the replacement store. Recovery without that old
control proof requires a separate explicit policy decision. The component does
not accept a trial assertion by default or mint authority to fill that gap.

`AGENT_SESSION_CONTROLLER` must use actual Agent Auth validation, including JWT
signature, expiry, audience, method/URL/body binding, persistent replay protection
and capability-grant intersection, and attest the exact signed request digest.
`complete` returns `execution_context`
containing the link, project, namespace, source family/epoch and actor. Clients
sign the canonical `executionRequest(context, operation)` envelope; the bridge
recomputes that context from stored authority and checks `request_sha256` in the
controller assertion. Operation-only tokens/assertions are rejected, so a link ID
cannot be substituted to select another project before the first token use.
A link ID is never an authentication credential. This contract is not wired to the
candidate's public `connection_status` capability and must not be implemented by
simply trusting request headers, decoding a JWT or reusing a local replay Map.

`SOURCE_API_BRIDGE` must resolve the opaque existing authority reference inside
its existing vault/controller; no secret import is implied. It must atomically
order active-family/expected-epoch checking and dispatch against source revocation,
then use existing `AnonymousTrialClientV1`/`DelegatedPublicBetaClientV1` paths and
existing signing trust. It must preserve original namespace/idempotency semantics
and let the real API enforce quota/expiry/revocation and task validation. Its
receipt binds original project, namespace and epoch. Unavailable/mismatched
receipts are uncertain results, not permission to retry under a new key.

## Failure recovery and exact limits

Completion is denied if control, identity or source expiry changes while proofs
are checked. A crash before linking leaves a pending intent; after the atomic
commit the known intent ID is the link ID. Replayed completion is rejected;
recover committed results only via an authenticated controller lookup, never by
minting a second authority. No actual Agent Auth capability grants are created by
this component: the durable links are future authorization records, pending the
real controller/entry-point integration and independent review.

Revocation persists first and secondary cleanup is retryable after restart.
`pendingCleanup`/`finishCleanup` are trusted internal reconciliation primitives,
not public management APIs and not evidence that real D1 grant cleanup has run.
A future outbox/alarm adapter must confirm actual cleanup before marking it done.
Replacement identity is checked again after asynchronous controller validation
and immediately before API dispatch. The real adapters must still define and
enforce ordering for concurrent revocation versus in-flight authorized work.
A source API action that was authorized before revocation may already have
committed; do not reset tasks or quota to manufacture rollback.

Tests use real local Agent Auth registration/D1 records and real owner signature
verification. Old-authority, Agent Auth session and source API adapters are
**contract fixtures**, not production adapters or proof of end-to-end client
compatibility. The session fixture verifies signatures/request digest with jose;
it is not the real plugin's session/grant/replay integration. Its process-local
replay set is test-only. The API fixture's37-unit balance models the existing
source API and is never stored/debited by the bridge itself. There are no live
network calls. Full production controller fault injection, revival/recovery
policy, real API quota integration and client bridging remain prerequisites.
