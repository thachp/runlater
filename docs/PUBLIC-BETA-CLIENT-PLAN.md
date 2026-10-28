# Public self-service free beta: receiver/client handoff — source plan only

The current product direction is **public key-possession signup without an invitation**, with payments later. The first-cohort design is seven days, 100 attempt credits, ten lifetime public projects globally, and existing 16-task/128-publication safety ceilings. These are provisional source/rollout choices, not a statement that the hosted service currently offers them. Do not call 100 attempt credits “100 tasks”: acceptance reserves a finite retry budget, and the task/publication ceilings also apply. No prices, currency, automatic payment or public activation is selected by this plan.

The main API owner implements public signup, global pre-allocation limits, per-project callback material and signed scoped key retrieval. This branch contains only [a receiver example](../examples/public-beta-receiver/README.md), its local tests and this handoff. It does not change RunLater runtime code, the current invitation client, published alpha/discovery/OpenAPI or live hosts.

## Freeze the actual public wire contract before client implementation

The invitation client is a separate source-only protocol. Do not rename its invitation token endpoints into public signup or silently change its proof purpose. Wait for the owner's versioned public-beta DTO/checkpoint, then bind a distinct client/guide to that exact contract.

Required checkpoint facts, with no guessed routes or field names:

1. Public challenge/completion paths, Ed25519 encodings, domain-separated version/purpose/origin/key/nonce/expiry tuple and term/receipt binding. Proof must precede project allocation. Document bounded unknown/bad/replayed requests, the ten-project global ceiling and what happens after an uncertain successful completion.
2. Immutable server-derived project identity, finite grant/identity expiry, exact authorized scopes and original-allocation versus current balance semantics. Recovery must not create another project or refill the grant. Key possession is not one-person identity or Sybil prevention.
3. Signed `manage_destinations` callback-key retrieval shape: project/policy/key identifiers, secure per-project secret output, validity/rotation metadata, one-time versus repeat retrieval/recovery and response-loss behavior. A service master key must never leave the API. Define which verified receipt/identity fields the client must match in full.
4. Destination create/prepare/verify/revoke request/response DTOs, HTTP errors and idempotency behavior; proof TTL/attempt ceiling; latest-version acceptance and immutable source-version redrive. The proposed receiver supports only the exact configured `worker.account.workers.dev/callback` URL under the API's global strict-public-host flag. Ownership remains separate from egress authorization.
5. Current capability/health contract and explicit source-versus-deployed state. Neither a successful health check nor published metadata grants registration, signing, delivery or payment authority.

## Smallest client/guide follow-up after that checkpoint

- Reuse bounded transport, owner-only file handling and exact signed request v1 framing where compatible. Reconstruct the **new** public possession bytes from validated fields; never sign arbitrary returned text. Keep the published operator alpha and invitation client behavior unchanged.
- Require explicit term approval; preserve full validated receipt/identity context through response loss. Store per-project callback material only in owner-only output, never logs or tool arguments. Provide no default live transport or automatic task, retry, polling or payment loop.
- Prepare an already approved receiver and private configuration channel before asking for ownership proof. Install nonce-bearing static response privately; never implement reflection or a public proof-upload shortcut. Confirm the proof window is practical for Cloudflare secret rollout before presenting a runnable setup sequence.
- Demonstrate one explicit verified-destination task, signed status/cancel/revoke and deliberate recovery/replay using unchanged business input. Explain 7-day admission versus accepted funded work, 100 attempt credits versus 16-task/128-publication ceilings, in-flight cancellation/revocation uncertainty and application deduplication.
- Add mock protocol tests, a Rust canonical-byte oracle for the new proof, negative full-context/suffix substitution tests, DTO/schema/link checks and a local production-artifact journey with denied/intercepted egress. Keep code-availability and actual hosted-availability evidence separate.

The workers.dev-only starting restriction is an intentional first release boundary, conditional on the reviewed server implementation and real-runtime evidence. No wildcard admission, arbitrary customer DNS, custom domain or redirect expansion follows from this example.

## Publication and decision boundary

Review/test the receiver and final public client before any publication/activation decision. Current live sites, alpha identity/grant/receiver and published availability remain unchanged. Hosting a customer receiver would create resources in that owner's account and requires the appropriate authorized setup; no such setup is run here. Public-beta API resource/secret/host activation belongs to the main owner. No invitation distribution, paid upgrade, merchant setup or payment adapter is a prerequisite for the public free-beta client.
