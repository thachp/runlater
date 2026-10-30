# Agent Auth local proof (default off)

This directory is an isolated executable assessment, not a deployed service. It is
not imported by MCP, the Rust API, or a deployment config. `createPrototype()`
returns 503 unless explicitly enabled by a local caller. The only capability is
`trial_status`, which returns labelled fixture policy constants. It does not
inspect an actual trial, reserve quota, create projects, or schedule deliveries.

Run with Node 25 (tested 25.8.1):

```sh
cd agent-auth
npm ci
npm test
```

Tests use the real Better Auth 1.7.14 / Agent Auth 0.6.2 plugin, memory adapter,
ephemeral Ed25519 keys, and in-process Request/Response objects. No listener,
external fetch, hosted fixture, credential or persistent identity is created.
A client signs host registration JWTs (`host+jwt`) with inline host/agent public
keys; autonomous registration becomes active without signup. It then signs a
short-lived `agent+jwt`, bound to the execution audience, method, URL and body.
Private keys remain in the test process, with no human copy/paste step.

## Verified boundary and limitations

- Passing proof: autonomous registration; actual plugin execution; concurrent
  replay rejected; audience, signature, expiry and body binding checked;
  unknown capability/delegated registration/remote JWKS rejected; stored agent
  revocation denies newly signed requests. The revocation test changes a local
  DB record, not a protocol management endpoint.
- Registration proves key possession. It does **not** prove one human, customer,
  device or entitlement to a fresh trial. Key rotation/re-registration cannot be
  allowed to reset credits or expiry.
- The wrapper permits only two POST routes and root discovery. Discovery omits
  unavailable management/approval routes. It is intentionally an incomplete
  protocol deployment. No OAuth replacement or generic MCP compatibility claim.
- MCPJam's existing OAuth connection cannot use this signed protocol without an
  Agent Auth client bridge. No native MCPJam Agent Auth support was established
  or tested. The official `@auth/agent` client/CLI is a separate integration to
  validate; this proof signs wire-format tokens with jose.
- Memory cache and full-operation serialization protect this single process
  only. Published 0.6.2 verifies replay with `await cache.has(key)` followed by
  `await cache.add(key)`. Its secondary-storage implementation uses separate
  get/set. Redis/KV/D1 alone does not make that sequence atomic. Multiple Worker
  isolates can accept the same token concurrently. Do not host this prototype.
- The plugin's `maxAgentsPerUser` check applies only when `userId` exists, so it
  does not bound unowned autonomous hosts/agents. Unbounded dynamic registration
  remains a production blocker. Local fixture data disappears on process exit.
- Remote `host_jwks_url`/`agent_jwks_url` are denied before the plugin. No claim is
  made that its built-in remote fetch is a safe Workers SSRF boundary.
- Upstream execution can auto-grant an expired capability from the active host
  budget. It also relies on cascading revocation rather than rejecting a host
  tombstone alone during agent execution. This wrapper adds denial-only stored
  host/grant checks before verification, preventing both cases locally. This is
  an application policy, not a claim that upstream expiry is terminal. Upstream
  host revocation writes the host tombstone before sequential child revocation;
  a retry on an already-revoked host returns early. Crash recovery must therefore
  finish child cleanup even when the host tombstone already exists.

## Additive rollout design and blocking prerequisites

1. Keep existing OAuth `/mcp`, `/sse`, owner grants, DO `oauth:` namespace and
   revocation cleanup unchanged. Use a separate Agent Auth origin/routing gate,
   initially off, with separate storage, protocol version and audit dimensions.
   Never interpret OAuth bearer credentials as Agent Auth JWTs or vice versa.
2. Generate and review additive D1 tables from pinned Better Auth + Agent Auth:
   core user/session/account/verification plus agent, agentHost,
   agentCapabilityGrant, approvalRequest. `schema.snapshot.json` records the
   plugin's actual schema (not runnable SQL and not the core schema). Do not run
   a migration against the OAuth DO or import credentials. D1 adapter and
   transaction semantics still need a local Workers execution proof.
3. Route each host's complete authentication + replay + grant operation through
   one strongly consistent coordinator (DO), or upstream an atomic replay
   consume primitive to the plugin. Include dynamic registration's bootstrap
   keys in that coordination. Await state writes; test simultaneous requests,
   restart recovery, revocation and TTL across instances. D1 state reads alone
   cannot provide a complete serialized authentication operation.
4. Add durable admission keyed to an operator-approved entitlement/abuse policy,
   not a fresh agent id/public key. Store a unique, immutable mapping from host
   entitlement to existing trial project/bootstrap, original issued/expiry time,
   quota ledger and revocation tombstone. Reserve capacity before returning a
   grant, retain denial/tombstone history, and reject when this service is absent.
   Preserve 100 attempt units, original seven-day absolute expiry, finite lifetime
   project cap, namespaces and release signing trust. Agent session reactivation,
   host linking, deleting cookies, retries, new keys or protocol rollback must
   never mint another trial. Existing projects require explicit authorized proof
   of control for linking, never silent credential import.
5. Only after that bridge exists, expose narrow `http_schedule` via existing
   validation/admission/trial client paths. Do not map the older enqueue/read/
   cancel scopes to it implicitly. Check active grant, project, namespace,
   expiry, permission and API quota on every action. Persist revocation before
   upstream cleanup; keep cleanup retries when issuance is disabled. Do not
   expose the OpenAPI adapter broadly or rewrite the delivery engine.
6. Add ingress registration/body/concurrency/global lifetime caps and rate limits,
   secret-free audit events, key custody/recovery policy, browser-safe errors,
   authenticated management/revocation and SDK client interoperability tests.
   A lost autonomous host key has no safe automatic recovery absent another
   enrolled proof. Neither signup nor email is necessary, but identity continuity
   and anti-abuse policy are still necessary.
7. Rollback disables new Agent Auth registration/issuance and leaves existing
   OAuth intact. Retain additive tables, quota mappings and revocations. Define
   whether already-issued Agent Auth grants continue until original expiry or
   are explicitly revoked; do not drop data or reset limits on rollback.

Before rollout: independent security QA, a Workers/D1 + DO concurrency proof,
real Agent Auth SDK/client tests, explicit quota/recovery decisions and reviewed
migration/rollback are required. Deployments, credentials, exposure changes,
hosted test projects and production mutations each require separate action-time
authorization. This PR supplies none of those authorizations.

## Sources inspected 2026-10-30

- https://better-auth.com/docs/plugins/agent-auth (explicitly unstable)
- https://agentauthprotocol.com/specification/v1.0-draft
- https://github.com/better-auth/agent-auth
- npm installed `@better-auth/agent-auth@0.6.2` `dist/index.js`: registration,
  session verification, replay caches and options; package exports/declarations.
- Existing RunLater `mcp/worker.mjs`, `oauth-storage.mjs`, `oauth-trial.mjs`,
  `oauth-consent.mjs`, and `src/anonymous_trial.rs` on main `833ea650`.
