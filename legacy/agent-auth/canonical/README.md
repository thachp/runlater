# Canonical Agent Auth projects — local source candidate

This candidate uses a Better Auth Agent Auth host as the canonical identity for
**new** projects. Legacy OAuth migration is not a launch prerequisite. It is
default off, has no deployed entrypoint, bindings, migrations, or enabled
environment settings. It has not scheduled a real hosted task.

## Try the local proof

From this checkout, with Node 25 and local loopback listeners allowed:

```sh
cd agent-auth
npm ci
npm run test:canonical
```

The tests run actual `@auth/agent` 0.6.2, `@better-auth/agent-auth` 0.6.2 and
Better Auth 1.7.14 against ephemeral local workerd/SQLite/D1. SDK storage is
explicitly `MemoryStorage`; temporary server storage is deleted after tests.
Discovery/connect/status allocate no API project. Explicit `create_project`
admits one seven-day trial; `schedule_http` signs the existing source API wire
through `AnonymousTrialClientV1`. The API here is an isolated contract fixture,
not the Rust engine, hosted API, actual delivery, or a new quota ledger.
`npm test` also runs the older independent protocol/coordinator/bridge proofs.

## Authority and lifetime

- The immutable D1 host ID owns one durable project row. Agent sessions under
  that host share it. Alternate JSON/JWK representations are rejected rather
  than minting another host ID for the same public key. Registration remains
  bounded by ten lifetime hosts and four lifetime agents per host.
- The original project descriptor, bootstrap/idempotency key, permissions,
  issue time and seven-day expiry are durably recorded **before** provisioning.
  Unknown transport outcomes retry the same descriptor. Revoked/expired rows
  are permanent capacity tombstones. Neither a new agent nor retry refills a
  trial. New keys are new identities; this does not prove a unique human or
  prevent Sybil attacks. The existing source API's finite release project cap
  still applies across old and new identities.
- The API alone admits projects, checks revocation and charges attempt units.
  No local `remaining` counter authorizes scheduling. Status explicitly names
  `status_source: local-admission`; it is not a claim the API has reconciled
  external revocation. The API's 100 attempt allocation is not remaining quota.
  Operation and idempotency keys pass through unchanged.
- Operations never accept a project selector. They derive project authority
  exclusively from the authenticated host's stored row. Scope is the existing
  API `http_schedule`, `read`, `cancel` set; legacy `enqueue` is not substituted.
- Project revocation and signature-verified host revocation persist a deny-only
  tombstone and cleanup alarm before contacting the API or allowing the plugin
  to clear host keys. Cleanup retries survive restart. Original expiry ends
  authority even if cleanup cannot deliver; it never creates a fresh credential.
- The fixed hub serializes registration, authentication, durable replay and
  API dispatch. It is intentionally bounded, not an unreviewed scale-out design.
  No process-local cache is represented as distributed replay protection.

## Client compatibility

Agent Auth is a separate unstable protocol; standard OAuth/MCP clients are not
compatible with this candidate. Selecting the replacement router returns 410
for legacy OAuth/MCP routes. There is no claim MCPJam natively supports it.

The actual SDK's `executeCapability` in 0.6.2 omits `htm`, `htu`, `ath`. This
server requires all three and exact execute audience. `client.mjs` calls the
SDK's public `signJwt` API with method/URL/body hash, retaining private keys
inside SDK storage. Discovery is explicitly direct and transport is restricted
to the fixture origin. No keys are handled manually by the test user.

The official [SDK](https://agentauthprotocol.com/docs/client-sdk) and
[MCP bridge](https://agentauthprotocol.com/docs/mcp) describe
`npx @auth/agent-cli mcp --url <provider>` as an stdio bridge. This CLI has not
been executed or validated here; its default file storage persists keys, and
its use of execution binding must be checked before recommending it against
this server. There is no separate verified `@auth/agent-mcp` package.

## Gates before a hosted test

Source merge is not activation. A hosted test needs action-specific approval
for a deployment/cutover and a real test identity/project/task, plus:

1. A reviewed deployment entrypoint for `canonical/worker.mjs`, D1 schema and
   SQLite Durable Object migration/binding. Existing settings must be preserved.
2. A private API service binding (`CANONICAL_API`) and the existing gateway
   signing trust/release ID, with public-key equality verified. The source
   adapter fails closed when these are absent. No new Better Auth API key is
   required for this self-hosted package. No stored key values were read.
3. Explicit `CANONICAL_AGENT_AUTH_ENABLED` and replacement gates; no such
   configuration is added by this candidate. Validate API cap/expiry/revocation
   with the actual Rust engine and then an authorized hosted fixture.
4. Read-only inventory of existing tasks/grants/data before retiring legacy
   runtime routes or deleting anything. “No customers” does not establish that
   no live test task exists. No automatic OAuth-to-signing-key grant conversion.

Host key loss/recovery and long-term paid account admission need explicit future
policy; this trial candidate does not silently grant recovery or reset budgets.
The private Durable Object stores the new API capability and revocation secret;
they never appear in client responses or logs. Production storage and trust
configuration require review before activation.

The current Rust API ingress also requires its trusted `CF-Connecting-IP` rate
gate before trial authentication (`src/public_beta_runtime.rs::front`). The
contract fixture does not emulate that ingress. The private service-binding
path must be tested against the real engine to establish the platform-supplied
rate identity for both requests and alarm cleanup. This adapter never invents
an IP or forwards a caller-supplied substitute to bypass that gate; a missing
trusted ingress identity is an explicit hosted integration blocker.
