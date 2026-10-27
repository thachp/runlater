# Default queue admission and dispatch controls — local prototype

The next bounded slice adds one configurable **default logical queue per tenant/project**. The same tenant-scoped SQLite DO remains authoritative for all task admission and dispatch; there is no second object or queue name that can bypass aggregate project limits. Multiple named logical queues and cross-shard fairness remain deferred.

`GET /v1/queue` is a read-only query. `PUT /v1/queue` is a CQRS command that replaces all settings atomically with ledger state. Both require the existing authenticated project token. These public fixture tokens are local test data, not production credentials. Administrative key scopes and provisioning remain deferred.

```json
{
  "max_active_tasks": 1000,
  "max_payload_bytes": 131072,
  "max_concurrent": 4,
  "dispatch_per_second": 20,
  "dispatch_burst": 20
}
```

All defaults are proposed and adjustable within pilot ceilings. Active tasks (including future schedules and retries) count against admission. Retained terminal payloads also count against the combined byte limit until retention purge; cancellation frees active admission but does not erase retained bytes. The fixed 1000-row pilot ceiling remains independent of active quota. An already accepted idempotent request or redrive replay returns its original execution even when admission is now full.

Each granted attempt spends one token from a durable integer token bucket and one expiring concurrency lease, in the same snapshot upsert as the claim. First attempts and retries use the same gate. Failed or successful HTTP outcomes do not refund dispatch rate tokens. Duplicate/stale Queue messages consume neither a token nor an additional attempt. A process restart preserves token balance and refilling timestamp. A backwards clock cannot mint extra tokens; configuration updates refill under the old rate and cap existing balance instead of resetting a fresh burst. Raising concurrency does not revoke existing work; lowering it prevents new claims until capacity becomes available. Expired leases reconcile through the existing alarm and fencing path.

Rate/concurrency refusal returns structured 429 metadata internally. The consumer acknowledges this **durably persisted deferral**, leaving the ready/outbox row and wake-up alarm responsible for another claim. It does not run an independent transport retry policy for an application admission decision. Infrastructure failures still use transport retry; ledger outcome commits still precede acknowledgements. The pilot ready-outbox alarm polls at roughly one second, so a high configured rate is not a throughput promise.

Example public admission response:

```json
{"error":"tenant_limited","reason":"active_tasks","retry_after_ms":1000}
```

`Retry-After` rounds milliseconds up to seconds. Active/payload admission hints are advisory: cancellation, completion, configuration or retention expiry may be required before admission. Concurrency hints use the earliest expiring live lease; earlier completion can release capacity sooner. Rate hints include the next refill and any backwards-clock gap.

Input hardening validates the complete configured hash→tenant keyring, tenant identifiers and Queue identifiers, typed internal finish status/fence DTOs, JSON request media type, exact command routes and bounded queue settings. Client-supplied tenant headers cannot override authenticated project ownership. All real destination URLs remain rejected.

## Local proof

Run `scripts/check.sh`, then a local emulator and:

```
npm run test:local
node scripts/admission.mjs
node scripts/query-readonly.mjs
node scripts/delayed-body.mjs
```

The admission test waits for earlier short-running fixtures to settle, modifies only the local alpha configuration, restores it in a finally block and cancels its own scheduled fixtures. It proves real local Queue dispatch pacing, active-admission 429 metadata, idempotent replay under quota, cancellation release, second-tenant admission and tenant-header denial. Native tests cover durable rate balances, first/retry attempt gates, stale/duplicate no-spend, expiring permits, clock regression, reconfiguration, two-tenant isolation and invalid configuration.

`tests/recovery.rs` simulates persisted-ledger restart at acceptance/publish/claim/callback/outcome/ack boundaries. In particular, callback success before the durable result can duplicate a callback, while committed success before ack cannot create another committed attempt. These deterministic JSON snapshot tests use exactly the SQLite ledger's stored format, but are not live Cloudflare process-failure proofs. Real consumer concurrency, runtime failpoints, prolonged outage/capacity/noisy-neighbor load and production network safety remain launch gates. No issue is claimed fully complete from this slice alone.
