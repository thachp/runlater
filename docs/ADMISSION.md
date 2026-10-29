# Default queue admission and dispatch controls — local prototype

The next bounded slice adds one configurable **default logical queue per tenant/project**. The same tenant-scoped SQLite DO remains authoritative for all task admission and dispatch; there is no second object or queue name that can bypass aggregate project limits. Multiple named logical queues and cross-shard fairness remain deferred.

`GET /v1/queue` is a read-only query. `PUT /v1/queue` is a CQRS command that replaces all settings atomically with ledger state. Both require an authenticated project token: GET requires `read`, and PUT requires `configure`. Local action scopes and key issuance/revocation/rotation are now implemented in [AUTH.md](AUTH.md). These public fixture tokens are local test data, not production credentials; production provisioning and secure administrator enrollment remain deferred.

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

To require the fresh-store coincident-ID regression, start a local emulator with a new `--persist-to` directory and run `RUNLATER_REQUIRE_COINCIDENT_IDS=1 node scripts/admission.mjs` before other suites create tasks. Alpha and beta must each receive `task_0000000000000001`; distinct per-tenant operation keys and payloads prove that forged tenant headers still return the authenticated tenant's own data. The ordinary command also supports populated idle fixture stores without assuming global task-ID uniqueness.

## Bounded publication rotation (#9)

The default tenant outbox rotates its 32-reference publication window with a
persisted last-selected task ID when more than 32 tasks are eligible. Previously,
repeated publication selected only the lowest IDs, so an unclaimed head could
hide later accepted work until that head progressed or age-expired. The runtime
already commits the snapshot before Queue I/O. Advancing the cursor therefore
survives a restart or uncertain/failed send; retained ready rows are selected again
after wrapping. Publication spends neither rate tokens nor attempt permits.
Cohorts of at most 32 retain stable replay order. Older snapshots default to no
cursor, and cancellation/purge of the cursor task does not block progress.

`cargo test --locked --test publication_fairness` proves that a fixed 97-task
ready cohort is selected in four calls across snapshot restarts even when every
reference stays unclaimed, and is selected again within the next four calls.
Generally a fixed eligible cohort of N > 32 is covered within ceil(N/32)
completed outbox selections. This bound assumes repeated persisted selections;
it is not a wall-clock bound, successful-send guarantee, FIFO claim policy, or
cross-tenant/cross-shard Cloudflare scheduling guarantee. Continuous arrivals,
selective send failure under live provider conditions and actual consumer
scheduling still require live proof.
The cursor adds no second scheduling authority.

A separate deterministic 1000-task noisy-tenant scenario allows a quiet tenant to
complete, then simulates a transport outage longer than the delivery-age limit
with a crashed permit. Reconciliation terminates stale work, fences late results,
and retention purge permits fresh admission and claim. This is a local model
proof using the persisted format, not live process failure or load evidence.
Named queues, live failpoints/concurrency, global fairness and outage/load launch
gates remain open; numeric limits remain configuration rather than plan promises.

## Selective publication failures (#9)

All three Queue pumps (local fixtures, registered alpha, and invitation/public
beta) now attempt every reference in an already persisted selection, sequentially,
even if one send returns an error. Previously a persistently failing head could
hide the rest of a small stable-order cohort forever; rotating whole batches did
not protect tails when the same failures recurred at fixed batch positions.

The common sender returns the first error only after the remaining references
have received one send attempt. The existing durable watchdog remains responsible
for replay; ready rows are not removed, and publication does not spend dispatch
tokens or callback-attempt permits. The selection stays bounded to 32 references,
or fewer when an existing publication budget truncates it. There is no immediate
retry, added parallelism, fresh budget, or new scheduling authority. During a
complete Queue outage this intentionally makes up to 32 failed send calls per
pump instead of stopping after one; configured finite publication budgets still
count reserved references, including uncertain sends.

`cargo test --locked --test publication_fairness` covers selective failures across
snapshot restarts at cohort sizes 1, 2, 32, 33, 64, 97 and 1000, preserves every
ready row for recovery, and checks first-error reporting and single attempts.
`./scripts/test-publication-fairness.sh` runs a compiled local Worker with real
emulated SQLite/Queue transport, a fresh disposable store, denied network egress,
and three fixture tasks. Private pre-send exceptions repeatedly block the first
reference while both tails complete; removing the fault lets the retained head
complete without an extra callback attempt. The runner restores the normal
artifact and checks that runtime fault hooks are absent.

The local exception is **not** an actual provider Queue send failure or a live
load benchmark. Permanent errors still cannot guarantee delivery of the failing
reference. Named queues, continuous-arrival/global scheduling fairness, live
consumer concurrency, and live outage/load launch gates remain open.
