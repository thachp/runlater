# Local transport dead-letter reconciliation

This prototype distinguishes a task's authoritative ledger state from exhausted Queue references. A failed transport message is not evidence that a task failed or that its callback did not execute. No production DLQ is configured or provisioned by this change; arbitrary external callbacks remain disabled.

The optional `TRANSPORT_DLQ_NAME` identifies a separately configured diagnostic consumer. `READY_QUEUE_NAME` must identify the ordinary consumer. Missing, unknown or ambiguous roles fail closed. Each message is decoded independently; malformed references are acknowledged without persisting their raw contents. A valid reference routes only to its tenant's Durable Object. Permanent claim rejection is acknowledged; uncertain storage/consumer failures retry. Successful durable results and stale fenced results are acknowledged. The ready ledger and its alarms remain the authoritative outbox throughout transport exhaustion.

Cloudflare forwards exhausted messages to the configured DLQ; without one they are dropped. Naming a nonexistent DLQ can create it, so the default and staging configs deliberately contain **no** `dead_letter_queue` or DLQ consumer. Production setup, jurisdiction, retention, monitoring, enrollment and cleanup require separately reviewed provisioning. See [Cloudflare DLQ behavior](https://developers.cloudflare.com/queues/configuration/dead-letter-queues/).

## Operator contract

`GET /v1/queue/dead-letters` and `GET /v1/queue/dead-letters/{record_id}` require `read`. They are pure projections sampled using server time. Lists have 50 entries per page and an opaque `after` cursor. They do not reconcile leases, publish messages or maintain retention.

`POST /v1/queue/dead-letters` requires `configure` and accepts exactly `{task_id,generation}`. It reports a reference, without asserting that Queue exhaustion occurred. A private DLQ consumer sets separate `transport_observed` provenance. Public clients cannot forge that flag or specify a tenant. These records omit task bodies, destinations, operation/idempotency keys, credentials, signatures and callback responses. The task ID/generation are diagnostic identifiers, not callback contents.

`POST /v1/queue/dead-letters/{record_id}/reconcile` requires `configure`, an empty JSON object and no query parameters. It uses current authoritative state and trusted server time:

- Eligible ready work keeps the same durable outbox entry, task ID and generation. Existing alarms publish it; this command never publishes inline.
- Scheduled/retry work retains its due time; live leases retain their fence and possible in-flight effect. Expired leases follow the ordinary uncertain-outcome retry policy.
- Missing, stale, cancelled, succeeded and failed references never resurrect a task. A failed task requires the separate explicit `redrive` permission/API to create a linked execution.
- Age and attempt budgets are never reset. An exhausted nonrunning task is terminalized without a new callback or attempt. A defensive claim check also refuses a sixth attempt in an inconsistent ready snapshot.

The first reconciliation stores an immutable receipt with action, classification, server timestamp and an opaque hash of tenant/operator key identity. Replays return that historical receipt plus a freshly computed current classification; a receipt is not proof of delivery or a mandate to repeat its action. Normal command/alarm reconciliation can still advance due work. Configure-only callers receive only opaque record ID/replay status; read permission is required for details. No payment/credit operation is called or implied.

## Bounded storage and retention

At most 128 diagnostic references are retained per tenant ledger, evicting oldest first with a bounded eviction counter. IDs derive from tenant/task/generation, so repeated observations merge provenance without amplifying audit events or extending the first-observed deadline. Records expire 30 days after first observation through command/alarm maintenance; this deadline participates in the next wake. Eviction/expiry affects diagnostics only, preserving active tasks, payloads and acceptance/redrive deduplication. Task terminal retention remains 30 days after termination. After a diagnostic is evicted/expired, reporting it again creates a new diagnostic; terminal protection and task budgets still apply.

## Executable evidence and limits

`cargo test --test transport` covers duplicate capture, snapshot restart/replay, pure queries, malformed/foreign/stale references, terminal preservation, scheduled/live lease behavior, stale-result fencing, age/attempt exhaustion, bounded retention and scoped redaction.

`npm run test:transport-local` builds the compiled Rust Worker with `runtime-tests`, uses owned disposable Miniflare SQLite/Queues and private service-binding fault hooks, then restores a normal artifact and checks that hooks are absent. It exercises actual local source retries and dead-letter forwarding before claim and after a durable success, outbox recovery, schedule preservation, terminal no-op, permissions, malformed/foreign references, query immutability and a clean workerd/SQLite restart with receipt replay. Failures are injected exceptions; this suite does not kill a process or prove Cloudflare failure behavior. Separate runtime-recovery tests cover actual local SIGKILL boundaries.

[Cloudflare local Queue support](https://developers.cloudflare.com/queues/configuration/local-development/) does not model consumer concurrency. No live DLQ, external callback, cross-region outage, provider retention or production operational guarantee is proven here. Production issue #8 criteria require that separate validation.
