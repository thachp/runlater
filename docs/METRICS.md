# Tenant-local throttle and time-window observations

`GET /v1/queue/metrics` requires read permission and projects the tenant's authoritative default-queue ledger. It is a pure CQRS query: no reconciliation, token refill, task creation, counter update, bucket cleanup, SQL save or alarm change. Sampling uses trusted server time; a caller-provided timestamp/query cannot move a window. This is operational evidence, **not billing/credits, business-operation success rate, provider Queue depth, delivery count, external telemetry or an SLA**.

## Fixed windows and persistence

The ledger stores lifetime totals and at most 60 nonempty UTC minute slots. Each response includes 1-, 5- and 60-minute-bucket views in that order, **including the current partial minute**. A window starts at `(current UTC minute - width + 1) * 60000`, includes that lower bound and excludes the next-minute upper bound. `observed_through_ms` labels the current partial sample. It is an aligned bucket window, not an exact trailing N-minute duration. At the exact next-minute boundary the one-minute window excludes the previous bucket.

`sampled_at_ms` is the actual server sample, `last_observed_at_ms` is the last committed observation or null, and `effective_sample_ms` is clamped to the last observation if the clock moves backward. `clock_regressed` exposes that clamp. Command observations under a backward clock are assigned to the last-observed bucket rather than overwriting newer history; `clock_regressed_observations` counts each affected observation, not unique requests or clock transitions. Reads never record those observations. Normal expiry resumes as server time catches up. Logical task/lease time remains unchanged by this metrics clamp.

Old buckets are excluded logically on reads and pruned on the next observed command. Idle projects need no extra wake/publish loop just to expire metric slots. Aggregates contain only fixed categories/counts/times, not task IDs, bodies, URLs, operation/idempotency keys, credentials, signatures, receipts or raw error strings. Storage has bounded label cardinality and slots. Counter values cap at 10^12 with a per-summary saturation flag; counters do not wrap. Ratios are null when the denominator is zero or a summary is saturated. Lifetime totals persist through local SQLite restarts and task retention maintenance; they are not reconstructed from task history. Old snapshots without metrics start at zero after upgrade, so totals are since instrumentation, not historical account usage.

## Counter semantics

| Categories | Recorded only when |
| --- | --- |
| admission_active_tasks_denied / admission_payload_denied / admission_retained_tasks_denied | A new enqueue/redrive fails its authoritative tenant admission check. Repeated rejected calls are repeated observations; an existing idempotent result bypasses admission without another denial |
| claim_references | A valid internal claim DTO reaches the ledger; not a unique task or provider transport count |
| claim_ignored / claim_missing | A stale/duplicate/noneligible reference returns no claim, or its retained task is absent |
| claim_paused | An otherwise eligible reference is deferred by the durable pause gate before spending tokens or starting a lease |
| paused_age_expired | Paused nonrunning work exceeds its original delivery-age budget; no attempt is started |
| claim_rate_denied / claim_concurrency_denied | An otherwise eligible reference is deferred by durable dispatch limits; repeated transport references may repeat these counts |
| claim_age_expired | Work becomes terminal before starting an attempt because its delivery age budget expired |
| attempt_started | A new lease/fence/attempt is actually committed |
| attempt_succeeded / attempt_timeout / attempt_retryable_http / attempt_permanent_http / attempt_lease_expired_unknown / attempt_unknown_failure | A valid finish or lease reconciliation settles one logical attempt. Stale/duplicate results cannot record another outcome |
| stale_results_ignored | A finish for a retained task cannot own the current live fence/lease/state; transport observation, not a failed business attempt |

Attempt summaries include `attempt_completed`, `attempt_errors_or_unknown` and `attempt_error_ratio`. The denominator is **settled logical attempts**, not references, throttles, task acceptances, or starts in that window. Outcomes are assigned to trusted transition/reconciliation time, not a remote callback timestamp; an attempt can start in one window and settle in another. The numerator includes non-success/unknown lease outcomes. Thus it measures ledger attempt observations, not proof that an external side effect failed. Rate/concurrency/quota denial, age expiry without an attempt, ignored references and stale results never inflate it. Retryable HTTP includes 425/429/5xx; 408 is timeout. A fenced callback outcome of 429 is an attempt outcome; an API/claim 429 is a separate denial observation. HTTP categories classify the ledger outcome, not an independent capture of remote response data. Unknown lease outcomes remain explicitly uncertain.

Denied commands commit observations in the existing synchronous ledger save before returning. They do not create a task/idempotency record, increment task sequence or debit a dispatch token; existing command reconciliation can still settle already-expired work. Rate refill may update elapsed-time bookkeeping, but a denied take debits no token. Duplicate references are classified before rate/concurrency checks. Malformed/unauthorized outer HTTP requests, read denials, local staging campaign guards and key-admin policy errors are not tenant throttle counters in this slice.

## Local evidence and remaining work

`tests/metrics.rs` covers exact minute/window expiry, rollback, bounded slots/saturation, additive snapshot migration, serialized restart, cross-tenant isolation, pure queries, quota without task/token effects, idempotent replay, rate/concurrency denial, duplicate references, stale results, lease reconciliation and age expiry. `npm run test:metrics-local` uses the compiled default Worker with actual SQLite/DO command paths and a clean runtime restart. It verifies committed denial counts, scope/tenant isolation, fixed server sampling, payload redaction, and unchanged SQLite schema/ledger/alarm metadata across metric reads. It deliberately has no Queue consumer so private claim scenarios stay deterministic; the separate executable contract exercises actual Queue/finish outcomes.

OpenAPI and the local client include metrics. The contract suite executes all 19 current operations and validates metric schemas. Metrics are not exported to another service; alerts, calibrated intervals, production retention/recovery/access policies, live load/noisy-neighbor evidence and customer-facing capacity targets remain open in #10/#11. Callback key administration/integration, DLQ recovery and pause/resume are separate work; no live service/resource or billing change is made here.
