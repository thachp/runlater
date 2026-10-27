# Local operational visibility and retention

These endpoints inspect one authenticated tenant's single default logical queue. They use the authoritative SQLite snapshot through separate CQRS query handlers, require `read`, and do not reconcile, refill rate tokens, purge data, write audit events or rearm alarms. Sampling time comes from the server. This is bounded local functionality, not a production monitoring service.

| Route | Permission | Result |
| --- | --- | --- |
| `GET /v1/queue/health` | `read` | Snapshot counts, eligible and retry backlog, oldest eligible due time/age, lease observations, retained attempt failure categories |
| `GET /v1/queue/audit` | `read` | At most 256 durable structured activity events, sequence and capacity |
| `GET /v1/tasks/{id}/inspection` | `read` | Task state, scheduling/lease/terminal times, lineage and attempts, without input body, destination or operation key |
| `POST /v1/queue/maintenance` with `{}` | `configure` | Retention removal counts, committed through the command path |

The existing full task/list routes still expose input to authorized `read` credentials. Use inspection/health/audit for payload-free operational views. Key-management audit remains separately protected by `manage_keys`.

## Metric semantics

`sampled_at_ms` timestamps the read. `counts_by_state` counts **stored** states, including overdue `scheduled`/`retry_wait` and expired `running` rows. `eligible_backlog` separately counts due scheduled/ready/retry rows; `due_retry_backlog` is its subset with prior attempts, including ready retries after reconciliation. `future_backlog` counts those rows with a future due time. Oldest eligible time/age is null when empty. These are ledger observations, **not provider Queue depth or delivery latency guarantees**. A stored lease with expiry greater than sample time is active; expiry equal to or before sample time is expired. Missing lease timestamps are reported separately. Lease counts do not measure actual network requests or capacity currently available at the provider.

Attempt failure counts cover retained attempt outcomes: timeout, unknown expired lease, retryable HTTP, permanent HTTP and unknown. `finished_attempts` is the retained denominator if a client computes a failure ratio; these are not interval rates. Failed tasks without attempts are counted separately (for example, age-budget expiry before dispatch). No query advances a lease, task or retry state to make metrics look current. Commands and alarms perform reconciliation.

## Structured activity and redaction

The activity journal records accepted/redriven tasks, cancellation requests, claims, finishes, lease/age expiry, queue configuration and retention removal. Fields are a monotonic tenant-local sequence, server time, fixed event kind, optional generated task ID and fixed failure category. Idempotent enqueue/redrive replay does not add acceptance events. Rejected API requests and tenant throttling are not audited in this slice. There is no payload, destination, operation/idempotency key, credential, verifier, signature, receipt, raw exception or response capture. This bounded journal is not a complete security/compliance archive or external log export. It retains at most the latest 256 events and expires events 30 days after their event time; at capacity, older events can disappear earlier. Sequence gaps therefore indicate truncation/expiry, not missing task execution.

## Retention and maintenance

All active tasks retain their payload, attempt evidence and enqueue idempotency record, including long schedules. Terminal task/payload/attempt rows and their enqueue key expire together **30 days after termination**, at the exact deadline. Redrive idempotency follows the child execution's lifetime/window, even after its source has expired. No earlier payload-only deletion is implemented. Existing acceptance fingerprints remain unchanged.

Maintenance accepts only an empty JSON object and no query parameters. It uses trusted server time; callers cannot request a future cutoff. It requires `configure`, preserves active work and is repeatable without extra removals at the same time. Alarm pumping also performs retention. The next alarm includes terminal retention and journal expiry deadlines, so cleanup does not depend on polling health. A retention event contains no deleted task ID. When the journal alone expires it is cleared without creating an endless new retention event.

Run `./scripts/check.sh` for native/Wasm checks, and `node scripts/operations.mjs` against a fresh `wrangler dev --local` store. `RUNLATER_STATE_DIR=<store> node scripts/query-readonly.mjs` verifies that actual operational HTTP reads leave local SQLite schema, data and alarm metadata unchanged. Deterministic native tests cover exact retention boundaries, restart, active dedup/payload preservation and child redrive replay after source expiry.

Still required before production: exported metrics/alerts and time-window rates; throttle counters; durable long-term audit policy/export and recovery; normalized/indexed storage and measured scan costs; formal deletion/legal retention policy; operational access review and capacity/load evidence. No live account deletion, resource creation, deployment or new credential provisioning is part of this slice. Issue #10 remains partial.
