# Executable local API quickstart

RunLater is an early Rust/Cloudflare prototype. This guide uses only the loopback emulator, public fixture credentials and in-process destinations. It creates no Cloudflare account resources. A live signed HTTPS delivery failed in the earlier isolated campaign; see staging/CAMPAIGN-2026-10-27.md. These examples do not establish production delivery or SSRF safety.

## Start and try the API

Install the pinned Rust/worker-build tools and dependencies using [LOCAL.md](LOCAL.md), then:

```sh
npm run dev -- --ip 127.0.0.1 --port 8787
# Second terminal:
npm run example:local
```

The example schedules a synthetic fixture task, repeats the same enqueue with the same immutable input/idempotency key, inspects metadata, then cancels it. It prints only generated task ID/statuses. `examples/local-client.mjs` includes enqueue/read/list/attempts/inspection/cancel/redrive, queue configuration/health/metrics/audit, diagnostic transport reconciliation and retention commands. Its constructor accepts only `http://127.0.0.1:<port>/`, refuses redirects, uses a five-second timeout and a 1MiB response bound. Errors expose HTTP status and optional numeric Retry-After, not raw response bodies or credential values. It is an example, not a production SDK; it does not automatically retry writes. Retrying enqueue/redrive requires the **same** idempotency key and unchanged request. Preserve operation_key across ordinary redrive.

Read credentials can return task payloads through full task/list routes. Prefer inspection for payload-free diagnostics. Enqueue/cancel/redrive without read permission return a smaller receipt. Missing/revoked credentials produce 401, insufficient scope 403, absent tenant-owned task 404, immutable idempotency conflict 409, disabled destination 422, capacity/admission deferral 429. Some errors are structured JSON, others UTF-8 plain text. Content-Type distinguishes them. Retry-After is a hint in integer seconds, not guaranteed admission; capacity may require retention expiry/configuration. Neither changing the idempotency key nor retrying indefinitely is a safe response to an uncertain enqueue.

## Run the executable contract

```sh
npm ci
npm run test:examples
npm run test:contract
```

The contract command builds the pinned Rust default Wasm and starts fresh ephemeral local workerd with SQLite DO/alarm/Queue execution. Every documented OpenAPI operation must execute and every observed status/media type/body must match its declared schema. All outbound fetches are wired to an internal local rejection Worker; no remote callbacks or provider resources are used. The runtime is disposed in finally, including failures. Tests use only public deterministic local token fixtures and finite polling/call budgets. CI runs the same command.

`docs/openapi.json` describes the **default local build**, not the separately gated staging variant or a published api.runlater.io service. JSON Schema 2020-12 is checked with pinned development-only Ajv. The `x-max-utf8-bytes` extension supplements character limits for Rust byte-bound fields. JSON numeric int64 values are checked as integers within the signed range; JavaScript rounds the legacy bootstrap expiry sentinel near i64::MAX. The example does not use that sentinel for decisions; an exact-int64 consumer needs a lossless parser. Normal scheduled/issued-key timestamps are safe JavaScript integers. Key permission arrays are normalized as sets: duplicate input values are accepted/deduplicated, while returned permission sets are unique. Task, receipt, inspection, attempt, key, health, activity and retention schemas describe actual returned fields, including optional staging diagnostic metadata in compatible stored snapshots. Errors share reusable media schemas; endpoint descriptions retain their scope/context.

Covered behavior includes full/scoped receipts, enqueue/redrive replay, body conflict, UTF-8 byte bound, malformed/oversized media, authentication/permissions/revocation, queue configuration, snapshot operational views, retention command, Retry-After/capacity and failed-only redrive. Dynamic policies such as maximum scheduling horizon, authority subset checks, retention windows and concurrency still require deterministic native tests; a schema is not the whole state machine. This suite does not prove production network delivery, cloud crash recovery, costs, security enrollment or load behavior.

## Receiver protocol demonstration

`examples/local-receiver.mjs` exports a pure function, not a listening server. It verifies the public local fixture HMAC over exact `timestamp.task_id.operation_key.` bytes followed by unchanged raw body bytes. The timestamp window is ±300 seconds. Unit tests cover tampering, malformed signatures, byte limits and duplicates across retries/redriven task IDs. Deduplication uses tenant + operation_key and a body hash, returning 204 for matching replay and 409 for a conflicting body. The map stops accepting new identities at 1024 entries instead of growing indefinitely.

This map is **process memory only**, with no durable side effects, expiry, recovery or production secret management. A real receiver must commit durable business-operation deduplication atomically with its side effect and use securely provisioned/rotated keys. Timestamp checks alone do not prevent replay within the window. The example neither fetches destinations nor demonstrates safe arbitrary outbound networking.

## Shared middleware error coverage

The default build's 18 tenant operations can return 400 for malformed JSON envelopes, 401 for credentials, 403 for scope/authority, 413 for the shared 24KiB body bound and 503 for the outer prototype/configuration gate. That gate precedes authentication/media/body work. GET requests also pass through the body reader; the suite uses bounded raw loopback HTTP to verify malformed/oversized GET bodies because fetch clients disallow them. A GET Content-Type of text/plain does not trigger 415. POST/PUT operations can return 415 for an explicitly non-JSON media type; root task/key/queue mutations also require Content-Type. The unauthenticated local `/health` route returns before those gates and only documents 200.

Operation-specific responses remain separate: task inspection/history/detail and cancel can return 404; enqueue adds 409/422/429; failed-only redrive adds 404/409/429; key issuance adds 409/429; key revocation adds 404; rotation adds 404/409/429. Read-only queue/list/key-journal queries do not inherit impossible command-specific conflict/destination/capacity errors. The contract suite checks all eight POST/PUT wrong-media/oversized exits, all ten tenant GET malformed/oversized body exits, GET's absent media gate, and all 18 disabled-prototype exits, in addition to normal operation/state-machine probes. These are local runtime checks, not provider infrastructure error guarantees.
