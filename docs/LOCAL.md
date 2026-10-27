# Local prototype

This is a tested first vertical slice, not completion of issues 1–13. Original README design targets remain unchanged. No Cloudflare account, resources or secrets are required.

## Tools

Released worker/worker-build 0.8.7, Wrangler 4.154.0 (package-lock), Rust 1.92.0, wasm32-unknown-unknown. worker 0.8.7 requires Rust >=1.91. On this Mac Homebrew rustc 1.90 precedes rustup, so the build script explicitly selects the pinned Rust 1.92.0 compiler. Dependencies are locked in Cargo.lock. No upstream main dependencies.

```
rustup target add wasm32-unknown-unknown --toolchain 1.92.0
RUSTC="$(rustup which rustc --toolchain 1.92.0)" rustup run 1.92.0 cargo install worker-build --version 0.8.7 --locked
npm ci
./scripts/check.sh
npm run dev -- --ip 127.0.0.1 --port 8787
# second terminal
npm run test:local
```

All callbacks run in-process. No HTTP callbacks, DNS queries, redirects or production secrets exist. Public test tokens `local-alpha` and `local-beta` map to separate Durable Objects through SHA-256 token hashes. Fixture signing key is public test data. Local project-scoped key issuance, revocation, rotation and administrative permissions are now implemented; see [AUTH.md](AUTH.md). Once initialized, the persisted keyring is authoritative. Production credential provisioning and secure administrator enrollment remain deferred.

Create requires `Idempotency-Key` (1–128 bytes); body is a UTF-8 string, maximum 16KiB; JSON envelope maximum 24KiB. UTC Unix milliseconds are used for scheduling (at most 365 days ahead). `0` requests immediate delivery. Exact dispatch time and ordering are not guaranteed. GET list accepts `after` cursor, returns at most 50 tasks. POST cancel suppresses future attempts, while recorded success can win an in-flight race. Failed-only redrive requires a fresh idempotency key (maximum 64 bytes) and creates a linked task, leaving history intact.

## Persistence and recovery

Each authenticated tenant routes to its own SQLite-backed DO. One versioned SQLite row stores a bounded ledger snapshot: task, deduplication identity, ready/outbox intent, lease and attempt transitions commit in one synchronous upsert, without an await between load and save. SQL BEGIN/SAVEPOINT is not used. This intentionally small pilot supports up to 1000 retained tasks and 128KiB combined payload bytes per tenant. It needs normalized indexed tables before scale testing. At capacity it returns 429; this is a proposed pilot bound, not a plan promise.

HTTP queries return through a read-only path before schema initialization, reconciliation, alarms or persistence. Command bodies are fully parsed before a mutation persists a watchdog alarm, then reloads after storage awaits. Acceptance does not rely on a best-effort enqueue. Alarm processing persists reconciliation and re-arms its watchdog BEFORE Queue publication. Ready rows remain the outbox until claimed; uncertain sends can republish. A queue outage leaves a durable future alarm rather than depending only on the platform's finite automatic alarm retries. Reconciliation recovers expired leases with a new generation; stale results cannot overwrite current state. Queue messages contain tenant/task ID/generation only.

The consumer claims before the in-process signed callback and persists its result before ack. Application retry lives only in the ledger; transport retries only recover infrastructure failures. A crash after external success but before result commit could duplicate delivery once real HTTP is implemented. Lease expiry is an uncertain attempt, not proof that no side effect occurred.

Proposed defaults: lease 30s; 4 concurrent attempts per tenant by default (now configurable); 5 attempts; retry age one day after initial due time; exponential backoff capped at 60s with deterministic bounded jitter. 408/425/429/5xx and unknown timeouts retry, other non-2xx stop. Retry-After support and rate fairness remain deferred. Dedupe remains throughout the active lifetime plus 30 days after termination; terminal task/attempt/payload rows then purge together. Purge is driven by alarms. No payload/response/authorization logging is performed. Tenant-owned reads currently return the supplied body.

## Boundaries still required before beta

Actual HTTPS delivery, runtime DNS-rebinding proof and verified destination enrollment; bounded real HTTP timeout/headers/body and key rotation; production API-key provisioning, enrollment and recovery; multiple named queues and measured rate/fairness/load controls; DLQ operational reconciliation; normalized SQL/index migration and load limits; full failure injection, noisy-neighbor and restart suites; metrics; capacity evidence; hosted landing/docs/API; deployment and DNS review. Do not close all backlog issues based on this slice.

## CQRS

`application::Command` and its command handler own enqueue/cancel/redrive mutations. `application::Query` and its read-only handler own task/status/history/list DTOs. Both use the tenant's authoritative SQLite ledger in this MVP, so a query after a successful command reads committed state; there is no asynchronous projection, dual write, event sourcing, or extra read database. Default-queue configuration now has a separate CQRS command/query path; see [ADMISSION.md](ADMISSION.md).

## Callback signing contract (fixture proof only)

Future HTTP callbacks use POST with the unchanged UTF-8 body and these proposed headers: `RunLater-Task-Id` (tenant-qualified task ID), `RunLater-Operation-Key` (business identity), `RunLater-Timestamp` (UTC seconds), and `RunLater-Signature` (lowercase hex HMAC-SHA256). Exact signed bytes are ASCII `timestamp.task_id.operation_key.` followed by the raw body bytes. Identifiers are restricted to avoid separator ambiguity. Ordinary retries retain task ID and operation key; redrive gets a new task ID and retains operation key. Verification uses constant-time MAC checking and a ±300-second replay window. Receivers must additionally persist operation-key deduplication across attempts and redrives; a timestamp check alone cannot stop replay within the window. Public fixture keys only prove encoding/verification, not real HTTP or secret management.

## Sources and capability evidence

- Released SDK source: `worker 0.8.7` / `worker-sys 0.8.7` from crates.io, SQL `exec`/typed cursor, DO storage alarms, Queue send and MessageExt ack/retry compiled to Wasm.
- [Cloudflare alarms](https://developers.cloudflare.com/durable-objects/api/alarms/): one alarm per object, at-least-once, finite automatic retries. Explicit watchdog recovery is required.
- [SQLite API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/): one synchronous SQL upsert gives this bounded snapshot an atomic mutation; no explicit SQL transaction commands.
- [Local Queue development](https://developers.cloudflare.com/queues/configuration/local-development/): local emulator can exercise producer/consumer flow; real consumer concurrency is not proven locally.

All reported evidence is local/native/Wasm unless explicitly marked otherwise. No deployment or production durability claim follows from compilation.

During the local spike, integration caught and corrected two runtime-specific defects: workers-rs `set_alarm(i64)` expects a **relative offset**, and status polling must never postpone an earlier due alarm. The integration suite continuously polls while real local alarm/Queue dispatch completes, guarding against both. It also caught the immediate-task retry-age baseline: omitted/zero scheduling remains stable in the canonical idempotency fingerprint while a separately persisted initial due timestamp starts the delivery age budget at acceptance.

Reviewer regression commands (with local emulator running): `node scripts/query-readonly.mjs` checks actual durable SQLite schema/ledger/alarm immutability across HTTP GETs; `node scripts/delayed-body.mjs` overlaps a streamed request body with an earlier scheduled alarm. Redrive dedupe uses a separate nested parent/key map, checks fingerprint and lineage, and survives source retention expiry while the new execution remains retained.

Default-queue admission and durable dispatch rate/concurrency controls are documented in [ADMISSION.md](ADMISSION.md). All source and endpoints remain local-fixture-only.

Project-scoped action permissions, nonproduction key issuance/revocation/rotation and redacted lifecycle audit are now implemented in [AUTH.md](AUTH.md). Run `node scripts/key-lifecycle.mjs` against a fresh local emulator store. These tests deliberately use public fixture credentials; production key provisioning remains gated.

Tenant-scoped read-only operational views and explicit retention maintenance are described in [OPERATIONS.md](OPERATIONS.md).

For a runnable local client, pure receiver demonstration and an executable OpenAPI parity suite, see [QUICKSTART.md](QUICKSTART.md).
