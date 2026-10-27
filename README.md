# RunLater

RunLater is a reusable HTTP task delivery API with a local prototype built in **Rust on Cloudflare Workers**. Other systems will be able to submit work now and have RunLater deliver a signed HTTP request later, with bounded retries and a record of each attempt.

Product domain: **runlater.io**. Domain registration does not mean a hosted service is available.

## Status

**Early local prototype; not production-ready.** The repository includes a tested Rust/Cloudflare fixture-only vertical slice and the proposed product backlog. The architecture and delivery semantics below describe the broader design targets; they are not a claim that the full MVP is implemented. Real outbound HTTPS delivery is disabled. There is no published SLA, production endpoint, or verified capacity claim. See [local setup and limits](docs/LOCAL.md) and [verification evidence](docs/VERIFICATION.md).

## Current local capabilities and launch gates

Merged [#15](https://github.com/thachp/runlater/pull/15), [#16](https://github.com/thachp/runlater/pull/16), and [#17](https://github.com/thachp/runlater/pull/17) establish the following **local-fixture-only** capabilities:

- CQRS command and read-only query handlers over one authoritative, tenant-scoped SQLite Durable Object ledger.
- Durable acceptance/deduplication, alarm-driven ready/outbox recovery, Queue dispatch, expiring fenced leases, bounded retries, cancellation, and linked **failed-task** redrive. Callbacks are signed in-process fixtures, not network requests.
- One configurable default queue per project, active-task/payload admission, durable token-bucket dispatch limits, expiring concurrency capacity, and structured throttling metadata. Retries share the same limits.
- Project-scoped action permissions and hash-only local key issuance, revocation, rotation overlap/cutover, redacted receipts, and bounded lifecycle audit. No production credentials are provisioned.

See [local setup](docs/LOCAL.md), [admission controls](docs/ADMISSION.md), and [local authentication](docs/AUTH.md). The pilot uses a bounded versioned SQLite snapshot, not a production-scale indexed task store. The broader design below includes planned capabilities beyond this slice, including real HTTPS and any expansion of redrive eligibility.

**Verification checkpoint — 2026-10-27:** the merged key-lifecycle slice records 47 native Rust tests, 2 redirect tests, Wasm compilation and release bundling, plus codeowner-run local HTTP/SQLite/Queue integration suites. Independent QA reported 15 additional adversarial probes, and reviewed-head CI passed. These are checkpoint results, not a permanent test-count or production guarantee. This README update did not independently rerun the emulator. Details and earlier checkpoints are in [verification evidence](docs/VERIFICATION.md).

**Still gated:** real HTTPS callbacks and connection-target/DNS-rebinding defenses; production key enrollment, secret delivery/recovery and callback-key rotation; live-runtime failure injection, prolonged outages, measured fairness/noisy-neighbor capacity; operational metrics and durable audit policy; and hosted service/DNS/deployment readiness. External HTTPS delivery remains disabled, and no hosted service is available.

## Planned hosts

| Host | Intended role |
| --- | --- |
| `runlater.io` | Product landing page |
| `docs.runlater.io` | Developer documentation |
| `api.runlater.io` | HTTP API |
| `www.runlater.io` | Redirect to `https://runlater.io`, preserving path and query |

This is the confirmed host layout, not a deployment claim. DNS, routes, certificates, and live service readiness still need verification before launch. See [issue #13](https://github.com/thachp/runlater/issues/13).

## Proposed MVP

- Create an immediate or one-time scheduled HTTP task.
- Read task status, list tasks, and inspect delivery attempts.
- Cancel pending work and explicitly redrive eligible terminal tasks.
- Authenticate with project-scoped API keys and enforce tenant isolation.
- Deliver signed HTTPS callbacks with bounded retries, rate limits, and concurrency controls.
- Keep auditable outcomes without logging credentials or sensitive payloads by default.

Recurring cron schedules, workflow orchestration, a full dashboard, billing, and language-specific SDKs are outside the first MVP. The versioned API contract, limits, and retention policy will be finalized in [issue #1](https://github.com/thachp/runlater/issues/1); a local-only fixture prototype and setup commands are now available in [docs/LOCAL.md](docs/LOCAL.md). The hosted service and real HTTPS delivery remain unavailable.

## System design

RunLater uses **CQRS (Command Query Responsibility Segregation)**: distinct command and query interfaces and handlers over a **tenant-scoped Durable Object with SQLite storage**, which remains the authoritative task ledger. Cloudflare Queues transports due work; it does not own task state or serve as long-term scheduled storage.

```mermaid
flowchart TD
    Client["Customer application"]
    API["Rust API Worker: authenticate and authorize"]
    Commands["Command handlers: enqueue, cancel, redrive, configure"]
    Queries["Query handlers: status, attempts, paginated lists"]
    Ledger["Tenant-scoped Durable Object: SQLite task ledger, attempts, outbox, leases"]
    Alarm["Durable Object alarm: wake for next due work"]
    Queue["Cloudflare Queues: task identifiers and dispatch generation"]
    Consumer["Rust delivery consumer: claim lease and enforce limits"]
    Guard["Outbound boundary: safe HTTPS destination and signed request"]
    Endpoint["Customer callback endpoint"]
    Reports["Optional derived reporting: not authoritative"]

    Client -->|"Create, inspect, cancel, redrive"| API
    API -->|"Validated mutation commands"| Commands
    API -->|"Tenant-scoped read queries"| Queries
    Commands -->|"Durable writes and state transitions"| Ledger
    Queries -->|"Read-only access to authoritative state"| Ledger
    Ledger -->|"Arm earliest due time"| Alarm
    Alarm -->|"Reconcile due work and re-arm"| Ledger
    Ledger -->|"Publish durable outbox entries"| Queue
    Queue -->|"At-least-once transport"| Consumer
    Consumer -->|"Claim or reject stale dispatch"| Ledger
    Consumer --> Guard
    Guard -->|"Bounded HTTPS request"| Endpoint
    Endpoint -->|"Response or timeout"| Consumer
    Consumer -->|"Persist outcome using lease token"| Ledger
    Consumer -->|"Acknowledge only after durable disposition"| Queue
    Ledger -.->|"Redacted events"| Reports
```

### CQRS boundaries

- **Commands** validate and change state: enqueue, cancel, redrive, and queue configuration. Their DTOs and handlers are separate from queries. Internal attempt claims and outcomes also use the command side so consumers cannot bypass state-transition rules.
- **Queries** read task status, attempt history, and paginated lists through tenant-scoped, read-only handlers. They must not mutate business state.
- **One authority for the MVP.** Both sides can use the same Durable Object storage through separate interfaces. CQRS does not require event sourcing or a separate physical read database.
- **Consistency is explicit.** Command success means the mutation is durably accepted; responses should include the identifiers and state/version needed for the API read-after-write contract. Any future asynchronous read projection must disclose lag and source versions, apply updates idempotently, and support ordering, rebuilds, and deletion propagation. Such a projection is not a second task authority.

The local CQRS implementation and separation-test scope is complete in [issue #14](https://github.com/thachp/runlater/issues/14). Broader production and consistency gates remain separate.

### Delivery path

1. **Accept durably.** Authenticate the project, validate the request and destination policy, then commit the task, create-request deduplication record, and required outbox/scheduling work before returning success.
2. **Schedule from the ledger.** Store future timestamps in SQLite. Each Durable Object has one alarm, so it wakes for the earliest due work, processes a bounded batch, and re-arms itself. Alarms can run more than once; reconciliation must be idempotent. See [Cloudflare alarms](https://developers.cloudflare.com/durable-objects/api/alarms/).
3. **Publish through an outbox.** Send identifiers and a dispatch generation, not the full customer payload, to Queues. Preserve recoverable intent across uncertain enqueue outcomes; duplicate publication is safe only because the ledger rejects stale or duplicate claims.
4. **Claim before delivery.** The consumer obtains an expiring lease with a fencing token, checks cancellation and retry budgets, and acquires tenant rate/concurrency capacity. Old messages must not trigger a newer task generation.
5. **Send and record.** Validate the outbound destination, sign the request, and enforce a timeout. Persist the result or retry decision before acknowledging the transport message. A duplicate message for already-resolved work is acknowledged without another callback.
6. **Recover.** Reconcile expired leases, stranded outbox entries, and due work after failures. An expired lease permits recovery but cannot prove that an earlier HTTP request had no effect.

Optional reporting stores are derived views, never a second authority for scheduling or state transitions. Per-tenant limits, retention, and sharding need measured capacity tests before any scale claims.

### Rust and platform validation

The local runtime uses Rust 1.92.0, released worker/worker-build 0.8.7, and Wrangler 4.154.0 with locked dependencies. The [workers-rs](https://github.com/cloudflare/workers-rs) compatibility spike in [issue #2](https://github.com/thachp/runlater/issues/2) is complete for the local prototype: HTTP handling, SQLite Durable Objects, alarms, Queue publishing/consumption, acknowledgement, and persisted emulator restart were exercised. This is local/native/Wasm evidence, not live Cloudflare deployment or production reliability proof; see [verification evidence](docs/VERIFICATION.md).

## Task state diagram

Proposed task states are separate from transport-message status and individual attempt records.

```mermaid
stateDiagram-v2
    [*] --> scheduled: accepted with a future time
    [*] --> ready: accepted for immediate delivery
    scheduled --> ready: due time reached
    ready --> running: lease and capacity granted
    running --> succeeded: success durably recorded
    running --> retry_wait: retryable outcome within budgets
    retry_wait --> ready: retry time reached
    running --> failed: permanent error or budget exhausted
    ready --> failed: delivery age budget exhausted
    retry_wait --> failed: delivery age budget exhausted
    scheduled --> cancelled: cancellation accepted
    ready --> cancelled: cancellation accepted before claim
    retry_wait --> cancelled: cancellation accepted
    running --> cancelled: cancellation requested and attempt settles without recorded success
    succeeded --> [*]
    failed --> [*]
    cancelled --> [*]

    note right of running
        Cancellation sets a flag while an attempt is in flight.
        It cannot undo an external effect.
        A recorded success may still win the race.
    end note
    note right of failed
        Explicit redrive creates a new linked task.
        Terminal history is never reset in place.
    end note
```

| State | Meaning |
| --- | --- |
| `scheduled` | Accepted durably; initial scheduled time is still in the future. |
| `ready` | Eligible for dispatch, subject to tenant capacity and cancellation checks. |
| `running` | A leased attempt is active; the destination may already have received it. |
| `retry_wait` | Waiting for the next permitted attempt after backoff. |
| `succeeded` | A successful HTTP response was recorded; this is not proof of downstream business completion. |
| `failed` | A non-retryable outcome or an exhausted delivery budget stopped further attempts. |
| `cancelled` | No further attempts will be started; a previous or in-flight request may still have had an effect. |

### Retries, cancellation, and redrive

- The ledger owns the application retry policy: bounded exponential backoff with jitter, an attempt limit, and an age limit. Timeouts and uncertain outcomes may require another attempt. HTTP status classification and bounded handling of `Retry-After` belong in the API contract.
- Transport retries recover infrastructure failures; they must not create a second independent application retry loop. Fencing prevents stale workers from overwriting newer ledger state, not from causing an already-sent external effect.
- Cancellation before an attempt is claimed prevents that attempt. While `running`, it records `cancel_requested` and suppresses future retries; it does not promise to abort the HTTP request. The attempt is allowed to settle, with success taking precedence if durably recorded. Expired leases need reconciliation and truthful uncertainty in attempt history.
- Explicit redrive of an eligible `failed` or `cancelled` task creates a **new task ID linked to the original**, with a fresh attempt budget. It never resets terminal history. Customers must understand that replay can repeat an effect whose earlier outcome was uncertain.

## Delivery contract and idempotency

The target is **at-least-once delivery attempts within configured budgets**, not guaranteed eventual success. There is no exactly-once processing, FIFO ordering, or exact-time execution promise. Cloudflare Queues itself can deliver messages more than once; see its [delivery guarantees](https://developers.cloudflare.com/queues/reference/delivery-guarantees/).

Two different forms of idempotency matter:

- **Create-request deduplication:** a project-scoped idempotency key with the same request returns the original task during a documented retention window. Reusing it with different content is a conflict. This prevents duplicate task creation, not duplicate callback effects.
- **Callback idempotency:** automatic retries carry a stable task-level identity, while each attempt has its own identity. The receiver should atomically deduplicate the business operation with its side effect. Explicit redrive has a new task identity. Supply a customer-defined business-operation key in the top-level `operation_key` field when creating the task; RunLater preserves this key across automatic retries and redrive and delivers it in the signature-covered `RunLater-Operation-Key` header. The receiver can use that stable key to deduplicate across redrives without changing the payload.

If the customer processes a callback but RunLater crashes before recording success, the callback can be sent again. Receiver-side idempotency is required even with leases, signatures, and queue deduplication.

## Security and release gates

- Authorize project ownership on every API and internal ledger operation. Store API-key hashes, support rotation/revocation, and test cross-tenant access failures.
- Require approved public HTTPS destinations. Reject local, private, link-local, metadata, and disallowed address forms, including IPv6 variants. Disable redirects by default. URL parsing alone is not an SSRF defense.
- **Prove DNS-rebinding and actual connection-target defenses in the deployed Workers runtime before enabling arbitrary destinations.** Until that evidence exists, any restricted alpha must use controlled, independently validated endpoints. An allowlist alone does not prevent DNS rebinding; runtime egress validation remains a release gate for arbitrary destinations.
- Sign callbacks with a timestamp and key identifier; document receiver verification, replay windows, and key rotation. Keep authorization credentials out of logs and URLs.
- Bound request/response sizes, header handling, timeouts, scheduling horizon, attempts, retention, and tenant resource use. Final defaults remain open decisions.
- Test failures between persistence, enqueue, claim, callback, result recording, and acknowledgement. Add duplicate-delivery, lease-expiry, cancellation-race, rate-limit, SSRF, and tenant-isolation tests before public beta.

## Implementation backlog

This tracks both completed local foundations and remaining MVP work. Issues #2 and #14 are closed for their bounded local scope; other entries can contain implemented slices without satisfying their full launch criteria. Consult each issue for current progress.

| Issue | Work |
| --- | --- |
| [#1](https://github.com/thachp/runlater/issues/1) | MVP API contract and delivery guarantees |
| [#2](https://github.com/thachp/runlater/issues/2) | Pinned Rust and Cloudflare runtime spike — local scope complete |
| [#3](https://github.com/thachp/runlater/issues/3) | Project authentication and tenant isolation |
| [#4](https://github.com/thachp/runlater/issues/4) | Durable ledger, deduplication, and outbox |
| [#5](https://github.com/thachp/runlater/issues/5) | Alarm-based scheduled dispatch |
| [#6](https://github.com/thachp/runlater/issues/6) | Delivery leases and crash-safe consumers |
| [#7](https://github.com/thachp/runlater/issues/7) | Destination security and callback signing |
| [#8](https://github.com/thachp/runlater/issues/8) | Retries, cancellation, and explicit redrive |
| [#9](https://github.com/thachp/runlater/issues/9) | Quotas, rate limits, and concurrency fairness |
| [#10](https://github.com/thachp/runlater/issues/10) | Attempts, audit events, and retention |
| [#11](https://github.com/thachp/runlater/issues/11) | Reliability and security release evidence |
| [#12](https://github.com/thachp/runlater/issues/12) | Onboarding and an end-to-end integration |
| [#13](https://github.com/thachp/runlater/issues/13) | Landing, docs, API hosts, and canonical www redirect |
| [#14](https://github.com/thachp/runlater/issues/14) | CQRS command/query boundaries and consistency — local scope complete |

A loopback-only client example, receiver protocol demonstration and executable local API contract are documented in [the local quickstart](docs/QUICKSTART.md). No account provisioning or live callbacks are required.
