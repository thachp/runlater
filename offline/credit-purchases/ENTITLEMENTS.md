# Atomic fixture trial and prepaid task admission

Source-only increment for [#28](https://github.com/thachp/runlater/issues/28). The `entitlements::Entitlements` aggregate is **not a dependency of the Worker** and has no HTTP routes, network I/O, default commercial terms, public identity issuer, provider verifier, or live activation path. It composes the existing `runlater::core::Ledger`, `funding::State`, and `OfflineLedger`; it does not implement a second task or attempt-accounting engine. The only shipped payment verifier still rejects every claim.

## Immutable trial and purchase policy

Construction accepts an optional explicit `TrialTerms { task_allowance, duration_ms }`, an optional synthetic purchase `Policy`, and trusted server time. `None` grants nothing. Duration, allowance, and all purchase values are configurable fictional inputs, **not approved trial or commercial values**.

The trial's start, expiry, task allowance, and grant identity are fixed at aggregate creation. Each newly accepted trial-funded task consumes one lifetime trial task slot and reserves all five attempt units. Cancel/terminal settlement can return unused attempt units under the existing funding rules, but **never restores a trial task slot**. Replay consumes no additional slot; redrive creates a distinct task requiring new funding. No trial replacement/reset method exists. Restart restores the same trial identity and counter. This is per-project reset resistance, not proof against deleting authoritative storage, creating another project, or Sybil onboarding; the future issuer must prevent those resets.

Purchase authority remains separate from task authority. Creating an intent does not fund a task; only a successfully verified **fixture** settlement can issue credits. Neither `paid=true`, a client projection, nor scheduling permission can issue credits. Partial refunds remain rejected by the underlying purchase model. Refund/reversal keeps gross spending-cap consumption, closes unused admission credit permanently, and does not remove already accepted reservations.

The aggregate reserves lifetime grant-identity capacity and JavaScript-safe total-unit headroom **when the purchase intent is accepted**, including pending/unpaid intents. A trial consumes one of the 32 lifetime grant slots, leaving at most 31 purchase identities; identities are never recycled. An idempotent purchase retry still resolves at the bound. These checks prevent accepting a quote that cannot later receive its complete synthetic grant.

## One authoritative commit boundary

All mutating commands require the aggregate's current expected revision. They validate a clone and replace the aggregate only at commit. A future host must persist **the entire snapshot with a durable compare-and-swap/serialized project transaction** before acknowledging; separate writes for the purchase journal, cursor, funding, task, or idempotency evidence are prohibited. Revision checking on an in-memory clone is not distributed locking or durable database CAS.

The purchase journal's revisions are remapped into a private aggregate funding-policy sequence, preserving every ordered grant/revocation without colliding with trial installation or task-time grant selection. On fresh acceptance, selection prefers an eligible trial slot, then an open purchased grant with enough units, ordered by earliest admission expiry and grant ID. Older unspent purchased grants are not hidden by a newer settlement. A reservation is funded entirely by one grant; fragmented balances are **not pooled**.

Create/redrive first resolves task idempotency on the clone, then selects and reserves funding. A previously accepted replay succeeds using its existing reservation, even after expiry/depletion/reversal. Fresh valid requests with no usable funding return exactly:

```json
{"task_accepted":false,"funding_reserved":false,"created":false,"error":{"code":"payment_required"}}
```

There is no task ID, task row, sequence increment, dedupe entry, reservation, purchase, or trial-use increment from that denial. It does commit the observed monotonic time and any expiry retirement on a fresh copy of the prior state. This is intentional: a denied request observed after trial expiry must not reopen the trial after restart plus clock rollback. A future HTTP adapter should map this decision to 402, without a payment URL, challenge, or payment authority inferred from this offline decision. Existing Worker error codes are **unchanged** by this source increment.

Claim/outcome/cancel use the same existing finite accounting and fenced task transitions. One committed claim spends once, duplicate/stale references do not double-spend, and uncertain effects remain spent. Rate/concurrency-denied claims still commit unrelated reconciliation/terminal funding settlement. Terminal unused units return only to an open source grant; after expiry or reversal they retire. None of these internal unit dispositions promise a monetary refund.

## Queries, restoration, and bounds

Balance and task/reservation queries are project-scoped read-only views. Balance includes its source revision/time, `activation_enabled=false`, and `fixture_only=true`. `available_attempt_units` is an accounting total, **not** necessarily admissible task capacity: trial slots may be exhausted or residual units fragmented across grants. `admissible_tasks` applies each grant's finite five-unit requirement and the remaining trial slot limit. A read does not advance persisted time, reserve funds, or authorize a later write.

Public deserialization and `restore` both validate the aggregate, including immutable trial terms/start/expiry, task-to-reservation/fence/terminal consistency, purchase cursor, grant specs and required closure after expiry/reversal. Snapshots are trusted storage formats, never entitlement/payment request bodies. Restore input is capped at 2 MiB. Existing ledger/funding bounds apply, including 1,000 retained tasks and 128 KiB total payload; this increment deliberately has no task/history purge or policy rollover. Capacity exhaustion fails closed and needs a reviewed migration rather than tombstone deletion.

## Evidence and remaining work

Run the existing crate checks; its existing CI workflow includes this module automatically:

```sh
cargo fmt --manifest-path offline/credit-purchases/Cargo.toml -- --check
cargo test --locked --manifest-path offline/credit-purchases/Cargo.toml
cargo check --locked --manifest-path offline/credit-purchases/Cargo.toml --target wasm32-unknown-unknown
```

The entitlement fixture suite covers exact denial/no partial acceptance, trial cancellation/reset resistance, purchase→original-task retry, immutable settlement replay, older purchased-grant fallback, 16-thread last-budget contention under a mutex, restored accepted reservations after expiry/reversal, one-spend claim behavior, long scheduling, read immutability, authority/tenant separation, redrive funding, invalid terms/overflow/stale revisions, sticky rejected expiry, corrupt snapshot rejection, rate-denied reconciliation, and quote-time capacity/headroom reservation.

These are native model and serialized snapshot tests, **not actual process-kill, SQLite/Worker transaction, Queue, cloud concurrency, identity authentication, provider settlement, or live payment evidence**. The 16-thread mutex test demonstrates expected-revision semantics, not a durable storage implementation. No provider calls, credentials, purchases, hosted API changes, MCP changes, deployment or real funds occur here.

Keep #28 open for authoritative Worker persistence/authentication integration and agreed commercial policy. #29 still needs real provider verification/reconciliation and merchant eligibility; #30 needs scoped entitlement/action routes; #31 needs the complete approved end-to-end journey. A new host must also authenticate task/purchase authorities, prevent project/trial reset abuse, persist denied-time and limited-claim observations, enforce durable CAS, and supply trusted server time. This source aggregate is not authorization to perform any of that live activation work.
