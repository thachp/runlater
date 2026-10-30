# Reliability and security acceptance evidence

Tracking issue: [#11](https://github.com/thachp/runlater/issues/11). **Public-beta reliability/security acceptance remains blocked.** Passing local suites is necessary evidence, not a launch authorization, production guarantee, capacity measurement, or SLA.

## Reproducible offline acceptance

Use the pinned tools and installation instructions in [LOCAL.md](LOCAL.md), then:

```sh
./scripts/check.sh
npm run test:runtime-recovery
```

`check.sh` includes `tests/reliability.rs` automatically. For focused iteration, use `cargo test --locked --test reliability`. The recovery command rebuilds the compiled local test profile, creates only owned disposable stores/processes, and restores a default artifact with the no-runtime-hooks check. Do not deploy a runtime-test artifact.

| Acceptance surface | Reproducible evidence | What this does not establish |
| --- | --- | --- |
| Accepted ledger / enqueue boundary | `tests/recovery.rs`; recovery harness SIGKILL after SQLite acceptance before publish, then same-store replay | Cloud storage loss, provider outage or machine power loss |
| Uncertain Queue publication / duplicate callbacks | Recovery harness post-send exception, real local duplicate references, and SIGKILL after fixture result before ledger finish | External receiver business transactions; exactly-once delivery |
| Durable claim / pre-callback boundary | Recovery harness SIGKILL at the private `after_claim` gate, same-store restart, real lease deadline, higher generation/fence and one fixture invocation after recovery; `tests/reliability.rs` repeats serialized claim crashes through all five attempts and verifies new-ID redrive lineage | An HTTP request or receiver side effect; the ledger truthfully reports unknown lease loss even when the harness knows the fixture was not invoked |
| Durable finish / Queue ack boundary | Recovery harness SIGKILL while `after_finish` is held; persisted terminal attempt unchanged after restart and three explicit replay references; claim-ignored counters prove at least three replay deliveries reached the guard and no new fixture call | Provider in-flight Queue persistence/redelivery; the harness deliberately republishes references rather than assuming emulator durability; any original message redelivery can contribute to the ignored-delivery count |
| Long schedules / retention | `tests/reliability.rs`: exact 365-day boundary, purges/restarts before due, stable idempotency, due-based age expiry and termination-based retention | A year-long wall-clock trial or provider scheduler timing |
| Clock / lease timing | `tests/reliability.rs`: one millisecond before/exact lease deadline, backward clock before/after reconciliation, stale fence and old-generation rejection; `tests/limits.rs` token refill regression | Provider clock guarantees, clock synchronization or effects that outlive a lease |
| Cancel races | `tests/reliability.rs`: persisted cancel before claim or during attempt, success/429/timeout/lease-loss outcomes and duplicate replays after terminal state; `tests/pause.rs`; runtime SIGKILL after persisted cancellation at the pre-fixture gate, lease settlement to cancelled and ignored replay deliveries | Ability to retract an already-started external side effect |
| 429 storm / bounded retries | `tests/reliability.rs`: 32 tasks, 160 bounded attempts, persisted restarts, duplicate claims/results, rate/concurrency envelope, positive backoff and independent quiet-tenant ledger | Load/throughput benchmark, CPU isolation, provider fairness or Retry-After support |
| SSRF / request isolation | `tests/ledger.rs`, `tests/destinations.rs`, `tests/delivery.rs`; `npm run test:destinations`, `npm run test:delivery`, `npm run test:signed-requests` compiled local suites | Live DNS rebinding / redirect / TLS / network-enforcement proof; production policy correctness |
| Tenant / credentials / permissions | `tests/auth.rs`, `tests/limits.rs`, `tests/signed.rs`, `tests/invitation.rs`; local admission, key-lifecycle and signed-request suites | Operator credential provisioning or security review of a deployed environment |

The model campaign advances explicit timestamps; it does not sleep for the simulated duration. Its 32-task/160-attempt bounds are test workload sizes, **not supported capacity targets**. Quiet/noisy ledgers demonstrate logical state and budget separation only. The runtime fixture uses a public, in-process signing key and rejects outbound network access; it is not an HTTP customer callback.

## Remaining launch gates

All of the following remain unresolved by this increment. No unsupported availability, latency, durability, capacity or exactly-once claim should be published.

- **Durability:** authorized provider-runtime fault campaign at acceptance, publication, receiver outcome, finish and acknowledgement boundaries; storage engine errors, alarm retry exhaustion, prolonged transport outage and recovery. Preserve task/operation identities and document unknown outcomes.
- **Security:** authorized real HTTPS/destination-enrollment and DNS-rebinding/redirect/TLS tests; independent tenant/credential isolation review; production secrets and network policy verification. Existing local policy tests are not an external network proof.
- **Capacity/fairness:** benchmark the actual intended deployment/profile under representative payloads, schedules, retry storms and mixed tenants. Record version/configuration, duration, workload, offered versus achieved throughput, schedule lag/latency percentiles, duplicate/unknown outcomes, queue backlog, error rates, resource use and cost. Include recovery and quiet-tenant observations. Only after evidence and review set measurable trial SLOs/capacity limits; none are assigned here.
- **Operational decision:** record reviewed evidence and unresolved findings against the tested commit/profile. Any unresolved durability/security failure blocks public beta. A passing local suite cannot change a release flag, authorize spending/provisioning or substitute for the separate release decision.

This document records acceptance evidence and unresolved issue #11 criteria, not current deployment status or a new release controller. Live provisioning, deployment, DNS, credentials, payments and paid benchmark campaigns require separate authorization. The existing release configuration is unchanged.

## Prior offline checkpoint — PR #59, 2026-10-29

`./scripts/check.sh` passed with 173 native Rust tests, the default Wasm target check, rustfmt and 13 shared Node checks. The compiled local recovery suite passed six scenarios using ten owned subprocesses, three actual process-group kills and 24 bounded HTTP calls; the wrapper restored the default release bundle and passed the no-runtime-hooks marker check. No live resources or external callbacks were used. This checkpoint advances local evidence only and leaves the gates above unresolved.

## Claim-boundary checkpoint — 2026-10-29

`./scripts/check.sh` passed with 183 native Rust tests, the default Wasm target check, rustfmt and 13 shared Node checks. The expanded recovery suite passed eight scenarios with fourteen owned subprocesses, five actual process-group kills and 100 bounded HTTP calls on its final run, including persisted retry/settlement timestamp assertions. An earlier run passed with 99 HTTP calls before that assertion strengthening. Both runs restored the default release bundle and passed the no-runtime-hooks marker check. Independent source review found no blocking findings. All evidence is local; no live resource or external callback was used, and issue #11 remains open.
