# Local verification checkpoint — 2026-10-27

Passed on this Mac with Rust 1.92.0, released worker/worker-build 0.8.7 and Wrangler 4.154.0:

- `scripts/check.sh`: 15 meaningful native Rust tests, doc-test compilation, Wasm target check, rustfmt, 2 Node redirect tests.
- `scripts/build.sh`: release Wasm build, wasm-bindgen and wasm-opt bundle completed.
- `npm run test:local` against `wrangler dev --local`: real local SQLite DO + alarm + Queue producer/consumer + signed in-process fixture + committed result; create idempotency with omitted schedule, conflict detection, tenant denial, all real destinations rejected, retry, linked redrive retaining operation key, cancellation, task list, future schedule, unauthorized access. Passed.
- Manual persisted-state process restart: created a task scheduled 15 seconds ahead, stopped the emulator process, restarted with the same `.wrangler` state, observed exactly one recorded successful attempt through Queue; repeated create with the original key returned the original task. Passed.

Integration initially exposed the released alarm API's relative-offset semantics, starvation from postponing alarms during polling, and immediate scheduling's delivery-age baseline. All were corrected; the final integration suite passed with continuous polling.

No production deployment, live Cloudflare binding, DNS change, credential provisioning, live callback, production capacity benchmark, or SLA validation was performed. This does not close the full backlog. Remaining launch gates are listed in LOCAL.md.

## Independent review follow-up

Corrected the reviewer-confirmed CQRS HTTP query mutation and enqueue/redrive dedupe namespace collision. HTTP GET paths now return through an immutable handler before schema initialization, alarms, reconciliation or save; schema initialization occurs only on command/alarm paths. The runtime reads SQLite schema metadata without CREATE on empty query stores.

Redrive dedupe is a structurally separate parent→key mapping, validates fingerprint and lineage, and resolves an existing execution before requiring its source task. This preserves replay after the source expires while the redriven task remains active. An additive command/alarm migration preserves historical linked executions from the first local snapshot format.

Passed four additional Rust regressions: malicious enqueue-key collision, corrupt redrive fingerprint/lineage, replay after source-retention expiry, and migration preserving ordinary enqueue identities. Full local integration passed again. `node scripts/query-readonly.mjs` compared all local DO SQLite schema/data/alarm metadata before and after actual HTTP list/task/attempt/not-found queries and found no changes. `node scripts/delayed-body.mjs` exercised a slow streamed request overlapping an earlier alarm; both local tasks delivered.

Parsing now completes before the durable watchdog is armed; there is no non-storage await between that watchdog and ledger load/mutate/save. The hypothesized final-rearm failure/crash boundary is not fully fault-injected by these tests; it remains part of the broader reliability gate. No independent reviewer approval is claimed for the follow-up SHA until re-review.

Local scripts, rust-toolchain.toml and CI now consistently pin Rust 1.92.0; moving stable overrides were removed. Native/Wasm checks and the release Worker bundle were re-run with the named pinned toolchain.

## Admission hardening slice

The subsequent local slice adds tenant-wide default queue configuration, durable token-bucket rate gates, configurable expiring concurrency and active/payload admission, stricter authentication/tenant/internal DTO validation, and deterministic persisted-state recovery regressions. See ADMISSION.md for exact scope, proposed values and local commands. No multiple-queue or production concurrency/load proof is implied.

Hardening verification on this Mac passed: **31 native Rust tests** (15 ledger, 11 limits/authentication, 5 recovery), Wasm compilation, release Worker bundling, 2 redirect tests, the full existing local integration suite, new real Queue dispatch pacing/admission/tenant validation integration, and unchanged-SQL query/delayed-body regressions. An initial admission-harness run correctly encountered a short retry left by the prior suite; the harness now waits for an idle local fixture tenant and follows pagination. The final sequential suite passed. Local emulator checks remain distinct from deterministic state-restart tests and from unperformed live failpoint/load proofs.

PR #16 test reproducibility follow-up: admission fixtures now use distinct alpha/beta payload and operation-key markers and compare forged-header reads with each authenticated tenant's actual owned result. On a fresh emulator store, `RUNLATER_REQUIRE_COINCIDENT_IDS=1 node scripts/admission.mjs` explicitly required both first tasks to be `task_0000000000000001` and passed isolation plus the full admission/rate suite. Standard checks still pass (31 native tests, Wasm compilation, 2 redirect tests). Product source is unchanged by this test correction.
