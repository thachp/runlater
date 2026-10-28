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

## Local key lifecycle slice

Added project-bound verifier checks, six distinct action permissions, hash-only key state, redacted mutation receipts for actors without read, revoke/rotation overlap and cutover, immutable replay identities and bounded audit. The lifecycle integration passed through the actual local SQLite Worker/DO path with public fixture credentials. Prior task/admission/Queue/query/body regressions passed with the same isolated emulator state. Key/audit queries are included in the read-only SQL regression; the harness now requires an actual ledger and accepts RUNLATER_STATE_DIR for alternate persistence directories, avoiding a vacuous comparison against a different or empty store. No production credentials or real outbound HTTP were introduced.

Final local auth checkpoint passed: **47 native tests** (16 auth, 15 ledger, 11 limits, 5 recovery), Wasm check, release Worker bundle and 2 redirect tests. Actual local HTTP/SQLite lifecycle tests passed, including mutation-only receipts omitting task payload/history, all six operation permissions, revocation and rotation replay/cutover; existing enqueue/Queue/retry/redrive/admission/pacing/body tests passed. Query comparison included key/audit endpoints and used the exact isolated emulator store with a nonempty-ledger guard. These are local/nonproduction proofs, not production credential or live-runtime safety claims.

## Review-only disposable staging patch

Prepared mandatory outer gate, synthetic-only admission, finite task/publication/deadline limits and separate signed controlled receiver. Only read-only existing-account inventory was performed; zero live resources or real staging secrets were created. The US$5 worst-case budget is blocked by unverified DO allowance and official overage rounding; see staging/README.md and staging/manifest.json. Live execution is not released by this patch.

Staging review checks passed: 52 native tests, default and staging-feature Wasm checks, staging release bundle, 2 redirect tests and 3 receiver protocol tests. Actual local staging API tests proved no-gate/wrong-gate aliases cannot parse malformed bodies or allocate a task DO, then exercised local alarm/Queue state with egress disabled and the 12-task cap. The dedicated receiver also passed a real local workerd/Web Crypto signed request and domain-separated receipt check. These are local proofs only; no live HTTPS validation or spending took place.

PR #18 reviewer follow-up: staging now accepts only explicit canonical routes and validates the parsed Enqueue command independently of raw spelling. Native and actual local staging regressions reject trailing/duplicate slashes, encoded route variants, nonsynthetic/oversized payloads and distant schedules; URL-layer-normalized dot segments still receive the typed envelope checks. Receiver gate inputs must match the same exact ASCII 64-hex format as the expected value, so Unicode/wrong-length/malformed headers return403 without timingSafeEqual length exceptions. Cleanup documentation now explicitly describes a manual foreground operator procedure, including exact returned IDs and uncertain partial-deployment checks; no automatic provider-resource ledger/finally driver is claimed.

Reviewer-fix checks passed: 54 native tests, default/staging Wasm checks and 6 Node tests (2 redirects, 4 receiver), plus the actual local canonical-route/envelope regression. Destination rejection retains the existing 422 contract. The user approved USD20 incremental risk, but live execution is not released; planning estimates and unimplemented aggregate counters are explicitly identified in the manifest. No live resources or real secrets were created.

Risk-gate follow-up: execution now checks explicit approved-risk acknowledgements, reviewed finite campaign limits, exact checkout SHA/phase and parent live release instead of requiring a false billing certificate. Committed release remains false. Queue publication reservations are a durable cap; configured max_retries=1 is not represented as a hard two-delivery guarantee, and aggregate DO/SQL/CPU totals remain conservative estimates. Five pure authorization tests cover missing/false approval, SHA/phase mismatch and expanded limits; no live mutation occurred.

Compiled local process-interruption/exception evidence and its limits are in [RUNTIME-RECOVERY.md](RUNTIME-RECOVERY.md). Run `npm run test:runtime-recovery`; it uses only fresh owned local stores and restores a normal artifact afterward.

## Transport reconciliation increment (offline)

The bounded transport-diagnostic/reconciliation slice passed 86 native tests, including 8 new transport tests, default Wasm checking and the shared 11 Node redirect/receiver/authorization tests. The expanded contract passed all 23 operations through 139 bounded local HTTP calls. The actual compiled local Queue/DLQ harness passed exhaustion before claim and after durable completion, recovery from the authoritative outbox, terminal/schedule protection, scoped permissions, malformed/foreign references, query immutability, clean SQLite/workerd restart and receipt replay (41 bounded API calls plus direct local Queue/private-binding operations). Failures in that harness are injected exceptions, not process interruption or cloud failures. The existing five runtime recovery cases also passed, including two actual local SIGKILL cases. Example client tests (5) and Rust/Node callback-wire tests (6) passed. The metrics local SQLite/restart suite passed. See [transport semantics and limitations](TRANSPORT-RECOVERY.md); no live DLQ or provider resource was provisioned, and launch/runtime validation remains open under #7/#11; #8's original local component criteria are complete.

Default and staging release bundles also passed; all 10 offline staging wire cases passed with local receiver bindings, and the final default artifact passed the no-runtime-hook marker check.

## Durable pause/resume increment (offline)

94 native tests passed, including 8 new pause tests; default Wasm checking and 11 shared Node tests passed. All 23 OpenAPI operations passed through 151 bounded local HTTP calls, including explicit paused input, omitted-field rejection, health projection and example client pause/resume helpers. The compiled local Worker/SQLite/Queue/alarm pause suite passed through 78 bounded HTTP calls: queued-reference pause race, already-started publication across pause, in-flight completion, retry due during pause, identity-preserving resume, cancellation, restart, read/tenant isolation and pure SQL/schema/alarm query checks. Idle paused work produced no repeated ready publication/pump loop. An old timestamp was seeded only into an owned stopped SQLite fixture to verify actual alarm age expiry; elapsed age is simulated, not a day-long or live test.

Existing five runtime interruption cases (including both actual SIGKILL cases), local transport exhaustion/reconciliation, metrics persistence, 5 example tests and 6 callback-wire tests also passed. Default/staging release builds and all 10 offline staging wire cases passed. Wrappers restored the default artifact and verified private hook absence. No live resources, secrets, DNS, callbacks or billing/payment changes occurred. Queue PUT now requires an explicit paused boolean; old stored snapshots migrate to false without a query write. Live launch/runtime proof remains separate under #7/#11.

## Source-only agent discovery increment

Eight discovery tests passed: strict descriptor/pricing/tool schemas; unique local/proposed tool coverage; byte-identical canonical OpenAPI and derived input/header/path/scope parity; every planned descriptor/schema/Markdown/HTML link mapped to the correct assembled host tree; valid/invalid local DTO fixtures; disabled nonbinding proposal shapes; rejection of accidental hosted execution/payment activation; deterministic rebuild/stale-output cleanup and refusal to overwrite unrelated output; no builder network calls. These are offline link-consistency checks, not live URL availability or a registration/payment/delivery test.

Static artifact assembly passed. Standard checks passed with 94 native tests, default Wasm check and 11 shared Node tests; 5 local example and 6 Rust/Node callback-wire tests passed. Rust runtime and API behavior are unchanged. No host, provider resource, secret, credential, billing policy or live service was changed. See AGENT-DISCOVERY.md and AGENT-NEXT.md; public hosting and functional onboarding remain separate work.
