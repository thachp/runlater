# Disposable staging patch — review first; live execution blocked

No live resource mutations or real staging secret generation were performed for this patch. Read-only inventory through the existing Cloudflare connector found the authorized account, 2 existing Workers, no Queues and 4 existing Durable Object namespaces. None uses the proposed `runlater-staging-20261027r1-*` names. Preserve every existing resource and repeat the inventory/collision check immediately before any future creation. Existing Wrangler authentication matches that account; no login, credential reading or permission expansion was performed. Billing access remains unavailable and was not retried through another interface.

## Budget amount approved; live execution still on hold

Independent research confirmed the rounding described in the [official Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/): paid duration overage can cross a $12.50 unit boundary. The user has approved **US$20 incremental staging-test risk**, acknowledging there is no guaranteed account-wide spending cap. This changes the budget amount only. **Do not create, deploy or run live resources before exact code/manifest/cleanup review and parent release.** Billing access remains unavailable and was not bypassed. No plan upgrade is authorized. Public unauthenticated traffic can incur edge usage despite the application gate.

[manifest.json](manifest.json) is the proposed resource/test manifest, not a creation receipt. No live cleanup is required yet because `live_resources_created` is empty.

## Source and security boundary

- API is built with the `staging` Cargo feature. The ingress gate is the first operation of the fetch handler, including health, unknown routes, alternate hosts and version/preview URLs. The feature keeps it mandatory even if `STAGING_MODE` is accidentally unset. Missing secrets, malformed or expired deadlines fail closed. Preview URLs are disabled in generated config as an additional restriction.
- Public fixture bearer tokens still require the independent `X-RunLater-Staging-Gate` secret. Only project alpha and task create/read/attempt/cancel paths are reachable. Key management, queue reconfiguration, redrive and other routes are disabled in staging.
- Task bodies must be <=256-byte JSON with exactly `run`, `case` and `synthetic:true`; operation identity must match. Scheduling is at most 30 seconds ahead. No customer payloads, arbitrary destinations or destination headers are accepted. Maximum 12 retained tasks bounds accepted work for this short run.
- Phase 1 uses in-process fixtures; `STAGING_DELIVERY_ENABLED` defaults false. Phase 2, only after parent review/release, may accept the symbolic `staging://receiver` destination. The actual URL is assembled from the exact operator-controlled receiver Worker hostname. It must equal its canonical HTTPS `/callback` URL, with no port, credentials, query, fragment, alternate host or customer URL.
- The controlled path sets `redirect: manual`, rejects every 3xx, uses a 3-second abort deadline, bounded response/header consumption, and a small fixed outbound header set. It sends the separate callback HMAC plus the receiver ingress gate, never customer API credentials. A domain-separated authenticated receipt proves the receiver knows the HMAC secret; merely echoing the request signature is insufficient.
- Receiver has no fetch/proxy/state path. Every route is gated before URL/body parsing; only POST `/callback` accepts a small synthetic body with timestamped HMAC and a 30-second replay window. Its only successful effect is a 204 authenticated receipt. There are no customer side effects to undo on duplicate delivery.
- Publication budget is persisted before Queue I/O; uncertain sends spend a slot. A run publishes at most 128 messages from the sole alpha DO. Consumer transport retry is 1, batch/concurrency are 1. Alarms are clamped to run expiry and stop on expiry/publication exhaustion; expired queue work is acknowledged without new DO access. The ordinary local prototype remains unchanged outside staging mode.
- Observability persistence is disabled. Application responses/evidence contain task IDs, statuses, timing and receipts, never payloads or secrets in logs. No URLs carry secret values. This controlled receiver does **not** prove arbitrary customer-host DNS-rebinding/SSRF safety. Arbitrary destinations remain disabled.

## Conservative test envelope and cost review

Proposed upper bounds: 15-minute lifetime, 200 operator HTTP calls, 12 accepted tasks, 128 Queue publications and one transport retry. Under these limits, application-owned Queue work is at most 512 <=64KB operations (write, up to 2 reads, delete). One alpha DO can be active for at most the 900-second run window (approximately 113 GB-s at 128MB, before conservatism). Reserve 10,000 DO invocations and 1 million SQL row reads/writes for metadata and automatic alarm retries; these are conservative planning ceilings, not measured capacity promises.

[Workers rates](https://developers.cloudflare.com/workers/platform/pricing/) list $0.30/million requests and $0.02/million CPU ms. [Queue rates](https://developers.cloudflare.com/queues/platform/pricing/) list $0.40/million operations. DO overage units can add $12.50 duration, $0.15 requests and $1 SQL writes (plus small read/storage amounts), even though raw proportional usage is tiny. The independent whole-rate-unit reserve is **$14.571** (DO duration $12.50 + requests $0.15; SQL reads $0.001 + writes $1 + storage $0.20; Worker requests $0.30 + CPU $0.02; Queue operations $0.40), leaving $5.429 against the approved $20 risk amount. This assumes strict finite usage and is not a guaranteed account-wide hard cap or a certification that the current source enforces every metered dimension. No included allowance is assumed and no paid logging/tracing is enabled.

### Exact bound status before live release

| Quantity | Current implementation | Remaining limit of evidence |
| --- | --- | --- |
| Operator HTTP calls | Runner asserts at most 200 including task cleanup attempts | Does not count public edge traffic from others |
| Accepted work | At most 12 retained tasks in one alpha ledger | Other tenants rejected before DO access |
| Queue publications | At most 128 durable reservations | One configured retry permits at most 256 consumer deliveries under that policy |
| Queue-driven DO calls | At most two per delivery, hence <=512 | API calls and alarm/provider retries are additional |
| API-driven DO calls | <=200 from bounded operator runner | No-gate/wrong-gate requests make no DO calls |
| DO invocation / SQL operation totals | No durable aggregate counters | The 10,000 DO and 1-million row-read/write figures above are planning estimates, not enforced caps |
| CPU | 50ms configured per Worker invocation; 4 subrequests | No cumulative CPU counter; DO applicability and total invocation bound need validation |
| Cleanup | Manual foreground procedure with captured ID checks below | No automatic provider-resource ledger validator, finally driver or cleanup-operation counter |

Before live release, review must establish conservative finite DO/SQL/cumulative-CPU/cleanup bounds or add enforcement. The manifest remains uncertified and the live runner remains blocked. If usage, provider retries or teardown become uncertain, stop new tests and perform/report cleanup promptly.

## Local verification only

```
./scripts/check.sh
node --test staging/receiver.test.mjs
./scripts/build-staging.sh
# Generate configs only, with an expiry <=15 minutes ahead and a fresh /tmp output folder:
node staging/render-config.mjs review thachp <expiry-ms> /tmp/runlater-staging-local-config
```

Local staging verification uses explicitly public `a...a`/`b...b` test values in an untracked temporary emulator config, never real staging secrets. Start `wrangler dev --local` with that config and an empty `--persist-to` directory. `RUNLATER_STATE_DIR=<that-directory> node staging/local-check.mjs` refuses non-loopback URLs, checks gate-before-body/DO behavior on alias hosts, tests actual local DO/alarm/Queue persistence with egress disabled, and checks synthetic-only admission and the 12-task cap. Receiver unit tests cover signatures, receipts, foreign tenants, replay window, body bounds and no-gate aliases. The controlled Rust fetch path is compiled; live HTTPS/runtime network behavior is unverified until a separately released bounded test.

## Execution phase — NOT released by this patch

1. Confirm the approved $20 risk envelope and complete code/manifest/cleanup review, then obtain parent release of the exact reviewed SHA. Re-read the existing account ID/subdomain using existing access. Inventory scripts, queues and namespace IDs; record their original names/IDs privately. Require candidate names absent; never reuse a previous resource.
2. Render fresh configs with a unique run ID, the verified existing account subdomain and <=15-minute absolute expiry. The generator performs no provider calls. Confirm no routes/custom domains, one new SQLite class, dedicated queue, 50ms CPU limit, preview URLs off, outbound false, and observability off.
3. Only then run `prepare-secrets.py --parent-released-execution /tmp/<unique-private-file>.json`. It writes exactly two CSPRNG 256-bit values, mode 0600, refuses overwrite and prints no values. It was **not run** during review preparation. Never cat/read values into a model/tool transcript, put them in CLI arguments, GitHub or messages. Reuse the two values as bindings on both new Workers; no provider credentials are generated.
4. Use supported [Wrangler `--secrets-file`](https://developers.cloudflare.com/workers/configuration/secrets/#upload-secrets-alongside-code) to upload secrets atomically with the initial code. Set `umask 077` and keep Wrangler debug logs in a private temporary file. Only the new receiver and API Worker may be deployed; create exactly the dedicated Queue through existing authorized API/CLI. No account-plan changes. If existing access denies an action, stop without refreshing OAuth scopes.
5. `synthetic-campaign.mjs` is a bounded execution-phase runner and refuses to read staging secrets or make network calls while the manifest budget is uncertified. It is syntax-checked only in this review; do not override its budget gate. Record exact Worker/version IDs, queue ID and the newly generated namespace ID after each successful mutation. First verify no-gate/wrong-gate requests fail on all reachable host forms with no DO allocation, then run a fixed small phase-1 task/Queue test. Inspect metadata only. No open-ended loops.
6. Enable only the canonical controlled receiver for phase 2 after its exact deployed ownership/URL and signatures are verified. Keep task/request counters below the manifest ceilings. Read staging secrets directly from the private file inside the runner; do not expose them in model context. No customer traffic.
7. Before execution is released, the parent/operator must explicitly own the foreground manual cleanup procedure below, including partial-failure handling. Do not leave cleanup to a future reminder. There is no implemented provider-resource finally driver in this patch.

## Supported teardown and required confirmation

**This is a manual, foreground operator procedure, not an implemented automatic ledger validator or provider-resource `finally` driver.** `synthetic-campaign.mjs` only attempts to cancel its API tasks; it does not remove Cloudflare resources. The parent/operator must perform and record each check below. A live release must not imply automated refusal or cleanup enforcement.

Before the first mutation, write a private creation ledger (no secrets) with the reviewed run ID/account ID, exact allowed resource names, complete before-inventory IDs, and an empty `created` list. Use a fresh collision-resistant run ID and require all names absent immediately before creation. After **each** successful create/deploy, append the returned or subsequently verified resource ID before continuing: queue UUID, queue consumer UUID, Worker immutable ID/name and deployed version ID, and the namespace UUID plus owning script/class. Each entry must record `existed_before:false`, the originating action, confirmation evidence and `creation_status` (`confirmed` or `uncertain`). Never infer ownership from prefix alone.

Keep these steps in one foreground session:

1. Enter the cleanup section after success **or any partial deployment/test failure**. Stop issuing campaign calls. Persist completed action receipts; do not overwrite the ledger with the proposed manifest.
2. For an uncertain mutation, perform a read-only existence check for its exact candidate name/returned ID and compare the full before-inventory. Do not repeat a create blindly. Only mark a resource confirmed when its returned identity, owning script/version and this run's action evidence establish it was newly created by this run. If identity/ownership is ambiguous, stop destructive actions and report the exact candidate/ID to the parent; do not delete or adopt a possibly preexisting resource.
3. Review every confirmed ledger entry against the exact reviewed run names, account and before-inventory. If any entry existed before, is outside this run or has unrelated references, do not delete it. First disable/delete only the dedicated consumer UUID on the dedicated queue UUID, using the captured identities and supported API. Verify that consumer is absent. This prevents further synthetic consumption while retiring the producer/namespace.
4. Apply the namespace-retirement procedure in the following paragraph only for the captured API-owned namespace. If retirement fails, retain its identity and report cleanup incomplete; do not force another namespace deletion. Then delete only the confirmed Worker scripts and Queue as described below.
5. Re-list the account's scripts, queues and namespaces and compare exact IDs, not just names, against both the creation ledger and before-inventory. Record deletion acknowledgements plus absence checks and verify original resources remain. Any denied/uncertain deletion remains cleanup-required; report exact survivors and reasons, never a blanket success.
6. Remove secret-bearing private files only after verified teardown, or preserve them mode0600 for a parent takeover if cleanup is incomplete. Never publish their contents. Record a final cleanup receipt with statuses/IDs only.

For the new API Worker, render/use the generated teardown config: it removes the DO binding/class from code and applies the pinned Wrangler-supported `deleted_classes: [TaskLedger]` migration. This deletes this Worker's fresh namespace and its synthetic state; no other Worker may reference it. Confirm the captured namespace ID is absent in a full namespace inventory before proceeding. Then delete only the two new Worker scripts using the supported Worker DELETE API with `force` false, and delete the captured dedicated Queue. Do not force-delete shared references. The [DO lifecycle docs](https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/) and the existing API's Worker-delete schema describe destructive namespace deletion; use the migration route so data removal is explicit.

Finally list Workers, queues and namespaces again. Require both new script names, the queue ID and namespace ID absent, and original resources preserved. Remove the private staging secret file and any private temporary secret-bearing runner files after cleanup verification. If deletion is denied or uncertain, inspect the actual resource state once before retrying; report exact surviving names/IDs and keep unrelated resources untouched. No success/cleanup claim may rest solely on a CLI exit message.
