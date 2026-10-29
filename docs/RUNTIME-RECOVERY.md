# Local runtime interruption evidence

Run `npm run test:runtime-recovery` after the pinned tool installation in LOCAL.md and `npm ci`. CI runs the same command on Ubuntu; local execution was checked on macOS. POSIX process groups/signals are required. The callback recovery case waits for the real 30-second lease plus normal retry timing; no clock override or shortened lease is used.

This suite runs compiled Rust in local workerd with SQLite Durable Object/alarm/Queue emulation, fresh per-scenario stores and public fixture credentials. It adds evidence beyond deterministic serialized-Ledger unit tests, but is **not live Cloudflare crash, machine power-loss or external side-effect proof**. No live resources, real credentials, DNS changes or network callbacks are used. Outbound fetches are bound to an internal rejection service.

| Boundary | Interruption actually used | Local assertion |
| --- | --- | --- |
| SQLite accepted task, before publish/reply | SIGKILL of newly spawned Node/workerd process group; restart on same owned store | Private pre-publish gate is held as well, so no Queue send can start before kill; task recovers with one attempt; unknown enqueue response retries with same key to same task |
| Successful Queue send, before producer continues | Injected exception, plus three actual duplicate Queue references | Duplicate claims occur but only one leased fixture attempt/completion |
| Fixture completion, before ledger finish | SIGKILL of test-owned process group; restart and wait real lease deadline | Prior attempt is unknown/expired, fixture can repeat, operation identity retained; old-fence result sent through private local DO binding returns 409; new result commits |
| Durable finish, before Queue ack | SIGKILL while the private post-finish gate is held; restart same owned SQLite store and explicitly publish three replay references | Terminal task/attempt unchanged; claim-ignored counters prove at least three replay deliveries reached the guard; no new fixture callback |
| Final pump alarm re-arm boundary | Injected exception **before** re-arm storage call, not a storage-engine failure | Earlier watchdog path and local alarm handling republish retained work; task completes once claims are released |
| Test artifact ingress/config | Wrong host, disabled harness and missing private binding | Fail closed before request body/DO work |

The re-arm case does not isolate local automatic alarm retries from the earlier explicit watchdog or establish cloud retry behavior after the provider's finite automatic retries. The fixture completion is a signed in-process result, not an HTTP customer callback or committed business transaction. Duplicates after an uncertain side effect remain possible by design. Exact lease/fence and attempt outcomes are inspected through the actual compiled runtime; the harness does not edit the SQLite task rows or advance its clock.

## Test-only controls and artifact separation

Fault points are compiled only with the `runtime-tests` Cargo feature. Default and staging call sites are compiled out; `runtime-tests` + `staging` is rejected at compile time. No fault route, query parameter, customer header or public credential selects a failure. Only parent-process IPC resolves a private local `TEST_CONTROL` service binding. Test builds additionally require HTTP loopback host 127.0.0.1, explicit TEST_RUNTIME_ENABLED and LOCAL_FIXTURES, plus that binding. Hooks carry fixed point names and generated task/fence/status/reference metadata, never body, operation/idempotency key, signature, receipt or credential values.

The normal/staging build scripts do not set the test feature. The recovery wrapper restores the default release artifact in its EXIT trap on success or failure, then checks absence of fault-binding/point markers. Marker scanning is an additional tripwire, not a formal binary proof. Never deploy the test feature/artifact. If the restoring build fails, treat the command as failed and rebuild normally before any further use.

## Owned resource cleanup and failure handling

The parent creates a fresh mkdtemp directory and ownership marker; children accept only scenario stores beneath it. An owned children.json ledger records newly spawned PIDs/groups and timestamps. Each child is spawned in its own new POSIX process group, and SIGKILL is limited to those newly recorded group IDs. Normal exits await Miniflare disposal. Finally, SIGINT and SIGTERM handlers stop remaining owned groups and remove only the marked test directory after child closure. Cleanup failure reports that directory for inspection instead of deleting unrelated data. SIGKILL of the *harness parent itself* cannot run a finally handler; do not kill it that way. If that occurs, inspect the owned ledger and verify current process identity before manually cleaning only those groups/stores. No existing .wrangler or other saved local state is reused or deleted.

Bounds: ten child runtimes, 240 parent HTTP calls, finite per-boundary waits, bounded retained diagnostic stderr tail, and at most six explicit duplicate messages across the two replay cases. A failed assertion stops the suite; it is not an indefinite outage/load campaign. Local stores are disposable, not a production backup.

Remaining #11 gates include real cloud faults/transport recovery (including provider post-finish/pre-ack interruption), storage engine failures, prolonged outages, noisy-neighbor/load measurements, real HTTPS/receiver side effects, destination network safety, operational rollout and measured capacity/SLOs. Passing these cases does not close #11 or unblock public beta.

The post-finish/pre-ack case is an actual local process kill, but does not assume that Miniflare durably retains an in-flight Queue message: it explicitly replays three references after restart. The checked claim-ignored counter establishes that at least three replay deliveries reached the authoritative terminal guard; if the original in-flight Queue message is also redelivered, it can contribute to that count. See [the acceptance evidence matrix and remaining launch gates](RELIABILITY-ACCEPTANCE.md).
