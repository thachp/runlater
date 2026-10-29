# Private Container controller candidate — source only, not deployable as configured

This is a separately reviewed hosting candidate, not a provisioned egress service.
`wrangler.example.jsonc` is disabled and contains an intentionally unusable image
placeholder. `Dockerfile.example` requires an independently reviewed immutable native
Node Linux/amd64 image reference; no image was downloaded, built or pushed here.
Before activation, select a currently patched native image, review and pin its exact
digest, and rerun the entire native TLS/egress suite inside that exact image. Host-
Node test results do not establish image-runtime proof; no Docker/Podman image build
or provider-level test has been performed in this workspace.
Production remains disabled. Source readiness is constructible only with explicit
EGRESS_ENABLED=operator-approved and nonzero 64-hex EGRESS_REVIEW_REVISION matching
the API's independently reviewed artifact-manifest revision; absent flags fail closed.

## Testing minimal runtime images

The production transport uses Node's DNS/TLS/HTTPS APIs; it does not require the
OpenSSL command-line executable. The native TLS integration test normally uses
that executable only to generate a disposable self-signed local certificate.
For a minimal image without that executable, generate a one-day `example.com`
certificate and key outside the image using the same command in
`native-tls.test.mjs`, then mount their directory read-only and set the test-only
`RUNLATER_NATIVE_TLS_FIXTURE_DIR` to its absolute container path. Name the files
`cert.pem` and `key.pem`, and let the nonroot container user read them. Use only
disposable local test material, never a production key or trusted certificate.

Run all three suites inside the exact image:
`node --test egress/egress.test.mjs egress/controller.test.mjs egress/native-tls.test.mjs`.
The test copies fixtures into its own temporary directory and still performs real
loopback TLS, checking success, hostname mismatch, untrusted CA, request counts
and diagnostic redaction. Missing/invalid fixtures fail rather than skip. No
runtime trust store, production transport or provider behavior is changed by this
test input. Keep the test container offline with a read-only root, bounded writable
temporary directory, dropped capabilities and nonroot execution. Local synthetic
peer translation remains **not** hosted-provider network proof.

## Proposed boundary

Existing API → explicit same-account `GENERAL_HTTPS_EGRESS` service binding to named
`EgressBinding` → fixed `runlater-egress-v1` SQLite Durable Object → fixed port 8080
native Node Container. Default public Worker fetch always returns 404; workers.dev,
preview URLs, routes/custom domains are disabled. No network bearer secret is needed
for the binding capability, but adding the binding expands API authority and requires
approval. Account administrators can create bindings; this is not protection against
a compromised account/operator. No caller-selected class, instance, port or environment.

Named-entrypoint HTTP fetch is used rather than a JSON-only RPC method so the Request
carries cancellation. End-to-end cancellation behavior still needs provider testing;
absolute lease expiration is an independent bound, not replaced by signal propagation.
No `waitUntil`, delivery background task, dispatch retry or redirect follow-up exists.

The source envelope is versioned, exact-key checked, limited to 8192 bytes before
JSON parse, and contains adapter revision, release/project/task/fence, API attempt start, absolute deadline,
immutable target digest, and exact POST JSON request. The target hash uses the existing
Rust target object. `envelope-vector.json` is a cross-language test fixture. Absolute
deadline is exactly attempt start +29000 ms (30-second API lease minus one second).
The native operation is limited to min(remaining absolute lease, five seconds), with
monotonic elapsed-budget and absolute-deadline checks before DNS, connect and HTTP
socket handoff. Cold start does not reset authority.

The same transaction enforces durable global one-dispatch/second and canonical-
hostname one-dispatch/ten-seconds plus one concurrent attempt. A 1024-host map never
evicts to reset limits. Clock regression fails closed; reserved uncertain attempts
retain the host slot until lease expiry. This is bounded beta fairness, not proof of
destination ownership, and the global cap limits alias/subdomain burst bypass.
Rate rejection returns explicit unsent `rate_limited` before any receipt/network;
only the API scheduler may later create a fresh budgeted attempt.

The DO transaction reserves a receipt and increments a bounded lifetime count before
container startup or delivery. Completed duplicates return a redacted cached result;
reserved/crashed/uncertain duplicates never resend. Different immutable-envelope hash
for the same release/project/task/fence is rejected. The envelope adapter revision
must match controller configuration before receipt creation, and native process
revision must also match; the marker does not itself prove the running image. No receipts are deleted: the
10,000-attempt lifetime cap requires an explicitly reviewed migration/replay strategy
before expansion. The transaction uses SQLite-backed Durable Object storage; no
network occurs inside the transaction or `blockConcurrencyWhile`.

A fixed singleton and max_instances=1 are intentional limited-beta capacity/cost
constraints, **not scalable architecture**. Four operations may run simultaneously.
The Container sleeps after 30 seconds of DO inactivity. Read-only startup probes are
finite; delivery POST is issued once. Startup failure consumes its receipt conservatively.
The API ledger must persist claim/fence first, accept completion only for the matching
unexpired lease and never automatically replay an uncertain same attempt.

Readiness is read-only (no container start or receipt writes) and reports exact
protocol/revision/capacity. Capacity is advisory and rechecked transactionally.
An operator declaration is not security proof; relevant source/image/runtime/network/
binding changes invalidate the prior approval and require renewed verification.

## Native network assumptions

Use real native Node, `enableInternet:true`, HTTPS interception off, no ContainerProxy
rewrite or injected proxy CA. Cloudflare's deny-internet interception mode returns
placeholder DNS answers and routes through Workers; it does not preserve this pinned
socket/original-host TLS proof. This candidate therefore relies on reviewed application
SSRF enforcement, not an independent provider public-IP firewall. Native CA/runtime,
DNS resolver, environment and image integrity remain trusted. The provider must pass
negative private-IP, mixed-answer, rebinding, peer/TLS mismatch, cancellation and timeout
checks before any live general destination activation.

## Cost/approval planning (official docs checked 2026-10-29)

Candidate lite resources: 1/16 vCPU, 256 MiB RAM, 2 GB disk; max one running instance.
Containers require Workers Paid availability ($5/month account minimum). No upgrade
or plan selection is authorized by this source. Included monthly container usage:
25 GiB-hours RAM, 375 vCPU-minutes, 200 GB-hours disk. Excess memory is
$0.0000025/GiB-second, active CPU $0.000020/vCPU-second, disk $0.00000007/GB-second.
At full lite CPU, raw compute before included usage is approximately $0.007254/hour:
60 seconds approximately $0.000121, one hour/day for 30 days approximately $0.218,
or continuous 30 days approximately $5.22. These are compute illustrations, not a bill
or hard cap. Shared account allocation may already be consumed.

Network excess ranges $0.025–$0.05/GB depending on region. Worker Standard includes
10M requests/30M CPU-ms monthly, then $0.30/M requests and $0.02/M CPU-ms. DO includes
1M requests/400k GB-s, then $0.15/M requests and $12.50/M GB-s with billing-unit rounding.
SQLite rows/storage and image/build/log costs may also apply. max_instances, idle sleep
and request limits reduce exposure but do not establish a dollar spending cap.

Future approval must name one private Worker, SQLite DO namespace, Container app/image,
one API service binding, existing Paid-plan metering without upgrade, bounded negative
network/smoke operations, private ingress readback, rollback and cleanup. No project
keys, new global credential, public proxy, domain, plan upgrade or arbitrary test task
is included by default. First deployment must remain admission-disabled until proof.

Primary sources:
- https://developers.cloudflare.com/containers/concepts/architecture/
- https://developers.cloudflare.com/containers/configuration/outbound-traffic/
- https://developers.cloudflare.com/containers/api/durable-object-container/
- https://developers.cloudflare.com/containers/platform/pricing/
- https://developers.cloudflare.com/containers/faq/
- https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/
- https://developers.cloudflare.com/workers/platform/pricing/
- https://developers.cloudflare.com/durable-objects/platform/pricing/
