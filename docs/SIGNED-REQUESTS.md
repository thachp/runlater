# Signed production reads/configuration — offline source

This increment authenticates operator-approved enrolled keys for GET /v1/queue, GET /v1/identity/me and PUT /v1/queue in the separate production profile. GET requires read; PUT requires configure. The existing production origin/configuration/fixture guards remain. There is no bearer fallback, new issuer or secret provisioning. All task admission remains 503 with task_accepted=false: no task is accepted without the future finite funding and real-delivery boundary. No live service is activated.

## Exact request envelope v1

The algorithm is standard Ed25519 with the shared strict verifier. HTTP headers and application framing below are RunLater-owned v1, not an implementation of an industry HTTP-signature protocol. Enrollment, signed requests and callback signatures are different protocols with distinct message prefixes.

The client signs UTF-8 `RunLater signed request v1\n` followed by compact JSON, without a trailing newline:

```
[1,origin,project_id,public_key,method,path,query,body_sha256,idempotency_key,issued_at_ms,expires_at_ms,nonce]
```

origin is exactly https://api.runlater.io. Method is uppercase GET or PUT. The effective URL path must be exactly /v1/queue or the supported GET-only /v1/identity/me. Query is an empty string: query parameters, including pagination, are not supported in this bounded slice. Trailing/duplicate/encoded-slash path variants are not routes. URL-layer dot-segment normalization may occur before the handler; signatures bind the resulting effective resource path, not a claim about raw transport URI bytes. Host, scheme, port and userinfo are independently checked before routing.

body_sha256 is lowercase SHA256 of the exact raw request body bytes, including whitespace; the server recomputes it rather than trusting a digest header or JSON reserialization. GET has an empty body and empty idempotency key. PUT requires application/json, a full QueueLimits object with explicit paused, and an Idempotency-Key of 1–128 ASCII alphanumerics or ._:-. Unknown/duplicate configuration fields are rejected. Bodies retain the 2048-byte, 32-chunk and five-second read bounds.

Headers:

| Header | Value |
| --- | --- |
| RunLater-Project-Id | Approved project slug |
| RunLater-Public-Key | 64 lowercase hex characters, enrolled Ed25519 key |
| RunLater-Nonce | 64 lowercase hex characters; client-generated 32 random bytes |
| RunLater-Issued-At | Nonnegative canonical decimal UTC milliseconds |
| RunLater-Expires-At | Canonical decimal UTC milliseconds, later than issued |
| RunLater-Request-Signature | 128 lowercase hex characters |
| Idempotency-Key | Required for PUT; absent/empty for GET |

Version/origin/method/path/query/body digest are reconstructed by the server. Leading-zero timestamp encodings, future-issued requests, expired requests and validity intervals over 60000ms are rejected. There is no implicit clock-skew allowance. Clients must establish an appropriate server-time offset before signing. Exact body, project, signer, resource, timestamps, nonce and idempotency identity cannot be substituted under an existing signature.

## CQRS and replay

Signed GET validates against a private copy of the latest server policy plus the durable enrolled identity/revocations. It returns a fresh projection with sampled_at_ms and the 60000ms maximum signature window. It does not save policy, consume a nonce, create a receipt, refill tokens, reconcile leases, prune state or migrate SQLite/schema. Identical signed reads can replay until expiry; this is intentionally not one-use read authorization. A read response is a current sample, not a cached command result. Bounded expiry and current authority still apply on every read.

PUT validates latest policy, current enrollment/scopes/expiry and exact proof after all request I/O. It consumes/reserves the signer-specific nonce, applies configuration and stores the command receipt in the same authoritative project snapshot, with no intervening await or call to another ledger. A prior monotonic policy transition may be persisted independently so revocation is durable even when later command verification fails. No detached authorize-then-await-ledger capability is exposed.

Configuration idempotency is project-wide in a dedicated configuration namespace, separate from task/redrive identity. It binds method/path/query/body digest and key. A different active enrolled key with configure authority can recover the original result using the same operation key and identical body; a revoked key cannot. A nonce reused for a different signed envelope or an operation key reused with a different body returns 409 without reconfiguration. Every replay authenticates against current policy before looking up the receipt.

Results contain result, replayed and committed_at_ms. Replays return the original accepted configuration result/timestamp; they never undo a later configuration change, append another configuration event or refund/refill rate tokens. Use GET for current configuration after replay. A fresh signature/nonce with the same operation key can recover a response after the old signature expires, while the receipt remains retained and current permission remains valid.

At most 128 live command nonces and 128 configuration receipts exist per project; filling capacity fails closed instead of evicting valid protection. Nonce records expire with their signed request. Configuration receipts expire 24 hours after first commit, without extension on replay. Maintenance occurs on command paths only. After receipt expiry the key can represent a new configuration command. These are configuration-only windows: future task/funding commands must retain their own full active-task/terminal protection and cannot reuse this short window as a financial guarantee. Signatures and raw bodies are not persisted; configuration values are retained as the response/effect, alongside digests and receipt metadata. No task payload, destination or payment data is accepted here.

## Policy, storage and clocks

The same ProjectIdentity Durable Object now stores a versioned project snapshot containing catalog, authoritative ledger and request protection state in one SQLite row. Existing enrollment-only catalog snapshots decode without writing; only a later command migrates storage. Unknown/malformed versioned snapshots fail closed, without bootstrap reset. Older enrollment-only artifacts cannot read the new wrapper; rollback needs a compatible reviewed decoder rather than deletion/reset of durable data.

Current configured policy is checked inside that object on each request. Signed reads apply it to a copy; operator rollout must still confirm POST /v1/identity/sync before treating revocation as durably recorded or rolling back policy configuration. Recorded revocation is sticky. Commands persist a clock high-water mark and reject regression; reads reject time behind the last recorded command. Pure reads do not maintain a separate ever-seen read clock, so read expiry relies on trusted server time plus that durable command floor. Caller timestamps cannot advance server time.

## Evidence and next gates

Native tests cover each signed field/body, scopes, nonce/idempotency substitution, policy revocation between request creation and execution, receipt recovery across key rotation, clock regression, capacity/retention, strict JSON and legacy decoding. Revocation interleaving and clock faults are deterministic model cases.

The compiled local Worker/SQLite suite tests pure reads of seeded legacy/populated stores, path/query/project/nonce/time substitution, concurrent identical PUTs with one durable effect, discarded-response replay after clean restart, cross-project/scope isolation and revocation before replay after policy/restart changes. It does not claim an actual process kill mid-signed-command or a live deployment race. Production test flags/hooks remain forbidden. Wrappers restore the default artifact and check profile separation.

Next: finite operator-grant reservations and authenticated task commands inside this same project boundary; registered exact HTTPS endpoint handling; actual callback-v2 material selection; controlled receiver 400 diagnosis and bounded real-runtime proof. Real keys, enrollment, resources, grants and api.runlater.io activation still require specific review/authorization and total US$20/month accounting. No live resources, credentials, DNS or payment provider changes occur in this source increment.
