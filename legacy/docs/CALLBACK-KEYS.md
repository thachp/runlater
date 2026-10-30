# Callback key rotation: implemented offline v2 protocol

Callback signing keys are separate from API authentication keys. `callback::Keyring` implements nonsecret key metadata lifecycle, dispatch-time issuer selection, v2 HMAC signing/verification and immutable private policy snapshots. `Material` supplies raw secret bytes by exact key ID; verifier hashes or API credentials are not a signer. The provider must bind immutable bytes to each ID; replacing bytes requires a new ID, never overwriting a provider slot. The supplied FixtureMaterial contains **public deterministic test strings**, not production keys. No credential is generated or provisioned.

**Integration boundary:** this is an opt-in offline Rust protocol/library and example receiver, not a callback-key administration service. Current Worker task/attempt DTOs and default in-process callbacks still use the reviewed unversioned legacy fixture format. The existing staging receiver/secrets are unchanged. No new API endpoint or OpenAPI schema is claimed. Authoritative SQLite key administration, queue/attempt snapshot integration, secure secret provider, receiver enrollment and live HTTPS proof remain future work. The existing API-key rotation does not rotate these callback keys.

## Dispatch and immutable execution policy

A private Snapshot binds v2 protocol, tenant, policy ID, accepted task ID, operation key and SHA-256 of unchanged body bytes. It pins **protocol/policy identity, not a key ID or secret**. `sign` checks the exact body against the snapshot and selects the current active issuer at dispatch time. Ordinary retries reuse the snapshot and can cross a key cutover. `redrive` changes only to a fresh task ID and retains tenant/policy/version/operation/body identity. This code is executable independently of the Worker ledger; migrating actual accepted Worker tasks to v2 is not done silently.

A future control plane must authorize a dedicated tenant-scoped callback-signing administration capability; it must not infer this authority from raw API-key lifecycle access. No new management permission or endpoint is granted here.

A future queue adapter must commit this snapshot with durable acceptance and keep it unchanged through retry/redrive. Per-attempt storage may record only nonsecret selected key ID, protocol and signing timestamp; never persist signatures/raw key bytes in task/audit/log data. A signature is built immediately before sending. If key metadata changes between selection and send, revalidate eligibility before producing the packet; do not send an old key with a new post-cutover timestamp. A packet already signed before cutover can remain valid during the overlap below. Key revocation cannot undo an effect that already occurred.

No active key, expired/revoked key or unavailable/short material returns a typed failure before any packet is produced. There is no old/global/API-key fallback and the library starts no retry loop. A future adapter must map this to a bounded existing attempt/age budget or an explicit terminal configuration failure; that runtime mapping is design-only here.

## Lifecycle and receiver rollout

| Operation | Behavior |
| --- | --- |
| Initialize | One enrolled key ID with activation/signing expiry; raw material must already exist in the provider |
| Rotate | Atomically clone/validate/commit metadata: distinct immutable new key ID, signing cutover and expiry; old signing window ends at cutover, old verifier window is shortened to at most cutover + 300 seconds |
| Replay rotation | New key ID identifies the immutable source/cutover/original-expiry request. Identical retries return current metadata even after later expiry/rotation/revocation; changed requests conflict |
| Revoke | Immediate sticky state, not scheduled revocation. Every later sign/verify rejects the key regardless of timestamp or clock rollback. There is no delete/un-revoke/reuse operation |
| Explicit recovery | A new distinct enrolled key can replace a retired/revoked current epoch at an immediate cutover. This never reactivates an old key. An existing pending future plan must be revoked before replacing it |

New cutover is bounded to trusted server now through 24 hours ahead; only one non-revoked future plan is accepted. Caller time is trusted server time, never callback payload time. The example receiver defaults to its own current UTC time. Activation/signing/verification cutoffs are exclusive at their upper bound. Verification requires a canonical timestamp within ±300 seconds of receiver time, timestamp inside the key's signing interval, receiver time inside its verifier interval, and no revoked flag. For normal rotation, pre-cutover in-flight signatures can verify during the overlap, bounded by both their own replay age and the old verification deadline. A retired key cannot sign a timestamp at/after cutover. Emergency revocation intentionally rejects even valid old in-flight packets; completion remains uncertain and business-operation dedup is still necessary.

Before cutover, enroll the new verifier material at receivers while preserving the old key for overlap. Trusted metadata updates are revisioned; the example receiver rejects rollback, changed same-revision state, removed key/history records, postponed revocation, extended old signing/verification windows and changed rotation identities. An HMAC verifier retaining an old key cannot distinguish a genuine pre-cutover signature from one forged with a compromised old key during the permitted window; compromise requires emergency revocation, not just normal overlap.

Metadata retains at most 16 key identities, including revoked/expired IDs. Capacity fails closed; production key garbage collection/tombstones need a separate policy. Revision/count/history validation bounds state and rejects malformed or overlapping active signing intervals. Callers must durably commit authoritative metadata before publishing it, reload the latest version after restart and use conditional version updates; do not reconstruct a fixture bootstrap after revocation. Rust &mut updates plus serialized-restart tests do not establish durable SQLite/CAS administration. The example receiver's policy and dedup state are process memory only; production receivers must persist the latest revision/revocations and atomic business-operation dedup.

## Canonical v2 wire

Required headers are RunLater-Signature-Version: v2, RunLater-Signing-Policy, RunLater-Key-Id, RunLater-Timestamp (canonical UTC integer seconds), RunLater-Task-Id (tenant:task_id), RunLater-Operation-Key and lowercase hex RunLater-Signature. All identifiers forbid dot/colon ambiguity except the fixed tenant:task separator. Exact MAC bytes are:

```text
runlater.v2.<policy_id>.<key_id>.<timestamp>.<tenant:task_id>.<operation_key>.<unchanged raw body bytes>
```

Policy, key ID and protocol domain are covered by the HMAC, preventing cross-key aliases or version/scope substitution even when test material is shared. Unknown/missing keys, protocol, policy or tenant fail closed. Rust's header-pair parser rejects duplicates case-insensitively and noncanonical timestamp strings; HTTP adapters must preserve duplicates until validation. JS Headers combines duplicates and the combined values fail canonical checks. Neither v2 verification nor the legacy example silently falls back between versions. Legacy headers with no v2 metadata keep their original public-fixture HMAC contract.

## Verification

`cargo test --test callback` covers selection, retries/redrive, overlap/expiry/replay boundaries, sticky revocation across serialized restart/clock rollback, atomic failure/replay/conflict, missing material/no signer, same-secret key-ID/tenant/policy substitution, header ambiguity, bounded retained identities and redacted Debug views. `npm run test:callback-wire` actually executes the Rust fixture signer/verifier and the independent JS receiver in both directions, including exact UTF-8 body bytes, policy update rollback and old/new/redriven packets. Fixture vector output intentionally contains only public synthetic bodies/signatures; never log real envelopes or private snapshots. CI runs these tests.

Production issuance/enrollment, real secret-provider access and rotation operations, Worker ledger/attempt integration, HTTPS destination safety and live delivery remain gated. This increment makes no claim that the previous failed live HTTPS campaign now succeeds.
