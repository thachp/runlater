# Public-beta receiver example — inactive source

This small Cloudflare Worker demonstrates the existing destination-proof and callback-v2 protocols for one owner-configured project. It does not register a public project, deploy a Worker, enable the beta, retrieve a key or contact RunLater. The example configuration disables workers.dev, preview URLs and request logging; all values needed to accept a request are absent by default.

The intended first receiver shape is an **exact** `https://worker.account.workers.dev/callback` URL. The API owner is implementing a separate global strict-public-host policy plus ownership verification. A hostname suffix is not an arbitrary-host SSRF/DNS-rebinding proof. This example grants no host approval and does not support custom domains, IPs, alternate ports, query/fragment or redirects. It must pass the reviewed API admission policy before use.

## Reuse and behavior

The Worker imports `validatePolicy`, `verifyV2WithMaterial` and `advancePolicy` from [the existing rotating-receiver example](../rotating-receiver.mjs). The new explicit-material verifier has no fixture fallback. Existing offline fixture behavior and Rust/JS callback vectors remain regression tests. `nodejs_compat` supplies the existing Node HMAC verifier; no additional web framework or package is introduced.

The single exact POST route has two branches:

- `text/plain; charset=utf-8`: compare a destination verification request with privately installed static proof data, then return only the installed response verbatim.
- `application/json`: verify callback-v2 HMAC/context/timestamp/key policy before selecting the project's own SQLite inbox. Verify again inside that inbox, then atomically deduplicate the business operation and increment a local counter.

No public install/reset/inspect endpoint exists. No payload, proof, signature or key is logged. There is no outbound fetch or external business effect. The receiver never receives a Durable Object binding back to RunLater; `INBOX` is its own private namespace.

## Private owner setup inputs

After separately reviewed activation, an owner would configure these bindings through supported private Cloudflare mechanisms. This source includes no deploy or secret-install command to run now.

| Binding | Input and purpose |
|---|---|
| `RECEIVER_ENABLED` | Explicit `owner-configured`; source config defaults to `disabled`. |
| `RECEIVER_URL` | The exact owner-controlled workers.dev HTTPS callback URL. |
| `RECEIVER_PROJECT_ID` | The project returned by public key-possession registration. Validated public-beta enrollment receipt; see `contracts/public-beta-v1.json`. |
| `CALLBACK_POLICY` | Existing callback-v2 `Keyring` metadata for exactly that tenant/policy/key history. The current key-retrieval DTO omits validity times: obtain this nonsecret metadata from the reviewed release policy, never infer it from the client clock. |
| `CALLBACK_KEYS` | Secret JSON key-ID → 32-byte lowercase-hex material map. Only the scoped per-project callback material belongs here; never a service master key. Fixture-prefixed IDs and repeated-byte placeholders are refused; these checks cannot establish key secrecy. |
| `OWNERSHIP_PROOF` | Secret JSON `{id,response,expires_at_ms}` from destination preparation, privately installed before verification. It contains the nonce. |
| `INBOX` | The receiver's own SQLite-backed `ReceiverInbox` namespace. |

Keep files containing key/proof data owner-only and outside Git. Never paste them into command arguments, chat, public vars, source, console output or a public web directory. Per-project key retrieval requires the server's signed `manage_destinations` authority; its public-beta DTO is owned by the API integration and is not invented here.

## Static ownership response; never reflection

Have the handler and private owner configuration channel ready **before** preparing a proof. The current destination protocol has a five-minute TTL and three lifetime issuances per endpoint version. Secret installation/rollout may consume that window; do not promise deployment will finish within it or burn retries automatically. Do not retry preparation automatically; a failed/expired proof consumes an issuance.

The installed response is exactly:

```text
RunLater destination proof v1\n
[1,project,endpoint_id,version,exact_url,attempt,expiry_ms,nonce_hex]
```

The notation `\n` means one LF byte, followed immediately by compact JSON with no trailing newline. `id` is SHA-256 of those exact UTF-8 response bytes. This response is installed privately; no part is synthesized from caller input.

The server POSTs only:

```text
RunLater destination verification v1\n
[project,endpoint_id,version,proof_id,expiry_ms]
```

The request omits the secret nonce. The Worker validates installed digest, tenant, version, exact URL, expiry and attempt; it compares the complete incoming bytes with the expected nonsecret tuple. Only a matching unexpired request gets HTTP 200 with the preinstalled response and `Cache-Control: no-store`. Echoing the request, accepting a client-supplied response, GETing a proof or redirecting does not work. Proof is independent of callback key material, so its static setup does not expose callback secrets.

## Callback authentication and durable dedup

The existing v2 verifier checks exact protocol/policy/key ID, tenant-prefixed task ID, operation key, canonical decimal timestamp, the five-minute verification window, key activation/sign/verification intervals and current key revocation metadata. It HMACs the exact received body bytes. Body reads are capped at 1,024 bytes/32 chunks and three seconds; request headers at 2,048 bytes. Raw data never enters diagnostics or SQLite.

The inbox is selected only from configured tenant context after HMAC verification. It persists operation key, body digest and first task ID. An identical operation/body returns 204 without applying the local effect again, including concurrent deliveries, retries, redrive task IDs and process restart. A changed body under the same operation key returns 409. Dedup and the local counter update share one synchronous SQL transaction.

The example intentionally applies **only a local SQLite counter**. Replacing that with an external HTTP request, email or payment would introduce an uncertain side-effect window; this code is not an exactly-once wrapper for those actions. Put an application's transactional effect beside its dedup record, or design an explicit outbox/reconciliation boundary separately.

Storage is bounded to 128 unique operations per configured project lifetime and has no public reset or automatic expiry. This receiver safety ceiling is not a service credit, task or delivery promise. Do not purge/recreate its database while accepted or replayable operations remain: doing so discards dedup history.

After authenticated traffic observes a policy revision/material identity, SQLite rejects revision rollback, removed/reintroduced history and same-ID material replacement. This is an **observed-state** guard: an owner configuration change that never reached the inbox is not a durable revocation event. The owner must privately install and verify current policy during rotation; the receiver does not poll RunLater or inherit its administrative namespace. No live rotation procedure is authorized by this example.

## Local checks only

`npm run test:public-beta-receiver` exercises the real Worker in local workerd with disposable SQLite, generated ephemeral material and denied outbound traffic. It covers static proof matching/reflection rejection, invalid context/timestamps, HMAC/body substitution, concurrent duplicate/counter atomicity, digest conflicts, actual local disposal/restart, observed policy rollback/material substitution and bounded storage. Existing callback vector tests prove the shared verifier still agrees with Rust. These tests do not prove live workers.dev routing, DNS/TLS, provider limits or a deployed beta.

The separate [public-beta client/quickstart](../../docs/PUBLIC-BETA-QUICKSTART-v1.md) follows the actual source DTOs. Nothing here changes the published alpha, billing, credentials or availability.

References consulted: [Cloudflare SQLite transactions](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/), [Node crypto support](https://developers.cloudflare.com/workers/runtime-apis/nodejs/crypto/), [Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/).
