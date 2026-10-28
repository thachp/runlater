# Invitation client v1 — source-only quickstart

This guide targets [the gated invitation v1 contract](../contracts/invitation-v1.json) at PR #46 head `ef0c8d74ccb52e5d6b9053ef83abc7781af57452`. It does not describe an available public service. The [published operator alpha client](../examples/alpha-quickstart.mjs), discovery and local OpenAPI are unchanged. No signup, invitation, receiver, credentials, grant, deployment, payment or trial terms are activated here.

The [Node 22+ client](../examples/invitation-client.v1.mjs) has no default network transport. Every instance requires an explicitly injected `fetchImpl`; its signing origin is fixed to `https://api.runlater.io`. A local runtime harness can route those logical HTTPS requests in process. Supplying real `fetch` requires separately approved activation and credentials; this guide and its tests make no live API or receiver calls.

Run the complete offline mock journey and Rust/JS protocol/schema checks:

```sh
npm run test:invitation-client-v1
```

The tests generate ephemeral Ed25519 keys and invitation tokens in memory. The mock server checks exact wire bytes and DTOs; it is not proof of real delivery, DNS/TLS, Cloudflare durability or funding settlement. The separate runtime evidence is in [INVITATION-DELIVERY.md](INVITATION-DELIVERY.md).

## 1. Keep owner inputs private and approve the actual terms

The operator supplies a one-use invitation and agreed finite engineering terms. Keep the private PEM key, invitation token, terms, receipt and proof response in owner-only files outside the repository; never put invitation tokens/private keys in command arguments, logs, examples or tool inputs. Owner-file helpers require POSIX ownership/mode checks (Linux/macOS); they do not claim to enforce Windows ACLs. Use a caller-owned Ed25519 key. This client neither creates keys for a live identity nor chooses commercial terms.

The following JavaScript calls are a template for an authorized in-process adapter; `approvedTransport` is deliberately supplied by the integrator. They are not a command to contact the hosted alpha.

```js
import {
  InvitationClientV1, loadOwnerKey, loadInvitationToken, readOwnerText, writeOwnerJson,
} from '../examples/invitation-client.v1.mjs';

const client = new InvitationClientV1({
  privateKey: loadOwnerKey(process.env.RUNLATER_KEY_FILE),
  fetchImpl: approvedTransport,
});
const token = loadInvitationToken(process.env.RUNLATER_INVITATION_FILE);
const expectedTerms = JSON.parse(readOwnerText(process.env.RUNLATER_TERMS_FILE));
const offer = await client.challenge(token);
// Review offer.challenge.ticket.terms through a private local interface first.
const receipt = await client.complete(token, offer, expectedTerms);
writeOwnerJson(process.env.RUNLATER_RECEIPT_FILE, receipt);
```

`expectedTerms` must contain the operator-agreed `attempt_units`, `identity_ms` and exact `permissions` array. No defaults are supplied. Permission order follows the server's enum: enqueue, read, cancel, redrive, manage_destinations; include only the scopes actually agreed. The client rejects configure/key-administration escalation, wrong context, unexpected terms, changed canonical bytes and expired challenges before submitting a possession signature. It reconstructs the Rust ticket serialization order before hashing rather than hashing the response object's map order.

Enrollment uses unsigned POST `/registration/challenge` with `{token, public_key}`, then POST `/registration/complete` with `{token, challenge_id, signature}`. The key signs only the reconstructed `RunLater invitation proof v1` bytes. A receipt's `attempt_units` is the original allocation, not the current available balance.

After an uncertain completion, do not create another identity or change keys. Retrying the same completion is explicit and limited to its original invitation/challenge window. Each client instance retains its full validated ticket ID and checks completion/recovery receipts against it, including the suffix not represented in the project/grant prefixes. Preserve both the project ID and full ticket ID from the validated offer/receipt even if the completion response is lost. A fresh client should receive the known values as `{project: saved.project_id, ticketId: saved.ticket_id}` (or `offer.challenge.ticket.project_id` and `offer.challenge.ticket.id`); it can then call `recover(projectId)`. Recovery signs its separate tuple and POSTs `/registration/recover`, requiring a valid, unrevoked read-scoped key. If no full ticket ID is known, the first valid recovery receipt supplies that identity for subsequent checks. No recovery or request retries happen automatically.

## 2. Prepare an owner-controlled receiver before issuing proof

Destination management requires the separately granted `manage_destinations` scope. It grants neither queue configure nor key administration. The operator must separately approve the exact receiver hostname in the server's egress policy. Ownership proof is not SSRF/DNS-rebinding authorization, and this example cannot add a host to that policy.

Have the receiver's proof handler ready before calling prepare: proof expires after 60 seconds. Load each prepared proof through an owner-controlled private configuration channel, not from the incoming verification request. Do not place the proof file in a public web directory.

```js
const endpoint = await client.createDestination(
  'owned_receiver', 1, 'https://owned.example.test/callback', 'create_receiver_v1',
);
const proof = await client.prepareDestination(endpoint, 'prepare_receiver_v1');
writeOwnerJson(process.env.RUNLATER_PROOF_FILE, proof);
// Owner installs proof on the already approved receiver through a private channel.
// Do not print proof.response, send it to this API, or echo an HTTP request body.
const verified = await client.verifyDestination('owned_receiver', 1, 'verify_receiver_v1');
```

The `.test` hostname is illustrative and is not a live receiver. Create sends `{endpoint_id, version, url}`. Prepare/verify/revoke send **only** `{endpoint_id, version}`; their URL, clock, proof response and project are not caller body fields. Each destination command carries a nonempty stable idempotency key and signed request v1 headers. Prepare/verify are one-use operations: reusing a key is not a promise to replay a secret response or perform another fetch.

The receiver stores the exact `proof.response` string as bytes, without appending a newline. To recognize the matching verification request:

1. Accept only the configured POST path and bounded `text/plain; charset=utf-8` request. Enforce a short read deadline, 1,024-byte body and 32-chunk ceiling.
2. Read the **installed** response tuple after `RunLater destination proof v1\n`: `[1, project, endpoint_id, version, url, attempt, expiry, nonce]`. Check its digest equals installed `proof.id` and its context/expiry matches the owner-approved endpoint.
3. Require the incoming body to be exactly `RunLater destination verification v1\n` plus compact JSON `[project, endpoint_id, version, proof.id, expiry]`, and require current time before expiry.
4. Return HTTP 200 with the installed `proof.response` verbatim and `Cache-Control: no-store`. Reject unmatched/expired requests. Never derive the expected response from request bytes: the request omits the secret nonce, and reflection cannot verify ownership.

This proof path is separate from callback-v2 signature verification and durable business-operation deduplication. A genuine task callback must pass [callback verification](CALLBACK-KEYS.md) before applying a business effect; the [receiver example](../examples/rotating-receiver.mjs) illustrates the signing protocol, not production deduplication storage. A redirect, an echo endpoint or a caller-submitted response cannot replace server verification. Server verification uses the same bounded safe egress as delivery.

Lost prepare response: wait for expiry, then explicitly request another proof if budget remains. An interrupted verify may have consumed its fetch lease; do not refetch automatically. Three lifetime proof issuances per endpoint version are an engineering ceiling, not an approved trial. A new version is not a way to undo endpoint-wide revocation or reset tenant caps.

## 3. Select once, then inspect or cancel explicitly

Only after verification succeeds, explicitly enqueue work against the registered ID:

```js
const input = {
  endpoint_id: 'owned_receiver',
  body: JSON.stringify({synthetic: true}),
  operation_key: 'one_business_operation',
  run_at_ms: agreedUtcMilliseconds,
};
const accepted = await client.enqueue(input, 'one_create_request');
const status = await client.task(accepted.result.id);
// Optional explicit cancellation:
const cancelled = await client.cancel(accepted.result.id);
// Optional explicit endpoint-wide revocation; version must exist:
await client.revokeDestination('owned_receiver', 1, 'revoke_owned_receiver');
```

The wire task DTO is `{destination: "registered:owned_receiver", body, operation_key, run_at_ms}`. **There is no task `version` field.** The server selects the latest registered version and atomically snapshots it with task/idempotency acceptance and the finite funding reservation. If a newer version is pending, new admission fails closed until that latest version is verified. Already accepted work retains its old version even after another version is created/verified. Do not claim the client can pin an older version in a fresh task body.

Retry an uncertain enqueue only with the same idempotency key and byte-identical business input, including schedule and operation key. That replay can recover the original acceptance after endpoint revocation; it does not authorize dispatch. Redrive, if explicitly invoked as `client.redrive(taskId, newIdempotencyKey)`, is a separate funded admission preserving the source task's selected version; it never silently migrates to the latest endpoint. At-least-once callbacks still require durable receiver deduplication.

Revocation checks the submitted version exists, then revokes the whole endpoint across all versions. It blocks new admissions and future dispatch, but cannot undo an in-flight side effect. Cancellation has the same in-flight uncertainty. Identity/grant expiry blocks new admission and may prevent signed reads, while already accepted funded work can still execute. An HTTP 403/410 read failure is not evidence that the task did not run.

The client exposes only a fixed error code and HTTP status, never raw response bytes. On 402 stop for separately authorized funding; there is no purchase endpoint or automatic payment. On 409 inspect the original request/context; on expiry or unavailable policy stop and reconcile with the operator. Every request uses manual redirects, a whole-response deadline of at most five seconds, and 32 KiB/32-chunk response bounds. It never follows redirects, changes origin, polls, retries, refills grants or invokes payment automatically.

The source contract, client and mocks do not change the current [published alpha contract](../discovery/alpha.v1.json), [service availability](../discovery/service.v1.json), [pricing status](../discovery/pricing-status.v1.json), or [public quickstart](AGENT-QUICKSTART.md).
