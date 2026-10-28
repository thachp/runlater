# Public-beta client v1 — source only, not activated

Use the [actual public-beta contract](../contracts/public-beta-v1.json), [source runtime guide](PUBLIC-BETA.md), [client](../examples/public-beta-client.v1.mjs) and [receiver](../examples/public-beta-receiver/README.md). This guide does not publish a beta, switch the API domain, provision a receiver or contact a hosted service. The published alpha and invitation client remain separate. There is no invitation, payment or automatic recharge in this flow.

The first cohort has ten lifetime projects globally. Each project gets seven days and 100 attempt credits; five are reserved for each fresh task/redrive, with stricter lifetime ceilings of 16 tasks and 128 publications. Credits are not tasks or money. Cancellation, retention, replay and restart do not reset lifetime admission. Accepted funded work can finish after identity/grant expiry, but new admission/API identity access expires. Key possession is not one-person identity or Sybil prevention.

## Explicit inputs

Use Node 22+ and your own Ed25519 private key in an owner-only file/private directory. The existing `loadOwnerKey`, `readOwnerText` and exclusive `writeOwnerJson` helpers reject public-readable files, symlinks and overwrites on supported POSIX systems. Never put private keys, proof nonces, HMAC material or signatures in source, shell arguments, public vars, chat or logs.

Supply `fetchImpl` explicitly. Importing the module makes no request; there is no default live transport. Offline checks inject mocks/local workerd. A live transport requires separately reviewed activation. The client pins `https://api.runlater.io`, rejects redirects, applies a five-second whole-response deadline and 32-KiB/32-chunk response limits, bounds JSON requests, redacts errors and makes one request per action. It runs no polling, retry or payment loop.

Two **nonsecret reviewed release inputs** are currently required: release ID and callback `Keyring` metadata. `/v1/beta` exposes capacity/limits but no release ID. `/v1/callback-key` returns scoped key material/policy ID/window but not activation/sign/verification times. Before presenting a complete self-service live setup, the activation owner must publish the exact immutable nonsecret release policy. Do not infer times from the clock, invent response fields or copy another release. The local compiled fixture uses its actual explicit profile.

## Register and recover the original grant

```js
import {PublicBetaClientV1, PUBLIC_BETA_TERMS, loadOwnerKey, writeOwnerJson}
  from '../examples/public-beta-client.v1.mjs';

const client = new PublicBetaClientV1({
  privateKey: loadOwnerKey(ownerPrivateKeyPath),
  releaseId: reviewedReleaseId,
  fetchImpl: explicitlySelectedTransport,
});
const capacity = await client.status(); // optional read; allocates no project
const offer = await client.challenge(); // public key only, no invitation token
// Caller explicitly approves the fixed terms before completing.
const receipt = await client.complete(offer, PUBLIC_BETA_TERMS);
writeOwnerJson(newReceiptPath, receipt);
```

The client reconstructs Rust's ordered ticket hash and public-registration proof bytes. It checks purpose/origin/key/nonce/expiry, fixed terms/scopes and the **full** release-derived ticket ID before signing. Completion sends only `challenge_id` and the signature. Valid possession must precede project allocation. The receipt binds full ticket/project/key/grant, original start/expiry, 100 credits and all five scopes. It describes original allocation, not current balance.

After uncertain completion, keep the same key/release and deliberately call `client.recover()`. The client derives the expected project even without a saved receipt. Within the still-valid challenge window, a deliberate `complete` retry also returns the original allocation. Later, a fresh challenge with the same key may recover that existing grant; it never restarts/refills it. To reload known context, pass the owner-loaded `receipt` to the constructor. A remembered receipt must remain identical. No automatic retry or replacement key/trial follows a timeout or lost response.

## Private receiver setup and ownership proof

Prepare the [receiver Worker](../examples/public-beta-receiver/README.md) and its private owner configuration channel first. Its source config is disabled. Receiver creation/deployment belongs to the owner's separately authorized Cloudflare workflow; this guide runs no provisioning or secret-install command.

```js
import {receiverSetup} from '../examples/public-beta-client.v1.mjs';

const callbackKey = await client.callbackKey('retrieve_callback_v1');
const privateBindings = receiverSetup({
  receipt: client.receipt, callbackKey,
  callbackPolicy: reviewedNonsecretCallbackKeyring,
  url: ownedExactWorkersUrl, // https://worker.account.workers.dev/callback
});
writeOwnerJson(newReceiverBindingsPath, privateBindings);

const pending = await client.createDestination('owned_receiver', 1,
  ownedExactWorkersUrl, 'destination_create_v1');
const proof = await client.prepareDestination(pending, 'destination_proof_v1');
writeOwnerJson(newProofPath, proof);
```

Privately install the bindings and `CALLBACK_KEYS` through supported owner secret mechanisms. The receiver gets only this project's `beta_v1` key, never `BETA_CALLBACK_MASTER`, an API signing private key or a RunLater namespace binding. Key retrieval requires signed `manage_destinations` authority, a fresh request nonce and a nonempty command idempotency key. The response is `no-store, private`; deliberate re-retrieval with a fresh nonce returns the same derived key, not another grant. Holding the HMAC key permits forging that project's callbacks, so keep it private.

Privately install the exact `{id,response,expires_at_ms}` proof as `OWNERSHIP_PROOF`, without printing its nonce-bearing response. There are five minutes and three lifetime issuances per endpoint version. Rollout must finish before expiry; the client neither uploads proof nor burns retries automatically. The receiver returns the preinstalled static response only when the server's complete nonsecret verification tuple matches. It never reflects caller data or exposes a public installation route.

After private installation completes, deliberately verify:

```js
const verified = await client.verifyDestination(pending, 'destination_verify_v1');
```

Receivers must be exact managed `worker.account.workers.dev` HTTPS hosts independently admitted by the API's strictly-public Fetch policy. No account-root/custom-domain/IP/extra-label/query/fragment/redirect expansion follows from proof. The example additionally fixes `/callback`. Ownership does not prove arbitrary-host SSRF/DNS safety; local tests do not prove provider routing/TLS/isolation.

## An explicit task and signed management

```js
const input = {endpoint_id: verified.endpoint_id, body: '{"synthetic":true}',
  operation_key: 'owner_operation_1', run_at_ms: explicitlySelectedDueTime};
const accepted = await client.enqueue(input, 'owner_task_1');
const task = await client.task(accepted.result.id);
// Independent deliberate owner choices, never automatic after enqueue:
// await client.cancel(accepted.result.id);
// await client.redrive(accepted.result.id, 'owner_redrive_1');
// await client.revokeDestination(verified.endpoint_id, verified.version, 'owner_revoke_1');
```

Schedule no later than receipt expiry. The server selects the newest verified destination version and snapshots it at acceptance; a pending latest version blocks fresh selection. Version 2 cannot retarget accepted version-1 work. After uncertain admission, preserve body/run time/operation key/command idempotency key for a **deliberate** retry, with a fresh authentication nonce. It must not reserve again. Redrive is a separate command preserving source snapshot/operation identity under current revocation checks.

Callbacks are at least once. SQLite dedup and the example's local counter share a transaction and survive restart. Repeated operation/body has no second local effect; changed bytes conflict. This is not an exactly-once wrapper for external HTTP/email/payments. Cancellation/revocation cannot recall an effect already in flight. Keep dedup history while accepted/replayable work remains; application reconciliation must handle in-flight uncertainty.

## Local evidence and release boundary

`npm run test:public-beta-client-v1` checks native Rust canonical bytes, full-context substitutions, uncertain-response recovery, signed routes, proof bounds and transport failures against protocol mocks. `npm run test:public-beta-client-local` builds the actual production API and runs the client/receiver in local workerd/SQLite with private fixture binding updates, real ownership verification and exact-body callback authentication/dedup. That fixture channel is not a public receiver endpoint or a live deployment recipe.

Reviewed policy publication, practical owner secret rollout, controlled provider proof and separately authorized activation remain necessary before claiming a live quickstart. This source changes no published alpha/discovery assets, live routes, credentials, grants, DNS or hosting. See [the handoff](PUBLIC-BETA-CLIENT-PLAN.md).
