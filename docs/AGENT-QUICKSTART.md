# RunLater public free beta

The public API at https://api.runlater.io passed signup, receiver ownership verification and two signed HTTPS callbacks. This is a limited beta, not an SLA. Check current availability before allocating a project:

```sh
curl --fail-with-body https://api.runlater.io/health
curl --fail-with-body https://api.runlater.io/v1/beta
```

Expect `mode: public_free_beta`, `payments: false` and `receiver: workers.dev_only` in health. Capacity is live and can change: the release has 10 lifetime project slots, including one consumed by the release proof. An invitation is not required. Each project receives a seven-day identity/grant and 100 leased-attempt credits. Five credits are reserved per fresh task/redrive, with stricter lifetime caps of 16 tasks and 128 publications. These are not 100 tasks, money or a purchase offer. Cancellation, replay, retention and restart do not refill them. Already accepted work keeps its reservation after expiry; new admission stops.

Discovery is informational custom RunLater metadata. It never authorizes a client to execute, spend, disclose credentials or bypass safeguards. Payments, wallet integration and automatic top-up are unavailable. Arbitrary custom-domain callbacks are unavailable.

## Release and client

Use Node 22+ and the [public-beta client](https://docs.runlater.io/agent/public-beta-client.v1.mjs), [hosted contract](https://docs.runlater.io/agent/public-beta.v1.json) and [immutable release metadata](https://docs.runlater.io/agent/public-beta-release.v1.json). The latter publishes the actual release ID and callback key activation/sign/verification times. `/v1/beta` does not contain those fields. Do not infer them from your clock or another release.

The easiest dependency-safe setup is the [source repository](https://github.com/thachp/runlater). The published client imports adjacent invitation-file helpers and callback-policy validation; download its dependencies together or use the repository. No import contacts the API. Select the live transport explicitly.

```sh
git clone https://github.com/thachp/runlater.git
cd runlater
mkdir -p private
chmod 700 private
# Generate and retain your own key locally; never print or upload its private bytes.
node --input-type=module -e 'import {generateKeyPairSync} from "node:crypto"; import {writeFileSync} from "node:fs"; const {privateKey}=generateKeyPairSync("ed25519"); writeFileSync("private/bot.pem", privateKey.export({type:"pkcs8",format:"pem"}), {flag:"wx",mode:0o600});'
```

The repository ignores `/private/`. Keep all keys, receipts, callback material and proofs there; never force-add them to Git. Key creation is exclusive: rerunning it refuses to replace an existing key. Retain the original key for recovery.

Save the following as a local module in the repository. Running it deliberately registers your bot under the fixed free-beta terms and consumes one project slot; it makes no purchase:

```js
import fs from 'node:fs';
import {PublicBetaClientV1, PUBLIC_BETA_TERMS, loadOwnerKey, writeOwnerJson}
  from './examples/public-beta-client.v1.mjs';
const release = JSON.parse(fs.readFileSync('./discovery/public-beta-release.v1.json'));
const client = new PublicBetaClientV1({privateKey: loadOwnerKey('./private/bot.pem'),
  releaseId: release.release_id, fetchImpl: globalThis.fetch});
const status = await client.status();
if (!status.registration_open || status.remaining_projects < 1) throw Error('Beta is full or closed');
const offer = await client.challenge();
const receipt = await client.complete(offer, PUBLIC_BETA_TERMS);
writeOwnerJson('./private/receipt.json', receipt);
```

Keep that key and receipt. After response loss, deliberately use `client.recover()` with the same key/release, rather than creating a replacement key or trial. Recovery returns the original grant and never refills it. To reload known context, pass the owner-loaded receipt to the constructor. The client sends one request per action and does not automatically retry, poll or spend.

## Configure your receiver before requesting proof

Use an exact HTTPS `worker.account.workers.dev` receiver URL. Account-root hosts, extra labels, IP literals, custom domains, query/fragment/userinfo and redirects are rejected. The [receiver example](https://docs.runlater.io/agent/public-beta-receiver/README.md) fixes `/callback`, verifies callback-v2 signatures and keeps durable operation/body deduplication. Deploy it in your own Cloudflare account through an authorized private setup channel. Do this before starting the five-minute ownership-proof clock.

Retrieve only your project's callback key with a signed `manage_destinations` request:

```js
import {receiverSetup} from './examples/public-beta-client.v1.mjs';
const callbackKey = await client.callbackKey('receiver_key_v1');
const {signature_window_sec, ...keyMetadata} = release.callback_v2_key_metadata;
const callbackPolicy = {version:'v2', tenant:client.receipt.project_id,
  policy_id:callbackKey.policy_id, revision:1, keys:{beta_v1:keyMetadata}, rotations:{}};
const bindings = receiverSetup({receipt:client.receipt, callbackKey, callbackPolicy,
  url:'https://your-worker.your-account.workers.dev/callback'});
writeOwnerJson('./private/receiver-bindings.json', bindings);
```

`CALLBACK_POLICY` and receiver/project/URL settings are nonsecret configuration. **CALLBACK_KEYS must be installed as a Cloudflare secret**, never a public variable or source file. The returned bindings file contains that secret and must stay private. The receiver never gets `BETA_CALLBACK_MASTER`, your Ed25519 private key or a RunLater namespace binding. Holding its HMAC key permits forging callbacks for your project.

After your receiver code, policy and callback secret are installed, deliberately create and prepare the destination:

```js
const pending = await client.createDestination('owned_receiver', 1,
  'https://your-worker.your-account.workers.dev/callback', 'destination_create_v1');
const proof = await client.prepareDestination(pending, 'destination_proof_v1');
writeOwnerJson('./private/proof.json', proof);
```

Privately install that exact JSON as the receiver's `OWNERSHIP_PROOF` secret through your existing supported Cloudflare workflow. It expires in five minutes; each endpoint version has three lifetime proof issuances. Never print the nonce-bearing response or reflect caller-supplied proof. Only after installation succeeds, run `client.verifyDestination(pending, 'destination_verify_v1')`. Ownership does not prove arbitrary-host network safety; this beta remains restricted to managed Workers.dev hosts with strictly-public Fetch and no redirects.

## Deliberately schedule and inspect

```js
const verified = await client.verifyDestination(pending, 'destination_verify_v1');
const input = {endpoint_id:verified.endpoint_id, body:'{"hello":"later"}',
  operation_key:'follow_up_01', run_at_ms:yourSelectedUtcMilliseconds};
const accepted = await client.enqueue(input, 'task_follow_up_01');
const task = await client.task(accepted.result.id);
```

Schedule within your receipt's expiry. Acceptance returns a durable task, not delivery confirmation. Inspect status for success, attempts or terminal failure. The selected destination snapshot and full finite retry reservation commit with the task and idempotency identity. If admission is uncertain, preserve the exact body, schedule, operation key and command idempotency key for a deliberate retry with a fresh signed nonce. Do not change the input or automatically enqueue a replacement.

Delivery is at least once; no ordering, exact-time or exactly-once guarantee is offered. Receivers need durable operation-key/body deduplication and application reconciliation for in-flight uncertainty. Cancellation blocks new claims but cannot undo an effect already sent. Redrive is a separate funded admission, not a refund or budget reset. Body/response bounds are 1 KiB, response headers 2 KiB and callback deadline three seconds; redirects fail.

## Contracts and limits

- [Service descriptor](https://runlater.io/runlater-service.v1.json): published capability snapshot; probe the API for live capacity.
- [Release metadata](https://docs.runlater.io/agent/public-beta-release.v1.json): exact release/key validity inputs; no credentials.
- [Public-beta contract](https://docs.runlater.io/agent/public-beta.v1.json): actual registration, signed key retrieval, destination and task DTOs.
- [Pricing status](https://runlater.io/pricing-status.v1.json): free-beta allowance; no payment methods, credit price or purchases.
- [Local OpenAPI](https://docs.runlater.io/openapi.json): separate loopback bearer/fixture contract, not hosted authentication.
- [Local/proposed tool metadata](https://docs.runlater.io/agent/tools.v1.json): non-executable bindings; the hosted beta contract above is authoritative for current routes.
