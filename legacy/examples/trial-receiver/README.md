# Trial receiver pairing — disabled source example

This **optional beta reference Worker** is an actual bounded callback inbox, not a generic agent wake-up service. Local workerd tests exercise its SQLite state and the existing RunLater callback-v2 protocol. Nothing in this directory deploys a receiver, creates a Cloudflare resource, activates anonymous trials or connects Grok to a webhook. The example configuration is disabled, with workers.dev, previews and observability off.

The product target is delivery to a customer-provided HTTP endpoint, not a bot-specific or permanently Workers.dev-only architecture. This source milestone does not widen the current beta's managed-host egress restriction. Customers do not have to adopt this inbox design as the future callback architecture; broader endpoint support requires separate safe-egress work.

This optional receiver must be separately deployed and privately configured in an operator-authorized runtime. RunLater receives no Cloudflare credentials. A generic OAuth client cannot be assumed to deploy that runtime or consume its inbox. An application's later inbox consumer or downstream action requires its own design and authorization; no public inbox-reading endpoint is provided here.

## Private setup and public manifest

The immutable intent is one project, one exact `https://worker.account.workers.dev/callback` URL, one receiver Ed25519 setup key, and one pairing ID. The setup window is **at most five minutes**. Deploy the disabled runtime and prepare its private configuration channel first; preparing a manifest before a slow infrastructure rollout can exhaust that deadline. There is no automatic replacement key, binding, receiver, trial or quota refill after failure.

The optional `prepare.mjs` helper is **offline only**. It generates a receiver setup key and a signed public manifest, never an owner key or Cloudflare credential. Its four explicit arguments are `--release`, `--project`, `--url` and `--output-dir`. The output must be a new absolute directory outside this repository, underneath an existing owner-only directory. Symlink ancestors, unsafe parent permissions and existing output paths are refused. The helper uses exclusive creation: a 0700 directory and 0600 files named `receiver-setup-private.pem` and `receiver-manifest.json`. Only the public manifest is printed. It performs no HTTP requests, secret installation or deployment. Tests create disposable local fixtures and delete them.

**Running this helper for a real project creates a credential and requires the operator's specific authorization.** Keep the private PEM outside Git, chat, model context, command-line arguments, public vars and logs. Install it using an approved private provider input mechanism; this guide intentionally provides no command embedding the secret. A failed preparation never replaces an existing identity; if local cleanup is prevented, any residual files remain under the owner-only output directory and must be inspected privately.

Required bindings after separately authorized deployment/configuration:

| Binding | Purpose |
|---|---|
| `RECEIVER_ENABLED` | Explicit `pairing-configured`; source defaults to `disabled`. |
| `RECEIVER_MANIFEST` | Exact signed public manifest produced for the project's release, callback URL and five-minute window. |
| `RECEIVER_SETUP_PRIVATE_KEY` | Secret PKCS8 Ed25519 PEM matching the manifest public key. Never returned by HTTP or tools. |
| `INBOX` | This receiver's own SQLite-backed `TrialReceiverInbox` namespace. No access to RunLater's internal storage. |

`GET /.well-known/runlater-receiver` returns only that configured, signed public manifest. It cannot set a project, URL, key, expiry or identity. The API's public probe can sign only the exact privately configured context with a distinct domain prefix; it cannot obtain a private pull/ack signature.

## Fixed-origin pull, not public secret installation

The [wire contract](../../docs/RECEIVER-PAIRING-WIRE.md) separates project authority from receiver possession. The API first requires a trial capability explicitly scoped for `receiver_setup`, pins this manifest and probes the exact managed callback URL. Neither a public project ID nor the public manifest is authority to install a receiver into an unrelated project.

The receiver then **pulls** private installation material from the fixed `https://api.runlater.io` origin. It signs fresh, short-lived request envelopes with its setup key. It accepts no caller-supplied API URL, redirect, cookie, token, key, proof or installation payload. Pull/ack signatures, callback material and installation digests are never returned on public routes. Outbound requests have a five-second overall deadline, 4 KiB response-header bound and 16 KiB/64-chunk response-body bound. Non-200 replies, redirects, malformed contexts and digests fail closed.

The first metadata/probe request initializes a **fixed, durable alarm schedule** under the privately configured intent. At least 30 seconds separate network cycles, at most ten cycles occur, and polling stops at the original setup deadline. Public requests cannot trigger an immediate poll, reset/extend its budget or change its cadence. A cycle reserves its count and pre-arms the next alarm **before** network I/O; duplicate alarms and process restarts preserve the bound. These limits are not a Cloudflare spending cap or protection against all public ingress abuse.

The API returns existing project-derived HMAC-v2 material, its original validity policy and the existing hidden destination proof directly over authenticated HTTPS. The receiver validates every context field and digest, then persists the exact immutable installation before sending its signed acknowledgement. API acknowledgement calls the same `/callback` route for existing non-reflection ownership verification. No transaction/lock spans that network await, so this proof callback can reenter the Durable Object safely.

A lost acknowledgement response retries **ack only**, never pulls a replacement payload or invents another binding. A pre-install lost pull can retrieve the same immutable payload during the original window. Final readiness is the API's existing proof result, not simply an HTTP connection or manifest signature. If the final response is lost near expiry, use the trial's normal status operation to reconcile; do not infer failure means no binding was committed.

## Callback handling and private durable inbox

`POST /callback` accepts only bounded existing protocol traffic:

- Exact domain-separated receiver probe, within the configured setup window.
- Existing destination-verification bytes: only a matching, unexpired request receives the privately installed hidden response. It never reflects supplied proof material.
- Existing HMAC-v2 callback, with exact policy/key/tenant/task/operation/timestamp/body authentication.

The short setup expiry does **not** truncate callback key validity. After installation, valid callbacks continue through the original callback policy horizon, including callbacks already accepted before trial revocation. Disabling new API pairing admission does not remove installed receiver data. Never purge or replace the receiver database to reset deduplication.

The receiver stores up to 128 unique operations, each with at most a 1 KiB body, in private SQLite. An operation key and body digest identify a duplicate; an identical retry returns 204 without adding another inbox entry, while a changed body under the same key returns 409. Body bytes, dedup record and local accepted count commit atomically. No external HTTP/email/payment effect is applied, and no public read/reset route exists. Provider administrators can access this runtime's storage; this is private receiver custody, not an encryption-against-the-operator claim.

The one constant object name in the receiver's own namespace prevents a configuration edit from selecting a fresh project inbox. Persisted manifest, installation digest and full context are revalidated; rebound configuration or malformed stored payload fails closed. This does not protect against an operator intentionally deleting/replacing the whole namespace or compromising the runtime.

## Local verification and remaining gates

`node --test examples/trial-receiver/*.test.mjs` uses ephemeral keys and local workerd/SQLite only. Test-only private RPC wrappers accelerate alarm time; those wrappers are never part of `worker.mjs` or the deployment config. Tests cover context/signing separation, bounded private transport, immutable install, reentrant ownership proof, duplicate alarm cooldown, lost acknowledgement/restart, callback authentication/dedup/capacity, disabled mode, unsafe offline preparation paths and callback validity after setup expiry.

The API's compiled composition test additionally owns actual API ↔ reference-receiver pairing. These local proofs do not establish live workers.dev routing, provider DNS/TLS isolation, production CPU/storage limits or a real agent's wake-up capability. Those tests and any deployment, new key, namespace, receiver setup authority, feature activation or downstream application behavior require separate authorization. Both API/gateway pairing and trial feature flags remain default-off in this source milestone.

References: [Cloudflare SQLite-backed storage](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/), [Durable Object alarms](https://developers.cloudflare.com/durable-objects/api/alarms/), [Node crypto in Workers](https://developers.cloudflare.com/workers/runtime-apis/nodejs/crypto/).
