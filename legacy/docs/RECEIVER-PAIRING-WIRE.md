# Receiver pairing v1 — optional managed-beta adapter, source only, default off

Requires `MCP_RECEIVER_PAIRING_ENABLED=operator-approved` in API and gateway, existing anonymous-trial gate, and **new explicitly consented** `receiver_setup` descriptor permission. Old descriptors and owner delegation scopes never gain it. One immutable receiver per trial. No automatic deployment or provider credentials.

## Private receiver intent and public manifest

Privately deployed receiver configuration pins the exact project, callback URL, pairing identity and its private Ed25519 setup key. A public endpoint must never sign arbitrary contexts or setup request prefixes. Public manifest property order:

`{version:1,release_id,project_id,url,receiver_public_key,pairing_id,issued_at_ms,expires_at_ms,signature}`

Keys/signatures are lowerhex (32/64 bytes), pairing ID is random32bytes lowerhex. URL is exact HTTPS managed `worker.account.workers.dev/callback`, no query/fragment/credentials/port. Expiry is >issuance and <=issuance+300000ms, within trial expiry. Signature bytes:

`RunLater receiver manifest v1\n` + compact JSON `[1,release_id,project_id,url,receiver_public_key,pairing_id,issued_at_ms,expires_at_ms]`.

`manifest_sha256` hashes compact JSON of the full manifest in the above order, including signature.

## Capability-authorized pin

`POST /v1/mcp/trials/receiver`, body exactly the manifest, ordinary anonymous-trial signed request with capability and gateway signature; Idempotency-Key is pairing_id. This pins only under receiver_setup authority. Pin alone never makes receiver ready. Changed binding conflicts permanently, including after expiry. Successful retry is safe and never refills credit.

Safe response: `{state:'awaiting_receiver'|'ready',project_id,receiver_ready:boolean,endpoint_id:null|'receiver'}`. No installation digest, hidden proof or callback key in capability-path responses. Existing trial status/validate use actual receiver_ready and may include endpoint_id:'receiver' only when ready; before readiness retain the existing shape. No separate polling route or implicit setup on status.

## API-to-receiver public probe

POST exact callback URL with body `RunLater receiver probe v1\n` + compact JSON `[1,release_id,project_id,url,receiver_public_key,pairing_id,manifest_sha256,nonce,expires_at_ms]`. Nonce is32bytes lowerhex. Receiver accepts only its privately pinned exact context and unexpired intent. Response `{signature}` signs those exact bytes. It must not sign other domain prefixes. API uses existing bounded safe egress (no redirects, managed host restrictions,3second deadline,1024byte response limit). At most3 reserved probe attempts; reserve before awaits.

## Receiver-private pull and acknowledgement

POST fixed `https://api.runlater.io/v1/mcp/receiver/pull` body `{}`; POST `/v1/mcp/receiver/ack` body `{installation_sha256}`. No OAuth/capability sent by receiver.

Headers: RunLater-Project-Id, RunLater-Public-Key (receiver key), RunLater-Pairing-Id, RunLater-Issued-At, RunLater-Expires-At, RunLater-Nonce, RunLater-Request-Signature. No Idempotency-Key. Signed bytes:

`RunLater receiver setup request v1\n` + compact JSON `[1,'https://api.runlater.io',release_id,project_id,pairing_id,manifest_sha256,'POST',path,sha256(exactbody),issued_at_ms,expires_at_ms,nonce]`.

Window <=60000ms and <=manifest expiry. Each private pull/ack envelope nonce is single-use at the project, with at most32 stored nonces for the immutable setup; retry uncertain responses with a fresh signed nonce, never a new binding/payload. API authenticates only an existing pinned project before routing/allocating a project object. Public probe signatures cannot authorize pull. Receiver trusts fixed API HTTPS origin, never supplied endpoints, redirects or public installation payloads.

Pull returns `{installation,installation_sha256}` where installation has these fields (canonical JSON uses lexicographic object-property order recursively; arrays retain order):

`{version:1,project_id,pairing_id,manifest_sha256,installation_id,expires_at_ms,callback_url,callback_policy,callback_keys:{beta_v1:key_hex},destination_proof:{id,response,expires_at_ms},endpoint_id:'receiver',endpoint_version:1}`.

installation_id =manifest_sha256. Digest hashes compact JSON installation. Policy/material are EXISTING project-derived HMACv2, with ORIGINAL callback validity horizon; never a new global key or new rotation. Hidden destination proof is the existing non-reflection protocol. Installation/proof expiry equals manifest expiry. API keeps bounded private hidden-proof setup state for stable lost-response replay, never callback material. Runtime persists exact installation before ack; material/proof/digest/pull signatures never returned to public trigger/model/gateway or logged.

Ack succeeds only after existing outbound destination verification, returning the safe ready response. Verification attempts bounded3 and reserved before network; repeated same ack recovers lost responses without new proof/key/endpoint. API checks current trial revocation/expiry before routing and again after outbound awaits before committing readiness. Installed receivers continue normal HMAC callbacks beyond short setup expiry through existing callback policy; pairing admission being disabled must not disable installed callbacks. Setup that expires before readiness fails closed, with no automatic proof epoch, reset, replacement, or quota refill. Lost final ack can be checked via ordinary trial status; receiver retains installed material for callback delivery.

All setup HTTP responses are `Cache-Control:no-store, private`; errors never echo credential/body material. No claim that callback delivery wakes a Grok session. Deployment and private configuration remain separately authorized prerequisites.

## Rollback and revocation

Once receiver pin/pairing state exists, retain a compatible reader on rollback;
pre-pairing readers can reject the newly persisted fields. Disable pairing admission
rather than restoring an incompatible old binary or deleting state. Existing
installed callback material cannot be recalled by revoking an OAuth/task capability.
That revocation stops future API authority but does not cancel accepted tasks or
undo callbacks. Operator-level project revocation remains the existing dispatch
cutoff; preserve receiver deduplication and the callback validity horizon.

This managed-host adapter is NOT the general product requirement for customer endpoints. Arbitrary HTTPS/webhook support needs a separate egress and destination-authorization design; third-party endpoints may provide neither ownership proof nor HMAC support. Nothing here expands host policy. Capability expiry/revocation prevents future API/setup authority but does not recall previously admitted callbacks or already transferred HMAC material; operator project revocation remains the queue-wide stop.
