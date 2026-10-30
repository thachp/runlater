# Guarded automatic API releases

`release-api.yml` builds on a GitHub runner after **Local prototype checks** passes for a push to main. It deploys only the current main SHA, serializes releases without cancelling an in-flight mutation, and uses the `runlater-public-api` environment. Fork/PR runs cannot release. Normal releases upload one version, recheck active deployment/settings for drift, then promote that exact version. The provider must then report that version alone at100%, and public health must return the same Cloudflare version ID and beta mode; an alpha health200 cannot pass. Only bounded public health **reads** may retry; uploads/promotions never automatically retry. There is no infrastructure creation, migration, domain change, secret issuance or rollback.

This runs ordinary releases on GitHub runners after separately completed first provisioning. It never creates a missing public Worker. The existing `runlater-alpha-api` is a different application/profile and is deliberately rejected. Its settings URL must not be used as the beta release target. Keep alpha and accepted work intact.

The existing alpha has no Workers Builds triggers (read-only API inspection). Native Workers Builds is another option, but requires a GitHub integration grant and deploy-token setup and runs on push independently of this repository's long integration suite. Do not configure both systems. This implementation chooses Actions so the actual required CI finishes before release.

## Configuration and activation safeguards

1. Review/merge source and protect main: require pull requests and passing `rust-and-hosts`, `offline-contract` and `offline-codec` checks, an up-to-date branch, resolved conversations and linear history; block force pushes/deletion and enforce protections for administrators. The owner chose zero required reviewer approvals. Workflow code does not configure repository administration settings.
2. Use the `runlater-public-api` GitHub environment with a main-only branch restriction. The owner explicitly chose automatic releases without a manual environment reviewer; administrator bypass remains disabled. Keep both release flags false during diagnosis or unresolved provider drift.
3. Specifically authorize a **new persistent Cloudflare CI API token**, stored only in that environment's `CLOUDFLARE_API_TOKEN`. Minimum current documented scope: **Workers Editor restricted to the existing `runlater-public-api` Worker**, plus **Queues Read on the selected RunLater account**. Pinned Wrangler4.154.0 lists Queues by name during `preUploadApiChecks` even for versions upload; it does not create them. Queue metadata listing is account-scoped. No Account Settings Read is needed with the explicit account ID; no DNS, routes, billing, Queue Write, token-management or product-wide Workers Admin permission is requested. Current Cloudflare roles support individual Worker scopes; the legacy Workers Scripts Edit permission is broader and must not be silently substituted. Editor can update code/settings/secrets for this Worker, and malicious code could use its existing data bindings or expose its callback master; it is persistent privileged access even with per-Worker scope. Set a short expiry and rotate/revoke explicitly. Existing local OAuth credentials must not be copied to GitHub. Do not create this token without specific consent. A per-Worker token cannot be created for a nonexistent Worker; first provisioning remains separate. If the account/token UI cannot express the narrow scope, stop and report rather than expand permissions.
4. Complete separately approved first provisioning, master-secret installation, verified bindings/consumer/rate limits, and supervised public cutover. This workflow never provisions the beta or retries the failed launch. Preserve the existing fixed beta profile, release ID, namespace identities, revocations and key validity. A normal source release must not reset an admission/grant cohort. Migration/schema/policy changes require their own review and release procedure.
5. In the protected environment configure nonsecret variables:
   - `RUNLATER_RELEASE_CONFIG`: strict JSON of the approved **existing-resource** Wrangler profile. Adapt `beta/wrangler.example.jsonc`: main `build/worker/shim.mjs`, remove `$schema`, `build`, `migrations`, and Queue `consumers`. Add `"version_metadata":{"binding":"RELEASE_VERSION"}` (nonsecret provider-generated version identity). Keep all required bindings, CPU50, observability off, previews/workers.dev off and strict-public fetch. Set the actual immutable approved `PUBLIC_BETA_PROFILE`, existing revocations and `PUBLIC_BETA_ENABLED`=`operator-approved`. Never include secrets. Consumers/routes are separately managed and unchanged by version promotion.
   - `RUNLATER_RELEASE_APPROVAL`: JSON `{ "worker":"runlater-public-api", "account_id":"<approved account>", "worker_tag":"<existing immutable Worker tag>", "config_sha256":"<canonical config hash>", "settings_schema":"runtime-v1", "settings_sha256":"<reviewed runtime settings hash>" }`. Obtain the immutable tag from `/workers/services/runlater-public-api` and bind it to the exact Worker name and production environment. Obtain provider settings with an authorized read; never export secret values. `settingsDigest` in `scripts/api-release.mjs` fingerprints the parsed JSON `result` for `/workers/scripts/runlater-public-api/settings` using the required `runtime-v1` schema. It excludes only the per-version annotation keys `workers/message`, `workers/tag` and `workers/triggered_by`, then recursively sorts object keys. The annotation tag is distinct from the immutable Worker tag. All bindings, policy settings, unknown fields and other annotations remain fingerprinted. Untyped or unknown-schema approvals fail closed. Hashes are drift detectors, not a substitute for reviewing configuration. Refresh only after reviewing an intentional provider change. No real profile or account ID is committed here.
   - Initially keep `RUNLATER_RELEASE_ENABLED` unset. Only set to `true` after exact activation approval/protections/baseline verification. Separately set repository variable `RUNLATER_AUTODEPLOY_ENABLED` to `true` to permit the job trigger. The execution gate is the distinct environment variable `RUNLATER_RELEASE_ENABLED`; never define that name at repository/organization scope. GitHub evaluates job `if` before environment variables are available. Setting only the repository trigger flag cannot satisfy the script gate. Both flags must be deliberately enabled.
6. Verify first deployment with supervision. Read-only credential checks do not prove upload/promotion permissions; verify the first token-based upload and promotion under supervision. Before upload, read service metadata and require the approved Worker name, production environment and immutable tag. Wrangler4.154.0 unconditionally refuses an API-origin upload under `--strict`; for that matching API-origin identity only, acknowledge its generic warning using the existing approved settings/deployment fingerprints. Other origins retain `--strict`. Before either upload path, read the remote secret listing, require the existing master name, and reject collisions with every local variable or binding name (Durable Objects, Queue producer, rate limits and version metadata included). Check both secret-list and settings secret-binding names; neither source may be omitted. Secret-name sets are separately pinned across upload, independent of provider list order. Secret names and values are never logged. Both origin paths still require unchanged settings and deployment fingerprints after upload and before promotion, a matching Worker tag in the upload receipt, and current main. Unexpected changes fail closed. Preview URLs must remain absent. Recheck `https://api.runlater.io/health` and truthful beta availability after promotion, with no signup/task traffic. Publish nonsecret release/key validity metadata separately.

## Failure, drift and rollback

For a failed preflight with no uploaded-version receipt, **Diagnose API release (read only)** can run from main independently of the release execution gates. It never changes those gates. It uses the same environment credential for at most ten GETs: GitHub main, existing Worker settings/deployments, one page of Queue metadata, and the six fixed dashboard metadata paths below. Each read has an eight-second limit, total foreground budget35seconds and response bound64KiB/64chunks; the job has a three-minute limit. Exhausting the shared budget skips remaining reads. There is no retry, redirect following or pagination. Output is restricted to HTTP statuses, numeric API error codes, fixed error labels and baseline/source/binding booleans. It never emits response bodies, credentials or exception messages, refreshes a baseline, or uploads/promotes anything. This diagnostic can identify which metadata read failed; it does not certify the token's write permissions or authorize a broader token. Reconcile versions/deployments before any retry of an uncertain upload.

The dashboard paths match locked Wrangler's pre-upload comparison. All are GETs
below `/accounts/<approved-account-id>`; the Worker and production environment
are fixed in source, with no arbitrary URL or header input.

| Output label | Fixed path |
| --- | --- |
| `dashboard_bindings` | `/workers/services/runlater-public-api/environments/production/bindings` |
| `dashboard_routes` | `/workers/services/runlater-public-api/environments/production/routes?show_zonename=true` |
| `dashboard_domains` | `/workers/domains/records?page=0&per_page=5&service=runlater-public-api&environment=production` |
| `dashboard_subdomain` | `/workers/services/runlater-public-api/environments/production/subdomain` |
| `dashboard_environment` | `/workers/services/runlater-public-api/environments/production` |
| `dashboard_schedules` | `/workers/scripts/runlater-public-api/schedules` |

The domain request intentionally checks one page, not the complete inventory.
Bodies are discarded after bounded parsing; secret binding names/values and
provider-provided links are never reflected or followed. Local fake responses
and the pinned Wrangler path test prove source behavior, not CI permissions.

If this workflow is disabled by the operator, source changes do not enable it.
Running a diagnosis requires separate explicit permission to temporarily enable
**Diagnose API release (read only)** and dispatch it once on reviewed main using
the existing `runlater-public-api` environment's CI token, then restore its
disabled state. The proposed run is capped at ten metadata GETs/35 seconds
(three-minute job ceiling), exposes only the sanitized fields above in Actions
logs, and creates no credential, resource, trial, task or delivery. It adds no
token scope and does not enable other workflows. Coordinate any source merge
with release automation separately; merging to main can start the normal release
pipeline, which is outside permission for a read-only diagnostic run.

Fixed release-phase labels, HTTP status numbers and numeric child exit status locate failures without exposing provider bodies, exception text or child stdout/stderr. The uploaded version UUID and source SHA are emitted immediately to the Actions log before post-upload checks, preserving a receipt even on later failure. After promotion, bounded public `/health` verification requires HTTP 200, configured public-beta mode and that exact version. Current main and the sole 100% active provider version are rechecked after a matching health response. This proves ordinary public routing, not a full signup/callback journey or a custom-domain inventory audit. No domain-administration permission is added.

Public health reads have a 120-second overall monotonic deadline, at most 12 requests, five seconds per request (including body), and at least five seconds between attempts. Transport failures, HTTP 429, selected transient 5xx and a well-formed beta reporting another valid version may retry. A valid `Retry-After` (seconds or HTTP date) is respected; a delay that cannot fit ends verification without retrying early. Malformed retry metadata fails closed. Redirects are rejected without following, and there are no authorization/version-override headers, fallback hosts or identity bypasses. Wrong profile/configuration, invalid identity/JSON/UTF-8, more than 4096 body bytes or 128 chunks, and non-retryable statuses fail closed. Diagnostics contain only attempt/elapsed/status numbers, fixed outcome categories and match booleans, never response bodies, raw headers or exceptions. The health endpoint's existing IP gate remains unchanged; a 429 may represent either limiting or a gate failure. A transient mismatch is not evidence of its particular cause.

Failure after promotion explicitly reports **promotion completed; verification incomplete**, preserves the receipt and requires reconciliation; it never promotes again or rolls back. Each final provider/GitHub read retains its separate 15-second deadline; each Wrangler child has 120 seconds, the job 20 minutes. These are runner bounds, not Cloudflare billing hard caps. Upload or promotion timeout can have executed remotely. Inspect version/deployment history before retry, record the exact uploaded version, and preserve all DO/Queue state and secrets. A staged but unpromoted version may remain after a guard failure. Never automatically delete it or reset resources. Provider external administrators can race the final check; serialize all releases operationally as well.

Rollback means explicitly promote a reviewed prior compatible Worker version after checking state-schema compatibility; no automatic data rollback and no DNS remap. An old binary may be unsafe after a migration. Keep `RUNLATER_RELEASE_ENABLED` false during investigation. Rotating secrets or changing revocations/profile/settings intentionally invalidates the pinned baseline until reviewed. No automatic cohort refill, key generation, paid logging or resource provisioning occurs.

## Local verification

`node --test scripts/api-release.test.mjs` exercises gates and mocked provider flow, including missing Worker/secret, drift and uncertain upload/promotion with no retries. `./scripts/build-production.sh` builds the Rust/Wasm production artifact. Tests never contact Cloudflare. No end-to-end CI credential/deployment success is claimed until activation. Health version metadata is null in local configurations without the optional provider binding; the automated release profile requires the binding and refuses null identity.

### Dashboard-origin releases

A dashboard secret edit also changes Worker provenance to `dash`. Pinned Wrangler
then downloads routing and binding metadata before its strict configuration check.
An existing custom domain omitted from the local profile, or an omitted service
environment, appears to be a deletion even for a version-only upload.

The release guard optionally accepts exactly this existing domain description:

```json
{"routes":[{"pattern":"api.runlater.io","zone_name":"runlater.io","custom_domain":true,"enabled":true,"previews_enabled":false}]}
```

The single already allowlisted egress service may also explicitly declare
`"environment":"production"`. Other domains, routes, environments, extra fields
and extra services are rejected. Omitting these optional descriptions remains
supported for existing profiles. Adding them changes the complete config digest
and requires a separately reviewed approval; nothing refreshes it automatically.
Dashboard-origin uploads retain `--strict`. The version-only release flow does
not create or change routes, domains, secrets or resources.

Before reconciling a release profile, compare actual version module bytes and the
complete settings fingerprint, confirm the intended existing domain/environment,
recheck current main and absence of conflicting releases, and review the exact
new config/approval. Preserve secret bindings and the live settings baseline.
This source change does not update GitHub variables or retry a failed release.

Child failures emit only numeric exit status, a fixed diagnostic class and
allowlisted authentication error codes. Raw stdout/stderr, arbitrary provider
messages, URLs and credentials are never printed. Output inspection is bounded;
unknown or truncated failures may remain unclassified. A class is a hint, not
proof that an upload had no effect. Retain any version receipt and reconcile live
versions/deployments before considering a retry. The existing read-only
diagnostic uses the CI credential when endpoint permission evidence is needed;
successful local OAuth reads do not prove that CI has the same permissions.

`node --test scripts/api-release-dashboard.test.mjs scripts/api-release-errors.test.mjs`
checks exact config restrictions, the pinned Wrangler comparison with synthetic
offline metadata, strict-mode retention and sentinel-secret redaction. These
tests are not hosted deployment or credential-permission proof.

References: [Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/), [configuration](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/), [versions](https://developers.cloudflare.com/workers/versions-and-deployments/), [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

Permission evidence: [Workers roles and per-Worker scopes](https://developers.cloudflare.com/workers/authorization/workers/), [version upload API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/create/), [Queue listing permissions](https://developers.cloudflare.com/api/resources/queues/methods/list/). Scope support is documented, not yet exercised with a new token in this account.

### Latest uploaded settings and baseline migration

The settings endpoint describes the latest uploaded version, which may be staged rather than active. Expected version labels therefore change without changing runtime policy. The active deployment fingerprint is checked separately and must remain unchanged until promotion.

The initial reviewed configuration replaces the nonsecret `RUNLATER_RELEASE_RUN` binding with `RELEASE_VERSION` version metadata. This binding change is deliberately **not** normalized away: review it against the approved configuration and explicitly install a `runtime-v1` baseline for that configuration before enabling another release. Do not refresh a baseline merely because a guard failed. Reconcile the exact staged version, immutable Worker identity, secret-name sets, bindings and active deployment first. A failed upload or post-upload check does not authorize promoting the staged version.

## Optional general HTTPS transport selection

The API release guard accepts exactly one of these private service bindings, or no
egress binding at all:

| Transport | Binding | Service | Named entrypoint |
| --- | --- | --- | --- |
| Native observed-peer/IP pinning | `GENERAL_HTTPS_EGRESS` | `runlater-general-egress` | `EgressBinding` |
| Worker provider public-network boundary | `GENERAL_HTTPS_EGRESS` | `runlater-public-fetch-candidate` | `PublicFetchBinding` |

The exact tuple is the selector. Crossed service/entrypoint pairs, aliases, default
entrypoints, extra properties, multiple bindings and fallback lists are rejected,
even with a refreshed config digest. The native tuple remains valid as before;
absent egress configuration stays absent. Source support changes no release profile,
feature flag, provider binding, adapter setting, trust key or namespace.

Either binding requires an explicit nonzero lowercase 64-hex
`GENERAL_HTTPS_EGRESS_REVIEW_REVISION`. This value identifies a separately reviewed
artifact; its syntax is not proof of its code, runtime or network behavior. Existing
API admission still requires protocol-1 readiness, the exact matching revision and
positive bounded receipt capacity, then sends that revision in the immutable attempt
envelope. The adapter rejects a different revision. The release script does not probe
the adapter or infer readiness from its binding name. General HTTPS admission still
requires its separate `GENERAL_HTTPS_ENABLED=operator-approved` flag and the existing
trial/gateway authority gates. Missing flags do not activate it.

Both complete approved-config and runtime-settings fingerprints remain mandatory.
Changing a transport or its reviewed revision invalidates the old config approval;
changing provider bindings also invalidates the runtime baseline. Review/reconcile
the intended provider transition separately before a normal release. Never refresh
an approval merely to bypass a failure, reinterpret a native revision as Worker
proof, repoint the native service behind its existing name, or silently choose an
available alternative. This workflow releases only the existing API; it never deploys adapter code, creates
adapter storage, enables adapter flags or changes adapter receipt identities. An API
binding installation/change is an explicit reviewed runtime configuration transition,
not an ordinary code-only release.

Native `EgressContainer` and Worker `PublicFetchReceipts` retain separate permanent
receipt namespaces and fixed singleton identities (`runlater-egress-v1` and
`runlater-public-fetch-v1`, respectively). Do not copy, clear, migrate or
substitute receipt stores to change transports. Account for running/uncertain
attempts before any transport transition, and preserve same-fence replay truth.
The Worker candidate's hosted boundary/recovery/TLS proof and authenticated API/MCP
integration gates remain separate activation work; allowing its tuple is not that
proof. See [the Worker candidate](../egress/public-fetch/README.md).

## Optional MCP delegated authorization

A separately approved deployment may include nonsecret
`MCP_DELEGATION_GATEWAY_PUBLIC_KEY` (64 lowercase hexadecimal Ed25519 bytes) in
`RUNLATER_RELEASE_CONFIG.vars`. Its absence keeps delegated API authentication
disabled. The exact config and live-settings baseline must be reviewed and refreshed
for any addition, rotation or removal; merely merging source does not activate it.
No owner private key or gateway private key belongs in this API profile. The private
gateway signer lives only in the separately approved MCP Worker. See
[hosted MCP rollout gates](../docs/MCP-HOSTING.md), including the state-compatible
rollback restriction after first persisted delegation revocation. Do not bypass
this workflow's existing fingerprints, release sequencing, or secret-collision checks.
