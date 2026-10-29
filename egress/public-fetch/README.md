# Worker public Fetch candidate — source only, default off

This is an explicit alternative to the [native Container transport](../controller/README.md).
It is not a Fetch shim with native peer-pinning guarantees. No deployment, API binding,
credentials, DNS change, external test request or public activation is included.
The existing private Container service is untouched. API/MCP general HTTPS flags stay off.

## Boundary and deliberate tradeoff

The intended caller is the existing API's `GENERAL_HTTPS_EGRESS` private service binding,
explicitly selecting named `PublicFetchBinding` in this separately reviewed Worker artifact.
The internet entrypoint returns 404. The named binding uses one fixed SQLite DO,
`PublicFetchReceipts`, with no customer-selected namespace or instance. It accepts only
`https://egress.internal/ready` and `/dispatch`, using the existing version-1 immutable
attempt envelope and bounded private result format. It grants no new admission authority.
There is no native↔Fetch fallback, health-triggered transport substitution or shared receipt
namespace. Switching transports for an in-flight attempt could duplicate its effect: do not
switch until running/uncertain attempts have been reconciled. Never erase receipts to regain
capacity. Future binding, configuration and activation changes require separate review.

The candidate requires `EGRESS_TRANSPORT=worker-public-fetch-v1`, explicit
`EGRESS_ENABLED=operator-approved`, and a nonzero 64-hex `EGRESS_REVIEW_REVISION`.
The example sets enablement false and revision UNVERIFIED. The API's reviewed revision
must match the candidate's exact revision through existing readiness and envelope checks.
`node scripts/public-fetch-manifest.mjs` computes a transport-specific source manifest
revision from all runtime sources and the example configuration. Record exact compiled
bundle digest/toolchain and final deployed configuration alongside that source revision
in any future activation review. The manifest and operator strings are identities, not
proof of provider behavior. Source/config/runtime changes invalidate the prior review.
No API binding or activation configuration is added here.

Cloudflare's global Fetch public-network routing is the SSRF enforcement boundary.
`global_fetch_strictly_public` is mandatory: it routes own-zone requests through the public
front door rather than bypassing Workers/security settings to an origin. Removing it
invalidates this candidate. No DNS precheck is presented as connected-IP identity;
`resolveOverride` cannot pin arbitrary customer domains. The Worker does not observe
peer IP, original-host TLS verification, all A/AAAA answers, CNAME history or mixed-answer
rejection. It does not emit evidence claiming those checks. The native path retains its
independent application address policy, chosen-IP connection and observed peer/TLS checks.
Cloudflare-controlled DNS, connection selection, retries inside Fetch, network routing,
TLS trust and zone configuration remain trusted here; one Fetch invocation is not a
claim of one underlying TCP attempt or exactly-once downstream effect.

External, nonproxied, out-of-zone Fetch requests use Cloudflare Full (strict) TLS.
That statement is not a blanket guarantee about proxied/same-zone downstream origin TLS
settings. Those need separate hosted inspection. No custom origin trust, `cf` override,
`cots_on_external_fetch`, incoming credential or supplied header is accepted.

## Request, resources and uncertain effects

The sender revalidates the exact immutable envelope and target hash, canonical HTTPS
DNS hostname on default port 443, fixed POST JSON, 1024 UTF-8 body bytes and narrow
operation key. It creates a fresh Request with only Content-Type, Idempotency-Key and
User-Agent; the provider may add its own routing/framing headers. No incoming Request is used as the outbound template. Redirect mode is
`manual`; all 3xx responses are cancelled and summarized without following Location.
No response body/header/URL/payload is reflected or logged. There is no background
send, waitUntil, reconnect loop or application retry within this transport.

The existing API retains task/target immutability, funded claim-before-dispatch, deadlines,
quotas and its explicit ledger retry policy. That policy may create a new fenced attempt;
transport `automatic_retry:false` does not promise no later ledger attempts. A timeout or
exception after invoking Fetch always reports a possible effect. Persisted same-fence
receipts prevent application redispatch even after abort, reset, expiry or lost responses.
Aborting cannot retract an already delivered request. Receivers should deduplicate the
stable operation key. Native and Fetch receipt stores must never be substituted during
recovery. Existing target-retention behavior remains unchanged.

The singleton dispatcher retains its four active-call bound, 10,000 permanent receipts,
1,024 permanent hostname slots, durable 1/s global and 1/10s hostname pacing, and a hostname
lock through the absolute lease for reserved/unfinished receipts. Completed bounded
transport failures release that lock while retaining replay suppression and normal pacing. Input parsing is limited to 8 KiB/128 chunks
and two seconds. The sender uses the earlier of the immutable 29-second envelope lease
and five seconds, including response consumption. It counts at most 8 KiB of exposed
response header names/values and 16 KiB/128 response chunks. Headers and individual
chunks are already materialized by the runtime before application inspection; these are
application acceptance limits, not wire allocation limits. Platform runtime limits remain
trusted. Redirects, invalid statuses, oversized headers/bodies, failures and cancellation
cancel response streams without waiting on hostile cancellation promises. Late responses
are also cancelled. Provider propagation of disconnect signals still needs hosted proof;
`enable_request_signal` is explicit, with absolute deadlines as a separate bound.

## Local evidence and hosted gates

Run `npm run test:egress`, `npm run test:public-fetch-local`, and
`npm run build:public-fetch`. The new unit suite uses fake Fetch, and the workerd suite
uses a fake `outboundService` for all outbound traffic. These prove application validation,
limits, named binding/DO wiring and durable SQLite replay across restart. They do not prove
provider SSRF controls, DNS behavior, TLS or real cross-service cancellation. The existing
native TLS and full general-HTTP integration suites remain relevant regression checks.

All hosted checks remain pending, with no live fixture authorized by this change:

- Same-zone front-door routing and absence of legacy origin bypass; public entrypoint,
  named binding isolation, disabled readiness and exact revision mismatch.
- Controlled DNS rebinding, private/link-local/metadata ranges, mixed public/private
  A/AAAA answers, IPv6/mapped addresses and CNAME chains. Determine provider behavior;
  do not assert equivalence to native all-answer inspection.
- Invalid/untrusted/expired/hostname-mismatched certificates, plus proxied and same-zone
  origin TLS posture. Confirm no custom origin trust or routing override.
- Redirects to private/alternate targets, hostile headers and oversized/stalled bodies.
- Absolute deadline and client/API/service disconnect cancellation before/after send,
  late completion, DO eviction/reset, receipt durability and same-attempt replay without
  redispatch, plus quota exhaustion and durable clock/rate behavior.
- Bounded authenticated end-to-end delivery, immutable target/operation key, ledger retry
  policy, uncertain effect accounting, private diagnostics, operational cost and rollback.

Official references checked 2026-10-29:

- [Workers security model](https://developers.cloudflare.com/workers/reference/security-model/)
- [Bindings and SSRF](https://blog.cloudflare.com/workers-environment-live-object-bindings/)
- [Strict public Fetch flag](https://developers.cloudflare.com/workers/configuration/compatibility-flags/#global-fetch-strictly-public)
- [External Fetch TLS](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-526/)
- [Request redirect, signal and resolveOverride](https://developers.cloudflare.com/workers/runtime-apis/request/)
