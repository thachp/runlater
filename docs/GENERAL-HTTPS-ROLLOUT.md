# General HTTPS release coordination — activation pending

The selected release architecture is the private Cloudflare Worker public Fetch
adapter described in [the current contract](GENERAL-HTTPS-DESTINATIONS.md) and
[adapter evidence](../egress/public-fetch/README.md). A Container is not required.
Production activation is being coordinated separately; this document is not a
claim of live availability or permission to create resources.

Before publishing staged landing/docs copy as available, record the exact API,
MCP and adapter revisions, successful readiness/flag readback, finite hosted
proof and independent QA. Preserve existing quota and project state. Do not
create another hosted trial identity or reset quota for documentation QA.
Deploy docs and landing separately from API/MCP, preserving empty docs bindings
and disabled workers.dev/previews. Coordinate merge and publication with the
release owner; do not infer activation from a successful static build.

## Historical native Container plan (superseded for this release)

The following retained plan describes the earlier alternative only. Its resource
and proof requests are not requirements or authorization for the selected Worker
release. Native peer/TLS checks below must not be attributed to public Fetch.

# General HTTPS: pending activation checklist

This is a **plan, not authorization or evidence of activation**. The live managed
beta restrictions remain unchanged. Source review, a green PR and local fixtures
do not establish provider behavior or authorize new resources.

## Approvals to obtain at action time

1. **Host:** create one private egress Worker, one SQLite Durable Object namespace
   and one native Node Container application/image in the existing account. Use
   the reviewed immutable image, one `lite` instance, fixed singleton/port,
   `workers.dev`/previews/routes off and no request/body logging. No plan upgrade,
   payment setup, new API token or unrelated identity provider is included. Verify
   an existing Workers Paid plan before proceeding; inability to read billing via
   an existing OAuth connection is not permission to mint a billing credential.
2. **Trust:** add exactly one API service binding to the named egress entrypoint,
   pinned to the reviewed revision. No public proxy endpoint and no shared
   application bearer secret are needed. This nevertheless expands the API's
   permitted outbound behavior and creates a new trusted component. A compromised
   image/controller/binding could undermine application-level destination policy;
   native validation is not an independent egress firewall.
3. **Activation:** deploy reviewed source and separately enable anonymous trials
   and general HTTPS on the appropriate API/MCP components, preserving existing
   project, task, attempt, operation, CPU and rate limits. Existing owner grants
   are not broadened. The new `http_schedule` permission appears on explicit new
   trial consent. Public no-account trials can consume the remaining lifetime
   project slots; reserve/confirm test capacity immediately before enabling.
4. **Finite proof:** approve one new disposable anonymous project, up to four
   short-lived OAuth grants, and up to five synthetic tasks (at most 25 finite
   dispatch attempts under the unchanged task policy). Cover ordinary HTTPS JSON
   receipt, cancellation, redirect refusal, certificate rejection and a
   DNS-resolved special-address rejection without contacting that special target.
   Use only explicitly controlled test destinations or approved public negative
   TLS fixtures. Any temporary ordinary HTTPS sink, hostname/DNS records or test
   identity must be named and approved before creation. No customer's private key,
   endpoint credential, payment or third-party business action is part of proof.
5. **Cleanup and publication:** revoke the test trial, reconcile all accepted
   tasks/uncertain receipts, stop/remove the approved temporary sink/resources and
   preserve audit/state needed for rollback. A lifetime project slot may remain
   consumed. Publish only measured functionality to the existing docs/landing
   hosts; distinguish an agent-driven official MCP SDK test from verified support
   in any named commercial agent UI. Never claim Grok webhook/wakeup support from
   HTTP receipt alone.

## Safeguards and stopping rules

- HTTPS/443, canonical DNS names, fixed POST/JSON, 1 KiB payload; no endpoint auth,
  custom headers, followed redirects, response-body reflection or completion hook.
- Validate every DNS result and actual peer plus original-host TLS before HTTP
  handoff. The adapter uses one address/attempt, with no hidden retransmission.
- Persist the immutable attempt receipt before startup/send. A crash or lost
  response cannot resend that same attempt. Cold start consumes the same absolute
  API lease deadline; the native DNS/TLS/request budget is at most five seconds
  within that remaining deadline. No background delivery after caller timeout.
- Bound concurrency, receipts and host accounting. Durable global/per-host pacing
  is part of the reviewed candidate, not an assumption that finite trials prevent
  bursts. At unchanged public-beta ceilings, ten lifetime projects × sixteen
  lifetime tasks × five attempts is at most 800 scheduled HTTP attempts. This does
  not bound unauthenticated ingress, startup probes or every provider cost.
- Stop on unexpected routes/bindings, secret exposure, image/revision drift,
  connected-address/TLS mismatch, deadline failure or uncertain provisioning.
  Reconcile an uncertain write before any retry. Do not extend a smoke test's
  identity/task/resource budget to work around failure.
- Rollback must retain readers for already persisted trial, destination and
  attempt-receipt data. Never delete receipts or deploy an older strict parser to
  make a rollback appear clean. Disabling authority cannot undo an in-flight
  customer effect. `GENERAL_HTTPS_ENABLED` is both an admission and future-dispatch
  kill switch: disabling it pauses new admission and queued general dispatch, not
  in-flight effects. Retain task/target/receipt state for a compatible resume.

## Cost estimate (research, not a spending cap)

Cloudflare's published `lite` shape is 1/16 vCPU, 256 MiB memory and 2 GB disk.
Containers require Workers Paid (currently a $5/month minimum baseline). At full
lite CPU and before included account allowances, the Container resource rate is
approximately **$0.007254/hour**: about **$0.000121 for 60 seconds**, **$0.218 for
one hour/day over 30 days**, or **$5.22 for continuous 30-day resource usage**.
These figures are **not the total bill**. Workers, Durable Objects, rounded usage,
build/image storage, network, existing account-wide usage and baseline charges
may add cost. Idle sleep and one instance reduce exposure but do not create a hard
monetary cap. Verify current rates and account entitlement again before approval.

Sources: [Containers pricing](https://developers.cloudflare.com/containers/platform/pricing/),
[Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/),
[Container architecture](https://developers.cloudflare.com/containers/concepts/architecture/).
