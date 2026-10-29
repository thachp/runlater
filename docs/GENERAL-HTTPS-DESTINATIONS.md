# Customer-chosen HTTPS destinations — target architecture, not activated

RunLater's product is scheduled HTTP delivery to a **customer-provided endpoint**.
It is not a bot-specific receiver service. A customer may want to call their own
application, an agent runtime with a documented webhook, or a third-party webhook.
An HTTP success does not establish that a chat session wakes or a business action
completed.

The desired simple interface is `schedule(url, payload, time)`: the scheduled HTTP
request goes to that URL. A separate completion notification URL is a future,
optional feature, not the delivery destination and not required for the core call.
The reference receiver must not be inserted as an extra mandatory hop.

The current Workers.dev-only beta and its ownership-verified HMAC receiver are
temporary safety restrictions. [Receiver pairing](RECEIVER-PAIRING-WIRE.md) is an
optional reference path for that beta, not a universal requirement for the target
architecture. An ordinary third-party endpoint may be unable to install RunLater
keys, answer its ownership proof, or run its inbox code. General delivery must not
pretend those endpoints can do so.

## Separate destination authority from task authority

The future general-HTTPS profile should register an explicitly authorized,
project-scoped destination version: exact HTTPS URL, permitted method, content
type and a private authentication reference. The task refers to that immutable
destination version; it cannot override URL, headers or credentials per attempt.
This can be enforced internally when accepting an inline URL in a single explicit
scheduling request; it need not require a separate user-facing registration step.
Changes require a new reviewed version and explicit authority, not an automatic
redirect, reconnect, trial reset or a broadened `enqueue` scope.

Authorization to send requests is not proof that the customer owns the server.
For a third-party webhook, the relevant approval is use of that precise endpoint
and the intended effect under the customer's account. RunLater must not require
an incompatible proprietary ownership protocol, nor treat a public URL as proof
of permission to spam it. Anonymous abuse controls and consequential-action
approval remain separate from destination syntax validation.

Webhook paths/query strings and header values can themselves be bearer secrets.
Provide a private credential-ingestion path, encrypt/manage those values under an
explicit custody model, and return only a destination identifier plus redacted
metadata to MCP. No provider/API/OAuth token pass-through, arbitrary model-selected
headers, response-body reflection, or secret-bearing URLs in logs, errors or
discovery. RunLater signatures can be an optional receiver feature, not a universal
third-party compatibility requirement.

## Safe egress is a launch blocker, not a hostname regex

The first general profile should remain HTTPS on port 443, with canonical URL
parsing, no userinfo, fragments or IP literals, and **no followed redirects**.
Bound URL/header/body sizes, request and response time, redirects, concurrency,
attempts and total lifetime budget. A response must be classified without returning
its arbitrary body or sensitive headers to the caller.

DNS validation must cover every A/AAAA/CNAME result, including IPv4-mapped IPv6,
private, loopback, link-local, metadata and other special-use ranges. Crucially,
the **actual connected address** must remain permitted and TLS must verify the
original hostname/SNI. A separate DNS preflight followed by an unbound Fetch does
not prevent rebinding. Do not claim that `global_fetch_strictly_public`, a public
hostname suffix, or local mocks alone prove this property.

Before expanding beyond the current managed-host profile, establish either a
documented, independently tested provider egress guarantee or a separately reviewed
egress component that enforces connected-address and TLS policy. A proxy/runtime,
new credential, namespace or access grant is **not provisioned or selected by this
document**. If the existing runtime cannot demonstrate the necessary boundary,
general arbitrary-host delivery must remain disabled rather than silently falling
back to ordinary Fetch.

## Required evidence and rollout

- Contract tests for immutable destination version/auth references, project
  isolation, scope separation, redaction and task replay without extra effects.
- Adversarial DNS/TLS/connected-address tests: CNAME chains, rebinding, split
  answers, IPv6 forms, special-use targets, certificate mismatch and redirects.
- Slow/large/chunked responses, connection resets and uncertain outcomes; preserve
  finite retries, idempotency/operation keys and existing cancellation semantics.
- Per-destination and global admission/rate/concurrency limits, noisy-neighbor and
  distributed abuse assessment. Finite budgets are not a hard provider spending cap.
- Independent security QA plus provider-level evidence before a separately
  approved staged rollout and compatible rollback. Preserve the old beta profile
  until the new one is explicitly activated.

No live host policy, destination permission, billing or deployment changes are
made here. The optional managed receiver is useful for protocol testing, but its
local counter/inbox is not the customer's eventual application integration.

References: [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html),
[Cloudflare Fetch](https://developers.cloudflare.com/workers/runtime-apis/fetch/).

## Staged source contract (not deployed)

The first narrow source profile is implemented behind separate,
**default-off** `GENERAL_HTTPS_ENABLED` gates. A newly consented anonymous trial
must hold `http_schedule`; neither the old `enqueue` scope nor an existing
owner-signed grant silently gains this authority. Existing `read` and `cancel`
permissions cover the resulting task IDs. The initial request is deliberately
not an arbitrary HTTP client:

```json
{
  "url": "https://customer.example/events",
  "payload": {"message": "Run the customer-authorized action"},
  "run_at_ms": 1800000000000,
  "operation_key": "customer-stable-effect-key"
}
```

`POST /v1/http/tasks` also requires a stable `Idempotency-Key`. The hosted MCP tool
is `schedule_http_request`, whose input adds `idempotency_key` to those four
fields. The API verifies the original signed route and body before creating its
internal immutable destination; it does not turn the request into an unsigned or
re-signed legacy receiver request. The task shares the trial's existing task,
operation, publication and attempt budgets. No extra project or quota pool is
created for HTTP delivery.

Only **POST, application/json, HTTPS port 443, a canonical public DNS name and at
most 1,024 UTF-8 bytes of serialized JSON** are accepted. No custom headers,
private endpoint authentication, RunLater HMAC or ownership probe, automatic
receiver deployment, response-body return, or separate completion callback is
part of this first profile. A chosen endpoint must already be willing to accept
the intended JSON request. A URL pasted into MCP is model-visible: do **not** put
API keys or webhook bearer secrets in its path/query or payload. Private
credential ingestion requires a later explicitly reviewed custody mechanism.

The API currently refuses general admission unless a reviewed authenticated
transport can be supplied. A flag alone is insufficient. Its explicit
unavailable response is HTTP 503:

```json
{"error":{"code":"general_https_unavailable"},"task_accepted":false}
```

The initial availability guard runs before registry/project admission, nonce
consumption, task/credit writes or egress. Availability is checked again inside the
project: if it changes after registry authorization, one counted client operation
may already have been consumed, but no task/nonce/attempt-credit is created there.
Edge ingress limiting also applies. MCP treats only that exact bounded
response as confirmed non-admission; a lost/malformed response is uncertain and
must not trigger automatic retries, changed keys or a replacement identity.

### Native transport and hosting candidate

The source-only `egress/` component uses native Node sockets rather than the
Workers Fetch-backed `node:https` implementation. It bounds the entire DNS
CNAME/A/AAAA graph, rejects any mixed public/special result, chooses one validated
address, and verifies the connected peer plus CA chain and the **original** TLS
hostname before handing an HTTP request to the socket. It follows no redirect,
does not try another address, limits concurrency, and aborts sockets on timeout.
Responses are reduced to bounded status/outcome metadata; body content and
headers are never returned to the agent. Local TLS tests are synthetic tests,
not evidence that a hosted provider preserves this boundary.

The candidate host is one same-account Cloudflare Container with native Node,
behind a private Worker/DO and one explicit API service binding. Public routes,
workers.dev and preview URLs must remain off. Fixed instance/port/image and a
narrow dispatch envelope are mandatory; caller-selected infrastructure is not.
The absolute API lease deadline must include cold start, DNS, TLS and delivery.
Durable attempt receipts must suppress replay of the same uncertain attempt,
including after a crash. No background delivery or timeout-resetting retry is
acceptable. HTTPS interception must remain off so the native socket sees the real
peer/TLS session. This is trusted application enforcement, **not** an independent
public-IP network firewall.

This hosting candidate, its API binding and any billable resources are not
provisioned by this source. Separate independent QA, provider-level negative
proof, exact configuration review and action-time approval are required before
activation. Anonymous Connect also remains separately gated; source availability
is not a statement that the public endpoint accepts no-account trials today.

See the [pending activation and finite-proof checklist](GENERAL-HTTPS-ROLLOUT.md)
for resources, access consequences, cost exposure and explicit approval boundaries.

The reviewed-source kill switch pauses both new admission and future general
dispatch. It does not erase task/target/attempt records or recall in-flight HTTP
effects. A rollback must retain readers for those new persisted records.
