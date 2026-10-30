# General HTTPS egress — native Node source integration, live-disabled

RunLater's target is a scheduled HTTP request to a customer-chosen public HTTPS URL.
A special RunLater receiver, HMAC verifier or bot webhook is **not** required by this
component. A separate completion-notification URL is outside this milestone.

The root modules are a **library, not a deployed service or public proxy**. The
separately reviewed `controller/` source candidate adds a private Container listener
and disabled/example hosting definitions; nothing is provisioned and no live API binding is configured. The source-only
API/private-binding integration exists and remains disabled by default. Neither component contains credentials or a fallback to Worker Fetch. `createNativeEgress()` defaults to disabled. The live
API's current managed-host restrictions are unchanged. Source tests do not authorize
activation or establish a provider-level proof.

A separate [Worker public-Fetch candidate](public-fetch/README.md) now offers an explicit
provider-enforced public-network boundary. It is source-only/default-off and makes no
claim of native observed-peer pinning. Selecting it requires its own reviewed artifact
and private binding; the native path never falls back to it.

## Native runtime decision and exact blocker

The current Cloudflare Workers `node:https` implementation wraps Fetch. Its official
documentation lists `servername` and `rejectUnauthorized` as unsupported and does
not support the socket event. The documented TCP API and installed Rust worker
0.8.7 socket wrapper do not expose a documented independent original-host TLS name
when connecting to a chosen numeric IP. We therefore do **not** claim that a DNS
preflight plus Worker Fetch prevents DNS rebinding.

This candidate requires **native Node with real TLS sockets** (tested locally on
Node 24). Before production, it needs separately approved hosting/runtime and an
authenticated, narrowly scoped API-to-egress transport, trusted DNS resolver policy,
reviewed connected-peer/TLS enforcement with the documented residual trusted
runtime/network boundary, capacity/cost limits and independent security QA. No production infrastructure is created or configured here. The API must refuse general task/nonce/credit admission when the adapter is
unavailable. The initial unavailable check precedes registry writes; readiness
loss later in the request may consume one registry operation, but must not admit a
task or consume its nonce/credit. It must not silently use ordinary Fetch. Do not bundle this as a Workers compatibility shim.

## Trusted internal contract

The application calls a process-local adapter with an **already authenticated and
authorized immutable destination/task snapshot**:

```js
const adapter = createNativeEgress({enabled: false}); // intentional default
await adapter.deliver({
  url: 'https://customer.example/endpoint',
  body: '{"event":"example"}',
  contentType: 'application/json',
  operationKey: 'stable_operation'
}, {signal});
```

The URL can contain private capability path/query data. Do not expose it in logs,
model responses or public status. The library does not perform user/project
admission, grant consent, select a destination, install credentials, or enforce the
entire project's budget. A future caller must bind URL/body/method/auth-reference
and operation key to the accepted task and its fixed destination version. A simple
user-facing `schedule(url, payload, time)` can do that internally without an extra
receiver-registration ritual.

The first API profile uses fixed POST + JSON, with no caller-supplied authentication
headers. The internal library also permits `text/plain; charset=utf-8` and at most
one privately ingested `Authorization` or `X-API-Key` header. That internal capability
is **not** a public API authority grant. Any future credential path needs its own
approved custody/redaction mechanism. Never forward a RunLater OAuth/API token,
provider credential, cookie, Host, proxy or hop-by-hop header from a caller.

Outputs contain only fixed fields: HTTP status, classified outcome, bounded byte
count and whether a request may have been sent. `ok:true` means a complete bounded
HTTP response was observed, **not business success**. A 3xx is classified
`redirect_rejected`; no follow-up is made. The delivery ledger remains responsible
for status-based retry policy and uncertain effects. This component never retries,
selects another IP after failure, or returns response bodies/headers/URLs/errors.

## Egress boundary

- Canonical ASCII HTTPS URLs, default port 443 only; no userinfo, IP literals,
  fragments, backslashes, authority normalization or encoded control bytes.
- Bounded CNAME graph (eight names, one alias per name), A and AAAA answers at every
  hop, at most 16 unique addresses. Reject mixed public/special-use answers rather
  than selecting just the attractive public answer. Resolver attempts are one per
  query, with an overall deadline; the resolver is operator-owned, not request data.
- Conservative IANA-based policy: IPv4 special-purpose ranges are denied; IPv6 must
  be in global-unicast 2000::/3 and outside reserved/special prefixes. All IPv4-in-IPv6,
  mapped, NAT64, zone-ID, private/link-local/loopback/multicast forms are denied.
  This conservatively rejects some globally reachable special-purpose services.
  Review registry changes before a production rollout; this is not an eternal list.
- Select **one** validated IP and connect directly to it. A new private single-use
  Agent opens TLS with the original hostname as SNI and certificate identity,
  normal trust-chain verification, TLS >=1.2 and HTTP/1.1 ALPN. It checks the socket's
  actual remote address/port against the selected public pin **before** passing
  the socket to HTTP. No request headers/body are emitted before those checks.
- No global Agent, proxy setting, caller-selected DNS/socket, pooled socket,
  session cache, alternate-address reconnect, implicit DNS lookup or Fetch fallback.
- Four concurrent operations, 1 KiB request body, 2 KiB private header, 8 KiB/64-pair
  response headers, 16 KiB/128-chunk response body, five-second end-to-end deadline
  including DNS/TLS/streaming. Cancellation destroys request/response/socket and
  cancels resolver work. These are per-process safeguards, not a spending cap.

The dependencies accepted by the factory/internal transport are trusted composition
seams for offline tests. They must never be deserialized from a request, environment
value or database row. Production integration should instantiate the adapter with
native defaults in a controlled process and provide no public access to those seams.
Known debug/keylog configuration guards prevent accidental diagnostic leakage; they
do not defend against a hostile runtime/operator, injected CA trust, monkey-patched
native modules or transparent TLS interception. The deployment must separately
control those assumptions. A future controller must propagate the absolute API
lease deadline across cold start and recheck it before HTTP handoff; the library's
relative five-second timeout must not reset an expired authorization window.

## Local verification

Run `node --test egress/*.test.mjs`. Tests cover special-address forms, mixed DNS,
CNAME loops/depth, canonical URL rejection, header injection, disabled admission,
bounded concurrency/cancellation, secret redaction, single pin/no fallback, TLS
hostname/peer gating before HTTP bytes, redirect refusal and response bounds.

`native-tls.test.mjs` generates an ephemeral self-signed certificate in a private
temporary directory and runs a real loopback TLS/HTTP server. Its **test-only**
connector translates a synthetic public pin to loopback and reports a synthetic
peer. It proves native TLS trust/name checking and HTTP behavior; it is not proof
of public network policy, DNS-rebinding resistance in a provider, or live routing.
The ordinary production connector has no such rewrite. No real project, provider
credential, public server or external request is created by the tests.

## Before activation

Independent exact-source QA, real runtime/network controls, authenticated caller
binding and replay protection, API admission/ledger integration, restricted private
credential provisioning, provider-level negative DNS/TLS/rebinding tests, bounded
end-to-end delivery proof, operational cost/abuse controls and rollback are still
required. Do not label the generic public endpoint feature live based on this source.

Primary references: [Cloudflare HTTPS support](https://developers.cloudflare.com/workers/runtime-apis/nodejs/https/),
[Cloudflare TCP sockets](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/),
[Node HTTPS](https://nodejs.org/api/https.html), [Node TLS](https://nodejs.org/api/tls.html),
[IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry),
[IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry).
