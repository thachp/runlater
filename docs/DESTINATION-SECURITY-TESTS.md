# Compiled destination-security regression matrix

Related: [issue #7](https://github.com/thachp/runlater/issues/7). This is a bounded
**local test-only** increment. It does not close the runtime network threat-model
gate or change any production destination policy, feature, secret or deployment.

## Reproduce

```sh
npm ci
npm run test:destination-security
```

The script builds the actual Rust/Wasm `production` artifact, checks that runtime
and destination-fixture hooks are absent, then runs `scripts/destination-security.mjs`.
An EXIT trap restores the default artifact and checks both sets of fixture markers.
The same matrix runs inside `npm run test:public-beta`, so the existing Local
prototype checks workflow exercises it on pushes and pull requests.

## What the matrix establishes locally

The production entrypoint runs in disposable Miniflare/workerd with SQLite-backed
`AdmissionRegistry`/`InvitationProject`, actual local alarm/Queue delivery, signed
Ed25519 public-beta requests and `global_fetch_strictly_public`. It uses a newly
generated synthetic owner/master and local-only registration. No real cohort slot,
credential, receiver or provider resource is touched.

| Cases | Assertions |
| --- | --- |
| 65 prohibited URLs | Create returns 403 / `destination_unavailable`; prepare and verify return 404; **zero outbound Fetch invocations**, checked separately after every case. |
| Allowed positive control | Exact `https://receiver.account.workers.dev/callback` creates, prepares and verifies; one real local queued callback succeeds with `http_success`. This rules out disabled routes, bad authentication or a blanket-deny fixture passing the negative matrix. |
| 13 ownership-proof redirects | One intercepted request to the approved original URL, verification failure, no followed Location; immediate proof replay returns 409 without another Fetch; the still-unverified endpoint cannot admit a task. |
| Same 13 callback redirects | Each accepted task sends exactly once, terminates failed with exactly one `redirect_rejected` delivery record and never follows Location or retries the redirect. |

Prohibited inputs include private/shared/loopback/link-local/metadata/public IP
literals; IPv6 unspecified/loopback/unique-local/link-local/mapped/zone forms;
integer, short, hexadecimal, octal and percent-encoded IPv4; localhost/internal
names; custom domains and malformed/lookalike Workers.dev hosts; service self-host
and RunLater hosts; alternate schemes/ports; userinfo and authority confusion;
backslashes, whitespace/control/NUL characters, Unicode/case/trailing-dot/percent
aliases, query/fragment, dot segments and overlong URLs.

Redirects cover 301/302/303/307/308 and additional 300/304/399 statuses. Locations
include private/loopback/metadata/IPv6/encoded-IP targets, an internal DNS alias,
self-host, a custom public domain, userinfo confusion, a different otherwise-valid
Workers.dev host, a relative path and a same-host path. **All redirects are denied**,
not just redirects to the prohibited subset. Redirect responses originate in a
local workerd receiver to exercise the compiled Rust Fetch redirect mode.

Every production global Fetch goes through a counting local service and is never
forwarded to the supplied URL. Unexpected destinations/methods are recorded before
returning a local denial; a separate counted deny-all outbound service protects the
local receiver itself. Assertions run in the host driver, not only in service
callbacks where thrown assertions could be mistaken for expected network failure.
Proof requests are also checked for absence of credentials, callback signatures and
the secret proof nonce. API calls are capped at 600; task polling has a ten-second
deadline per task. The successful matrix has exactly 28 intercepted requests (two
positive controls plus 26 redirect first hops), zero second hops and zero external
network calls. The temporary SQLite directory is removed on exit.

## What remains open

Local interception does **not** exercise public DNS resolution, TLS, provider
network enforcement, DNS rebinding, cloud interruption or arbitrary-host safety.
The Workers.dev-only public-beta restriction, self/RunLater exclusions, manual
redirect rejection and bounded transport remain unchanged. No live metadata or
private-network probes are permitted by this suite. No custom-domain support,
allowlist widening, deployment, production activation or issue closure is implied.

Existing [destination lifecycle tests](DESTINATIONS.md),
[callback contract](CALLBACK-KEYS.md) and public-beta integration retain their
separate coverage. See [public-beta network boundary](PUBLIC-BETA.md#network-boundary)
for the provider-isolation assumption and remaining reviewed live-evidence gate.
