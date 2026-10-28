# Invitation delivery integration v1 — disabled source contract

This increment connects invitation enrollment, destination ownership and funded callbacks in the production artifact. It does not deploy or configure it. The live static alpha, its fixed receiver, identity/grant, sites and published discovery/OpenAPI remain unchanged. No trial duration, allowance or commercial prices are selected. No payment/credit-purchase adapter is activated.

The separate RunLater-owned contract is [contracts/invitation-v1.json](../contracts/invitation-v1.json). It is informational metadata, not an authorization grant or a standards claim. Do not use the current alpha quickstart as a public signup client.

## Permission and request boundary

| Operation | Required enrolled scope | Signed body |
|---|---|---|
| Create endpoint/version | `manage_destinations` | `endpoint_id`, positive `version`, canonical HTTPS `url` |
| Prepare ownership proof | `manage_destinations` | `endpoint_id`, `version` |
| Fetch/verify ownership proof | `manage_destinations` | `endpoint_id`, `version` |
| Revoke endpoint | `manage_destinations` | `endpoint_id`, existing `version` |
| Accept/read/cancel/redrive task | enqueue/read/cancel/redrive respectively | Existing task DTOs |

Destination commands are POST `/v1/destinations/create`, `/prepare`, `/verify`, `/revoke` under that same prefix. Unknown body fields are rejected; `url` is forbidden outside create. Every command uses the existing Ed25519 signed-request v1 headers with a nonempty idempotency key. The new scope does not grant queue `configure` or key administration. Existing invitations retain their immutable scopes; deployment cannot silently add this permission to an old ticket.

A bot redeems its invitation and proves its key, creates an approved endpoint, prepares proof, installs the returned response at its endpoint, then requests verification. The bounded outbound verification request omits the secret proof response/nonce. Echoing that request cannot verify. A prepared proof is shown once; lost responses may require waiting for expiry and consuming another bounded proof attempt. Repeating create with identical input is idempotent; prepare/verify do not replay their secret response or refetch after the one-use attempt has started. Concurrent requests cannot refund the lifetime three-attempt proof budget. Verification reloads the latest snapshot after I/O and rechecks scope/key expiry, project and endpoint revocation before committing.

Endpoint revocation is endpoint-wide, including prior versions. Its submitted version must exist. New admission and future dispatch are blocked; a callback already in flight may have effects. Ownership establishes endpoint control, not SSRF or DNS-rebinding safety. Only the separately configured exact HTTPS host allowlist can authorize bounded egress. No IP literals, userinfo, custom ports, query/fragment, redirects, caller authorization headers, wildcard or arbitrary customer host are enabled.

## Atomic acceptance and dispatch

The `Enrollment` snapshot includes additive defaulted outbound state beside its existing project. No layout change is made to `signed::Project` or `funding::State`; old invitation snapshots decode with closed outbound state. Normal/default and destination fixture profiles retain their separation.

Signed acceptance clones the whole aggregate and commits only after authentication, immutable grant reservation, task/idempotency acceptance, verified destination selection and callback-v2 body/operation snapshot all succeed. Task requests name `registered:<endpoint_id>`; the server snapshots the latest registered version in that same commit. Redrive is a distinct funded admission bound to the source task's immutable endpoint version. It never silently retargets to a newer version. Identical enqueue/redrive replay returns the original selection/reservation even if the endpoint is later revoked; that replay does not authorize a callback.

Callback metadata and hashes of material identity are persisted; secret material and signatures are not. Operator keyring revisions/revocations and material identities are synchronized independently before a new admission can roll back. Dispatch selects the current active callback key against the accepted protocol/body/operation snapshot. Invalid/rolled-back callback config blocks fresh admission but does not block authenticated existing task replay/cancellation. Key administration remains operator configuration, not an enrollment privilege.

Before acceptance mutation the runtime durably arms a watchdog and reloads after that await. It commits outbox intent before publishing. Queue references contain tenant/task/generation only. A fixed registry gate validates the tenant before selecting a project object. Lease/fence and funding spend commit before fetch; callback outcome/settlement commits before Queue acknowledgement. Duplicate/stale references cannot claim a resolved generation; uncertain outcomes retry. Fenced result commits reload after network I/O. This is at-least-once delivery, not exactly-once receiver effects.

Accepted funding survives identity/grant admission expiry; delivery does not reauthenticate the expired enqueue request. Destination policy removal/revocation or unusable signer fails closed at the next claimed attempt. A policy rejection spends that attempt, terminalizes with the existing nonretryable HTTP400 policy outcome and settles unused units using the existing funding rules. Identity/project revocation bars future effects and cancels unclaimed work; a running callback may still complete. Cancellation/refund and spent-fence accounting remain replay-safe. No uncertain network result refunds a spent attempt.

The existing lifetime cap of 128 durable publication reservations per project is reused. Exhaustion preserves age/lease/retention wakeups rather than republishing every second. Maintenance always expires overdue nonrunning work and settles funding before rearm, even with missing/bad callback configuration. When configuration is unavailable, alarms retain only lease, retry-age and retention deadlines; there is no configuration polling loop. After an operator repairs configuration, a successful signed destination command (including an idempotent create) or task command pumps due work. GETs never do this. Project queries are pure; the separate registry records routing-rate observations. Endpoint/acceptance storage retains the destination component's finite lifetime caps and fails closed when full.

## Explicit configuration; no activation here

Invitation mode retains its separate `ADMISSION`/`PROJECTS` namespaces, `INVITATION_ENROLLMENT`, policy and digest seeds. Delivery additionally needs:

- `INVITATION_DELIVERY_ENABLED=operator-approved`
- `INVITATION_READY` Queue binding and `INVITATION_READY_QUEUE=runlater-invitation-ready`
- `INVITATION_DELIVERY_POLICIES`: at most eight `{keys: <callback Keyring>, egress: {approved_hosts: [...]}}` records, each with a distinct enrolled tenant.
- `INVITATION_CALLBACK_KEYS`: secret key-ID → 32-byte lowercase-hex material map. Fixture IDs and repeated-byte placeholders are refused.

No config defaults enable this. New bindings, persistent credentials, operator-approved hosts, admission terms and live signup still require their activation review. A secret-provider/configuration failure never falls back to public fixture material. Operators must retain valid signing material long enough to honor accepted scheduled tasks and the documented verifier overlap; emergency revocation overrides delivery and leaves bounded failure outcomes. Revocation cannot be undone by restoring an older config.

## Evidence and limits

`npm run test:delivery` now includes a full compiled production invitation journey against local intercepted receivers: enrollment → ownership proof → scheduled acceptance → SQLite restart → alarm/Queue consumption → exact HMAC-v2 callback; callback retry, idempotent acceptance replay, endpoint revocation before claim, cross-project key rejection, pure query snapshots, and a callback after identity/grant expiry. No external DNS/TLS/customer callback or live provider resource is involved. Restart uses actual local Miniflare disposal/recreation over the same SQLite state; the existing invitation suite separately retains three actual process SIGKILL boundaries.

Native tests model atomic rollback on unverified selection, dispatch-time key rotation, spent-attempt settlement on revocation, funded delivery after expiry, and repeated maintenance after publication exhaustion. They are simulations, not additional process crashes. Existing alpha delivery, enrollment, signed-request, funding, destination and artifact-isolation suites remain regression gates. The result is a reviewed source path toward activation, not a universal durability, scale, arbitrary-host safety or production SLA claim.
