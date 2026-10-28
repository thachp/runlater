# Invitation enrollment: offline component

This component is not enabled on api.runlater.io. Public signup, invitation distribution, commercial trial terms and payments remain unavailable. The retained operator alpha is unchanged. `npm run test:invitations` builds an exclusive local fixture profile and restores the normal artifact afterward; it does not provision Cloudflare resources.

## Admission and authority

An operator-supplied policy has optional terms: finite attempt units, identity lifetime and enqueue/read/cancel/redrive scopes. Missing terms close new admission. The limits in `src/invitation.rs` are engineering ceilings, not an approved free-trial offer. No configure or key-administration permission can be granted through this component.

The fixed `Registry` reserves a lifetime project slot before selecting a project object. Tickets contain a SHA-256 digest of a secret invitation token, never the token itself. A trusted issuer must generate and distribute unpredictable tokens; that issuer is not implemented here. Caller input cannot choose the project, grant, scopes or allowance. Expired/revoked reservations remain counted, so replay, restart and expiry cannot reset the project ceiling. Unknown references consume the bounded registry request budget but cannot select a project object. This limits project creation, not global edge traffic or provider billing.

Within one `Enrollment` snapshot, successful Ed25519 proof atomically consumes the ticket, establishes scoped key authority, applies an immutable funding grant and records a receipt. Registry acknowledgement is a separate derived progress marker. An interruption before project creation leaves a recoverable reservation; an interruption after the project commit can recover the same receipt without issuing more units. Cross-object handoff is recoverable, not a distributed transaction.

`Receipt.attempt_units` is the original allocation, not the current spendable balance. Replay never re-applies a grant. Grant expiry does not discard funding already reserved for accepted work. Revocation retires unused units and preserves accepted reservations. Registry revocation and the project revocation barrier are separate commits; do not claim revocation has reached an enrolled project until its barrier succeeds. Retrying that barrier is idempotent.

## Signed bytes and recovery

The challenge bytes are UTF-8 `RunLater invitation proof v1\n` followed by compact JSON of this ordered array:

```text
[1, origin, "invitation_enrollment", ticket_sha256, ticket_id,
 project_id, grant_id, public_key_hex, nonce_hex, issued_at_ms, expires_at_ms]
```

`ticket_sha256` hashes the canonical Rust serde JSON of the immutable ticket, including its terms and policy revision. Clients sign the returned `canonical_utf8` exactly; they must check origin, purpose and advertised terms before signing. Origin is `https://api.runlater.io`. Ed25519 key/signature encodings are lowercase hex. Challenges last at most five minutes and never outlive the invitation. Three bad signatures lock a challenge. Possession proves control of a key, not personhood or eligibility for repeated trials.

An identical successful completion can replay during its original challenge/invitation window. After that window, an enrolled read-scoped key can recover its original receipt using UTF-8 `RunLater invitation recovery v1\n` plus compact JSON:

```text
[1, origin, project_id, public_key_hex, nonce_hex, issued_at_ms, expires_at_ms]
```

Recovery validity is at most 60 seconds; the identity must remain valid and unrevoked. Identical signed recovery reads may replay during that window. The project read is pure: it consumes no nonce, updates no clock and extends no expiry. The separate registry routing gate records rate observations before selecting a known project. Trusted server time must be monotonic for commands; regressed clocks fail closed.

## Integration surface and limits

`Registry`, `Policy`, optional `Terms`, immutable `Ticket`, `Enrollment`, `Challenge` and `Receipt` are the new component types. `Enrollment` wraps the existing `signed::Project`; this change does not alter that project's layout, `funding::State`, or destination interfaces. `Mode::OperatorStatic` refuses invitation enrollment. Production integration must preserve this explicit mode separation: a static bootstrap policy must never replace or replenish an invitation grant or revive a revoked identity.

The fixture runtime uses two SQLite Durable Object classes, a fixed registry and server-derived project names, versioned single-row snapshots and synchronous snapshot mutations after body parsing. It requires both the exclusive `invitation-tests` build feature and a private control service binding, accepts loopback HTTP only, and cannot combine with production/staging/fault/funding-test profiles. Fault controls travel through private test IPC, not public request fields. Normal and production artifacts are checked for fixture markers.

The fixture's `/fixture/*` and `/registration/*` routes are test adapters, not additions to the deployed API or OpenAPI contract. A production issuer, public registration router, durable policy synchronization, dynamic-mode signed task routing, destination integration, abuse controls and activation review remain necessary. No live bindings, keys, grants, policies or discovery capabilities are changed by these tests.

## Verification

Ten native component tests cover immutable issuance, ceilings, revision/clock rejection, canonical proof tampering, cross-key/project rejection, lockout, replay/restart, mode separation, expiry, read scope and reserved-funding preservation during revocation.

The compiled Worker harness executes actual local SQLite/workerd requests. It SIGKILLs the owned Node/workerd process group after durable registry resolution before project creation, and after the atomic project commit before registry acknowledgement, then restarts against the same disposable SQLite files. It also exercises concurrent completion, malformed/unknown requests before project creation, global bounds, pure receipt recovery, expired-invitation recovery and sticky revocation across restart. These two interruption boundaries are actual process termination; native snapshot tests are simulations. They do not establish universal cloud durability, live registration safety or exactly-once delivery.
