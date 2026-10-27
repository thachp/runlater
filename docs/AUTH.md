# Nonproduction project key lifecycle

This source implements project-scoped verification and key lifecycle **only for local fixtures**. `LOCAL_FIXTURES` must remain enabled for the prototype API; it is not a production authentication setup. No production credentials were generated, provisioned, granted or rotated. All examples use public test data. No external service access is required.

## Implemented permission boundaries

| Permission | Allowed API operations |
| --- | --- |
| enqueue | POST /v1/tasks |
| read | GET task, attempts, paginated tasks and queue settings |
| cancel | POST /v1/tasks/{id}/cancel |
| redrive | POST /v1/tasks/{id}/redrive |
| configure | PUT /v1/queue |
| manage_keys | List/audit/issue/revoke/rotate project keys |

Task mutation responses without `read` contain a receipt (ID, status, generation, cancellation flag, parent). They exclude persisted payload, destination and attempt history. Existing full-scope bootstrap fixtures preserve the prior full task response. A manager can only grant a subset of its own permissions and can only revoke/rotate targets with permissions contained in its own scope. These are action permissions for one project/default queue, not multiple-queue or resource-ID policies.

A credential has the local format `rl_local.<tenant>.<key_id>.<secret>`. Tenant/key IDs are validated; the tenant must already appear in the local bootstrap configuration before the Worker routes to its DO. That prefix is an untrusted routing claim. The tenant's authoritative keyring verifies the complete token's SHA-256 using constant-time comparison, checks project ownership, time bounds, revocation and the operation permission. Client `x-tenant` headers cannot override this verification.

Legacy `local-alpha` and `local-beta` remain public local bootstrap fixtures with all permissions. `API_KEY_HASHES` contains only their verifier hashes and project directory mapping. On an old snapshot with no keyring field, the initial keyring is derived in memory; queries do not seed state or create SQL schema. The first command persists the keyring in the same atomic tenant snapshot as task state. Once present, the persisted keyring is authoritative: bootstrap fallback never resurrects a revoked key. Changing environment hashes does not issue replacement keys into an already initialized registry. The configured project directory must remain consistent; a production project catalog is deferred.

## Commands and time semantics

- `POST /v1/keys`: accept an immutable key ID, full-token `token_sha256`, permission set, optional `not_before_ms` (default 0), and exclusive `expires_at_ms`. The caller computes its public fixture verifier locally. The server never returns or persists plaintext tokens. Same-ID/same-spec retries return current metadata, including revocation, without reactivation; changed specs conflict.
- `POST /v1/keys/{id}/revoke`: revoke at the current authoritative request time. Later API operations fail authentication. Revocation does not cancel accepted work, undo external effects or revoke independently issued child credentials.
- `POST /v1/keys/{id}/rotate`: atomically create `new_key` and schedule source revocation at `revoke_old_at_ms`. New ID/spec plus the cutoff are the immutable replay identity. Both keys may authenticate during the overlap. At the exact cutoff the old key is invalid. Existing source expiry or an earlier scheduled revocation is also respected; rotation cannot introduce a validity gap. An identical retry still resolves after the old key becomes inactive.

Proposed local bounds: 64 retained key identities per tenant; new key lifetime at most 30 days ahead; overlap at most 24 hours; 256 most recent redacted audit entries. IDs are not reusable after revocation/expiry. There is no deletion or production garbage-collection policy yet. If every local administrator is revoked/expired, there is no HTTP bootstrap recovery bypass; use a fresh local fixture store for tests. Production break-glass recovery needs separate design/review.

Authorization is rechecked against a freshly loaded keyring after storage awaits and immediately before synchronous mutation/SQLite save. No further await separates that check from the mutation and upsert. Thus a concurrent revocation that commits first denies the later command; a command already committed before revocation can still return success. Queries authenticate against their immutable committed snapshot and perform no reconciliation, audit append, alarm or save.

## Storage, audit and logs

Only verifier hashes and bounded key metadata live in the project's durable snapshot. Key list, issue/rotate/revoke responses and audit views omit hashes. Bootstrap IDs are separately derived opaque labels, not embedded credential verifiers. Audit entries contain actor key ID, target ID, action and timestamp; they contain no token, verifier, customer payload or authorization header. Application code does not log credentials or request bodies. Unauthorized failures return generic 401, insufficient permissions return generic 403. High-volume authorization-failure telemetry and durable production audit retention/export are deferred; local bounded audit is not a compliance archive.

API authorization tokens are forwarded only inside the private Worker→DO request header and discarded after verification. Internal Queue claim/finish calls use private bindings, not a customer-exposed bypass. Callback signing still uses the separate public in-process fixture key; API-key rotation does not rotate customer callback-signing secrets.

## Verification and deployment gate

`tests/auth.rs` exercises exact validity/cutover boundaries, scope separation, cross-tenant denial, replay without resurrection, failed-rotation atomicity, revocation across serialized restart, stale/forged actor rejection, no privilege escalation, and verifier redaction. `scripts/key-lifecycle.mjs` proves the actual local HTTP/SQLite flows using public fixture credentials. The SQL query regression includes key-list and audit reads; when using an alternate emulator `--persist-to` directory, set `RUNLATER_STATE_DIR` to that directory so the test inspects the actual store.

Production remains gated on explicit credential/resource approval plus high-entropy credential generation and delivery, secure initial administrator enrollment, separate project directory, secret-manager/trace/header redaction review, durable audit/recovery policy, abuse/rate controls and live-runtime security validation. None is provisioned by this change. Arbitrary outbound HTTP remains disabled; no real transport was added to this slice.
