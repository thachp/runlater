# Public HTTPS scheduling — finite public beta

API/MCP activation was reported on 2026-10-30. Public read-only checks confirmed
API version `92b152b6-4715-4615-b299-e545274abcc2`, MCP version
`a78fe67a-62b4-4f24-bc38-5c4a0ef9d837`, enabled anonymous/general HTTPS flags
and OAuth discovery advertising `http_schedule`. These checks establish
configuration visibility, not a delivery or named-chatbot compatibility test.
The selected release transport is the private Cloudflare Worker public Fetch
adapter, not a required Container. The older native transport is an alternative,
not a customer prerequisite. See [rollout coordination](GENERAL-HTTPS-ROLLOUT.md).

RunLater schedules requests to customer-chosen public HTTPS endpoints. Your
application performs the business action. No custom RunLater receiver, ownership
probe, callback signing key or separate completion notification is required.
HTTP success does not establish business completion or wake every chatbot session.

## Connect and explicitly schedule

Start the connection in an OAuth-compatible MCP client’s integration settings with `https://mcp.runlater.io/mcp`
(Streamable HTTP), or `https://mcp.runlater.io/sse` (legacy SSE). Choose **Start free agent project** and consent to `http_schedule` plus the desired
read/cancel permissions. The consent button appears only after that client starts
OAuth; opening `/authorize` directly is not a signup or connection flow. Everyday users do not generate an Ed25519 key or create
an account. The client holds OAuth credentials; the gateway holds trial authority.
This is not owner-local-key custody. Existing owner-key grants are not broadened.

Connecting, initialization, discovery and status do not allocate a project.
Explicitly request `provision_trial({"accept_finite_trial":true})`, then inspect
`trial_status`. Do not create a replacement identity to evade capacity or quota.
See [trial credentials and limits](MCP-ANONYMOUS-TRIAL.md).

The hosted MCP tool is `schedule_http_request`:

```json
{
  "url": "https://app.example.com/events",
  "payload": {"action": "follow_up"},
  "run_at_ms": 1800000000000,
  "operation_key": "follow_up_01",
  "idempotency_key": "task_follow_up_01"
}
```

The timestamp is illustrative: replace it with a selected future UTC millisecond
time within trial expiry. Both keys use 1–128 ASCII letters, digits, `_` or `-`.
The API route is `POST /v1/http/tasks`: the body has `url`, `payload`, `run_at_ms`
and `operation_key`; `Idempotency-Key` is a required header. The hosted gateway
supplies authenticated trial authority. This is not an anonymous curl endpoint.

## Exact first-release boundary

- Fixed `POST`, `application/json`, HTTPS on default port 443 and a canonical
  public DNS hostname. No IP literals, userinfo, fragments or followed redirects.
- At most 1,024 UTF-8 bytes of serialized JSON payload and a 4,096-byte API body.
  The URL is at most 2,048 bytes under the API's ASCII URL rules.
- No custom headers, private endpoint authentication, response-body reflection,
  automatic receiver deployment or separate completion callback.
- The endpoint must already accept the intended unauthenticated JSON POST, and
  you must be authorized to cause its effect. A public URL is not permission.
- URLs and payloads are model-visible. Never paste API keys or bearer webhook
  secrets into paths, query strings or payloads. Private credential ingestion is
  outside this release.

Task acceptance snapshots the immutable destination. It uses the same finite
project/task/operation/publication/attempt budgets, not another quota pool.
Seven days starts at OAuth consent; the trial has 100 attempt credits and 16
lifetime tasks. A fresh task reserves five attempt credits; there are at most five
logical attempts and a 24-hour retry-age budget. Capacity is bounded by the beta's
10 lifetime project slots. Check status rather than assuming a slot is available.
Payments, automatic top-up and trial resets are disabled.

## Duplicates, uncertain outcomes and cancellation

Delivery is **at least once at task level**. The downstream `Idempotency-Key` is
`operation_key`, stable across attempts. Your application must durably deduplicate
that key before repeating an effect. API admission's `idempotency_key` separately
protects task creation: preserve the identical URL, payload, time and both keys
when resolving an uncertain result. Do not automatically choose new keys or a new
identity. Inspect the same project's task status before a deliberate retry.

The transport retains same-attempt receipts, but the ledger can schedule a later
bounded attempt. Cloudflare may also perform internal network activity within a
Fetch invocation. Neither receipt suppression nor one Fetch invocation promises
exactly-once downstream effects. Cancellation prevents future claims; it cannot
recall an in-flight effect. There is no exact-time, ordering or SLA guarantee.

If transport admission is unavailable, the bounded API response is HTTP 503:

```json
{"error":{"code":"general_https_unavailable"},"task_accepted":false}
```

Only this exact confirmed response establishes non-admission. A lost or malformed
response remains uncertain. A special RunLater receiver is not the remedy for an
unavailable general HTTPS adapter.

## Transport trust boundary

The selected Cloudflare Worker public Fetch adapter uses the provider's public
network boundary and mandatory `global_fetch_strictly_public`. Redirect mode is
`manual`; all 3xx responses are rejected without following `Location`. A fresh
outbound request carries only the application's fixed headers; incoming credentials
are not forwarded. Response bodies and sensitive headers are not returned to MCP.

The Worker does not observe or pin the connected peer IP, inspect every DNS answer
or CNAME, or independently prove native socket TLS identity. Provider DNS, routing,
TLS and zone configuration remain trusted. Do not describe this as native peer-IP
pinning, all-answer DNS inspection or an independent egress firewall. See the
[adapter boundary and evidence](../egress/public-fetch/README.md).

`GENERAL_HTTPS_ENABLED` pauses new admission and future general dispatch when off;
it cannot undo in-flight effects. Retain task, destination and attempt state during
rollback. Production verification and bounded hosted delivery evidence remain separate from
these configuration readbacks. API health’s `receiver: workers.dev_only` describes
the optional registered receiver path, not the general HTTPS destination policy.
