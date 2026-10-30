# Language-neutral local HTTP walkthrough

These requests use the **default loopback emulator** and its intentionally public fixture token. Never send these credentials or fixture destinations to api.runlater.io. Install the pinned tools from [LOCAL.md](LOCAL.md), run `npm run dev -- --ip 127.0.0.1 --port 8787`, and use a disposable local store. The invitation production flow instead uses Ed25519 signed requests; it is not a bearer-token variant of this contract.

## Enqueue and recover an uncertain response

```http
POST /v1/tasks HTTP/1.1
Host: 127.0.0.1:8787
Authorization: Bearer local-alpha
Content-Type: application/json
Idempotency-Key: demo_enqueue_01

{"destination":"fixture://success","body":"synthetic demo","operation_key":"demo_operation_01","run_at_ms":0}
```

Equivalent curl (one bounded request, no redirects):

```sh
curl --silent --show-error --max-time 5 --max-redirs 0 \
  -H 'Authorization: Bearer local-alpha' -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo_enqueue_01' \
  --data '{"destination":"fixture://success","body":"synthetic demo","operation_key":"demo_operation_01","run_at_ms":0}' \
  http://127.0.0.1:8787/v1/tasks
```

Copy the returned `id`. If the acceptance response is lost, repeat the same request with exactly the same key/body/schedule; do not invent another key. A task ID means durable acceptance, not successful delivery. `0` means eligible now, not exact delivery time. A second unchanged enqueue returns its original task; changed input under that key conflicts.

## Inspect status and attempt history

```sh
# Replace with the ID returned by your own request:
RUNLATER_DEMO_TASK_ID='task_0000000000000001'
curl --silent --show-error --max-time 5 --max-redirs 0 \
  -H 'Authorization: Bearer local-alpha' \
  "http://127.0.0.1:8787/v1/tasks/$RUNLATER_DEMO_TASK_ID/inspection"
curl --silent --show-error --max-time 5 --max-redirs 0 \
  -H 'Authorization: Bearer local-alpha' \
  "http://127.0.0.1:8787/v1/tasks/$RUNLATER_DEMO_TASK_ID/attempts"
```

The inspection route omits input body, destination and operation key; full task reads require read scope and can return payloads. Avoid logging them. Inspect once after an uncertain result; any further polling should be explicitly finite. Cancellation uses POST `/v1/tasks/{id}/cancel` with `{}` and the same local auth/media headers. It prevents new claims but cannot undo an in-flight receiver effect.

## Demonstrate failed-only redrive

Enqueue a second task using `fixture://fail`, a distinct enqueue key and a chosen stable operation key. Inspect its returned ID until the state is `failed` using a bounded number of checks; otherwise stop and diagnose rather than looping indefinitely. Then:

```sh
# Replace with the failed task's returned ID:
RUNLATER_DEMO_FAILED_ID='task_0000000000000002'
curl --silent --show-error --max-time 5 --max-redirs 0 \
  -H 'Authorization: Bearer local-alpha' -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo_redrive_01' --data '{}' \
  "http://127.0.0.1:8787/v1/tasks/$RUNLATER_DEMO_FAILED_ID/redrive"
```

Redrive creates a linked execution and keeps the source history and operation key. Retrying that redrive with the same key returns the same child. A new redrive is a separate execution, not a way to change body or evade idempotency. Only failed tasks can redrive; a nonfailed task returns conflict. A failing fixture remains failing after redrive.

## Receiver and operational boundaries

A receiver must verify the exact raw body and timestamped signature before processing, and durably deduplicate by tenant + operation key + body identity in the same transaction as its side effect. Timestamp windows alone do not stop within-window replay. The small `examples/local-receiver.mjs` protocol example uses a bounded **in-memory** map and public fixture HMAC; it is not durable business storage or production key management. `examples/rotating-receiver.mjs` demonstrates the separate v2 keyring protocol. Do not mix the legacy fixture wire format with v2.

Fixture destinations above complete in-process, not over HTTPS. For the compiled enrollment → verified destination → signed Fetch callback → status/retry flow, run [the local invitation demo](PILOT.md). It intercepts all callback traffic locally and leaves hosted services unchanged.

Use `docs/openapi.json` and `npm run test:contract` for executable request/response/media/schema parity. Common outcomes include 401 credentials, 403 scope, 404 tenant-owned resource absent, 409 immutable conflict/wrong state, 422 disabled fixture destination and 429 finite admission/dispatch controls with Retry-After. Do not assume an error means no acceptance; recover an uncertain enqueue with its original identity. See [OPERATIONS.md](OPERATIONS.md), [FUNDING.md](FUNDING.md), [PAUSE.md](PAUSE.md), and [RUNTIME-RECOVERY.md](RUNTIME-RECOVERY.md) for bounded maintenance, settlement, leases and uncertainty. No SLA, billing or production provisioning follows from these examples.
