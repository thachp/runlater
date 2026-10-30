# RunLater — Product Spec (v1)

Status: **draft for review** · Owner: Patrick Thach · Last updated: 2026-10-30

## One line

**RunLater lets an AI agent say "make this HTTP request later" — and then check whether it happened.**

## Problem

Agents work in short sessions. They cannot sleep for an hour, wake up tomorrow, or
retry a flaky webhook five times over twenty minutes. Today an agent that needs
"call this URL at 9am" or "retry this until it succeeds" has nowhere to put that
intent. Developers solve it with cron boxes, queues, or QStash-style services that
assume a human signed up, pasted an API key, and wired a dashboard.

## Who it's for

| Priority | User | How they reach us |
| --- | --- | --- |
| Primary | **AI agents** acting for a person or system | Agent Auth capabilities (directly, or as MCP tools via the Agent Auth MCP bridge) |
| Secondary | Developers building those agents | Same capabilities over HTTP; docs site |

There is no human sign-up, password, or dashboard in v1. The agent *is* the customer.

## Core jobs (v1)

1. **Schedule** an HTTP request to a public HTTPS URL, now or at a future time.
2. **Check** a task's status and its delivery attempts.
3. **List** recent tasks for the project.
4. **Cancel** a task that hasn't run yet.
5. **Redrive** a task that failed, to try it again.

That's the whole product for v1.

## How it works (user's view)

```
Agent ──discover──▶ RunLater           "what can you do?"
Agent ──register──▶ Agent Auth         gets an identity + keys
Agent ──create_project──▶ RunLater     gets a free trial (finite budget, 7 days)
Agent ──schedule_http──▶ RunLater      { url, method, headers, body, run_at }
                                       ← task_id, status: scheduled
          … time passes …
RunLater ──signed HTTPS request──▶ destination   (retries on failure)
Agent ──get_task──▶ RunLater           ← status: succeeded, attempts: [...]
```

## Concepts

| Term | Meaning |
| --- | --- |
| **Agent identity** | An Agent Auth host + agent keypair. The only way to authenticate. |
| **Project** | Owned by exactly one agent host. Holds tasks, budget, and the signing secret. One project per host in v1. |
| **Trial** | A project's free allocation: N delivery attempts, expires after 7 days. No refills. |
| **Task** | One HTTP request to make at `run_at`, with a retry policy. |
| **Attempt** | One try at delivering a task: time, response status, duration, error. |

## Task lifecycle

```
scheduled ──(run_at reached)──▶ delivering ──2xx──▶ succeeded
    │                               │
    │ cancel                        └─non-2xx/timeout─▶ retrying ──(backoff)──▶ delivering
    ▼                                                      │
 canceled                                     attempts exhausted ──▶ failed ──redrive──▶ scheduled
```

- `succeeded` means the destination returned 2xx. It does not mean the business action downstream worked.
- Delivery is **at-least-once**. Destinations should use the `RunLater-Task-Id` header to dedupe.
- No promise of exact timing, ordering, or an SLA in v1.

## Capabilities (the API surface)

Each one is an Agent Auth capability. The same set is also exposed as MCP tools.

| Capability | Input | Output |
| --- | --- | --- |
| `create_project` | — | project id, trial budget, expiry |
| `get_project` | — | budget used/remaining, expiry, signing key id |
| `schedule_http` | `url`, `method`, `headers?`, `body?`, `run_at?`, `idempotency_key?`, `max_attempts?` | `task_id`, `status` |
| `get_task` | `task_id` | task + attempts |
| `list_tasks` | `status?`, `cursor?` | page of tasks |
| `cancel_task` | `task_id` | task |
| `redrive_task` | `task_id` | task |

The REST routes underneath (`/v1/tasks`, …) are an internal contract between
services, not a public product in v1.

## Delivery rules

- **Destinations:** `https://` on the default port to a public DNS name. No IP literals, credentials in the URL, fragments, or non-public names (`localhost`, `*.local`, `*.internal`, `*.test`, …). Checked when the task is accepted and again before every attempt. Resolved addresses are restricted to the public internet by Cloudflare (`global_fetch_strictly_public`).
- **Methods and headers:** `GET`, `POST` (default), `PUT`, `PATCH`, `DELETE`. Callers may set any header except hop-by-hop/framing headers (`Host`, `Content-Length`, `Transfer-Encoding`, …) and the `RunLater-*`, `CF-*`, `X-Forwarded-*` and `Proxy-*` families. `GET` cannot have a body.
- **Signing:** every outbound request carries `RunLater-Task-Id`, `RunLater-Attempt`, `RunLater-Timestamp` (unix seconds) and `RunLater-Signature: v1=<hex>`, an HMAC-SHA256 with the project's signing secret over `"{timestamp}.{task_id}.{attempt}."` followed by the raw body. While a secret is being rotated, the header carries one comma-separated `v1=` entry per active secret. Receivers should reject timestamps more than 5 minutes off.
- **Retries:** default 5 attempts total, max 5. Delay before retry *n* is 10 s × 2ⁿ⁻¹ (capped at 10 min) with equal jitter; a `Retry-After` from the destination is honoured as a minimum, up to the same cap.
- **Timeout:** 10 s per attempt. Redirects are not followed.
- **Success:** any 2xx. Retry on 408, 425, 429, 5xx, timeouts and network errors. Anything else (other 4xx, 3xx) fails without retry.
- **Idempotency:** an optional `idempotency_key` makes `schedule_http` safe to repeat. The same key with the same request returns the original task; with a different request it is a conflict.

## v1 limits

| Limit | Value |
| --- | --- |
| Request body | 64 KB (today's beta: 1 KB — to be raised) |
| Headers | 32 headers, 8 KB total |
| Furthest `run_at` | 7 days out (bounded by trial expiry) |
| Trial | 100 delivery attempts, 7 days |
| Retention | Task + attempts kept 30 days after terminal state |
| Tasks held per project | 1,000, finished ones included until purged. A task's body is dropped once it succeeds or is canceled; failed tasks keep it for redrive. |
| Projects | 1 per agent host |

## Explicitly not in v1

| Out of scope | Why it's later |
| --- | --- |
| Recurring / cron schedules | Repeats a task on a timer ("every day at 9"). Useful, but one-shot must be solid first. |
| Web dashboard | A page where a human signs in to see tasks. v1 has no humans signing in. |
| Billing / paid plans | Charging for more than the free trial. Needed once trials run out — v2. |
| SDKs | A packaged npm client. Agents use capabilities/MCP directly. |
| API keys, OAuth, invitations, anonymous trials, receiver pairing | Replaced by Agent Auth. |
| Workflows, fan-out, ordering guarantees | Different product. |

## Success criteria for v1 launch

- An agent goes from zero to a delivered, signed request in under 5 tool calls, without human help.
- Accepted tasks are never lost: every one reaches `succeeded`, `failed` or `canceled`.
- No task can reach a private network or another project's data (tested).
- p95 delivery lateness under 60 s for tasks due "now", measured on a real deployment.

## Open questions

1. **MCP client compatibility.** Agent Auth is not standard MCP OAuth. Claude Desktop, Cursor, etc. would need the `@auth/agent-cli mcp` stdio bridge, which hasn't been validated. Do we also want a hosted remote MCP endpoint, and how would it authenticate?
2. **Key loss.** If an agent loses its keys, its project is gone. Acceptable for a trial?
3. **Abuse.** New keys are new identities (Sybil). Is a global trial cap + per-IP registration limit enough for launch?
4. **What happens after the trial?** Even without billing, do we want a waitlist / "contact us" path?
