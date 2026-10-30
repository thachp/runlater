// The agent-facing contract. Each capability is one Agent Auth capability and, through the
// Agent Auth MCP bridge, one MCP tool; its description and input schema are what the agent
// reads. Each maps to exactly one call on the private API (packages/contracts/openapi.yaml).

import type { Capability } from "@better-auth/agent-auth";
import type { ApiClient, Scope } from "./api";

const TASK_ID = { type: "string", pattern: "^task_[0-9a-f]{20}$", description: "The task id returned by schedule_http." };
const TASK_ID_RE = /^task_[0-9a-f]{20}$/;
const STATUSES = ["scheduled", "delivering", "retrying", "succeeded", "failed", "canceled"];

const noArgs = { type: "object", additionalProperties: false, properties: {} };
const taskArgs = { type: "object", additionalProperties: false, required: ["task_id"], properties: { task_id: TASK_ID } };

export const capabilities: Capability[] = [
  {
    name: "create_project",
    description:
      "Create this agent's RunLater project with a free trial (100 delivery attempts, 7 days). " +
      "Call once before scheduling; calling again returns the same project and never resets the trial. " +
      "The returned signing_secret lets the destination verify RunLater-Signature on each delivery.",
    input: noArgs,
  },
  {
    name: "get_project",
    description: "Show this agent's project: trial expiry, delivery attempts used and remaining, and the signing secret.",
    input: noArgs,
  },
  {
    name: "schedule_http",
    description:
      "Schedule an HTTP request to a public https:// URL, now or at run_at_ms (unix milliseconds, at most 7 days ahead). " +
      "RunLater signs the request, retries timeouts, 408, 425, 429 and 5xx with backoff (up to max_attempts), " +
      "and records every attempt. Returns the task; check it later with get_task. " +
      "Pass idempotency_key to make retries of this call safe.",
    input: {
      type: "object",
      additionalProperties: false,
      required: ["url"],
      properties: {
        url: { type: "string", maxLength: 2048, description: "https:// URL on a public domain name." },
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"], default: "POST" },
        headers: {
          type: "object",
          maxProperties: 32,
          additionalProperties: { type: "string" },
          description: "Headers to send. Host, Content-Length and RunLater-*/CF-*/X-Forwarded-* headers are not allowed.",
        },
        body: { type: "string", maxLength: 65536, description: "Request body as text, e.g. JSON. Not allowed with GET." },
        run_at_ms: { type: "integer", minimum: 0, description: "When to send, unix ms. Omit to send now." },
        idempotency_key: {
          type: "string",
          pattern: "^[A-Za-z0-9_-]{1,128}$",
          description: "Repeat a call with the same key and request to get the same task back.",
        },
        max_attempts: { type: "integer", minimum: 1, maximum: 5, default: 5 },
      },
    },
  },
  {
    name: "get_task",
    description: "Get a task's status and every delivery attempt (time, HTTP status or error).",
    input: taskArgs,
  },
  {
    name: "list_tasks",
    description: "List this project's tasks, newest first. Pass next_cursor from a previous page to continue.",
    input: {
      type: "object",
      additionalProperties: false,
      properties: {
        status: { type: "string", enum: STATUSES },
        cursor: { type: "string", pattern: "^[0-9]{1,16}$" },
        limit: { type: "integer", minimum: 1, maximum: 100, default: 20 },
      },
    },
  },
  {
    name: "cancel_task",
    description: "Cancel a task that has not been delivered yet. A task mid-delivery is canceled once that attempt ends, unless it succeeds.",
    input: taskArgs,
  },
  {
    name: "redrive_task",
    description: "Retry a failed task from now, with a fresh set of attempts. Its attempt history is kept.",
    input: taskArgs,
  },
];

export const capabilityNames = capabilities.map((c) => c.name);

/** Raised for bad arguments before anything reaches the API. */
export class ArgumentError extends Error {
  constructor(
    message: string,
    readonly field?: string,
  ) {
    super(message);
  }
}

type Args = Record<string, unknown>;

function only(args: Args, allowed: string[]): void {
  for (const key of Object.keys(args)) {
    if (!allowed.includes(key)) throw new ArgumentError(`unknown argument ${JSON.stringify(key)}`, key);
  }
}

function taskId(args: Args): string {
  only(args, ["task_id"]);
  const id = args.task_id;
  // Validated here because it becomes part of an API path.
  if (typeof id !== "string" || !TASK_ID_RE.test(id)) throw new ArgumentError("task_id is not a valid task id", "task_id");
  return id;
}

function listQuery(args: Args): string {
  only(args, ["status", "cursor", "limit"]);
  const q = new URLSearchParams();
  if (args.status !== undefined) {
    if (typeof args.status !== "string" || !STATUSES.includes(args.status)) throw new ArgumentError("unknown status", "status");
    q.set("status", args.status);
  }
  if (args.cursor !== undefined) {
    if (typeof args.cursor !== "string" || !/^[0-9]{1,16}$/.test(args.cursor)) throw new ArgumentError("invalid cursor", "cursor");
    q.set("cursor", args.cursor);
  }
  if (args.limit !== undefined) {
    if (!Number.isInteger(args.limit) || (args.limit as number) < 1 || (args.limit as number) > 100) {
      throw new ArgumentError("limit must be 1-100", "limit");
    }
    q.set("limit", String(args.limit));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

/** The API call a capability makes, minus project creation (handled by the caller). */
export function route(capability: string, args: Args): { method: "GET" | "POST"; path: string; scope: Scope; body?: unknown } {
  switch (capability) {
    case "create_project":
      only(args, []);
      return { method: "POST", path: "/v1/projects", scope: "project" };
    case "get_project":
      only(args, []);
      return { method: "GET", path: "/v1/projects/self", scope: "read" };
    case "schedule_http":
      // The API validates the request fully and names the failing field.
      return { method: "POST", path: "/v1/tasks", scope: "schedule", body: args };
    case "get_task":
      return { method: "GET", path: `/v1/tasks/${taskId(args)}`, scope: "read" };
    case "list_tasks":
      return { method: "GET", path: `/v1/tasks${listQuery(args)}`, scope: "read" };
    case "cancel_task":
      return { method: "POST", path: `/v1/tasks/${taskId(args)}/cancel`, scope: "cancel" };
    case "redrive_task":
      return { method: "POST", path: `/v1/tasks/${taskId(args)}/redrive`, scope: "schedule" };
    default:
      throw new ArgumentError(`unknown capability ${capability}`);
  }
}

export async function execute(client: ApiClient, capability: string, args: Args): Promise<unknown> {
  const r = route(capability, args);
  return client.call(r.method, r.path, r.scope, r.body);
}
