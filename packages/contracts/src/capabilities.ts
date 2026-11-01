// The agent-facing contract: RunLater's Agent Auth capabilities. The gateway serves these
// (apps/gateway) and the docs render them (apps/web), so both read this one definition.
// Through the Agent Auth MCP bridge the description and input schema are what an agent reads.

export interface CapabilityDefinition {
  name: string;
  description: string;
  /** JSON Schema for the capability's `arguments`. */
  input: Record<string, unknown> & { properties: Record<string, Record<string, unknown>>; required?: string[] };
}

const TASK_ID = { type: "string", pattern: "^task_[0-9a-f]{20}$", description: "The task id returned by schedule_http." };
export const STATUSES = ["scheduled", "delivering", "retrying", "succeeded", "failed", "canceled"];

const noArgs = { type: "object", additionalProperties: false, properties: {} };
const taskArgs = { type: "object", additionalProperties: false, required: ["task_id"], properties: { task_id: TASK_ID } };

export const capabilities: CapabilityDefinition[] = [
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
      "Schedule an HTTP request to a public https:// URL: now, after a delay (\"90s\", \"15m\", \"24h\", \"7d\"), " +
      "or at run_at_ms (unix milliseconds), at most 7 days ahead. " +
      "RunLater signs the request, retries timeouts, 408, 425, 429 and 5xx with backoff (up to max_attempts), " +
      "and records every attempt. Returns the task; check it later with get_task, or pass callback_url to have " +
      "the final result POSTed to you. Pass idempotency_key to make retries of this call safe.",
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
        run_at_ms: { type: "integer", minimum: 0, description: "When to send, unix ms. Omit to send now. Not with delay." },
        delay: {
          type: "string",
          pattern: "^[0-9]{1,7}[smhd]$",
          description: "Send after this long instead of at run_at_ms: a whole number and s, m, h or d, e.g. \"24h\". At most 7d.",
        },
        callback_url: {
          type: "string",
          maxLength: 2048,
          description:
            "https:// URL that receives a signed POST with the task's final state once it succeeds, fails or is canceled. " +
            "The callback is itself a task (see callback_task_id) and costs one delivery attempt per try.",
        },
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
