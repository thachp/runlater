// Maps each capability (defined in @runlater/contracts) to exactly one call on the private
// API (packages/contracts/openapi.yaml), validating arguments that end up in a path.

import { STATUSES } from "@runlater/contracts/capabilities";
import type { ApiClient, Scope } from "./api";

export { capabilities, capabilityNames } from "@runlater/contracts/capabilities";

const TASK_ID_RE = /^task_[0-9a-f]{20}$/;

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
