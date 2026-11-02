// Maps an owner to its RunLater project: an Agent Auth host id, or `mcp:<id>` for a hosted MCP
// connection. One project per owner, never reassigned.

import { ApiClient, ApiError } from "./api";
import { execute } from "./capabilities";

export async function findProject(db: D1Database, owner: string): Promise<string | null> {
  const row = await db
    .prepare("SELECT project_id FROM runlater_project WHERE host_id = ?")
    .bind(owner)
    .first<{ project_id: string }>();
  return row?.project_id ?? null;
}

/** Returns the owner's project id, allocating one on first call. Safe to repeat. */
export async function ensureProject(db: D1Database, owner: string): Promise<string> {
  const id = `prj_${[...crypto.getRandomValues(new Uint8Array(12))].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  await db
    .prepare("INSERT OR IGNORE INTO runlater_project (host_id, project_id, created_at) VALUES (?, ?, ?)")
    .bind(owner, id, Date.now())
    .run();
  const existing = await findProject(db, owner);
  if (!existing) throw new Error("project mapping missing after insert");
  return existing;
}

/** Runs a capability for an owner: create_project allocates its project, anything else needs one. */
export async function runCapability(
  env: { DB: D1Database; API: Fetcher },
  key: CryptoKey,
  owner: string,
  capability: string,
  args: Record<string, unknown>,
): Promise<unknown> {
  const projectId = capability === "create_project" ? await ensureProject(env.DB, owner) : await findProject(env.DB, owner);
  if (!projectId) {
    throw new ApiError(404, {
      error: { code: "project_not_found", message: "call create_project before using other capabilities" },
    });
  }
  return execute(new ApiClient(env.API, key, projectId), capability, args);
}
