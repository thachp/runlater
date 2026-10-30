// Maps an Agent Auth host to its RunLater project. One project per host, never reassigned.

export async function findProject(db: D1Database, hostId: string): Promise<string | null> {
  const row = await db
    .prepare("SELECT project_id FROM runlater_project WHERE host_id = ?")
    .bind(hostId)
    .first<{ project_id: string }>();
  return row?.project_id ?? null;
}

/** Returns the host's project id, allocating one on first call. Safe to repeat. */
export async function ensureProject(db: D1Database, hostId: string): Promise<string> {
  const id = `prj_${[...crypto.getRandomValues(new Uint8Array(12))].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  await db
    .prepare("INSERT OR IGNORE INTO runlater_project (host_id, project_id, created_at) VALUES (?, ?, ?)")
    .bind(hostId, id, Date.now())
    .run();
  const existing = await findProject(db, hostId);
  if (!existing) throw new Error("project mapping missing after insert");
  return existing;
}
