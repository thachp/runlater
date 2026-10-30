-- One RunLater project per Agent Auth host, never reassigned.
CREATE TABLE runlater_project (
  host_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
