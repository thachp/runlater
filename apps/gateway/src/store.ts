// Better Auth's secondary storage, shared by every gateway instance: JWT `jti` replay
// protection and rate-limit counters. One Durable Object, so check-and-set is atomic.

import { DurableObject } from "cloudflare:workers";

const MAX_KEY = 1024;
const MAX_VALUE = 16 * 1024;
const MAX_TTL_SECS = 30 * 24 * 3600;
/** Hard cap so a flood of distinct keys cannot grow storage without bound. */
const MAX_ENTRIES = 200_000;

export class AuthStore extends DurableObject<Record<string, never>> {
  constructor(ctx: DurableObjectState, env: Record<string, never>) {
    super(ctx, env);
    ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires INTEGER)`,
    );
    ctx.storage.sql.exec(`CREATE INDEX IF NOT EXISTS kv_expires ON kv (expires)`);
  }

  private live(key: string): string | null {
    const row = this.ctx.storage.sql
      .exec<{ value: string; expires: number | null }>("SELECT value, expires FROM kv WHERE key = ?", key)
      .toArray()[0];
    if (!row) return null;
    if (row.expires !== null && row.expires <= Date.now()) {
      this.ctx.storage.sql.exec("DELETE FROM kv WHERE key = ?", key);
      return null;
    }
    return row.value;
  }

  private write(key: string, value: string, ttlSecs?: number): void {
    if (key.length > MAX_KEY || value.length > MAX_VALUE) throw new Error("auth store entry too large");
    const now = Date.now();
    this.ctx.storage.sql.exec("DELETE FROM kv WHERE expires IS NOT NULL AND expires <= ?", now);
    const count = this.ctx.storage.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM kv").one().n;
    const exists = this.ctx.storage.sql.exec("SELECT 1 FROM kv WHERE key = ?", key).toArray().length > 0;
    if (!exists && count >= MAX_ENTRIES) throw new Error("auth store full");
    const ttl = ttlSecs === undefined ? MAX_TTL_SECS : Math.min(Math.max(ttlSecs, 1), MAX_TTL_SECS);
    this.ctx.storage.sql.exec(
      `INSERT INTO kv (key, value, expires) VALUES (?, ?, ?)
       ON CONFLICT (key) DO UPDATE SET value = excluded.value, expires = excluded.expires`,
      key,
      value,
      now + ttl * 1000,
    );
  }

  async get(key: string): Promise<string | null> {
    return this.live(key);
  }

  async getAndDelete(key: string): Promise<string | null> {
    const value = this.live(key);
    if (value !== null) this.ctx.storage.sql.exec("DELETE FROM kv WHERE key = ?", key);
    return value;
  }

  async set(key: string, value: string, ttlSecs?: number): Promise<void> {
    this.write(key, value, ttlSecs);
  }

  /** TTL applies only when the counter is created, per Better Auth's contract. */
  async increment(key: string, ttlSecs: number): Promise<number> {
    const current = this.live(key);
    if (current === null) {
      this.write(key, "1", ttlSecs);
      return 1;
    }
    const next = Number(current) + 1;
    this.ctx.storage.sql.exec("UPDATE kv SET value = ? WHERE key = ?", String(next), key);
    return next;
  }

  /**
   * Records `key` if absent and reports whether this call did so. Atomic: Durable Object
   * methods with no `await` run to completion before the next request is processed.
   */
  async claim(key: string, ttlSecs: number): Promise<boolean> {
    if (this.live(key) !== null) return false;
    this.write(key, "1", ttlSecs);
    return true;
  }

  async delete(key: string): Promise<void> {
    this.ctx.storage.sql.exec("DELETE FROM kv WHERE key = ?", key);
  }
}
