import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";

const envWithApi = (status: number) =>
  ({ API: { fetch: async () => new Response(null, { status }) } }) as unknown as Env;
const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;

const get = (path: string, env: Env) => worker.fetch(new Request(`https://gateway.test${path}`), env, ctx);

describe("gateway", () => {
  it("reports healthy when the API is reachable", async () => {
    const res = await get("/health", envWithApi(200));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: "ok", api: "ok" });
  });

  it("reports 503 when the API is down", async () => {
    const res = await get("/health", envWithApi(500));
    expect(res.status).toBe(503);
  });

  it("rate limits registration per IP", async () => {
    const env = { ...envWithApi(200), REGISTER_RATE: { limit: async () => ({ success: false }) } } as unknown as Env;
    const req = new Request("https://gateway.test/api/auth/agent/register", {
      method: "POST",
      headers: { "CF-Connecting-IP": "203.0.113.7" },
      body: "{}",
    });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(429);
    expect(await res.json()).toMatchObject({ error: "rate_limited" });
  });

  it("refuses oversized bodies before parsing them", async () => {
    const req = new Request("https://gateway.test/api/auth/capability/execute", {
      method: "POST",
      headers: { "Content-Length": String(1024 * 1024) },
      body: "{}",
    });
    expect((await worker.fetch(req, envWithApi(200), ctx)).status).toBe(413);
  });

  it("serves only the agent routes", async () => {
    for (const path of ["/nope", "/api/auth/agent/list", "/api/auth/sign-in/email", "/api/auth/host/create"]) {
      expect((await get(path, envWithApi(200))).status, path).toBe(404);
    }
  });
});
