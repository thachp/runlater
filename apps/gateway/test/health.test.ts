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

  it("counts body bytes even without Content-Length", async () => {
    const chunk = new Uint8Array(64 * 1024);
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(c) {
        if (sent++ < 4) c.enqueue(chunk);
        else c.close();
      },
    });
    const req = new Request("https://gateway.test/api/auth/capability/execute", {
      method: "POST",
      body: stream,
      duplex: "half",
    } as RequestInit);
    expect(req.headers.get("Content-Length")).toBeNull();
    expect((await worker.fetch(req, envWithApi(200), ctx)).status).toBe(413);
  });

  it("claims each token's jti atomically before Better Auth sees it", async () => {
    const claims: string[] = [];
    const store = { claim: async (key: string) => (claims.push(key), claims.length === 1) };
    const env = {
      ...envWithApi(200),
      ASSERTION_PRIVATE_KEY: "07".repeat(32),
      AUTH_STORE: { idFromName: () => "id", get: () => store },
    } as unknown as Env;
    const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, "");
    const token = `${b64({ alg: "EdDSA" })}.${b64({ sub: "agent_1", jti: "abc" })}.sig`;
    const send = () =>
      worker.fetch(
        new Request("https://gateway.test/api/auth/capability/execute", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "{}",
        }),
        env,
        ctx,
      );
    // First use passes the gateway (and then fails inside Better Auth, which has no DB here).
    await send().catch(() => undefined);
    const second = await send();
    expect(second.status).toBe(401);
    expect(await second.json()).toMatchObject({ error: "invalid_jwt" });
    expect(claims).toEqual(["replay::agent_1:abc", "replay::agent_1:abc"]);
  });

  it("serves only the agent routes", async () => {
    for (const path of ["/nope", "/api/auth/agent/list", "/api/auth/sign-in/email", "/api/auth/host/create"]) {
      expect((await get(path, envWithApi(200))).status, path).toBe(404);
    }
  });
});
