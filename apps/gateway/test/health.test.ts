import { describe, expect, it } from "vitest";
import worker, { type Env } from "../src/index";

const envWithApi = (status: number): Env => ({
  API: { fetch: async () => new Response(null, { status }) } as unknown as Fetcher,
});

const get = (path: string, env: Env) =>
  worker.fetch(new Request(`https://gateway.test${path}`), env);

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

  it("returns 404 for unknown routes", async () => {
    expect((await get("/nope", envWithApi(200))).status).toBe(404);
  });
});
