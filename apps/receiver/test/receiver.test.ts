import { describe, expect, it } from "vitest";
import worker, { type Delivery, type Env } from "../src/index";

/** In-memory stand-in for the Inbox Durable Object, one per run. */
function env(token = "t0ken"): Env {
  const runs = new Map<string, Delivery[]>();
  const inbox = (run: string) => {
    const list = runs.get(run) ?? runs.set(run, []).get(run)!;
    return {
      record: async (d: Delivery) => {
        const earlier = list.filter((x) => x.name === d.name).length;
        list.push(d);
        return d.name === "gone" ? 404 : d.name === "flaky" && earlier === 0 ? 503 : 200;
      },
      list: async () => list,
    };
  };
  return { INBOX: { idFromName: (n: string) => n, get: inbox }, RECEIVER_TOKEN: token } as unknown as Env;
}

const call = (e: Env, path: string, init?: RequestInit) => worker.fetch(new Request(`https://r.test${path}`, init), e);

describe("receiver", () => {
  it("records deliveries and scripts replies", async () => {
    const e = env();
    expect((await call(e, "/hook/run-12345/ok", { method: "POST", body: "a" })).status).toBe(200);
    expect((await call(e, "/hook/run-12345/flaky", { method: "POST", body: "b" })).status).toBe(503);
    expect((await call(e, "/hook/run-12345/flaky", { method: "POST", body: "b" })).status).toBe(200);
    expect((await call(e, "/hook/run-12345/gone", { method: "DELETE" })).status).toBe(404);

    const res = await call(e, "/runs/run-12345", { headers: { Authorization: "Bearer t0ken" } });
    const { deliveries } = (await res.json()) as { deliveries: Delivery[] };
    expect(deliveries.map((d) => [d.name, d.method])).toEqual([
      ["ok", "POST"],
      ["flaky", "POST"],
      ["flaky", "POST"],
      ["gone", "DELETE"],
    ]);
  });

  it("needs the token to read", async () => {
    const e = env();
    expect((await call(e, "/runs/run-12345")).status).toBe(401);
    expect((await call(e, "/runs/run-12345", { headers: { Authorization: "Bearer nope" } })).status).toBe(401);
    expect((await call(env(""), "/runs/run-12345", { headers: { Authorization: "Bearer " } })).status).toBe(401);
  });

  it("rejects bad paths and big bodies", async () => {
    const e = env();
    expect((await call(e, "/hook/x/ok", { method: "POST" })).status).toBe(404);
    expect((await call(e, "/hook/run-12345/../x", { method: "POST" })).status).toBe(404);
    expect((await call(e, "/hook/run-12345/ok", { method: "POST", body: "x".repeat(200 * 1024) })).status).toBe(413);
  });
});
