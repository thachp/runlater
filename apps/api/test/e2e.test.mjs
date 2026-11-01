// End-to-end: the built Worker in local workerd (Miniflare) with real Durable Object
// SQLite, alarms and Queues. Outbound deliveries are captured by `outboundService`
// instead of leaving the machine. Run `npm run build` first.
//
// `global_fetch_strictly_public` is left off here: it would route fetch() to the real
// internet, around the capture. It is a provider guarantee, set in wrangler.jsonc.

import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, sign } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const root = fileURLToPath(new URL("..", import.meta.url));
const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicHex = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url").toString("hex");

function assertion(project, scope = "project schedule read cancel") {
  const now = Math.floor(Date.now() / 1000);
  const claims = { aud: "runlater-api", sub: project, scope, iat: now, exp: now + 60 };
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const sig = sign(null, Buffer.from(payload), privateKey).toString("base64url");
  return `${payload}.${sig}`;
}

/** Requests the Worker sent out, and scripted replies per path (default 200). */
const received = [];
const replies = new Map();

let mf;
before(async () => {
  // Miniflare 5 takes a new options shape; it converts from the documented v4 one.
  mf = new Miniflare(convertV4MiniflareOptions({
    modulesRoot: root,
    modules: [
      { type: "ESModule", path: `${root}build/index.js` },
      { type: "CompiledWasm", path: `${root}build/index_bg.wasm` },
    ],
    compatibilityDate: "2026-10-27",
    durableObjects: { LEDGER: { className: "TaskLedger", useSQLite: true } },
    queueProducers: { READY: { queueName: "runlater-ready" } },
    queueConsumers: { "runlater-ready": { maxBatchTimeout: 1 } },
    bindings: { GATEWAY_PUBLIC_KEY: publicHex },
    outboundService: async (req) => {
      const url = new URL(req.url);
      received.push({
        url: req.url,
        method: req.method,
        headers: Object.fromEntries(req.headers),
        body: await req.text(),
      });
      const script = replies.get(url.pathname) ?? [];
      const status = script.length ? script.shift() : 200;
      return new Response(`status ${status}`, { status });
    },
  }));
  await mf.ready;
});
after(() => mf?.dispose());

async function api(method, path, { project = "proj_a", body, scope, token } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token !== null) headers["RunLater-Assertion"] = token ?? assertion(project, scope);
  const res = await mf.dispatchFetch(`https://api.internal${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

async function until(check, timeoutMs = 20_000) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > end) throw new Error("timed out waiting");
    await new Promise((r) => setTimeout(r, 200));
  }
}

const settled = (project, id, statuses, timeoutMs) =>
  until(async () => {
    const { json } = await api("GET", `/v1/tasks/${id}`, { project });
    return statuses.includes(json.status) && json;
  }, timeoutMs);

let secret;

describe("api", () => {
  test("health needs no auth", async () => {
    const res = await mf.dispatchFetch("https://api.internal/health");
    assert.equal(res.status, 200);
  });

  test("rejects missing, forged and under-scoped assertions", async () => {
    assert.equal((await api("GET", "/v1/projects/self", { token: null })).status, 401);
    assert.equal((await api("GET", "/v1/projects/self", { token: "a.b" })).status, 401);
    const res = await api("POST", "/v1/tasks", { scope: "read", body: {} });
    assert.equal(res.status, 403);
    assert.equal((await api("GET", "/v1/nope")).status, 404);
  });

  test("creates a project once", async () => {
    assert.equal((await api("GET", "/v1/tasks")).json.error.code, "project_not_found");
    const first = await api("POST", "/v1/projects");
    assert.equal(first.status, 201);
    assert.match(first.json.signing_secret, /^rls_[0-9a-f]{64}$/);
    assert.equal(first.json.attempts_remaining, 100);
    const again = await api("POST", "/v1/projects");
    assert.equal(again.status, 200);
    assert.equal(again.json.signing_secret, first.json.signing_secret);
    secret = first.json.signing_secret;
  });

  test("validates requests and names the field", async () => {
    const res = await api("POST", "/v1/tasks", { body: { url: "http://insecure.example.com/" } });
    assert.equal(res.status, 400);
    assert.equal(res.json.error.field, "url");
    const bad = await api("POST", "/v1/tasks", { body: { url: "https://a.example.com/", nope: 1 } });
    assert.equal(bad.status, 400);
  });

  test("delivers a signed request and records the attempt", async () => {
    const body = JSON.stringify({ hello: "world" });
    const res = await api("POST", "/v1/tasks", {
      body: {
        url: "https://receiver.example.com/ok",
        headers: { "X-Custom": "yes", "Content-Type": "application/json" },
        body,
      },
    });
    assert.equal(res.status, 201);
    const id = res.json.id;
    assert.match(id, /^task_[0-9a-f]{20}$/);

    const task = await settled("proj_a", id, ["succeeded", "failed"]);
    assert.equal(task.status, "succeeded");
    assert.deepEqual(
      task.attempts.map((a) => [a.number, a.outcome, a.http_status]),
      [[1, "http_200", 200]],
    );

    const sent = received.find((r) => r.headers["runlater-task-id"] === id);
    assert.equal(sent.method, "POST");
    assert.equal(sent.body, body);
    assert.equal(sent.headers["x-custom"], "yes");
    assert.equal(sent.headers["runlater-attempt"], "1");
    const ts = sent.headers["runlater-timestamp"];
    const expected = createHmac("sha256", secret).update(`${ts}.${id}.1.${body}`).digest("hex");
    assert.equal(sent.headers["runlater-signature"], `v1=${expected}`);

    const project = await api("GET", "/v1/projects/self");
    assert.equal(project.json.attempts_used, 1);
  });

  test("retries a 503 with backoff, then succeeds", async () => {
    replies.set("/flaky", [503]);
    const { json } = await api("POST", "/v1/tasks", { body: { url: "https://receiver.example.com/flaky" } });
    const task = await settled("proj_a", json.id, ["succeeded", "failed"], 30_000);
    assert.equal(task.status, "succeeded");
    assert.deepEqual(task.attempts.map((a) => a.outcome), ["http_503", "http_200"]);
    assert.ok(task.attempts[1].started_ms - task.attempts[0].finished_ms >= 5_000);
  });

  test("fails on a 404 without retrying, and redrive tries again", async () => {
    replies.set("/gone", [404]);
    const { json } = await api("POST", "/v1/tasks", {
      body: { url: "https://receiver.example.com/gone", method: "DELETE" },
    });
    const failed = await settled("proj_a", json.id, ["failed"]);
    assert.equal(failed.attempt_count, 1);

    const redriven = await api("POST", `/v1/tasks/${json.id}/redrive`);
    assert.equal(redriven.status, 200);
    const done = await settled("proj_a", json.id, ["succeeded"]);
    assert.deepEqual(done.attempts.map((a) => a.outcome), ["http_404", "http_200"]);
  });

  test("cancels a future task before it runs", async () => {
    const { json } = await api("POST", "/v1/tasks", {
      body: { url: "https://receiver.example.com/later", run_at_ms: Date.now() + 3_600_000 },
    });
    const canceled = await api("POST", `/v1/tasks/${json.id}/cancel`);
    assert.equal(canceled.json.status, "canceled");
    assert.equal((await api("POST", `/v1/tasks/${json.id}/cancel`)).status, 200);
    assert.ok(!received.some((r) => r.url.endsWith("/later")));
  });

  test("replays an idempotent schedule", async () => {
    const body = { url: "https://receiver.example.com/once", idempotency_key: "order-42" };
    const first = await api("POST", "/v1/tasks", { body });
    const again = await api("POST", "/v1/tasks", { body });
    assert.deepEqual([first.status, again.status], [201, 200]);
    assert.equal(again.json.id, first.json.id);
    const clash = await api("POST", "/v1/tasks", { body: { ...body, method: "PUT" } });
    assert.equal(clash.json.error.code, "idempotency_conflict");
  });

  test("schedules after a relative delay", async () => {
    const before = Date.now();
    const { status, json } = await api("POST", "/v1/tasks", {
      body: { url: "https://receiver.example.com/delayed", delay: "1h" },
    });
    assert.equal(status, 201);
    assert.ok(json.run_at_ms >= before + 3_600_000 && json.run_at_ms <= Date.now() + 3_600_000);
    await api("POST", `/v1/tasks/${json.id}/cancel`);
    const both = await api("POST", "/v1/tasks", {
      body: { url: "https://receiver.example.com/delayed", delay: "1h", run_at_ms: before },
    });
    assert.equal(both.json.error.field, "delay");
  });

  test("posts the final result to callback_url, signed", async () => {
    replies.set("/job", [404]);
    const { json } = await api("POST", "/v1/tasks", {
      body: { url: "https://receiver.example.com/job", callback_url: "https://receiver.example.com/callback" },
    });
    assert.equal(json.callback_url, "https://receiver.example.com/callback");
    const failed = await settled("proj_a", json.id, ["failed"]);
    assert.match(failed.callback_task_id, /^task_[0-9a-f]{20}$/);

    const cb = await settled("proj_a", failed.callback_task_id, ["succeeded"]);
    assert.equal(cb.callback_for, json.id);
    const sent = received.find((r) => r.headers["runlater-task-id"] === cb.id);
    assert.equal(sent.method, "POST");
    assert.equal(sent.headers["content-type"], "application/json");
    const ts = sent.headers["runlater-timestamp"];
    const expected = createHmac("sha256", secret).update(`${ts}.${cb.id}.1.${sent.body}`).digest("hex");
    assert.equal(sent.headers["runlater-signature"], `v1=${expected}`);
    const report = JSON.parse(sent.body);
    assert.equal(report.event, "task.finished");
    assert.equal(report.task.id, json.id);
    assert.equal(report.task.status, "failed");
    assert.deepEqual(report.task.attempts.map((a) => a.http_status), [404]);
  });

  test("lists tasks newest first with a cursor", async () => {
    const page = await api("GET", "/v1/tasks?limit=2");
    assert.equal(page.json.tasks.length, 2);
    assert.ok(page.json.next_cursor);
    const next = await api("GET", `/v1/tasks?limit=2&cursor=${page.json.next_cursor}`);
    assert.notEqual(next.json.tasks[0].id, page.json.tasks[0].id);
    const canceled = await api("GET", "/v1/tasks?status=canceled");
    assert.ok(canceled.json.tasks.every((t) => t.status === "canceled"));
  });

  test("keeps projects apart", async () => {
    const mine = await api("GET", "/v1/tasks");
    const id = mine.json.tasks[0].id;
    await api("POST", "/v1/projects", { project: "proj_b" });
    const theirs = await api("GET", `/v1/tasks/${id}`, { project: "proj_b" });
    assert.equal(theirs.status, 404);
    const list = await api("GET", "/v1/tasks", { project: "proj_b" });
    assert.deepEqual(list.json.tasks, []);
  });
});
