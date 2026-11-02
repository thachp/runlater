// End-to-end: an agent, using the real Agent Auth SDK and the real MCP bridge, talks to the
// built gateway, which calls the built Rust API, which delivers to a captured destination.
// Both Workers run in one local workerd (Miniflare) with D1, Durable Objects and Queues.
//
// Build first: `npm run build` in apps/api and `npm run check` in apps/gateway.

import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { AgentAuthClient, MemoryStorage } from "@auth/agent";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { runJourney } from "./journey.mjs";

const gatewayDir = fileURLToPath(new URL("..", import.meta.url));
const apiDir = fileURLToPath(new URL("../../api/", import.meta.url));
const receiverDir = fileURLToPath(new URL("../../receiver/", import.meta.url));
const RECEIVER_HOST = "receiver.example.com";
const receiverToken = randomBytes(16).toString("hex");
const CAPABILITIES = [
  "create_project", "get_project", "schedule_http", "get_task", "list_tasks", "cancel_task", "redrive_task",
  "create_cron", "get_cron", "list_crons", "delete_cron", "watch_http",
];

// Gateway → API assertion keys, fresh per run.
const seed = randomBytes(32);
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
  format: "der",
  type: "pkcs8",
});
const publicHex = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");

const freePort = () =>
  new Promise((resolve) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

/** Deliveries the API sent out, and scripted replies per path (default 200). */
const received = [];
const replies = new Map();

let mf;
let origin;
/** The staging receiver fixture, on its own port; the API reaches it as RECEIVER_HOST. */
let receiver;
let receiverOrigin;
before(async () => {
  const receiverPort = await freePort();
  receiverOrigin = `http://127.0.0.1:${receiverPort}`;
  receiver = new Miniflare(
    convertV4MiniflareOptions({
      host: "127.0.0.1",
      port: receiverPort,
      modulesRoot: join(receiverDir, "dist"),
      modules: [{ type: "ESModule", path: join(receiverDir, "dist/index.js") }],
      compatibilityDate: "2026-10-27",
      durableObjects: { INBOX: { className: "Inbox", useSQLite: true } },
      bindings: { RECEIVER_TOKEN: receiverToken },
    }),
  );
  await receiver.ready;

  const port = await freePort();
  origin = `http://127.0.0.1:${port}`;
  mf = new Miniflare(
    convertV4MiniflareOptions({
      host: "127.0.0.1",
      port,
      workers: [
        {
          name: "gateway",
          modules: true,
          modulesRoot: join(gatewayDir, "dist"),
          modules: [{ type: "ESModule", path: join(gatewayDir, "dist/index.js") }],
          compatibilityDate: "2026-10-27",
          compatibilityFlags: ["nodejs_compat"],
          bindings: {
            PUBLIC_URL: origin,
            ASSERTION_PRIVATE_KEY: seed.toString("hex"),
            BETTER_AUTH_SECRET: randomBytes(32).toString("hex"),
          },
          serviceBindings: { API: "api" },
          d1Databases: { DB: "gateway-db" },
          durableObjects: { AUTH_STORE: { className: "AuthStore", useSQLite: true } },
          ratelimits: { REGISTER_RATE: { namespace_id: "1001", simple: { limit: 100, period: 60 } } },
          outboundService: () => {
            throw new Error("the gateway must not reach the internet");
          },
        },
        {
          name: "api",
          modulesRoot: apiDir,
          modules: [
            { type: "ESModule", path: join(apiDir, "build/index.js") },
            { type: "CompiledWasm", path: join(apiDir, "build/index_bg.wasm") },
          ],
          compatibilityDate: "2026-10-27",
          durableObjects: { LEDGER: { className: "TaskLedger", useSQLite: true } },
          queueProducers: { READY: { queueName: "runlater-ready" } },
          queueConsumers: { "runlater-ready": { maxBatchTimeout: 1 } },
          bindings: { GATEWAY_PUBLIC_KEY: publicHex },
          outboundService: async (req) => {
            if (new URL(req.url).hostname === RECEIVER_HOST) {
              const body = ["GET", "HEAD"].includes(req.method) ? undefined : await req.arrayBuffer();
              const res = await receiver.dispatchFetch(req.url, { method: req.method, headers: req.headers, body });
              return new Response(await res.arrayBuffer(), { status: res.status, headers: res.headers });
            }
            received.push({ url: req.url, headers: Object.fromEntries(req.headers), body: await req.text() });
            const script = replies.get(new URL(req.url).pathname) ?? [];
            const status = script.length ? script.shift() : 200;
            return new Response("", { status });
          },
        },
      ],
    }),
  );
  await mf.ready;
  const db = await mf.getD1Database("DB", "gateway");
  for (const file of (await readdir(join(gatewayDir, "migrations"))).sort()) {
    const sql = await readFile(join(gatewayDir, "migrations", file), "utf8");
    await db.batch(splitSql(sql).map((s) => db.prepare(s)));
  }
});
after(async () => {
  await mf?.dispose();
  await receiver?.dispose();
});

/** A migration file's statements, without comments. */
function splitSql(sql) {
  return sql.split(";").map((s) => s.replace(/^\s*--.*$/gm, "").trim()).filter(Boolean);
}

/** Every request the SDK made, so tests can replay one. */
const sent = [];
/** When set, the next execute request is sent twice at once; statuses land here. */
let duplicateNext = null;
const transport = async (url, init) => {
  if (duplicateNext && String(url).endsWith("/capability/execute")) {
    const record = duplicateNext;
    duplicateNext = null;
    const [a, b] = await Promise.all([fetch(url, init), fetch(url, init)]);
    record.statuses = [a.status, b.status].sort();
    return a.ok ? a : b;
  }
  const response = await fetch(url, init);
  sent.push({ url: String(url), init, response: response.clone() });
  return response;
};

function sdk() {
  return new AgentAuthClient({
    storage: new MemoryStorage(),
    fetch: transport,
    directoryUrl: null,
    allowDirectDiscovery: true,
    hostName: "RunLater e2e",
  });
}

async function until(check, timeoutMs = 20_000) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > end) throw new Error("timed out waiting");
    await new Promise((r) => setTimeout(r, 250));
  }
}

const data = (r) => r.data ?? r;

describe("agent journey through the gateway", () => {
  let client;
  let agentId;
  let project;

  test("health reaches the API through the binding", async () => {
    const res = await fetch(`${origin}/health`);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).api, "ok");
  });

  test("discovery advertises only the served endpoints", async () => {
    const config = await (await fetch(`${origin}/.well-known/agent-configuration`)).json();
    assert.equal(config.provider_name, "RunLater");
    const paths = Object.values(config.endpoints).map((u) => new URL(u).pathname);
    assert.ok(paths.includes("/api/auth/capability/execute"));
    assert.ok(paths.includes("/api/auth/agent/request-capability"));
    assert.ok(paths.every((p) => !p.includes("/agent/list") && !p.includes("/host/create")));
  });

  test("an autonomous agent registers with no human account", async () => {
    client = sdk();
    const connection = await client.connectAgent({
      provider: origin,
      mode: "autonomous",
      capabilities: CAPABILITIES,
      name: "e2e agent",
    });
    agentId = connection.agentId;
    assert.ok(agentId);
  });

  test("capabilities need a project first", async () => {
    await assert.rejects(client.executeCapability({ agentId, capability: "get_project", arguments: {} }), {
      code: "project_not_found",
      status: 404,
    });
  });

  test("create_project is idempotent", async () => {
    project = data(await client.executeCapability({ agentId, capability: "create_project", arguments: {} }));
    assert.match(project.id, /^prj_[0-9a-f]{24}$/);
    assert.equal(project.attempts_remaining, 100);
    const again = data(await client.executeCapability({ agentId, capability: "create_project", arguments: {} }));
    assert.equal(again.id, project.id);
    assert.equal(again.signing_secret, project.signing_secret);
  });

  test("schedule_http delivers a signed request", async () => {
    const body = JSON.stringify({ order: 42 });
    const task = data(
      await client.executeCapability({
        agentId,
        capability: "schedule_http",
        arguments: { url: "https://dest.example.com/hook", body, headers: { "Content-Type": "application/json" } },
      }),
    );
    assert.equal(task.status, "scheduled");
    const done = await until(async () => {
      const t = data(await client.executeCapability({ agentId, capability: "get_task", arguments: { task_id: task.id } }));
      return t.status === "succeeded" && t;
    });
    assert.equal(done.attempts[0].http_status, 200);

    const delivery = received.find((r) => r.headers["runlater-task-id"] === task.id);
    const ts = delivery.headers["runlater-timestamp"];
    const mac = createHmac("sha256", project.signing_secret).update(`${ts}.${task.id}.1.${body}`).digest("hex");
    assert.equal(delivery.headers["runlater-signature"], `v1=${mac}`);
    assert.equal(delivery.body, body);
  });

  test("API validation errors reach the agent with the field", async () => {
    await assert.rejects(
      client.executeCapability({ agentId, capability: "schedule_http", arguments: { url: "http://insecure.example.com/" } }),
      { code: "invalid_request", status: 400, message: "URL must use https://" },
    );
    // The SDK keeps code and status; the response body also names the field.
    const last = sent.findLast((s) => s.url.endsWith("/capability/execute"));
    assert.equal((await last.response.json()).field, "url");
  });

  test("crons can be created, read, listed and deleted", async () => {
    const run = (capability, args) => client.executeCapability({ agentId, capability, arguments: args }).then((r) => r.data);
    const cron = await run("create_cron", {
      name: "daily-backup",
      schedule: "0 6 * * *",
      url: "https://dest.example.com/backup",
      alert_url: "https://dest.example.com/alerts",
    });
    assert.equal(cron.health, "pending");
    assert.ok(cron.next_run_ms > Date.now());
    assert.equal(new Date(cron.next_run_ms).getUTCHours(), 6);
    assert.equal((await run("get_cron", { name: "daily-backup" })).schedule, "0 6 * * *");
    assert.deepEqual((await run("list_crons", {})).crons.map((c) => c.name), ["daily-backup"]);
    await assert.rejects(
      client.executeCapability({ agentId, capability: "create_cron", arguments: { name: "x", schedule: "* * * * *", url: "https://dest.example.com/" } }),
      { code: "invalid_request", status: 400 },
    );
    await assert.rejects(
      client.executeCapability({ agentId, capability: "get_cron", arguments: { name: ".." } }),
      { code: "invalid_request", status: 400 },
    );
    assert.equal((await run("delete_cron", { name: "daily-backup" })).name, "daily-backup");
    await assert.rejects(
      client.executeCapability({ agentId, capability: "get_cron", arguments: { name: "daily-backup" } }),
      { code: "cron_not_found", status: 404 },
    );
  });

  test("watch_http polls until the condition matches", async () => {
    const run = (capability, args) => client.executeCapability({ agentId, capability, arguments: args }).then((r) => r.data);
    const watch = await run("watch_http", {
      url: "https://dest.example.com/job-status",
      every: "5m",
      until: { status: [200] },
      deadline: "1h",
    });
    assert.equal(watch.watch.every_ms, 300_000);
    const done = await until(async () => {
      const t = await run("get_task", { task_id: watch.id });
      return t.status === "succeeded" && t;
    });
    assert.equal(done.watch.reason, "matched");
    assert.equal(done.watch.matched, 200);
    await assert.rejects(
      client.executeCapability({ agentId, capability: "watch_http", arguments: { url: "https://dest.example.com/", every: "1m", until: { status: [200] }, deadline: "1h" } }),
      { code: "invalid_request", status: 400 },
    );
  });

  test("task ids cannot be used to escape the API path", async () => {
    await assert.rejects(
      client.executeCapability({ agentId, capability: "get_task", arguments: { task_id: "../projects/self" } }),
      { code: "invalid_request", status: 400 },
    );
  });

  test("a captured execute request cannot be replayed", async () => {
    await client.executeCapability({ agentId, capability: "get_project", arguments: {} });
    const last = sent.findLast((s) => s.url.endsWith("/capability/execute"));
    const replay = await fetch(last.url, last.init);
    assert.equal(replay.status, 401);
  });

  // Local workerd runs both copies in one isolate, so this checks the outcome but does not
  // reproduce the cross-isolate race; test/health.test.ts covers the gateway's atomic claim.
  test("two copies of one request sent at once execute only once", async () => {
    const record = {};
    duplicateNext = record;
    await client.executeCapability({
      agentId,
      capability: "schedule_http",
      arguments: { url: "https://dest.example.com/once", run_at_ms: Date.now() + 3_600_000 },
    });
    assert.deepEqual(record.statuses, [200, 401]);
    const tasks = data(await client.executeCapability({ agentId, capability: "list_tasks", arguments: {} }));
    assert.equal(tasks.tasks.filter((t) => t.url === "https://dest.example.com/once").length, 1);
  });

  test("agents of a revoked host are refused even if not yet revoked themselves", async () => {
    const other = sdk();
    const conn = await other.connectAgent({ provider: origin, mode: "autonomous", capabilities: CAPABILITIES, name: "doomed" });
    await other.executeCapability({ agentId: conn.agentId, capability: "create_project", arguments: {} });
    // Simulate a host revocation that stopped before reaching its agents.
    const db = await mf.getD1Database("DB", "gateway");
    await db.prepare('UPDATE "agentHost" SET status = ? WHERE id = ?').bind("revoked", conn.hostId).run();
    await assert.rejects(other.executeCapability({ agentId: conn.agentId, capability: "get_project", arguments: {} }), {
      code: "host_revoked",
      status: 403,
    });
  });

  test("a host registered before a capability existed can still be granted it", async () => {
    // Agent Auth saves a host's capabilities when it activates and never widens them, so
    // hosts from before the cron tools were added hold only the original seven.
    const original = CAPABILITIES.slice(0, 7);
    const old = sdk();
    const conn = await old.connectAgent({ provider: origin, mode: "autonomous", capabilities: original, name: "old host" });
    const db = await mf.getD1Database("DB", "gateway");
    await db.prepare('UPDATE "agentHost" SET "defaultCapabilities" = ? WHERE id = ?').bind(JSON.stringify(original), conn.hostId).run();
    await old.executeCapability({ agentId: conn.agentId, capability: "create_project", arguments: {} });
    const listCrons = () => old.executeCapability({ agentId: conn.agentId, capability: "list_crons", arguments: {} });
    const request = () => old.requestCapability({ agentId: conn.agentId, capabilities: ["list_crons"] });

    await request();
    await assert.rejects(listCrons(), { code: "capability_not_granted" });

    for (const file of (await readdir(join(gatewayDir, "migrations"))).filter((f) => /^000[3-9]_/.test(f)).sort()) {
      await db.batch(splitSql(await readFile(join(gatewayDir, "migrations", file), "utf8")).map((q) => db.prepare(q)));
    }
    await request();
    assert.deepEqual(data(await listCrons()).crons, []);
  });

  test("another agent on the same host shares the project", async () => {
    const second = await client.connectAgent({ provider: origin, mode: "autonomous", capabilities: CAPABILITIES, name: "e2e agent 2" });
    const p = data(await client.executeCapability({ agentId: second.agentId, capability: "get_project", arguments: {} }));
    assert.equal(p.id, project.id);
  });

  test("another host cannot see this project's tasks", async () => {
    const tasks = data(await client.executeCapability({ agentId, capability: "list_tasks", arguments: {} }));
    const taskId = tasks.tasks[0].id;
    const other = sdk();
    const { agentId: otherAgent } = await other.connectAgent({ provider: origin, mode: "autonomous", capabilities: CAPABILITIES, name: "stranger" });
    await other.executeCapability({ agentId: otherAgent, capability: "create_project", arguments: {} });
    await assert.rejects(
      other.executeCapability({ agentId: otherAgent, capability: "get_task", arguments: { task_id: taskId } }),
      { code: "task_not_found", status: 404 },
    );
  });
});

describe("MCP bridge (@auth/agent-cli mcp)", () => {
  let mcp;
  let storageDir;

  before(async () => {
    storageDir = await mkdtemp(join(tmpdir(), "runlater-mcp-"));
    mcp = new Client({ name: "runlater-e2e", version: "1.0.0" });
    await mcp.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [
          fileURLToPath(import.meta.resolve("@auth/agent-cli")).replace(/index\.js$/, "index.js"),
          "mcp",
          "--url",
          origin,
          "--storage-dir",
          storageDir,
          "--no-browser",
        ],
        env: { ...process.env, AGENT_AUTH_ENCRYPTION_KEY: randomBytes(32).toString("hex") },
        stderr: "pipe",
      }),
    );
  });
  after(async () => {
    await mcp?.close();
    await rm(storageDir, { recursive: true, force: true });
  });

  const call = async (name, args) => {
    const res = await mcp.callTool({ name, arguments: args });
    const text = res.content.map((c) => c.text).join("");
    assert.ok(!res.isError, `${name} failed: ${text}`);
    return JSON.parse(text);
  };

  test("exposes the Agent Auth tools", async () => {
    const { tools } = await mcp.listTools();
    const names = tools.map((t) => t.name);
    for (const n of ["connect_agent", "list_capabilities", "execute_capability"]) assert.ok(names.includes(n), n);
  });

  test("an MCP client can connect, create a project and schedule a task", async () => {
    const connected = await call("connect_agent", {
      provider: origin,
      capabilities: CAPABILITIES,
      mode: "autonomous",
      name: "mcp agent",
    });
    const agentId = connected.agentId ?? connected.agent_id;
    assert.ok(agentId, JSON.stringify(connected));

    const caps = await call("list_capabilities", { provider: origin });
    const listed = JSON.stringify(caps);
    for (const c of CAPABILITIES) assert.ok(listed.includes(c), c);

    const exec = (capability, args) => call("execute_capability", { agent_id: agentId, capability, arguments: args });
    const created = data(await exec("create_project", {}));
    assert.match(created.id, /^prj_/);
    const task = data(await exec("schedule_http", { url: "https://dest.example.com/from-mcp" }));
    const done = await until(async () => {
      const t = data(await exec("get_task", { task_id: task.id }));
      return t.status === "succeeded" && t;
    });
    assert.equal(done.attempt_count, 1);
  });
});

describe("staging journey, run against the local stack", () => {
  test("passes end to end through the receiver fixture", async () => {
    const result = await runJourney({
      gatewayUrl: origin,
      receiverUrl: `https://${RECEIVER_HOST}`,
      receiverReadUrl: receiverOrigin,
      receiverToken,
      timeoutMs: 60_000,
    });
    // ok + flaky (2) + gone + behind + delayed + its callback + one poll = 8 attempts;
    // canceled tasks and the deleted cron use none.
    assert.equal(result.attemptsUsed, 8);
  });
});
