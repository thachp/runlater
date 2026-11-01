// The agent journey against a deployed (or local) stack: a fresh Agent Auth identity, a
// project, and real deliveries to the staging receiver, checked end to end including the
// signature, lanes, delays, callbacks and crons. Used by `staging.mjs` after each staging deploy, and by agent.e2e.mjs locally.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { AgentAuthClient, MemoryStorage } from "@auth/agent";

const CAPABILITIES = [
  "create_project", "get_project", "schedule_http", "get_task", "list_tasks", "cancel_task", "redrive_task",
  "create_cron", "get_cron", "list_crons", "delete_cron",
];

class JourneyError extends Error {}
const check = (ok, message) => {
  if (!ok) throw new JourneyError(message);
};

/**
 * @param {object} c
 * @param {string} c.gatewayUrl   where agents connect, e.g. https://gateway-staging.runlater.io
 * @param {string} c.receiverUrl  public https base the API delivers to
 * @param {string} [c.receiverReadUrl] base for reading recorded deliveries (defaults to receiverUrl)
 * @param {string} c.receiverToken bearer token for reading recorded deliveries
 * @param {(msg: string) => void} [c.log]
 * @param {number} [c.timeoutMs] per wait
 */
export async function runJourney(c) {
  const log = c.log ?? (() => {});
  const timeoutMs = c.timeoutMs ?? 120_000;
  const readUrl = c.receiverReadUrl ?? c.receiverUrl;
  const run = `run-${Date.now().toString(36)}-${randomBytes(4).toString("hex")}`;
  const hook = (name) => `${c.receiverUrl}/hook/${run}/${name}`;

  const until = async (what, probe) => {
    const end = Date.now() + timeoutMs;
    for (;;) {
      const value = await probe();
      if (value) return value;
      if (Date.now() > end) throw new JourneyError(`timed out waiting for ${what}`);
      // Gentle on Better Auth's per-path rate limits.
      await new Promise((r) => setTimeout(r, 2_000));
    }
  };

  log(`run ${run}`);
  const health = await fetch(`${c.gatewayUrl}/health`);
  check(health.ok, `gateway /health returned ${health.status}`);
  check((await health.json()).api === "ok", "gateway cannot reach the API");
  log("health ok");

  const client = new AgentAuthClient({
    storage: new MemoryStorage(),
    directoryUrl: null,
    allowDirectDiscovery: true,
    hostName: `RunLater journey ${run}`,
  });
  const { agentId } = await client.connectAgent({
    provider: c.gatewayUrl,
    mode: "autonomous",
    capabilities: CAPABILITIES,
    name: "journey",
  });
  // Agent Auth allows 60 capability calls a minute; a 429 is refused before it runs, so the
  // journey waits it out and sends the same call again.
  const exec = async (capability, args = {}) => {
    for (let tries = 1; ; tries++) {
      try {
        const r = await client.executeCapability({ agentId, capability, arguments: args });
        return r.data ?? r;
      } catch (e) {
        if (e?.status !== 429 || tries >= 8) throw e;
        await new Promise((r) => setTimeout(r, 10_000));
      }
    }
  };
  log("agent registered");

  const project = await exec("create_project");
  check(/^prj_/.test(project.id) && project.signing_secret, "create_project returned no project");
  log(`project ${project.id}`);

  const deliveries = async () => {
    const res = await fetch(`${readUrl}/runs/${run}`, { headers: { Authorization: `Bearer ${c.receiverToken}` } });
    check(res.ok, `receiver read returned ${res.status}`);
    return (await res.json()).deliveries;
  };
  const settled = (task, statuses) =>
    until(`${task.id} to reach ${statuses.join("/")}`, async () => {
      const t = await exec("get_task", { task_id: task.id });
      return statuses.includes(t.status) && t;
    });
  const verify = (d, body) => {
    const h = d.headers;
    const mac = createHmac("sha256", project.signing_secret)
      .update(`${h["runlater-timestamp"]}.${h["runlater-task-id"]}.${h["runlater-attempt"]}.`)
      .update(body)
      .digest();
    const sent = Buffer.from((h["runlater-signature"] ?? "").replace(/^v1=/, ""), "hex");
    return sent.length === mac.length && timingSafeEqual(sent, mac);
  };

  // 1. A signed delivery, verified at the destination.
  const body = JSON.stringify({ run, hello: "staging" });
  const ok = await exec("schedule_http", {
    url: hook("ok"),
    body,
    headers: { "Content-Type": "application/json", "X-Journey": run },
  });
  const okDone = await settled(ok, ["succeeded", "failed"]);
  check(okDone.status === "succeeded", `ok task ended ${okDone.status}: ${JSON.stringify(okDone.attempts)}`);
  const okDelivery = (await deliveries()).find((d) => d.headers["runlater-task-id"] === ok.id);
  check(okDelivery, "the receiver has no record of the ok delivery");
  check(okDelivery.body === body, "delivered body differs from the scheduled one");
  check(okDelivery.headers["x-journey"] === run, "custom header was not delivered");
  check(verify(okDelivery, body), "RunLater-Signature does not verify with the project's signing_secret");
  log("signed delivery verified");

  // 2. A 503 is retried with backoff and then succeeds. It holds its lane meanwhile: the
  //    task queued behind it is delivered only after the retry.
  const lane = `journey-${run}`;
  const flaky = await exec("schedule_http", { url: hook("flaky"), lane });
  const behind = await exec("schedule_http", { url: hook("behind"), lane });
  check(flaky.lane === lane && behind.lane === lane, "schedule_http did not keep the lane");
  const flakyDone = await settled(flaky, ["succeeded", "failed"]);
  const outcomes = flakyDone.attempts.map((a) => a.outcome);
  check(
    flakyDone.status === "succeeded" && outcomes.join() === "http_503,http_200",
    `flaky task: ${flakyDone.status} ${outcomes.join()}`,
  );
  // Waits on the receiver, not get_task: the gateway rate-limits capability calls.
  const inLane = await until("the task behind in the lane", async () => {
    const ds = (await deliveries()).filter((d) => d.name === "flaky" || d.name === "behind");
    return ds.some((d) => d.name === "behind") && ds;
  });
  const order = inLane.map((d) => d.name);
  check(order.join() === "flaky,flaky,behind", `lane delivered out of order: ${order.join()}`);
  log("retry after 503 succeeded, and its lane waited for it");

  // 3. A 404 fails without a retry.
  const gone = await exec("schedule_http", { url: hook("gone"), method: "DELETE" });
  const goneDone = await settled(gone, ["failed", "succeeded"]);
  check(goneDone.status === "failed" && goneDone.attempt_count === 1, `gone task: ${goneDone.status}, ${goneDone.attempt_count} attempts`);
  log("404 failed once, no retry");

  // 4. A future task can be canceled and is never sent.
  const later = await exec("schedule_http", { url: hook("later"), run_at_ms: Date.now() + 3_600_000 });
  const canceled = await exec("cancel_task", { task_id: later.id });
  check(canceled.status === "canceled", `cancel returned ${canceled.status}`);
  log("future task canceled");

  // 5. Idempotent scheduling and validation errors.
  const key = `journey-${run}`;
  const first = await exec("schedule_http", { url: hook("later"), run_at_ms: Date.now() + 3_600_000, idempotency_key: key });
  const again = await exec("schedule_http", { url: hook("later"), run_at_ms: first.run_at_ms, idempotency_key: key });
  check(first.id === again.id, "idempotent schedule created a second task");
  await exec("cancel_task", { task_id: first.id });
  const invalid = await exec("schedule_http", { url: "http://insecure.example.com/" }).then(
    () => null,
    (e) => e,
  );
  check(invalid?.code === "invalid_request", `insecure URL was not rejected: ${invalid?.code ?? "accepted"}`);
  log("idempotency and validation ok");

  // 6. A relative delay, then the final result posted to callback_url, signed.
  const delayed = await exec("schedule_http", { url: hook("delayed"), delay: "5s", callback_url: hook("callback") });
  check(delayed.run_at_ms - delayed.created_ms === 5_000, `delay 5s gave run_at_ms ${delayed.run_at_ms - delayed.created_ms}ms out`);
  const callback = await until("the callback", async () => (await deliveries()).find((d) => d.name === "callback"));
  const sent = (await deliveries()).find((d) => d.name === "delayed");
  check(sent && sent.received_at >= delayed.run_at_ms, "the delayed task was delivered early");
  check(verify(callback, callback.body), "the callback's RunLater-Signature does not verify");
  const report = JSON.parse(callback.body);
  check(
    report.event === "task.finished" && report.task?.id === delayed.id && report.task.status === "succeeded",
    `unexpected callback body: ${callback.body.slice(0, 200)}`,
  );
  log("delay held, signed callback received");

  // 7. A cron: created, replaced by name, read, and deleted. An hourly cron cannot fire
  //    inside one journey; firing and alerts are covered by the API's tests.
  const cronArgs = { name: "journey", schedule: "0 6 * * *", url: hook("cron"), alert_url: hook("alert") };
  const cron = await exec("create_cron", cronArgs);
  const next = new Date(cron.next_run_ms ?? 0);
  check(
    cron.health === "pending" && next.getUTCHours() === 6 && next.getUTCMinutes() === 0 && cron.next_run_ms > cron.created_ms,
    `create_cron returned ${JSON.stringify(cron)}`,
  );
  const replaced = await exec("create_cron", { ...cronArgs, schedule: "30 7 * * 1" });
  check(replaced.schedule === "30 7 * * 1" && new Date(replaced.next_run_ms).getUTCDay() === 1, "create_cron did not replace by name");
  const tooOften = await exec("create_cron", { ...cronArgs, schedule: "*/10 * * * *" }).then(
    () => null,
    (e) => e,
  );
  check(tooOften?.code === "invalid_request", `a 10-minute cron was not rejected: ${tooOften?.code ?? "accepted"}`);
  const listed = await exec("list_crons");
  check(listed.crons?.map((c) => c.name).join() === "journey", `list_crons returned ${JSON.stringify(listed)}`);
  check((await exec("get_cron", { name: "journey" })).schedule === "30 7 * * 1", "get_cron disagrees with list_crons");
  await exec("delete_cron", { name: "journey" });
  const deleted = await exec("get_cron", { name: "journey" }).then(
    () => null,
    (e) => e,
  );
  check(deleted?.code === "cron_not_found", `deleted cron still readable: ${deleted?.code ?? "found"}`);
  log("cron created, replaced, listed and deleted");

  const all = await deliveries();
  check(!all.some((d) => d.name === "later"), "a canceled task was delivered");
  check(!all.some((d) => d.name === "cron" || d.name === "alert"), "the deleted cron sent something");
  const used = (await exec("get_project")).attempts_used;
  log(`done: ${used} delivery attempts used`);
  return { run, projectId: project.id, attemptsUsed: used };
}
