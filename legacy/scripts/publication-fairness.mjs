// Compiled local Worker/SQLite/Queue proof. Faults use the private runtime-test
// service binding, not a public request parameter or a deployed failpoint.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-publication-fairness-'));
fs.writeFileSync(path.join(root, '.owner'), 'runlater-publication-fairness-test');
const events = [];
let poison, fail = true, failures = 0, calls = 0, sends = 0, mf, cleaning;
async function cleanup() {
  if (cleaning) return cleaning;
  cleaning = (async () => {
    await mf?.dispose();
    assert.equal(fs.readFileSync(path.join(root, '.owner'), 'utf8'), 'runlater-publication-fairness-test');
    fs.rmSync(root, {recursive: true});
  })();
  return cleaning;
}
for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
  process.once(signal, () => { void cleanup().then(() => process.exit(code), () => process.exit(1)); });
}
async function waitFor(predicate, message) {
  const deadline = Date.now() + 15000;
  while (!predicate()) {
    assert.ok(Date.now() < deadline, message);
    await new Promise(resolve => setTimeout(resolve, 50));
  }
}

try {
  const bindings = JSON.parse(fs.readFileSync(new URL('../wrangler.jsonc', import.meta.url))).vars;
  mf = new Miniflare(convertV4MiniflareOptions({
    resourcePersistencePath: root,
    workers: [{
      name: 'publication-api',
      modules: [{type: 'ESModule', path: 'build/index.js'}, {type: 'CompiledWasm', path: 'build/index_bg.wasm'}],
      compatibilityDate: '2026-10-27',
      bindings: {...bindings, READY_QUEUE_NAME: 'publication-ready', TEST_RUNTIME_ENABLED: 'true'},
      serviceBindings: {TEST_CONTROL: async request => {
        const event = await request.json();
        events.push(event);
        assert.ok(events.length <= 500, 'Private test-event budget exceeded');
        if (event.point === 'before_publish') {
          assert.ok(++sends <= 96, 'Local publication-attempt budget exceeded');
          if (fail && event.metadata.id === poison) {
            failures++;
            return new Response(null, {status: 500});
          }
        }
        return new Response(null, {status: 204});
      }},
      durableObjects: {LEDGER: {className: 'TaskLedger', useSQLite: true}},
      queueProducers: {READY: 'publication-ready'},
      queueConsumers: {'publication-ready': {maxBatchSize: 1, maxBatchTimeout: 0, maxRetries: 1}},
      outboundService: 'deny-egress',
    }, {
      name: 'deny-egress', modules: true, compatibilityDate: '2026-10-27',
      script: 'export default {fetch(){return new Response(null,{status:403})}}',
    }],
  }));
  const base = await mf.ready;
  assert.equal(base.hostname, '127.0.0.1');
  async function api(route, {method = 'GET', body, key, expected = 200} = {}) {
    assert.ok(++calls <= 16, 'Loopback HTTP budget exceeded');
    const response = await fetch(new URL(route, base), {
      method,
      headers: {Authorization: 'Bearer local-alpha', 'Content-Type': 'application/json', ...(key ? {'Idempotency-Key': key} : {})},
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(8000),
    });
    assert.equal(response.status, expected, 'Local API status (body omitted)');
    return response.json();
  }
  // Pause until all three tasks have been committed, avoiding timing-dependent
  // cohort membership. This also exercises the ordinary configure/rearm path.
  const limits = await api('/v1/queue');
  await api('/v1/queue', {method: 'PUT', body: {...limits, paused: true}});
  const ids = [];
  for (let i = 0; i < 3; i++) {
    const task = await api('/v1/tasks', {
      method: 'POST', expected: 201, key: `publication_${i}`,
      body: {destination: 'fixture://success', body: 'local publication proof', operation_key: `publication_${i}`},
    });
    ids.push(task.id);
  }
  poison = ids[0];
  await api('/v1/queue', {method: 'PUT', body: limits});
  const finished = id => events.some(event => event.point === 'after_finish' && event.metadata.id === id);
  await waitFor(() => failures >= 2 && ids.slice(1).every(finished), 'A selectively failing head hid later references');
  const blocked = await api('/v1/tasks/' + poison);
  assert.equal(blocked.status, 'ready');
  assert.equal(blocked.attempts.length, 0, 'Publication errors must not spend attempt permits');
  for (const id of ids.slice(1)) {
    const task = await api('/v1/tasks/' + id);
    assert.equal(task.status, 'succeeded');
    assert.equal(task.attempts.length, 1);
  }
  // The failed row is retained, and the watchdog must replay it after recovery.
  fail = false;
  await waitFor(() => finished(poison), 'Failed reference was not replayed after fault recovery');
  const recovered = await api('/v1/tasks/' + poison);
  assert.equal(recovered.status, 'succeeded');
  assert.equal(recovered.attempts.length, 1);
  assert.equal(events.filter(event => event.point === 'callback_complete').length, 3);
  console.log('PASS compiled local selective publication failure: both tail tasks complete while head fails; head replays after recovery; exactly three fixture attempts');
  console.log(JSON.stringify({tasks: 3, injected_before_send_failures: failures, publication_attempts: sends, http_calls: calls, live_resources: 0, external_callbacks: 0}));
} finally {
  await cleanup();
}
