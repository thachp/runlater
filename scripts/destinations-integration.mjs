// Actual isolated Rust/Wasm + local SQLite + Fetch. No live network, API or authentication claim.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-destinations-'));
fs.writeFileSync(path.join(root, '.owner'), 'destination-fixture');
const url = 'https://receiver-alpha.runlater.io/callback';
let clock = 10;
let hosts = ['receiver-alpha.runlater.io'], mf, requests = 0, outbound = 0;
const proofs = new Map(), counts = new Map(), gates = new Map();
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function gate(id) {
  let enter, release;
  const entered = new Promise(r => { enter = r; }), held = new Promise(r => { release = r; });
  gates.set(id, {enter, held, release});
  return {entered, release};
}
async function receiver(req) {
  assert.ok(++outbound <= 32, 'bounded outbound fixture budget');
  assert.equal(req.method, 'POST'); // outbound service Request reconstruction does not preserve redirect mode; redirect target/count assertions below prove rejection.
  assert.equal(new URL(req.url).host, 'receiver-alpha.runlater.io');
  assert.equal(req.headers.get('authorization'), null);
  assert.equal(req.headers.get('content-type'), 'text/plain; charset=utf-8');
  const body = await req.text();
  assert.ok(body.startsWith('RunLater destination verification v1\n'));
  const [tenant, id, version, challenge] = JSON.parse(body.split('\n')[1]);
  const p = proofs.get(`${tenant}/${id}/${version}`);
  assert.ok(p); assert.equal(p.id, challenge); assert.notEqual(body, p.response);
  const nonce = JSON.parse(p.response.split('\n')[1]).at(-1);
  assert.equal(body.includes(nonce), false, 'echo endpoint must not see secret proof nonce');
  counts.set(id, (counts.get(id) ?? 0) + 1);
  if (gates.has(id)) { const g = gates.get(id); g.enter(); await g.held; }
  return new Response(JSON.stringify({id, expected: p.response, request: body}));
}
// Stream directly from workerd. Node service interceptors buffer bodies and cannot
// establish response-stream/chunk behavior of the compiled Rust client.
const localReceiver = `export default {async fetch(req, env) {
  const {id,expected,request} = await (await env.CONTROL.fetch(req)).json();
  const pause = ms => new Promise(r => setTimeout(r, ms));
  if (id === 'echo') return new Response(request);
  if (id === 'wrong') return new Response('a proof for another tenant');
  if (id === 'redirect') return new Response(null, {status:302,headers:{location:'http://169.254.169.254/latest/meta-data'}});
  if (id === 'headers') return new Response(expected, {headers:{'x-overflow':'x'.repeat(2049)}});
  if (id === 'oversize') return new Response('x'.repeat(1025));
  if (id === 'failure') return new Response(expected, {status:500});
  if (id === 'timeout') { await pause(3400); return new Response(expected); }
  if (id === 'delayed_body') return new Response(new ReadableStream({async start(c){await pause(3400);try{c.enqueue(new TextEncoder().encode(expected));c.close();}catch{}}}));
  if (id === 'stream_error') return new Response(new ReadableStream({async start(c){c.enqueue(new Uint8Array([120]));await pause(50);c.error(new Error('local stream failure'));}}));
  if (id === 'chunks') { let n=0;return new Response(new ReadableStream({async pull(c){await pause(10);if(n++<33)c.enqueue(new Uint8Array([120]));else c.close();}})); }
  return new Response(expected);
}}`;

function start() {
  return new Miniflare(convertV4MiniflareOptions({resourcePersistencePath: root, workers: [{
    name: 'destination-api',
    modules: [{type: 'ESModule', path: 'build/index.js'}, {type: 'CompiledWasm', path: 'build/index_bg.wasm'}],
    compatibilityDate: '2026-10-27',
    bindings: {TEST_APPROVED_HOSTS: JSON.stringify({approved_hosts: hosts})},
    serviceBindings: {TEST_DESTINATION_CONTROL: 'deny-egress'},
    durableObjects: {DESTINATIONS: {className: 'DestinationFixture', useSQLite: true}},
    outboundService: 'proof-receiver',
  }, {name: 'proof-receiver', modules: true, compatibilityDate: '2026-10-27', script: localReceiver, serviceBindings: {CONTROL: receiver}, outboundService: 'deny-egress'}, {name: 'deny-egress', modules: true, compatibilityDate: '2026-10-27', script: 'export default {fetch(){return new Response(null,{status:403})}}'}]}));
}
async function api(action, id = 'success', {tenant = 'alpha', version = 1, at = clock, status = 200, ...extra} = {}) {
  assert.ok(++requests <= 150);
  const r = await mf.dispatchFetch(`https://fixture.invalid/${tenant}`, {method: 'POST', body: JSON.stringify({action, endpoint_id: id, version, at_ms: at, ...extra})});
  const v = await r.json(); assert.equal(r.status, status, `${tenant}/${id}/${action}: ${JSON.stringify(v)}`); return v;
}
async function create(id, options = {}) { return api('create', id, {url, ...options}); }
async function prepare(id, options = {}) {
  const p = await api('prepare', id, options);
  proofs.set(`${options.tenant ?? 'alpha'}/${id}/${options.version ?? 1}`, p);
  return p;
}
function snapshot() {
  const r = spawnSync('python3', ['-c', `import pathlib,sqlite3,json,sys
rows=[]
for p in pathlib.Path(sys.argv[1]).rglob('*.sqlite'):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 if c.execute("SELECT count(*) FROM sqlite_master WHERE name='destination_fixture'").fetchone()[0]:rows.extend(c.execute('SELECT data FROM destination_fixture').fetchall())
print(json.dumps(sorted(rows)))`, root], {encoding: 'utf8'});
  assert.equal(r.status, 0, r.stderr); return r.stdout;
}
try {
  mf = start();
  await create('success'); await create('success', {tenant: 'beta'});
  await api('snapshot', 'success', {task_id: 'task_a', status: 503});
  await prepare('success'); await prepare('success', {tenant: 'beta'});
  const p = proofs.get('alpha/success/1'); assert.equal(snapshot().includes(p.response), false);
  assert.equal(snapshot().includes(JSON.parse(p.response.split('\n')[1]).at(-1)), false);
  await api('verify'); await api('verify', 'success', {tenant: 'beta'});
  await api('verify', 'success', {status: 503}); assert.equal(counts.get('success'), 2, 'verified replay fetched again');
  const accepted = await api('snapshot', 'success', {task_id: 'task_a'});
  const before = snapshot(); await api('get'); await api('dispatch', 'success', {task_id: 'task_a'});
  assert.equal(snapshot(), before, 'query/dispatch policy checks wrote state');
  await api('snapshot', 'success', {tenant: 'beta', task_id: 'task_a'});
  await api('create', 'success', {version: 1, url: url + '/changed', status: 409});
  await create('success', {version: 2, url: url + '/new'}); await prepare('success', {version: 2}); await api('verify', 'success', {version: 2});
  assert.equal((await api('dispatch', 'success', {task_id: 'task_a'})).url, url);
  await api('snapshot', 'success', {version: 2, task_id: 'task_a', status: 409});
  for (const [id, category] of [['echo', null], ['wrong', null], ['redirect', 'redirect_rejected'], ['headers', 'response_headers_too_large'], ['oversize', 'response_body_too_large'], ['failure', null], ['stream_error', 'network_uncertain'], ['chunks', 'response_body_too_large'], ['timeout', 'timeout_uncertain'], ['delayed_body', 'timeout_uncertain']]) {
    await create(id); await prepare(id);
    const failure = await api('verify', id, {status: 503}); assert.equal(failure.category, category);
    assert.equal((await api('get', id)).status, 'pending');
    await api('verify', id, {status: 409}); assert.equal(counts.get(id), 1, `${id} replay fetched twice`);
  }
  await create('expiry'); const expiry = await prepare('expiry');
  await api('verify', 'expiry', {complete_at_ms: expiry.expires_at_ms, status: 410});
  clock = expiry.expires_at_ms;
  await create('race'); await prepare('race'); const race = gate('race');
  const inflight = api('verify', 'race', {complete_at_ms: clock + 2, status: 409}); await race.entered;
  await api('verify', 'race', {status: 409});
  await api('revoke', 'race', {at: clock + 1}); race.release(); await inflight;
  clock += 2;
  assert.equal(counts.get('race'), 1); assert.equal((await api('get', 'race')).status, 'revoked');
  // Prove a stopped local workerd cannot refund the already-durable one-use fetch lease.
  await create('interrupted'); await prepare('interrupted'); const interrupted = gate('interrupted');
  const lost = api('verify', 'interrupted').catch(() => null); await interrupted.entered;
  await mf.dispose(); interrupted.release(); await lost; mf = start();
  await api('verify', 'interrupted', {status: 409}); assert.equal(counts.get('interrupted'), 1);
  const stillPending = snapshot(); assert.ok(stillPending.includes('interrupted'));
  clock += 60001;
  await prepare('interrupted'); await api('verify', 'interrupted');
  await api('revoke', 'success', {at: clock}); await mf.dispose(); mf = start();
  assert.deepEqual(await api('snapshot', 'success', {task_id: 'task_a', at: clock}), accepted);
  await api('dispatch', 'success', {task_id: 'task_a', status: 503});
  await create('success', {version: 3, at: clock, status: 503});
  assert.equal((await api('get', 'success', {tenant: 'beta'})).status, 'verified');
  // Operator allowlist removal also blocks previously accepted verified destinations.
  await mf.dispose(); hosts = []; mf = start();
  await api('dispatch', 'success', {tenant: 'beta', task_id: 'task_a', status: 503});
  await create('closed', {tenant: 'beta', status: 503});
  console.log(`PASS destination Rust/Wasm + SQLite + intercepted Fetch: isolation, non-echo ownership, immutable versions/snapshots, one-use proofs/replay, redirects, header/body/chunk limits, header/body deadline, injected-clock expiry, revoke-during-I/O, actual local process disposal/restart, sticky revocation and closed allowlists. ${requests} calls; ${outbound} intercepted requests. No DNS/TLS/cloud proof; no task admission or live API activation.`);
} finally {
  for (const g of gates.values()) g.release();
  await mf?.dispose();
  assert.equal(fs.readFileSync(path.join(root, '.owner'), 'utf8'), 'destination-fixture');
  fs.rmSync(root, {recursive: true});
}
