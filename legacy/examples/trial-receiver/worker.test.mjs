// Ephemeral local workerd/SQLite fixtures only. No external network, real credentials or deployment.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createHmac, createPublicKey, generateKeyPairSync, randomBytes, sign, verify} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import Ajv from 'ajv';
import {API, PULL, ACK, sha, manifestBytes, manifest, installation} from './protocol.mjs';
const here = fileURLToPath(new URL('./', import.meta.url));
function fixture({ttl = 300000} = {}) {
  const keys = generateKeyPairSync('ed25519'), now = Date.now();
  const m = {version: 1, release_id: 'receiver_fixture', project_id: 'p_' + 'a'.repeat(60),
    url: 'https://receiver.account.workers.dev/callback', receiver_public_key: keys.publicKey.export({format: 'der', type: 'spki'}).subarray(12).toString('hex'),
    pairing_id: randomBytes(32).toString('hex'), issued_at_ms: now, expires_at_ms: now + ttl};
  m.signature = sign(null, Buffer.from(manifestBytes(m)), keys.privateKey).toString('hex');
  const key = randomBytes(32).toString('hex'), end = Math.floor(now / 1000) + 3600;
  const policy = {version: 'v2', tenant: m.project_id, policy_id: 'public_callbacks', revision: 1,
    keys: {beta_v1: {key_id: 'beta_v1', introduced_revision: 1, active_from_sec: 0,
      sign_until_sec: end, verify_until_sec: end + 300, revoked_at_sec: null}}, rotations: {}};
  const response = 'RunLater destination proof v1\n' + JSON.stringify([1, m.project_id, 'receiver', 1, m.url, 1, m.expires_at_ms, randomBytes(32).toString('hex')]);
  const proof = {id: sha(response), response, expires_at_ms: m.expires_at_ms};
  const mh = sha(JSON.stringify(m));
  const p = {version: 1, project_id: m.project_id, pairing_id: m.pairing_id, manifest_sha256: mh, installation_id: mh,
    expires_at_ms: m.expires_at_ms, callback_url: m.url, callback_policy: policy, callback_keys: {beta_v1: key},
    destination_proof: proof, endpoint_id: 'receiver', endpoint_version: 1};
  return {m, keys, p, key, response: {installation: p, installation_sha256: sha(JSON.stringify(p))},
    env: {RECEIVER_ENABLED: 'pairing-configured', RECEIVER_MANIFEST: JSON.stringify(m),
      RECEIVER_SETUP_PRIVATE_KEY: keys.privateKey.export({format: 'pem', type: 'pkcs8'})},
    probe: 'RunLater receiver probe v1\n' + JSON.stringify([1, m.release_id, m.project_id, m.url, m.receiver_public_key,
      m.pairing_id, mh, randomBytes(32).toString('hex'), m.expires_at_ms]),
    proofRequest: 'RunLater destination verification v1\n' + JSON.stringify([m.project_id, 'receiver', 1, proof.id, m.expires_at_ms]),
    callback(body = '{"synthetic":true}', operation = 'one', task = 'task_0000000000000001') {
      const ts = Math.floor(Date.now() / 1000), taskId = m.project_id + ':' + task;
      return {'Content-Type': 'application/json', 'RunLater-Signature-Version': 'v2', 'RunLater-Signing-Policy': policy.policy_id,
        'RunLater-Key-Id': 'beta_v1', 'RunLater-Timestamp': String(ts), 'RunLater-Task-Id': taskId, 'RunLater-Operation-Key': operation,
        'RunLater-Signature': createHmac('sha256', Buffer.from(key, 'hex')).update(`runlater.v2.${policy.policy_id}.beta_v1.${ts}.${taskId}.${operation}.`).update(body).digest('hex')};
    }};
}
let script;
async function bundled() {
  if (script) return script;
  script = (await build({stdin: {resolveDir: here, contents: `
    import worker,{TrialReceiverInbox} from './worker.mjs';
    export default worker;
    export class TestInbox extends TrialReceiverInbox {
      async testCycle(force=true){if(force)this.sql.exec('UPDATE receiver_setup SET next_at=0 WHERE id=1');await this.alarm();return this.testSnapshot();}
      testCorrupt(){this.sql.exec("UPDATE receiver_setup SET installation='{}' WHERE id=1");}
      async testSnapshot(){return {setup:this.sql.exec('SELECT * FROM receiver_setup').one(),operations:this.sql.exec('SELECT operation_key,body_sha256,first_task FROM receiver_operations').toArray(),effects:this.sql.exec('SELECT * FROM receiver_effect').one(),alarm:await this.ctx.storage.getAlarm()};}
    }`}, bundle: true, platform: 'neutral', mainFields: ['module', 'main'], format: 'esm',
    external: ['cloudflare:*', 'node:*'], write: false})).outputFiles[0].text;
  return script;
}
async function harness(f = fixture(), options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-trial-receiver-'));
  let mf, outbound = [], behavior = options.behavior, calls = 0;
  async function start(extra = {}) {
    mf = new Miniflare(convertV4MiniflareOptions({script: await bundled(), modules: true,
      resourcePersistencePath: root, compatibilityDate: '2026-10-28', compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'],
      bindings: {...f.env, ...extra}, durableObjects: {INBOX: {className: 'TestInbox', useSQLite: true}},
      outboundService: async request => {
        const body = await request.text(), h = request.headers, url = new URL(request.url);
        assert.equal(url.origin, API); assert.ok([PULL, ACK].includes(url.pathname)); assert.equal(url.search, '');
        assert.equal(request.method, 'POST'); assert.equal(h.get('Authorization'), null); assert.equal(h.get('RunLater-Trial-Capability'), null);
        assert.equal(h.get('RunLater-Project-Id'), f.m.project_id); assert.equal(h.get('RunLater-Public-Key'), f.m.receiver_public_key);
        assert.equal(h.get('RunLater-Pairing-Id'), f.m.pairing_id); assert.match(h.get('RunLater-Nonce'), /^[a-f0-9]{64}$/);
        const issued = Number(h.get('RunLater-Issued-At')), expires = Number(h.get('RunLater-Expires-At'));
        assert.ok(expires <= f.m.expires_at_ms && expires > issued && expires - issued <= 60000);
        const wire = 'RunLater receiver setup request v1\n' + JSON.stringify([1, API, f.m.release_id, f.m.project_id, f.m.pairing_id,
          sha(JSON.stringify(f.m)), 'POST', url.pathname, sha(body), issued, expires, h.get('RunLater-Nonce')]);
        assert.ok(verify(null, Buffer.from(wire), f.keys.publicKey, Buffer.from(h.get('RunLater-Request-Signature'), 'hex')));
        outbound.push({path: url.pathname, body, nonce: h.get('RunLater-Nonce')});
        if (behavior) {const response = await behavior(request, body, url.pathname); if (response) return response;}
        if (url.pathname === PULL) {assert.equal(body, '{}'); return Response.json(f.response);}
        assert.deepEqual(JSON.parse(body), {installation_sha256: f.response.installation_sha256});
        const r = await mf.dispatchFetch(f.m.url, {method: 'POST', headers: {'Content-Type': 'text/plain; charset=utf-8'}, body: f.proofRequest});
        assert.equal(r.status, 200); assert.equal(await r.text(), f.p.destination_proof.response);
        return Response.json({state: 'ready', project_id: f.m.project_id, receiver_ready: true, endpoint_id: 'receiver'});
      }}));
  }
  await start();
  return {f, outbound, setBehavior(value) {behavior = value;},
    async fetch(address = f.m.url, init = {}) {
      assert.ok(++calls <= 200); const r = await mf.dispatchFetch(address, init); const text = await r.text();
      for (const secret of [f.key, f.env.RECEIVER_SETUP_PRIVATE_KEY, f.response.installation_sha256]) assert.ok(!text.includes(secret));
      return {r, text};
    },
    async stub() {const ns = await mf.getDurableObjectNamespace('INBOX'); return ns.getByName('bound-receiver-v1');},
    async restart(extra = {}) {await mf.dispose(); await start(extra);},
    async close() {await mf.dispose(); fs.rmSync(root, {recursive: true});}};
}
const metadata = f => new URL('/.well-known/runlater-receiver', f.m.url).href;
const post = (body, type = 'text/plain; charset=utf-8') => ({method: 'POST', headers: {'Content-Type': type}, body});
test('strict public manifest and private payload context; no arbitrary signing context', () => {
  const f = fixture(); assert.deepEqual(manifest(f.m), f.m); assert.deepEqual(installation(f.response, f.m, Date.now()), f.p);
  for (const change of [{project_id: 'other'}, {url: f.m.url + '?x=1'}, {url: 'https://evil.example/callback'},
    {release_id: 1}, {version: 2}, {signature: '0'.repeat(128)}, {expires_at_ms: f.m.issued_at_ms + 300001}, {extra: true}]) {
    assert.throws(() => manifest({...f.m, ...change}));
  }
  for (const change of [{project_id: 'other'}, {callback_url: 'https://other.account.workers.dev/callback'},
    {installation_id: 'b'.repeat(64)}, {endpoint_id: 'other'}, {expires_at_ms: f.m.expires_at_ms + 1}]) {
    const p = {...f.p, ...change}; assert.throws(() => installation({installation: p, installation_sha256: sha(JSON.stringify(p))}, f.m, Date.now()));
  }
  assert.throws(() => installation(f.response, f.m, f.m.expires_at_ms));
});
test('disabled config has no secrets, routes, observability or automatic deployment', () => {
  const c = JSON.parse(fs.readFileSync(path.join(here, 'wrangler.example.jsonc')));
  const schema = JSON.parse(fs.readFileSync(path.join(here, '../../node_modules/wrangler/config-schema.json')));
  const validate = new Ajv({strict: false}).compile(schema); assert.ok(validate(c), JSON.stringify(validate.errors));
  assert.equal(c.workers_dev, false); assert.equal(c.preview_urls, false); assert.equal(c.routes, undefined);
  assert.equal(c.observability.enabled, false); assert.deepEqual(c.vars, {RECEIVER_ENABLED: 'disabled'});
});
test('local Worker: fixed-context public proof; alarm pull/install/ack; reentrant private proof and durable callback inbox', async () => {
  const h = await harness(), f = h.f;
  try {
    let q = await h.fetch(metadata(f)); assert.equal(q.r.status, 200); assert.deepEqual(JSON.parse(q.text), f.m);
    const stub = await h.stub(), initial = await stub.testSnapshot(); assert.equal(initial.setup.cycles, 0);
    assert.ok(initial.alarm > Date.now() + 25000); assert.equal(h.outbound.length, 0);
    q = await h.fetch(f.m.url, post(f.probe)); assert.equal(q.r.status, 200);
    assert.ok(verify(null, Buffer.from(f.probe), f.keys.publicKey, Buffer.from(JSON.parse(q.text).signature, 'hex')));
    assert.equal((await h.fetch(f.m.url, post(f.probe.replace(f.m.project_id, 'p_' + 'b'.repeat(60))))).r.status, 403);
    assert.equal((await h.fetch(f.m.url, post('RunLater receiver setup request v1\n[]'))).r.status, 503);
    assert.equal((await h.fetch(f.m.url + '?x=1', post(f.probe))).r.status, 404);
    assert.equal((await h.fetch(f.m.url, post('x'.repeat(2049)))).r.status, 413);
    assert.equal((await h.fetch(f.m.url, post('{}', 'text/plain'))).r.status, 415);
    for (let i = 0; i < 3; i++) await h.fetch(metadata(f));
    assert.equal((await stub.testSnapshot()).setup.cycles, 0); assert.equal(h.outbound.length, 0);
    let s = await stub.testCycle(); assert.equal(s.setup.ready, 1); assert.equal(s.alarm, null);
    assert.deepEqual(h.outbound.map(x => x.path), [PULL, ACK]); assert.notEqual(h.outbound[0].nonce, h.outbound[1].nonce);
    const body = '{"synthetic":true}', init = {method: 'POST', headers: f.callback(body), body};
    assert.equal((await h.fetch(f.m.url, init)).r.status, 204);
    assert.equal((await h.fetch(f.m.url, init)).r.status, 204);
    assert.equal((await h.fetch(f.m.url, {method: 'POST', headers: f.callback('changed'), body: 'changed'})).r.status, 409);
    assert.equal((await h.fetch(f.m.url, {method: 'POST', headers: f.callback(body), body: 'forged'})).r.status, 403);
    s = await stub.testSnapshot(); assert.equal(s.effects.accepted_operations, 1); assert.equal(s.operations.length, 1);
    await h.restart(); assert.equal((await h.fetch(f.m.url, init)).r.status, 204);
    assert.equal((await (await h.stub()).testSnapshot()).effects.accepted_operations, 1);
    for (let i = 1; i < 128; i++) assert.equal((await h.fetch(f.m.url, {method: 'POST', headers: f.callback(body, 'op' + i), body})).r.status, 204);
    assert.equal((await h.fetch(f.m.url, {method: 'POST', headers: f.callback(body, 'overflow'), body})).r.status, 429);
    assert.equal((await (await h.stub()).testSnapshot()).effects.accepted_operations, 128);
    assert.equal(h.outbound.length, 2);
  } finally {await h.close();}
});
test('lost acknowledgement, restart and exact retry never pull a replacement installation', async () => {
  let failed = false; const h = await harness(undefined, {behavior: async (_r, _b, p) => {
    if (p === ACK && !failed) {failed = true; throw Error('local lost response');}
  }});
  try {
    await h.fetch(metadata(h.f)); let s = await (await h.stub()).testCycle();
    assert.equal(s.setup.ready, 0); assert.equal(s.setup.digest, h.f.response.installation_sha256); assert.ok(s.alarm > Date.now());
    const count = h.outbound.length; await (await h.stub()).testCycle(false); assert.equal(h.outbound.length, count, 'duplicate alarm bypassed cooldown');
    await h.restart(); s = await (await h.stub()).testCycle(); assert.equal(s.setup.ready, 1);
    assert.deepEqual(h.outbound.map(x => x.path), [PULL, ACK, ACK]);
  } finally {await h.close();}
});
test('redirects/malformed installation fail closed; public calls cannot reset finite alarm budget', async () => {
  const h = await harness(undefined, {behavior: async () => new Response(null, {status: 302, headers: {Location: 'https://evil.example/steal'}})});
  try {
    await h.fetch(metadata(h.f)); const stub = await h.stub();
    for (let i = 0; i < 12; i++) {await stub.testCycle(); await h.fetch(metadata(h.f));}
    const s = await stub.testSnapshot(); assert.equal(s.setup.cycles, 10); assert.equal(h.outbound.length, 10);
    assert.equal(s.setup.installation, null); assert.equal(s.setup.ready, 0);
  } finally {await h.close();}
});
test('installed HMAC callbacks survive pairing expiry; no public key/material installation route', async () => {
  const h = await harness(fixture({ttl: 1500}));
  try {
    await h.fetch(metadata(h.f)); await (await h.stub()).testCycle();
    await new Promise(resolve => setTimeout(resolve, Math.max(0, h.f.m.expires_at_ms - Date.now() + 10)));
    const body = '{"after_setup_expiry":true}';
    assert.equal((await h.fetch(h.f.m.url, {method: 'POST', headers: h.f.callback(body), body})).r.status, 204);
    assert.equal((await h.fetch(h.f.m.url, post(h.f.probe))).r.status, 403);
    assert.equal((await h.fetch(h.f.m.url, post(h.f.proofRequest))).r.status, 403);
    assert.equal((await h.fetch(new URL('/install', h.f.m.url).href, post(JSON.stringify(h.f.response), 'application/json'))).r.status, 404);
  } finally {await h.close();}
});
test('malformed/oversized/incorrect-context private responses never install; nonsecret HTTP errors use later bounded slot', async () => {
  const h = await harness();
  try {
    await h.fetch(metadata(h.f)); const stub = await h.stub();
    const bad = structuredClone(h.f.response); bad.installation.destination_proof.response += 'x';
    bad.installation_sha256 = sha(JSON.stringify(bad.installation));
    const wrong = structuredClone(h.f.response); wrong.installation.callback_keys.beta_v1 = '0'.repeat(64);
    wrong.installation_sha256 = sha(JSON.stringify(wrong.installation));
    const responses = [new Response('secret-server-error', {status: 503}),
      new Response('{}', {headers: {'Content-Type': 'application/json', 'x-wide': 'x'.repeat(4097)}}),
      Response.json(bad), Response.json(wrong),
      new Response('x'.repeat(16385), {headers: {'Content-Type': 'application/json'}}),
      new Response(Buffer.from([0xff]), {headers: {'Content-Type': 'application/json'}}),
      new Response(JSON.stringify(h.f.response), {headers: {'Content-Type': 'text/html'}})];
    for (const response of responses) {
      h.setBehavior(async () => response); const s = await stub.testCycle();
      assert.equal(s.setup.installation, null); assert.equal(s.setup.ready, 0); assert.ok(s.alarm > Date.now());
    }
    h.setBehavior(null); assert.equal((await stub.testCycle()).setup.ready, 1);
    assert.equal(h.outbound.filter(x => x.path === ACK).length, 1);
  } finally {await h.close();}
});
test('private binding identity cannot change or reset SQLite state; disabled receiver makes no outbound calls', async () => {
  const h = await harness();
  try {
    await h.fetch(metadata(h.f)); await (await h.stub()).testCycle();
    const before = h.outbound.length, replacement = fixture();
    await h.restart(replacement.env);
    assert.equal((await h.fetch(metadata(replacement))).r.status, 503);
    assert.equal(h.outbound.length, before);
    await h.restart(); assert.equal((await h.fetch(metadata(h.f))).r.status, 200);
    assert.equal((await (await h.stub()).testSnapshot()).setup.ready, 1);
    await h.restart({RECEIVER_ENABLED: 'disabled'});
    assert.equal((await h.fetch(metadata(h.f))).r.status, 503); assert.equal(h.outbound.length, before);
  } finally {await h.close();}
});
test('duplicate alarm during outstanding pull and restart after lost pull preserve reserved cooldown', async () => {
  let entered, release;
  const seen = new Promise(resolve => {entered = resolve;}), gate = new Promise(resolve => {release = resolve;});
  let first = true;
  const h = await harness(undefined, {behavior: async (_r, _b, p) => {
    if (p === PULL && first) {first = false; entered(); await gate; return new Response(null, {status: 503});}
  }});
  try {
    await h.fetch(metadata(h.f)); const stub = await h.stub();
    const pending = stub.testCycle(); await seen;
    const s = await stub.testCycle(false); assert.equal(s.setup.cycles, 1); assert.equal(h.outbound.length, 1);
    assert.ok(s.alarm > Date.now()); release(); await pending;
    await h.restart(); const after = await (await h.stub()).testCycle(false);
    assert.equal(after.setup.cycles, 1); assert.equal(h.outbound.length, 1, 'restart discarded reserved cooldown');
    assert.equal((await (await h.stub()).testCycle()).setup.ready, 1);
  } finally {release(); await h.close();}
});
test('tampered persisted private installation fails closed instead of signing or accepting callbacks', async () => {
  const h = await harness();
  try {
    await h.fetch(metadata(h.f)); const stub = await h.stub(); await stub.testCycle(); await stub.testCorrupt();
    assert.equal((await h.fetch(metadata(h.f))).r.status, 503);
    const body = '{"synthetic":true}';
    assert.equal((await h.fetch(h.f.m.url, {method: 'POST', headers: h.f.callback(body), body})).r.status, 503);
    await h.restart(); assert.equal((await h.fetch(metadata(h.f))).r.status, 503);
    assert.equal(h.outbound.length, 2);
  } finally {await h.close();}
});
