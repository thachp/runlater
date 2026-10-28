// Local workerd/SQLite only. Ephemeral material; no network, Cloudflare account or deployed receiver.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash, createHmac, randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import Ajv from 'ajv';
import {validatePolicy, verifyV2WithMaterial} from '../rotating-receiver.mjs';

const here = fileURLToPath(new URL('./', import.meta.url));
const project = 'public_example', url = 'https://receiver.account.workers.dev/callback';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const now = () => Math.floor(Date.now() / 1000);
function fixture() {
  const end = now() + 3600, material = {server_one: randomBytes(32).toString('hex')};
  const policy = {version: 'v2', tenant: project, policy_id: 'public_callbacks', revision: 1,
    keys: {server_one: {key_id: 'server_one', introduced_revision: 1, active_from_sec: 0,
      sign_until_sec: end, verify_until_sec: end + 300, revoked_at_sec: null}}, rotations: {}};
  const response = 'RunLater destination proof v1\n' + JSON.stringify([1, project, 'owned', 1, url, 1, Date.now() + 60000, randomBytes(32).toString('hex')]);
  const proof = {id: sha(response), response, expires_at_ms: JSON.parse(response.split('\n')[1])[6]};
  const verifyBody = 'RunLater destination verification v1\n' + JSON.stringify([project, 'owned', 1, proof.id, proof.expires_at_ms]);
  const bindings = () => ({RECEIVER_ENABLED: 'owner-configured', RECEIVER_PROJECT_ID: project,
    RECEIVER_URL: url, CALLBACK_POLICY: JSON.stringify(policy), CALLBACK_KEYS: JSON.stringify(material), OWNERSHIP_PROOF: JSON.stringify(proof)});
  function headers(body, {kid = 'server_one', timestamp = now(), task = project + ':task_0000000000000001', operation = 'same_operation'} = {}) {
    return {'Content-Type': 'application/json', 'RunLater-Signature-Version': 'v2', 'RunLater-Signing-Policy': policy.policy_id,
      'RunLater-Key-Id': kid, 'RunLater-Timestamp': String(timestamp), 'RunLater-Task-Id': task, 'RunLater-Operation-Key': operation,
      'RunLater-Signature': createHmac('sha256', Buffer.from(material[kid], 'hex'))
        .update(`runlater.v2.${policy.policy_id}.${kid}.${timestamp}.${task}.${operation}.`).update(body).digest('hex')};
  }
  return {policy, material, proof, verifyBody, bindings, headers};
}
function snapshot(root) {
  const r = spawnSync('python3', ['-c', `import pathlib,sqlite3,json,sys
out=[]
for p in pathlib.Path(sys.argv[1]).rglob('*.sqlite'):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 if c.execute("SELECT count(*) FROM sqlite_master WHERE name='receiver_effect'").fetchone()[0]:
  out.append({'effects':c.execute('SELECT accepted_operations FROM receiver_effect').fetchone()[0],'operations':c.execute('SELECT operation_key,body_sha256 FROM receiver_operations ORDER BY operation_key').fetchall(),'policy':c.execute('SELECT policy,material_hashes FROM receiver_policy').fetchall()})
print(json.dumps(out,sort_keys=True))`, root], {encoding: 'utf8'});
  assert.equal(r.status, 0, r.stderr); return JSON.parse(r.stdout);
}
test('explicit material verifier has no fixture fallback and retains exact v2 context checks', () => {
  const f = fixture(), body = Buffer.from('{"synthetic":true}'), headers = f.headers(body);
  assert.ok(validatePolicy(f.policy));
  assert.equal(verifyV2WithMaterial(f.policy, headers, body, now(), () => null), false);
  assert.equal(verifyV2WithMaterial(f.policy, headers, body, now(), key => Buffer.from(f.material[key], 'hex')), true);
  assert.equal(verifyV2WithMaterial(f.policy, headers, Buffer.from('changed'), now(), key => Buffer.from(f.material[key], 'hex')), false);
});
test('inactive receiver example config validates without secrets, routes or public activation', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(here, '../../node_modules/wrangler/config-schema.json')));
  const config = JSON.parse(fs.readFileSync(path.join(here, 'wrangler.example.jsonc')));
  const validate = new Ajv({strict: false}).compile(schema);
  assert.ok(validate(config), JSON.stringify(validate.errors));
  assert.equal(config.workers_dev, false); assert.equal(config.preview_urls, false);
  assert.equal(config.vars.RECEIVER_ENABLED, 'disabled'); assert.equal(config.routes, undefined);
  for (const name of ['CALLBACK_KEYS', 'OWNERSHIP_PROOF']) assert.equal(config.vars[name], undefined);
  assert.equal(config.observability.enabled, false);
  for (const file of ['README.md', '../../docs/PUBLIC-BETA-CLIENT-PLAN.md']) {
    const doc = path.join(here, file), text = fs.readFileSync(doc, 'utf8');
    for (const [, target] of text.matchAll(/\]\(([^)]+)\)/g)) {
      if (!target.startsWith('https://')) assert.ok(fs.existsSync(path.resolve(path.dirname(doc), target)), target);
    }
  }
});
test('actual local Worker/SQLite: static proof, HMAC authentication, atomic dedup, restart and observed policy/material rollback', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-beta-receiver-'));
  fs.writeFileSync(path.join(root, '.owner'), 'beta-receiver-fixture');
  const f = fixture(); let mf, outbound = 0, calls = 0;
  function start(extra = {}) {
    return new Miniflare(convertV4MiniflareOptions({resourcePersistencePath: root, workers: [{
      name: 'beta-receiver', modulesRoot: path.join(here, '..'),
      modules: ['public-beta-receiver/worker.mjs', 'rotating-receiver.mjs', 'operation-dedup.mjs']
        .map(file => ({type: 'ESModule', path: path.join(here, '..', file)})), compatibilityDate: '2026-10-28',
      compatibilityFlags: ['nodejs_compat'], bindings: {...f.bindings(), ...extra},
      durableObjects: {INBOX: {className: 'ReceiverInbox', useSQLite: true}},
      outboundService: () => { outbound++; return new Response(null, {status: 403}); },
    }]}));
  }
  async function call({body = '{"synthetic":true}', headers = f.headers(body), address = url, method = 'POST', status = 204} = {}) {
    assert.ok(++calls <= 200);
    const r = await mf.dispatchFetch(address, {method, headers, body: method === 'GET' ? undefined : body});
    assert.equal(r.status, status); assert.equal(r.headers.get('Location'), null); const text = await r.text();
    for (const material of Object.values(f.material)) assert.equal(text.includes(material), false);
    return text;
  }
  try {
    mf = start();
    const proofHeaders = {'Content-Type': 'text/plain; charset=utf-8'};
    assert.equal(f.verifyBody.includes(JSON.parse(f.proof.response.split('\n')[1])[7]), false);
    assert.equal(await call({body: f.verifyBody, headers: proofHeaders, status: 200}), f.proof.response);
    await call({body: f.proof.response, headers: proofHeaders, status: 403}); // never reflect caller response
    await call({body: f.verifyBody.replace('owned', 'other'), headers: proofHeaders, status: 403});
    await call({address: url + '?proof=1', status: 404}); await call({method: 'GET', status: 404});
    await call({headers: {'Content-Type': 'text/plain'}, status: 415});
    await call({headers: {...proofHeaders, 'x-untrusted': 'x'.repeat(2049)}, status: 431});
    await call({body: 'x'.repeat(1025), headers: proofHeaders, status: 413});
    await call({headers: {...f.headers('bad'), 'RunLater-Signature': '0'.repeat(64)}, status: 403});
    await call({headers: {...f.headers('{"synthetic":true}'), 'RunLater-Task-Id': 'other:task_0000000000000001'}, status: 403});
    await call({headers: {...f.headers('{"synthetic":true}'), 'RunLater-Timestamp': '0' + now()}, status: 403});
    await call({headers: {...f.headers('{"synthetic":true}'), 'RunLater-Key-Id': 'unknown'}, status: 403});
    await call({headers: {...f.headers('{"synthetic":true}'), 'RunLater-Signing-Policy': 'other_policy'}, status: 403});
    await call({headers: f.headers('{"synthetic":true}', {timestamp: now() - 301}), status: 403});
    assert.deepEqual(snapshot(root), [], 'Proof/invalid callbacks created a durable inbox');
    await Promise.all([call(), call()]);
    await call({headers: f.headers('{"synthetic":true}', {task: project + ':task_0000000000000002'})});
    await call({body: 'changed', headers: f.headers('changed'), status: 409});
    let s = snapshot(root); assert.equal(s.length, 1); assert.equal(s[0].effects, 1); assert.equal(s[0].operations.length, 1);
    assert.equal(JSON.stringify(s).includes(f.material.server_one), false);
    assert.equal(JSON.stringify(s).includes(f.proof.response), false);
    await mf.dispose(); mf = start(); await call();
    assert.equal(snapshot(root)[0].effects, 1, 'Process restart forgot durable dedup');
    const oldPolicy = structuredClone(f.policy), cut = now();
    f.material.server_two = randomBytes(32).toString('hex');
    f.policy.revision = 2; f.policy.keys.server_one.sign_until_sec = cut; f.policy.keys.server_one.verify_until_sec = cut + 300;
    f.policy.keys.server_two = {key_id: 'server_two', introduced_revision: 2, active_from_sec: cut,
      sign_until_sec: cut + 3600, verify_until_sec: cut + 3900, revoked_at_sec: null};
    f.policy.rotations.server_two = {source: 'server_one', cutover_sec: cut, sign_until_sec: cut + 3600};
    await mf.dispose(); mf = start();
    await call({headers: f.headers('{"synthetic":true}', {kid: 'server_two', operation: 'rotated'})});
    await mf.dispose(); mf = start({CALLBACK_POLICY: JSON.stringify(oldPolicy), CALLBACK_KEYS: JSON.stringify({server_one: f.material.server_one})});
    await call({headers: f.headers('{"synthetic":true}', {timestamp: cut - 1, operation: 'rollback'}), status: 503});
    assert.equal(snapshot(root)[0].effects, 2);
    f.policy.revision = 3; f.policy.keys.server_one.revoked_at_sec = cut;
    await mf.dispose(); mf = start();
    await call({headers: f.headers('{"synthetic":true}', {kid: 'server_two', operation: 'revocation_observed'})});
    await call({headers: f.headers('{"synthetic":true}', {timestamp: cut - 1}), status: 403});
    const changed = {...f.material, server_two: randomBytes(32).toString('hex')};
    await mf.dispose(); mf = start({CALLBACK_KEYS: JSON.stringify(changed)});
    const forged = {...f.headers('{"synthetic":true}', {kid: 'server_two', operation: 'material_swap'})};
    const ts = forged['RunLater-Timestamp'], task = forged['RunLater-Task-Id'];
    forged['RunLater-Signature'] = createHmac('sha256', Buffer.from(changed.server_two, 'hex'))
      .update(`runlater.v2.${f.policy.policy_id}.server_two.${ts}.${task}.material_swap.`).update('{"synthetic":true}').digest('hex');
    await call({headers: forged, status: 503}); assert.equal(snapshot(root)[0].effects, 3);
    await mf.dispose(); mf = start();
    for (let i = 3; i < 128; i++) await call({headers: f.headers('{"synthetic":true}', {kid: 'server_two', operation: 'bounded_' + i})});
    await call({headers: f.headers('{"synthetic":true}', {kid: 'server_two', operation: 'overflow'}), status: 429});
    assert.equal(snapshot(root)[0].effects, 128); assert.equal(outbound, 0);
    await mf.dispose(); mf = start({RECEIVER_ENABLED: 'disabled'}); await call({status: 503});
    await mf.dispose(); mf = start({OWNERSHIP_PROOF: JSON.stringify({...f.proof, response: f.proof.response + 'x'})});
    await call({body: f.verifyBody, headers: proofHeaders, status: 503});
    const expiredTuple = JSON.parse(f.proof.response.split('\n')[1]); expiredTuple[6] = Date.now() - 1;
    const expiredResponse = 'RunLater destination proof v1\n' + JSON.stringify(expiredTuple);
    await mf.dispose(); mf = start({OWNERSHIP_PROOF: JSON.stringify({id: sha(expiredResponse), response: expiredResponse, expires_at_ms: expiredTuple[6]})});
    await call({body: f.verifyBody, headers: proofHeaders, status: 503});
    for (const target of ['https://attacker.example/callback', 'https://account.workers.dev/callback',
      'https://prefix.receiver.account.workers.dev/callback', url + '?query=1']) {
      await mf.dispose(); mf = start({RECEIVER_URL: target}); await call({status: 503});
    }
  } finally {
    await mf?.dispose(); assert.equal(fs.readFileSync(path.join(root, '.owner'), 'utf8'), 'beta-receiver-fixture');
    fs.rmSync(root, {recursive: true});
  }
});
