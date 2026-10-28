// Actual production API + customer Worker + SQLite. Local private binding updates only.
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {generateKeyPairSync, randomBytes} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {PublicBetaClientV1, PUBLIC_BETA_TERMS, receiverSetup} from '../examples/public-beta-client.v1.mjs';

const repo = fileURLToPath(new URL('../', import.meta.url));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-public-client-'));
fs.writeFileSync(path.join(root, '.owner'), 'public-client-fixture');
const receiverURL = 'https://receiver.account.workers.dev/callback';
const begin = Date.now() - 1000, profile = {release_id: 'compiled_client_v1', opens_at_ms: begin,
  closes_at_ms: begin + 604800000, callback_end_sec: Math.ceil((begin + 15 * 86400000) / 1000) + 301,
  self_host: 'runlater-public-api.operator.workers.dev'};
const master = randomBytes(32).toString('hex'), pair = generateKeyPairSync('ed25519');
let mf, httpCalls = 0, deniedOutbound = 0, proofFetches = 0, loseTaskResponse = true, forceRetry = true;
let receiverBindings = {RECEIVER_ENABLED: 'disabled'};
const callbacks = [];
const modules = ['public-beta-receiver/worker.mjs', 'rotating-receiver.mjs', 'operation-dedup.mjs']
  .map(file => ({type: 'ESModule', path: path.join(repo, 'examples', file)}));
async function outbound(req) {
  assert.equal(req.url, receiverURL);
  const body = Buffer.from(await req.arrayBuffer()), headers = new Headers(req.headers);
  if (headers.get('Content-Type') === 'text/plain; charset=utf-8') {
    proofFetches++;
    const installed = JSON.parse(receiverBindings.OWNERSHIP_PROOF);
    const nonce = JSON.parse(installed.response.split('\n')[1])[7];
    assert.equal(body.toString().includes(nonce), false);
    return mf.getWorker('customer-receiver').then(worker => worker.fetch(receiverURL, {method: 'POST', headers, body}));
  }
  assert.equal(headers.get('Content-Type'), 'application/json');
  const worker = await mf.getWorker('customer-receiver');
  const response = await worker.fetch(receiverURL, {method: 'POST', headers, body});
  assert.equal(response.status, 204); await response.arrayBuffer();
  callbacks.push({headers: Object.fromEntries(headers), body});
  // The receiver committed, but the API observes a synthetic failure. A real retry must dedup.
  if (forceRetry) { forceRetry = false; return new Response(null, {status: 503}); }
  return new Response(null, {status: 204});
}
function options() {
  return convertV4MiniflareOptions({resourcePersistencePath: root, workers: [{
    name: 'public-api', modules: [{type: 'ESModule', path: path.join(repo, 'build/index.js')},
      {type: 'CompiledWasm', path: path.join(repo, 'build/index_bg.wasm')}],
    compatibilityDate: '2026-10-27', compatibilityFlags: ['global_fetch_strictly_public'],
    ratelimits: {BETA_IP_RATE: {namespace_id: '1001', simple: {limit: 60, period: 60}},
      BETA_REG_IP_RATE: {namespace_id: '1002', simple: {limit: 6, period: 60}}},
    bindings: {PUBLIC_BETA_ENABLED: 'operator-approved', PUBLIC_BETA_PROFILE: JSON.stringify(profile),
      BETA_CALLBACK_MASTER: master, BETA_READY_QUEUE: 'runlater-public-ready'},
    durableObjects: {ADMISSION: {className: 'AdmissionRegistry', useSQLite: true}, PROJECTS: {className: 'InvitationProject', useSQLite: true}},
    queueProducers: {BETA_READY: 'runlater-public-ready'}, queueConsumers: {'runlater-public-ready': {maxBatchSize: 1, maxBatchTimeout: 0, maxRetries: 1}},
    outboundService: outbound,
  }, {
    name: 'customer-receiver', modulesRoot: path.join(repo, 'examples'), modules,
    compatibilityDate: '2026-10-28', compatibilityFlags: ['nodejs_compat'], bindings: receiverBindings,
    durableObjects: {INBOX: {className: 'ReceiverInbox', useSQLite: true}},
    outboundService: () => {deniedOutbound++; return new Response(null, {status: 403});},
  }]});
}
async function start() { mf = new Miniflare(options()); await mf.ready; }
async function install(bindings) {
  // Test harness owner channel, not an HTTP install/reset route or provider secret operation.
  receiverBindings = {...bindings}; await mf.setOptions(options()); await mf.ready;
}
function snapshots() {
  const r = spawnSync('python3', ['-c', `import pathlib,sqlite3,json,sys
out={'effects':[],'projects':[]}
for p in pathlib.Path(sys.argv[1]).rglob('*.sqlite'):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 names={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
 if 'receiver_effect' in names:out['effects'].extend(r[0] for r in c.execute('SELECT accepted_operations FROM receiver_effect'))
 if 'invitation_snapshot' in names:
  for row in c.execute('SELECT data FROM invitation_snapshot'):
   v=json.loads(row[0])
   if 'mode' in v.get('data',{}):out['projects'].append(v)
print(json.dumps(out,sort_keys=True))`, root], {encoding: 'utf8'});
  assert.equal(r.status, 0); return JSON.parse(r.stdout);
}
const transport = async (url, init) => {
  assert.ok(++httpCalls <= 75); assert.equal(new URL(url).origin, 'https://api.runlater.io');
  const response = await mf.dispatchFetch(url, {...init, headers: {...init.headers, 'CF-Connecting-IP': '192.0.2.7'}});
  if (loseTaskResponse && new URL(url).pathname === '/v1/tasks' && init.method === 'POST') {
    loseTaskResponse = false; assert.equal(response.status, 201); await response.arrayBuffer(); throw Error('synthetic response loss after commit');
  }
  return response;
};
const client = new PublicBetaClientV1({privateKey: pair.privateKey, releaseId: profile.release_id, fetchImpl: transport});
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
try {
  await start();
  assert.equal((await client.status()).remaining_projects, 10); assert.deepEqual(snapshots().projects, []);
  const offer = await client.challenge(); assert.deepEqual(snapshots().projects, []);
  const receipt = await client.complete(offer, PUBLIC_BETA_TERMS);
  assert.deepEqual(await client.recover(), receipt);
  const callbackKey = await client.callbackKey('retrieve_own_callback');
  assert.ok(callbackKey.key_hex !== master, 'master returned as tenant key');
  const callbackPolicy = {version: 'v2', tenant: receipt.project_id, policy_id: callbackKey.policy_id, revision: 1,
    keys: {beta_v1: {key_id: 'beta_v1', introduced_revision: 1, active_from_sec: Math.floor(profile.opens_at_ms / 1000),
      sign_until_sec: profile.callback_end_sec, verify_until_sec: profile.callback_end_sec + 300, revoked_at_sec: null}}, rotations: {}};
  await install(receiverSetup({receipt, callbackKey, callbackPolicy, url: receiverURL}));
  const pending = await client.createDestination('my_receiver', 1, receiverURL, 'create_receiver');
  const proof = await client.prepareDestination(pending, 'prepare_receiver');
  assert.ok(proof.expires_at_ms - Date.now() > 240000);
  await install({...receiverBindings, OWNERSHIP_PROOF: JSON.stringify(proof)});
  const worker = await mf.getWorker('customer-receiver');
  const reflection = await worker.fetch(receiverURL, {method: 'POST', headers: {'Content-Type': 'text/plain; charset=utf-8'}, body: proof.response});
  assert.equal(reflection.status, 403); await reflection.arrayBuffer();
  const verified = await client.verifyDestination(pending, 'verify_receiver'); assert.equal(verified.status, 'verified');
  assert.equal(proofFetches, 1); assert.deepEqual(snapshots().effects, []);
  const input = {endpoint_id: 'my_receiver', body: '{"synthetic":true}', operation_key: 'compiled_business_operation', run_at_ms: Date.now() + 1000};
  const before = httpCalls;
  await assert.rejects(client.enqueue(input, 'preserved_task_command'), /transport_uncertain/); assert.equal(httpCalls, before + 1);
  await mf.dispose(); await start(); // actual workerd disposal/restart, all SQLite retained
  const accepted = await client.enqueue(input, 'preserved_task_command'); assert.equal(accepted.replayed, true);
  let task;
  for (let i = 0; i < 50; i++) {
    task = await client.task(accepted.result.id); if (task.result.status === 'succeeded') break; await pause(100);
  }
  assert.equal(task.result.status, 'succeeded'); assert.equal(task.result.attempts.length, 2);
  assert.equal(callbacks.length, 2); assert.equal(callbacks[0].body.toString(), input.body);
  assert.equal(callbacks[0].headers['runlater-operation-key'], input.operation_key);
  assert.equal(callbacks[0].headers['runlater-task-id'], callbacks[1].headers['runlater-task-id']);
  assert.deepEqual(snapshots().effects, [1]);
  const ownReceiver = await mf.getWorker('customer-receiver');
  const duplicate = await ownReceiver.fetch(receiverURL, {method: 'POST', headers: callbacks[0].headers, body: callbacks[0].body});
  assert.equal(duplicate.status, 204); await duplicate.arrayBuffer(); assert.deepEqual(snapshots().effects, [1]);
  const future = await client.enqueue({...input, operation_key: 'future_cancelled', run_at_ms: Date.now() + 3600000}, 'future_task');
  assert.equal((await client.cancel(future.result.id)).result.status, 'cancelled');
  await assert.rejects(client.redrive(accepted.result.id, 'invalid_succeeded_redrive'), e => e.status === 409);
  assert.equal((await client.revokeDestination('my_receiver', 1, 'revoke_receiver')).revoked, true);
  await mf.dispose(); await start(); assert.deepEqual(snapshots().effects, [1]);
  assert.deepEqual(await client.recover(), receipt);
  assert.ok((await client.callbackKey('retrieve_after_restart')).key_hex === callbackKey.key_hex, 'tenant key changed after restart');
  const stored = JSON.stringify(snapshots()); assert.equal(stored.includes(master), false); assert.equal(stored.includes(callbackKey.key_hex), false);
  assert.equal(stored.includes(proof.response), false);
  assert.equal(stored.includes(JSON.parse(proof.response.split('\n')[1])[7]), false); assert.equal(deniedOutbound, 0);
  console.log(JSON.stringify({status: 'passed', http_calls: httpCalls, proof_fetches: proofFetches, callback_attempts: callbacks.length,
    durable_effects: 1, persisted_api_receiver_restart: true, uncertain_admission_recovered: true, external_calls: 0, live_resources: 0}));
} finally {
  await mf?.dispose(); assert.equal(fs.readFileSync(path.join(root, '.owner'), 'utf8'), 'public-client-fixture'); fs.rmSync(root, {recursive: true});
}
