// Actual bundled OAuth/MCP + official SDK transports -> compiled Rust API -> optional receiver.
// All credentials, storage, metadata and callback traffic are disposable/local; no external effects.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash, generateKeyPairSync, randomBytes, sign} from 'node:crypto';
import {build} from 'esbuild';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {SSEClientTransport} from '@modelcontextprotocol/sdk/client/sse.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {bundleMcp} from './build-mcp.mjs';
import {delegationPublicKey} from '../mcp/delegation.mjs';
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-receiver-composition-'));
const apiOrigin = 'https://api.runlater.io', mcpOrigin = 'https://mcp.runlater.io';
const clientId = 'https://client.example.com/metadata', callback = 'https://client.example.com/callback';
const gateway = generateKeyPairSync('ed25519'), gatewayKey = delegationPublicKey(gateway.privateKey);
const releaseId = 'local_receiver_composition', begin = Date.now() - 1000;
const apiCalls = [], secrets = new Set(), apiSecrets = new Set(), unexpected = []; let mcpCalls = 0, lostProvision = false, api, hosted;
const receivers = new Map(), receiverCalls = [], callbackBodies = [], modelOutputs = [];
let probes = 0, proofs = 0;
function snapshots() {
  const value = spawnSync('python3', ['-c', `import pathlib,sqlite3,json,sys
out=[]
for p in pathlib.Path(sys.argv[1]).rglob('*.sqlite'):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 if c.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='invitation_snapshot'").fetchone()[0]:
  for row in c.execute('SELECT data FROM invitation_snapshot'):out.append(json.loads(row[0])['data'])
print(json.dumps(out,sort_keys=True))`, root], {encoding: 'utf8'});
  assert.equal(value.status, 0, value.stderr); return JSON.parse(value.stdout);
}
const grants = () => Object.values(snapshots().find(value => value.trials)?.trials || {});
async function bridge(request) {
  if (request.url === clientId) return Response.json({client_id: clientId, client_name: 'Offline trial composition', redirect_uris: [callback],
    token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code']});
  const url = new URL(request.url);
  if (url.origin !== apiOrigin || url.search || !(/^\/v1\/mcp\/trials\/(provision|status|validate|revoke|receiver)$/.test(url.pathname) || url.pathname === '/v1/beta' || /^\/v1\/tasks(?:\/task_[a-f0-9]{16}(?:\/cancel)?)?$/.test(url.pathname))) {
    unexpected.push('unexpected_egress'); return new Response(null, {status: 403});
  }
  assert.equal(request.headers.has('authorization'), false); assert.ok(apiCalls.length < 300);
  apiCalls.push(url.pathname);
  for (const name of ['RunLater-Trial-Capability', 'RunLater-Trial-Revocation']) if (request.headers.has(name)) {secrets.add(request.headers.get(name)); apiSecrets.add(request.headers.get(name));}
  const headers = new Headers(request.headers); headers.set('CF-Connecting-IP', `192.0.2.${1 + Math.floor(apiCalls.length / 20)}`);
  const response = await api.dispatchFetch(request.url, {method: request.method, headers, body: request.method === 'GET' ? undefined : await request.text(), redirect: 'manual'});
  if (lostProvision && url.pathname.endsWith('/provision')) {lostProvision = false; throw new Error('simulated_committed_response_loss');}
  return response;
}
async function call(route, init = {}) {
  assert.ok(++mcpCalls < 300);
  const headers = new Headers(init.headers); headers.set('CF-Connecting-IP', `198.51.100.${1 + Math.floor(mcpCalls / 20)}`);
  return hosted.dispatchFetch(mcpOrigin + route, {...init, headers, redirect: 'manual'});
}
const tokenRequest = value => call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams(value).toString()});
async function authorize(scopes = 'cancel enqueue read receiver_setup') {
  const verifier = randomBytes(48).toString('base64url'), challenge = createHash('sha256').update(verifier).digest('base64url');
  const query = new URLSearchParams({response_type: 'code', client_id: clientId, redirect_uri: callback, scope: scopes,
    state: 'offline', resource: mcpOrigin, code_challenge: challenge, code_challenge_method: 'S256'});
  const before = snapshots(), page = await call('/authorize?' + query); assert.equal(page.status, 200);
  const html = await page.text(); assert.match(html, /Start free agent project/); assert.match(html, /receiver/i); if (scopes.includes('receiver_setup')) assert.match(html, /pair one fixed callback receiver/);
  const handle = html.match(/name="handle" value="([^"]+)"/)[1];
  const consent = await call('/authorize', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded',
    Origin: mcpOrigin, Cookie: page.headers.get('set-cookie').split(';')[0]}, body: new URLSearchParams({handle, decision: 'trial'}).toString()});
  assert.equal(consent.status, 302); assert.deepEqual(snapshots(), before);
  const response = await tokenRequest({grant_type: 'authorization_code', client_id: clientId, redirect_uri: callback,
    code: new URL(consent.headers.get('location')).searchParams.get('code'), code_verifier: verifier, resource: mcpOrigin});
  assert.equal(response.status, 200); const token = await response.json(); assert.ok(token.refresh_token); assert.equal(token.expires_in, 3600);
  assert.deepEqual(snapshots(), before); secrets.add(token.access_token); secrets.add(token.refresh_token); return token;
}
function sdkFor(kind, token) {
  const client = new Client({name: 'actual-trial-composition', version: '1'});
  const localFetch = (url, init = {}) => {const u = new URL(url); assert.equal(u.origin, mcpOrigin);
    const headers = new Headers(init.headers); headers.set('Authorization', 'Bearer ' + token.access_token);
    return call(u.pathname + u.search, {...init, headers});};
  const transport = kind === 'sse' ? new SSEClientTransport(new URL(mcpOrigin + '/sse'), {fetch: localFetch})
    : new StreamableHTTPClientTransport(new URL(mcpOrigin + '/mcp'), {fetch: localFetch});
  return {client, transport};
}
try {
  api = new Miniflare(convertV4MiniflareOptions({resourcePersistencePath: root, workers: [{name: 'trial-api',
    modules: [{type: 'ESModule', path: 'build/index.js'}, {type: 'CompiledWasm', path: 'build/index_bg.wasm'}],
    compatibilityDate: '2026-10-27', compatibilityFlags: ['global_fetch_strictly_public'],
    bindings: {PUBLIC_BETA_ENABLED: 'operator-approved', MCP_ANONYMOUS_TRIAL_ENABLED: 'operator-approved', MCP_RECEIVER_PAIRING_ENABLED: 'operator-approved', MCP_DELEGATION_GATEWAY_PUBLIC_KEY: gatewayKey,
      BETA_CALLBACK_MASTER: randomBytes(32).toString('hex'), BETA_READY_QUEUE: 'runlater-public-ready',
      PUBLIC_BETA_PROFILE: JSON.stringify({release_id: releaseId, opens_at_ms: begin, closes_at_ms: begin + 604800000,
        callback_end_sec: Math.ceil((begin + 15 * 86400000) / 1000) + 301, self_host: 'runlater-public-api.operator.workers.dev'})},
    ratelimits: {BETA_IP_RATE: {namespace_id: '1001', simple: {limit: 60, period: 60}}, BETA_REG_IP_RATE: {namespace_id: '1002', simple: {limit: 6, period: 60}}},
    durableObjects: {ADMISSION: {className: 'AdmissionRegistry', useSQLite: true}, PROJECTS: {className: 'InvitationProject', useSQLite: true}},
    queueProducers: {BETA_READY: 'runlater-public-ready'}, queueConsumers: {'runlater-public-ready': {maxBatchSize: 1, maxBatchTimeout: 0, maxRetries: 1}},
    outboundService: async request => {
      const receiver = receivers.get(request.url); if (!receiver) {unexpected.push('api_outbound'); return new Response(null, {status: 403});}
      const body = await request.text();
      if (body.startsWith('RunLater receiver probe v1\n')) probes++;
      else if (body.startsWith('RunLater destination verification v1\n')) proofs++;
      else {callbackBodies.push(body); assert.equal(request.headers.get('RunLater-Signature-Version'), 'v2');}
      return receiver.dispatchFetch(request.url, {method: request.method, headers: request.headers, body, redirect: 'manual'});}}]}));
  hosted = new Miniflare(convertV4MiniflareOptions({modules: true, script: await bundleMcp(), compatibilityDate: '2026-10-29',
    compatibilityFlags: ['global_fetch_strictly_public'], durableObjects: {MCP_HUB: {className: 'McpHub', useSQLite: true}},
    ratelimits: {MCP_IP_RATE: {namespace_id: '2101', simple: {limit: 60, period: 60}}, MCP_AUTH_RATE: {namespace_id: '2102', simple: {limit: 6, period: 60}}},
    bindings: {MCP_ENABLED: 'operator-approved', MCP_OAUTH_ENABLED: 'operator-approved', MCP_ANONYMOUS_TRIAL_ENABLED: 'operator-approved', MCP_RECEIVER_PAIRING_ENABLED: 'operator-approved',
      MCP_GATEWAY_PUBLIC_KEY: gatewayKey, MCP_GATEWAY_PRIVATE_KEY: gateway.privateKey.export({format: 'pem', type: 'pkcs8'}), MCP_RELEASE_ID: releaseId}, outboundService: bridge}));
  await Promise.all([api.ready, hosted.ready]);
  const receiverScript = (await build({stdin: {resolveDir: process.cwd(), contents: `
    import worker,{TrialReceiverInbox} from './examples/trial-receiver/worker.mjs'; export default worker;
    export class TestInbox extends TrialReceiverInbox {
      async testCycle(){this.sql.exec('UPDATE receiver_setup SET next_at=0 WHERE id=1');await this.alarm();return this.testSnapshot();}
      testSnapshot(){return {setup:this.sql.exec('SELECT ready,cycles FROM receiver_setup').one(),operations:this.sql.exec('SELECT operation_key,body_sha256 FROM receiver_operations').toArray()};}
    }`}, bundle: true, platform: 'neutral', mainFields: ['module', 'main'], format: 'esm', external: ['cloudflare:*', 'node:*'], write: false})).outputFiles[0].text;
  const tools = async (client, name, args = {}) => {
    const value = await client.callTool({name, arguments: args}); modelOutputs.push(JSON.stringify(value)); return value.structuredContent;
  };
  const denied = (client, name, args) => assert.rejects(() => tools(client, name, args), error => error.code === 403 || /403|insufficient_scope/.test(String(error)));
  // Old three-scope consent never silently gains receiver setup authority or allocates a project.
  const old = await authorize('cancel enqueue read'), oldSdk = sdkFor('mcp', old), oldBefore = snapshots();
  try {
    await oldSdk.client.connect(oldSdk.transport);
    await denied(oldSdk.client, 'pair_receiver', {confirm: true, manifest: {}});
    assert.deepEqual(snapshots(), oldBefore);
    await tools(oldSdk.client, 'revoke_trial', {confirm: true});
  } finally {await oldSdk.client.close();}
  for (const kind of ['sse', 'mcp']) {
    const token = await authorize(), {client, transport} = sdkFor(kind, token), before = snapshots();
    try {
      await client.connect(transport); assert.equal((await client.listTools()).tools.length, 8);
      await client.listResources(); await client.readResource({uri: 'runlater://service'}); await client.readResource({uri: 'runlater://setup'});
      await tools(client, 'service_status'); assert.equal((await tools(client, 'trial_status')).state, 'unprovisioned');
      assert.deepEqual(snapshots(), before);
      lostProvision = true;
      assert.equal((await tools(client, 'provision_trial', {accept_finite_trial: true})).provisioning, 'unknown');
      const committed = snapshots(), provision = await tools(client, 'provision_trial', {accept_finite_trial: true});
      assert.equal(provision.state, 'active'); assert.equal(provision.scheduling_ready, false); assert.deepEqual(snapshots(), committed);
      const payload = JSON.stringify({synthetic: true, private_payload_sentinel: kind});
      const taskInput = {idempotency_key: 'callback_' + kind, endpoint_id: 'receiver', body: payload, operation_key: 'callback_' + kind, run_at_ms: Date.now() + 2000};
      assert.equal((await tools(client, 'schedule_task', taskInput)).error.code, 'receiver_setup_required');
      const key = generateKeyPairSync('ed25519'), at = Date.now(), url = `https://receiver-${kind}.account.workers.dev/callback`;
      const m = {version: 1, release_id: releaseId, project_id: provision.project_id, url,
        receiver_public_key: delegationPublicKey(key.privateKey), pairing_id: randomBytes(32).toString('hex'), issued_at_ms: at, expires_at_ms: at + 300000};
      m.signature = sign(null, Buffer.from('RunLater receiver manifest v1\n' + JSON.stringify([1, m.release_id, m.project_id, m.url,
        m.receiver_public_key, m.pairing_id, m.issued_at_ms, m.expires_at_ms])), key.privateKey).toString('hex');
      const pem = key.privateKey.export({format: 'pem', type: 'pkcs8'}); secrets.add(pem);
      let losePull = true, loseAck = true; const digests = [];
      const receiver = new Miniflare(convertV4MiniflareOptions({script: receiverScript, modules: true,
        resourcePersistencePath: path.join(root, 'receiver-' + kind), compatibilityDate: '2026-10-28',
        compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'], durableObjects: {INBOX: {className: 'TestInbox', useSQLite: true}},
        bindings: {RECEIVER_ENABLED: 'pairing-configured', RECEIVER_MANIFEST: JSON.stringify(m), RECEIVER_SETUP_PRIVATE_KEY: pem},
        outboundService: async request => {
          const u = new URL(request.url); assert.equal(u.origin, apiOrigin); assert.ok(['/v1/mcp/receiver/pull', '/v1/mcp/receiver/ack'].includes(u.pathname));
          assert.equal(request.headers.has('Authorization'), false); assert.equal(request.headers.has('RunLater-Trial-Capability'), false);
          assert.ok(receiverCalls.length < 30); receiverCalls.push(u.pathname); const headers = new Headers(request.headers);
          headers.set('CF-Connecting-IP', '203.0.113.' + (1 + receiverCalls.length));
          const response = await api.dispatchFetch(request.url, {method: request.method, headers, body: await request.text(), redirect: 'manual'});
          if (response.status === 200 && u.pathname.endsWith('/pull')) {
            const value = await response.clone().json(); digests.push(value.installation_sha256); secrets.add(value.installation_sha256);
            secrets.add(value.installation.destination_proof.response); for (const material of Object.values(value.installation.callback_keys)) secrets.add(material);
            if (losePull) {losePull = false; return new Response(null, {status: 503});}
          }
          if (response.status === 200 && u.pathname.endsWith('/ack') && loseAck) {loseAck = false; return new Response(null, {status: 503});}
          return response;
        }}));
      receivers.set(url, receiver); await receiver.ready;
      const paired = await tools(client, 'pair_receiver', {confirm: true, manifest: m});
      assert.equal(paired.state, 'awaiting_receiver'); assert.equal(paired.infrastructure_created, false); assert.equal(paired.secrets_returned, false);
      const stub = (await receiver.getDurableObjectNamespace('INBOX')).getByName('bound-receiver-v1'); let inbox;
      for (let i = 0; i < 5; i++) {inbox = await stub.testCycle(); if (inbox.setup.ready === 1) break;}
      assert.equal(inbox.setup.ready, 1); assert.ok(digests.length >= 2); assert.equal(new Set(digests).size, 1);
      const ready = await tools(client, 'trial_status'); assert.equal(ready.receiver_ready, true); assert.equal(ready.scheduling_ready, true);
      taskInput.run_at_ms = Date.now() + 2000;
      const queued = await tools(client, 'schedule_task', taskInput); assert.equal(queued.ok, true); assert.equal(queued.task_accepted, true);
      const replay = await tools(client, 'schedule_task', taskInput); assert.equal(replay.task_id, queued.task_id); assert.equal(replay.replayed, true);
      let delivered; const deadline = Date.now() + 15000;
      do {delivered = await tools(client, 'task_status', {task_id: queued.task_id}); if (delivered.status === 'succeeded') break;
        await new Promise(resolve => setTimeout(resolve, 250));} while (Date.now() < deadline);
      assert.equal(delivered.status, 'succeeded'); assert.equal(delivered.delivery_confirmed, true);
      assert.match(delivered.delivery_meaning, /not downstream business completion/);
      inbox = await stub.testSnapshot(); assert.equal(inbox.operations.length, 1); assert.equal(inbox.operations[0].body_sha256, createHash('sha256').update(payload).digest('hex'));
      const future = await tools(client, 'schedule_task', {...taskInput, idempotency_key: 'cancel_' + kind, operation_key: 'cancel_' + kind, run_at_ms: Date.now() + 60000});
      assert.equal(future.ok, true); assert.equal((await tools(client, 'cancel_task', {task_id: future.task_id})).status, 'cancelled');
      const refreshed = await tokenRequest({grant_type: 'refresh_token', client_id: clientId, refresh_token: token.refresh_token, resource: mcpOrigin, scope: 'read'});
      assert.equal(refreshed.status, 200); const next = await refreshed.json(); assert.equal(next.scope, 'read');
      secrets.add(next.access_token); secrets.add(next.refresh_token);
      assert.equal((await call('/mcp', {headers: {Authorization: 'Bearer ' + token.access_token}})).status, 401);
      const newer = sdkFor(kind, next);
      try {
        await newer.client.connect(newer.transport); const status = await tools(newer.client, 'trial_status');
        assert.equal(status.project_id, provision.project_id); assert.equal(status.expires_at_ms, provision.expires_at_ms);
        assert.deepEqual(status.permissions, ['read']); assert.equal(status.scheduling_ready, false);
        await denied(newer.client, 'pair_receiver', {confirm: true, manifest: m});
        await denied(newer.client, 'schedule_task', taskInput);
        await denied(newer.client, 'cancel_task', {task_id: future.task_id});
        assert.equal((await tools(newer.client, 'task_status', {task_id: queued.task_id})).status, 'succeeded');
        const revoked = await tools(newer.client, 'revoke_trial', {confirm: true}); assert.equal(revoked.api_revoked, true);
      } finally {await newer.client.close();}
      assert.equal((await call('/mcp', {headers: {Authorization: 'Bearer ' + next.access_token}})).status, 401);
      assert.equal((await tokenRequest({grant_type: 'refresh_token', client_id: clientId, refresh_token: next.refresh_token, resource: mcpOrigin})).status, 400);
    } finally {await client.close();}
  }
  assert.equal(grants().length, 2); assert.ok(grants().every(grant => grant.revoked_at_ms !== null));
  const snapshotText = JSON.stringify(snapshots()), outputs = modelOutputs.join('\n');
  for (const secret of secrets) assert.equal(outputs.includes(secret), false);
  for (const secret of apiSecrets) assert.equal(snapshotText.includes(secret), false);
  assert.equal(outputs.includes('private_payload_sentinel'), false); assert.deepEqual(unexpected, []);
  assert.equal(probes, 2); assert.equal(proofs, 2); assert.equal(callbackBodies.length, 2);
  console.log(JSON.stringify({status: 'passed', mcp_calls: mcpCalls, gateway_api_calls: apiCalls.length, receiver_api_calls: receiverCalls.length,
    transports: ['legacy_SSE', 'Streamable_HTTP'], explicit_four_scope_consent: true, old_scope_not_broadened: true,
    zero_implicit_allocation: true, explicit_provision_and_pair: true, immutable_lost_response_recovery: true,
    actual_private_receiver_install: true, actual_signed_callbacks: callbackBodies.length, local_tasks: 4,
    status_and_cancel: true, refresh_downscope: true, api_revocation_confirmed: true, secret_outputs: false,
    external_calls: 0, live_resources: 0}));
} finally {for (const receiver of receivers.values()) await receiver.dispose(); await hosted?.dispose(); await api?.dispose(); fs.rmSync(root, {recursive: true, force: true});}
