// Actual bundled OAuth/MCP Worker -> compiled Rust API. All identities, storage,
// metadata and HTTP traffic are disposable/local. No live resource or callback.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash, generateKeyPairSync, randomBytes} from 'node:crypto';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {SSEClientTransport} from '@modelcontextprotocol/sdk/client/sse.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {bundleMcp} from './build-mcp.mjs';
import {delegationPublicKey} from '../mcp/delegation.mjs';
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-trial-composition-'));
const apiOrigin = 'https://api.runlater.io', mcpOrigin = 'https://mcp.runlater.io';
const clientId = 'https://client.example.com/metadata', callback = 'https://client.example.com/callback';
const gateway = generateKeyPairSync('ed25519'), gatewayKey = delegationPublicKey(gateway.privateKey);
const releaseId = 'local_trial_composition', begin = Date.now() - 1000;
const apiCalls = [], secrets = new Set(), unexpected = []; let mcpCalls = 0, lostProvision = false, api, hosted;
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
  if (url.origin !== apiOrigin || url.search || !(/^\/v1\/mcp\/trials\/(provision|status|validate|revoke)$/.test(url.pathname) || url.pathname === '/v1/beta')) {
    unexpected.push('unexpected_egress'); return new Response(null, {status: 403});
  }
  assert.equal(request.headers.has('authorization'), false); assert.ok(apiCalls.length < 150);
  apiCalls.push(url.pathname);
  for (const name of ['RunLater-Trial-Capability', 'RunLater-Trial-Revocation']) if (request.headers.has(name)) secrets.add(request.headers.get(name));
  const headers = new Headers(request.headers); headers.set('CF-Connecting-IP', `192.0.2.${1 + Math.floor(apiCalls.length / 20)}`);
  const response = await api.dispatchFetch(request.url, {method: request.method, headers, body: request.method === 'GET' ? undefined : await request.text(), redirect: 'manual'});
  if (lostProvision && url.pathname.endsWith('/provision')) {lostProvision = false; throw new Error('simulated_committed_response_loss');}
  return response;
}
async function call(route, init = {}) {
  assert.ok(++mcpCalls < 150);
  const headers = new Headers(init.headers); headers.set('CF-Connecting-IP', `198.51.100.${1 + Math.floor(mcpCalls / 20)}`);
  return hosted.dispatchFetch(mcpOrigin + route, {...init, headers, redirect: 'manual'});
}
const tokenRequest = value => call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams(value).toString()});
async function authorize() {
  const verifier = randomBytes(48).toString('base64url'), challenge = createHash('sha256').update(verifier).digest('base64url');
  const query = new URLSearchParams({response_type: 'code', client_id: clientId, redirect_uri: callback, scope: 'cancel enqueue read',
    state: 'offline', resource: mcpOrigin, code_challenge: challenge, code_challenge_method: 'S256'});
  const before = snapshots(), page = await call('/authorize?' + query); assert.equal(page.status, 200);
  const html = await page.text(); assert.match(html, /Start free agent project/); assert.match(html, /receiver/i);
  const handle = html.match(/name="handle" value="([^"]+)"/)[1];
  const consent = await call('/authorize', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded',
    Origin: mcpOrigin, Cookie: page.headers.get('set-cookie').split(';')[0]}, body: new URLSearchParams({handle, decision: 'trial'}).toString()});
  assert.equal(consent.status, 302); assert.deepEqual(snapshots(), before);
  const response = await tokenRequest({grant_type: 'authorization_code', client_id: clientId, redirect_uri: callback,
    code: new URL(consent.headers.get('location')).searchParams.get('code'), code_verifier: verifier, resource: mcpOrigin});
  assert.equal(response.status, 200); const token = await response.json(); assert.ok(token.refresh_token); assert.equal(token.expires_in, 3600);
  assert.deepEqual(snapshots(), before); return token;
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
    bindings: {PUBLIC_BETA_ENABLED: 'operator-approved', MCP_ANONYMOUS_TRIAL_ENABLED: 'operator-approved', MCP_DELEGATION_GATEWAY_PUBLIC_KEY: gatewayKey,
      BETA_CALLBACK_MASTER: randomBytes(32).toString('hex'), BETA_READY_QUEUE: 'runlater-public-ready',
      PUBLIC_BETA_PROFILE: JSON.stringify({release_id: releaseId, opens_at_ms: begin, closes_at_ms: begin + 604800000,
        callback_end_sec: Math.ceil((begin + 15 * 86400000) / 1000) + 301, self_host: 'runlater-public-api.operator.workers.dev'})},
    ratelimits: {BETA_IP_RATE: {namespace_id: '1001', simple: {limit: 60, period: 60}}, BETA_REG_IP_RATE: {namespace_id: '1002', simple: {limit: 6, period: 60}}},
    durableObjects: {ADMISSION: {className: 'AdmissionRegistry', useSQLite: true}, PROJECTS: {className: 'InvitationProject', useSQLite: true}},
    queueProducers: {BETA_READY: 'runlater-public-ready'}, queueConsumers: {'runlater-public-ready': {maxBatchSize: 1, maxBatchTimeout: 0, maxRetries: 1}},
    outboundService: () => {unexpected.push('api_outbound'); return new Response(null, {status: 403});}}]}));
  hosted = new Miniflare(convertV4MiniflareOptions({modules: true, script: await bundleMcp(), compatibilityDate: '2026-10-29',
    compatibilityFlags: ['global_fetch_strictly_public'], durableObjects: {MCP_HUB: {className: 'McpHub', useSQLite: true}},
    ratelimits: {MCP_IP_RATE: {namespace_id: '2101', simple: {limit: 60, period: 60}}, MCP_AUTH_RATE: {namespace_id: '2102', simple: {limit: 6, period: 60}}},
    bindings: {MCP_ENABLED: 'operator-approved', MCP_OAUTH_ENABLED: 'operator-approved', MCP_ANONYMOUS_TRIAL_ENABLED: 'operator-approved',
      MCP_GATEWAY_PUBLIC_KEY: gatewayKey, MCP_GATEWAY_PRIVATE_KEY: gateway.privateKey.export({format: 'pem', type: 'pkcs8'}), MCP_RELEASE_ID: releaseId}, outboundService: bridge}));
  await Promise.all([api.ready, hosted.ready]);
  for (const kind of ['sse', 'mcp']) {
    const token = await authorize(), {client, transport} = sdkFor(kind, token), before = snapshots();
    try {
      await client.connect(transport); assert.equal((await client.listTools()).tools.length, 7);
      await client.listResources(); await client.readResource({uri: 'runlater://service'}); await client.readResource({uri: 'runlater://setup'});
      await client.callTool({name: 'service_status', arguments: {}});
      assert.equal((await client.callTool({name: 'trial_status', arguments: {}})).structuredContent.state, 'unprovisioned');
      assert.deepEqual(snapshots(), before);
      lostProvision = true;
      const uncertain = await client.callTool({name: 'provision_trial', arguments: {accept_finite_trial: true}});
      assert.equal(uncertain.structuredContent.provisioning, 'unknown'); const committed = snapshots();
      const provision = await client.callTool({name: 'provision_trial', arguments: {accept_finite_trial: true}});
      assert.equal(provision.structuredContent.state, 'active'); assert.equal(provision.structuredContent.scheduling_ready, false);
      assert.deepEqual(snapshots(), committed);
      const scheduled = await client.callTool({name: 'schedule_task', arguments: {idempotency_key: 'stable', endpoint_id: 'not_installed', body: '{}', operation_key: 'stable', run_at_ms: 0}});
      assert.equal(scheduled.structuredContent.error.code, 'receiver_setup_required'); assert.deepEqual(snapshots(), committed);
      const refreshed = await tokenRequest({grant_type: 'refresh_token', client_id: clientId, refresh_token: token.refresh_token, resource: mcpOrigin});
      assert.equal(refreshed.status, 200); const next = await refreshed.json();
      assert.equal((await call('/mcp', {headers: {Authorization: 'Bearer ' + token.access_token}})).status, 401);
      const newer = sdkFor(kind, next);
      try {
        await newer.client.connect(newer.transport);
        const status = await newer.client.callTool({name: 'trial_status', arguments: {}});
        assert.equal(status.structuredContent.project_id, provision.structuredContent.project_id);
        assert.equal(status.structuredContent.expires_at_ms, provision.structuredContent.expires_at_ms);
        const revoked = await newer.client.callTool({name: 'revoke_trial', arguments: {confirm: true}});
        assert.equal(revoked.structuredContent.revoked, true); assert.equal(revoked.structuredContent.api_revoked, true);
      } finally {await newer.client.close();}
      assert.equal((await call('/mcp', {headers: {Authorization: 'Bearer ' + next.access_token}})).status, 401);
      assert.equal((await tokenRequest({grant_type: 'refresh_token', client_id: clientId, refresh_token: next.refresh_token, resource: mcpOrigin})).status, 400);
    } finally {await client.close();}
  }
  assert.equal(grants().length, 2); assert.ok(grants().every(grant => grant.revoked_at_ms !== null));
  const snapshotText = JSON.stringify(snapshots()); for (const secret of secrets) assert.equal(snapshotText.includes(secret), false);
  assert.deepEqual(unexpected, []); assert.equal(apiCalls.some(route => route.startsWith('/v1/tasks')), false);
  console.log(JSON.stringify({status: 'passed', mcp_calls: mcpCalls, api_calls: apiCalls.length, transports: ['legacy_SSE', 'Streamable_HTTP'],
    no_account: true, zero_implicit_allocation: true, explicit_lost_response_recovery: true, immutable_refresh_identity: true,
    receiver_required: true, api_revocation_confirmed: true, task_capability_hash_only_api: true, external_calls: 0, tasks: 0, live_resources: 0}));
} finally {await hosted?.dispose(); await api?.dispose(); fs.rmSync(root, {recursive: true, force: true});}
