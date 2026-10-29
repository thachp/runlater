import test from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {SSEClientTransport} from '@modelcontextprotocol/sdk/client/sse.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createHostedProtocol, MCP_ORIGIN} from './hosted-protocol.mjs';
import {createTrialAuthority} from './oauth-trial.mjs';
import {trialToolHandler} from './trial-tools.mjs';
function principal() {
  const {props} = createTrialAuthority({releaseId: 'offline_trial', clientId: 'https://client.example/metadata', scopes: ['cancel', 'enqueue', 'read']});
  return {kind: 'trial', trial: {descriptor: props.descriptor, capability: props.capability},
    scopes: ['cancel', 'enqueue', 'read'], tokenHash: 'a'.repeat(64), expiresAt: Date.now() + 3600000, projectId: props.projectId};
}
for (const lane of ['sse', 'mcp']) test(`official SDK ${lane}: trial connection/discovery allocate nothing; provision explicit and receiver guarded`, async t => {
  const p = principal(), calls = []; let active = false;
  const reply = () => ({state: active ? 'active' : 'unprovisioned', project_id: p.projectId,
    expires_at_ms: p.trial.descriptor.expires_at_ms, permissions: p.scopes, receiver_ready: false,
    attempt_units: active ? 100 : 0, client_operations_limit: 1000});
  p.revokeTrial = async () => {calls.push('revoke'); return {revoked: true, api_revoked: true, cleanup_pending: false};};
  p.markTrialProvisioned = async () => {calls.push('promote');};
  const server = createHostedProtocol({setup: '# Anonymous trial source only, receiver setup not implemented.', status: async () => ({mode: 'public_free_beta'}),
    makeClient: () => ({async provision() {calls.push('provision'); active = true; return reply();},
      async status() {calls.push('status'); return reply();}, async enqueue() {calls.push('UNSAFE_TASK'); throw new Error();}})});
  t.after(() => server.close());
  const client = new Client({name: 'offline-trial-sdk', version: '1'}); t.after(() => client.close());
  const localFetch = (url, init) => server.handle(new Request(url, init), p);
  const transport = lane === 'sse' ? new SSEClientTransport(new URL(MCP_ORIGIN + '/sse'), {fetch: localFetch})
    : new StreamableHTTPClientTransport(new URL(MCP_ORIGIN + '/mcp'), {fetch: localFetch});
  await client.connect(transport); assert.equal((await client.listTools()).tools.length, 7);
  await client.listResources(); await client.readResource({uri: 'runlater://setup'});
  const service = JSON.parse((await client.readResource({uri: 'runlater://service'})).contents[0].text);
  assert.match(service.onboarding, /receiver setup required/); assert.match(service.authentication, /no mandatory human account/);
  await client.callTool({name: 'service_status', arguments: {}}); assert.deepEqual(calls, []);
  const before = await client.callTool({name: 'trial_status', arguments: {}});
  assert.equal(before.structuredContent.state, 'unprovisioned'); assert.equal(before.structuredContent.attempt_units, 0);
  assert.deepEqual(calls, ['status']);
  for (const args of [{}, {accept_finite_trial: false}, {accept_finite_trial: true, capability: 'injected'}]) {
    assert.equal((await client.callTool({name: 'provision_trial', arguments: args})).isError, true);
  }
  assert.deepEqual(calls, ['status']);
  const provisioned = await client.callTool({name: 'provision_trial', arguments: {accept_finite_trial: true}});
  assert.equal(provisioned.structuredContent.state, 'active'); assert.equal(provisioned.structuredContent.scheduling_ready, false);
  const scheduled = await client.callTool({name: 'schedule_task', arguments: {idempotency_key: 'stable', endpoint_id: 'owned', body: '{}', operation_key: 'stable', run_at_ms: 0}});
  assert.equal(scheduled.structuredContent.error.code, 'receiver_setup_required'); assert.equal(calls.includes('UNSAFE_TASK'), false);
  assert.equal((await client.callTool({name: 'revoke_trial', arguments: {confirm: true}})).structuredContent.revoked, true);
  assert.deepEqual(calls, ['status', 'provision', 'promote', 'revoke']);
  assert.ok(!JSON.stringify(provisioned).includes(p.trial.capability));
});
test('trial SSE partition cannot occupy reserved owner sessions; cross-trial session IDs never authorize', async t => {
  const server = createHostedProtocol({setup: '# offline', makeClient: () => ({}), maxSessions: 12}); t.after(() => server.close());
  const streams = []; t.after(() => Promise.all(streams.map(stream => stream.body.cancel())));
  const ps = Array.from({length: 9}, principal);
  for (const p of ps.slice(0, 8)) {const r = await server.handle(new Request(MCP_ORIGIN + '/sse'), p); assert.equal(r.status, 200); streams.push(r);}
  assert.equal((await server.handle(new Request(MCP_ORIGIN + '/sse'), ps[8])).status, 429);
  const owner = {tokenHash: 'b'.repeat(64), scopes: ['read'], expiresAt: Date.now() + 60000,
    delegation: {project_id: 'p_' + '0'.repeat(60), delegation_id: 'c'.repeat(64)}};
  const old = await server.handle(new Request(MCP_ORIGIN + '/sse'), owner); assert.equal(old.status, 200); streams.push(old);
});
test('tool errors never echo exception text, upstream capability or revocation material', async () => {
  for (const method of ['provision', 'status']) {
    const call = trialToolHandler({client: {[method]: async () => {throw new Error('SECRET_MUST_NOT_LEAK');}}, taskHandler: () => {throw new Error();}});
    const result = await call(method === 'provision' ? 'provision_trial' : 'trial_status', method === 'provision' ? {accept_finite_trial: true} : {}, true);
    assert.equal(result.isError, true); assert.ok(!JSON.stringify(result).includes('SECRET_MUST_NOT_LEAK'));
  }
});
