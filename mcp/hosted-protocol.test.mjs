import test from 'node:test';
import assert from 'node:assert/strict';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {SSEClientTransport} from '@modelcontextprotocol/sdk/client/sse.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {createHostedProtocol, MCP_ORIGIN} from './hosted-protocol.mjs';
const ID = 'task_0000000000000001';
const principal = {tokenHash: 'a'.repeat(64), delegation: {project_id: 'p_' + '1'.repeat(60), delegation_id: 'b'.repeat(64)}, scopes: ['cancel', 'enqueue', 'read'], expiresAt: Date.now() + 60000};
const input = {idempotency_key: 'stable_001', endpoint_id: 'owned', body: '{"private":"no-echo"}', operation_key: 'operation_001', run_at_ms: 0};
function app(t, options = {}) {
  const calls = []; let state = 'scheduled';
  const reply = () => ({result: {id: ID, status: state, due_ms: 0, terminal_ms: null}, task_accepted: true, replayed: false});
  const server = createHostedProtocol({setup: '# Source only; hosted verification pending.', makeClient: () => ({
    async enqueue(value, key) {calls.push(['enqueue', value, key]); return reply();},
    async task(id) {calls.push(['task', id]); return reply();},
    async cancel(id) {calls.push(['cancel', id]); state = 'cancelled'; return reply();},
  }), status: async () => ({mode: 'public_free_beta'}), ...options});
  t.after(() => server.close()); return {server, calls};
}
for (const lane of ['legacy SSE', 'Streamable HTTP']) test(`official SDK ${lane} connect, discover, create → inspect → cancel`, async t => {
  const {server, calls} = app(t);
  const client = new Client({name: 'offline-hosted-test', version: '1.0'}); t.after(() => client.close());
  const localFetch = (url, init) => server.handle(new Request(url, init), principal);
  const transport = lane === 'legacy SSE'
    ? new SSEClientTransport(new URL(MCP_ORIGIN + '/sse'), {fetch: localFetch})
    : new StreamableHTTPClientTransport(new URL(MCP_ORIGIN + '/mcp'), {fetch: localFetch});
  await client.connect(transport);
  assert.equal((await client.listTools()).tools.length, 4);
  assert.equal((await client.listResources()).resources.length, 2);
  const service = JSON.parse((await client.readResource({uri: 'runlater://service'})).contents[0].text);
  assert.equal(service.transports.sse, 'legacy_HTTP_SSE'); assert.equal(service.transports.mcp, 'stateless_Streamable_HTTP');
  assert.equal(service.hosted_verification, 'not_performed_by_this_source');
  const scheduled = await client.callTool({name: 'schedule_task', arguments: input});
  assert.equal(scheduled.structuredContent.task_id, ID);
  assert.ok(!JSON.stringify(scheduled).includes('no-echo'));
  assert.equal((await client.callTool({name: 'task_status', arguments: {task_id: ID}})).structuredContent.status, 'scheduled');
  assert.equal((await client.callTool({name: 'cancel_task', arguments: {task_id: ID}})).structuredContent.status, 'cancelled');
  assert.deepEqual(calls.map(v => v[0]), ['enqueue', 'task', 'cancel']);
  assert.equal(calls[0][2], 'stable_001');
});

test('SSE routing requires same rechecked bearer/project/delegation on POST, never session ID alone', async t => {
  const {server, calls} = app(t);
  const response = await server.handle(new Request(MCP_ORIGIN + '/sse'), principal);
  const reader = response.body.getReader(); t.after(() => reader.cancel());
  const first = new TextDecoder().decode((await reader.read()).value);
  const endpoint = first.match(/data: (.+)/)[1];
  const message = {jsonrpc: '2.0', id: 1, method: 'tools/list', params: {}};
  const req = () => new Request(MCP_ORIGIN + endpoint, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(message)});
  assert.equal((await server.handle(req(), null)).status, 401);
  for (const foreign of [{...principal, tokenHash: 'c'.repeat(64)}, {...principal, delegation: {...principal.delegation, project_id: 'p_' + '2'.repeat(60)}},
    {...principal, delegation: {...principal.delegation, delegation_id: 'd'.repeat(64)}}]) assert.equal((await server.handle(req(), foreign)).status, 403);
  assert.equal((await server.handle(req(), principal)).status, 202);
  assert.equal(calls.length, 0);
});

test('host/origin, expiration, strict body and unavailable methods fail closed', async t => {
  const {server, calls} = app(t);
  const post = (body, headers = {}) => new Request(MCP_ORIGIN + '/mcp', {method: 'POST', headers: {'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...headers}, body});
  assert.equal((await server.handle(new Request('https://attacker.test/sse'), principal)).status, 403);
  assert.equal((await server.handle(post('{}', {Origin: 'https://attacker.test'}), principal)).status, 403);
  assert.equal((await server.handle(post('{}'), {...principal, expiresAt: 0})).status, 401);
  assert.equal((await server.handle(post('['), principal)).status, 400);
  assert.equal((await server.handle(post('[]'), principal)).status, 400);
  assert.equal((await server.handle(post('x'.repeat(8193)), principal)).status, 413);
  assert.equal((await server.handle(new Request(MCP_ORIGIN + '/mcp'), principal)).status, 405);
  assert.equal((await server.handle(new Request(MCP_ORIGIN + '/sse?token=not-allowed'), principal)).status, 404);
  assert.equal(calls.length, 0);
});

test('session pool is finite and disconnected streams release capacity', async t => {
  const {server} = app(t, {maxSessions: 1});
  const first = await server.handle(new Request(MCP_ORIGIN + '/sse'), principal);
  assert.equal(first.status, 200); assert.equal(server.sessionCount, 1);
  assert.equal((await server.handle(new Request(MCP_ORIGIN + '/sse'), principal)).status, 429);
  await first.body.cancel(); assert.equal(server.sessionCount, 0);
  const replacement = await server.handle(new Request(MCP_ORIGIN + '/sse'), principal);
  assert.equal(replacement.status, 200); await replacement.body.cancel();
});

test('missing task scope yields OAuth HTTP challenge before either transport executes', async t => {
  const {server, calls} = app(t), readOnly = {...principal, scopes: ['read']};
  const message = JSON.stringify({jsonrpc: '2.0', id: 7, method: 'tools/call', params: {name: 'schedule_task', arguments: input}});
  const headers = {'Content-Type': 'application/json', Accept: 'application/json, text/event-stream'};
  const stream = await server.handle(new Request(MCP_ORIGIN + '/sse'), readOnly);
  const reader = stream.body.getReader(); t.after(() => reader.cancel());
  const endpoint = new TextDecoder().decode((await reader.read()).value).match(/data: (.+)/)[1];
  for (const path of ['/mcp', endpoint]) {
    const response = await server.handle(new Request(MCP_ORIGIN + path, {method: 'POST', headers, body: message}), readOnly);
    assert.equal(response.status, 403); assert.match(response.headers.get('www-authenticate'), /error="insufficient_scope"/);
    assert.match(response.headers.get('www-authenticate'), /scope="enqueue"/);
  }
  assert.equal(calls.length, 0);
});
