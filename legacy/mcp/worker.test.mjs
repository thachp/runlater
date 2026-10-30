// Whole hosted Worker + OAuth + SDK transports in local workerd only.
// All egress is intercepted; no real token, registration, task or receiver exists.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, verify} from 'node:crypto';
import {bundleMcp} from '../scripts/build-mcp.mjs';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {SSEClientTransport} from '@modelcontextprotocol/sdk/client/sse.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {signDelegation, delegationPublicKey, decodeDelegation} from './delegation.mjs';
import {authorizeFixture} from './oauth-test-helpers.mjs';
const origin = 'https://mcp.runlater.io', api = 'https://api.runlater.io';
const hash = value => createHash('sha256').update(value).digest('hex');

test('whole Worker OAuth-bound SSE and Streamable clients remain tenant-bound and revoke immediately', {timeout: 45000}, async t => {
  const owner = generateKeyPairSync('ed25519'), gateway = generateKeyPairSync('ed25519');
  const releaseId = 'worker_mcp_fixture', key = delegationPublicKey(owner.privateKey), gatewayKey = delegationPublicKey(gateway.privateKey), now = Date.now();
  const ticket = hash(JSON.stringify(['runlater.public-beta.registration.v1', releaseId, key]));
  const receipt = {ticket_id: ticket, project_id: 'p_' + ticket.slice(0, 60), grant_id: 'g_' + ticket.slice(0, 60), public_key: key,
    enrolled_at_ms: now - 1000, expires_at_ms: now - 1000 + 604800000, attempt_units: 100,
    permissions: ['enqueue', 'read', 'cancel', 'redrive', 'manage_destinations']};
  const delegation = signDelegation({privateKey: owner.privateKey, receipt, releaseId, gatewayPublicKey: gatewayKey,
    permissions: ['cancel', 'enqueue', 'read'], delegationId: 'a'.repeat(64), issuedAtMs: now, expiresAtMs: now + 3600000});
  const script = await bundleMcp();
  const calls = [], violations = []; let state = 'scheduled';
  const mf = new Miniflare(convertV4MiniflareOptions({modules: true, script, compatibilityDate: '2026-10-29',
    compatibilityFlags: ['global_fetch_strictly_public'], durableObjects: {MCP_HUB: {className: 'McpHub', useSQLite: true}},
    ratelimits: {MCP_IP_RATE: {namespace_id: '2101', simple: {limit: 60, period: 60}}, MCP_AUTH_RATE: {namespace_id: '2102', simple: {limit: 6, period: 60}}},
    bindings: {MCP_ENABLED: 'operator-approved', MCP_OAUTH_ENABLED: 'operator-approved', MCP_GATEWAY_PUBLIC_KEY: gatewayKey,
      MCP_GATEWAY_PRIVATE_KEY: gateway.privateKey.export({format: 'pem', type: 'pkcs8'}), MCP_RELEASE_ID: releaseId},
    outboundService: async request => {
      if (request.url === 'https://client.example.com/metadata') return Response.json({client_id: request.url, client_name: 'Local fixture client',
        redirect_uris: ['https://client.example.com/callback'], token_endpoint_auth_method: 'none'}, {headers: {'Cache-Control': 'no-store'}});
      if (!request.url.startsWith(api + '/v1/tasks') && request.url !== api + '/v1/mcp/delegations/validate') {violations.push('unexpected_outbound'); return new Response(null, {status: 403});}
      const url = new URL(request.url), h = request.headers, body = await request.text();
      calls.push({path: url.pathname, method: request.method});
      try {
        assert.equal(h.has('Authorization'), false); assert.equal(h.get('RunLater-Project-Id'), receipt.project_id);
        assert.equal(h.get('RunLater-Public-Key'), key); assert.deepEqual(decodeDelegation(h.get('RunLater-MCP-Delegation')), delegation);
        const wire = 'RunLater signed request v1\n' + JSON.stringify([1, api, receipt.project_id, key, request.method, url.pathname, '', hash(body),
          h.get('Idempotency-Key') || '', Number(h.get('RunLater-Issued-At')), Number(h.get('RunLater-Expires-At')), h.get('RunLater-Nonce')]);
        assert.ok(verify(null, Buffer.from(wire), gateway.publicKey, Buffer.from(h.get('RunLater-Request-Signature'), 'hex')));
      } catch {violations.push('invalid_downstream_proof'); return new Response(null, {status: 403});}
      if (url.pathname === '/v1/mcp/delegations/validate') return Response.json({active: true, project_id: receipt.project_id, expires_at_ms: delegation.expires_at_ms, permissions: delegation.permissions});
      if (url.pathname.endsWith('/cancel')) state = 'cancelled';
      else if (url.pathname === '/v1/tasks') state = 'scheduled';
      return Response.json({task_accepted: true, replayed: false, result: {id: 'task_0000000000000001', status: state, due_ms: now, terminal_ms: null}});
    }}));
  t.after(() => mf.dispose()); await mf.ready;
  const call = (path, init = {}) => mf.dispatchFetch(origin + path, {...init, redirect: 'manual', headers: {'CF-Connecting-IP': '198.51.100.1', ...Object.fromEntries(new Headers(init.headers))}});
  assert.equal((await call('/mcp')).status, 401);
  assert.equal((await call('/internal/authenticate')).status, 404);
  for (const transportName of ['sse', 'mcp']) {
    const token = await authorizeFixture(call, {privateKey: owner.privateKey, delegation});
    const client = new Client({name: 'full-worker-test', version: '1'});
    const localFetch = async (url, init = {}) => {
      assert.equal(new URL(url).origin, origin);
      return call(new URL(url).pathname + new URL(url).search, {...init, headers: {...Object.fromEntries(new Headers(init.headers)), Authorization: `Bearer ${token.access_token}`}});
    };
    const transport = transportName === 'sse' ? new SSEClientTransport(new URL(origin + '/sse'), {fetch: localFetch})
      : new StreamableHTTPClientTransport(new URL(origin + '/mcp'), {fetch: localFetch});
    try {
      await client.connect(transport);
      assert.equal((await client.listTools()).tools.length, 4);
      const created = await client.callTool({name: 'schedule_task', arguments: {idempotency_key: 'stable_' + transportName, endpoint_id: 'owned',
        body: '{"private":"fixture"}', operation_key: 'op_' + transportName, run_at_ms: 0}});
      assert.equal(created.structuredContent.task_id, 'task_0000000000000001', JSON.stringify({result:created,violations,calls}));
      assert.equal((await client.callTool({name: 'task_status', arguments: {task_id: 'task_0000000000000001'}})).structuredContent.status, 'scheduled');
      assert.equal((await client.callTool({name: 'cancel_task', arguments: {task_id: 'task_0000000000000001'}})).structuredContent.status, 'cancelled');
      const revoked = await call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams({token: token.access_token, client_id: 'https://client.example.com/metadata'}).toString()});
      assert.equal(revoked.status, 200);
      assert.equal((await call('/mcp', {headers: {Authorization: `Bearer ${token.access_token}`}})).status, 401);
    } finally {await client.close();}
  }
  assert.equal(calls.filter(call => call.path.startsWith('/v1/tasks')).length, 6);
  assert.equal(calls.filter(call => call.path === '/v1/mcp/delegations/validate').length, 4); assert.deepEqual(violations, []);
});
