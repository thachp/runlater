// All credentials and API responses here are disposable offline fixtures, never enrolled or deployed.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import path from 'node:path';
import {createHash, generateKeyPairSync, verify} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {SSEClientTransport} from '@modelcontextprotocol/sdk/client/sse.js';
import {createMcpHttpServer, loadConfig, ENDPOINT} from './server.mjs';
import {toolHandler, publicStatus, TOOLS} from './tools.mjs';
import {PublicBetaClientV1, PUBLIC_BETA_TERMS, ORIGIN} from '../examples/public-beta-client.v1.mjs';

const TOKEN = 'public_test_fixture_only_not_a_live_token';
const SECRET = 'sensitive_payload_or_authorization_marker';
const ID = 'task_0000000000000001';
const input = {endpoint_id: 'verified_receiver', body: SECRET, operation_key: 'business_001', run_at_ms: 0, idempotency_key: 'stable_001'};
const hash = value => createHash('sha256').update(value).digest('hex');
const statusValue = {mode: 'public_free_beta', registration_open: true, remaining_projects: 10, payments: false,
  trial: {attempt_units: 100, duration_ms: 604800000, units_reserved_per_task: 5},
  limits: {client_operations_per_project: 1000, lifetime_projects: 10, lifetime_publications_per_project: 128,
    lifetime_tasks_per_project: 16, receiver: 'worker.account.workers.dev'}};
function fixture({loseFirst = false, failStatus, malformed = false} = {}) {
  const pair = generateKeyPairSync('ed25519'), publicKey = pair.publicKey.export({format: 'der', type: 'spki'}).subarray(-32).toString('hex');
  const releaseId = 'offline_mcp_fixture', ticket = hash(JSON.stringify(['runlater.public-beta.registration.v1', releaseId, publicKey]));
  let now = Date.now(), lost = false, task;
  const receipt = {ticket_id: ticket, project_id: 'p_' + ticket.slice(0, 60), public_key: publicKey, grant_id: 'g_' + ticket.slice(0, 60),
    enrolled_at_ms: now, expires_at_ms: now + 604800000, attempt_units: 100, permissions: [...PUBLIC_BETA_TERMS.permissions]};
  const calls = [];
  const fetchImpl = async (url, init) => {
    assert.equal(new URL(url).origin, ORIGIN); assert.equal(init.redirect, 'manual');
    const route = new URL(url).pathname, headers = init.headers;
    calls.push({route, ...init});
    assert.equal(headers['RunLater-Project-Id'], receipt.project_id);
    assert.equal(headers.Authorization, undefined);
    assert.equal(headers['RunLater-Public-Key'], publicKey);
    const wire = 'RunLater signed request v1\n' + JSON.stringify([1, ORIGIN, receipt.project_id, publicKey, init.method, route, '',
      hash(init.body || ''), headers['Idempotency-Key'] || '', Number(headers['RunLater-Issued-At']), Number(headers['RunLater-Expires-At']), headers['RunLater-Nonce']]);
    assert.ok(verify(null, Buffer.from(wire), pair.publicKey, Buffer.from(headers['RunLater-Request-Signature'], 'hex')));
    if (failStatus) return Response.json({error: SECRET, body: SECRET}, {status: failStatus});
    if (route === '/v1/tasks') {
      const body = JSON.parse(init.body);
      assert.equal(body.destination, 'registered:verified_receiver');
      if (task && (task.request !== init.body || task.key !== headers['Idempotency-Key'])) return Response.json({error: SECRET}, {status: 409});
      const replayed = !!task;
      task ??= {request: init.body, key: headers['Idempotency-Key'], status: 'ready'};
      if (loseFirst && !lost) {lost = true; throw new Error(SECRET);}
      return response(replayed);
    }
    if (route === `/v1/tasks/${ID}/cancel`) {assert.equal(init.body, '{}'); task.status = 'cancelled'; return response(false);}
    if (route === `/v1/tasks/${ID}` && init.method === 'GET') return response(false);
    return Response.json({error: SECRET}, {status: 404});
  };
  function response(replayed) {return Response.json(malformed ? {result: SECRET} : {task_accepted: true, replayed,
    result: {id: ID, status: task.status, cancel_requested: task.status === 'cancelled', due_ms: now, terminal_ms: null,
      input: {body: SECRET}, token: SECRET, attempts: [{fence: 1, started_ms: now, finished_ms: now, outcome: 'timeout', staging_diagnostic: SECRET}]},
    funding: {secret: SECRET}, delivery: [{key_id: SECRET}], raw_headers: SECRET});}
  const client = new PublicBetaClientV1({privateKey: pair.privateKey, releaseId, receipt, fetchImpl, clock: () => now});
  return {client, receipt, pair, releaseId, fetchImpl, calls, expire() {now = receipt.expires_at_ms;}, advance() {now += 1000;}};
}
async function start(t, options = {}) {
  const reservation = net.createServer();
  await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const base = `http://127.0.0.1:${port}`;
  const app = createMcpHttpServer({...options, publicOrigin: base});
  await new Promise(resolve => app.server.listen(port, '127.0.0.1', resolve));
  const localFetch = fetch;
  const clients = [];
  t.after(async () => {await Promise.all(clients.map(client => client.close())); await app.close();});
  async function connect(token) {
    const client = new Client({name: 'offline-integration-test', version: '1.0.0'});
    clients.push(client);
    await client.connect(new SSEClientTransport(new URL(base + '/sse'), {fetch: localFetch, requestInit: token ? {headers: {Authorization: `Bearer ${token}`}} : undefined}));
    return client;
  }
  return {base, localFetch, connect};
}
const value = result => result.structuredContent;
const clean = result => assert.ok(!JSON.stringify(result).includes(SECRET), 'sensitive upstream data must not escape');

test('SDK client connects via SSE, reads setup and discovers tools without API requests', async t => {
  const f = fixture(), app = await start(t, {token: TOKEN, client: f.client, allowedScopes: ['enqueue', 'read', 'cancel'], status: async () => statusValue});
  const client = await app.connect();
  assert.deepEqual((await client.listTools()).tools.map(t => t.name), TOOLS.map(t => t.name));
  assert.equal((await client.listResources()).resources.length, 2);
  const setup = (await client.readResource({uri: 'runlater://setup'})).contents[0].text;
  assert.match(setup, /configuration evidence, not verified/);
  assert.match(setup, /Receiver pairing remains disabled/);
  assert.match(setup, /proof of business completion/);
  assert.equal(JSON.parse((await client.readResource({uri: 'runlater://service'})).contents[0].text).intended_endpoint, ENDPOINT);
  assert.equal(value(await client.callTool({name: 'service_status', arguments: {}})).mode, 'public_free_beta');
  assert.equal(value(await client.callTool({name: 'schedule_task', arguments: input})).error.code, 'credentials_required');
  assert.equal(f.calls.length, 0);
});

test('SDK authorized create → status with attempts → cancel uses signed fixed-project API and redacts data', async t => {
  const f = fixture(), app = await start(t, {token: TOKEN, client: f.client, allowedScopes: ['enqueue', 'read', 'cancel']});
  const client = await app.connect(TOKEN);
  const created = await client.callTool({name: 'schedule_task', arguments: input}); clean(created);
  assert.equal(value(created).task_id, ID); assert.equal(value(created).task_accepted, true); assert.equal(value(created).delivery_confirmed, false);
  const status = await client.callTool({name: 'task_status', arguments: {task_id: ID}}); clean(status);
  assert.equal(value(status).attempts[0].outcome, 'timeout');
  const cancelled = await client.callTool({name: 'cancel_task', arguments: {task_id: ID}}); clean(cancelled);
  assert.equal(value(cancelled).status, 'cancelled'); assert.equal(value(cancelled).cancellation_cannot_undo_callback, true);
  assert.deepEqual(f.calls.map(c => c.route), ['/v1/tasks', `/v1/tasks/${ID}`, `/v1/tasks/${ID}/cancel`]);
});

test('lost admission response is uncertain with no retry; explicit identical retry preserves key/body and gets same ID', async () => {
  const f = fixture({loseFirst: true}), call = toolHandler({client: f.client, allowedScopes: ['enqueue']});
  const uncertain = await call('schedule_task', input, true); clean(uncertain);
  assert.equal(value(uncertain).task_acceptance, 'unknown'); assert.equal(f.calls.length, 1);
  f.advance();
  const retry = await call('schedule_task', {...input}, true);
  assert.equal(value(retry).task_id, ID); assert.equal(value(retry).replayed, true);
  assert.equal(f.calls[0].body, f.calls[1].body);
  assert.equal(f.calls[0].headers['Idempotency-Key'], f.calls[1].headers['Idempotency-Key']);
  assert.notEqual(f.calls[0].headers['RunLater-Nonce'], f.calls[1].headers['RunLater-Nonce']);
  const conflict = await call('schedule_task', {...input, body: 'different'}, true);
  assert.equal(value(conflict).error.code, 'conflict'); assert.equal(f.calls.length, 3);
});

test('strict schemas reject unknown fields, credentials, foreign project, arbitrary destinations and UTF-8 overflow before fetch', async () => {
  const f = fixture(), call = toolHandler({client: f.client, allowedScopes: ['enqueue', 'read', 'cancel']});
  for (const args of [{...input, project_id: 'other'}, {...input, private_key: SECRET}, {...input, authorization: SECRET}, {...input, destination: 'https://evil.example/'}, {...input, endpoint_id: 'fixture://success'}, {...input, body: 'é'.repeat(600)}, {...input, run_at_ms: -1}, {...input, idempotency_key: ''}]) {
    const result = await call('schedule_task', args, true); clean(result); assert.equal(value(result).error.code, 'invalid_input');
  }
  assert.equal(value(await call('task_status', {task_id: '../other'}, true)).error.code, 'invalid_input');
  assert.equal(f.calls.length, 0);
});

test('missing/expired identity, reduced local scopes, unknown tools and upstream failures are bounded and actionable', async () => {
  const f = fixture(), call = toolHandler({client: f.client, allowedScopes: ['read']});
  assert.equal(value(await call('schedule_task', input, true)).error.code, 'insufficient_scope');
  assert.equal(value(await call('task_status', {task_id: ID}, false)).error.code, 'credentials_required');
  for (const tool of ['redrive_task', 'list_tasks', 'registration_challenge', 'purchase_credits']) assert.equal(value(await call(tool, {}, true)).error.code, 'capability_unavailable');
  f.expire(); assert.equal(value(await call('task_status', {task_id: ID}, true)).error.code, 'credentials_expired_or_missing');
  assert.equal(f.calls.length, 0);
  for (const [status, expected] of [[400, 'invalid_request'], [401, 'credentials_rejected'], [403, 'insufficient_scope_or_project'], [404, 'not_found'], [409, 'conflict'], [429, 'limits_exhausted'], [503, 'result_uncertain']]) {
    const x = fixture({failStatus: status}), handler = toolHandler({client: x.client, allowedScopes: ['enqueue']});
    const result = await handler('schedule_task', input, true); clean(result); assert.equal(value(result).error.code, expected); assert.equal(x.calls.length, 1);
  }
  const x = fixture({malformed: true}), handler = toolHandler({client: x.client, allowedScopes: ['enqueue']});
  assert.equal(value(await handler('schedule_task', input, true)).task_acceptance, 'unknown');
});

test('public status is fixed-origin, bounded, profile-aware, redacted and does not follow redirects', async () => {
  const status = await publicStatus(async (url, init) => {assert.equal(url, ORIGIN + '/v1/beta'); assert.equal(init.redirect, 'manual'); return Response.json({...statusValue, sensitive: SECRET});});
  clean(status); assert.equal(status.remaining_projects, 10);
  for (const response of [Response.json({...statusValue, mode: 'unsupported'}), Response.json({...statusValue, limits: {...statusValue.limits, receiver: 'arbitrary'}}), Response.json({...statusValue, trial: {...statusValue.trial, attempt_units: 999}}), Response.json({...statusValue, payments: true}), new Response('x'.repeat(9000)), new Response(null, {status: 302, headers: {location: 'https://elsewhere.example'}})]) await assert.rejects(publicStatus(async () => response));
  const call = toolHandler({status: async () => {throw Error(SECRET);}});
  const failure = await call('service_status', {}); clean(failure); assert.equal(value(failure).error.code, 'status_unavailable');
});

test('both SSE channels require matching owner token; invalid Origin/Host and malformed payloads do not echo secrets', async t => {
  const f = fixture(), app = await start(t, {token: TOKEN, client: f.client, allowedScopes: ['enqueue']});
  const headers = {Authorization: `Bearer ${TOKEN}`};
  const controller = new AbortController(); t.after(() => controller.abort());
  const stream = await app.localFetch(app.base + '/sse', {headers, signal: controller.signal});
  const reader = stream.body.getReader(), event = new TextDecoder().decode((await reader.read()).value);
  const endpoint = event.match(/data: (\/messages\?sessionId=[^\n]+)/)[1];
  const post = (h, body) => app.localFetch(app.base + endpoint, {method: 'POST', headers: {'Content-Type': 'application/json', ...h}, body});
  assert.equal((await post({}, '{}')).status, 403);
  assert.equal((await post({Authorization: 'Bearer wrong'}, '{}')).status, 401);
  const invalid = await post(headers, JSON.stringify({secret: SECRET})); assert.equal(invalid.status, 400); assert.ok(!(await invalid.text()).includes(SECRET));
  const invalidJson = await post(headers, SECRET); assert.equal(invalidJson.status, 400); assert.ok(!(await invalidJson.text()).includes(SECRET));
  assert.equal((await post(headers, 'x'.repeat(8193))).status, 413);
  assert.equal((await app.localFetch(app.base + '/sse', {headers: {Origin: 'https://evil.example'}})).status, 403);
  assert.equal(await new Promise((resolve, reject) => {const req = http.get(app.base + '/sse', {headers: {Host: 'evil.example'}}, res => {res.resume(); resolve(res.statusCode);}); req.on('error', reject);}), 403);
  assert.equal((await app.localFetch(app.base + '/sse?token=' + SECRET)).status, 404);
  assert.equal(f.calls.length, 0); await reader.cancel();
});

test('SDK-level validation errors are sanitized rather than echoed on SSE', async t => {
  const app = await start(t);
  const client = await app.connect();
  await assert.rejects(client.request({method: 'resources/read', params: {uri: SECRET}}, {parse: v => v}), error => !error.message.includes(SECRET));
});

test('owner configuration rejects symlinks, broad file permissions and mismatched projects without disclosing contents', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-mcp-config-'));
  try {
    const f = fixture(), put = (name, content) => {const file = path.join(dir, name); fs.writeFileSync(file, content, {mode: 0o600}); return file;};
    const config = {key_file: put('key.pem', f.pair.privateKey.export({format: 'pem', type: 'pkcs8'})), receipt_file: put('receipt.json', JSON.stringify(f.receipt)), token_file: put('token', TOKEN), release_id: f.releaseId, scopes: ['read']};
    const file = put('config.json', JSON.stringify(config));
    const loaded = loadConfig(file, async () => {throw Error('No network allowed');}); assert.equal(loaded.client.project, f.receipt.project_id); assert.deepEqual(loaded.allowedScopes, ['read']);
    fs.chmodSync(config.token_file, 0o644); assert.throws(() => loadConfig(file), /Invalid MCP configuration/); fs.chmodSync(config.token_file, 0o600);
    fs.writeFileSync(config.receipt_file, JSON.stringify({...f.receipt, project_id: 'other'})); assert.throws(() => loadConfig(file), /Invalid MCP configuration/);
    fs.symlinkSync(file, path.join(dir, 'link')); assert.throws(() => loadConfig(path.join(dir, 'link')), /Invalid MCP configuration/);
    assert.deepEqual(loadConfig(), {});
  } finally {fs.rmSync(dir, {recursive: true, force: true});}
});

test('shared in-flight bound does not silently retry or start excess commands', async () => {
  let resolve, count = 0;
  const pending = new Promise(r => {resolve = r;});
  const call = toolHandler({client: {enqueue: async () => {count++; await pending; throw Error(SECRET);}}, allowedScopes: ['enqueue']});
  const calls = Array.from({length: 4}, () => call('schedule_task', input, true));
  const busy = await call('schedule_task', input, true); assert.equal(value(busy).error.code, 'busy'); assert.equal(count, 4);
  resolve(); await Promise.all(calls); assert.equal(count, 4);
});


test('gateway scope attenuation strips read-only metadata from mutation receipts', async () => {
  const f = fixture(), call = toolHandler({client: f.client, allowedScopes: ['enqueue', 'cancel']});
  for (const result of [await call('schedule_task', input, true), await call('cancel_task', {task_id: ID}, true)]) {
    assert.equal(value(result).task_id, ID); assert.equal(value(result).task_accepted, true);
    for (const field of ['attempts', 'due_ms', 'terminal_ms', 'input', 'funding']) assert.equal(Object.hasOwn(value(result), field), false);
  }
  assert.equal(value(await call('task_status', {task_id: ID}, true)).error.code, 'insufficient_scope');
});


test('unadvertised async task execution is rejected before scheduling', async t => {
  const f = fixture(), app = await start(t, {token: TOKEN, client: f.client, allowedScopes: ['enqueue']});
  const client = await app.connect(TOKEN);
  await assert.rejects(client.request({method: 'tools/call', params: {name: 'schedule_task', arguments: input, task: {ttl: 60000}}}, {parse: v => v}));
  assert.equal(f.calls.length, 0);
});
