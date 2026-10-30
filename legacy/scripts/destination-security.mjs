// Actual --features production artifact, public-beta routes and real local Queue/SQLite.
// Every global Fetch is intercepted. No DNS, TLS, provider isolation or live SSRF claim.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash, generateKeyPairSync, randomBytes, sign} from 'node:crypto';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';

const origin = 'https://api.runlater.io';
const host = 'receiver.account.workers.dev';
const callback = `https://${host}/callback`;
const selfHost = 'runlater-public-api.operator.workers.dev';
const forbidden = [
  ['IPv4 unspecified', 'https://0.0.0.0/callback'],
  ['IPv4 private 10/8', 'https://10.0.0.1/callback'],
  ['IPv4 private 172.16/12', 'https://172.16.0.1/callback'],
  ['IPv4 private 192.168/16', 'https://192.168.0.1/callback'],
  ['IPv4 shared address space', 'https://100.64.0.1/callback'],
  ['IPv4 loopback', 'https://127.0.0.1/callback'],
  ['IPv4 link local metadata', 'https://169.254.169.254/latest/meta-data'],
  ['IPv4 multicast', 'https://224.0.0.1/callback'],
  ['IPv4 public literal', 'https://8.8.8.8/callback'],
  ['IPv4 short form', 'https://127.1/callback'],
  ['IPv4 integer', 'https://2130706433/callback'],
  ['IPv4 hexadecimal integer', 'https://0x7f000001/callback'],
  ['IPv4 hexadecimal dotted', 'https://0x7f.0.0.1/callback'],
  ['IPv4 octal dotted', 'https://0177.0.0.1/callback'],
  ['IPv4 percent encoded', 'https://%31%32%37.0.0.1/callback'],
  ['IPv6 unspecified', 'https://[::]/callback'],
  ['IPv6 loopback', 'https://[::1]/callback'],
  ['IPv6 unique local', 'https://[fc00::1]/callback'],
  ['IPv6 link local', 'https://[fe80::1]/callback'],
  ['IPv6 mapped loopback dotted', 'https://[::ffff:127.0.0.1]/callback'],
  ['IPv6 mapped loopback hex', 'https://[::ffff:7f00:1]/callback'],
  ['IPv6 mapped metadata', 'https://[::ffff:169.254.169.254]/callback'],
  ['IPv6 public literal', 'https://[2606:4700:4700::1111]/callback'],
  ['IPv6 zone identifier', 'https://[fe80::1%25eth0]/callback'],
  ['localhost', 'https://localhost/callback'],
  ['localhost subdomain', 'https://receiver.localhost/callback'],
  ['local suffix', 'https://receiver.local/callback'],
  ['metadata DNS alias', 'https://metadata.google.internal/computeMetadata/v1/'],
  ['custom public domain', 'https://example.com/callback'],
  ['Workers.dev root', 'https://workers.dev/callback'],
  ['Workers.dev account root', 'https://account.workers.dev/callback'],
  ['Workers.dev nested worker', 'https://nested.receiver.account.workers.dev/callback'],
  ['Workers.dev lookalike', 'https://receiver.account.workers.dev.evil.test/callback'],
  ['Workers.dev wrong suffix', 'https://receiver.account.workers-dev/callback'],
  ['Workers.dev empty label', 'https://receiver..workers.dev/callback'],
  ['Workers.dev invalid label', 'https://-receiver.account.workers.dev/callback'],
  ['Workers.dev wildcard', 'https://*.account.workers.dev/callback'],
  ['configured service itself', `https://${selfHost}/callback`],
  ['RunLater apex', 'https://runlater.io/callback'],
  ['RunLater API', 'https://api.runlater.io/callback'],
  ['RunLater receiver', 'https://receiver-alpha.runlater.io/callback'],
  ['HTTP scheme', `http://${host}/callback`],
  ['FTP scheme', `ftp://${host}/callback`],
  ['scheme relative', `//${host}/callback`],
  ['explicit default port', `https://${host}:443/callback`],
  ['alternate port', `https://${host}:8443/callback`],
  ['username', `https://user@${host}/callback`],
  ['password', `https://user:password@${host}/callback`],
  ['allowed host as userinfo', `https://${host}@127.0.0.1/callback`],
  ['userinfo authority confusion', `https://127.0.0.1@${host}/callback`],
  ['uppercase alias', `https://RECEIVER.account.workers.dev/callback`],
  ['trailing dot alias', `https://${host}./callback`],
  ['percent encoded hostname', 'https://%72eceiver.account.workers.dev/callback'],
  ['Unicode hostname normalization', 'https://ｒeceiver.account.workers.dev/callback'],
  ['backslash authority confusion', `https://${host}\\@127.0.0.1/callback`],
  ['backslash scheme confusion', `https:\\\\${host}/callback`],
  ['encoded authority delimiter', `https://${host}%2f.evil.test/callback`],
  ['leading whitespace', ` https://${host}/callback`],
  ['embedded control', `https://receiver.\naccount.workers.dev/callback`],
  ['NUL authority', `https://${host}\0.evil.test/callback`],
  ['query', `${callback}?token=synthetic`],
  ['fragment', `${callback}#fragment`],
  ['dot segment alias', `https://${host}/a/../callback`],
  ['encoded dot segment alias', `https://${host}/a/%2e%2e/callback`],
  ['oversize URL', `${callback}/${'x'.repeat(256)}`],
];

// Includes every common redirect status plus edge cases in the rejected 3xx range.
// Even an otherwise allowed URL or relative Location must not be followed.
const redirects = [
  {status: 301, location: 'https://127.0.0.1/callback'},
  {status: 302, location: 'http://169.254.169.254/latest/meta-data'},
  {status: 303, location: 'https://10.0.0.1/callback'},
  {status: 307, location: 'https://[::1]/callback'},
  {status: 308, location: 'https://[::ffff:169.254.169.254]/callback'},
  {status: 302, location: 'https://2130706433/callback'},
  {status: 307, location: 'https://metadata.google.internal/computeMetadata/v1/'},
  {status: 308, location: `https://${selfHost}/callback`},
  {status: 301, location: 'https://example.com/callback'},
  {status: 302, location: `https://${host}@127.0.0.1/callback`},
  {status: 300, location: 'https://other.account.workers.dev/callback'},
  {status: 304, location: '/second-hop'},
  {status: 399, location: `${callback}/second-hop`},
];

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-destination-security-'));
const pair = generateKeyPairSync('ed25519');
const publicKey = pair.publicKey.export({format: 'der', type: 'spki'}).subarray(-32).toString('hex');
const hash = value => createHash('sha256').update(value).digest('hex');
const proofs = new Map();
const requests = [];
const unexpected = [];
const receiverViolations = [];
let fallbackEgress = 0, calls = 0, mf, project;

// No URL is forwarded by this controller. Count before classifying so a failed
// unexpected request (or a swallowed assertion in workerd) still fails the test.
async function control(req) {
  const body = await req.text();
  const record = {url: req.url, method: req.method, operation: req.headers.get('RunLater-Operation-Key')};
  requests.push(record);
  let reply;
  if (req.method === 'POST' && body.startsWith('RunLater destination verification v1\n')) {
    const [, endpoint, , digest] = JSON.parse(body.split('\n')[1]);
    const proof = proofs.get(digest);
    if (proof && req.url === proof.url && endpoint === proof.endpoint) {
      // Record, rather than throw inside a service callback: a thrown assertion
      // becomes a network error and could falsely satisfy a negative proof test.
      for (const header of ['authorization', 'cookie', 'RunLater-Signature']) {
        if (req.headers.has(header)) receiverViolations.push(`${endpoint}: leaked ${header}`);
      }
      if (body.includes(JSON.parse(proof.response.split('\n')[1]).at(-1))) {
        receiverViolations.push(`${endpoint}: leaked secret proof nonce`);
      }
      reply = proof.redirect ?? {status: 200, body: proof.response};
    }
  } else if (req.method === 'POST' && req.url === callback) {
    if (record.operation === 'positive_control') reply = {status: 200, body: '{}'};
    else if (/^redirect_\d+$/.test(record.operation ?? '')) reply = redirects[Number(record.operation.slice(9))];
  }
  if (!reply) {
    unexpected.push(record);
    reply = {status: 403, body: 'blocked by local test controller'};
  }
  return Response.json(reply);
}

// Return redirects from workerd, not from Node's reconstructed Request/Response.
// This exercises the compiled Rust Fetch redirect mode, not a JS imitation of it.
const receiver = `export default {async fetch(request, env) {
  const reply = await (await env.CONTROL.fetch(request)).json();
  return new Response(reply.body ?? null, {
    status: reply.status, headers: reply.location ? {location: reply.location} : {}
  });
}}`;

async function api(route, {body, method = 'POST', headers = {}, status = 200} = {}) {
  assert.ok(++calls <= 600, 'bounded local API budget');
  const response = await mf.dispatchFetch(origin + route, {
    method,
    headers: {'Content-Type': 'application/json', 'CF-Connecting-IP': `192.0.2.${1 + Math.floor(calls / 30)}`, ...headers},
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  assert.equal(response.status, status, `${route}: ${text}`);
  return JSON.parse(text);
}

function signed(route, body, {method = 'POST', status = 200} = {}) {
  const issued = Date.now(), expires = issued + 60000, nonce = randomBytes(32).toString('hex');
  const idempotency = method === 'GET' ? '' : `security_${calls}`;
  const wire = 'RunLater signed request v1\n' + JSON.stringify([
    1, origin, project, publicKey, method, route, '', hash(body === undefined ? '' : JSON.stringify(body)),
    idempotency, issued, expires, nonce,
  ]);
  return api(route, {body, method, status, headers: {
    'RunLater-Project-Id': project, 'RunLater-Public-Key': publicKey,
    'RunLater-Request-Signature': sign(null, Buffer.from(wire), pair.privateKey).toString('hex'),
    'RunLater-Nonce': nonce, 'RunLater-Issued-At': String(issued), 'RunLater-Expires-At': String(expires),
    'Idempotency-Key': idempotency,
  }});
}

function assertNoUnexpected() {
  assert.deepEqual(unexpected, [], 'a forbidden or unconfigured URL reached intercepted Fetch');
  assert.deepEqual(receiverViolations, [], 'proof receiver contract violated');
  assert.equal(fallbackEgress, 0, 'local receiver attempted a network request');
}

async function configure(endpoint, url, redirect) {
  const input = {endpoint_id: endpoint, version: 1};
  const created = await signed('/v1/destinations/create', {...input, url});
  assert.equal(created.status, 'pending');
  const proof = await signed('/v1/destinations/prepare', input);
  proofs.set(proof.id, {...proof, endpoint, url, redirect});
  return input;
}

async function waitTask(id, wanted) {
  const deadline = Date.now() + 10000;
  do {
    const value = await signed(`/v1/tasks/${id}`, undefined, {method: 'GET'});
    if (value.result.status === wanted) return value;
    assert.ok(!['succeeded', 'failed', 'cancelled'].includes(value.result.status), `unexpected terminal task ${value.result.status}`);
    await new Promise(resolve => setTimeout(resolve, 50));
  } while (Date.now() < deadline);
  assert.fail(`local task did not become ${wanted} before the bounded deadline`);
}

try {
  const begin = Date.now() - 1000;
  mf = new Miniflare(convertV4MiniflareOptions({resourcePersistencePath: root, workers: [{
    name: 'production-api',
    modules: [{type: 'ESModule', path: 'build/index.js'}, {type: 'CompiledWasm', path: 'build/index_bg.wasm'}],
    compatibilityDate: '2026-10-27', compatibilityFlags: ['global_fetch_strictly_public'],
    bindings: {
      PUBLIC_BETA_ENABLED: 'operator-approved',
      PUBLIC_BETA_PROFILE: JSON.stringify({release_id: 'local_security_1', opens_at_ms: begin,
        closes_at_ms: begin + 7 * 86400000, callback_end_sec: Math.ceil((begin + 15 * 86400000) / 1000) + 301,
        self_host: selfHost}),
      BETA_CALLBACK_MASTER: randomBytes(32).toString('hex'), BETA_READY_QUEUE: 'runlater-public-ready',
    },
    ratelimits: {
      BETA_IP_RATE: {namespace_id: '1001', simple: {limit: 60, period: 60}},
      BETA_REG_IP_RATE: {namespace_id: '1002', simple: {limit: 6, period: 60}},
    },
    durableObjects: {ADMISSION: {className: 'AdmissionRegistry', useSQLite: true}, PROJECTS: {className: 'InvitationProject', useSQLite: true}},
    queueProducers: {BETA_READY: 'runlater-public-ready'},
    queueConsumers: {'runlater-public-ready': {maxBatchSize: 1, maxBatchTimeout: 0, maxRetries: 1}},
    outboundService: 'local-receiver',
  }, {
    name: 'local-receiver', modules: true, compatibilityDate: '2026-10-27', script: receiver,
    serviceBindings: {CONTROL: control},
    outboundService: () => { fallbackEgress++; return new Response(null, {status: 403}); },
  }]}));
  await mf.ready;
  assert.equal((await api('/health', {method: 'GET'})).mode, 'public_free_beta');
  const challenge = await api('/v1/registration/challenge', {body: {public_key: publicKey}});
  const receipt = await api('/v1/registration/complete', {status: 201, body: {
    challenge_id: challenge.challenge_id,
    signature: sign(null, Buffer.from(challenge.canonical_utf8), pair.privateKey).toString('hex'),
  }});
  project = receipt.project_id;

  for (const [label, url] of forbidden) {
    const before = requests.length;
    const input = {endpoint_id: 'rejected', version: 1};
    const rejected = await signed('/v1/destinations/create', {...input, url}, {status: 403});
    assert.equal(rejected.error, 'destination_unavailable', label);
    assert.equal(rejected.task_accepted, false, label);
    // A route-level failure must not leave an endpoint that can prepare or fetch.
    await signed('/v1/destinations/prepare', input, {status: 404});
    await signed('/v1/destinations/verify', input, {status: 404});
    assert.equal(requests.length, before, `${label}: rejection emitted an outbound request`);
    assertNoUnexpected();
  }
  assert.equal(requests.length, 0, 'all prohibited inputs must have zero egress');

  // Positive control prevents a disabled route, broken auth or blanket deny mock
  // from making the negative matrix pass accidentally.
  const accepted = await configure('owned', callback);
  assert.equal((await signed('/v1/destinations/verify', accepted)).status, 'verified');
  assert.equal(requests.length, 1);
  const task = {destination: 'registered:owned', body: '{"synthetic":true}', run_at_ms: 0};
  const positive = await signed('/v1/tasks', {...task, operation_key: 'positive_control'}, {status: 201});
  const completed = await waitTask(positive.result.id, 'succeeded');
  assert.equal(completed.delivery.length, 1);
  assert.equal(completed.delivery[0].category, 'http_success');
  assertNoUnexpected();
  assert.equal(requests.length, 2);

  for (const [index, redirect] of redirects.entries()) {
    const endpoint = `redirect_${index}`;
    const input = await configure(endpoint, `https://${host}/proof/${index}`, redirect);
    const beforeProof = requests.length;
    await signed('/v1/destinations/verify', input, {status: 503});
    assert.equal(requests.length, beforeProof + 1, `${endpoint}: proof followed Location`);
    assertNoUnexpected();
    await signed('/v1/destinations/verify', input, {status: 409});
    assert.equal(requests.length, beforeProof + 1, `${endpoint}: replay fetched again`);
    await signed('/v1/tasks', {...task, destination: `registered:${endpoint}`, operation_key: `pending_${index}`}, {status: 503});
    assert.equal(requests.length, beforeProof + 1, `${endpoint}: failed proof authorized delivery`);

    const beforeCallback = requests.length;
    const created = await signed('/v1/tasks', {...task, operation_key: endpoint}, {status: 201});
    const failed = await waitTask(created.result.id, 'failed');
    assert.equal(failed.delivery.length, 1, `${endpoint}: more than one delivery attempt`);
    assert.equal(failed.delivery[0].category, 'redirect_rejected', `${endpoint}: wrong terminal cause`);
    assert.equal(requests.length, beforeCallback + 1, `${endpoint}: callback followed Location or retried`);
    assertNoUnexpected();
  }
  assert.equal(requests.length, 2 + redirects.length * 2, 'exact bounded outbound count');
  console.log(JSON.stringify({status: 'passed', artifact: 'production', mode: 'public_free_beta',
    prohibited_url_cases: forbidden.length, prohibited_url_egress: 0,
    proof_redirect_cases: redirects.length, callback_redirect_cases: redirects.length,
    redirect_second_hops: 0, intercepted_requests: requests.length, http_calls: calls,
    external_calls: 0, live_resources: 0, dns_tls_rebinding_proof: false}));
} finally {
  await mf?.dispose();
  fs.rmSync(root, {recursive: true, force: true});
}
