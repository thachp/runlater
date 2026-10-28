// Offline protocol mocks/native byte oracle. Compiled Worker journey is a separate script.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash, generateKeyPairSync, randomBytes, verify} from 'node:crypto';
import {execFileSync, spawnSync} from 'node:child_process';
import Ajv from 'ajv';
import {PublicBetaClientV1, PublicBetaClientError, PUBLIC_BETA_TERMS, ORIGIN, receiverSetup} from './public-beta-client.v1.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const hash = value => createHash('sha256').update(value).digest('hex');
const now = 1900000000000, releaseId = 'mock_public_v1', url = 'https://receiver.account.workers.dev/callback';
const profile = {release_id: releaseId, opens_at_ms: now - 1000, closes_at_ms: now - 1000 + 604800000,
  callback_end_sec: Math.ceil((now + 15 * 86400000) / 1000) + 301, self_host: 'runlater-public-api.operator.workers.dev'};
const contract = JSON.parse(fs.readFileSync(path.join(root, 'contracts/public-beta-v1.json')));
const destinationContract = JSON.parse(fs.readFileSync(path.join(root, 'contracts/invitation-v1.json')));
const validateDestination = new Ajv({strict: true}).compile(destinationContract.request_schema);
const rustc = execFileSync('rustup', ['which', 'rustc', '--toolchain', '1.92.0'], {encoding: 'utf8'}).trim();
const build = spawnSync('rustup', ['run', '1.92.0', 'cargo', 'build', '--locked', '--quiet', '--example', 'public_beta_client_v1_vectors'],
  {cwd: root, encoding: 'utf8', env: {...process.env, RUSTC: rustc}});
assert.equal(build.status, 0, build.stderr);
const oracle = challenge => JSON.parse(execFileSync(path.join(root, 'target/debug/examples/public_beta_client_v1_vectors'),
  {input: JSON.stringify({profile, challenge}), encoding: 'utf8'}));
const betaStatus = () => ({mode: 'public_free_beta', registration_open: true, remaining_projects: 10,
  trial: {attempt_units: 100, duration_ms: 604800000, units_reserved_per_task: 5},
  limits: {client_operations_per_project: 1000, lifetime_projects: 10, lifetime_publications_per_project: 128,
    lifetime_tasks_per_project: 16, receiver: 'worker.account.workers.dev'}, payments: false});
const taskId = n => 'task_' + n.toString(16).padStart(16, '0');
function mock({mutateOffer, mutateReceipt, mutateRecovery, mutateKey, mutateProof, loseCompletion = false, loseTask = false} = {}) {
  const pair = generateKeyPairSync('ed25519'), publicKey = pair.publicKey.export({type: 'spki', format: 'der'}).subarray(-32).toString('hex');
  const id = hash(JSON.stringify(['runlater.public-beta.registration.v1', releaseId, publicKey])), project = 'p_' + id.slice(0, 60);
  const ticket = {id, project_id: project, grant_id: 'g_' + id.slice(0, 60), terms: structuredClone(PUBLIC_BETA_TERMS),
    issued_at_ms: now - 1000, expires_at_ms: now + 299000, policy_revision: 1, revoked: false};
  const offer = oracle({version: 1, origin: ORIGIN, purpose: 'public_beta_registration', ticket,
    public_key: publicKey, nonce: randomBytes(32).toString('hex'), issued_at_ms: now, expires_at_ms: now + 300000}).offer;
  const callback = {version: 'v2', project_id: project, policy_id: 'public_beta_' + releaseId,
    key_id: 'beta_v1', key_hex: randomBytes(32).toString('hex'), signature_window_sec: 300};
  const policy = {version: 'v2', tenant: project, policy_id: callback.policy_id, revision: 1, rotations: {},
    keys: {beta_v1: {key_id: 'beta_v1', introduced_revision: 1, active_from_sec: Math.floor(profile.opens_at_ms / 1000),
      sign_until_sec: profile.callback_end_sec, verify_until_sec: profile.callback_end_sec + 300, revoked_at_sec: null}}};
  const requests = [], endpoints = new Map(), proofs = new Map(), installed = new Map(), tasks = new Map(), admissions = new Map();
  let receipt, completionLost = loseCompletion, taskLost = loseTask;
  const fail = status => Response.json({code: 'synthetic_rejection'}, {status});
  const fetchImpl = async (address, init) => {
    const route = new URL(address).pathname, input = init.body === undefined ? undefined : JSON.parse(init.body);
    assert.equal(new URL(address).origin, ORIGIN); assert.equal(new URL(address).search, '');
    assert.equal(init.redirect, 'manual'); assert.ok(init.signal instanceof AbortSignal);
    requests.push({route, ...init}); assert.ok(requests.length <= 70);
    if (route === '/v1/beta') { assert.equal(init.method, 'GET'); assert.deepEqual(init.headers, {}); return Response.json(betaStatus()); }
    if (route === '/v1/registration/challenge') {
      assert.deepEqual(input, {public_key: publicKey});
      return Response.json(mutateOffer ? mutateOffer(structuredClone(offer)) : offer);
    }
    if (route === '/v1/registration/complete') {
      assert.deepEqual(Object.keys(input).sort(), ['challenge_id', 'signature']); assert.equal(input.challenge_id, offer.challenge_id);
      assert.ok(verify(null, Buffer.from(offer.canonical_utf8), pair.publicKey, Buffer.from(input.signature, 'hex')));
      receipt ??= {ticket_id: id, project_id: project, public_key: publicKey, grant_id: ticket.grant_id,
        enrolled_at_ms: now, expires_at_ms: now + 604800000, attempt_units: 100, permissions: [...PUBLIC_BETA_TERMS.permissions]};
      if (completionLost) { completionLost = false; throw Error('untrusted private data must not surface'); }
      return Response.json(mutateReceipt ? mutateReceipt(structuredClone(receipt)) : receipt, {status: 201});
    }
    if (route === '/v1/registration/recover') {
      assert.deepEqual(Object.keys(input).sort(), ['expires_at_ms', 'issued_at_ms', 'nonce', 'project_id', 'public_key', 'signature']);
      assert.equal(input.project_id, project); assert.equal(input.public_key, publicKey);
      const wire = 'RunLater invitation recovery v1\n' + JSON.stringify([1, ORIGIN, project, publicKey, input.nonce, input.issued_at_ms, input.expires_at_ms]);
      assert.ok(verify(null, Buffer.from(wire), pair.publicKey, Buffer.from(input.signature, 'hex')));
      return receipt ? Response.json(mutateRecovery ? mutateRecovery(structuredClone(receipt)) : receipt) : fail(403);
    }
    assert.equal(init.headers['RunLater-Project-Id'], project); assert.equal(init.headers['RunLater-Public-Key'], publicKey);
    assert.equal(init.headers.Authorization, undefined);
    const at = Number(init.headers['RunLater-Issued-At']), exp = Number(init.headers['RunLater-Expires-At']);
    const wire = 'RunLater signed request v1\n' + JSON.stringify([1, ORIGIN, project, publicKey, init.method, route, '', hash(init.body ?? ''),
      init.headers['Idempotency-Key'] ?? '', at, exp, init.headers['RunLater-Nonce']]);
    assert.equal(exp - at, 60000);
    assert.ok(verify(null, Buffer.from(wire), pair.publicKey, Buffer.from(init.headers['RunLater-Request-Signature'], 'hex')));
    if (route === '/v1/callback-key') {
      assert.deepEqual(input, {}); assert.ok(init.headers['Idempotency-Key']);
      return Response.json(mutateKey ? mutateKey(structuredClone(callback)) : callback, {headers: {'Cache-Control': 'no-store, private'}});
    }
    if (route.startsWith('/v1/destinations/')) {
      const definition = destinationContract.destination_commands['POST ' + route];
      assert.ok(definition); assert.equal(definition.permission, 'manage_destinations');
      assert.ok(validateDestination(input)); assert.deepEqual(Object.keys(input).sort(), [...definition.required].sort());
      assert.ok(init.headers['Idempotency-Key']); const slot = input.endpoint_id + '/' + input.version;
      if (route.endsWith('/create')) {
        endpoints.set(slot, {endpoint_id: input.endpoint_id, version: input.version, url: input.url, status: 'pending',
          created_at_ms: now, verified_at_ms: null, revoked_at_ms: null}); return Response.json(endpoints.get(slot));
      }
      const e = endpoints.get(slot); if (!e) return fail(404);
      if (route.endsWith('/prepare')) {
        const response = 'RunLater destination proof v1\n' + JSON.stringify([1, project, e.endpoint_id, e.version, e.url, 1, now + 300000, randomBytes(32).toString('hex')]);
        const proof = {id: hash(response), response, expires_at_ms: now + 300000}; proofs.set(slot, proof);
        return Response.json(mutateProof ? mutateProof(structuredClone(proof)) : proof);
      }
      if (route.endsWith('/verify')) {
        const p = proofs.get(slot); if (installed.get(p?.id) !== p?.response || !p) return fail(503);
        e.status = 'verified'; e.verified_at_ms = now; return Response.json(e);
      }
      for (const value of endpoints.values()) if (value.endpoint_id === input.endpoint_id) value.status = 'revoked';
      return Response.json({revoked: true});
    }
    if (route === '/v1/tasks') {
      const previous = admissions.get(init.headers['Idempotency-Key']);
      if (previous) return previous.bytes === init.body ? Response.json({...previous.value, created: false, replayed: true}) : fail(409);
      const id = input.destination.slice('registered:'.length);
      const selected = [...endpoints.values()].filter(e => e.endpoint_id === id).sort((a, b) => b.version - a.version)[0];
      if (selected?.status !== 'verified') return fail(503);
      const task = {id: taskId(tasks.size + 1), status: 'scheduled'}, value = {created: true, replayed: false, result: task};
      tasks.set(task.id, {task, input, selection: structuredClone(selected)}); admissions.set(init.headers['Idempotency-Key'], {bytes: init.body, value});
      if (taskLost) { taskLost = false; throw Error('lost accepted-task response'); } return Response.json(value, {status: 201});
    }
    const t = tasks.get(route.split('/')[3]); if (!t) return fail(404);
    if (route.endsWith('/cancel')) { assert.deepEqual(input, {}); assert.equal(init.headers['Idempotency-Key'], undefined); t.task.status = 'cancelled'; }
    if (route.endsWith('/redrive')) { assert.deepEqual(input, {}); assert.ok(init.headers['Idempotency-Key']); }
    return Response.json({result: t.task});
  };
  const client = new PublicBetaClientV1({privateKey: pair.privateKey, fetchImpl, releaseId, clock: () => now});
  return {pair, client, fetchImpl, requests, offer, callback, policy, ticket, tasks,
    install: proof => installed.set(proof.id, proof.response)};
}
async function enroll(f) { return f.client.complete(await f.client.challenge(), PUBLIC_BETA_TERMS); }

test('actual Rust public proof and release-derived ID match despite ticket JSON order; approval is explicit', async () => {
  const f = mock(); const o = await f.client.challenge();
  o.challenge.ticket = Object.fromEntries(Object.entries(o.challenge.ticket).reverse());
  assert.equal(oracle(o.challenge).ticket_id, o.challenge.ticket.id);
  await assert.rejects(f.client.complete(o, {...PUBLIC_BETA_TERMS, attempt_units: 101}), /unexpected_terms/);
  assert.equal(f.requests.length, 1); await f.client.complete(o, PUBLIC_BETA_TERMS);
  assert.equal(f.client.project, f.client.expectedProject); assert.equal(f.client.receipt.attempt_units, 100);
});
test('mock self-service flow: status, signup/recover, scoped key, private proof, immutable selection, signed status/cancel/revoke', async () => {
  const f = mock(); assert.equal((await f.client.status()).remaining_projects, 10);
  const receipt = await enroll(f); assert.deepEqual(await f.client.recover(), receipt);
  const callbackKey = await f.client.callbackKey('own_key_1');
  const bindings = receiverSetup({receipt, callbackKey, callbackPolicy: f.policy, url});
  assert.equal(JSON.parse(bindings.CALLBACK_KEYS).beta_v1, callbackKey.key_hex);
  assert.throws(() => receiverSetup({receipt, callbackKey, url}), /reviewed_receiver_policy_required/);
  assert.throws(() => receiverSetup({callbackPolicy: f.policy, url}), /reviewed_receiver_policy_required/);
  assert.throws(() => receiverSetup({receipt, callbackKey: {...callbackKey, key_hex: '01'.repeat(32)}, callbackPolicy: f.policy, url}), /reviewed_receiver_policy_required/);
  const e1 = await f.client.createDestination('owned', 1, url, 'create_1');
  const proof = await f.client.prepareDestination(e1, 'proof_1'); assert.equal(proof.expires_at_ms - now, 300000);
  await assert.rejects(f.client.verifyDestination(e1, 'before_install'), e => e.status === 503);
  f.install(proof); await f.client.verifyDestination(e1, 'verify_1');
  const input = {endpoint_id: 'owned', body: '{"synthetic":true}', operation_key: 'business_1', run_at_ms: now + 3600000};
  const accepted = await f.client.enqueue(input, 'task_1');
  const e2 = await f.client.createDestination('owned', 2, url, 'create_2');
  f.install(await f.client.prepareDestination(e2, 'proof_2')); await f.client.verifyDestination(e2, 'verify_2');
  assert.equal((await f.client.enqueue(input, 'task_1')).replayed, true);
  assert.equal(f.tasks.get(accepted.result.id).selection.version, 1);
  const latest = await f.client.enqueue({...input, operation_key: 'business_2'}, 'task_2');
  assert.equal(f.tasks.get(latest.result.id).selection.version, 2);
  assert.equal((await f.client.task(accepted.result.id)).result.status, 'scheduled');
  assert.equal((await f.client.cancel(accepted.result.id)).result.status, 'cancelled');
  await f.client.redrive(accepted.result.id, 'deliberate_redrive'); await f.client.revokeDestination('owned', 1, 'revoke_all');
  assert.equal(f.requests.some(r => r.route.startsWith('/registration/')), false);
});
test('lost responses cause no automatic retry or grant refill; deliberate completion/task retries preserve identity', async () => {
  const f = mock({loseCompletion: true, loseTask: true}), offer = await f.client.challenge();
  await assert.rejects(f.client.complete(offer, PUBLIC_BETA_TERMS), /transport_uncertain/); assert.equal(f.requests.length, 2);
  const receipt = await f.client.recover(); assert.equal(receipt.attempt_units, 100);
  assert.deepEqual(await f.client.complete(offer, PUBLIC_BETA_TERMS), receipt);
  const e = await f.client.createDestination('owned', 1, url, 'create');
  f.install(await f.client.prepareDestination(e, 'prepare')); await f.client.verifyDestination(e, 'verify');
  const input = {endpoint_id: 'owned', body: 'same bytes', operation_key: 'same_op', run_at_ms: now + 1000};
  await assert.rejects(f.client.enqueue(input, 'same_task'), /transport_uncertain/);
  assert.equal((await f.client.enqueue(input, 'same_task')).replayed, true); assert.equal(f.tasks.size, 1);
  const reload = new PublicBetaClientV1({privateKey: f.pair.privateKey, releaseId, receipt, fetchImpl: f.fetchImpl, clock: () => now});
  assert.deepEqual(await reload.recover(), receipt);
});
test('wrong release, purpose/origin, suffix-only ticket substitution, terms and canonical bytes never get signed', async () => {
  const mutations = [o => {o.challenge.purpose = 'invitation_enrollment';}, o => {o.challenge.origin = 'https://other.test';},
    o => {o.challenge.ticket.id = o.challenge.ticket.id.slice(0, 63) + (o.challenge.ticket.id.endsWith('0') ? '1' : '0');}, o => {o.challenge.public_key = '0'.repeat(64);},
    o => {o.challenge.ticket.terms.permissions.pop();}, o => {o.challenge.ticket.terms.attempt_units++;},
    o => {o.challenge.expires_at_ms = now;}, o => {o.challenge.nonce = 'invalid';}, o => {o.canonical_utf8 += ' ';}];
  for (const mutate of mutations) {
    const f = mock({mutateOffer: o => {mutate(o); return o;}}); await assert.rejects(f.client.challenge(), PublicBetaClientError);
    assert.equal(f.requests.length, 1); assert.equal(f.client.project, null);
  }
  const f = mock(), wrong = new PublicBetaClientV1({privateKey: f.pair.privateKey, releaseId: 'other_release', fetchImpl: f.fetchImpl, clock: () => now});
  await assert.rejects(wrong.challenge(), PublicBetaClientError); assert.equal(f.requests.length, 1);
});
test('full receipt/known recovery and callback-key context reject substitution, expansion and material placeholders', async () => {
  for (const mutate of [r => {r.ticket_id = r.ticket_id.slice(0, 63) + (r.ticket_id.endsWith('0') ? '1' : '0');}, r => {r.project_id = 'other';},
    r => {r.public_key = '0'.repeat(64);}, r => {r.attempt_units++;}, r => {r.expires_at_ms++;}, r => {r.permissions.pop();}]) {
    const f = mock({mutateReceipt: r => {mutate(r); return r;}}); await assert.rejects(enroll(f), PublicBetaClientError); assert.equal(f.client.project, null);
  }
  const f = mock({mutateRecovery: r => {r.ticket_id = r.ticket_id.slice(0, 63) + (r.ticket_id.endsWith('0') ? '1' : '0'); return r;}}); await enroll(f);
  await assert.rejects(f.client.recover(), PublicBetaClientError);
  for (const mutate of [k => {k.project_id = 'other';}, k => {k.policy_id += '_other';}, k => {k.key_id = 'other';},
    k => {k.signature_window_sec++;}, k => {k.key_hex = '01'.repeat(32);}, k => {k.master = 'forbidden';}]) {
    const f = mock({mutateKey: k => {mutate(k); return k;}}); await enroll(f); await assert.rejects(f.client.callbackKey('own_key'), /invalid_callback_key/);
  }
});
test('existing grant may have an expired original ticket while the new public challenge remains valid', async () => {
  const f = mock(); const receipt = await enroll(f), at = now + 600000;
  const fresh = oracle({...f.offer.challenge, issued_at_ms: at, expires_at_ms: at + 300000}).offer;
  const client = new PublicBetaClientV1({privateKey: f.pair.privateKey, releaseId, clock: () => at,
    fetchImpl: async (_, init) => init.body.includes('signature') ? Response.json(receipt) : Response.json(fresh)});
  assert.deepEqual(await client.complete(await client.challenge(), PUBLIC_BETA_TERMS), receipt);
});
test('five-minute static proof checks full tenant/version/url/nonce/digest and canonical bytes', async () => {
  for (const mutate of [t => {t[1] = 'other';}, t => {t[3]++;}, t => {t[4] += '/other';}, t => {t[5] = 4;},
    t => {t[6] = now + 300001;}, t => {t[7] = 'bad';}]) {
    const f = mock({mutateProof: p => {const t = JSON.parse(p.response.split('\n')[1]); mutate(t);
      p.response = 'RunLater destination proof v1\n' + JSON.stringify(t); p.id = hash(p.response); p.expires_at_ms = t[6]; return p;}});
    await enroll(f); const e = await f.client.createDestination('owned', 1, url, 'create');
    await assert.rejects(f.client.prepareDestination(e, 'prepare'), PublicBetaClientError);
  }
});
test('invalid endpoint/task/command and enrollment context causes no requests', async () => {
  const f = mock(); await assert.rejects(f.client.callbackKey('key'), /enrollment_required/); assert.equal(f.requests.length, 0);
  await enroll(f); const n = f.requests.length;
  for (const target of ['https://127.0.0.1/callback', 'https://account.workers.dev/callback',
    'https://custom.example/callback', 'https://extra.worker.account.workers.dev/callback', url + '?q=1']) {
    await assert.rejects(f.client.createDestination('owned', 1, target, 'create'), /invalid_endpoint/);
  }
  await assert.rejects(f.client.callbackKey(''), /idempotency_key_required/);
  assert.throws(() => f.client.enqueue({endpoint_id: 'owned', body: 'body', operation_key: 'op', run_at_ms: now + 604800001}, 'task'), /invalid_task/);
  assert.throws(() => f.client.enqueue({endpoint_id: 'owned', body: 'body', operation_key: 'op', run_at_ms: now, version: 1}, 'task'), /invalid_task/);
  assert.equal(f.requests.length, n);
  let at = now;
  const reload = new PublicBetaClientV1({privateKey: f.pair.privateKey, releaseId, receipt: f.client.receipt,
    fetchImpl: f.fetchImpl, clock: () => at});
  at = f.client.receipt.expires_at_ms;
  await assert.rejects(reload.callbackKey('after_expiry'), /identity_expired/); assert.equal(f.requests.length, n);
});
test('bounded transport rejects redirects/errors/invalid JSON/UTF8/chunks/size/deadline without exposing response data', async () => {
  const privateText = randomBytes(32).toString('hex');
  const cases = [() => new Response(privateText, {status: 302, headers: {Location: 'https://attacker.test'}}),
    () => new Response(privateText, {status: 503}), () => new Response(privateText),
    () => new Response(new Uint8Array([255])), () => new Response('x'.repeat(32769)),
    () => new Response(new ReadableStream({start(c) {for (let i = 0; i < 33; i++) c.enqueue(Buffer.from(' ')); c.close();}})),
    () => new Response(new ReadableStream({start() {}, cancel() {}}))];
  for (const response of cases) {
    let calls = 0; const client = new PublicBetaClientV1({privateKey: generateKeyPairSync('ed25519').privateKey, releaseId,
      timeoutMs: 10, fetchImpl: async () => {calls++; return response();}});
    await assert.rejects(client.challenge(), e => e instanceof PublicBetaClientError && !String(e).includes(privateText)); assert.equal(calls, 1);
  }
});
test('public source contract/guide checks do not enable hosted alpha, default live transport or payments', () => {
  assert.equal(contract.origin, ORIGIN); assert.equal(contract.registration.purpose, 'public_beta_registration');
  assert.equal(contract.registration.proof_prefix, 'RunLater public registration proof v1\n');
  assert.equal(contract.callback_key.path, '/v1/callback-key'); assert.equal(contract.callback_key.permission, 'manage_destinations');
  assert.equal(contract.trial.duration_ms, PUBLIC_BETA_TERMS.identity_ms); assert.equal(contract.trial.attempt_units, PUBLIC_BETA_TERMS.attempt_units);
  assert.equal(contract.trial.lifetime_project_capacity, 10); assert.equal(contract.trial.lifetime_tasks_per_project, 16);
  assert.equal(contract.trial.lifetime_publications_per_project, 128);
  assert.throws(() => new PublicBetaClientV1(), /explicit_transport_required/);
  assert.throws(() => new PublicBetaClientV1({privateKey: generateKeyPairSync('ed25519').privateKey, fetchImpl() {}}), /reviewed_release_id_required/);
  for (const file of ['docs/PUBLIC-BETA-QUICKSTART-v1.md']) {
    const text = fs.readFileSync(path.join(root, file), 'utf8'); assert.match(text, /not activated/);
    for (const [, target] of text.matchAll(/\]\(([^)]+)\)/g)) if (!target.startsWith('https://'))
      assert.ok(fs.existsSync(path.resolve(root, path.dirname(file), target)), target);
  }
});
