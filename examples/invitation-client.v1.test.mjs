// Offline protocol mocks, not Cloudflare/receiver delivery evidence. No global fetch is used.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, createPublicKey, generateKeyPairSync, randomBytes, verify} from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync, spawnSync} from 'node:child_process';
import Ajv from 'ajv';
import {InvitationClientV1, InvitationClientError, ORIGIN, loadOwnerKey, loadInvitationToken,
  readOwnerText, writeOwnerJson} from './invitation-client.v1.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const hash = value => createHash('sha256').update(value).digest('hex');
const now = 1900000000000;
const scopes = ['enqueue', 'read', 'cancel', 'redrive', 'manage_destinations'];
const agreed = {attempt_units: 20, identity_ms: 3600000, permissions: scopes}; // engineering fixture, not a trial offer
const url = 'https://owned.example.test/callback';
const taskId = n => 'task_' + n.toString(16).padStart(16, '0');
const contract = JSON.parse(fs.readFileSync(path.join(root, 'contracts/invitation-v1.json')));
const validateDestination = new Ajv({strict: true}).compile(contract.request_schema);
const rustc = execFileSync('rustup', ['which', 'rustc', '--toolchain', '1.92.0'], {encoding: 'utf8'}).trim();
const build = spawnSync('rustup', ['run', '1.92.0', 'cargo', 'build', '--locked', '--quiet', '--example', 'invitation_client_v1_vectors'],
  {cwd: root, encoding: 'utf8', env: {...process.env, RUSTC: rustc}});
assert.equal(build.status, 0, build.stderr);
const oracle = challenge => JSON.parse(execFileSync(path.join(root, 'target/debug/examples/invitation_client_v1_vectors'),
  {input: JSON.stringify(challenge), encoding: 'utf8'})); // stdin contains only public metadata, never token/private key
const publicObject = raw => createPublicKey({key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(raw, 'hex')]), type: 'spki', format: 'der'});

function mock({mutateOffer, mutateReceipt, mutateRecovery, mutateProof, loseCompletion = false, timeoutMs = 5000} = {}) {
  const pair = generateKeyPairSync('ed25519'), publicKey = pair.publicKey.export({type: 'spki', format: 'der'}).subarray(-32).toString('hex');
  const token = randomBytes(32).toString('hex'), id = hash(token), project = 'p_' + id.slice(0, 60);
  const ticket = {id, project_id: project, grant_id: 'g_' + id.slice(0, 60), terms: structuredClone(agreed),
    issued_at_ms: now - 1000, expires_at_ms: now + 3600000, policy_revision: 1, revoked: false};
  const offer = oracle({version: 1, origin: ORIGIN, purpose: 'invitation_enrollment', ticket,
    public_key: publicKey, nonce: randomBytes(32).toString('hex'), issued_at_ms: now, expires_at_ms: now + 300000});
  const requests = [], proofRequests = [], endpoints = new Map(), proofs = new Map(), installed = new Map(), tasks = new Map(), admissions = new Map();
  let receipt, lost = loseCompletion;
  const httpError = status => Response.json({error: {code: 'mock_rejected'}}, {status});
  function signature(headers, method, route, bytes) {
    assert.equal(headers['RunLater-Project-Id'], project);
    assert.equal(headers['RunLater-Public-Key'], publicKey);
    assert.equal(headers.Authorization, undefined);
    const wire = 'RunLater signed request v1\n' + JSON.stringify([1, ORIGIN, project, publicKey, method, route, '', hash(bytes),
      headers['Idempotency-Key'] ?? '', Number(headers['RunLater-Issued-At']), Number(headers['RunLater-Expires-At']), headers['RunLater-Nonce']]);
    assert.equal(verify(null, Buffer.from(wire), pair.publicKey, Buffer.from(headers['RunLater-Request-Signature'], 'hex')), true);
    assert.equal(Number(headers['RunLater-Expires-At']) - Number(headers['RunLater-Issued-At']), 60000);
  }
  const fetchImpl = async (address, init) => {
    const parsed = new URL(address), route = parsed.pathname, body = init.body ? JSON.parse(init.body) : undefined;
    assert.equal(parsed.origin, ORIGIN); assert.equal(parsed.search, ''); assert.equal(init.redirect, 'manual');
    assert.ok(init.signal instanceof AbortSignal);
    requests.push({address, ...init}); assert.ok(requests.length <= 60);
    if (route === '/registration/challenge') {
      assert.deepEqual(body, {token, public_key: publicKey});
      return Response.json(mutateOffer ? mutateOffer(structuredClone(offer)) : offer);
    }
    if (route === '/registration/complete') {
      assert.deepEqual(Object.keys(body).sort(), ['challenge_id', 'signature', 'token']);
      assert.equal(body.token, token); assert.equal(body.challenge_id, offer.challenge_id);
      assert.ok(verify(null, Buffer.from(offer.canonical_utf8), pair.publicKey, Buffer.from(body.signature, 'hex')));
      receipt ??= {ticket_id: id, project_id: project, public_key: publicKey, grant_id: ticket.grant_id,
        enrolled_at_ms: now, expires_at_ms: now + agreed.identity_ms, attempt_units: agreed.attempt_units, permissions: scopes};
      if (lost) { lost = false; throw new Error('mock response lost after commit'); }
      return Response.json(mutateReceipt ? mutateReceipt(structuredClone(receipt)) : receipt, {status: 201});
    }
    if (route === '/registration/recover') {
      assert.deepEqual(Object.keys(body).sort(), ['expires_at_ms', 'issued_at_ms', 'nonce', 'project_id', 'public_key', 'signature']);
      assert.equal(body.project_id, project); assert.equal(body.public_key, publicKey);
      const wire = 'RunLater invitation recovery v1\n' + JSON.stringify([1, ORIGIN, project, publicKey, body.nonce, body.issued_at_ms, body.expires_at_ms]);
      assert.ok(verify(null, Buffer.from(wire), pair.publicKey, Buffer.from(body.signature, 'hex')));
      return receipt ? Response.json(mutateRecovery ? mutateRecovery(structuredClone(receipt)) : receipt) : httpError(403);
    }
    signature(init.headers, init.method, route, init.body ?? '');
    if (route.startsWith('/v1/destinations/')) {
      const command = contract.destination_commands['POST ' + route];
      assert.ok(command); assert.ok(validateDestination(body));
      assert.deepEqual(Object.keys(body).sort(), [...command.required].sort());
      assert.equal(command.permission, 'manage_destinations');
      assert.ok(init.headers['Idempotency-Key']);
      const slot = body.endpoint_id + '/' + body.version;
      if (route.endsWith('/create')) {
        const endpoint = {endpoint_id: body.endpoint_id, version: body.version, url: body.url, status: 'pending',
          created_at_ms: now, verified_at_ms: null, revoked_at_ms: null};
        if (endpoints.has(slot) && endpoints.get(slot).url !== body.url) return httpError(409);
        endpoints.set(slot, endpoints.get(slot) ?? endpoint); return Response.json(endpoints.get(slot));
      }
      const endpoint = endpoints.get(slot); if (!endpoint) return httpError(404);
      if (route.endsWith('/prepare')) {
        const response = 'RunLater destination proof v1\n' + JSON.stringify([1, project, body.endpoint_id, body.version,
          endpoint.url, 1, now + 60000, randomBytes(32).toString('hex')]);
        const proof = {id: hash(response), response, expires_at_ms: now + 60000}; proofs.set(slot, proof);
        return Response.json(mutateProof ? mutateProof(structuredClone(proof)) : proof);
      }
      if (route.endsWith('/verify')) {
        const proof = proofs.get(slot); if (!proof || !installed.has(proof.id)) return httpError(503);
        const request = 'RunLater destination verification v1\n' + JSON.stringify([project, body.endpoint_id, body.version, proof.id, proof.expires_at_ms]);
        proofRequests.push(request);
        assert.equal(request.includes(JSON.parse(proof.response.split('\n')[1])[7]), false);
        if (installed.get(proof.id) !== proof.response) return httpError(503);
        endpoint.status = 'verified'; endpoint.verified_at_ms = now; return Response.json(endpoint);
      }
      for (const value of endpoints.values()) if (value.endpoint_id === body.endpoint_id) value.status = 'revoked';
      return Response.json({revoked: true});
    }
    if (route === '/v1/tasks') {
      const previous = admissions.get(init.headers['Idempotency-Key']);
      if (previous) return previous.bytes === init.body ? Response.json({...previous.value, created: false, replayed: true}) : httpError(409);
      assert.deepEqual(Object.keys(body).sort(), ['body', 'destination', 'operation_key', 'run_at_ms']);
      const id = body.destination.slice('registered:'.length);
      const selected = [...endpoints.values()].filter(e => e.endpoint_id === id).sort((a, b) => b.version - a.version)[0];
      if (selected?.status !== 'verified') return httpError(503);
      const task = {id: taskId(tasks.size + 1), status: 'scheduled', input: body, attempts: []};
      tasks.set(task.id, {task, selection: structuredClone(selected)});
      const value = {created: true, replayed: false, result: task}; admissions.set(init.headers['Idempotency-Key'], {bytes: init.body, value});
      return Response.json(value, {status: 201});
    }
    const task = tasks.get(route.split('/')[3]); if (!task) return httpError(404);
    if (route.endsWith('/cancel')) { assert.deepEqual(body, {}); assert.equal(init.headers['Idempotency-Key'], undefined); task.task.status = 'cancelled'; }
    return Response.json({result: task.task});
  };
  const client = new InvitationClientV1({privateKey: pair.privateKey, fetchImpl, clock: () => now, timeoutMs});
  return {client, token, offer, project, pair, requests, proofRequests, tasks, fetchImpl,
    install: proof => installed.set(proof.id, proof.response), reflect: proof => installed.set(proof.id, 'reflected request')};
}
async function enrolled(f) { const offer = await f.client.challenge(f.token); return f.client.complete(f.token, offer, agreed); }

test('Rust-generated invitation canonical bytes are reconstructed despite JSON map reordering; approval is explicit', async () => {
  const f = mock(); const offer = await f.client.challenge(f.token);
  const reversed = Object.fromEntries(Object.entries(offer.challenge.ticket).reverse()); offer.challenge.ticket = reversed;
  await assert.rejects(f.client.complete(f.token, offer, {...agreed, attempt_units: 21}), /unexpected_terms/);
  assert.equal(f.requests.length, 1);
  const receipt = await f.client.complete(f.token, offer, agreed);
  assert.equal(receipt.project_id, f.project); assert.equal(f.client.project, f.project);
  assert.equal(receipt.attempt_units, 20);
});
test('offline mock journey: enrollment, owner-configured proof, immutable server version selection, signed status/cancel/revoke/recovery', async () => {
  const f = mock(); await enrolled(f);
  const endpoint = await f.client.createDestination('owned', 1, url, 'create_1');
  const proof = await f.client.prepareDestination(endpoint, 'prepare_1');
  await assert.rejects(f.client.verifyDestination('owned', 1, 'verify_before_setup'), e => e.status === 503);
  f.reflect(proof); await assert.rejects(f.client.verifyDestination('owned', 1, 'verify_echo'), e => e.status === 503);
  f.install(proof); await f.client.verifyDestination('owned', 1, 'verify_1');
  const input = {endpoint_id: 'owned', body: '{"synthetic":true}', operation_key: 'one_operation', run_at_ms: now + 60000};
  const accepted = await f.client.enqueue(input, 'task_1'); assert.equal(f.tasks.get(accepted.result.id).selection.version, 1);
  const next = await f.client.createDestination('owned', 2, url + '/v2', 'create_2');
  const proof2 = await f.client.prepareDestination(next, 'prepare_2'); f.install(proof2); await f.client.verifyDestination('owned', 2, 'verify_2');
  assert.equal((await f.client.enqueue(input, 'task_1')).replayed, true);
  assert.equal(f.tasks.get(accepted.result.id).selection.version, 1);
  const latest = await f.client.enqueue({...input, operation_key: 'second'}, 'task_2');
  assert.equal(f.tasks.get(latest.result.id).selection.version, 2);
  assert.equal((await f.client.task(accepted.result.id)).result.status, 'scheduled');
  assert.equal((await f.client.cancel(accepted.result.id)).result.status, 'cancelled');
  await f.client.revokeDestination('owned', 1, 'revoke_all_versions');
  assert.equal((await f.client.enqueue(input, 'task_1')).replayed, true);
  assert.equal((await f.client.recover(f.project)).project_id, f.project);
  assert.equal(f.proofRequests.length, 3); // one reflected response plus the two configured proofs
});
test('response loss never triggers automatic retry or new enrollment; caller can recover the original receipt', async () => {
  const f = mock({loseCompletion: true}); const offer = await f.client.challenge(f.token);
  await assert.rejects(f.client.complete(f.token, offer, agreed), /transport_uncertain/); assert.equal(f.requests.length, 2);
  const receipt = await f.client.recover(f.project); assert.equal(receipt.attempt_units, agreed.attempt_units);
  assert.equal(f.requests.length, 3); assert.equal(f.requests.filter(r => r.address.endsWith('/registration/complete')).length, 1);
});
test('challenge substitution, escalation, clock/expiry and canonical tampering are rejected before any proof submission', async () => {
  const mutations = [
    o => { o.challenge.origin = 'https://foreign.example'; }, o => { o.challenge.purpose = 'operator_alpha_enrollment'; },
    o => { o.challenge.ticket.project_id = 'other'; }, o => { o.challenge.ticket.grant_id = 'other'; },
    o => { o.challenge.ticket.id = randomBytes(32).toString('hex'); }, o => { o.challenge.public_key = randomBytes(32).toString('hex'); },
    o => { o.challenge.ticket.terms.permissions.push('configure'); }, o => { o.challenge.ticket.terms.permissions.reverse(); },
    o => { o.challenge.issued_at_ms = now + 1; }, o => { o.challenge.expires_at_ms = now; },
    o => { o.canonical_utf8 += '\n'; }, o => { o.challenge_id = randomBytes(32).toString('hex'); },
    o => { o.challenge.ticket.revoked = true; }, o => { o.challenge.nonce = 'not-hex'; },
  ];
  for (const change of mutations) {
    const f = mock({mutateOffer: offer => { change(offer); return offer; }});
    await assert.rejects(f.client.challenge(f.token), InvitationClientError); assert.equal(f.requests.length, 1);
  }
});
test('invalid caller inputs, task version overrides and fixture fields cause no network calls', () => {
  const f = mock();
  assert.throws(() => new InvitationClientV1({privateKey: f.pair.privateKey}), /explicit_transport/);
  assert.throws(() => f.client.enqueue({endpoint_id: 'owned', version: 1, body: '{}', operation_key: 'op', run_at_ms: 0}, 'k'));
  assert.throws(() => f.client.enqueue({endpoint_id: 'owned', body: '{}', operation_key: 'op', run_at_ms: 0, at_ms: now}, 'k'));
  assert.throws(() => f.client.task('../other')); assert.throws(() => f.client.cancel('task_1'));
  assert.equal(f.requests.length, 0);
});
test('substituted receipt cannot install another project or silently change agreed allocation/scopes', async () => {
  for (const change of [r => {r.project_id='other';}, r => {r.public_key=randomBytes(32).toString('hex');},
    r => {r.grant_id='other';}, r => {r.attempt_units++;}, r => {r.permissions=['read'];}, r => {r.expires_at_ms=now;}]) {
    const f=mock({mutateReceipt:r=>{change(r);return r;}}), offer=await f.client.challenge(f.token);
    await assert.rejects(f.client.complete(f.token,offer,agreed),InvitationClientError);
    assert.equal(f.client.project,null);
  }
});
function substituteTicketSuffix(receipt) {
  const original=receipt.ticket_id;
  receipt.ticket_id=original.slice(0,60)+(original.slice(-4)==='ffff'?'0000':'ffff');
  assert.notEqual(receipt.ticket_id,original);
  assert.equal(receipt.project_id,'p_'+receipt.ticket_id.slice(0,60));
  assert.equal(receipt.grant_id,'g_'+receipt.ticket_id.slice(0,60));
  return receipt;
}
test('suffix-only completion receipt substitution is rejected before installing project context', async () => {
  const f=mock({mutateReceipt:substituteTicketSuffix}),offer=await f.client.challenge(f.token);
  await assert.rejects(f.client.complete(f.token,offer,agreed),InvitationClientError);
  assert.equal(f.client.project,null);
});
test('recovery checks the full known ticket after completion, response loss and trusted receipt reload', async () => {
  for(const loseCompletion of [false,true]) {
    const f=mock({loseCompletion,mutateRecovery:substituteTicketSuffix}),offer=await f.client.challenge(f.token);
    if(loseCompletion)await assert.rejects(f.client.complete(f.token,offer,agreed),/transport_uncertain/);
    else await f.client.complete(f.token,offer,agreed);
    await assert.rejects(f.client.recover(f.project),InvitationClientError);
    assert.equal(f.client.project,loseCompletion?null:f.project);
    const restored=new InvitationClientV1({privateKey:f.pair.privateKey,fetchImpl:f.fetchImpl,
      project:f.project,ticketId:offer.challenge.ticket.id,clock:()=>now});
    await assert.rejects(restored.recover(f.project),InvitationClientError);
  }
  const good=mock();const receipt=await enrolled(good);
  const restored=new InvitationClientV1({privateKey:good.pair.privateKey,fetchImpl:good.fetchImpl,
    project:receipt.project_id,ticketId:receipt.ticket_id,clock:()=>now});
  assert.deepEqual(await restored.recover(good.project),receipt);
});
test('prepared proof is checked against exact tenant, endpoint, version, URL, expiry and digest before owner setup', async () => {
  for(const change of [t=>{t[1]='other';},t=>{t[2]='other';},t=>{t[3]=2;},t=>{t[4]=url+'/other';},t=>{t[6]=now;}]) {
    const f=mock({mutateProof:p=>{const t=JSON.parse(p.response.split('\n')[1]);change(t);p.response='RunLater destination proof v1\n'+JSON.stringify(t);p.id=hash(p.response);p.expires_at_ms=t[6];return p;}});
    await enrolled(f);const endpoint=await f.client.createDestination('owned',1,url,'create');
    await assert.rejects(f.client.prepareDestination(endpoint,'prepare'),InvitationClientError);
    assert.equal(f.proofRequests.length,0);
  }
});
test('malformed/unsafe URLs and missing command idempotency fail without sending', async () => {
  const f = mock(); await enrolled(f); const before = f.requests.length;
  for (const bad of ['http://owned.example.test/x', 'https://127.0.0.1/', 'https://[::1]/', 'https://u@owned.example.test/x', url + '?key=x', url + '#x', 'https://owned.example.test:443/callback']) {
    await assert.rejects(f.client.createDestination('owned', 1, bad, 'create'));
  }
  await assert.rejects(f.client.createDestination('owned', 1, url, ''), /idempotency/);
  assert.equal(f.requests.length, before);
});
test('HTTP errors/redirects are redacted; body/chunk/UTF-8 limits and whole-response deadlines terminate without retries', async () => {
  const pair = generateKeyPairSync('ed25519');
  for (const response of [new Response('PRIVATE_RESPONSE_MUST_NOT_ESCAPE', {status: 402}),
    new Response(null, {status: 302, headers: {Location: 'https://foreign.example'}}), new Response('x'.repeat(32769)),
    new Response(new ReadableStream({start(c) { for (let i = 0; i < 33; i++) c.enqueue(new Uint8Array([32])); c.close(); }})),
    new Response(new Uint8Array([255]))]) {
    let calls = 0;
    const c = new InvitationClientV1({privateKey: pair.privateKey, project: 'approved', fetchImpl: async () => { calls++; return response; }});
    await assert.rejects(c.task(taskId(1)), e => e instanceof InvitationClientError && !e.message.includes('PRIVATE_RESPONSE'));
    assert.equal(calls, 1);
  }
  for (const bodyDelay of [false, true]) {
    let calls = 0, signal;
    const c = new InvitationClientV1({privateKey: pair.privateKey, project: 'approved', timeoutMs: 20,
      fetchImpl: async (_url, init) => { calls++; signal = init.signal; return bodyDelay ? new Response(new ReadableStream({pull() { return new Promise(() => {}); }})) : new Promise(() => {}); }});
    await assert.rejects(c.task(taskId(1)), /transport_uncertain/); assert.equal(calls, 1); assert.equal(signal.aborted, true);
  }
});
test('owner-only key/token/proof storage refuses permissions, symlinks and overwrite; fixture secrets are ephemeral', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-invitation-client-'));
  try {
    const pem = path.join(dir, 'key.pem'), token = path.join(dir, 'invitation.txt'), proof = path.join(dir, 'proof.json');
    fs.writeFileSync(pem, generateKeyPairSync('ed25519').privateKey.export({format: 'pem', type: 'pkcs8'}), {mode: 0o600});
    fs.writeFileSync(token, randomBytes(32).toString('hex') + '\n', {mode: 0o600});
    assert.equal(loadOwnerKey(pem).type, 'private'); assert.equal(loadInvitationToken(token).length, 64);
    fs.chmodSync(pem, 0o644); assert.throws(() => loadOwnerKey(pem)); fs.chmodSync(pem, 0o600);
    fs.symlinkSync(token, path.join(dir, 'alias')); assert.throws(() => readOwnerText(path.join(dir, 'alias')));
    writeOwnerJson(proof, {response: randomBytes(32).toString('hex')}); assert.equal(fs.statSync(proof).mode & 0o777, 0o600);
    const previous = fs.readFileSync(proof); assert.throws(() => writeOwnerJson(proof, {})); assert.deepEqual(fs.readFileSync(proof), previous);
  } finally { fs.rmSync(dir, {recursive: true}); }
});

// Pinned published-alpha source bytes at the PR46 dependency; no live availability claim.
const publishedAlphaHashes = {
  "discovery/alpha.v1.json": "3304efdea45a6a74a2c33b13ce507a48cb6c2094f61e086697a9ffd592d89082",
  "discovery/alpha.v1.schema.json": "d20d12052511169011b4cc88a832af1b4428a2abdf1fd998067807302d14bb1e",
  "discovery/service.v1.json": "c5f18c7fb46e74ead07472271587903297d84d9c4c8657c8e8e9b02f5546472a",
  "discovery/pricing-status.v1.json": "b3b993c4af44e55ae00795d634dd955b4c24b3c823cce4e87e36b48fb1b5326e",
  "examples/alpha-quickstart.mjs": "8de88a85943243f0d63f94ad7eaa85c9f3bebb77675d1da1868fd7b54d4864eb",
  "web/docs/index.html": "d3a762e0866f919581ef4d6334bd47256c32e26b314850b2c4632a213906b1c5",
  "docs/AGENT-QUICKSTART.md": "9943f39d272807f2f08b75dccba4c0f4741840af765827b9fe404300c3ff998b",
  "docs/openapi.json": "0f6a658e18dff55ce391e75732987ca4e0f60a0f9b195793ce45aefcb533998e",
  "scripts/discovery.mjs": "44866017edfa9dd0801a9f977dfd30df148436afd72f97f5dc41b07fc92df1b7"
};
test('client/guide preserve published alpha assets and source-only contract; relative guide links resolve without network', () => {
  for (const [name, expected] of Object.entries(publishedAlphaHashes)) assert.equal(hash(fs.readFileSync(path.join(root, name))), expected, name);
  assert.equal(contract.schema_version, 'runlater.invitation.v1');
  assert.equal(contract.availability, 'source_only_disabled'); assert.equal(contract.origin, ORIGIN);
  assert.deepEqual(Object.keys(contract.destination_commands).sort(), ['create', 'prepare', 'verify', 'revoke'].map(action => 'POST /v1/destinations/' + action).sort());
  assert.equal(validateDestination({endpoint_id:'owned',version:1,complete_at_ms:now}), false);
  const file=path.join(root,'docs/INVITATION-QUICKSTART-v1.md'), guide=fs.readFileSync(file,'utf8');
  for(const m of guide.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
    if(m[1].startsWith('https://')) continue;
    const target=path.resolve(path.dirname(file),m[1].split('#')[0]);
    assert.ok(target.startsWith(root)); assert.ok(fs.existsSync(target),'missing source link '+m[1]);
  }
  assert.match(guide,/There is no task `version` field/);
  assert.match(guide,/reflection cannot verify/);
  assert.equal(guide.includes('v1'+String.fromCharCode(92).repeat(2)+'n'),false,'prefix notation must represent one newline');
  assert.match(guide,/no default network transport/);
  assert.doesNotMatch(guide,/BEGIN (?:ED25519 |RSA )?PRIVATE KEY/);
});
