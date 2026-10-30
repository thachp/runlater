// All authority here is synthetic and offline; no live trial is allocated.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, verify} from 'node:crypto';
import {AnonymousTrialClientV1, canonicalTrialDescriptor, trialProjectId} from './trial-client.mjs';
import {PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
const NOW = 1800000000000, hash = value => createHash('sha256').update(value).digest('hex');
function fixture(scopes = ['cancel', 'enqueue', 'read']) {
  const gateway = generateKeyPairSync('ed25519'), capability = '11'.repeat(32), revocationSecret = '22'.repeat(32);
  const release = 'offline_trial', bootstrap = '33'.repeat(32);
  const digest = (purpose, secret) => hash(`RunLater anonymous trial ${purpose} v1\n` + JSON.stringify([1, release, bootstrap, secret]));
  const descriptor = {version: 1, release_id: release, bootstrap_id: bootstrap, capability_hash: digest('capability', capability),
    revocation_hash: digest('revocation', revocationSecret), issued_at_ms: NOW, expires_at_ms: NOW + 604800000, permissions: scopes};
  const status = {state: 'active', project_id: trialProjectId(descriptor), expires_at_ms: descriptor.expires_at_ms,
    permissions: scopes, receiver_ready: false, attempt_units: 100, client_operations_limit: 1000};
  const calls = [], options = {privateKey: gateway.privateKey, descriptor, capability, releaseId: release,
    clock: () => NOW, nonce: () => '44'.repeat(32), fetchImpl: async (url, init) => {calls.push({url, init});
      return Response.json(url.endsWith('/revoke') ? {revoked: true, provisioned: true} : url.includes('/trials/') ? status : {ok: true});}};
  return {gateway, descriptor, capability, revocationSecret, status, calls, options, client: new AnonymousTrialClientV1(options)};
}
test('trial lifecycle and task wire binds immutable descriptor, dedicated secret and exact request', async () => {
  const f = fixture(), input = {endpoint_id: 'owned', body: '{}', operation_key: 'stable', run_at_ms: 0};
  await f.client.provision(); await f.client.status(); await f.client.validate();
  await f.client.enqueue(input, 'stable'); await f.client.task('task_0000000000000001'); await f.client.cancel('task_0000000000000001');
  const revoker = new AnonymousTrialClientV1({...f.options, capability: undefined, revocationSecret: f.revocationSecret});
  await revoker.revoke();
  for (const {url, init} of f.calls) {
    const h = init.headers, revoke = url.endsWith('/revoke'), d = f.descriptor;
    assert.equal(init.redirect, 'manual'); assert.equal(h.Authorization, undefined); assert.equal(h['RunLater-Public-Key'], undefined);
    assert.equal(h['RunLater-MCP-Delegation'], undefined); assert.equal(h['RunLater-Trial-Capability'], revoke ? undefined : f.capability);
    assert.equal(h['RunLater-Trial-Revocation'], revoke ? f.revocationSecret : undefined);
    const encoded = Buffer.from(h['RunLater-Trial-Bootstrap'], 'base64url').toString(); assert.equal(encoded, JSON.stringify(d));
    const wire = 'RunLater anonymous trial request v1\n' + JSON.stringify([1, 'https://api.runlater.io', d.release_id,
      f.status.project_id, d.bootstrap_id, d.capability_hash, hash(encoded), init.method, new URL(url).pathname, '',
      hash(init.body ?? ''), h['Idempotency-Key'] ?? '', NOW, NOW + 60000, '44'.repeat(32)]);
    assert.ok(verify(null, Buffer.from(wire), f.gateway.publicKey, Buffer.from(h['RunLater-Request-Signature'], 'hex')));
  }
  assert.equal(f.calls[0].init.headers['Idempotency-Key'], f.descriptor.bootstrap_id);
  assert.equal(f.calls[1].init.body, undefined); assert.equal(f.calls[2].init.headers['Idempotency-Key'], undefined);
  assert.equal(f.calls[6].init.headers['Idempotency-Key'], f.descriptor.bootstrap_id);
});
test('capability and revocation authority are non-interchangeable and scope cannot be expanded by reference', async () => {
  const f = fixture(['read']); f.descriptor.permissions.push('enqueue');
  await assert.rejects(f.client.enqueue({endpoint_id: 'owned', body: '{}', operation_key: 'stable', run_at_ms: 0}, 'stable'), /insufficient_scope/);
  await assert.rejects(f.client.revoke(), /insufficient_scope/);
  const revoker = new AnonymousTrialClientV1({...f.options, descriptor: {...f.descriptor, permissions: ['read']}, capability: undefined, revocationSecret: f.revocationSecret});
  await assert.rejects(revoker.provision(), /insufficient_scope/); await assert.rejects(revoker.task('task_0000000000000001'), /insufficient_scope/);
  for (const change of [{capability: f.revocationSecret}, {revocationSecret: f.revocationSecret}, {capability: undefined}, {releaseId: 'other'}]) {
    assert.throws(() => new AnonymousTrialClientV1({...f.options, ...change}), PublicBetaClientError);
  }
  assert.equal(f.calls.length, 0);
});
test('descriptor rejects malformed, expanded, overflow and reordered permissions', () => {
  const f = fixture();
  for (const change of [{version: 2}, {release_id: ''}, {release_id: 1}, {extra: true}, {bootstrap_id: 'AA'.repeat(32)},
    {issued_at_ms: -1}, {expires_at_ms: NOW + 604800001}, {permissions: []}, {permissions: ['read', 'cancel']},
    {permissions: ['read', 'read']}, {permissions: ['manage_destinations']}]) assert.throws(() => canonicalTrialDescriptor({...f.descriptor, ...change}));
  assert.throws(() => new AnonymousTrialClientV1({...f.options, clock: () => NOW + 604800000}), /identity_expired/);
});
test('lifecycle rejects wrong project, reset expiry, false receiver readiness and extra secret fields', async () => {
  const f = fixture();
  for (const change of [{project_id: 'p_' + '0'.repeat(60)}, {expires_at_ms: NOW + 604800001}, {receiver_ready: true},
    {capability: f.capability}, {attempt_units: 101}, {state: 'unprovisioned'}, {permissions: ['read']}]) {
    const client = new AnonymousTrialClientV1({...f.options, fetchImpl: async () => Response.json({...f.status, ...change})});
    await assert.rejects(client.status(), /invalid_trial_response/);
  }
});
test('lost provisioning response never automatically retries or creates a new bootstrap', async () => {
  const f = fixture(), calls = []; let counter = 0;
  const client = new AnonymousTrialClientV1({...f.options, nonce: () => String(++counter).padStart(64, '0'),
    fetchImpl: async (url, init) => {calls.push(init); if (calls.length === 1) throw new Error('SECRET'); return Response.json(f.status);}});
  await assert.rejects(client.provision(), error => error.code === 'transport_uncertain' && !String(error).includes('SECRET'));
  assert.equal(calls.length, 1); await client.provision();
  assert.equal(calls[0].body, calls[1].body);
  for (const name of ['Idempotency-Key', 'RunLater-Trial-Bootstrap', 'RunLater-Trial-Capability']) assert.equal(calls[0].headers[name], calls[1].headers[name]);
  assert.notEqual(calls[0].headers['RunLater-Nonce'], calls[1].headers['RunLater-Nonce']);
});
