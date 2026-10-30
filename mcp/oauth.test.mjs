import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {signDelegation, delegationPublicKey} from './delegation.mjs';
import {ownerChallenge, oauthConsentBytes, verifyOwnerApproval, normalizedAuthRequest} from './oauth-consent.mjs';
import {authorizeOwner} from './oauth-app.mjs';
import {createOAuthStorage} from './oauth-storage.mjs';
import {createOAuthScheduling} from './oauth-scheduling.mjs';

const hash = input => createHash('sha256').update(input).digest('hex');
export function oauthFixture() {
  const owner = generateKeyPairSync('ed25519'), gateway = generateKeyPairSync('ed25519');
  const ownerKey = delegationPublicKey(owner.privateKey), gatewayKey = delegationPublicKey(gateway.privateKey);
  const now = Date.now(), releaseId = 'offline_oauth_test', ticket = hash(JSON.stringify(['runlater.public-beta.registration.v1', releaseId, ownerKey]));
  const receipt = {ticket_id: ticket, project_id: 'p_' + ticket.slice(0, 60), grant_id: 'g_' + ticket.slice(0, 60),
    public_key: ownerKey, enrolled_at_ms: now - 1000, expires_at_ms: now - 1000 + 604800000, attempt_units: 100,
    permissions: ['enqueue', 'read', 'cancel', 'redrive', 'manage_destinations']};
  const config = {gatewayPublicKey: gatewayKey, releaseId, now,
    validateDelegation: async c => ({active: true, project_id: c.project_id, expires_at_ms: c.expires_at_ms, permissions: c.permissions})};
  const delegation = signDelegation({privateKey: owner.privateKey, receipt, releaseId, gatewayPublicKey: gatewayKey,
    permissions: ['enqueue', 'read'], delegationId: 'a'.repeat(64), issuedAtMs: now, expiresAtMs: now + 3600000});
  const request = {responseType: 'code', clientId: 'https://client.example.com/metadata', redirectUri: 'https://client.example.com/callback',
    scope: ['enqueue', 'read'], state: 'owner-started-request', codeChallenge: 'a'.repeat(43), codeChallengeMethod: 'S256',
    resource: 'https://mcp.runlater.io', issuer: 'https://mcp.runlater.io'};
  const challenge = ownerChallenge(request, 'h'.repeat(43), config);
  const approval = {delegation, consent_signature: sign(null, oauthConsentBytes(challenge, delegation), owner.privateKey).toString('hex')};
  return {owner, gateway, receipt, delegation, request, challenge, approval, config};
}
test('owner proof binds exact OAuth client, redirect, PKCE, scopes, state, handle and API certificate', () => {
  const f = oauthFixture();
  assert.deepEqual(verifyOwnerApproval(f.approval, f.challenge, f.config), f.delegation);
  for (const [field, value] of [['clientId', 'attacker'], ['redirectUri', 'https://attacker.example/callback'], ['state', 'other'], ['codeChallenge', 'b'.repeat(43)]]) {
    const changed = structuredClone(f.challenge); changed.request[field] = value;
    assert.throws(() => verifyOwnerApproval(f.approval, changed, f.config), field);
  }
  assert.throws(() => verifyOwnerApproval(f.approval, {...f.challenge, handle: 'x'.repeat(43)}, f.config));
  assert.throws(() => normalizedAuthRequest({...f.request, extra: 'ignored'}));
  assert.throws(() => normalizedAuthRequest({...f.request, redirectUri: 'javascript:alert(1)'}));
  assert.throws(() => normalizedAuthRequest({...f.request, codeChallengeMethod: 'plain'}));
  assert.throws(() => verifyOwnerApproval({...f.approval, private_key: 'never accept'}, f.challenge, f.config));
  assert.throws(() => verifyOwnerApproval(f.approval, f.challenge, {...f.config, gatewayPublicKey: 'b'.repeat(64)}));
  assert.throws(() => verifyOwnerApproval(f.approval, f.challenge, {...f.config, now: f.delegation.expires_at_ms}));
});
test('consent UI escapes metadata and only library-recovered approved request can issue a grant', async () => {
  const f = oauthFixture(); let grants = 0;
  const oauth = {parseAuthRequest: async () => f.request, describeConsent: async () => ({clientName: '<script>attack</script>', redirectIsLoopback: false}),
    beginConsent: async () => ({handle: f.challenge.handle, headers: new Headers({'Set-Cookie': 'binding=opaque'})}),
    approveConsent: async () => ({request: f.request, headers: new Headers()}),
    completeAuthorization: async options => {grants++; assert.deepEqual(options.props, {delegation: f.delegation}); return {redirectTo: 'https://client.example.com/callback?code=opaque'};}};
  const page = await authorizeOwner(new Request('https://mcp.runlater.io/authorize'), oauth, f.config);
  const html = await page.text(); assert.equal(page.status, 200); assert.ok(!html.includes('<script>attack')); assert.match(html, /&#60;script/);
  const post = (approval = f.approval, origin = 'https://mcp.runlater.io') => new Request('https://mcp.runlater.io/authorize', {
    method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded', Origin: origin},
    body: new URLSearchParams({handle: f.challenge.handle, decision: 'approve', approval: JSON.stringify(approval)})});
  assert.equal((await authorizeOwner(post(), oauth, f.config)).status, 302); assert.equal(grants, 1);
  assert.equal((await authorizeOwner(post(f.approval, 'https://attacker.example'), oauth, f.config)).status, 400);
  assert.equal((await authorizeOwner(post({...f.approval, consent_signature: '0'.repeat(128)}), oauth, f.config)).status, 400);
  assert.equal(grants, 1);
  assert.equal((await authorizeOwner(post(), oauth, {...f.config, validateDelegation: async () => ({active: false})})).status, 400);
  assert.equal(grants, 1);
});
test('OAuth storage is bounded, expires records, lists metadata and never accepts unlimited entries', async () => {
  const map = new Map(); let now = 100000;
  const storage = {get: async key => map.get(key), put: async (key, value) => map.set(key, value), delete: async key => map.delete(key),
    list: async ({prefix, limit}) => new Map([...map].filter(([key]) => key.startsWith(prefix)).slice(0, limit))};
  const kv = createOAuthStorage(storage, {clock: () => now, maxEntries: 2, maxBytes: 20});
  await kv.put('one', '{"test":1}', {expirationTtl: 60, metadata: {type: 'fixture'}});
  await kv.put('two', 'second');
  assert.deepEqual(await kv.get('one', {type: 'json'}), {test: 1});
  assert.equal((await kv.list({limit: 1})).list_complete, false);
  await assert.rejects(kv.put('three', 'third'));
  await assert.rejects(kv.put('one', 'x'.repeat(21)));
  now += 60000; assert.equal(await kv.get('one'), null);
  await kv.put('three', 'third'); assert.equal((await kv.list()).keys.length, 2);
});
test('anonymous consent storage cannot consume reserved grant/token capacity', async () => {
  const map = new Map();
  const storage = {get: async key => map.get(key), put: async (key, value) => map.set(key, value), delete: async key => map.delete(key),
    list: async ({prefix, limit}) => new Map([...map].filter(([key]) => key.startsWith(prefix)).slice(0, limit))};
  const kv = createOAuthStorage(storage);
  const outcomes = await Promise.allSettled(Array.from({length: 65}, (_, i) => kv.put('transaction:' + i, 'fixture')));
  assert.equal(outcomes.filter(r => r.status === 'fulfilled').length, 64);
  await kv.put('grant:project:one', 'fixture'); await kv.put('token:project:one:hash', 'fixture');
  assert.equal(map.size, 66);
  for (let i = 0; i < 30; i++) await kv.put('grant:project:more' + i, 'fixture');
  await assert.rejects(kv.put('grant:project:over', 'fixture'));
  await kv.put('grant:other_project:one', 'fixture');
});
test('slow hostile authorization does not hold token validation or another client lane', async () => {
  const scheduler = createOAuthScheduling(); let release;
  const slow = new Promise(resolve => {release = resolve;});
  const blocked = scheduler.critical('client:attacker', () => scheduler.network('setup', () => slow));
  assert.equal(await scheduler.validate(async () => 'existing_token'), 'existing_token');
  assert.equal(await scheduler.critical('client:owner', () => scheduler.network('token', async () => 'revoked')), 'revoked');
  release(); await blocked;
});

test('bare browser authorization explains client-started Connect without touching OAuth state', async () => {
  let calls = 0;
  const oauth = new Proxy({}, {get() {calls++; throw Error('must_not_start_oauth');}});
  const response = await authorizeOwner(new Request('https://mcp.runlater.io/authorize', {
    headers: {Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'},
  }), oauth, {});
  assert.equal(response.status, 400);
  assert.match(response.headers.get('content-type'), /text\/html/);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(response.headers.get('location'), null);
  const html = await response.text();
  assert.match(html, /Start in your agent app/);
  assert.match(html, /https:\/\/mcp.runlater.io\/mcp/);
  assert.match(html, /https:\/\/docs.runlater.io\/#connect/);
  assert.doesNotMatch(html, /<form|<button|client_id=|code_challenge=/);
  assert.equal(calls, 0);
});

test('browser guidance never accepts partial OAuth input or changes machine errors', async () => {
  let parsed = 0;
  const oauth = {parseAuthRequest: async () => {parsed++; throw Error('invalid_oauth_fixture');}};
  for (const [suffix, accept] of [['', 'application/json'], ['', '*/*'], ['', 'text/html;q=0'],
    ['?client_id=incomplete', 'text/html'], ['?redirect_uri=https://attacker.example/callback', 'text/html']]) {
    const response = await authorizeOwner(new Request('https://mcp.runlater.io/authorize' + suffix,
      {headers: {Accept: accept}}), oauth, {});
    assert.equal(response.status, 400);
    assert.match(response.headers.get('content-type'), /application\/json/);
    assert.deepEqual(await response.json(), {error: 'invalid_request'});
    assert.equal(response.headers.get('set-cookie'), null);
    assert.equal(response.headers.get('location'), null);
  }
  assert.equal(parsed, 5);
});
