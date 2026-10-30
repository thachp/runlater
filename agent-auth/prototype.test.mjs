import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {generateKeyPair, exportJWK, SignJWT} from 'jose';
import {createPrototype, ORIGIN, BASE} from './prototype.mjs';

async function fixture() {
  const app = createPrototype({enabled: true});
  const host = await generateKeyPair('EdDSA');
  const agent = await generateKeyPair('EdDSA');
  async function sign(key, typ, claims, audience = BASE, age = 45) {
    return new SignJWT(claims).setProtectedHeader({alg: 'EdDSA', typ})
      .setIssuedAt().setExpirationTime(Math.floor(Date.now()/1000)+age)
      .setAudience(audience).setJti(randomUUID()).sign(key);
  }
  const registration = {name: 'Ephemeral local agent', mode: 'autonomous', capabilities: ['trial_status']};
  const hostClaims = {iss: 'local-fixture-host', host_public_key: await exportJWK(host.publicKey), agent_public_key: await exportJWK(agent.publicKey)};
  const send = (path, token, body) => app.fetch(new Request(`${BASE}${path}`, {method: 'POST', headers: {'content-type': 'application/json', authorization: `Bearer ${token}`}, body: JSON.stringify(body)}));
  const registered = await send('/agent/register', await sign(host.privateKey, 'host+jwt', hostClaims), registration);
  const identity = await registered.json();
  assert.equal(registered.status, 200, JSON.stringify(identity));
  assert.equal(identity.status, 'active');
  const body = {capability: 'trial_status', arguments: {}};
  const claims = () => ({sub: identity.agent_id, capabilities: ['trial_status'], htm: 'POST', htu: `${BASE}/capability/execute`, ath: createHash('sha256').update(JSON.stringify(body)).digest('base64url')});
  return {app, agent, host, hostClaims, registration, identity, send, sign, body, claims};
}

test('default off', async () => assert.equal((await createPrototype().fetch(new Request(ORIGIN))).status, 503));
test('real plugin autonomous registration and bound capability execution', async () => {
  const f = await fixture();
  const response = await f.send('/capability/execute', await f.sign(f.agent.privateKey, 'agent+jwt', f.claims()), f.body);
  assert.equal(response.status, 200, await response.clone().text());
  assert.match(await response.text(), /provisioning_enabled/);
});
test('concurrent replay permits one execution', async () => {
  const f = await fixture();
  const token = await f.sign(f.agent.privateKey, 'agent+jwt', f.claims());
  const responses = await Promise.all([f.send('/capability/execute', token, f.body), f.send('/capability/execute', token, f.body)]);
  assert.deepEqual(responses.map(r=>r.status).sort(), [200,401]);
});
test('wrong audience, expired token, tampered body, missing binding and wrong key rejected', async () => {
  const f = await fixture();
  for (const [key, claims, aud, age, body] of [
    [f.agent.privateKey, f.claims(), 'https://other.invalid',45,f.body],
    [f.agent.privateKey, f.claims(), BASE,-120,f.body],
    [f.agent.privateKey, f.claims(), BASE,45,{...f.body,arguments:{tampered:true}}],
    [f.agent.privateKey, {sub:f.identity.agent_id, capabilities:['trial_status']},BASE,45,f.body],
    [f.host.privateKey,f.claims(),BASE,45,f.body],
    [f.agent.privateKey,{...f.claims(),htm:'GET'},BASE,45,f.body],
    [f.agent.privateKey,{...f.claims(),htu:BASE+'/other'},BASE,45,f.body],
  ]) {
    const response = await f.send('/capability/execute', await f.sign(key,'agent+jwt',claims,aud,age),body);
    assert.ok(response.status >= 400, `unexpected ${response.status}`);
  }
});
test('scope escalation, remote JWKS and delegated signup fail closed', async () => {
  const f = await fixture();
  for (const [claims, body] of [
    [f.hostClaims,{...f.registration,capabilities:['http_schedule']}],
    [{...f.hostClaims,agent_jwks_url:'http://127.0.0.1/keys'},f.registration],
    [f.hostClaims,{...f.registration,mode:'delegated'}],
  ]) assert.equal((await f.send('/agent/register',await f.sign(f.host.privateKey,'host+jwt',claims),body)).status,400);
});
test('server-side revocation prevents newly signed requests', async () => {
  const f = await fixture();
  f.app.db.agent.find(a=>a.id===f.identity.agent_id).status='revoked';
  assert.equal((await f.send('/capability/execute',await f.sign(f.agent.privateKey,'agent+jwt',f.claims()),f.body)).status,403);
});
test('grant revocation and expiry are enforced from storage', async () => {
  for (const mutate of [g=>{g.status='revoked';},g=>{g.expiresAt=new Date(0);}]) {
    const f = await fixture();
    mutate(f.app.db.agentCapabilityGrant.find(g=>g.agentId===f.identity.agent_id));
    assert.equal((await f.send('/capability/execute',await f.sign(f.agent.privateKey,'agent+jwt',f.claims()),f.body)).status,403);
  }
});
test('host revocation prevents execution and unknown capability cannot be executed', async () => {
  const f = await fixture();
  const other = {capability:'http_schedule',arguments:{}};
  const claims = {...f.claims(),capabilities:['http_schedule'],ath:createHash('sha256').update(JSON.stringify(other)).digest('base64url')};
  assert.ok((await f.send('/capability/execute',await f.sign(f.agent.privateKey,'agent+jwt',claims),other)).status>=400);
  f.app.db.agentHost.find(h=>h.id===f.identity.host_id).status='revoked';
  assert.equal((await f.send('/capability/execute',await f.sign(f.agent.privateKey,'agent+jwt',f.claims()),f.body)).status,403);
});
test('local discovery, host and path boundaries', async () => {
  const app = createPrototype({enabled:true});
  const config = await (await app.fetch(new Request(`${ORIGIN}/.well-known/agent-configuration`))).json();
  assert.deepEqual(config.modes,['autonomous']);
  assert.equal(config.default_location,`${BASE}/capability/execute`);
  assert.deepEqual(Object.keys(config.endpoints),['register','execute']);
  assert.equal((await app.fetch(new Request('https://mcp.runlater.io/.well-known/agent-configuration'))).status,403);
  assert.equal((await app.fetch(new Request(`${BASE}/host/create`))).status,404);
  assert.equal((await app.fetch(new Request(`${BASE}/agent/register`))).status,405);
});
