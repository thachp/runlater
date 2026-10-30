// Actual pinned OAuth library and real Durable Object storage in local workerd.
// Every key/client/API response is a disposable local fixture; no external calls.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {build} from 'esbuild';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import {fileURLToPath} from 'node:url';
import {signDelegation, delegationPublicKey} from './delegation.mjs';
import {oauthConsentBytes} from './oauth-consent.mjs';
import {authorizeFixture} from './oauth-test-helpers.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const decodeHTML = value => value.replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)));

test('real OAuth PKCE, owner consent, audience, replay, concurrent exchange and revocation', {timeout: 30000}, async t => {
  const owner = generateKeyPairSync('ed25519'), gateway = generateKeyPairSync('ed25519');
  const publicKey = delegationPublicKey(owner.privateKey), gatewayKey = delegationPublicKey(gateway.privateKey);
  const releaseId = 'oauth_runtime_fixture', now = Date.now();
  const ticket = hash(JSON.stringify(['runlater.public-beta.registration.v1', releaseId, publicKey]));
  const receipt = {ticket_id: ticket, project_id: 'p_' + ticket.slice(0, 60), grant_id: 'g_' + ticket.slice(0, 60), public_key: publicKey,
    enrolled_at_ms: now - 1000, expires_at_ms: now - 1000 + 604800000, attempt_units: 100,
    permissions: ['enqueue', 'read', 'cancel', 'redrive', 'manage_destinations']};
  const root = fileURLToPath(new URL('../', import.meta.url));
  const script = (await build({stdin: {resolveDir: root, contents: `
    import {DurableObject} from 'cloudflare:workers';
    import {createRunLaterOAuth} from './mcp/oauth.mjs';
    export class TestHub extends DurableObject {
      constructor(ctx, env) {super(ctx,env); this.app=createRunLaterOAuth({env,storage:ctx.storage,
        validateTrial:async()=>{throw new Error('no_trial_in_owner_fixture');},revokeTrial:async()=>{throw new Error('no_trial_in_owner_fixture');},
        validateDelegation:async c=>{if(c.project_id!==env.FIXTURE_PROJECT)throw new Error('not_enrolled');return {active:true,project_id:c.project_id,expires_at_ms:c.expires_at_ms,permissions:c.permissions};},
        protectedHandler:{fetch(request,env,ctx){return Response.json({project:ctx.principal.delegation.project_id,scope:ctx.principal.scopes});}}});}
      fetch(request){return this.app.fetch(request,this.env,this.ctx);}
    }
    export default {fetch(request,env){return env.HUB.get(env.HUB.idFromName('one')).fetch(request);}};`},
    bundle: true, platform: 'neutral', mainFields: ['module', 'main'], format: 'esm', external: ['cloudflare:*', 'node:*'], write: false})).outputFiles[0].text;
  let outbound = 0, unexpectedOutbound = 0, slowRequests = 0, releaseSlow, markSlow;
  const slow = new Promise(resolve => {releaseSlow = resolve;});
  const slowSeen = new Promise(resolve => {markSlow = resolve;});
  const mf = new Miniflare(convertV4MiniflareOptions({modules: true, script, compatibilityDate: '2026-10-28',
    compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'], durableObjects: {HUB: {className: 'TestHub', useSQLite: true}},
    bindings: {MCP_OAUTH_ENABLED: 'operator-approved', MCP_ANONYMOUS_TRIAL_ENABLED: 'operator-approved', MCP_RECEIVER_PAIRING_ENABLED: 'operator-approved', MCP_GATEWAY_PUBLIC_KEY: gatewayKey, MCP_RELEASE_ID: releaseId, FIXTURE_PROJECT: receipt.project_id},
    outboundService: async request => {
      outbound++;
      if (/^https:\/\/slow[0-3]?\.example\.com\/metadata$/.test(request.url)) {
        if (++slowRequests === 5) markSlow();
        await slow;
        return Response.json({client_id: request.url, client_name: 'Blocked fixture client',
          redirect_uris: ['https://client.example.com/callback'], token_endpoint_auth_method: 'none'}, {headers: {'Cache-Control': 'no-store'}});
      }
      if (request.url !== 'https://client.example.com/metadata') {unexpectedOutbound++; return new Response(null, {status: 403});}
      assert.equal(request.headers.has('authorization'), false);
      return Response.json({client_id: request.url, client_name: 'Local fixture client', redirect_uris: ['https://client.example.com/callback'],
        token_endpoint_auth_method: 'none'}, {headers: {'Cache-Control': 'no-store'}});
    }}));
  t.after(() => mf.dispose()); await mf.ready;
  // OAuth redirects are inspected only. Never follow them to the synthetic client.
  const call = (path, init = {}) => mf.dispatchFetch('https://mcp.runlater.io' + path, {...init, redirect: 'manual'});
  const browserHelp = await call('/authorize', {headers: {Accept: 'text/html'}});
  assert.equal(browserHelp.status, 400);
  assert.match(browserHelp.headers.get('content-type'), /text\/html/);
  assert.match(await browserHelp.text(), /Start in your agent app/);
  assert.equal(browserHelp.headers.get('set-cookie'), null);
  assert.equal(outbound, 0, 'bare browser visit must not fetch client metadata');
  const machineError = await call('/authorize');
  assert.deepEqual(await machineError.json(), {error: 'invalid_request'});
  const partialBrowser = await call('/authorize?client_id=missing_context', {headers: {Accept: 'text/html'}});
  assert.equal(partialBrowser.status, 400);
  assert.match(partialBrowser.headers.get('content-type'), /application\/json/);
  assert.equal(outbound, 0);
  const unauth = await call('/sse'); assert.equal(unauth.status, 401); assert.match(unauth.headers.get('www-authenticate'), /oauth-protected-resource/);
  assert.equal((await (await call('/.well-known/oauth-protected-resource')).json()).resource, 'https://mcp.runlater.io');
  const verifier = 'v'.repeat(64), challenge = createHash('sha256').update(verifier).digest('base64url');
  const query = new URLSearchParams({response_type: 'code', client_id: 'https://client.example.com/metadata',
    redirect_uri: 'https://client.example.com/callback', scope: 'enqueue read', state: 'fixed-owner-state',
    code_challenge: challenge, code_challenge_method: 'S256', resource: 'https://mcp.runlater.io'});
  const setupQuery=new URLSearchParams(query);setupQuery.set('scope','enqueue read receiver_setup');
  const setupPage=await call('/authorize?'+setupQuery);assert.equal(setupPage.status,200);
  const setupCookie=setupPage.headers.get('set-cookie').split(';')[0],setupHtml=await setupPage.text();
  const ownerLink=new URL(decodeHTML(setupHtml.match(/<a href="([^"]+)">Connect existing project/)[1]));
  assert.equal(ownerLink.origin,'https://mcp.runlater.io');assert.equal(ownerLink.searchParams.get('scope'),'enqueue read');
  for(const field of ['client_id','redirect_uri','response_type','state','code_challenge','code_challenge_method','resource'])assert.equal(ownerLink.searchParams.get(field),query.get(field));
  const page = await call(ownerLink.pathname+ownerLink.search);
  assert.equal(page.status, 200, await page.clone().text());
  const html = await page.text();
  const publicChallenge = JSON.parse(decodeHTML(html.match(/<textarea readonly[^>]*>([\s\S]*?)<\/textarea>/)[1]));
  const cookie = page.headers.get('set-cookie').split(';')[0];
  const delegation = signDelegation({privateKey: owner.privateKey, receipt, releaseId, gatewayPublicKey: gatewayKey,
    permissions: ['enqueue', 'read'], delegationId: 'a'.repeat(64), issuedAtMs: now, expiresAtMs: now + 3600000});
  const approval = {delegation, consent_signature: sign(null, oauthConsentBytes(publicChallenge, delegation), owner.privateKey).toString('hex')};
  const form = new URLSearchParams({handle: publicChallenge.handle, decision: 'approve', approval: JSON.stringify(approval)}).toString();
  const approve = () => call('/authorize', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded',
    Origin: 'https://mcp.runlater.io', Cookie: cookie}, body: form});
  assert.equal((await call('/authorize', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded',
    Origin: 'https://mcp.runlater.io'}, body: form})).status, 400);
  // A stale/back-tab cookie from the wider-scope page cannot approve the new owner context.
  assert.equal((await call('/authorize',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Origin:'https://mcp.runlater.io',Cookie:setupCookie},body:form})).status,400);
  const consentResults = await Promise.all([approve(), approve()]);
  assert.deepEqual(consentResults.map(r => r.status).sort(), [302, 400]);
  const callback = new URL(consentResults.find(r => r.status === 302).headers.get('location'));
  assert.equal(callback.origin, 'https://client.example.com'); assert.equal(callback.searchParams.get('state'), 'fixed-owner-state');
  assert.equal(callback.searchParams.get('iss'), 'https://mcp.runlater.io');
  const tokenForm = new URLSearchParams({grant_type: 'authorization_code', client_id: 'https://client.example.com/metadata',
    redirect_uri: 'https://client.example.com/callback', code: callback.searchParams.get('code'), code_verifier: verifier,
    resource: 'https://mcp.runlater.io'});
  const exchange = values => call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: values.toString()});
  const wrongAudience = new URLSearchParams(tokenForm); wrongAudience.set('resource', 'https://api.runlater.io');
  assert.equal((await exchange(wrongAudience)).status, 400);
  const wrongVerifier = new URLSearchParams(tokenForm); wrongVerifier.set('code_verifier', 'x'.repeat(64));
  assert.equal((await exchange(wrongVerifier)).status, 400);
  const results = await Promise.all([exchange(tokenForm), exchange(tokenForm)]);
  assert.deepEqual(results.map(r => r.status).sort(), [200, 400]);
  const replayed = await results.find(r => r.status === 200).json();
  // OAuth library revokes the whole grant after detecting a repeated code.
  assert.equal((await call('/mcp', {headers: {Authorization: `Bearer ${replayed.access_token}`}})).status, 401);
  const token = await authorizeFixture(call, {privateKey: owner.privateKey, delegation});
  assert.equal(token.refresh_token, undefined); assert.ok(token.expires_in <= 3600 && token.expires_in > 300);
  const slowQuery = new URLSearchParams(query); slowQuery.set('client_id', 'https://slow.example.com/metadata');
  const slowPage = call('/authorize?' + slowQuery);
  const slowTokens = Array.from({length: 4}, (_, i) => call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({client_id: `https://slow${i}.example.com/metadata`, grant_type: 'authorization_code', code: 'synthetic'}).toString()}));
  await slowSeen;
  const resource = await call('/mcp', {headers: {Authorization: `Bearer ${token.access_token}`}});
  assert.equal(resource.status, 200); assert.deepEqual(await resource.json(), {project: receipt.project_id, scope: ['enqueue', 'read']});
  const wrongClientRevocation = await call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({token: token.access_token, client_id: 'https://attacker.example.com/metadata'}).toString()});
  assert.equal(wrongClientRevocation.status, 503); // Cannot consume a reserved slot with another client's token.
  const unknownRevocation = await call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({token: 'unknown_synthetic_token', client_id: 'https://client.example.com/metadata'}).toString()});
  assert.equal(unknownRevocation.status, 503); // Unknown tokens stay in the saturated ordinary lane.
  const revoked = await call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: new URLSearchParams({token: token.access_token, client_id: 'https://client.example.com/metadata'}).toString()});
  assert.equal(revoked.status, 200);
  assert.equal((await call('/mcp', {headers: {Authorization: `Bearer ${token.access_token}`}})).status, 401);
  releaseSlow();
  assert.equal((await slowPage).status, 200);
  for (const response of await Promise.all(slowTokens)) assert.equal(response.status, 400);
  assert.ok(outbound > 0); // Metadata only; no API task, receiver or real credential request.
  assert.equal(unexpectedOutbound, 0);
});
