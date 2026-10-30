import test from 'node:test';
import assert from 'node:assert/strict';
import {build} from 'esbuild';
import {generateKeyPairSync} from 'node:crypto';
import {delegationPublicKey} from './delegation.mjs';

// Use the actual ingress and McpHub methods with local dependency sentinels.
const {outputFiles} = await build({entryPoints: ['mcp/worker.mjs'], bundle: true,
  loader: {'.md': 'text'}, platform: 'node', format: 'esm', write: false,
  plugins: [{name: 'local-sentinels', setup(build) {
    build.onResolve({filter: /^cloudflare:workers$/}, () => ({path: 'workers', namespace: 'fixture'}));
    build.onResolve({filter: /^\.\/oauth\.mjs$/}, () => ({path: 'oauth', namespace: 'fixture'}));
    build.onLoad({filter: /.*/, namespace: 'fixture'}, ({path}) => ({contents: path === 'workers'
      ? 'export class DurableObject {constructor(ctx,env){this.ctx=ctx;this.env=env;}}'
      : `export function createRunLaterOAuth() {globalThis.oauthInitializations++;
        return {fetch(){throw new Error('OAuth handler executed');},
          async revocationSchedule(){globalThis.cleanupCalls.push('schedule');return {pending:true,nextAttemptAtMs:1};},
          async drainRevocations(){globalThis.cleanupCalls.push('drain');return {pending:true,nextAttemptAtMs:2};}};}` }));
  }}]});
const {default: worker, McpHub, gatewayReady} = await import('data:text/javascript;base64,' + Buffer.from(outputFiles[0].text).toString('base64'));
const gateway = generateKeyPairSync('ed25519');
const enabled = {MCP_ENABLED: 'operator-approved', MCP_OAUTH_ENABLED: 'operator-approved', MCP_RELEASE_ID: 'local_fixture',
  MCP_GATEWAY_PUBLIC_KEY: delegationPublicKey(gateway.privateKey), MCP_GATEWAY_PRIVATE_KEY: gateway.privateKey.export({format:'pem',type:'pkcs8'})};
const paths = ['/authorize','/oauth/token','/.well-known/oauth-authorization-server','/.well-known/oauth-protected-resource','/sse','/messages','/mcp'];
test('every legacy route returns 410 before accessing bindings, auth, providers or rate limits', async () => {
  let calls = 0;
  const poison = new Proxy({}, {get(){calls++;throw new Error('binding accessed');}});
  const env = {...enabled, MCP_HUB: poison, MCP_IP_RATE: poison, MCP_AUTH_RATE: poison};
  for (const settings of [env, {}]) for (const path of paths) for (const method of ['GET','POST','OPTIONS','DELETE']) {
    const result = await worker.fetch(new Request('https://mcp.runlater.io' + path + '?client_id=https://client.invalid',
      {method, headers:{Authorization:'Bearer fixture', 'Content-Length':'99999'}}), settings);
    assert.equal(result.status, 410, method + ' ' + path);
    assert.deepEqual(await result.json(), {error:'legacy_mcp_retired'});
    assert.equal(result.headers.get('Cache-Control'), 'no-store');
    for (const header of ['WWW-Authenticate','Location']) assert.equal(result.headers.has(header), false);
  }
  assert.equal(calls, 0);
  assert.equal((await worker.fetch(new Request('https://mcp.runlater.io/unknown'), env)).status,404);
  assert.equal((await worker.fetch(new Request('https://other.invalid/mcp'), env)).status,403);
});
test('health distinguishes public retirement from cleanup configuration and Agent Auth readiness', async () => {
  for (const env of [enabled, {}]) {
    const result = await worker.fetch(new Request('https://mcp.runlater.io/health'),env);
    const health = await result.json();
    assert.equal(result.status,200); assert.equal(health.configured,false);
    assert.equal(health.legacy_public_ingress_retired,true); assert.equal(health.mode,'legacy_retired');
    assert.equal(health.agent_auth_ready,false); assert.equal(health.cleanup_configured,gatewayReady(env));
  }
});
test('unchanged enabled bindings initialize OAuth and alarms preserve pre-arm, drain and retry scheduling', async () => {
  globalThis.oauthInitializations = 0; globalThis.cleanupCalls = [];
  const alarms = [], ctx = {storage:{async setAlarm(time){alarms.push(time);}}};
  const hub = new McpHub(ctx, enabled);
  assert.equal(globalThis.oauthInitializations,1); assert.ok(hub.oauth); assert.ok(hub.protocol);
  await hub.alarm();
  assert.deepEqual(globalThis.cleanupCalls,['schedule','drain']);
  assert.equal(alarms.length,2); assert.ok(alarms.every(Number.isSafeInteger)); assert.equal(hub.cleanup,null);
});
