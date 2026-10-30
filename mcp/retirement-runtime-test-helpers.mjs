// Public production bundle only. No Rust API, identities, remote tasks or egress.
import assert from 'node:assert/strict';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import {bundleMcp} from '../scripts/build-mcp.mjs';
export async function assertPublicMcpRetired() {
  let outbound = 0;
  const local = new Miniflare(convertV4MiniflareOptions({modules: true, script: await bundleMcp(),
    compatibilityDate: '2026-10-29', compatibilityFlags: ['global_fetch_strictly_public'],
    durableObjects: {MCP_HUB: {className: 'McpHub', useSQLite: true}},
    bindings: {MCP_ENABLED: 'operator-approved', MCP_OAUTH_ENABLED: 'operator-approved',
      MCP_RELEASE_ID: 'local_retirement_fixture', MCP_GATEWAY_PUBLIC_KEY: 'a'.repeat(64),
      MCP_GATEWAY_PRIVATE_KEY: 'local-invalid-key-must-not-be-used'},
    outboundService: async () => {outbound++; throw new Error('Retired ingress attempted egress');}}));
  try {
    await local.ready;
    for (const route of ['/authorize', '/oauth/token', '/.well-known/oauth-authorization-server',
      '/.well-known/oauth-protected-resource', '/sse', '/messages', '/mcp']) {
      for (const method of ['GET', 'POST', 'OPTIONS', 'DELETE']) {
        const result = await local.dispatchFetch('https://mcp.runlater.io' + route + '?state=local-fixture',
          {method, redirect: 'manual', headers: {Authorization: 'Bearer local-fixture'}});
        assert.equal(result.status, 410, `${method} ${route}`);
        assert.deepEqual(await result.json(), {error: 'legacy_mcp_retired'});
        assert.equal(result.headers.has('Location'), false);
        assert.equal(result.headers.has('WWW-Authenticate'), false);
        assert.equal(result.headers.get('Cache-Control'), 'no-store');
      }
    }
    const result = await local.dispatchFetch('https://mcp.runlater.io/health');
    assert.equal(result.status, 200);
    const health = await result.json();
    assert.equal(health.configured, false);
    assert.equal(health.cleanup_configured, true);
    assert.equal(health.legacy_public_ingress_retired, true);
    assert.equal(health.agent_auth_ready, false);
    assert.equal(health.mode, 'legacy_retired');
    assert.equal(outbound, 0);
  } finally {await local.dispose();}
}
