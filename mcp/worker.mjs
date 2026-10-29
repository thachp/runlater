import {DurableObject} from 'cloudflare:workers';
import {createPrivateKey} from 'node:crypto';
import setup from '../docs/MCP.md';
import {createRunLaterOAuth} from './oauth.mjs';
import {createHostedProtocol, MCP_ORIGIN} from './hosted-protocol.mjs';
import {DelegatedPublicBetaClientV1} from './delegation-client.mjs';
import {delegationPublicKey} from './delegation.mjs';

const paths = new Set(['/sse', '/messages', '/mcp', '/authorize', '/oauth/token',
  '/.well-known/oauth-authorization-server', '/.well-known/oauth-protected-resource']);
const response = (status, error) => Response.json({error}, {status, headers: {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}});
export function gatewayReady(env) {
  return env.MCP_ENABLED === 'operator-approved' && env.MCP_OAUTH_ENABLED === 'operator-approved'
    && /^[A-Za-z0-9_-]{1,32}$/.test(env.MCP_RELEASE_ID || '') && /^[a-f0-9]{64}$/.test(env.MCP_GATEWAY_PUBLIC_KEY || '')
    && typeof env.MCP_GATEWAY_PRIVATE_KEY === 'string' && env.MCP_GATEWAY_PRIVATE_KEY.length < 512;
}
export class McpHub extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env); this.env = env;
    // One known object, no attacker-controlled namespace fan-out and no binding to
    // the API's task Durable Objects, queues, callback master or admission registry.
    if (!gatewayReady(env)) return;
    try {
      const key = createPrivateKey(env.MCP_GATEWAY_PRIVATE_KEY);
      if (delegationPublicKey(key) !== env.MCP_GATEWAY_PUBLIC_KEY) return;
      this.protocol = createHostedProtocol({setup, makeClient: principal => new DelegatedPublicBetaClientV1({
        privateKey: key, delegation: principal.delegation, releaseId: env.MCP_RELEASE_ID, fetchImpl: (url, init) => fetch(url, init),
      })});
      this.oauth = createRunLaterOAuth({env, storage: ctx.storage,
        validateDelegation: delegation => new DelegatedPublicBetaClientV1({privateKey: key, delegation,
          releaseId: env.MCP_RELEASE_ID, fetchImpl: (url, init) => fetch(url, init)}).validateDelegation(),
        protectedHandler: {
        fetch: (request, _env, context) => this.protocol.handle(request, context.principal),
      }});
    } catch { /* Fail closed; no secret or exception logging. */ }
  }
  async fetch(request) {
    if (!this.oauth || this.ctx.id.toString() !== this.env.MCP_HUB.idFromName('mcp-hub-v1').toString()) return response(503, 'mcp_unavailable');
    return this.oauth.fetch(request, this.env, this.ctx);
  }
}
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.origin !== MCP_ORIGIN) return response(403, 'host_rejected');
      if (url.pathname === '/health' && request.method === 'GET' && !url.search) return Response.json({
        service: 'runlater-mcp', configured: gatewayReady(env), source_sha: env.MCP_SOURCE_SHA || null,
        version_id: env.MCP_RELEASE_VERSION?.id || null, mode: 'delegated_public_beta',
      }, {headers: {'Cache-Control': 'no-store'}});
      if (!paths.has(url.pathname)) return response(404, 'not_found');
      if (!gatewayReady(env) || !env.MCP_HUB || !env.MCP_IP_RATE || !env.MCP_AUTH_RATE) return response(503, 'mcp_unavailable');
      let headerBytes = 0; for (const [key, value] of request.headers) headerBytes += key.length + value.length;
      if (headerBytes > 8192 || Number(request.headers.get('content-length') || 0) > 16384) return response(413, 'request_too_large');
      // This header is set by Cloudflare at the public ingress. Never use X-Forwarded-For.
      const ip = request.headers.get('CF-Connecting-IP');
      if (!ip || ip.length > 64) return response(503, 'ingress_unavailable');
      if (!(await env.MCP_IP_RATE.limit({key: ip})).success) return response(429, 'rate_limited');
      if (url.pathname === '/authorize' && !(await env.MCP_AUTH_RATE.limit({key: ip})).success) return response(429, 'authorization_rate_limited');
      return env.MCP_HUB.get(env.MCP_HUB.idFromName('mcp-hub-v1')).fetch(request);
    } catch {return response(503, 'mcp_unavailable');}
  },
};
