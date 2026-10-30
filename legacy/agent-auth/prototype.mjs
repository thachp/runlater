import {betterAuth} from 'better-auth';
import {memoryAdapter} from 'better-auth/adapters/memory';
import {agentAuth} from '@better-auth/agent-auth';
import {decodeJwt} from 'jose';

export const ORIGIN = 'http://localhost:8789';
export const BASE = `${ORIGIN}/api/auth`;
// Local protocol proof only. No Worker imports this module and no network listener
// is provided. In-memory data must never be used for hosted trial admission.
export function createPrototype({enabled = false} = {}) {
  if (!enabled) return {fetch: async () => Response.json({error: 'agent_auth_disabled'}, {status: 503})};
  const db = {user: [], session: [], account: [], verification: [], agent: [], agentHost: [], agentCapabilityGrant: [], approvalRequest: []};
  const plugin = agentAuth({
    providerName: 'RunLater local Agent Auth proof',
    modes: ['autonomous'],
    allowDynamicHostRegistration: true,
    allowedKeyAlgorithms: ['Ed25519'],
    defaultHostCapabilities: ['trial_status'],
    validateCapabilities: caps => caps.every(cap => cap === 'trial_status'),
    jwtMaxAge: 60,
    absoluteLifetime: 604800,
    agentMaxLifetime: 604800,
    jtiCacheStorage: 'memory',
    resolveAutonomousUser: ({hostId}) => ({id: `local:${hostId}`, name: 'Local autonomous fixture', email: `${hostId}@fixture.invalid`}),
    capabilities: [{name: 'trial_status', description: 'Inspect local fixture policy; does not create a RunLater project.'}],
    onExecute: async () => ({fixture: true, attempt_units: 100, lifetime_seconds: 604800, provisioning_enabled: false}),
  });
  const auth = betterAuth({baseURL: ORIGIN, basePath: '/api/auth',
    secret: 'local-ephemeral-proof-only-never-host-this-secret',
    database: memoryAdapter(db), plugins: [plugin],
    rateLimit: {enabled: false}, logger: {disabled: true}});
  let tail = Promise.resolve();
  async function handle(request) {
    const url = new URL(request.url);
    if (url.origin !== ORIGIN) return new Response(null, {status: 403});
    if (request.method === 'GET' && url.pathname === '/.well-known/agent-configuration') {
      const config = await auth.api.getAgentConfiguration();
      // Discovery truthfully lists only routes admitted by this local proof.
      config.approval_methods = [];
      config.endpoints = {register: config.endpoints.register, execute: config.endpoints.execute};
      return Response.json(config);
    }
    // Restrict the proof to inline-key registration and one read-only capability.
    // No remote JWKS fetching, account linking, key rotation or hosted provisioning.
    if (!['/api/auth/agent/register', '/api/auth/capability/execute'].includes(url.pathname)) return new Response(null, {status: 404});
    if (request.method !== 'POST') return new Response(null, {status: 405});
    let raw = '';
    const reader = request.body?.getReader();
    const decoder = new TextDecoder();
    let bytes = 0;
    if (reader) {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > 8192) {await reader.cancel(); return new Response(null, {status: 413});}
        raw += decoder.decode(value, {stream: true});
      }
      raw += decoder.decode();
    }
    try {
      const token = request.headers.get('authorization')?.replace(/^Bearer /, '');
      const claims = decodeJwt(token);
      if (claims.jwks_url || claims.host_jwks_url || claims.agent_jwks_url) throw new Error('remote_keys_disabled');
      if (url.pathname.endsWith('/execute')) {
        // Denial-only ledger checks precede upstream auto-grant behavior. These
        // unverified claims can only cause rejection; the plugin still verifies
        // the signature, audience, replay and grant before execution.
        const agent = db.agent.find(row => row.id === claims.sub);
        const host = db.agentHost.find(row => row.id === agent?.hostId);
        const grants = db.agentCapabilityGrant.filter(row => row.agentId === agent?.id);
        if (host?.status === 'revoked' || grants.some(g => g.status === 'revoked' || g.status === 'denied' || (g.expiresAt && new Date(g.expiresAt) <= new Date()))) {
          return Response.json({error: 'local_authority_inactive'}, {status: 403});
        }
      }
      if (url.pathname.endsWith('/execute') && (!claims.htm || !claims.htu || !claims.ath)) throw new Error('request_binding_required');
      if (url.pathname.endsWith('/register')) {
        const body = JSON.parse(raw);
        if (body.mode !== 'autonomous' || body.capabilities?.some(c => c !== 'trial_status')) throw new Error('capability_rejected');
        if (!claims.host_public_key || !claims.agent_public_key) throw new Error('inline_keys_required');
      }
    } catch {return Response.json({error: 'local_policy_rejected'}, {status: 400});}
    return auth.handler(new Request(request.url, {method: 'POST', headers: request.headers, body: raw}));
  }
  return {
    // Serialize the entire verify/check/add operation, not individual cache calls.
    // This is safe only for this one in-process fixture, not multiple Workers.
    fetch(request) {const result = tail.then(() => handle(request)); tail = result.catch(() => {}); return result;},
    schema: plugin.schema,
    db,
  };
}
