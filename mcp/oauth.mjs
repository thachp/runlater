import {createHash} from 'node:crypto';
import {OAuthAuthorizationServer, OAuthError} from '@cloudflare/workers-oauth-provider';
import {verifyDelegation} from './delegation.mjs';
import {MCP_RESOURCE, MCP_SCOPES} from './oauth-consent.mjs';
import {authorizeOwner, oauthFailure, privateHeaders, requireActiveDelegation} from './oauth-app.mjs';
import {createOAuthStorage} from './oauth-storage.mjs';
import {createOAuthScheduling} from './oauth-scheduling.mjs';

const protectedPaths = new Set(['/sse', '/messages', '/mcp']);
const authPaths = new Set(['/authorize', '/oauth/token', '/.well-known/oauth-authorization-server']);
const publicErrors = new Set(['invalid_request', 'invalid_client', 'invalid_grant', 'invalid_scope', 'invalid_target',
  'unauthorized_client', 'unsupported_grant_type', 'unsupported_response_type', 'access_denied', 'temporarily_unavailable']);
export const resourceMetadata = Object.freeze({resource: MCP_RESOURCE, authorization_servers: [MCP_RESOURCE], scopes_supported: [...MCP_SCOPES]});
export function oauthChallenge() {
  return Response.json({error: 'invalid_token'}, {status: 401, headers: {...privateHeaders,
    'WWW-Authenticate': `Bearer resource_metadata="${MCP_RESOURCE}/.well-known/oauth-protected-resource", scope="cancel enqueue read"`}});
}
export function createRunLaterOAuth({env, storage, protectedHandler, validateDelegation}) {
  const config = {releaseId: env.MCP_RELEASE_ID, gatewayPublicKey: env.MCP_GATEWAY_PUBLIC_KEY};
  const enabled = env.MCP_OAUTH_ENABLED === 'operator-approved' && /^[a-f0-9]{64}$/.test(config.gatewayPublicKey || '')
    && /^[A-Za-z0-9_-]{1,32}$/.test(config.releaseId || '') && typeof validateDelegation === 'function';
  const kv = createOAuthStorage(storage), oauthEnv = {...env, OAUTH_KV: kv};
  const scheduling = createOAuthScheduling();
  const clientLane = clientId => 'client:' + createHash('sha256').update(clientId).digest('hex');
  const consentLane = handle => 'consent:' + createHash('sha256').update(String(handle)).digest('hex');
  const provider = new OAuthAuthorizationServer({issuer: MCP_RESOURCE, resources: [MCP_RESOURCE],
    scopesSupported: [...MCP_SCOPES], accessTokenTTL: 3600, refreshTokenTTL: 0,
    clientIdMetadataDocumentEnabled: true, allowTokenExchangeGrant: false,
    onError: ({code, status}) => Response.json({error: publicErrors.has(code) ? code : 'invalid_request'}, {
      status: [400, 401, 403, 429, 500, 503].includes(status) ? status : 400,
      headers: {...privateHeaders, ...(status === 401 ? {'WWW-Authenticate': 'Basic realm="RunLater OAuth"'} : {})},
    }),
    tokenExchangeCallback: async options => {
      try {
        if (options.grantType !== 'authorization_code' || options.resource !== MCP_RESOURCE) throw new Error();
        const delegation = options.props?.delegation;
        verifyDelegation(delegation, {...config, now: Date.now()});
        if (!options.requestedScope.every(scope => delegation.permissions.includes(scope))) throw new Error();
        const active = await requireActiveDelegation(delegation, validateDelegation);
        const remaining = Math.floor((Math.min(delegation.expires_at_ms, active.expires_at_ms) - Date.now()) / 1000);
        if (remaining < 60) throw new Error();
        return {accessTokenTTL: Math.min(3600, remaining), refreshTokenTTL: 0};
      } catch {throw new OAuthError('invalid_grant');}
    },
  });
  const api = provider.getOAuthApi(oauthEnv);
  const consentApi = {
    parseAuthRequest: request => scheduling.network('setup', () => api.parseAuthRequest(request)),
    describeConsent: request => scheduling.network('setup', () => api.describeConsent(request)),
    beginConsent: request => api.beginConsent(request),
    approveConsent: (request, handle) => scheduling.critical(consentLane(handle), () => api.approveConsent(request, handle)),
    denyConsent: (request, handle) => scheduling.critical(consentLane(handle), () => api.denyConsent(request, handle)),
    completeAuthorization: options => scheduling.critical(clientLane(options.request.clientId),
      () => scheduling.network('token', () => api.completeAuthorization(options))),
  };
  async function authenticate(request) {
    const header = request.headers.get('authorization');
    if (!header || !/^Bearer [^\s]{16,2048}$/.test(header)) return null;
    const token = header.slice(7), value = await provider.validateToken(MCP_RESOURCE, token, oauthEnv);
    if (!value || value.audience !== MCP_RESOURCE || value.expiresAt * 1000 <= Date.now()) return null;
    const delegation = value.props?.delegation;
    try {verifyDelegation(delegation, {...config, now: Date.now()});} catch {return null;}
    if (value.userId !== delegation.project_id || !value.scope.length
      || !value.scope.every(scope => delegation.permissions.includes(scope))) return null;
    return {props: {delegation}, auth: {audience: value.audience, expiresAt: value.expiresAt,
      scope: value.scope, userId: value.userId, clientId: value.clientId},
    principal: {delegation, scopes: value.scope, tokenHash: createHash('sha256').update(token).digest('hex'),
      expiresAt: Math.min(value.expiresAt * 1000, delegation.expires_at_ms)}};
  }
  return {async fetch(request, _env, ctx) {
    const url = new URL(request.url);
    if (url.origin !== MCP_RESOURCE || !enabled) return oauthFailure(503);
    if (request.url.length > 8192) return oauthFailure();
    if (url.pathname === '/.well-known/oauth-protected-resource' && request.method === 'GET' && !url.search) {
      return Response.json(resourceMetadata, {headers: privateHeaders});
    }
    if (protectedPaths.has(url.pathname)) {
      // The pinned provider's validateToken only reads/decrypts a local token record;
      // it performs no CIMD fetch or issuance. Revocation is visible after token deletion.
      let auth; try {auth = await scheduling.validate(() => authenticate(request));} catch {return oauthFailure(503);}
      if (!auth) return oauthChallenge();
      // Streaming protocol requests do not hold the OAuth serialization lock.
      return protectedHandler.fetch(request, env, Object.assign(Object.create(ctx || null), auth));
    }
    if (!authPaths.has(url.pathname)) return new Response(null, {status: 404, headers: privateHeaders});
    try {
      const pending = [], context = {waitUntil: promise => pending.push(Promise.resolve(promise)), passThroughOnException() {}};
      try {
        // Read slow/untrusted bodies before any state-transition lane is acquired.
        const boundedRequest = await boundedOAuthRequest(request);
        let response;
        if (url.pathname === '/authorize') response = await authorizeOwner(boundedRequest, consentApi, {...config, now: Date.now(),
          validateDelegation: delegation => scheduling.network('token', () => validateDelegation(delegation))});
        else if (url.pathname === '/oauth/token') {
          let info;
          try {info = await tokenRequestInfo(boundedRequest);} catch {return oauthFailure();}
          let networkKind = 'token';
          if (info.revocationToken) {
            // Reserve two network slots for a holder of a currently valid token
            // issued to this exact client. This is admission, not authorization:
            // the library still authenticates the client and performs revocation.
            const proof = await scheduling.validate(() => authenticate(new Request(MCP_RESOURCE + '/mcp', {
              headers: {Authorization: 'Bearer ' + info.revocationToken},
            })));
            if (proof?.auth.clientId === info.clientId) networkKind = 'revocation';
          }
          response = await scheduling.critical(clientLane(info.clientId), () => scheduling.network(networkKind, async () => {
            const result = await provider.fetch(boundedRequest, oauthEnv, context);
            await Promise.all(pending); return result;
          }));
        } else response = await provider.fetch(boundedRequest, oauthEnv, context);
        await Promise.all(pending);
        return response;
      } catch {await Promise.allSettled(pending); return oauthFailure(503);}
    } catch {return oauthFailure(503);}
  }};
}

async function tokenRequestInfo(request) {
  if (request.method !== 'POST' || request.headers.has('authorization')) throw new Error('invalid_client');
  const form = new URLSearchParams(await request.clone().text());
  for (const key of ['client_id', 'client_assertion', 'client_assertion_type']) if (form.getAll(key).length > 1) throw new Error('invalid_client');
  let clientId = form.get('client_id');
  if (!clientId && form.has('client_assertion')) {
    const assertion = form.get('client_assertion');
    if (assertion.length > 8192 || assertion.split('.').length !== 3) throw new Error('invalid_client');
    clientId = JSON.parse(Buffer.from(assertion.split('.')[1], 'base64url').toString('utf8')).iss;
  }
  if (typeof clientId !== 'string' || !clientId || clientId.length > 2048) throw new Error('invalid_client');
  // This is a scheduling key, never proof of identity. The official provider still
  // validates CIMD and the exact public-client or private_key_jwt authentication.
  return {clientId, revocationToken: !form.has('grant_type') && form.getAll('token').length === 1
    && form.get('token').length <= 2048 ? form.get('token') : null};
}

async function boundedOAuthRequest(request) {
  if (!request.body) return request;
  const reader = request.body.getReader(); let size = 0, chunks = 0, timer;
  const data = [];
  try {
    await Promise.race([(async () => {for (;;) {const {done, value} = await reader.read(); if (done) break;
      size += value.byteLength; if (size > 16384 || ++chunks > 32) throw new Error('oauth_request_size'); data.push(value);
    }})(), new Promise((_, reject) => {timer = setTimeout(() => reject(new Error('oauth_request_timeout')), 5000);})]);
    return new Request(request, {body: Buffer.concat(data)});
  } finally {clearTimeout(timer); void reader.cancel().catch(() => {}); try {reader.releaseLock();} catch {}}
}
