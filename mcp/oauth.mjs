import {strictRefreshFetch} from './oauth-strict.mjs';
import {oauthTransaction} from './oauth-transaction.mjs';
import {validateTrialAuthority} from './oauth-trial.mjs';
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
export function createRunLaterOAuth({env, storage, protectedHandler, validateDelegation, validateTrial, revokeTrial}) {
  const trialEnabled = env.MCP_ANONYMOUS_TRIAL_ENABLED === 'operator-approved' && typeof validateTrial === 'function' && typeof revokeTrial === 'function';
  const config = {trialEnabled, releaseId: env.MCP_RELEASE_ID, gatewayPublicKey: env.MCP_GATEWAY_PUBLIC_KEY};
  const enabled = env.MCP_OAUTH_ENABLED === 'operator-approved' && /^[a-f0-9]{64}$/.test(config.gatewayPublicKey || '')
    && /^[A-Za-z0-9_-]{1,32}$/.test(config.releaseId || '') && typeof validateDelegation === 'function';
  const kv = createOAuthStorage(storage,{trialEnabled}), oauthEnv = {...env, OAUTH_KV: kv};
  const scheduling = createOAuthScheduling();
  const transaction=operation=>oauthTransaction(storage,operation,{trialEnabled});
  const clientLane = clientId => 'client:' + createHash('sha256').update(clientId).digest('hex');
  const consentLane = handle => 'consent:' + createHash('sha256').update(String(handle)).digest('hex');
  const trialStates=new Map();
  const provider = new OAuthAuthorizationServer({issuer: MCP_RESOURCE, resources: [MCP_RESOURCE],
    scopesSupported: [...MCP_SCOPES], accessTokenTTL: 3600, refreshTokenTTL: 0,
    clientIdMetadataDocumentEnabled: true, allowTokenExchangeGrant: false,
    onError: ({code, status}) => Response.json({error: publicErrors.has(code) ? code : 'invalid_request'}, {
      status: [400, 401, 403, 429, 500, 503].includes(status) ? status : 400,
      headers: {...privateHeaders, ...(status === 401 ? {'WWW-Authenticate': 'Basic realm="RunLater OAuth"'} : {})},
    }),
    tokenExchangeCallback: async options => {
      try {
        if (options.resource !== MCP_RESOURCE) throw new Error();
        if (options.props?.kind === 'trial') {
          if (!trialEnabled || !['authorization_code','refresh_token'].includes(options.grantType)) throw new Error();
          const props = validateTrialAuthority(options.props,{releaseId:config.releaseId,clientId:options.clientId});
          if (options.userId!==props.projectId || !options.requestedScope.every(s=>props.descriptor.permissions.includes(s))) throw new Error();
          let state;try {state = await validateTrial({descriptor:props.descriptor,capability:props.capability});} catch {throw new OAuthError('temporarily_unavailable',{statusCode:503});}
          if (!['unprovisioned','active'].includes(state?.state) || state.expires_at_ms !== props.descriptor.expires_at_ms) throw new Error();
          trialStates.set(options.grantId,{state:state.state,descriptor:props.descriptor});
          const remaining = Math.floor((props.descriptor.expires_at_ms-Date.now())/1000);
          if (remaining < 60) throw new Error();
          return {accessTokenTTL:Math.min(3600,remaining), ...(options.grantType === 'authorization_code' ? {refreshTokenTTL:remaining} : {})};
        }
        if (options.grantType !== 'authorization_code') throw new Error();
        const delegation = options.props?.delegation;
        verifyDelegation(delegation, {...config, now: Date.now()});
        if (!options.requestedScope.every(scope => delegation.permissions.includes(scope))) throw new Error();
        const active = await requireActiveDelegation(delegation, validateDelegation);
        const remaining = Math.floor((Math.min(delegation.expires_at_ms, active.expires_at_ms) - Date.now()) / 1000);
        if (remaining < 60) throw new Error();
        return {accessTokenTTL: Math.min(3600, remaining), refreshTokenTTL: 0};
      } catch (error) {if(error instanceof OAuthError) throw error;throw new OAuthError('invalid_grant');}
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
      () => scheduling.network('token', () => options.props?.kind !== 'trial' ? api.completeAuthorization(options) : transaction(async txkv => {
        const {trialRevocationSecret,...grantOptions} = options;
        const result = await provider.getOAuthApi({...oauthEnv,OAUTH_KV:txkv}).completeAuthorization(grantOptions);
        const code = new URL(result.redirectTo).searchParams.get('code'), [userId,grantId] = code.split(':');
        await txkv.put(`family:${userId}:${grantId}`,JSON.stringify({clientId:options.request.clientId,descriptor:options.props.descriptor,
          revocationSecret:trialRevocationSecret,expiresAt:options.props.descriptor.expires_at_ms,consumed:[],revoked:false,cleanupDone:false}),
          {expiration:Math.floor(Date.now()/1000)+600});
        return result;
      }))),
  };
  async function markProvisioned(key) {
    await transaction(async txkv=>{const family=await txkv.get(key,{type:'json'});if(!family||family.revoked)throw new Error('trial_revoked');
      family.provisioned=true;await txkv.put(key,JSON.stringify(family),{expiration:Math.ceil(family.expiresAt/1000)});});
  }
  async function revokeFamily(key) {
    await transaction(async txkv=>{const family=await txkv.get(key,{type:'json'});if(family){family.revoked=true;await txkv.put(key,JSON.stringify(family),{expiration:Math.ceil(family.expiresAt/1000)});}});
    try {await cleanupFamily(key);} catch {}
    const family=await kv.get(key,{type:'json'});
    return {revoked:true,api_revoked:!!family?.cleanupDone,cleanup_pending:!!family&&!family.cleanupDone&&(family.cleanupAttempts||0)<32&&family.expiresAt>Date.now()};
  }
  async function cleanupFamily(key) {
    const family = await kv.get(key,{type:'json'}), now=Date.now();
    if (!family?.revoked || family.cleanupDone || family.expiresAt<=now || (family.cleanupAttempts||0)>=32 || (family.nextAttemptAtMs||0)>now) return;
    // Persist admission before the network call; a crash does not create a hot retry loop.
    await transaction(async txkv=>{const current=await txkv.get(key,{type:'json'});
      if(!current?.revoked || current.cleanupDone || (current.nextAttemptAtMs||0)>Date.now()) throw new Error('cleanup_not_due');
      current.cleanupAttempts=(current.cleanupAttempts||0)+1;
      current.nextAttemptAtMs=Math.min(current.expiresAt,Date.now()+Math.min(3600000,30000*2**Math.min(current.cleanupAttempts-1,7)));
      await txkv.put(key,JSON.stringify(current),{expiration:Math.ceil(current.expiresAt/1000)});
    });
    try {
      const confirmation=await scheduling.network('revocation',()=>revokeTrial({descriptor:family.descriptor,revocationSecret:family.revocationSecret,idempotencyKey:family.descriptor.bootstrap_id}));
      if(confirmation?.revoked!==true)throw new Error('revocation_unconfirmed');
      await transaction(async txkv=>{const current=await txkv.get(key,{type:'json'});if(current?.revoked){current.cleanupDone=true;delete current.revocationSecret;await txkv.put(key,JSON.stringify(current),{expiration:Math.ceil(current.expiresAt/1000)});}});
    } catch {} // Durable tombstone remains; bounded alarm retries never execute tasks.
  }
  async function authenticate(request) {
    const header = request.headers.get('authorization');
    if (!header || !/^Bearer [^\s]{16,2048}$/.test(header)) return null;
    const token = header.slice(7), value = await provider.validateToken(MCP_RESOURCE, token, oauthEnv);
    if (!value || value.audience !== MCP_RESOURCE || value.expiresAt * 1000 <= Date.now()) return null;
    if (value.props?.kind === 'trial') {
      if (!trialEnabled) return null;
      let props; try {props=validateTrialAuthority(value.props,{releaseId:config.releaseId,clientId:value.clientId});} catch {return null;}
      const [,grantId]=token.split(':'), familyKey=`family:${value.userId}:${grantId}`;
      const family=await kv.get(familyKey,{type:'json'});
      if (!family || family.revoked || family.clientId!==value.clientId || JSON.stringify(family.descriptor)!==JSON.stringify(props.descriptor)) {return null;}
      if (value.userId!==props.projectId || !value.scope.length || !value.scope.every(s=>props.descriptor.permissions.includes(s))) return null;
      return {auth:{audience:value.audience,expiresAt:value.expiresAt,scope:value.scope,userId:value.userId,clientId:value.clientId},
        principal:{kind:'trial',trial:{descriptor:props.descriptor,capability:props.capability},scopes:value.scope,
          tokenHash:createHash('sha256').update(token).digest('hex'),expiresAt:Math.min(value.expiresAt*1000,props.descriptor.expires_at_ms),
          markTrialProvisioned:()=>scheduling.critical(clientLane(value.clientId),()=>markProvisioned(familyKey)),
          revokeTrial:()=>scheduling.critical(clientLane(value.clientId),()=>revokeFamily(familyKey))}};
    }
    const delegation = value.props?.delegation;
    try {verifyDelegation(delegation, {...config, now: Date.now()});} catch {return null;}
    if (value.userId !== delegation.project_id || !value.scope.length
      || !value.scope.every(scope => delegation.permissions.includes(scope))) return null;
    return {props: {delegation}, auth: {audience: value.audience, expiresAt: value.expiresAt,
      scope: value.scope, userId: value.userId, clientId: value.clientId},
    principal: {delegation, scopes: value.scope, tokenHash: createHash('sha256').update(token).digest('hex'),
      expiresAt: Math.min(value.expiresAt * 1000, delegation.expires_at_ms)}};
  }
  async function revocationSchedule() {
    const families=await kv.list({prefix:'family:',limit:42});let next=Infinity;
    for(const {name} of families.keys) {
      const family=await kv.get(name,{type:'json'});
      if(family?.revoked&&!family.cleanupDone&&(family.cleanupAttempts||0)<32&&family.expiresAt>Date.now())
        next=Math.min(next,family.nextAttemptAtMs||Date.now());
    }
    return Number.isFinite(next)?{pending:true,nextAttemptAtMs:next}:{pending:false};
  }
  return {revocationSchedule,async drainRevocations() {
    const families=await kv.list({prefix:'family:',limit:42});let attempted=0;
    for(const {name} of families.keys) {
      const family=await kv.get(name,{type:'json'});
      if(attempted<2&&family?.revoked&&!family.cleanupDone&&(family.cleanupAttempts||0)<32&&family.expiresAt>Date.now()&&(family.nextAttemptAtMs||0)<=Date.now()) {
        attempted++;try {await cleanupFamily(name);} catch {} // Another request may own this attempt.
      }
    }
    return revocationSchedule();
  }, async fetch(request, _env, ctx) {
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
            const result = await transaction(async txkv=>{
              const form=new URLSearchParams(await boundedRequest.clone().text());
              const token=form.get('code')||form.get('refresh_token'), parts=token?.split(':');
              try {
                const result=await strictRefreshFetch(provider,boundedRequest.clone(),{...oauthEnv,OAUTH_KV:txkv},context,info.clientId);
                if(result.ok&&parts?.length===3&&trialStates.has(parts[1])) {
                  const key=`family:${parts[0]}:${parts[1]}`,family=await txkv.get(key,{type:'json'});
                  if(!family||family.revoked||family.clientId!==info.clientId||family.expiresAt<=Date.now()||JSON.stringify(family.descriptor)!==JSON.stringify(trialStates.get(parts[1]).descriptor))throw new Error('trial_family_unavailable');
                  family.issued=true;if(trialStates.get(parts[1]).state==='active')family.provisioned=true;await txkv.put(key,JSON.stringify(family),{expiration:Math.ceil(family.expiresAt/1000)});
                }
                await Promise.all(pending);return result;
              } finally {if(parts?.length===3)trialStates.delete(parts[1]);}
            });
            const form=new URLSearchParams(await boundedRequest.clone().text());
            const supplied=form.get('refresh_token') || form.get('token') || form.get('code');
            if(supplied?.split(':').length===3){const [u,g]=supplied.split(':');const key=`family:${u}:${g}`;
              // Standard refresh-token revocation deletes the grant; tombstone the trial too.
              const family=await kv.get(key,{type:'json'});
              if(family && !await kv.get(`grant:${u}:${g}`)) await revokeFamily(key);
              else if(family?.revoked) await cleanupFamily(key);
            }
            return result;
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
  for (const key of ['client_id', 'client_assertion', 'client_assertion_type','grant_type','refresh_token','token','code','resource','scope']) if (form.getAll(key).length > 1) throw new Error('invalid_client');
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
