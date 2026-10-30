import {DurableObject} from 'cloudflare:workers';
import {createHash} from 'node:crypto';
import {betterAuth} from 'better-auth';
import {calculateJwkThumbprint,decodeJwt,importJWK,jwtVerify} from 'jose';
import {authOptions,ORIGIN,BASE} from './config.mjs';
const headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
const error=(status,code)=>Response.json({error:code},{status,headers});
const retired=new Set(['/authorize','/oauth/token','/.well-known/oauth-authorization-server','/.well-known/oauth-protected-resource','/mcp','/sse','/messages']);
const routes=new Set(['/agent/register','/capability/list','/capability/describe','/capability/execute','/agent/status','/agent/revoke','/host/revoke']);
export const ready=env=>env.AGENT_AUTH_REPLACEMENT_ENABLED==='operator-approved' && !!env.REPLACEMENT_AUTH_DB
  && typeof env.AGENT_AUTH_SESSION_SECRET==='string' && env.AGENT_AUTH_SESSION_SECRET.length>=32;
async function bodyText(request) {
  const reader=request.body?.getReader();if(!reader)return '';
  const parts=[];let size=0,chunks=0,timer;
  try {
    const read=(async()=>{for(;;){const {done,value}=await reader.read();if(done)break;if((size+=value.byteLength)>8192 || ++chunks>32)throw Error('body_limit');parts.push(value);}})();
    await Promise.race([read,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('body_timeout')),5000);})]);
    const bytes=new Uint8Array(size);let offset=0;for(const p of parts){bytes.set(p,offset);offset+=p.byteLength;}
    return new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  } finally {clearTimeout(timer);await reader.cancel();}
}
function publicKey(key) {
  if(key?.kty!=='OKP'||key.crv!=='Ed25519'||typeof key.x!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(key.x)||Object.keys(key).some(k=>!['kty','crv','x','kid'].includes(k))||(key.kid!==undefined&&(typeof key.kid!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(key.kid))))throw Error('public_key_required');
  return {kty:'OKP',crv:'Ed25519',x:key.x};
}
export function createAgentAuthHub({capabilities,onExecute,onHostRevoked,onAlarm,additionalReady=()=>true}={}) {
 return class AgentAuthHub extends DurableObject {
  constructor(ctx,env) {
    super(ctx,env);this.env=env;this.tail=Promise.resolve();this.waiting=0;
    if(!ready(env)||!additionalReady(env))return;
    ctx.blockConcurrencyWhile(async()=>{
      ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS secondary (key TEXT PRIMARY KEY,value TEXT NOT NULL,expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS admissions (key TEXT PRIMARY KEY,created INTEGER NOT NULL,host_id TEXT,revoked INTEGER NOT NULL DEFAULT 0);`);
    });
  }
  #sql(query,...args){return this.ctx.storage.sql.exec(query,...args).toArray();}
  #secondary(){return {
    get:async key=>{const row=this.#sql('SELECT * FROM secondary WHERE key=?',key)[0];return row&&row.expires>Date.now()?row.value:null;},
    set:async(key,value,ttl)=>{
      if(typeof key!=='string'||key.length>2048||typeof value!=='string'||value.length>16384||!Number.isFinite(ttl)||ttl<1||ttl>604800)throw Error('storage_bound');
      this.#sql('DELETE FROM secondary WHERE expires<=?',Date.now());
      if(!this.#sql('SELECT 1 FROM secondary WHERE key=?',key).length&&this.#sql('SELECT count(*) AS count FROM secondary')[0].count>=2048)throw Error('storage_capacity');
      this.#sql('INSERT INTO secondary VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,expires=excluded.expires',key,value,Date.now()+ttl*1000);
      await this.ctx.storage.sync();
    },
    increment:async(key,ttl)=>{
      if(typeof key!=='string'||key.length>2048||!Number.isFinite(ttl)||ttl<1||ttl>604800)throw Error('storage_bound');
      const count=this.ctx.storage.transactionSync(()=>{
        const now=Date.now();this.#sql('DELETE FROM secondary WHERE expires<=?',now);
        const old=this.#sql('SELECT * FROM secondary WHERE key=?',key)[0];
        if(!old&&this.#sql('SELECT count(*) AS count FROM secondary')[0].count>=2048)throw Error('storage_capacity');
        const next=old?Number(old.value)+1:1;
        this.#sql('INSERT INTO secondary VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',key,String(next),now+ttl*1000);
        return next;
      });
      await this.ctx.storage.sync();return count;
    },
    delete:async key=>{this.#sql('DELETE FROM secondary WHERE key=?',key);await this.ctx.storage.sync();},
  };}
  #auth(){
    if(this.auth)return this.auth;
    this.background=[];
    this.auth=betterAuth(authOptions({database:this.env.REPLACEMENT_AUTH_DB,secret:this.env.AGENT_AUTH_SESSION_SECRET,secondaryStorage:this.#secondary(),
      background:promise=>this.background.push(Promise.resolve(promise).then(()=>true,()=>false)),capabilities,
      resolveAutonomousUser:({hostId})=>({id:`agent-host:${hostId}`,name:'Autonomous RunLater agent',email:`${hostId}@identity.invalid`}),
      onExecute:async args=>onExecute?onExecute({...args,env:this.env,storage:this.ctx.storage}):({agent_id:args.agentSession.agent.id,host_id:args.agentSession.agent.hostId,project_link_required:true,legacy_grant_imported:false,scheduling_enabled:false}),
    }));
    return this.auth;
  }
  async #reconcileRevocations(){
    if(!onHostRevoked)return;
    const hosts=await this.env.REPLACEMENT_AUTH_DB.prepare("SELECT id FROM agentHost WHERE status='revoked'").all();
    const ids=new Set([...hosts.results.map(h=>h.id),...this.#sql('SELECT host_id FROM admissions WHERE revoked=1 AND host_id IS NOT NULL').map(h=>h.host_id)]);
    for(const hostId of ids)await onHostRevoked({hostId,env:this.env,storage:this.ctx.storage});
    if(onAlarm)await onAlarm({env:this.env,storage:this.ctx.storage});
  }
  async #handle(request){
    const url=new URL(request.url),path=url.pathname.slice(BASE.length),db=this.env.REPLACEMENT_AUTH_DB;
    const auth=this.#auth();
    await this.#reconcileRevocations();
    if(url.pathname==='/.well-known/agent-configuration'){
      const config=await auth.api.getAgentConfiguration();
      config.approval_methods=[];
      config.endpoints=Object.fromEntries(Object.entries(config.endpoints).filter(([,u])=>routes.has(new URL(u).pathname.slice(BASE.length))));
      return Response.json(config,{headers});
    }
    const raw=await bodyText(request);
    const token=request.headers.get('authorization')?.replace(/^Bearer\s+/i,'');
    let claims;
    if(token){
      if(token.length>8192)return error(400,'invalid_token');
      try {claims=decodeJwt(token);}catch{return error(401,'invalid_token');}
      if(['jwks_url','host_jwks_url','agent_jwks_url'].some(k=>claims[k]!==undefined))return error(400,'remote_keys_disabled');
    }
    if(path==='/agent/register'){
      let input,key;
      try {
        input=JSON.parse(raw);
        if(Object.keys(input).some(k=>!['name','mode','capabilities','reason','host_name'].includes(k))||input.mode!=='autonomous'||input.capabilities?.some(c=>!(capabilities?.map(def=>def.name)??['connection_status']).includes(c)))throw Error();
        key=publicKey(claims?.host_public_key);publicKey(claims?.agent_public_key);
        for(const jwk of [claims.host_public_key,claims.agent_public_key])if(jwk.kid!==undefined&&jwk.kid!==await calculateJwkThumbprint(publicKey(jwk)))throw Error();
        await jwtVerify(token,await importJWK(key,'EdDSA'),{algorithms:['EdDSA'],typ:'host+jwt',audience:[ORIGIN,ORIGIN+BASE],maxTokenAge:60,clockTolerance:30,requiredClaims:['iat','exp','jti']});
      }catch{return error(400,'registration_rejected');}
      // Bounded identity enrollment only; this does not allocate a trial/project.
      // Failed registrations keep their reservation instead of resetting capacity.
      const fingerprint=key.x;
      const admission=this.#sql('SELECT * FROM admissions WHERE key=?',fingerprint)[0];
      if(admission?.revoked)return error(403,'host_revoked');
      if(admission?.host_id){
        const prior=await db.prepare('SELECT status FROM agentHost WHERE id=?').bind(admission.host_id).first();
        if(!prior)return error(503,'identity_state_missing');
        if(prior.status==='revoked'){this.#sql('UPDATE admissions SET revoked=1 WHERE key=?',fingerprint);await this.ctx.storage.sync();return error(403,'host_revoked');}
      }
      const hostRows=await db.prepare('SELECT id,status FROM agentHost WHERE CASE WHEN json_valid(publicKey) THEN json_extract(publicKey,\'$.x\') END=?').bind(fingerprint).all();
      // The pinned plugin can look up a host by exact JSON. Reject an alternate
      // representation instead of permitting a second canonical host identity.
      if(hostRows.results.length>1)return error(503,'identity_reconciliation_required');
      if(hostRows.results.length){
        const existing=await db.prepare('SELECT publicKey FROM agentHost WHERE id=?').bind(hostRows.results[0].id).first();
        if(existing.publicKey!==JSON.stringify(claims.host_public_key))return error(403,'host_key_representation_changed');
        if(admission?.host_id&&admission.host_id!==hostRows.results[0].id)return error(503,'identity_reconciliation_required');
      }
      if(admission&&!admission.host_id&&!hostRows.results.length)return error(503,'identity_reconciliation_required');
      if(hostRows.results.some(h=>h.status==='revoked'))return error(403,'host_revoked');
      const agents=await db.prepare('SELECT count(*) AS count FROM agent WHERE hostId IN (SELECT id FROM agentHost WHERE CASE WHEN json_valid(publicKey) THEN json_extract(publicKey,\'$.x\') END=?)').bind(fingerprint).first();
      if(agents.count>=4)return error(429,'lifetime_agent_capacity');
      const old=this.#sql('SELECT 1 FROM admissions WHERE key=?',fingerprint).length;
      if(!old&&this.#sql('SELECT count(*) AS count FROM admissions')[0].count>=10)return error(429,'lifetime_host_capacity');
      if(!old){this.#sql('INSERT INTO admissions(key,created) VALUES(?,?)',fingerprint,Date.now());await this.ctx.storage.sync();}
    }else if(claims?.sub){
      // Denial-only DB policy; signature and capability verification remain owned
      // by Better Auth. Never authorize from these unverified claims.
      const row=await db.prepare('SELECT h.id AS hostId,h.status AS hostStatus FROM agent a JOIN agentHost h ON h.id=a.hostId WHERE a.id=?').bind(claims.sub).first();
      if(row?.hostStatus==='revoked')return error(403,'host_revoked');
      if(row?.hostId&&this.#sql('SELECT 1 FROM admissions WHERE host_id=? AND revoked=1',row.hostId).length)return error(403,'host_revoked');
      const expired=await db.prepare('SELECT 1 AS found FROM agentCapabilityGrant WHERE agentId=? AND (status IN (\'revoked\',\'denied\') OR (expiresAt IS NOT NULL AND expiresAt<=?)) LIMIT 1').bind(claims.sub,new Date().toISOString()).first();
      if(expired)return error(403,'grant_inactive');
    }
    if(path==='/capability/execute'&&(!claims?.htm||!claims?.htu||!claims?.ath||claims.aud!==ORIGIN+BASE+'/capability/execute'))return error(400,'request_binding_required');
    if(path==='/host/revoke'&&onHostRevoked){
      // Record a deny-only intent before the plugin clears its verification
      // key. A crash during its D1 cascade must not leave API authority alive.
      let host;
      try{
        const input=raw?JSON.parse(raw):{};
        if(Object.keys(input).some(k=>k!=='host_id'))throw Error();
        host=await db.prepare('SELECT id,publicKey FROM agentHost WHERE id=? OR kid=?').bind(claims?.iss??'',claims?.iss??'').first();
        if(!host||(input.host_id!==undefined&&input.host_id!==host.id))throw Error();
        const jwk=publicKey(JSON.parse(host.publicKey));
        const target=ORIGIN+BASE+'/host/revoke';
        if(claims.aud!==ORIGIN+BASE||claims.htm!=='POST'||claims.htu!==target||claims.ath!==createHash('sha256').update(raw).digest('base64url')||typeof claims.jti!=='string'||claims.jti.length>128||!claims.jti.length||claims.exp-claims.iat>60)throw Error();
        await jwtVerify(token,await importJWK(jwk,'EdDSA'),{algorithms:['EdDSA'],typ:'host+jwt',audience:ORIGIN+BASE,maxTokenAge:60,clockTolerance:30,requiredClaims:['iat','exp','jti']});
        const replayKey=`host-revoke:${host.id}:${claims.jti}`,secondary=this.#secondary();
        if(await secondary.get(replayKey))throw Error();
        await secondary.set(replayKey,'consumed',Math.max(1,claims.exp-Math.floor(Date.now()/1000)+31));
      }catch{return error(401,'host_revocation_rejected');}
      await onHostRevoked({hostId:host.id,env:this.env,storage:this.ctx.storage});
      this.#sql('UPDATE admissions SET revoked=1 WHERE host_id=?',host.id);
    }
    const copy=new Request(request.url,{method:request.method,headers:request.headers,...(request.method==='GET'?{}:{body:raw})});
    const response=await auth.handler(copy);
    if(path==='/agent/register'&&claims?.host_public_key){
      const fingerprint=publicKey(claims.host_public_key).x;
      // Capture even partial D1 registration so a later key-clearing revoke
      // cannot erase identity/capacity continuity. Never overwrite this link.
      const host=await db.prepare('SELECT id FROM agentHost WHERE CASE WHEN json_valid(publicKey) THEN json_extract(publicKey,\'$.x\') END=?').bind(fingerprint).first();
      if(host)this.#sql('UPDATE admissions SET host_id=COALESCE(host_id,?) WHERE key=?',host.id,fingerprint);
    }
    if(path==='/host/revoke'&&response.ok&&claims?.iss){
      this.#sql('UPDATE admissions SET revoked=1 WHERE host_id=?',claims.iss);
    }
    return response;
  }
  fetch(request){
    if(!ready(this.env)||!additionalReady(this.env)||!this.env.AGENT_AUTH_HUB||this.ctx.id.toString()!==this.env.AGENT_AUTH_HUB.idFromName('agent-auth-replacement-v1').toString())return Promise.resolve(error(503,'replacement_disabled'));
    if(this.waiting>=8)return Promise.resolve(error(429,'authorization_busy'));
    this.waiting++;
    const result=this.tail.then(async()=>{
      let response;
      try{response=await this.#handle(request);}catch{response=error(503,'authorization_unavailable');}
      try{
        // Include asynchronous lifecycle writes in this serialized operation and
        // fail closed on a rejected write instead of reporting successful auth.
        while(this.background?.length){
          const completed=await Promise.all(this.background.splice(0));
          if(completed.some(ok=>!ok))response=error(503,'lifecycle_write_unavailable');
        }
        await this.ctx.storage.sync();
      }catch{response=error(503,'authorization_unavailable');}
      return response;
    });
    this.tail=result.catch(()=>{});
    return result.finally(()=>{this.waiting--;});
  }
 alarm(){
  if(!ready(this.env)||!additionalReady(this.env)||this.ctx.id.toString()!==this.env.AGENT_AUTH_HUB.idFromName('agent-auth-replacement-v1').toString())return Promise.resolve();
  const result=this.tail.then(async()=>{await this.#reconcileRevocations();await this.ctx.storage.sync();});
  this.tail=result.catch(()=>{});return result;
 }
 };
}
export const AgentAuthReplacement=createAgentAuthHub();
export default {async fetch(request,env){
  const url=new URL(request.url);
  if(url.origin!==ORIGIN)return error(403,'host_rejected');
  if(!ready(env)||!env.AGENT_AUTH_HUB)return error(503,'replacement_disabled');
  if(retired.has(url.pathname))return Response.json({error:'authentication_protocol_replaced',protocol:'agent-auth',
    discovery:`${ORIGIN}/.well-known/agent-configuration`,legacy_grant_conversion:false},{status:410,headers});
  if(url.pathname!=='/.well-known/agent-configuration'&&(!url.pathname.startsWith(BASE+'/')||!routes.has(url.pathname.slice(BASE.length))))return error(404,'not_found');
  let headerBytes=0;for(const [key,value]of request.headers)headerBytes+=key.length+value.length;
  if(headerBytes>8192)return error(413,'headers_too_large');
  const path=url.pathname.slice(BASE.length);
  const queryKeys=path==='/capability/describe'?['name']:path==='/agent/status'?['agent_id']:path==='/capability/list'?['query','cursor','limit']:[];
  const seen=new Set();
  for(const [key,value]of url.searchParams){if(!queryKeys.includes(key)||seen.has(key)||value.length>256)return error(400,'request_rejected');seen.add(key);}
  if(request.url.length>8192)return error(400,'request_rejected');
  const get=url.pathname==='/.well-known/agent-configuration'||['/capability/list','/capability/describe','/agent/status'].includes(path);
  if(request.method!==(get?'GET':'POST'))return error(405,'method_not_allowed');
  return env.AGENT_AUTH_HUB.get(env.AGENT_AUTH_HUB.idFromName('agent-auth-replacement-v1')).fetch(request);
}};
