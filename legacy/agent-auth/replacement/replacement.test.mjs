import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {createHash,randomUUID} from 'node:crypto';
import {ORIGIN,BASE} from './config.mjs';
const root=new URL('./',import.meta.url);
const built=await build({entryPoints:[fileURLToPath(new URL('worker.mjs',root))],bundle:true,write:false,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:*','node:*'],conditions:['workerd','worker','browser']});
const schema=await readFile(new URL('schema.sql',root),'utf8');
async function start(dir,enabled=true){
 const options=convertV4MiniflareOptions({name:'replacement-proof',modules:true,script:built.outputFiles[0].text,
  compatibilityDate:'2026-10-23',compatibilityFlags:['nodejs_compat'],
  durableObjects:{AGENT_AUTH_HUB:{className:'AgentAuthReplacement',useSQLite:true}},d1Databases:['REPLACEMENT_AUTH_DB'],
  bindings:{AGENT_AUTH_REPLACEMENT_ENABLED:enabled?'operator-approved':'disabled',AGENT_AUTH_SESSION_SECRET:'ephemeral-local-fixture-only-do-not-use-in-production'},
  outboundService:()=>{throw Error('outbound_network_forbidden');}});
 options.resourcePersistencePath=dir;
 const mf=new Miniflare(options),db=await mf.getD1Database('REPLACEMENT_AUTH_DB');
 return {mf,db};
}
async function fixture(t){
 const dir=await mkdtemp(join(tmpdir(),'runlater-replacement-'));
 let current=await start(dir);
 t.after(async()=>{await current.mf.dispose();await rm(dir,{recursive:true,force:true});});
 await current.db.batch(schema.split(';').filter(s=>s.trim()).map(s=>current.db.prepare(s)));
 const host=await generateKeyPair('EdDSA'),agent=await generateKeyPair('EdDSA');
 const key=await exportJWK(host.publicKey),agentKey=await exportJWK(agent.publicKey);
 const sign=(privateKey,typ,claims,audience=ORIGIN+BASE)=>new SignJWT(claims).setProtectedHeader({alg:'EdDSA',typ}).setIssuedAt().setExpirationTime('45s').setAudience(audience).setJti(randomUUID()).sign(privateKey);
 const send=(path,token,body,method='POST')=>current.mf.dispatchFetch(ORIGIN+path,{method,headers:{'content-type':'application/json',...(token?{authorization:'Bearer '+token}:{})},...(body?{body:JSON.stringify(body)}:{})});
 const reg=async(changes={})=>send(BASE+'/agent/register',await sign(host.privateKey,'host+jwt',{iss:'fixture-host',host_public_key:key,agent_public_key:agentKey,...changes}),{name:'Local agent',mode:'autonomous',capabilities:['connection_status']});
 return {get db(){return current.db;},send,reg,sign,host,agent,
  async restart(){await current.mf.dispose();current=await start(dir);},
  async execution(identity,changes={}){
   const body={capability:'connection_status',arguments:{}};
   const jwt=await sign(agent.privateKey,'agent+jwt',{sub:identity.agent_id,capabilities:['connection_status'],htm:'POST',htu:ORIGIN+BASE+'/capability/execute',ath:createHash('sha256').update(JSON.stringify(body)).digest('base64url'),...changes},ORIGIN+BASE+'/capability/execute');
   return {jwt,body};
  }};
}
test('real Better Auth D1 registration, execution and durable replay survive runtime restart',async t=>{
 const f=await fixture(t);
 const reg=await f.reg(),identity=await reg.json();
 assert.equal(reg.status,200,JSON.stringify(identity));assert.equal(identity.status,'active');
 const {jwt,body}=await f.execution(identity);
 const res=await f.send(BASE+'/capability/execute',jwt,body);
 assert.equal(res.status,200,await res.clone().text());
 const value=await res.json();assert.equal(value.data?.scheduling_enabled,false,JSON.stringify(value));assert.equal(value.data.project_link_required,true);
 await f.restart();
 const replay=await f.send(BASE+'/capability/execute',jwt,body);
 assert.equal(replay.status,401,await replay.clone().text());
 const rows=await f.db.prepare('SELECT * FROM agent').all();assert.equal(rows.results.length,1);
});
test('replacement retires OAuth/MCP routes without importing bearer grants or state',async t=>{
 const f=await fixture(t);
 for(const path of ['/authorize','/oauth/token','/.well-known/oauth-authorization-server','/mcp','/sse']){
  const response=await f.send(path,'legacy-opaque-oauth-token',undefined,'GET');
  assert.equal(response.status,410);assert.equal((await response.json()).legacy_grant_conversion,false);
 }
 assert.equal((await f.db.prepare('SELECT count(*) AS count FROM agent').first()).count,0);
 const discovery=await f.send('/.well-known/agent-configuration',null,null,'GET');assert.equal(discovery.status,200);
});
test('concurrent real-plugin replay accepts exactly once',async t=>{
 const f=await fixture(t),identity=await (await f.reg()).json(),{jwt,body}=await f.execution(identity);
 const results=await Promise.all(Array.from({length:4},()=>f.send(BASE+'/capability/execute',jwt,body)));
 assert.deepEqual(results.map(r=>r.status).sort(),[200,401,401,401]);
});
test('no remote JWKS or implicit scheduling escalation, explicit request binding required',async t=>{
 const f=await fixture(t);
 assert.equal((await f.reg({agent_jwks_url:'https://127.0.0.1/keys'})).status,400);
 const identity=await (await f.reg()).json();
 const {jwt,body}=await f.execution(identity,{htm:undefined});
 assert.equal((await f.send(BASE+'/capability/execute',jwt,body)).status,400);
 const fresh=await f.execution(identity,{capabilities:['http_schedule']});
 assert.ok((await f.send(BASE+'/capability/execute',fresh.jwt,{capability:'http_schedule',arguments:{}})).status>=400);
});
test('D1 lifecycle denies revoked host or expired grant and cannot reset trials',async t=>{
 const f=await fixture(t),identity=await (await f.reg()).json();
 await f.db.prepare('UPDATE agentHost SET status=?,publicKey=? WHERE id=?').bind('revoked','',identity.host_id).run();
 const {jwt,body}=await f.execution(identity);
 assert.equal((await f.send(BASE+'/capability/execute',jwt,body)).status,403);
 assert.equal((await f.reg()).status,403);
});
test('expired D1 grants cannot auto-renew from host budget',async t=>{
 const f=await fixture(t),identity=await (await f.reg()).json();
 await f.db.prepare('UPDATE agentCapabilityGrant SET expiresAt=? WHERE agentId=?').bind(new Date(Date.now()-1000).toISOString(),identity.agent_id).run();
 const {jwt,body}=await f.execution(identity);
 assert.equal((await f.send(BASE+'/capability/execute',jwt,body)).status,403);
 assert.equal((await f.db.prepare('SELECT count(*) AS count FROM agentCapabilityGrant WHERE agentId=?').bind(identity.agent_id).first()).count,1);
});
test('per-host lifetime enrollment cap remains after agent revocation',async t=>{
 const f=await fixture(t),first=await (await f.reg()).json();
 for(let n=0;n<3;n++){
  const extra=await generateKeyPair('EdDSA');
  const response=await f.reg({agent_public_key:await exportJWK(extra.publicKey)});
  assert.equal(response.status,200,await response.clone().text());
 }
 await f.db.prepare('UPDATE agent SET status=? WHERE id=?').bind('revoked',first.agent_id).run();
 const extra=await generateKeyPair('EdDSA');
 assert.equal((await f.reg({agent_public_key:await exportJWK(extra.publicKey)})).status,429);
});
test('real signed host revoke retains key tombstone and does not break other registrations',async t=>{
 const f=await fixture(t),identity=await (await f.reg()).json();
 const token=await f.sign(f.host.privateKey,'host+jwt',{iss:identity.host_id});
 const revoked=await f.send(BASE+'/host/revoke',token,{host_id:identity.host_id});
 assert.equal(revoked.status,200,await revoked.clone().text());
 assert.equal((await f.db.prepare('SELECT publicKey FROM agentHost WHERE id=?').bind(identity.host_id).first()).publicKey,'');
 await f.restart();
 assert.equal((await f.reg()).status,403);
 const other=await generateKeyPair('EdDSA');
 const key=await exportJWK(other.publicKey),agent=await generateKeyPair('EdDSA');
 const jwt=await f.sign(other.privateKey,'host+jwt',{iss:'other-fixture',host_public_key:key,agent_public_key:await exportJWK(agent.publicKey)});
 const result=await f.send(BASE+'/agent/register',jwt,{name:'Other local agent',mode:'autonomous',capabilities:['connection_status']});
 assert.equal(result.status,200,await result.clone().text());
});
test('replacement gate is off without explicit configuration',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'runlater-off-'));
 const f=await start(dir,false);
 t.after(async()=>{await f.mf.dispose();await rm(dir,{recursive:true,force:true});});
 assert.equal((await f.mf.dispatchFetch(ORIGIN+'/.well-known/agent-configuration')).status,503);
 assert.equal((await f.mf.dispatchFetch(ORIGIN+'/authorize')).status,503);
});
test('registration refuses legacy credential fields instead of silently consuming them',async t=>{
 const f=await fixture(t),key=await exportJWK(f.host.publicKey),agentKey=await exportJWK(f.agent.publicKey);
 const jwt=await f.sign(f.host.privateKey,'host+jwt',{iss:'fixture-host',host_public_key:key,agent_public_key:agentKey});
 const response=await f.send(BASE+'/agent/register',jwt,{name:'Local agent',mode:'autonomous',capabilities:['connection_status'],legacy_access_token:'fixture-opaque-token'});
 assert.equal(response.status,400);
 assert.equal((await f.db.prepare('SELECT count(*) AS count FROM agent').first()).count,0);
});
test('ten lifetime host admissions remain consumed after real host revocation',async t=>{
 const f=await fixture(t),first=await (await f.reg()).json();
 for(let n=0;n<9;n++){
  const host=await generateKeyPair('EdDSA');
  const jwt=await f.sign(host.privateKey,'host+jwt',{iss:'fixture-'+n,host_public_key:await exportJWK(host.publicKey),agent_public_key:await exportJWK(f.agent.publicKey)});
  const response=await f.send(BASE+'/agent/register',jwt,{name:'Another fixture',mode:'autonomous',capabilities:['connection_status']});
  assert.equal(response.status,200,await response.clone().text());
 }
 const revoke=await f.sign(f.host.privateKey,'host+jwt',{iss:first.host_id});
 assert.equal((await f.send(BASE+'/host/revoke',revoke,{host_id:first.host_id})).status,200);
 await f.restart();
 const extra=await generateKeyPair('EdDSA');
 const jwt=await f.sign(extra.privateKey,'host+jwt',{iss:'extra',host_public_key:await exportJWK(extra.publicKey),agent_public_key:await exportJWK(f.agent.publicKey)});
 assert.equal((await f.send(BASE+'/agent/register',jwt,{name:'Extra fixture',mode:'autonomous',capabilities:['connection_status']})).status,429);
});
