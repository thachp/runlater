import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,generateKeyPairSync,verify} from 'node:crypto';
import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {AgentAuthClient,MemoryStorage,signHostJWT,generateKeypair} from '@auth/agent';
import {executeBound,revokeHostBound} from './client.mjs';
import {ORIGIN} from '../replacement/config.mjs';
import {capabilityNames} from './projects.mjs';
import {trialProjectId} from '../../mcp/trial-client.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
const built=await build({entryPoints:[fileURLToPath(new URL('worker.mjs',import.meta.url))],bundle:true,write:false,format:'esm',platform:'neutral',mainFields:['module','main'],external:['cloudflare:*','node:*'],conditions:['workerd','worker','browser']});
const schema=await readFile(new URL('../replacement/schema.sql',import.meta.url),'utf8');
async function fixture(t,{enabled=true}={}){
 const dir=await mkdtemp(join(tmpdir(),'runlater-canonical-')),gateway=generateKeyPairSync('ed25519');
 const apiProjects=new Map(),seen=new Set();let calls=0,failAfterProvision=false,captured,failRevoke=false;
 // Explicit API contract fixture, not the Rust engine or a hosted service.
 // Verify the real source client's signed wire, scope and budget continuity.
 const api=async request=>{
  calls++;
  const h=request.headers,url=new URL(request.url),body=await request.text();
  const d=JSON.parse(Buffer.from(h.get('RunLater-Trial-Bootstrap'),'base64url').toString());
  const project=trialProjectId(d),revoking=url.pathname==='/v1/mcp/trials/revoke';
  assert.equal(h.get('RunLater-Project-Id'),project);
  const secret=h.get(revoking?'RunLater-Trial-Revocation':'RunLater-Trial-Capability'),purpose=revoking?'revocation':'capability';
  assert.equal(hash(`RunLater anonymous trial ${purpose} v1\n`+JSON.stringify([1,d.release_id,d.bootstrap_id,secret])),d[purpose+'_hash']);
  const now=+h.get('RunLater-Issued-At'),expiry=+h.get('RunLater-Expires-At'),nonce=h.get('RunLater-Nonce'),key=h.get('Idempotency-Key')??'';
  assert.ok(now>=d.issued_at_ms&&now<Date.now()+1000&&expiry<=d.expires_at_ms&&expiry>now);
  assert.equal(seen.has(nonce),false);seen.add(nonce);
  const wire='RunLater anonymous trial request v1\n'+JSON.stringify([1,'https://api.runlater.io',d.release_id,project,d.bootstrap_id,d.capability_hash,hash(JSON.stringify(d)),request.method,url.pathname,'',hash(body),key,now,expiry,nonce]);
  assert.ok(verify(null,Buffer.from(wire),gateway.publicKey,Buffer.from(h.get('RunLater-Request-Signature'),'hex')));
  if(url.pathname==='/v1/mcp/trials/provision'){
   assert.equal(key,d.bootstrap_id);assert.deepEqual(JSON.parse(body),{});
   if(!apiProjects.has(project))apiProjects.set(project,{remaining:100,descriptor:d,revoked:false,keys:new Set()});
   if(failAfterProvision){failAfterProvision=false;return new Response('',{status:503});}
   return Response.json({state:'active',project_id:project,expires_at_ms:d.expires_at_ms,permissions:d.permissions,receiver_ready:false,attempt_units:100,client_operations_limit:1000});
  }
  const row=apiProjects.get(project);assert.ok(row);
  if(revoking){if(failRevoke)return new Response('',{status:503});row.revoked=true;return Response.json({revoked:true,provisioned:true});}
  if(row.revoked)return new Response('',{status:403});
  if(url.pathname==='/v1/http/tasks'){
   assert.ok(d.permissions.includes('http_schedule'));
   if(!row.keys.has(key)){if(!row.remaining)return new Response('',{status:429});row.remaining--;row.keys.add(key);}
   return Response.json({task_id:'task_0123456789abcdef',project_id:project,operation_key:JSON.parse(body).operation_key});
  }
  return Response.json({project_id:project,task_id:url.pathname.split('/')[3]});
 };
 let current;
 async function start(){
  const options=convertV4MiniflareOptions({name:'canonical-proof',modules:true,script:built.outputFiles[0].text,
   compatibilityDate:'2026-10-23',compatibilityFlags:['nodejs_compat'],
   durableObjects:{AGENT_AUTH_HUB:{className:'CanonicalAgentAuth',useSQLite:true}},d1Databases:['REPLACEMENT_AUTH_DB'],
   bindings:{AGENT_AUTH_REPLACEMENT_ENABLED:'operator-approved',CANONICAL_AGENT_AUTH_ENABLED:enabled?'operator-approved':'off',
    AGENT_AUTH_SESSION_SECRET:'ephemeral-local-fixture-only-do-not-use-in-production',MCP_RELEASE_ID:'canonical-fixture',
    MCP_GATEWAY_PRIVATE_KEY:gateway.privateKey.export({format:'pem',type:'pkcs8'}),MCP_GATEWAY_PUBLIC_KEY:gateway.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex')},
   serviceBindings:{CANONICAL_API:api},outboundService:()=>{throw Error('external_network_forbidden');}});
  options.resourcePersistencePath=dir;
  const mf=new Miniflare(options);return {mf,db:await mf.getD1Database('REPLACEMENT_AUTH_DB')};
 }
 current=await start();t.after(async()=>{await current.mf.dispose();await rm(dir,{recursive:true,force:true});});
 await current.db.batch(schema.split(';').filter(s=>s.trim()).map(s=>current.db.prepare(s)));
 const transport=async(url,init)=>{if(new URL(url).origin!==ORIGIN)throw Error('external_network_forbidden');
  captured={url,init};return current.mf.dispatchFetch(url,init);};
 const storage=new MemoryStorage(),sdk=new AgentAuthClient({storage,fetch:transport,directoryUrl:null,allowDirectDiscovery:true,hostName:'Ephemeral local fixture'});
 const connect=()=>sdk.connectAgent({provider:ORIGIN,mode:'autonomous',capabilities:capabilityNames,name:'Ephemeral agent'});
 const execute=(agentId,capability,args={})=>executeBound(sdk,{agentId,capability,args},{fetchImpl:transport});
 return {sdk,storage,transport,connect,execute,apiProjects,get calls(){return calls;},get captured(){return captured;},get db(){return current.db;},
  set failAfterProvision(v){failAfterProvision=v;},set failRevoke(v){failRevoke=v;},
  async replay(){return transport(captured.url,captured.init);},
  async restart(){await current.mf.dispose();current=await start();}};
}
async function data(response){assert.equal(response.status,200,await response.clone().text());return (await response.json()).data;}
test('actual SDK + Better Auth + workerd D1: no-account canonical project and signed API fixture scheduling',async t=>{
 const f=await fixture(t),identity=await f.connect();assert.equal(f.calls,0);
 assert.equal((await data(await f.execute(identity.agentId,'project_status'))).state,'unprovisioned');assert.equal(f.calls,0);
 const created=await data(await f.execute(identity.agentId,'create_project'));assert.equal(created.state,'active');assert.equal(f.apiProjects.size,1);
 const args={task:{url:'https://example.com/task',payload:{hello:'fixture'},operation_key:'local-operation',run_at_ms:Date.now()+60000},idempotency_key:'local-idempotency'};
 const task=await data(await f.execute(identity.agentId,'schedule_http',args));assert.equal(task.project_id,created.project_id);
 assert.equal([...f.apiProjects.values()][0].remaining,99);
 const replay=await f.replay();assert.equal(replay.status,401);
 await f.restart();const same=await data(await f.execute(identity.agentId,'create_project'));assert.equal(same.project_id,created.project_id);assert.equal(same.expires_at_ms,created.expires_at_ms);
 await data(await f.execute(identity.agentId,'schedule_http',args));assert.equal([...f.apiProjects.values()][0].remaining,99);
 const second=await f.connect();assert.equal(second.hostId,identity.hostId);
 assert.equal((await data(await f.execute(second.agentId,'create_project'))).project_id,created.project_id);
 assert.equal(f.apiProjects.size,1);
});
test('unknown signed API provision result cannot allocate a fresh project on retry',async t=>{
 const f=await fixture(t),identity=await f.connect();f.failAfterProvision=true;
 const first=await f.execute(identity.agentId,'create_project');assert.ok(first.status>=400);
 const pending=await data(await f.execute(identity.agentId,'project_status'));assert.equal(pending.state,'pending');await f.restart();
 const active=await data(await f.execute(identity.agentId,'create_project'));assert.equal(active.project_id,pending.project_id);assert.equal(f.apiProjects.size,1);
});
test('actual SDK convenience execution fails binding; forged project selectors rejected; revocation blocks forever',async t=>{
 const f=await fixture(t),identity=await f.connect();await data(await f.execute(identity.agentId,'create_project'));
 await assert.rejects(f.sdk.executeCapability({agentId:identity.agentId,capability:'project_status',arguments:{}}));
 assert.ok((await f.execute(identity.agentId,'project_status',{project_id:'other'})).status>=400);
 f.failRevoke=true;const revoked=await data(await f.execute(identity.agentId,'revoke_project'));assert.equal(revoked.state,'revoked');assert.equal(revoked.cleanup_pending,true);
 await f.restart();assert.ok((await f.execute(identity.agentId,'create_project')).status>=400);
 assert.equal(f.apiProjects.size,1);
});
test('canonical wrapper remains off by default',async t=>{
 const f=await fixture(t,{enabled:false});await assert.rejects(f.connect());assert.equal(f.calls,0);assert.equal(f.apiProjects.size,0);
});
test('same signing key cannot gain another canonical host/project by changing JWK representation',async t=>{
 const f=await fixture(t),identity=await f.connect();await data(await f.execute(identity.agentId,'create_project'));
 const host=await f.storage.getHostIdentity(),agent=await generateKeypair();
 for(const publicKey of [{x:host.keypair.publicKey.x,crv:'Ed25519',kty:'OKP',kid:host.keypair.publicKey.kid},
  {kty:'OKP',crv:'Ed25519',x:host.keypair.publicKey.x}, {...host.keypair.publicKey,kid:'alternate-id'}]){
  const token=await signHostJWT({hostKeypair:{...host.keypair,publicKey},agentPublicKey:agent.publicKey,audience:ORIGIN});
  const result=await f.transport(ORIGIN+'/api/auth/agent/register',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token},body:JSON.stringify({name:'Alternate representation',mode:'autonomous',capabilities:capabilityNames})});
  assert.ok(result.status>=400,await result.clone().text());
 }
 assert.equal((await f.db.prepare('SELECT count(*) AS count FROM agentHost').first()).count,1);assert.equal(f.apiProjects.size,1);
});
test('host revoke requires bound body and durable replay, and reconciles failed API cleanup after restart',async t=>{
 const f=await fixture(t),identity=await f.connect();await data(await f.execute(identity.agentId,'create_project'));
 const host=await f.storage.getHostIdentity(),token=await signHostJWT({hostKeypair:host.keypair,issuer:identity.hostId,audience:ORIGIN+'/api/auth'});
 const general=await f.transport(ORIGIN+'/api/auth/host/revoke',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+token},body:JSON.stringify({host_id:identity.hostId})});
 assert.equal(general.status,401);assert.equal((await data(await f.execute(identity.agentId,'project_status'))).state,'active');
 f.failRevoke=true;const response=await revokeHostBound(f.storage,identity.hostId,{fetchImpl:f.transport});
 assert.equal(response.status,200,await response.clone().text());const captured=f.captured;
 assert.equal((await f.transport(captured.url,captured.init)).status,401);
 await f.restart();assert.ok((await f.execute(identity.agentId,'create_project')).status>=400);
 f.failRevoke=false;await f.transport(ORIGIN+'/.well-known/agent-configuration');
 assert.equal([...f.apiProjects.values()][0].revoked,true);assert.equal(f.apiProjects.size,1);
});
test('partial upstream host revoke is reconciled before an agent can execute',async t=>{
 const f=await fixture(t),identity=await f.connect();await data(await f.execute(identity.agentId,'create_project'));
 await f.db.prepare("UPDATE agentHost SET status='revoked',publicKey='' WHERE id=?").bind(identity.hostId).run();
 await f.restart();assert.equal((await f.execute(identity.agentId,'schedule_http',{task:{},idempotency_key:'never'})).status,403);
 assert.equal([...f.apiProjects.values()][0].revoked,true);
});
