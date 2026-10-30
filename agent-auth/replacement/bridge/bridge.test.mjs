import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {generateKeyPair,exportJWK,SignJWT,jwtVerify} from 'jose';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {build} from 'esbuild';
import {signDelegation,delegationPublicKey} from '../../../mcp/delegation.mjs';
import {PUBLIC_BETA_TERMS} from '../../../examples/public-beta-client.v1.mjs';
import {digest,linkBytes,verifyOwnerLinkControl,executionRequest} from './proofs.mjs';
const BASE='https://mcp.runlater.io/api/auth';
const bundle=await build({entryPoints:[fileURLToPath(new URL('worker.mjs',import.meta.url))],bundle:true,write:false,format:'esm',platform:'neutral',mainFields:['module','main'],external:['node:*','cloudflare:*'],conditions:['workerd','worker','browser']});
const schema=await readFile(new URL('../schema.sql',import.meta.url),'utf8');
async function fixture(t,{oldController=true,sessionController=true,apiBridge=true,delegationMs=3600000}={}){
 const dir=await mkdtemp(join(tmpdir(),'runlater-link-')),now=Date.now();
 const owner=generateKeyPairSync('ed25519'),gateway=generateKeyPairSync('ed25519');
 const ownerKey=delegationPublicKey(owner.privateKey),gatewayPublicKey=delegationPublicKey(gateway.privateKey),releaseId='offline-link';
 const ticket=createHash('sha256').update(JSON.stringify(['runlater.public-beta.registration.v1',releaseId,ownerKey])).digest('hex');
 const receipt={ticket_id:ticket,project_id:'p_'+ticket.slice(0,60),public_key:ownerKey,grant_id:'g_'+ticket.slice(0,60),enrolled_at_ms:now-1000,expires_at_ms:now-1000+604800000,attempt_units:100,permissions:[...PUBLIC_BETA_TERMS.permissions]};
 const delegation=signDelegation({privateKey:owner.privateKey,receipt,releaseId,gatewayPublicKey,permissions:['enqueue','read'],delegationId:'ab'.repeat(32),issuedAtMs:now,expiresAtMs:now+delegationMs});
 const sources=new Map([['source-family',{owner,receipt,delegation}]]);
 const host=await generateKeyPair('EdDSA',{extractable:true}),agent=await generateKeyPair('EdDSA',{extractable:true});
 const calls=[],apiIdempotency=new Map(),sessionJtis=new Set();
 const state={active:true,epoch:0,remaining:37,failApi:false,drift:false,revokeOnDispatch:false,hugeOld:false,hugeSession:false,uncertainAfterCommit:false,slowOld:false,operationOnlyAssertion:false,expiredSource:false};
 let identity;
 const authority=c=>{const source=sources.get(c.family_id);return {active:true,challenge_sha256:digest(c),family_id:c.family_id,source_kind:c.source_kind,project_id:source.receipt.project_id,namespace:source.receipt.project_id,authority_ref:'authority-'+c.family_id,issued_at_ms:source.delegation.issued_at_ms,expires_at_ms:state.expiredSource?Date.now()-1:source.delegation.expires_at_ms,permissions:['enqueue','read'],revocation_epoch:state.epoch,release_id:releaseId,identity_sha256:'a'.repeat(64)};};
 const old=async req=>{
  const input=await req.json();if(state.slowOld)await new Promise(resolve=>setTimeout(resolve,6000));if(state.hugeOld)return Response.json({padding:'x'.repeat(20000)});if(!state.active)return Response.json({active:false,revocation_epoch:state.epoch});
  if(new URL(req.url).pathname==='/verify-control'){
   if(input.challenge.source_kind==='trial')return new Response(null,{status:403});
   try{verifyOwnerLinkControl(input.proof,input.challenge,{gatewayPublicKey,releaseId});}catch{return new Response(null,{status:403});}
  }
  const value=authority(input.challenge);if(state.drift)value.identity_sha256='b'.repeat(64);return Response.json(value);
 };
 const session=async req=>{
  const input=await req.json();if(state.hugeSession)return Response.json({padding:'x'.repeat(20000)});try{
   const {payload}=await jwtVerify(req.headers.get('authorization')?.slice(7),agent.publicKey,{audience:BASE+'/capability/execute',algorithms:['EdDSA'],typ:'agent+jwt',maxTokenAge:60,requiredClaims:['jti','exp','iat']});
   if(payload.sub!==identity.agent_id||payload.ath!==createHash('sha256').update(JSON.stringify(input.request)).digest('base64url')||JSON.stringify(payload.capabilities)!==JSON.stringify([input.request.operation.capability])||sessionJtis.has(payload.jti))throw Error();
   sessionJtis.add(payload.jti);if(state.operationOnlyAssertion)return Response.json({active:true,host_id:identity.host_id,agent_id:identity.agent_id,operation_sha256:digest(input.request.operation),capability:input.request.operation.capability});return Response.json({active:true,host_id:identity.host_id,agent_id:identity.agent_id,request_sha256:digest(input.request),capability:input.request.operation.capability});
  }catch{return new Response(null,{status:401});}
 };
 const api=async req=>{
  const input=await req.json();calls.push(input);if(state.revokeOnDispatch){state.active=false;state.epoch++;}
  // Contract oracle, not a live API: source must enforce family epoch again at
  // dispatch. This Map models only the existing source's idempotency/quota.
  if(!state.active||input.expected_epoch!==state.epoch)return new Response(null,{status:403});
  if(state.failApi)return new Response(null,{status:503});
  const key=input.project_id+':'+input.operation.idempotency_key;
  if(input.operation.capability==='enqueue'&&!apiIdempotency.has(key)){state.remaining-=5;apiIdempotency.set(key,{task_id:'existing-task-id',remaining:state.remaining});}
  if(state.uncertainAfterCommit){state.uncertainAfterCommit=false;return new Response(null,{status:503});}
  return Response.json({project_id:input.project_id,namespace:input.namespace,authority_epoch:state.epoch,result:apiIdempotency.get(key)??{remaining:state.remaining}});
 };
 async function start(){
  const services={};if(oldController)services.LEGACY_LINK_CONTROLLER=old;if(sessionController)services.AGENT_SESSION_CONTROLLER=session;if(apiBridge)services.SOURCE_API_BRIDGE=api;
  const options=convertV4MiniflareOptions({name:'control-link-fixture',modules:true,script:bundle.outputFiles[0].text,compatibilityDate:'2026-10-23',compatibilityFlags:['nodejs_compat'],
   durableObjects:{AGENT_AUTH_HUB:{className:'AgentAuthReplacement',useSQLite:true},LINKS:{className:'ProjectLinkAuthority',useSQLite:true}},d1Databases:['REPLACEMENT_AUTH_DB'],serviceBindings:services,
   bindings:{AGENT_AUTH_REPLACEMENT_ENABLED:'operator-approved',AGENT_AUTH_SESSION_SECRET:'ephemeral-fixture-only-not-a-production-key'},outboundService:()=>{throw Error('external_network_forbidden');}});
  options.resourcePersistencePath=dir;const mf=new Miniflare(options),db=await mf.getD1Database('REPLACEMENT_AUTH_DB'),ns=await mf.getDurableObjectNamespace('LINKS'),raw=ns.get(ns.idFromName('bounded-source-family-links'));
  return {mf,db,call:async(method,...args)=>{const result=await raw.call(method,args);if(!result.ok)throw Error(result.error);return result.value;}};
 }
 let current=await start();t.after(async()=>{await current.mf.dispose();await rm(dir,{recursive:true,force:true});});
 await current.db.batch(schema.split(';').filter(x=>x.trim()).map(x=>current.db.prepare(x)));
 const regJwt=await new SignJWT({iss:'host-fixture',host_public_key:await exportJWK(host.publicKey),agent_public_key:await exportJWK(agent.publicKey)}).setProtectedHeader({alg:'EdDSA',typ:'host+jwt'}).setIssuedAt().setExpirationTime('45s').setAudience(BASE).setJti(crypto.randomUUID()).sign(host.privateKey);
 const response=await current.mf.dispatchFetch(BASE+'/agent/register',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+regJwt},body:JSON.stringify({name:'Link fixture',mode:'autonomous',capabilities:['connection_status']})});identity=await response.json();assert.equal(response.status,200,JSON.stringify(identity));
 const prepare=(kind,family='source-family')=>current.call('prepare',{family_id:family,source_kind:kind??'owner',project_id:sources.get(family).receipt.project_id,release_id:releaseId,host_id:identity.host_id,agent_id:identity.agent_id,permissions:['enqueue','read']});
 const proof=async c=>{const source=sources.get(c.family_id);return {host_signature:Buffer.from(await crypto.subtle.sign('Ed25519',host.privateKey,linkBytes(c))).toString('hex'),agent_signature:Buffer.from(await crypto.subtle.sign('Ed25519',agent.privateKey,linkBytes(c))).toString('hex'),old_proof:{delegation:source.delegation,receipt:source.receipt,owner_signature:sign(null,linkBytes(c),source.owner.privateKey).toString('hex')}};};
 const token=(op,link,{operationOnly=false}={})=>new SignJWT({sub:identity.agent_id,capabilities:[op.capability],htm:'POST',htu:BASE+'/capability/execute',ath:createHash('sha256').update(JSON.stringify(operationOnly?op:executionRequest(link.execution_context,op))).digest('base64url')}).setProtectedHeader({alg:'EdDSA',typ:'agent+jwt'}).setAudience(BASE+'/capability/execute').setIssuedAt().setExpirationTime('45s').setJti(crypto.randomUUID()).sign(agent.privateKey);
 return {get db(){return current.db;},call:(...a)=>current.call(...a),state,calls,prepare,proof,token,identity,receipt,delegation,ownerOptions:{gatewayPublicKey,releaseId},
  addSource(){
   const other=generateKeyPairSync('ed25519'),publicKey=delegationPublicKey(other.privateKey);
   const ticket=createHash('sha256').update(JSON.stringify(['runlater.public-beta.registration.v1',releaseId,publicKey])).digest('hex');
   const otherReceipt={...receipt,ticket_id:ticket,project_id:'p_'+ticket.slice(0,60),public_key:publicKey,grant_id:'g_'+ticket.slice(0,60)};
   const otherDelegation=signDelegation({privateKey:other.privateKey,receipt:otherReceipt,releaseId,gatewayPublicKey,permissions:['enqueue','read'],delegationId:'cd'.repeat(32),issuedAtMs:now,expiresAtMs:now+delegationMs});
   sources.set('other-family',{owner:other,receipt:otherReceipt,delegation:otherDelegation});return 'other-family';
  },
  async linked(family='source-family'){const c=await prepare(undefined,family);return current.call('complete',c.intent_id,await proof(c));},async restart(){await current.mf.dispose();current=await start();}};
}
const operation=()=>({capability:'read',arguments:{task_id:'existing-task-id'},idempotency_key:''});
test('dual proof retains original owner identity/expiry with no budget or credential import',async t=>{
 const f=await fixture(t),link=await f.linked(),stored=await f.call('inspect',link.link_id);
 assert.equal(stored.authority.project_id,f.receipt.project_id);assert.equal(stored.authority.expires_at_ms,f.delegation.expires_at_ms);assert.equal(f.state.remaining,37);
 assert.ok(!Object.keys(stored.authority).some(k=>/budget|remaining|capability|token/.test(k)));
});
test('tampered/replayed dual proof and undefined trial ceremony cannot create authority',async t=>{
 const f=await fixture(t),c=await f.prepare(),p=await f.proof(c);
 await assert.rejects(f.call('complete',c.intent_id,{...p,agent_signature:'0'.repeat(128)}),/link_signature_rejected/);
 const other=await f.prepare();await assert.rejects(f.call('complete',other.intent_id,p));
 await f.call('complete',c.intent_id,p);await assert.rejects(f.call('complete',c.intent_id,p),/consumed/);
 const trial=await f.prepare('trial');await assert.rejects(f.call('complete',trial.intent_id,await f.proof(trial)),/old_authority_unavailable/);
 assert.equal(await f.call('inspect',trial.intent_id),null);
});
test('family revocation tombstones every linked record and preserves cleanup across restart',async t=>{
 const f=await fixture(t),a=await f.linked(),b=await f.linked();await f.call('revokeFamily','source-family',1);await f.restart();
 assert.equal((await f.call('inspect',a.link_id)).state,'revoked');assert.equal((await f.call('inspect',b.link_id)).state,'revoked');assert.equal((await f.call('pendingCleanup')).length,2);
 await f.call('finishCleanup',a.link_id,false);await f.restart();assert.equal((await f.call('pendingCleanup')).length,2);
 await f.call('revokeFamily','source-family',1);await f.call('finishCleanup',a.link_id,true);assert.equal((await f.call('pendingCleanup')).length,1);
 await assert.rejects(f.prepare(),/source_family_revoked/);await assert.rejects(f.call('execute',a.link_id,operation(),await f.token(operation(),a)),/linked_authority_inactive/);assert.equal(f.calls.length,0);
});
test('only source API debits and same idempotency key survives new links and uncertain retries',async t=>{
 const f=await fixture(t),a=await f.linked(),b=await f.linked(),op={capability:'enqueue',arguments:{operation_key:'original-op'},idempotency_key:'original-idempotency'};
 const one=await f.call('execute',a.link_id,op,await f.token(op,a));assert.deepEqual(await f.call('execute',b.link_id,op,await f.token(op,b)),one);assert.equal(f.state.remaining,32);
 assert.equal(f.calls[0].project_id,f.receipt.project_id);assert.equal(f.calls[0].namespace,f.receipt.project_id);assert.equal(f.calls[0].operation.idempotency_key,'original-idempotency');
 f.state.failApi=true;await assert.rejects(f.call('execute',a.link_id,op,await f.token(op,a)),/source_api_result_uncertain/);f.state.failApi=false;
 assert.deepEqual(await f.call('execute',a.link_id,op,await f.token(op,a)),one);assert.equal(f.state.remaining,32);
});
test('source epoch is checked at dispatch and later validation persists revocation',async t=>{
 const f=await fixture(t),link=await f.linked(),op=operation();f.state.revokeOnDispatch=true;
 await assert.rejects(f.call('execute',link.link_id,op,await f.token(op,link)),/source_api_result_uncertain/);assert.equal(f.state.remaining,37);
 await assert.rejects(f.call('execute',link.link_id,op,await f.token(op,link)),/source_family_revoked/);assert.equal((await f.call('inspect',link.link_id)).state,'revoked');
});
test('fresh session, permission ceiling, immutable source and new identity checks fail closed',async t=>{
 const f=await fixture(t),link=await f.linked(),op=operation();await assert.rejects(f.call('execute',link.link_id,op,'invalid'),/agent_session_rejected/);
 const wider={...op,capability:'http_schedule'};await assert.rejects(f.call('execute',link.link_id,wider,await f.token(wider,link)),/linked_scope_or_expiry_rejected/);
 f.state.drift=true;await assert.rejects(f.call('execute',link.link_id,op,await f.token(op,link)),/source_authority_drift/);assert.equal(f.calls.length,0);f.state.drift=false;
 await f.db.prepare('UPDATE agentHost SET status=? WHERE id=?').bind('revoked',f.identity.host_id).run();await assert.rejects(f.call('execute',link.link_id,op,await f.token(op,link)),/replacement_identity_inactive/);
});
test('missing old-authority/session/API implementations deny without dispatch',async t=>{
 const old=await fixture(t,{oldController:false}),c=await old.prepare();await assert.rejects(old.call('complete',c.intent_id,await old.proof(c)),/old_authority_ceremony_unavailable/);
 const session=await fixture(t,{sessionController:false}),a=await session.linked();await assert.rejects(session.call('execute',a.link_id,operation(),await session.token(operation(),a)),/agent_session_controller_missing/);
 const api=await fixture(t,{apiBridge:false}),b=await api.linked();await assert.rejects(api.call('execute',b.link_id,operation(),await api.token(operation(),b)),/source_api_bridge_missing/);
});

test('unknown result after source commit recovers with same original idempotency key after restart',async t=>{
 const f=await fixture(t),link=await f.linked(),op={capability:'enqueue',arguments:{operation_key:'stable-original-operation'},idempotency_key:'stable-original-key'};
 f.state.uncertainAfterCommit=true;
 await assert.rejects(f.call('execute',link.link_id,op,await f.token(op,link)),/source_api_result_uncertain/);
 assert.equal(f.state.remaining,32);await f.restart();
 const result=await f.call('execute',link.link_id,op,await f.token(op,link));
 assert.equal(result.task_id,'existing-task-id');assert.equal(f.state.remaining,32);
});
test('oversized old/session responses fail closed without dispatch',async t=>{
 const f=await fixture(t),c=await f.prepare();f.state.hugeOld=true;
 await assert.rejects(f.call('complete',c.intent_id,await f.proof(c)),/old_authority_unavailable/);
 assert.equal(await f.call('inspect',c.intent_id),null);f.state.hugeOld=false;
 const link=await f.linked(),op=operation();f.state.hugeSession=true;
 await assert.rejects(f.call('execute',link.link_id,op,await f.token(op,link)),/agent_session_rejected/);
 assert.equal(f.calls.length,0);
});

test('legacy controller requires fresh owner proof and enrollment receipt',async t=>{
 const f=await fixture(t),challenge=await f.prepare(),proof=await f.proof(challenge);
 await assert.rejects(f.call('complete',challenge.intent_id,{...proof,old_proof:{...proof.old_proof,owner_signature:'0'.repeat(128)}}),/old_authority_unavailable/);
 const {receipt,...withoutReceipt}=proof.old_proof;
 await assert.rejects(f.call('complete',challenge.intent_id,{...proof,old_proof:withoutReceipt}),/old_authority_unavailable/);
 assert.equal(await f.call('inspect',challenge.intent_id),null);
});
test('controller deadline releases serialized bridge after unavailable old authority',async t=>{
 const f=await fixture(t),challenge=await f.prepare(),proof=await f.proof(challenge);f.state.slowOld=true;
 const started=Date.now();await assert.rejects(f.call('complete',challenge.intent_id,proof),/old_authority_unavailable/);
 assert.ok(Date.now()-started<5800);f.state.slowOld=false;
 assert.equal(await f.call('inspect',challenge.intent_id),null);
});

test('signed request for one linked project cannot be substituted onto another link',async t=>{
 const f=await fixture(t),a=await f.linked(),b=await f.linked(f.addSource());
 assert.notEqual(a.project_id,b.project_id);
 const op={capability:'enqueue',arguments:{operation_key:'intended-project-a'},idempotency_key:'intended-project-a'};
 const intendedForA=await f.token(op,a);
 await assert.rejects(f.call('execute',b.link_id,op,intendedForA),/agent_session_rejected/);
 assert.equal(f.calls.length,0);assert.equal(f.state.remaining,37);
 await f.call('execute',a.link_id,op,await f.token(op,a));
 assert.equal(f.calls[0].project_id,a.project_id);assert.equal(f.state.remaining,32);
});
test('valid owner delegation with under five minutes left links without extending its expiry',async t=>{
 const f=await fixture(t,{delegationMs:120000}),challenge=await f.prepare();
 assert.ok(challenge.expires_at_ms>f.delegation.expires_at_ms);
 const linked=await f.call('complete',challenge.intent_id,await f.proof(challenge));
 assert.equal(linked.expires_at_ms,f.delegation.expires_at_ms);
 assert.equal(f.state.remaining,37);
});

test('operation-only tokens and legacy operation-only controller assertions fail closed',async t=>{
 const f=await fixture(t),link=await f.linked(),op=operation();
 await assert.rejects(f.call('execute',link.link_id,op,await f.token(op,link,{operationOnly:true})),/agent_session_rejected/);
 f.state.operationOnlyAssertion=true;
 await assert.rejects(f.call('execute',link.link_id,op,await f.token(op,link)),/agent_session_rejected/);
 assert.equal(f.calls.length,0);assert.equal(f.state.remaining,37);
});
test('signed project, namespace, family and epoch must match the selected link context',async t=>{
 const f=await fixture(t),link=await f.linked(),op=operation();
 for(const change of [{project_id:'p_'+'0'.repeat(60)},{namespace:'other-namespace'},{family_id:'other-family'},{source_epoch:1}]){
  const changed={...link,execution_context:{...link.execution_context,...change}};
  await assert.rejects(f.call('execute',link.link_id,op,await f.token(op,changed)),/agent_session_rejected/);
 }
 assert.equal(f.calls.length,0);assert.equal(f.state.remaining,37);
});

test('short-delegation linking still rejects expired source authority',async t=>{
 const f=await fixture(t,{delegationMs:120000}),challenge=await f.prepare(),proof=await f.proof(challenge);
 assert.throws(()=>verifyOwnerLinkControl(proof.old_proof,challenge,{...f.ownerOptions,now:f.delegation.expires_at_ms+1}),/identity_expired/);
 const linked=await f.call('complete',challenge.intent_id,proof),op=operation();
 assert.equal(linked.expires_at_ms,f.delegation.expires_at_ms);
 f.state.expiredSource=true;
 await assert.rejects(f.call('execute',linked.link_id,op,await f.token(op,linked)),/old_authority_rejected/);
 assert.equal(f.calls.length,0);assert.equal(f.state.remaining,37);
});
