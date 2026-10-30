import {DurableObject} from 'cloudflare:workers';
import {digest,verifySignature,executionContext,executionRequest} from './proofs.mjs';
import {AgentAuthReplacement} from '../worker.mjs';
import replacement from '../worker.mjs';
export {AgentAuthReplacement};
const id=value=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(value);
const scopes=new Set(['read','cancel','enqueue','http_schedule','receiver_setup']);
const deny=code=>{throw Error(code);};
const fields=(value,names)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===names.split(',').sort().join();
function snapshot(value,challenge){
 if(!fields(value,'active,challenge_sha256,family_id,source_kind,project_id,namespace,authority_ref,issued_at_ms,expires_at_ms,permissions,revocation_epoch,release_id,identity_sha256')||value.active!==true||value.challenge_sha256!==digest(challenge)||value.family_id!==challenge.family_id||value.project_id!==challenge.project_id||value.source_kind!==challenge.source_kind||value.release_id!==challenge.release_id||![value.family_id,value.namespace,value.authority_ref].every(id)||!Number.isSafeInteger(value.issued_at_ms)||value.issued_at_ms<0||!Number.isSafeInteger(value.expires_at_ms)||value.expires_at_ms<=Date.now()||value.expires_at_ms<=value.issued_at_ms||!Number.isSafeInteger(value.revocation_epoch)||value.revocation_epoch<0||typeof value.identity_sha256!=='string'||!/^[a-f0-9]{64}$/.test(value.identity_sha256)||!Array.isArray(value.permissions)||value.permissions.length>5||new Set(value.permissions).size!==value.permissions.length||value.permissions.some(p=>!scopes.has(p))||challenge.permissions.some(p=>!value.permissions.includes(p)))deny('old_authority_rejected');
 if(value.source_kind==='trial'&&value.expires_at_ms-value.issued_at_ms!==604800000)deny('trial_expiry_reset_rejected');
 return value;
}
// Inactive binding component. No public bridge routes, live controller, new
// identities, grants, quota ledger, credential import or provision operation.
export class ProjectLinkAuthority extends DurableObject {
 constructor(ctx,env){super(ctx,env);this.env=env;this.tail=Promise.resolve();this.waiting=0;
  ctx.blockConcurrencyWhile(async()=>ctx.storage.sql.exec(`
   CREATE TABLE IF NOT EXISTS intents(id TEXT PRIMARY KEY,challenge TEXT NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS links(id TEXT PRIMARY KEY,family TEXT NOT NULL,authority TEXT NOT NULL,challenge TEXT NOT NULL,state TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS tombstones(family TEXT PRIMARY KEY,epoch INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS cleanup(link TEXT PRIMARY KEY,done INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0);`));
 }
 #sql(q,...a){return this.ctx.storage.sql.exec(q,...a).toArray();}
 // Normalized envelope is also the local Miniflare beta RPC error boundary.
 call(method,args){
  if(!['prepare','complete','execute','revokeFamily','pendingCleanup','finishCleanup','inspect'].includes(method))return Promise.resolve({ok:false,error:'unknown_bridge_operation'});
  if(this.waiting>=8)return Promise.resolve({ok:false,error:'bridge_busy'});
  this.waiting++;
  const handlers={prepare:(...a)=>this.#prepare(...a),complete:(...a)=>this.#complete(...a),execute:(...a)=>this.#execute(...a),revokeFamily:(...a)=>this.#revokeFamily(...a),pendingCleanup:()=>this.#pendingCleanup(),finishCleanup:(...a)=>this.#finishCleanup(...a),inspect:(...a)=>this.#inspect(...a)};
  const run=this.tail.then(async()=>{try{const value=await handlers[method](...args);await this.ctx.storage.sync();return {ok:true,value};}catch(e){return {ok:false,error:e.message};}});
  this.tail=run.catch(()=>{});return run.finally(()=>{this.waiting--;});
 }
 async #identity(challenge){
  if(!this.env.REPLACEMENT_AUTH_DB)deny('identity_controller_missing');
  const agent=await this.env.REPLACEMENT_AUTH_DB.prepare('SELECT a.status,a.hostId,a.publicKey,a.mode,a.createdAt,a.activatedAt,a.expiresAt,h.status AS hostStatus,h.publicKey AS hostPublicKey FROM agent a JOIN agentHost h ON h.id=a.hostId WHERE a.id=?').bind(challenge.agent_id).first();
  if(!agent||agent.status!=='active'||agent.hostStatus!=='active'||agent.mode!=='autonomous'||agent.hostId!==challenge.host_id)deny('replacement_identity_inactive');
  const now=Date.now(),created=new Date(agent.createdAt).getTime(),activated=new Date(agent.activatedAt??agent.createdAt).getTime();
  if(!Number.isFinite(created)||!Number.isFinite(activated)||created+604800000<=now||activated+604800000<=now||(agent.expiresAt&&(!Number.isFinite(new Date(agent.expiresAt).getTime())||new Date(agent.expiresAt).getTime()<=now)))deny('replacement_identity_expired');
  let agentKey,hostKey;try{agentKey=JSON.parse(agent.publicKey);hostKey=JSON.parse(agent.hostPublicKey);}catch{deny('replacement_identity_inactive');}
  if(digest(agentKey)!==challenge.agent_key_sha256||digest(hostKey)!==challenge.host_key_sha256)deny('replacement_identity_changed');
  return {agentKey,hostKey};
 }
 async #request(binding,path,payload,code,{authentication,maxBytes=8192}={}){
  if(!binding)deny(code);
  let timer,reader;
  const controller=new AbortController();
  const work=(async()=>{
   const response=await binding.fetch(new Request('https://internal-controller.invalid/'+path,{method:'POST',redirect:'manual',signal:controller.signal,headers:{'content-type':'application/json',...(authentication?{authorization:'Bearer '+authentication}:{})},body:JSON.stringify(payload)}));
   if(!response.ok)deny(code);
   reader=response.body?.getReader();if(!reader)deny(code);
   let text='',size=0,chunks=0;const decoder=new TextDecoder('utf-8',{fatal:true});
   for(;;){const {done,value}=await reader.read();if(done)break;if((size+=value.byteLength)>maxBytes||++chunks>64)deny(code);text+=decoder.decode(value,{stream:true});}
   return JSON.parse(text+decoder.decode());
  })();
  try{return await Promise.race([work,new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Error(code));},5000);})]);}
  catch{deny(code);}
  finally{clearTimeout(timer);controller.abort();if(reader)void reader.cancel().catch(()=>{});}
 }
 async #old(path,payload){
  if(!this.env.LEGACY_LINK_CONTROLLER)deny('old_authority_ceremony_unavailable');
  return this.#request(this.env.LEGACY_LINK_CONTROLLER,path,payload,'old_authority_unavailable');
 }
 async #prepare(input){
  if(!fields(input,'family_id,source_kind,project_id,release_id,host_id,agent_id,permissions')||![input.family_id,input.release_id,input.host_id,input.agent_id].every(id)||!['owner','trial'].includes(input.source_kind)||!/^p_[a-f0-9]{60}$/.test(input.project_id)||!Array.isArray(input.permissions)||!input.permissions.length||input.permissions.some(p=>!scopes.has(p))||new Set(input.permissions).size!==input.permissions.length)deny('link_request_rejected');
  if(this.#sql('SELECT 1 FROM tombstones WHERE family=?',input.family_id).length)deny('source_family_revoked');
  this.#sql('DELETE FROM intents WHERE expires<=?',Date.now());
  if(this.#sql('SELECT count(*) AS count FROM intents')[0].count>=64)deny('link_intent_capacity');
  const row=await this.env.REPLACEMENT_AUTH_DB?.prepare('SELECT a.publicKey,h.publicKey AS hostPublicKey FROM agent a JOIN agentHost h ON h.id=a.hostId WHERE a.id=? AND h.id=?').bind(input.agent_id,input.host_id).first();
  if(!row)deny('replacement_identity_inactive');
  const now=Date.now(),intent=crypto.randomUUID();
  const challenge={version:1,origin:'https://mcp.runlater.io',intent_id:intent,nonce:crypto.randomUUID(),...input,
   permissions:[...input.permissions].sort(),host_key_sha256:digest(JSON.parse(row.hostPublicKey)),agent_key_sha256:digest(JSON.parse(row.publicKey)),issued_at_ms:now,expires_at_ms:now+300000};
  await this.#identity(challenge);
  this.#sql('INSERT INTO intents VALUES(?,?,?,?)',intent,JSON.stringify(challenge),challenge.expires_at_ms,'pending');
  return challenge;
 }
 async #complete(intent,proof){
  const row=this.#sql('SELECT * FROM intents WHERE id=?',intent)[0];
  if(!row||row.expires<=Date.now())deny('link_challenge_expired');
  if(row.state==='linked')deny('link_challenge_consumed');
  if(!fields(proof,'host_signature,agent_signature,old_proof')||JSON.stringify(proof).length>12288)deny('link_proof_rejected');
  const challenge=JSON.parse(row.challenge),keys=await this.#identity(challenge);
  verifySignature(keys.hostKey,proof.host_signature,challenge);verifySignature(keys.agentKey,proof.agent_signature,challenge);
  const value=await this.#old('verify-control',{challenge,proof:proof.old_proof});
  const authority=snapshot(value,challenge);
  await this.#identity(challenge);
  this.ctx.storage.transactionSync(()=>{
   if(row.expires<=Date.now()||authority.expires_at_ms<=Date.now())deny('link_challenge_expired');
   if(this.#sql('SELECT 1 FROM tombstones WHERE family=?',challenge.family_id).length)deny('source_family_revoked');
   if(this.#sql('SELECT count(*) AS count FROM links')[0].count>=40)deny('link_capacity');
   // Exact source authority retained: no project mint, expiry extension, namespace
   // rewrite, permission alias or budget copy. The source controls all quota.
   this.#sql('INSERT INTO links VALUES(?,?,?,?,?)',intent,authority.family_id,JSON.stringify(authority),row.challenge,'active');
   this.#sql('UPDATE intents SET state=? WHERE id=?','linked',intent);
  });
  return {link_id:intent,project_id:authority.project_id,expires_at_ms:authority.expires_at_ms,permissions:challenge.permissions,execution_context:executionContext(intent,authority,challenge)};
 }
 async #execute(linkId,operation,authentication){
  const row=this.#sql('SELECT * FROM links WHERE id=?',linkId)[0];
  if(!row||row.state!=='active'||this.#sql('SELECT 1 FROM tombstones WHERE family=?',row.family).length)deny('linked_authority_inactive');
  if(!fields(operation,'capability,arguments,idempotency_key')||typeof operation.arguments!=='object'||!operation.arguments||Array.isArray(operation.arguments)||JSON.stringify(operation.arguments).length>4096||typeof operation.idempotency_key!=='string'||operation.idempotency_key.length>128)deny('operation_rejected');
  const challenge=JSON.parse(row.challenge),authority=JSON.parse(row.authority);
  if(!challenge.permissions.includes(operation.capability)||authority.expires_at_ms<=Date.now())deny('linked_scope_or_expiry_rejected');
  await this.#identity(challenge);
  if(!this.env.AGENT_SESSION_CONTROLLER)deny('agent_session_controller_missing');
  if(typeof authentication!=='string'||authentication.length>8192)deny('agent_session_required');
  // The real Agent Auth controller must verify signature, request binding,
  // audience, replay and capability intersection. No link-id bearer shortcut.
  const request=executionRequest(executionContext(row.id,authority,challenge),operation);
  const requestDigest=digest(request);
  const session=await this.#request(this.env.AGENT_SESSION_CONTROLLER,'verify-session',{host_id:challenge.host_id,agent_id:challenge.agent_id,request,request_sha256:requestDigest},'agent_session_rejected',{authentication});
  if(session.active!==true||session.host_id!==challenge.host_id||session.agent_id!==challenge.agent_id||session.request_sha256!==requestDigest||session.capability!==operation.capability)deny('agent_session_rejected');
  await this.#identity(challenge);
  const state=await this.#old('validate-source',{challenge,authority_ref:authority.authority_ref,family_id:row.family});
  if(state?.active===false){await this.#revokeFamily(row.family,Math.max(authority.revocation_epoch,Number.isSafeInteger(state.revocation_epoch)?state.revocation_epoch:0));deny('source_family_revoked');}
  const current=snapshot(state,challenge);
  if(['project_id','namespace','authority_ref','issued_at_ms','expires_at_ms','identity_sha256','revocation_epoch'].some(key=>current[key]!==authority[key]))deny('source_authority_drift');
  if(!current.permissions.includes(operation.capability))deny('linked_scope_or_expiry_rejected');
  if(!this.env.SOURCE_API_BRIDGE)deny('source_api_bridge_missing');
  await this.#identity(challenge);
  // Idempotency key/project/namespace are forwarded unchanged. Never re-prefix by
  // agent/link id, call provision(), or debit a local replacement budget.
  const receipt=await this.#request(this.env.SOURCE_API_BRIDGE,'execute',{authority_ref:authority.authority_ref,project_id:authority.project_id,namespace:authority.namespace,family_id:row.family,expected_epoch:authority.revocation_epoch,operation},'source_api_result_uncertain',{maxBytes:16384});
  if(!fields(receipt,'project_id,namespace,authority_epoch,result')||receipt.project_id!==authority.project_id||receipt.namespace!==authority.namespace||receipt.authority_epoch!==authority.revocation_epoch)deny('source_api_result_uncertain');
  return receipt.result;
 }
 async #revokeFamily(family,epoch){
  if(!id(family)||!Number.isSafeInteger(epoch)||epoch<0)deny('revocation_rejected');
  this.ctx.storage.transactionSync(()=>{
   const prior=this.#sql('SELECT epoch FROM tombstones WHERE family=?',family)[0];
   if(!prior&&this.#sql('SELECT count(*) AS count FROM tombstones')[0].count>=128)deny('revocation_capacity');
   this.#sql('INSERT INTO tombstones VALUES(?,?) ON CONFLICT(family) DO UPDATE SET epoch=MAX(epoch,excluded.epoch)',family,Math.max(prior?.epoch??0,epoch));
   this.#sql('INSERT OR IGNORE INTO cleanup(link) SELECT id FROM links WHERE family=?',family);
   this.#sql('UPDATE links SET state=? WHERE family=?','revoked',family);
  });
  await this.ctx.storage.sync();return {revoked:true};
 }
 #pendingCleanup(){return this.#sql('SELECT link,attempts FROM cleanup WHERE done=0 ORDER BY link');}
 #finishCleanup(link,success){
  if(typeof success!=='boolean')deny('cleanup_rejected');
  this.#sql('UPDATE cleanup SET attempts=MIN(32,attempts+1),done=CASE WHEN ? THEN 1 ELSE done END WHERE link=?',success?1:0,link);
  return {recorded:true};
 }
 #inspect(link){const row=this.#sql('SELECT id,family,state,authority FROM links WHERE id=?',link)[0];return row?{...row,authority:JSON.parse(row.authority)}:null;}
}
// This module is a local test entry only. The production replacement candidate
// never imports it, and no HTTP route can call ProjectLinkAuthority.
export default replacement;
