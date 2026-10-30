import {createHash,randomBytes} from 'node:crypto';
import {AnonymousTrialClientV1,trialProjectId} from '../../mcp/trial-client.mjs';
import {delegationPublicKey} from '../../mcp/delegation.mjs';

const hash=s=>createHash('sha256').update(s).digest('hex');
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.sort().join();
const demand=(ok,code)=>{if(!ok)throw Error(code);};
const permissionNames=['cancel','http_schedule','read'];
export const capabilityNames=['project_status','create_project','schedule_http','read_task','cancel_task','revoke_project'];
export const capabilities=capabilityNames.map(name=>({name,description:{
 project_status:'Inspect the project bound to this Agent Auth host. Does not allocate a project.',
 create_project:'Allocate one seven-day, 100-attempt trial for this host through the RunLater API. Retrying preserves the original project and budget.',
 schedule_http:'Schedule an HTTPS task within this host project and its original API budget and expiry.',
 read_task:'Read a task in this host project.',cancel_task:'Cancel a task in this host project.',
 revoke_project:'Permanently revoke this host project. This does not grant a fresh trial.',
}[name],input:{type:'object',additionalProperties:false,
 properties:name==='schedule_http'?{task:{type:'object'},idempotency_key:{type:'string'}}:
  ['read_task','cancel_task'].includes(name)?{task_id:{type:'string'}}:{},
 required:name==='schedule_http'?['task','idempotency_key']:['read_task','cancel_task'].includes(name)?['task_id']:[]}}));

// Called only by the serialized authenticated hub. This is a durable identity
// mapping/outbox, never a quota ledger. The existing API is the quota authority.
export class CanonicalProjects {
 constructor({storage,clientFor,clock=Date.now,entropy=()=>randomBytes(32).toString('hex'),releaseId}){
  demand(storage?.sql&&typeof storage.sync==='function'&&typeof clientFor==='function','storage_adapter_required');
  demand(typeof releaseId==='string'&&/^[A-Za-z0-9_-]{1,32}$/.test(releaseId),'release_required');
  Object.assign(this,{storage,clientFor,clock,entropy,releaseId});
  storage.sql.exec(`CREATE TABLE IF NOT EXISTS canonical_projects (
   host_id TEXT PRIMARY KEY,project_id TEXT UNIQUE NOT NULL,authority TEXT NOT NULL,
   state TEXT NOT NULL CHECK(state IN ('pending','active','revoked')),cleanup_pending INTEGER NOT NULL DEFAULT 0,cleanup_attempts INTEGER NOT NULL DEFAULT 0);
   CREATE TABLE IF NOT EXISTS canonical_host_tombstones(host_id TEXT PRIMARY KEY);`);
 }
 sql(q,...args){return this.storage.sql.exec(q,...args).toArray();}
 row(host){return this.sql('SELECT * FROM canonical_projects WHERE host_id=?',host)[0];}
 summary(row){if(!row)return {state:'unprovisioned',quota_authority:'runlater-api'};
  const {descriptor}=JSON.parse(row.authority);
  return {state:row.state,status_source:'local-admission',project_id:row.project_id,issued_at_ms:descriptor.issued_at_ms,
   expires_at_ms:descriptor.expires_at_ms,permissions:descriptor.permissions,quota_authority:'runlater-api',
   trial_attempt_allocation:100,remaining_attempts:null,cleanup_pending:!!row.cleanup_pending};}
 async execute(host,capability,args){
  demand(typeof host==='string'&&host.length>0&&host.length<=256,'authenticated_host_required');
  demand(capabilityNames.includes(capability),'capability_rejected');
  if(['project_status','create_project','revoke_project'].includes(capability))demand(exact(args,[]),'arguments_rejected');
  if(['read_task','cancel_task'].includes(capability))demand(exact(args,['task_id']),'arguments_rejected');
  if(capability==='schedule_http')demand(exact(args,['task','idempotency_key']),'arguments_rejected');
  let row=this.row(host);
  if(capability==='project_status')return this.summary(row);
  demand(!this.sql('SELECT 1 FROM canonical_host_tombstones WHERE host_id=?',host).length,'host_revoked');
  if(capability==='revoke_project'){
   if(!row)return {state:'unprovisioned',quota_authority:'runlater-api'};
   await this.tombstone(host);return this.summary(this.row(host));
  }
  demand(row?.state!=='revoked','project_revoked');
  if(capability==='create_project'){
   if(!row){
    const issued=this.clock(),bootstrap=this.entropy(),capabilitySecret=this.entropy(),revocationSecret=this.entropy();
    demand(Number.isSafeInteger(issued)&&issued>=0&&[bootstrap,capabilitySecret,revocationSecret].every(v=>/^[a-f0-9]{64}$/.test(v)),'authority_rejected');
    const descriptor={version:1,release_id:this.releaseId,bootstrap_id:bootstrap,
     capability_hash:hash('RunLater anonymous trial capability v1\n'+JSON.stringify([1,this.releaseId,bootstrap,capabilitySecret])),
     revocation_hash:hash('RunLater anonymous trial revocation v1\n'+JSON.stringify([1,this.releaseId,bootstrap,revocationSecret])),
     issued_at_ms:issued,expires_at_ms:issued+604800000,permissions:permissionNames};
    const authority={descriptor,capability:capabilitySecret,revocationSecret};
    // Commit original identity before transport: an unknown API result must
    // reconcile the same project, idempotency key, expiry and trial budget.
    this.sql('INSERT INTO canonical_projects(host_id,project_id,authority,state) VALUES(?,?,?,?)',host,trialProjectId(descriptor),JSON.stringify(authority),'pending');
    await this.storage.sync();row=this.row(host);
   }
   this.activeTime(row);
   if(row.state==='pending'){
    const value=await this.clientFor(JSON.parse(row.authority),false).provision();
    demand(value.state==='active'&&value.project_id===row.project_id,'provision_not_confirmed');
    this.sql("UPDATE canonical_projects SET state='active' WHERE host_id=? AND state='pending'",host);await this.storage.sync();
   }
   return this.summary(this.row(host));
  }
  demand(row?.state==='active','project_not_active');this.activeTime(row);
  const client=this.clientFor(JSON.parse(row.authority),false);
  if(capability==='schedule_http')return client.scheduleHttp(args.task,args.idempotency_key);
  if(capability==='read_task')return client.task(args.task_id);
  return client.cancel(args.task_id);
 }
 activeTime(row){const {descriptor}=JSON.parse(row.authority),now=this.clock();
  demand(now>=descriptor.issued_at_ms&&now<descriptor.expires_at_ms,'identity_expired');}
 async tombstone(host,{hostRevoked=false}={}){
  if(hostRevoked)this.sql('INSERT OR IGNORE INTO canonical_host_tombstones VALUES(?)',host);
  this.sql("UPDATE canonical_projects SET state='revoked',cleanup_pending=1 WHERE host_id=? AND state!='revoked'",host);
  if(this.sql('SELECT 1 FROM canonical_projects WHERE cleanup_pending=1 LIMIT 1').length)
   await this.storage.setAlarm(this.clock()+60000);
  await this.storage.sync();if(!hostRevoked)await this.cleanup();
 }
 async cleanup(){
  if(this.sql('SELECT 1 FROM canonical_projects WHERE cleanup_pending=1 LIMIT 1').length)
   await this.storage.setAlarm(this.clock()+60000);
  // At most one API request per pass; rotate failed rows so one unavailable
  // project cannot starve other revocations. Alarms drain the durable outbox.
  for(const row of this.sql('SELECT * FROM canonical_projects WHERE cleanup_pending=1 ORDER BY cleanup_attempts,host_id LIMIT 1')){
   this.sql('UPDATE canonical_projects SET cleanup_attempts=cleanup_attempts+1 WHERE host_id=?',row.host_id);
   await this.storage.sync();
   try{
    const authority=JSON.parse(row.authority);
    // The API denies all operations after original expiry; no replacement
    // authority is minted merely to deliver an expired cleanup request.
    if(this.clock()<authority.descriptor.expires_at_ms)await this.clientFor(authority,true).revoke();
    this.sql('UPDATE canonical_projects SET cleanup_pending=0 WHERE host_id=?',row.host_id);
    await this.storage.sync();
   }catch{/* A durable tombstone already denies use; retry via alarm. */}
  }
  if(this.sql('SELECT 1 FROM canonical_projects WHERE cleanup_pending=1 LIMIT 1').length)
   await this.storage.setAlarm(this.clock()+60000);
 }
}

export function apiClientFactory(env){
 demand(env.CANONICAL_API&&typeof env.CANONICAL_API.fetch==='function','api_binding_required');
 demand(typeof env.MCP_GATEWAY_PUBLIC_KEY==='string'&&delegationPublicKey(env.MCP_GATEWAY_PRIVATE_KEY)===env.MCP_GATEWAY_PUBLIC_KEY,'gateway_trust_required');
 return (authority,revoke)=>new AnonymousTrialClientV1({privateKey:env.MCP_GATEWAY_PRIVATE_KEY,
  descriptor:authority.descriptor,...(revoke?{revocationSecret:authority.revocationSecret}:{capability:authority.capability}),
  releaseId:env.MCP_RELEASE_ID,fetchImpl:(url,init)=>env.CANONICAL_API.fetch(new Request(url,init))});
}
