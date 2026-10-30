// Production artifact, local synthetic transport only. No provider mutations or external callbacks.
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomBytes,createHash,createHmac} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-invitation-production-'));
const pair=generateKeyPairSync('ed25519'),pub=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const token=randomBytes(32).toString('hex'),hash=v=>createHash('sha256').update(v).digest('hex');
const expiry=Date.now()+3600000;
const tenant='p_'+hash(token).slice(0,60),epoch=Math.floor(Date.now()/1000);
const secret=randomBytes(32).toString('hex'),proofs=new Map(),received=[],counts=new Map();
const keys={version:'v2',tenant,policy_id:'invitation_callbacks',revision:1,keys:{operator_one:{key_id:'operator_one',introduced_revision:1,active_from_sec:0,sign_until_sec:epoch+7200,verify_until_sec:epoch+7500,revoked_at_sec:null}},rotations:{}};
async function receiver(req){assert.equal(req.url,'https://receiver.example.test/callback');const body=Buffer.from(await req.arrayBuffer());if(body.toString().startsWith('RunLater destination verification v1\n')){const value=JSON.parse(body.toString().split('\n')[1]);const proof=proofs.get(value[3]);assert.ok(proof,"Unknown verification request");assert.ok(!body.toString().includes(proof.response));return new Response(proof.response)}const h=req.headers,kid=h.get('RunLater-Key-Id'),policy=h.get('RunLater-Signing-Policy'),ts=h.get('RunLater-Timestamp'),task=h.get('RunLater-Task-Id'),op=h.get('RunLater-Operation-Key');assert.equal(policy,'invitation_callbacks');assert.equal(kid,'operator_one');assert.equal(h.get('RunLater-Signature-Version'),'v2');const expected=createHmac('sha256',Buffer.from(secret,'hex')).update(`runlater.v2.${policy}.${kid}.${ts}.${task}.${op}.`).update(body).digest('hex');assert.ok(h.get('RunLater-Signature')===expected,"callback signature mismatch");received.push({op,task,kid});const count=(counts.get(op)??0)+1;counts.set(op,count);return new Response('{}',{status:op==='retry_once'&&count===1?500:200})}

let mf,calls=0;
const base={INVITATION_ENROLLMENT:'operator-approved',INVITATION_POLICY:JSON.stringify({revision:1,terms:{attempt_units:20,identity_ms:3600000,permissions:['enqueue','read','cancel','redrive','manage_destinations']},max_projects:2,max_tickets:4,requests_per_minute:128}),INVITATION_SEEDS:JSON.stringify([{id:hash(token),expires_at_ms:expiry,revoked:false}]),INVITATION_DELIVERY_ENABLED:'operator-approved',INVITATION_READY_QUEUE:'runlater-invitation-ready',INVITATION_CALLBACK_KEYS:JSON.stringify({operator_one:secret}),INVITATION_DELIVERY_POLICIES:JSON.stringify([{keys,egress:{approved_hosts:['receiver.example.test']}}])};
function projectSnapshot() {
 const r=spawnSync('python3',['-c',`import pathlib,sqlite3,json,sys
out=[]
for p in pathlib.Path(sys.argv[1]).rglob('*.sqlite'):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 if c.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='invitation_snapshot'").fetchone()[0]:
  for row in c.execute('SELECT data FROM invitation_snapshot'):
   v=json.loads(row[0])['data']
   if 'mode' in v:out.append(v)
print(json.dumps(out,sort_keys=True))`,root],{encoding:'utf8'});
 assert.equal(r.status,0,r.stderr);return r.stdout;
}
async function start(extra={}) {
 await mf?.dispose();
 mf=new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'invitation-production',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',bindings:{...base,...extra},durableObjects:{ADMISSION:{className:'AdmissionRegistry',useSQLite:true},PROJECTS:{className:'InvitationProject',useSQLite:true}},queueProducers:{INVITATION_READY:'runlater-invitation-ready'},queueConsumers:{'runlater-invitation-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:receiver},{name:'deny-egress',modules:true,compatibilityDate:'2026-10-27',script:'export default {fetch(){return new Response(null,{status:403})}}'}]}));
 await mf.ready;
}
async function api(route,{body,headers={},method='POST',status=200,origin='https://api.runlater.io'}={}) {
 assert.ok(++calls<=150);
 const r=await mf.dispatchFetch(origin+route,{method,headers:{'Content-Type':'application/json',...headers},body:body===undefined?undefined:JSON.stringify(body)});
 const text=await r.text();assert.equal(r.status,status,route+': unexpected status');return JSON.parse(text);
}
function signed(project,route,body,{method='POST',idempotency='production-unavailable',key=pair}={}) {
 const publicKey=key.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex'),issued=Date.now(),expires=issued+60000,nonce=randomBytes(32).toString('hex'),text=body===undefined?'':JSON.stringify(body);
 const wire='RunLater signed request v1\n'+JSON.stringify([1,'https://api.runlater.io',project,publicKey,method,route,'',hash(text),idempotency,issued,expires,nonce]);
 return {body,method,headers:{'RunLater-Project-Id':project,'RunLater-Public-Key':publicKey,'RunLater-Request-Signature':sign(null,Buffer.from(wire),key.privateKey).toString('hex'),'RunLater-Nonce':nonce,'RunLater-Issued-At':String(issued),'RunLater-Expires-At':String(expires),'Idempotency-Key':idempotency}};
}

const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function taskStatus(id){return api('/v1/tasks/'+id,signed(tenant,'/v1/tasks/'+id,undefined,{method:'GET',idempotency:''}))}
async function waitTask(id,wanted){for(let i=0;i<24;i++){const v=await taskStatus(id);if(v.result.status===wanted)return v;await pause(250)}throw Error('Task did not reach '+wanted)}
try {
 await start();
 assert.equal((await api("/health",{method:"GET"})).fresh_task_admission,"conditional_operator_opt_in");
 const c=await api('/registration/challenge',{body:{token,public_key:pub}});
 const receipt=await api('/registration/complete',{body:{token,challenge_id:c.challenge_id,signature:sign(null,Buffer.from(c.canonical_utf8),pair.privateKey).toString('hex')},status:201});assert.equal(receipt.project_id,tenant);
 const input={endpoint_id:'owned_receiver',version:1,url:'https://receiver.example.test/callback'};
 await api('/v1/destinations/create',signed(tenant,'/v1/destinations/create',input,{idempotency:'create-endpoint'}));
 const proof=await api('/v1/destinations/prepare',signed(tenant,'/v1/destinations/prepare',{endpoint_id:'owned_receiver',version:1},{idempotency:'prepare-endpoint'}));proofs.set(proof.id,proof);
 await api('/v1/destinations/verify',signed(tenant,'/v1/destinations/verify',{endpoint_id:'owned_receiver',version:1},{idempotency:'verify-endpoint'}));
 const task={destination:'registered:owned_receiver',body:JSON.stringify({synthetic:true}),operation_key:'first_callback',run_at_ms:Date.now()+750};
 const accepted=await api('/v1/tasks',{...signed(tenant,'/v1/tasks',task,{idempotency:'first-task'}),status:201});const id=accepted.result.id;assert.ok(id);
 await start();const done=await waitTask(id,'succeeded');assert.equal(received.filter(x=>x.op==='first_callback').length,1);assert.equal(done.funding.spent_fences.length,1);
 const replay=await api('/v1/tasks',{...signed(tenant,'/v1/tasks',task,{idempotency:'first-task'}),status:200});assert.equal(replay.replayed,true);
 const retry=await api('/v1/tasks',{...signed(tenant,'/v1/tasks',{...task,run_at_ms:0,operation_key:'retry_once'},{idempotency:'retry-task'}),status:201});await waitTask(retry.result.id,'succeeded');assert.equal(counts.get('retry_once'),2);
 const future=await api('/v1/tasks',{...signed(tenant,'/v1/tasks',{...task,run_at_ms:Date.now()+750,operation_key:'blocked_revoked'},{idempotency:'revoked-task'}),status:201});
 await api('/v1/destinations/revoke',signed(tenant,'/v1/destinations/revoke',{endpoint_id:'owned_receiver',version:1},{idempotency:'revoke-endpoint'}));await waitTask(future.result.id,'failed');assert.equal(counts.get('blocked_revoked')??0,0);
 const before=projectSnapshot();await api('/v1/identity/me',signed(tenant,'/v1/identity/me',undefined,{method:'GET',idempotency:''}));assert.equal(projectSnapshot(),before);
 const second=generateKeyPairSync('ed25519'),pub2=second.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex'),token2=randomBytes(32).toString('hex'),tenant2='p_'+hash(token2).slice(0,60);
 await start({INVITATION_POLICY:JSON.stringify({...JSON.parse(base.INVITATION_POLICY),revision:2,terms:{...JSON.parse(base.INVITATION_POLICY).terms,identity_ms:1500}}),INVITATION_SEEDS:JSON.stringify([{id:hash(token2),expires_at_ms:Date.now()+60000,revoked:false}]),INVITATION_DELIVERY_POLICIES:JSON.stringify([{keys:{...keys,tenant:tenant2},egress:{approved_hosts:['receiver.example.test']}}])});
 const c2=await api('/registration/challenge',{body:{token:token2,public_key:pub2}});await api('/registration/complete',{body:{token:token2,challenge_id:c2.challenge_id,signature:sign(null,Buffer.from(c2.canonical_utf8),second.privateKey).toString('hex')},status:201});
 const scoped=(route,body,options={})=>signed(tenant2,route,body,{...options,key:second});
 await api('/v1/destinations/create',scoped('/v1/destinations/create',input,{idempotency:'create-two'}));
 const proof2=await api('/v1/destinations/prepare',scoped('/v1/destinations/prepare',{endpoint_id:'owned_receiver',version:1},{idempotency:'prepare-two'}));proofs.set(proof2.id,proof2);
 await api('/v1/destinations/verify',scoped('/v1/destinations/verify',{endpoint_id:'owned_receiver',version:1},{idempotency:'verify-two'}));
 await api('/v1/identity/me',{...signed(tenant2,'/v1/identity/me',undefined,{method:'GET',idempotency:''}),status:403});
 const later=await api('/v1/tasks',{...scoped('/v1/tasks',{...task,run_at_ms:Date.now()+2200,operation_key:'expired_grant_delivery'},{idempotency:'past-grant'}),status:201});
 for(let i=0;i<40&&!(counts.get('expired_grant_delivery')>0);i++)await pause(100);assert.equal(counts.get('expired_grant_delivery'),1);
 await api('/v1/tasks/'+later.result.id,{...scoped('/v1/tasks/'+later.result.id,undefined,{method:'GET',idempotency:''}),status:410});
 const stored=JSON.parse(projectSnapshot()).find(x=>x.project.catalog.project_id===tenant2);assert.equal(stored.project.ledger.tasks[later.result.id].status,'succeeded');assert.equal(stored.project.funding.reservations[later.result.id].spent_fences.length,1);
 console.log(JSON.stringify({status:'passed',http_calls:calls,callbacks:received.length,actual_local_queue:true,persisted_restart:true,accepted_after_identity_grant_expiry:true,external_calls:0,live_resources:0}));
}finally{await mf?.dispose();fs.rmSync(root,{recursive:true})}
