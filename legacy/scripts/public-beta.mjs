// Production artifact, local synthetic transport only. No provider mutations or external callbacks.
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomBytes,createHash,createHmac} from 'node:crypto';
import {spawnSync} from 'node:child_process';
let root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-invitation-production-'));
const pair=generateKeyPairSync('ed25519'),pub=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const token=randomBytes(32).toString('hex'),hash=v=>createHash('sha256').update(v).digest('hex');
const secret=randomBytes(32).toString('hex'),proofs=new Map(),received=[],counts=new Map();
async function receiver(req){assert.equal(req.url,'https://receiver.account.workers.dev/callback');const body=Buffer.from(await req.arrayBuffer());if(body.toString().startsWith('RunLater destination verification v1\n')){const value=JSON.parse(body.toString().split('\n')[1]);const proof=proofs.get(value[3]);assert.ok(proof);return new Response(proof.response)}const h=req.headers,policy=h.get('RunLater-Signing-Policy'),kid=h.get('RunLater-Key-Id'),ts=h.get('RunLater-Timestamp'),task=h.get('RunLater-Task-Id'),op=h.get('RunLater-Operation-Key');assert.equal(kid,'beta_v1');const own=tenantSecrets.get(policy);assert.ok(own);const expected=createHmac('sha256',Buffer.from(own,'hex')).update(`runlater.v2.${policy}.${kid}.${ts}.${task}.${op}.`).update(body).digest('hex');assert.equal(h.get('RunLater-Signature'),expected);received.push({op,task});return new Response('{}')}


let mf,calls=0;
const begin=Date.now()-1000;
const profile={release_id:'local_beta_1',opens_at_ms:begin,closes_at_ms:begin+7*86400000,callback_end_sec:Math.ceil((begin+15*86400000)/1000)+301,self_host:'runlater-public-api.operator.workers.dev'};
const base={PUBLIC_BETA_ENABLED:'operator-approved',PUBLIC_BETA_PROFILE:JSON.stringify(profile),BETA_CALLBACK_MASTER:secret,BETA_READY_QUEUE:'runlater-public-ready'};
const tenantSecrets=new Map();
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
 mf=new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'invitation-production',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',compatibilityFlags:['global_fetch_strictly_public'],ratelimits:{BETA_IP_RATE:{namespace_id:'1001',simple:{limit:60,period:60}},BETA_REG_IP_RATE:{namespace_id:'1002',simple:{limit:6,period:60}}},bindings:{...base,RELEASE_VERSION:{id:'01234567-0123-0123-0123-0123456789ab'},...extra},durableObjects:{ADMISSION:{className:'AdmissionRegistry',useSQLite:true},PROJECTS:{className:'InvitationProject',useSQLite:true}},queueProducers:{BETA_READY:'runlater-public-ready'},queueConsumers:{'runlater-public-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:receiver},{name:'deny-egress',modules:true,compatibilityDate:'2026-10-27',script:'export default {fetch(){return new Response(null,{status:403})}}'}]}));
 await mf.ready;
}
async function api(route,{body,headers={},method='POST',status=200,origin='https://api.runlater.io'}={}) {
 assert.ok(++calls<=150);
 const r=await mf.dispatchFetch(origin+route,{method,headers:{'Content-Type':'application/json','CF-Connecting-IP':`192.0.2.${1+Math.floor(calls/40)}`,...headers},body:body===undefined?undefined:JSON.stringify(body)});
 const text=await r.text();assert.equal(r.status,status,route+': unexpected status '+text);return JSON.parse(text);
}
function signed(project,route,body,{method='POST',idempotency='production-unavailable',key=pair}={}) {
 const publicKey=key.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex'),issued=Date.now(),expires=issued+60000,nonce=randomBytes(32).toString('hex'),text=body===undefined?'':JSON.stringify(body);
 const wire='RunLater signed request v1\n'+JSON.stringify([1,'https://api.runlater.io',project,publicKey,method,route,'',hash(text),idempotency,issued,expires,nonce]);
 return {body,method,headers:{'RunLater-Project-Id':project,'RunLater-Public-Key':publicKey,'RunLater-Request-Signature':sign(null,Buffer.from(wire),key.privateKey).toString('hex'),'RunLater-Nonce':nonce,'RunLater-Issued-At':String(issued),'RunLater-Expires-At':String(expires),'Idempotency-Key':idempotency}};
}

const pause=ms=>new Promise(r=>setTimeout(r,ms));
try {
 await start();
 const health=await api('/health',{method:'GET'});assert.equal(health.mode,'public_free_beta');assert.equal(health.version_id,'01234567-0123-0123-0123-0123456789ab');
 assert.equal((await api('/v1/beta',{method:'GET'})).remaining_projects,10);
 assert.deepEqual(JSON.parse(projectSnapshot()),[]);
 const c=await api('/v1/registration/challenge',{body:{public_key:pub}});
 assert.equal((await api('/v1/beta',{method:'GET'})).remaining_projects,10);
 assert.deepEqual(JSON.parse(projectSnapshot()),[]);
 await api('/v1/registration/complete',{body:{challenge_id:c.challenge_id,signature:'00'.repeat(64)},status:403});
 const request={challenge_id:c.challenge_id,signature:sign(null,Buffer.from(c.canonical_utf8),pair.privateKey).toString('hex')};
 const globalNamespace=await mf.getDurableObjectNamespace('ADMISSION');
 const committed=await globalNamespace.get(globalNamespace.idFromName('public_beta_registry_v1')).fetch('https://private/public/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request)});assert.equal(committed.status,200);assert.deepEqual(JSON.parse(projectSnapshot()),[]);
 await start();
 const receipt=await api('/v1/registration/complete' ,{body:request,status:201});const project=receipt.project_id;assert.equal(receipt.attempt_units,100);
 await start();
 const replay=await api('/v1/registration/complete',{body:request,status:201});assert.deepEqual(replay,receipt);
 const verifier=await api('/v1/callback-key',signed(project,'/v1/callback-key',{}, {idempotency:'get-callback-key'}));assert.equal(verifier.project_id,project);assert.equal(verifier.key_id,'beta_v1');assert.notEqual(verifier.key_hex,secret);tenantSecrets.set(verifier.policy_id,verifier.key_hex);
 const input={endpoint_id:'my_receiver',version:1,url:'https://receiver.account.workers.dev/callback'};
 await api('/v1/destinations/create',signed(project,'/v1/destinations/create',input,{idempotency:'create'}));
 const proof=await api('/v1/destinations/prepare',signed(project,'/v1/destinations/prepare',{endpoint_id:'my_receiver',version:1},{idempotency:'prepare'}));assert.ok(proof.expires_at_ms-Date.now()>240000);proofs.set(proof.id,proof);
 await api('/v1/destinations/verify',signed(project,'/v1/destinations/verify',{endpoint_id:'my_receiver',version:1},{idempotency:'verify'}));
 const task={destination:'registered:my_receiver',body:'{"synthetic":true}',operation_key:'public_beta_callback',run_at_ms:Date.now()+750};
 const accepted=await api('/v1/tasks',{...signed(project,'/v1/tasks',task,{idempotency:'task-one'}),status:201});
 await start();
 for(let i=0;i<50;i++){const v=await api('/v1/tasks/'+accepted.result.id,signed(project,'/v1/tasks/'+accepted.result.id,undefined,{method:'GET',idempotency:''}));if(v.result.status==='succeeded')break;await pause(100)}
 assert.equal(received.filter(x=>x.op==='public_beta_callback').length,1);
 const duplicate=await api('/v1/tasks',signed(project,'/v1/tasks',task,{idempotency:'task-one'}));assert.equal(duplicate.replayed,true);
 await api('/v1/destinations/create',{...signed(project,'/v1/destinations/create',{...input,endpoint_id:'bad_host',url:'https://127.0.0.1/callback'},{idempotency:'bad-host'}),status:403});
 await api('/v1/destinations/create',{...signed(project,'/v1/destinations/create',{...input,endpoint_id:'self_loop',url:'https://runlater-public-api.operator.workers.dev/callback'},{idempotency:'self-loop'}),status:403});
 await api('/v1/callback-key',{...signed('p_'+ 'f'.repeat(60),'/v1/callback-key',{}, {idempotency:'foreign'}),status:403});
 await api('/registration/challenge',{body:{token,public_key:pub},status:404});
 await api('/v1/tasks',{body:task,headers:{Authorization:'Bearer local-alpha-fixture'},status:403});
 const second=generateKeyPairSync('ed25519'),pub2=second.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
 const c2=await api('/v1/registration/challenge',{body:{public_key:pub2},headers:{'CF-Connecting-IP':'192.0.2.2'}});
 const r2=await api('/v1/registration/complete',{body:{challenge_id:c2.challenge_id,signature:sign(null,Buffer.from(c2.canonical_utf8),second.privateKey).toString('hex')},headers:{'CF-Connecting-IP':'192.0.2.2'},status:201});
 const k2=await api('/v1/callback-key',signed(r2.project_id,'/v1/callback-key',{}, {idempotency:'second-key',key:second}));assert.notEqual(k2.key_hex,verifier.key_hex);
 const foreign=await api('/v1/callback-key',{...signed(project,'/v1/callback-key',{}, {idempotency:'foreign-owner',key:second}),status:403});
 await api('/v1/tasks',{...signed(project,'/v1/tasks',{...task,operation_key:'past_trial',run_at_ms:receipt.expires_at_ms+1},{idempotency:'past-trial'}),status:400});
 let cancelAtCapacity;
 for(let i=2;i<=16;i++) {const accepted=await api('/v1/tasks',{...signed(project,'/v1/tasks',{...task,operation_key:'future_'+i,run_at_ms:Date.now()+3600000},{idempotency:'task-'+i}),status:201});if(i===2)cancelAtCapacity=accepted.result.id;}
 const exhausted=await api('/v1/tasks',{...signed(project,'/v1/tasks',{...task,operation_key:'over_capacity',run_at_ms:Date.now()+3600000},{idempotency:'task-17'}),status:429});assert.equal(exhausted.error.code,'beta_lifetime_task_capacity');assert.equal(exhausted.retryable,false);
 const atCapacityReplay=await api('/v1/tasks',signed(project,'/v1/tasks',task,{idempotency:'task-one'}));assert.equal(atCapacityReplay.replayed,true);
 await api('/v1/tasks/'+cancelAtCapacity+'/cancel',signed(project,'/v1/tasks/'+cancelAtCapacity+'/cancel',{}, {idempotency:''}));
 await start();
 const stillExhausted=await api('/v1/tasks',{...signed(project,'/v1/tasks',{...task,operation_key:'after_cancel',run_at_ms:Date.now()+3600000},{idempotency:'after-cancel'}),status:429});assert.equal(stillExhausted.error.code,'beta_lifetime_task_capacity');assert.equal(stillExhausted.retryable,false);


 const beforeRead=projectSnapshot();await api('/v1/identity/me',signed(project,'/v1/identity/me',undefined,{method:'GET',idempotency:''}));assert.equal(projectSnapshot(),beforeRead);
 await start({BETA_REVOKED_PROJECTS:JSON.stringify([r2.project_id])});
 await api('/v1/callback-key',{...signed(r2.project_id,'/v1/callback-key',{}, {idempotency:'revoked',key:second}),status:403});
 await start();
 await api('/v1/callback-key',{...signed(r2.project_id,'/v1/callback-key',{}, {idempotency:'rollback-revoked',key:second}),status:403});
 for(let i=0;i<6;i++)await api('/v1/registration/challenge',{body:{public_key:pub},headers:{'CF-Connecting-IP':'192.0.2.99'}});
 await api('/v1/registration/challenge',{body:{public_key:pub},headers:{'CF-Connecting-IP':'192.0.2.99'},status:429});
 const stored=projectSnapshot();assert.ok(!stored.includes(secret));assert.ok(!stored.includes(verifier.key_hex));assert.ok(!stored.includes(k2.key_hex));
 await mf.dispose();mf=undefined;fs.rmSync(root,{recursive:true});root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-public-cohort-'));await start();
 const cohort=[];
 for(let i=0;i<11;i++) {const pair=generateKeyPairSync('ed25519'),public_key=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');const challenge=await api('/v1/registration/challenge',{body:{public_key},headers:{'CF-Connecting-IP':`198.51.100.${i+1}`}});cohort.push({pair,challenge,ip:`198.51.100.${i+1}`})}
 assert.deepEqual(JSON.parse(projectSnapshot()),[]);
 const completion=(item)=>({challenge_id:item.challenge.challenge_id,signature:sign(null,Buffer.from(item.challenge.canonical_utf8),item.pair.privateKey).toString('hex')});
 for(const item of cohort.slice(0,9))await api('/v1/registration/complete',{body:completion(item),headers:{'CF-Connecting-IP':item.ip},status:201});
 const last=await Promise.all(cohort.slice(9).map(async item=>{calls++;const r=await mf.dispatchFetch('https://api.runlater.io/v1/registration/complete',{method:'POST',headers:{'Content-Type':'application/json','CF-Connecting-IP':item.ip},body:JSON.stringify(completion(item))});await r.text();return r.status}));assert.deepEqual(last.sort(),[201,429]);
 assert.equal((await api('/v1/beta',{method:'GET'})).remaining_projects,0);await start();assert.equal((await api('/v1/beta',{method:'GET'})).remaining_projects,0);
 console.log(JSON.stringify({status:'passed',http_calls:calls,callbacks:received.length,actual_local_queue:true,persisted_restart:true,interrupted_global_project_handoff:true,concurrent_last_cohort_slot:true,external_calls:0,live_resources:0}));
} finally {await mf?.dispose();fs.rmSync(root,{recursive:true})}
