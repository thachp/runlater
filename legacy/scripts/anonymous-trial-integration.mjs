// Actual production Rust/Wasm; synthetic credentials and local SQLite only. No outbound fetch.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {AnonymousTrialClientV1} from '../mcp/trial-client.mjs';
import {delegationPublicKey} from '../mcp/delegation.mjs';
import {PublicBetaClientV1,PUBLIC_BETA_TERMS} from '../examples/public-beta-client.v1.mjs';
const origin='https://api.runlater.io',root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-anonymous-trial-'));
const gateway=generateKeyPairSync('ed25519'),owner=generateKeyPairSync('ed25519'),wrong=generateKeyPairSync('ed25519');
const releaseId='local_anonymous_trial',begin=Date.now()-1000;
const base={PUBLIC_BETA_ENABLED:'operator-approved',BETA_CALLBACK_MASTER:randomBytes(32).toString('hex'),BETA_READY_QUEUE:'runlater-public-ready',
 PUBLIC_BETA_PROFILE:JSON.stringify({release_id:releaseId,opens_at_ms:begin,closes_at_ms:begin+604800000,callback_end_sec:Math.ceil((begin+15*86400000)/1000)+301,self_host:'runlater-public-api.operator.workers.dev'})};
const hash=v=>createHash('sha256').update(v).digest('hex');
function fixture(permissions=['cancel','enqueue','read']){const capability=randomBytes(32).toString('hex'),revocationSecret=randomBytes(32).toString('hex'),bootstrap=randomBytes(32).toString('hex'),issued=Date.now();return {capability,revocationSecret,descriptor:{version:1,release_id:releaseId,bootstrap_id:bootstrap,capability_hash:hash('RunLater anonymous trial capability v1\n'+JSON.stringify([1,releaseId,bootstrap,capability])),revocation_hash:hash('RunLater anonymous trial revocation v1\n'+JSON.stringify([1,releaseId,bootstrap,revocationSecret])),issued_at_ms:issued,expires_at_ms:issued+604800000,permissions}};}
let mf,calls=0;const outbound=[];
async function start(enabled=false,key=delegationPublicKey(gateway.privateKey)){
 await mf?.dispose();mf=new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'trial-api-local',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',compatibilityFlags:['global_fetch_strictly_public'],
 bindings:{...base,MCP_DELEGATION_GATEWAY_PUBLIC_KEY:key,...(enabled?{MCP_ANONYMOUS_TRIAL_ENABLED:'operator-approved'}:{})},
 ratelimits:{BETA_IP_RATE:{namespace_id:'1001',simple:{limit:60,period:60}},BETA_REG_IP_RATE:{namespace_id:'1002',simple:{limit:6,period:60}}},durableObjects:{ADMISSION:{className:'AdmissionRegistry',useSQLite:true},PROJECTS:{className:'InvitationProject',useSQLite:true}},queueProducers:{BETA_READY:'runlater-public-ready'},queueConsumers:{'runlater-public-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:req=>{outbound.push(req.url);return new Response(null,{status:403});}}]}));await mf.ready;
}
async function transport(url,init={}){assert.equal(new URL(url).origin,origin);assert.ok(++calls<=120);const headers=new Headers(init.headers);headers.set('CF-Connecting-IP',`192.0.2.${1+Math.floor(calls/20)}`);return mf.dispatchFetch(url,{...init,headers,redirect:'manual'});}
function client(f,revocation=false,fetchImpl=transport){return new AnonymousTrialClientV1({privateKey:gateway.privateKey,descriptor:f.descriptor,...(revocation?{revocationSecret:f.revocationSecret}:{capability:f.capability}),releaseId,fetchImpl});}
function snapshots(){const r=spawnSync('python3',['-c',`import pathlib,sqlite3,json,sys
out=[]
for p in pathlib.Path(sys.argv[1]).rglob('*.sqlite'):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 if c.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='invitation_snapshot'").fetchone()[0]:
  for row in c.execute('SELECT data FROM invitation_snapshot'):out.append(json.loads(row[0])['data'])
print(json.dumps(out,sort_keys=True))`,root],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout);}
try{
 const f=fixture(),c=client(f);await start();await assert.rejects(c.provision(),e=>e.status===403);
 await start(true,delegationPublicKey(wrong.privateKey));await assert.rejects(c.provision(),e=>e.status===403);
 await start(true);const empty=snapshots();assert.equal((await c.status()).state,'unprovisioned');assert.equal((await c.validate()).state,'unprovisioned');assert.deepEqual(snapshots(),empty);
 const results=await Promise.all([c.provision(),c.provision()]);assert.deepEqual(results[0],results[1]);assert.equal(results[0].state,'active');assert.equal(results[0].receiver_ready,false);
 const installed=snapshots();await start(true);assert.deepEqual(await c.provision(),results[0]);assert.deepEqual(snapshots(),installed);
 assert.equal((await c.status()).state,'active');assert.equal((await c.validate()).state,'active');assert.deepEqual(snapshots(),installed);
 // Interrupt after registry reservation but before project installation. Status cannot invent an enrollment.
 const interrupted=fixture();let pendingGrant;
 await assert.rejects(client(interrupted,false,async(url,init)=>{
  const h=new Headers(init.headers),u=new URL(url),descriptor=interrupted.descriptor;
  const envelope={version:1,origin,project_id:h.get('RunLater-Project-Id'),public_key:'',method:init.method,path:u.pathname,query:'',body_sha256:hash(init.body),idempotency_key:h.get('Idempotency-Key')||'',issued_at_ms:Number(h.get('RunLater-Issued-At')),expires_at_ms:Number(h.get('RunLater-Expires-At')),nonce:h.get('RunLater-Nonce')};
  const ns=await mf.getDurableObjectNamespace('ADMISSION');
  const response=await ns.get(ns.idFromName('public_beta_registry_v1')).fetch('https://internal/public/trial-request',{method:'POST',redirect:'manual',headers:{'Content-Type':'application/json'},body:JSON.stringify({envelope,descriptor,secret:interrupted.capability,signature:h.get('RunLater-Request-Signature'),body_hex:Buffer.from(init.body).toString('hex')})});
  assert.equal(response.status,200);pendingGrant=await response.json();throw new Error('interrupted_install');
 }).provision(),e=>e.code==='transport_uncertain');
 assert.ok(pendingGrant.grant);const pendingSnapshot=snapshots();await assert.rejects(client(interrupted).status(),e=>e.status===403);assert.deepEqual(snapshots(),pendingSnapshot);
 await start(true);assert.equal((await client(interrupted).provision()).state,'active');assert.equal((await client(interrupted).validate()).state,'active');
 // Simulate a committed response lost in transit; retry must not allocate a second slot or refill.
 const lost=fixture();await assert.rejects(client(lost,false,async(url,init)=>{await transport(url,init);throw new Error('simulated_lost_response');}).provision(),e=>e.code==='transport_uncertain');
 const lostCommitted=snapshots();assert.equal((await client(lost).provision()).state,'active');assert.deepEqual(snapshots(),lostCommitted);
 let missingReceiver;const missing=client(f,false,async(url,init)=>{const response=await transport(url,init);missingReceiver=await response.clone().json();return response;});
 await assert.rejects(missing.enqueue({endpoint_id:'not_configured',body:'{}',operation_key:'missing_receiver',run_at_ms:Date.now()+60000},'missing_receiver'),e=>e.status===409);assert.equal(missingReceiver.error.code,'receiver_required');
 const live=snapshots();assert.ok(live.every(s=>!s.project||Object.keys(s.project.ledger?.tasks??{}).length===0),'missing receiver must not commit task');
 const serialized=JSON.stringify(live);for(const secret of [f.capability,f.revocationSecret,lost.capability,lost.revocationSecret])assert.equal(serialized.includes(secret),false);
 const revoked=await client(f,true).revoke();assert.deepEqual(revoked,{revoked:true,provisioned:true});await start(true);const cutoff=snapshots();assert.deepEqual(await client(f,true).revoke(),revoked);
 await assert.rejects(c.status(),e=>e.status===403);await assert.rejects(c.provision(),e=>e.status===403);assert.deepEqual(snapshots(),cutoff);
 const never=fixture();assert.deepEqual(await client(never,true).revoke(),{revoked:true,provisioned:false});await start(true);await assert.rejects(client(never).provision(),e=>e.status===403);
 // No existing owner authentication or budget path was replaced.
 const own=new PublicBetaClientV1({privateKey:owner.privateKey,releaseId,fetchImpl:transport});const challenge=await own.challenge();await own.complete(challenge,PUBLIC_BETA_TERMS);
 await start();await assert.rejects(client(lost).status(),e=>e.status===403);await own.callbackKey('existing_owner_still_works');
 assert.deepEqual(outbound,[]);console.log(JSON.stringify({status:'passed',http_calls:calls,default_off:true,explicit_provision:true,concurrent_single_slot:true,uncertain_response_replay:true,interrupted_install_repaired:true,read_only_status:true,hash_only_storage:true,missing_receiver_no_task:true,revocation_persists:true,preprovision_tombstone:true,owner_unchanged:true,external_calls:0,live_resources:0}));
}finally{await mf?.dispose();fs.rmSync(root,{recursive:true,force:true});}
