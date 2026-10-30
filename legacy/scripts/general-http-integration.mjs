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
let mf,calls=0,generalFlag=false;const outbound=[];
async function start(enabled=false,key=delegationPublicKey(gateway.privateKey)){
 await mf?.dispose();mf=new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'trial-api-local',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',compatibilityFlags:['global_fetch_strictly_public'],
 bindings:{...base,...(generalFlag?{GENERAL_HTTPS_ENABLED:'operator-approved'}:{}),MCP_DELEGATION_GATEWAY_PUBLIC_KEY:key,...(enabled?{MCP_ANONYMOUS_TRIAL_ENABLED:'operator-approved'}:{})},
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
 const input={url:'https://customer.example.com/webhook?mode=public',payload:{synthetic:true},run_at_ms:Date.now()+60000,operation_key:'http_once'};
 const expected={error:{code:'general_https_unavailable'},task_accepted:false};
 await start(true);let before=snapshots();let response=await transport(origin+'/v1/http/tasks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input)});assert.equal(response.status,503);assert.deepEqual(await response.json(),expected);assert.deepEqual(snapshots(),before,'default unavailable must not create registry/project state');
 generalFlag=true;await start(true);before=snapshots();response=await transport(origin+'/v1/http/tasks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input)});assert.equal(response.status,503);assert.deepEqual(await response.json(),expected);assert.deepEqual(snapshots(),before,'feature flag cannot substitute for reviewed adapter');
 const f=fixture(['cancel','http_schedule','read']),c=client(f);await c.provision();before=snapshots();
 await assert.rejects(c.scheduleHttp(input,'http_once'),e=>e.status===503&&e.code==='general_https_unavailable');assert.deepEqual(snapshots(),before,'authenticated unavailable must not spend operations/nonce/credit/task budget');
 await assert.rejects(c.scheduleHttp(input,'http_once'),e=>e.status===503&&e.code==='general_https_unavailable');assert.deepEqual(snapshots(),before);
 assert.equal((await c.status()).state,'active');assert.deepEqual(snapshots(),before);
 // Existing registered-receiver owner path remains available, with no automatic receiver setup.
 const own=new PublicBetaClientV1({privateKey:owner.privateKey,releaseId,fetchImpl:transport});const challenge=await own.challenge();await own.complete(challenge,PUBLIC_BETA_TERMS);await own.callbackKey('old_owner_unchanged');
 assert.deepEqual(outbound,[]);console.log(JSON.stringify({status:'passed',http_calls:calls,default_unavailable:true,flag_cannot_bypass_adapter:true,authenticated_unavailable_zero_state_effect:true,exact_safe_unavailable:true,old_owner_unchanged:true,external_calls:0,live_resources:0}));
}finally{await mf?.dispose();fs.rmSync(root,{recursive:true,force:true});}
