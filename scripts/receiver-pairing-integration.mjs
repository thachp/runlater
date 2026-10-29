// Actual production Rust/Wasm; synthetic credentials and local SQLite only. No outbound fetch.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash,generateKeyPairSync,randomBytes,sign} from 'node:crypto';
import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {AnonymousTrialClientV1} from '../mcp/trial-client.mjs';
import {delegationPublicKey} from '../mcp/delegation.mjs';
import {PublicBetaClientV1,PUBLIC_BETA_TERMS} from '../examples/public-beta-client.v1.mjs';
const receiverURL='https://paired.account.workers.dev/callback';
const origin='https://api.runlater.io',root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-anonymous-trial-'));
const gateway=generateKeyPairSync('ed25519'),owner=generateKeyPairSync('ed25519'),wrong=generateKeyPairSync('ed25519');
const releaseId='local_anonymous_trial',begin=Date.now()-1000;
const base={PUBLIC_BETA_ENABLED:'operator-approved',BETA_CALLBACK_MASTER:randomBytes(32).toString('hex'),BETA_READY_QUEUE:'runlater-public-ready',
 PUBLIC_BETA_PROFILE:JSON.stringify({release_id:releaseId,opens_at_ms:begin,closes_at_ms:begin+604800000,callback_end_sec:Math.ceil((begin+15*86400000)/1000)+301,self_host:'runlater-public-api.operator.workers.dev'})};
const hash=v=>createHash('sha256').update(v).digest('hex');
function fixture(permissions=['cancel','enqueue','read']){const capability=randomBytes(32).toString('hex'),revocationSecret=randomBytes(32).toString('hex'),bootstrap=randomBytes(32).toString('hex'),issued=Date.now();return {capability,revocationSecret,descriptor:{version:1,release_id:releaseId,bootstrap_id:bootstrap,capability_hash:hash('RunLater anonymous trial capability v1\n'+JSON.stringify([1,releaseId,bootstrap,capability])),revocation_hash:hash('RunLater anonymous trial revocation v1\n'+JSON.stringify([1,releaseId,bootstrap,revocationSecret])),issued_at_ms:issued,expires_at_ms:issued+604800000,permissions}};}
let mf,receiverMf,calls=0,pairingEnabled=false;const outbound=[];let probeCalls=0,proofCalls=0,callbackCalls=0;
async function start(enabled=false,key=delegationPublicKey(gateway.privateKey)){
 await mf?.dispose();mf=new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'trial-api-local',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',compatibilityFlags:['global_fetch_strictly_public'],
 bindings:{...base,...(pairingEnabled?{MCP_RECEIVER_PAIRING_ENABLED:'operator-approved'}:{}),MCP_DELEGATION_GATEWAY_PUBLIC_KEY:key,...(enabled?{MCP_ANONYMOUS_TRIAL_ENABLED:'operator-approved'}:{})},
 ratelimits:{BETA_IP_RATE:{namespace_id:'1001',simple:{limit:60,period:60}},BETA_REG_IP_RATE:{namespace_id:'1002',simple:{limit:6,period:60}}},durableObjects:{ADMISSION:{className:'AdmissionRegistry',useSQLite:true},PROJECTS:{className:'InvitationProject',useSQLite:true}},queueProducers:{BETA_READY:'runlater-public-ready'},queueConsumers:{'runlater-public-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:async req=>{if(!receiverMf||req.url!==receiverURL){outbound.push(req.url);return new Response(null,{status:403});}const body=await req.text();if(body.startsWith('RunLater receiver probe v1\n'))probeCalls++;else if(body.startsWith('RunLater destination verification v1\n'))proofCalls++;else callbackCalls++;return receiverMf.dispatchFetch(req.url,{method:req.method,headers:req.headers,body,redirect:'manual'});}}]}));await mf.ready;
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
 const f=fixture(['cancel','enqueue','read','receiver_setup']),c=client(f);await start(true);await c.provision();
 const receiverKey=generateKeyPairSync('ed25519'),at=Date.now();const manifest={version:1,release_id:releaseId,project_id:c.project,url:receiverURL,receiver_public_key:delegationPublicKey(receiverKey.privateKey),pairing_id:randomBytes(32).toString('hex'),issued_at_ms:at,expires_at_ms:at+12000,signature:''};
 manifest.signature=sign(null,Buffer.from('RunLater receiver manifest v1\n'+JSON.stringify([1,manifest.release_id,manifest.project_id,manifest.url,manifest.receiver_public_key,manifest.pairing_id,manifest.issued_at_ms,manifest.expires_at_ms])),receiverKey.privateKey).toString('hex');
 await assert.rejects(c.pairReceiver(manifest),e=>e.status===403);assert.equal(probeCalls,0);
 let losePull=true,loseAck=true;const installationDigests=[],receiverCalls=[];
 const script=(await build({stdin:{resolveDir:process.cwd(),contents:`import worker,{TrialReceiverInbox} from './examples/trial-receiver/worker.mjs'; export default worker; export class TestInbox extends TrialReceiverInbox { async testCycle(){this.sql.exec('UPDATE receiver_setup SET next_at=0 WHERE id=1');await this.alarm();return this.testSnapshot();} async testSnapshot(){return {setup:this.sql.exec('SELECT ready,cycles FROM receiver_setup').one(),operations:this.sql.exec('SELECT operation_key FROM receiver_operations').toArray()};}}`},bundle:true,platform:'neutral',mainFields:['module','main'],format:'esm',external:['cloudflare:*','node:*'],write:false})).outputFiles[0].text;
 receiverMf=new Miniflare(convertV4MiniflareOptions({script,modules:true,resourcePersistencePath:path.join(root,'receiver'),compatibilityDate:'2026-10-28',compatibilityFlags:['nodejs_compat','global_fetch_strictly_public'],durableObjects:{INBOX:{className:'TestInbox',useSQLite:true}},bindings:{RECEIVER_ENABLED:'pairing-configured',RECEIVER_MANIFEST:JSON.stringify(manifest),RECEIVER_SETUP_PRIVATE_KEY:receiverKey.privateKey.export({format:'pem',type:'pkcs8'})},outboundService:async req=>{
  const u=new URL(req.url);assert.equal(u.origin,origin);assert.ok(['/v1/mcp/receiver/pull','/v1/mcp/receiver/ack'].includes(u.pathname));assert.equal(req.headers.has('Authorization'),false);assert.equal(req.headers.has('RunLater-Trial-Capability'),false);receiverCalls.push(u.pathname);
  const response=await transport(req.url,{method:req.method,headers:req.headers,body:await req.text()});
  if(response.status===200&&u.pathname.endsWith('/pull')){installationDigests.push((await response.clone().json()).installation_sha256);if(losePull){losePull=false;return new Response(null,{status:503});}}
  if(response.status===200&&u.pathname.endsWith('/ack')&&loseAck){loseAck=false;return new Response(null,{status:503});}
  return response;
 }}));await receiverMf.ready;
 pairingEnabled=true;await start(true);const pin=await c.pairReceiver(manifest);assert.equal(pin.state,'awaiting_receiver');assert.equal(probeCalls,1);
 const ns=await receiverMf.getDurableObjectNamespace('INBOX'),stub=ns.getByName('bound-receiver-v1');
 let snapshot;for(let i=0;i<5;i++){snapshot=await stub.testCycle();if(snapshot.setup.ready===1)break;}
 assert.equal(snapshot.setup.ready,1,JSON.stringify({snapshot,receiverCalls,probeCalls,proofCalls}));assert.ok(installationDigests.length>=2);assert.equal(new Set(installationDigests).size,1,'lostpull retry must return identical material');assert.equal(proofCalls,1,'lostack retry must not repeat successful ownership verification');
 assert.equal((await c.status()).receiver_ready,true);assert.equal((await c.pairReceiver(manifest)).endpoint_id,'receiver');assert.equal(probeCalls,1);
 // Setup feature OFF does not invalidate an already paired receiver or change callback authority.
 pairingEnabled=false;await start(true);await assert.rejects(c.pairReceiver(manifest),e=>e.status===403);
 const task=await c.enqueue({endpoint_id:'receiver',body:'{"synthetic":true}',operation_key:'paired_callback',run_at_ms:manifest.expires_at_ms+500},'paired_callback');
 const deadline=Date.now()+20000;let status;while(Date.now()<deadline){status=await c.task(task.result.id);if(status.result.status==='succeeded')break;await new Promise(r=>setTimeout(r,250));}
 assert.equal(status.result.status,'succeeded');assert.ok(Date.now()>manifest.expires_at_ms);assert.equal(callbackCalls,1);snapshot=await stub.testSnapshot();assert.equal(snapshot.operations.length,1);
 const safe=await c.status();for(const secret of [f.capability,f.revocationSecret,...installationDigests])assert.equal(JSON.stringify(safe).includes(secret),false);
 await client(f,true).revoke();await assert.rejects(c.status(),e=>e.status===403);
 assert.deepEqual(outbound,[]);console.log(JSON.stringify({status:'passed',http_calls:calls,actual_receiver:true,default_pairing_off:true,explicit_scope:true,lost_pull_same_installation:true,lost_ack_no_reverification:true,real_hmac_callback:true,callback_after_setup_expiry:true,pairing_off_preserves_callbacks:true,probe_calls:probeCalls,proof_calls:proofCalls,callback_calls:callbackCalls,external_calls:0,live_resources:0}));
}finally{await receiverMf?.dispose();await mf?.dispose();fs.rmSync(root,{recursive:true,force:true});}
