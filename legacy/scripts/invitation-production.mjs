// Production artifact, local synthetic transport only. No provider mutations or external callbacks.
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,randomBytes,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-invitation-production-'));
const pair=generateKeyPairSync('ed25519'),pub=pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex');
const token=randomBytes(32).toString('hex'),hash=v=>createHash('sha256').update(v).digest('hex');
const expiry=Date.now()+3600000;
let mf,calls=0;
const base={INVITATION_ENROLLMENT:'operator-approved',INVITATION_POLICY:JSON.stringify({revision:1,terms:{attempt_units:20,identity_ms:3600000,permissions:['enqueue','read','cancel','redrive']},max_projects:2,max_tickets:4,requests_per_minute:128}),INVITATION_SEEDS:JSON.stringify([{id:hash(token),expires_at_ms:expiry,revoked:false}])};
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
 mf=new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'invitation-production',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',bindings:{...base,...extra},durableObjects:{ADMISSION:{className:'AdmissionRegistry',useSQLite:true},PROJECTS:{className:'InvitationProject',useSQLite:true}},outboundService:'deny-egress'},{name:'deny-egress',modules:true,compatibilityDate:'2026-10-27',script:'export default {fetch(){return new Response(null,{status:403})}}'}]}));
 await mf.ready;
}
async function api(route,{body,headers={},method='POST',status=200,origin='https://api.runlater.io'}={}) {
 assert.ok(++calls<=50);
 const r=await mf.dispatchFetch(origin+route,{method,headers:{'Content-Type':'application/json',...headers},body:body===undefined?undefined:JSON.stringify(body)});
 const text=await r.text();assert.equal(r.status,status,route+': '+text);return JSON.parse(text);
}
function signed(project,route,body,{method='POST',idempotency='production-unavailable',key=pair}={}) {
 const publicKey=key.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('hex'),issued=Date.now(),expires=issued+60000,nonce=randomBytes(32).toString('hex'),text=body===undefined?'':JSON.stringify(body);
 const wire='RunLater signed request v1\n'+JSON.stringify([1,'https://api.runlater.io',project,publicKey,method,route,'',hash(text),idempotency,issued,expires,nonce]);
 return {body,method,headers:{'RunLater-Project-Id':project,'RunLater-Public-Key':publicKey,'RunLater-Request-Signature':sign(null,Buffer.from(wire),key.privateKey).toString('hex'),'RunLater-Nonce':nonce,'RunLater-Issued-At':String(issued),'RunLater-Expires-At':String(expires),'Idempotency-Key':idempotency}};
}
try {
 await start();
 await api('/fixture/issue',{body:{token,expires_at_ms:expiry},status:404});
 await api('/health',{method:'GET',origin:'http://127.0.0.1',status:421});
 await api('/registration/challenge',{body:{token,public_key:pub},headers:{Authorization:'Bearer local-alpha'},status:403});
 await api('/registration/challenge',{body:{token:randomBytes(32).toString('hex'),public_key:pub},status:403});
 const c=await api('/registration/challenge',{body:{token,public_key:pub}});
 const completion={token,challenge_id:c.challenge_id,signature:sign(null,Buffer.from(c.canonical_utf8),pair.privateKey).toString('hex')};
 const receipt=await api('/registration/complete',{body:completion,status:201});
 assert.deepEqual(await api('/registration/complete',{body:completion,status:201}),receipt);
 const beforeRead=projectSnapshot();await api('/v1/identity/me',{...signed(receipt.project_id,'/v1/identity/me',undefined,{method:'GET',idempotency:''})});assert.equal(projectSnapshot(),beforeRead);
 const task={destination:'registered:fixture',body:'synthetic',operation_key:'not-accepted'};
 await api('/v1/tasks',{...signed(receipt.project_id,'/v1/tasks',task),status:503});
 await api('/v1/identity/me',{...signed(receipt.project_id,'/v1/identity/me',undefined,{method:'GET',idempotency:'',key:generateKeyPairSync('ed25519')}),status:403});
 await start();
 assert.deepEqual(await api('/registration/complete',{body:completion,status:201}),receipt);
 await api('/v1/tasks',{...signed(receipt.project_id,'/v1/tasks',task),status:503});
 await start({INVITATION_POLICY:JSON.stringify({...JSON.parse(base.INVITATION_POLICY),revision:2,terms:null})});
 await api('/v1/identity/me',{...signed(receipt.project_id,'/v1/identity/me',undefined,{method:'GET',idempotency:''})});
 await api('/registration/challenge',{body:{token,public_key:pub},status:503});
 await start({INVITATION_POLICY:JSON.stringify({...JSON.parse(base.INVITATION_POLICY),revision:3,terms:null}),INVITATION_SEEDS:JSON.stringify([{id:hash(token),expires_at_ms:expiry,revoked:true}])});
 const beforeRevokedRead=projectSnapshot();await api('/v1/identity/me',{...signed(receipt.project_id,'/v1/identity/me',undefined,{method:'GET',idempotency:''}),status:403});assert.equal(projectSnapshot(),beforeRevokedRead);
 await start({INVITATION_POLICY:JSON.stringify({...JSON.parse(base.INVITATION_POLICY),revision:4,terms:null})});
 await api('/v1/identity/me',{...signed(receipt.project_id,'/v1/identity/me',undefined,{method:'GET',idempotency:''}),status:403});
 await start({ALPHA_PROJECT_POLICIES:'[]'});await api('/health',{method:'GET',status:403});
 await start({TEST_INVITATION_POLICY:'{}'});await api('/health',{method:'GET',status:403});
 await start({INVITATION_ENROLLMENT:'invalid'});await api('/health',{method:'GET',status:403});
 await start({INVITATION_POLICY:JSON.stringify({...JSON.parse(base.INVITATION_POLICY),revision:5}),INVITATION_SEEDS:'{}'});await api('/registration/challenge',{body:{token,public_key:pub},status:503});
 await start({INVITATION_POLICY:'{}'});await api('/registration/challenge',{body:{token,public_key:pub},status:503});
 console.log(JSON.stringify({status:'passed',production_compiled_http_calls:calls,fresh_admission:'disabled',external_callbacks:0,live_resources:0}));
} finally {await mf?.dispose();fs.rmSync(root,{recursive:true});}
