// Actual production Rust/Wasm, disposable SQLite/Queue and synthetic credentials only.
// Every API call is local; outbound receiver traffic is intercepted, never forwarded.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {generateKeyPairSync,randomBytes,sign,createHash,createHmac} from 'node:crypto';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {PublicBetaClientV1,PUBLIC_BETA_TERMS} from '../examples/public-beta-client.v1.mjs';
import {signDelegation,delegationBytes,encodeDelegation,delegationPublicKey} from '../mcp/delegation.mjs';
import {DelegatedPublicBetaClientV1} from '../mcp/delegation-client.mjs';
import {bundleMcp} from './build-mcp.mjs';
import {authorizeFixture} from '../mcp/oauth-test-helpers.mjs';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {SSEClientTransport} from '@modelcontextprotocol/sdk/client/sse.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
const origin='https://api.runlater.io', receiverURL='https://receiver.account.workers.dev/callback';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-mcp-delegation-'));
const owner=generateKeyPairSync('ed25519'), gateway=generateKeyPairSync('ed25519'), wrong=generateKeyPairSync('ed25519');
const gatewayPublicKey=delegationPublicKey(gateway.privateKey), releaseId='local_mcp_delegation';
const hash=v=>createHash('sha256').update(v).digest('hex');
const begin=Date.now()-1000;
const base={PUBLIC_BETA_ENABLED:'operator-approved',BETA_CALLBACK_MASTER:randomBytes(32).toString('hex'),BETA_READY_QUEUE:'runlater-public-ready',
 PUBLIC_BETA_PROFILE:JSON.stringify({release_id:releaseId,opens_at_ms:begin,closes_at_ms:begin+604800000,callback_end_sec:Math.ceil((begin+15*86400000)/1000)+301,self_host:'runlater-public-api.operator.workers.dev'})};
let mf,calls=0,callbackKey,receipt,proofResponse,callbackCount=0;
const unexpected=[];
async function receiver(req) {
 if(req.url!==receiverURL || req.method!=='POST'){unexpected.push({url:req.url,method:req.method});return new Response(null,{status:403});}
 const body=await req.text();
 if(body.startsWith('RunLater destination verification v1\n'))return new Response(proofResponse);
 const h=req.headers;
 const wire=`runlater.v2.${h.get('RunLater-Signing-Policy')}.${h.get('RunLater-Key-Id')}.${h.get('RunLater-Timestamp')}.${h.get('RunLater-Task-Id')}.${h.get('RunLater-Operation-Key')}.`;
 assert.equal(h.get('RunLater-Signature'),createHmac('sha256',Buffer.from(callbackKey.key_hex,'hex')).update(wire).update(body).digest('hex'));
 assert.equal(body,'{"synthetic":true}');assert.equal(h.get('Authorization'),null);callbackCount++;
 return new Response('{}');
}
function snapshots() {
 const r=spawnSync('python3',['-c',`import pathlib,sqlite3,json,sys
out=[]
for p in pathlib.Path(sys.argv[1]).rglob('*.sqlite'):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 if c.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='invitation_snapshot'").fetchone()[0]:
  for row in c.execute('SELECT data FROM invitation_snapshot'):out.append(json.loads(row[0])['data'])
print(json.dumps(out,sort_keys=True))`,root],{encoding:'utf8'});
 assert.equal(r.status,0,r.stderr);return JSON.parse(r.stdout);
}
function operationCount(){return snapshots().find(s=>s.grants).client_operations[receipt.project_id];}
async function start(trust=false) {
 await mf?.dispose();
 mf=new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'mcp-api-local',
 modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',compatibilityFlags:['global_fetch_strictly_public'],
 bindings:{...base,...(trust?{MCP_DELEGATION_GATEWAY_PUBLIC_KEY:typeof trust==='string'?trust:gatewayPublicKey}:{})},
 ratelimits:{BETA_IP_RATE:{namespace_id:'1001',simple:{limit:60,period:60}},BETA_REG_IP_RATE:{namespace_id:'1002',simple:{limit:6,period:60}}},
 durableObjects:{ADMISSION:{className:'AdmissionRegistry',useSQLite:true},PROJECTS:{className:'InvitationProject',useSQLite:true}},
 queueProducers:{BETA_READY:'runlater-public-ready'},queueConsumers:{'runlater-public-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:receiver}]}));
 await mf.ready;
}
async function transport(url,init={}) {
 assert.equal(new URL(url).origin,origin);assert.ok(++calls<=150,'bounded local HTTP calls');
 const headers=new Headers(init.headers);headers.set('CF-Connecting-IP',`192.0.2.${1+Math.floor(calls/25)}`);
 return mf.dispatchFetch(url,{...init,headers,redirect:'manual'});
}
const own=new PublicBetaClientV1({privateKey:owner.privateKey,releaseId,fetchImpl:transport});
function cert(permissions=['cancel','enqueue','read'],duration=3600000){const issuedAtMs=Date.now();return signDelegation({privateKey:owner.privateKey,receipt,releaseId,gatewayPublicKey,permissions,delegationId:randomBytes(32).toString('hex'),issuedAtMs,expiresAtMs:issuedAtMs+duration});}
function client(delegation){return new DelegatedPublicBetaClientV1({privateKey:gateway.privateKey,delegation,receipt,releaseId,fetchImpl:transport});}
function raw(route,{method='POST',body={},delegation,key=gateway.privateKey,project=receipt.project_id,ownerKey=receipt.public_key,idempotencyKey='raw-proof',extra={},expiresAt}={}){
 const now=Date.now(),text=method==='GET'?'':JSON.stringify(body),nonce=randomBytes(32).toString('hex'),expires=expiresAt??Math.min(now+60000,delegation?.expires_at_ms??Number.MAX_SAFE_INTEGER);
 const wire='RunLater signed request v1\n'+JSON.stringify([1,origin,project,ownerKey,method,route,'',hash(text),method==='GET'?'':idempotencyKey,now,expires,nonce]);
 const headers={'Content-Type':'application/json','RunLater-Project-Id':project,'RunLater-Public-Key':ownerKey,'RunLater-Nonce':nonce,'RunLater-Issued-At':String(now),'RunLater-Expires-At':String(expires),'RunLater-Request-Signature':sign(null,Buffer.from(wire),key).toString('hex'),...extra};
 if(method!=='GET'&&idempotencyKey)headers['Idempotency-Key']=idempotencyKey;
 if(delegation)headers['RunLater-MCP-Delegation']=encodeDelegation(delegation);
 return transport(origin+route,{method,headers,body:method==='GET'?undefined:text});
}
async function expect(response,status){const r=await response;const b=await r.json();assert.equal(r.status,status,`unexpected local API response ${JSON.stringify(b)}`);return b;}
// Compose the real hosted OAuth/SDK Worker with the actual Rust API, never a fake API.
async function hostedRoundTrip(delegation) {
 const mcpOrigin='https://mcp.runlater.io';let bridgeCalls=0;
 const hosted=new Miniflare(convertV4MiniflareOptions({modules:true,script:await bundleMcp(),compatibilityDate:'2026-10-29',
  compatibilityFlags:['global_fetch_strictly_public'],durableObjects:{MCP_HUB:{className:'McpHub',useSQLite:true}},
  ratelimits:{MCP_IP_RATE:{namespace_id:'2101',simple:{limit:60,period:60}},MCP_AUTH_RATE:{namespace_id:'2102',simple:{limit:6,period:60}}},
  bindings:{MCP_ENABLED:'operator-approved',MCP_OAUTH_ENABLED:'operator-approved',MCP_GATEWAY_PUBLIC_KEY:gatewayPublicKey,
   MCP_GATEWAY_PRIVATE_KEY:gateway.privateKey.export({format:'pem',type:'pkcs8'}),MCP_RELEASE_ID:releaseId},
  outboundService:async req=>{
   if(req.url==='https://client.example.com/metadata')return Response.json({client_id:req.url,client_name:'Local composition fixture',
    redirect_uris:['https://client.example.com/callback'],token_endpoint_auth_method:'none'},{headers:{'Cache-Control':'no-store'}});
   const url=new URL(req.url);
   if(url.origin!==origin || !(url.pathname==='/v1/mcp/delegations/validate'||/^\/v1\/tasks(?:\/[^/]+(?:\/cancel)?)?$/.test(url.pathname)) || url.search){
    unexpected.push({url:req.url,method:req.method});return new Response(null,{status:403});
   }
   assert.equal(req.headers.has('authorization'),false,'OAuth bearer must never reach API');bridgeCalls++;
   return transport(req.url,{method:req.method,headers:req.headers,body:req.method==='GET'?undefined:await req.text()});
  }}));
 try {
  await hosted.ready;
  const call=(route,init={})=>hosted.dispatchFetch(mcpOrigin+route,{...init,redirect:'manual',headers:{...Object.fromEntries(new Headers(init.headers)),'CF-Connecting-IP':'198.51.100.1'}});
  for(const kind of ['sse','mcp']){
   const token=await authorizeFixture(call,{privateKey:owner.privateKey,delegation});
   const sdk=new Client({name:'compiled-api-composition',version:'1'});
   const localFetch=(url,init={})=>{const u=new URL(url);assert.equal(u.origin,mcpOrigin);return call(u.pathname+u.search,{...init,headers:{...Object.fromEntries(new Headers(init.headers)),Authorization:`Bearer ${token.access_token}`}});};
   const wire=kind==='sse'?new SSEClientTransport(new URL(mcpOrigin+'/sse'),{fetch:localFetch}):new StreamableHTTPClientTransport(new URL(mcpOrigin+'/mcp'),{fetch:localFetch});
   try {
    await sdk.connect(wire);assert.equal((await sdk.listTools()).tools.length,4);
    const created=await sdk.callTool({name:'schedule_task',arguments:{...request,run_at_ms:Date.now()+300000,operation_key:'hosted_'+kind,idempotency_key:'hosted_'+kind}});
    assert.notEqual(created.isError,true,JSON.stringify(created));const task=created.structuredContent.task_id;assert.ok(task);
    assert.equal((await sdk.callTool({name:'task_status',arguments:{task_id:task}})).structuredContent.status,'scheduled');
    assert.equal((await sdk.callTool({name:'cancel_task',arguments:{task_id:task}})).structuredContent.status,'cancelled');
    assert.equal((await own.task(task)).result.status,'cancelled','independent owner confirms real API state');
   }finally{await sdk.close();}
  }
  assert.equal(bridgeCalls,10,'four real validation requests and six real task requests');
 }finally{await hosted.dispose();}
}
const request={endpoint_id:'owned',body:'{"synthetic":true}',operation_key:'mcp_future',run_at_ms:0};
try {
 await start();const challenge=await own.challenge();receipt=await own.complete(challenge,PUBLIC_BETA_TERMS);
 callbackKey=await own.callbackKey('receiver-verifier');const endpoint=await own.createDestination('owned',1,receiverURL,'receiver-create');
 const proof=await own.prepareDestination(endpoint,'receiver-prepare');proofResponse=proof.response;await own.verifyDestination(endpoint,'receiver-verify');
 const full=cert();
 await assert.rejects(client(full).enqueue({...request,run_at_ms:Date.now()+60000},'default-disabled'),e=>e.status===403);
 await start(delegationPublicKey(wrong.privateKey));
 await assert.rejects(client(full).enqueue({...request,run_at_ms:Date.now()+60000},'wrong-trust'),e=>e.status===403);
 await start(true); // Reload legacy snapshots without MCP fields; no state migration/reset.
 const beforeValidation=snapshots();
 assert.deepEqual(await client(full).validateDelegation(),{active:true,project_id:receipt.project_id,expires_at_ms:full.expires_at_ms,permissions:full.permissions});
 assert.deepEqual(snapshots(),beforeValidation,'validation must not write registry/project state or charge any budget');
 const fakeOwner=generateKeyPairSync('ed25519'),fakePublic=delegationPublicKey(fakeOwner.privateKey),fakeTicket=hash(JSON.stringify(['runlater.public-beta.registration.v1',releaseId,fakePublic])),fakeNow=Date.now();
 const fakeReceipt={...receipt,ticket_id:fakeTicket,project_id:'p_'+fakeTicket.slice(0,60),grant_id:'g_'+fakeTicket.slice(0,60),public_key:fakePublic,enrolled_at_ms:fakeNow-1000,expires_at_ms:fakeNow-1000+604800000};
 const fakeCert=signDelegation({privateKey:fakeOwner.privateKey,receipt:fakeReceipt,releaseId,gatewayPublicKey,permissions:['enqueue'],delegationId:randomBytes(32).toString('hex'),issuedAtMs:fakeNow,expiresAtMs:fakeNow+3600000});
 const fakeClient=new DelegatedPublicBetaClientV1({privateKey:gateway.privateKey,delegation:fakeCert,receipt:fakeReceipt,releaseId,fetchImpl:transport});
 await assert.rejects(fakeClient.validateDelegation(),e=>e.status===403);
 assert.deepEqual(snapshots(),beforeValidation,'fabricated enrollment validation must allocate no durable project or spend budget');
 // A reserved registry grant is not sufficient: interruption before project installation stays unauthorized.
 const pendingOwner=generateKeyPairSync('ed25519'),pendingClient=new PublicBetaClientV1({privateKey:pendingOwner.privateKey,releaseId,fetchImpl:transport});
 const pendingChallenge=await pendingClient.challenge();const namespace=await mf.getDurableObjectNamespace('ADMISSION');
 calls++;const committed=await namespace.get(namespace.idFromName('public_beta_registry_v1')).fetch('https://internal/public/complete',{method:'POST',redirect:'manual',headers:{'Content-Type':'application/json'},body:JSON.stringify({challenge_id:pendingChallenge.challenge_id,signature:sign(null,Buffer.from(pendingChallenge.canonical_utf8),pendingOwner.privateKey).toString('hex')})});
 assert.equal(committed.status,200);const {grant}=await committed.json();
 const pendingReceipt={ticket_id:grant.ticket.id,project_id:grant.ticket.project_id,public_key:grant.public_key,grant_id:grant.ticket.grant_id,enrolled_at_ms:grant.admitted_at_ms,expires_at_ms:grant.expires_at_ms,attempt_units:grant.ticket.terms.attempt_units,permissions:grant.ticket.terms.permissions};
 const pendingNow=Date.now(),pendingCert=signDelegation({privateKey:pendingOwner.privateKey,receipt:pendingReceipt,releaseId,gatewayPublicKey,permissions:['enqueue'],delegationId:randomBytes(32).toString('hex'),issuedAtMs:pendingNow,expiresAtMs:pendingNow+3600000});
 const pendingGateway=new DelegatedPublicBetaClientV1({privateKey:gateway.privateKey,delegation:pendingCert,receipt:pendingReceipt,releaseId,fetchImpl:transport});
 const beforePendingValidation=snapshots();await assert.rejects(pendingGateway.validateDelegation(),e=>e.status===403);assert.deepEqual(snapshots(),beforePendingValidation);
 const scheduled={...request,run_at_ms:Date.now()+60000};const delegated=client(full);
 const created=await delegated.enqueue(scheduled,'stable-create');assert.equal(created.created,true);assert.equal(created.task_accepted,true);
 const id=created.result.id;assert.equal((await delegated.enqueue(scheduled,'stable-create')).replayed,true);
 assert.equal((await delegated.task(id)).result.id,id);
 assert.equal((await delegated.cancel(id)).result.status,'cancelled');
 const narrow=cert(['enqueue']);const narrowResult=await client(narrow).enqueue({...scheduled,operation_key:'write_only'},'write-only');
 assert.equal(narrowResult.funding,null);assert.equal(narrowResult.result.input,undefined);assert.equal(narrowResult.result.attempts,undefined);
 await expect(raw(`/v1/tasks/${id}`,{method:'GET',delegation:narrow}),403);
 await expect(raw(`/v1/tasks/${id}`,{method:'GET',delegation:full,key:wrong.privateKey}),403);
 await expect(raw(`/v1/tasks/${id}`,{method:'GET',delegation:full,project:'p_'+'f'.repeat(60)}),403);
 const other=generateKeyPairSync('ed25519'),otherClient=new PublicBetaClientV1({privateKey:other.privateKey,releaseId,fetchImpl:transport});
 const otherChallenge=await otherClient.challenge();const otherReceipt=await otherClient.complete(otherChallenge,PUBLIC_BETA_TERMS);
 const at=Date.now(),otherCert=signDelegation({privateKey:other.privateKey,receipt:otherReceipt,releaseId,gatewayPublicKey,permissions:['read'],delegationId:randomBytes(32).toString('hex'),issuedAtMs:at,expiresAtMs:at+3600000});
 await expect(raw(`/v1/tasks/${id}`,{method:'GET',delegation:otherCert,project:otherReceipt.project_id,ownerKey:otherReceipt.public_key}),404);
 const tampered={...full,signature:'00'.repeat(64)};await expect(raw(`/v1/tasks/${id}`,{method:'GET',delegation:tampered}),403);
 await expect(raw('/v1/callback-key',{delegation:full}),403);
 await expect(raw(`/v1/tasks/${id}/redrive`,{delegation:full}),403);
 await expect(raw('/v1/mcp/delegations/revoke',{delegation:full}),403);
 const revoke=await expect(raw('/v1/mcp/delegations/revoke',{key:owner.privateKey,idempotencyKey:'owner-revoke-all'}),200);
 assert.equal(revoke.replayed,false);await start(true);
 const beforeReplayCount=operationCount();
 const replay=await expect(raw('/v1/mcp/delegations/revoke',{key:owner.privateKey,idempotencyKey:'owner-revoke-all'}),200);assert.deepEqual(replay,{revoked_before_ms:revoke.revoked_before_ms,replayed:true});
 assert.equal(operationCount(),beforeReplayCount,'revocation replay must not charge another operation');
 for(let i=0;i<5;i++)await assert.rejects(client(full).task(id),e=>e.status===403);
 await assert.rejects(client(full).validateDelegation(),e=>e.status===403);
 assert.equal(operationCount(),beforeReplayCount,'revoked proof must never consume owner lifetime budget');
 const fresh=cert();assert.ok(fresh.issued_at_ms>revoke.revoked_before_ms);assert.equal((await client(fresh).task(id)).result.id,id);
 await hostedRoundTrip(fresh);
 // Admission survives delegation expiry: authorization is required when scheduling, not at callback time.
 const short=cert(['enqueue'],2000);const due=short.expires_at_ms+1000;
 const future=await client(short).enqueue({...request,operation_key:'after_delegation_expiry',run_at_ms:due},'expiry-future');
 const deadline=Date.now()+12000;let status;
 while(Date.now()<deadline){status=await own.task(future.result.id);if(status.result.status==='succeeded')break;await new Promise(r=>setTimeout(r,100));}
 assert.equal(status.result.status,'succeeded');assert.ok(Date.now()>short.expires_at_ms);assert.equal(callbackCount,1);
 await expect(raw(`/v1/tasks/${id}`,{method:'GET',delegation:short,expiresAt:Date.now()+60000}),403);
 await start(); // Removing trust disables delegates immediately, owner signing remains operational.
 await assert.rejects(client(fresh).task(id),e=>e.status===403);assert.equal((await own.task(id)).result.id,id);
 assert.deepEqual(unexpected,[]);
 console.log(JSON.stringify({status:'passed',http_calls:calls,delegated_create_read_cancel:true,full_oauth_sse_rust:true,full_oauth_streamable_rust:true,default_disabled:true,wrong_trust_rejected:true,project_isolation:true,write_scope_redacted:true,owner_revoke_persisted:true,revoked_proofs_zero_budget:true,introspection_read_only:true,fake_enrollment_denied:true,incomplete_project_enrollment_denied:true,revoke_replay_original_cutoff:true,old_snapshot_reload:true,callback_after_delegation_expiry:true,callbacks:callbackCount,external_calls:0,live_resources:0}));
} finally {await mf?.dispose();fs.rmSync(root,{recursive:true,force:true});}
