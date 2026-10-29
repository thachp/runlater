// Synthetic local fixtures only; no receiver deployment or project allocation.
import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import {receiverManifest} from './receiver-manifest.mjs';
import {createTrialAuthority} from './oauth-trial.mjs';
import {AnonymousTrialClientV1} from './trial-client.mjs';
import {delegationPublicKey} from './delegation.mjs';
import {trialToolHandler} from './trial-tools.mjs';
import {MCP_RESOURCE, normalizedAuthRequest, ownerTaskAuthorizationUrl} from './oauth-consent.mjs';
import {authorizeOwner} from './oauth-app.mjs';
const now=1800000000000;
function fixture(scopes=['cancel','enqueue','read','receiver_setup']){
 const {props}=createTrialAuthority({releaseId:'offline_receiver',clientId:'fixture',scopes,now});
 const receiver=generateKeyPairSync('ed25519'),gateway=generateKeyPairSync('ed25519');
 const manifest={version:1,release_id:'offline_receiver',project_id:props.projectId,url:'https://receiver.owner.workers.dev/callback',
  receiver_public_key:delegationPublicKey(receiver.privateKey),pairing_id:'b'.repeat(64),issued_at_ms:now,expires_at_ms:now+300000};
 manifest.signature=sign(null,Buffer.from('RunLater receiver manifest v1\n'+JSON.stringify([1,manifest.release_id,manifest.project_id,manifest.url,manifest.receiver_public_key,manifest.pairing_id,manifest.issued_at_ms,manifest.expires_at_ms])),receiver.privateKey).toString('hex');
 const calls=[],options={privateKey:gateway.privateKey,descriptor:props.descriptor,capability:props.capability,releaseId:manifest.release_id,
  clock:()=>now,nonce:()=> 'c'.repeat(64),fetchImpl:async(url,init)=>{calls.push({url,init});return Response.json({state:'awaiting_receiver',project_id:props.projectId,receiver_ready:false,endpoint_id:null});}};
 return {props,manifest,calls,options,client:new AnonymousTrialClientV1(options),context:{project:props.projectId,releaseId:manifest.release_id,now,trialExpiresAt:props.descriptor.expires_at_ms}};
}
test('public manifest is exact, signed, fixed-origin intent; secret/URL/context substitutions fail before transport',async()=>{
 const f=fixture();assert.deepEqual(receiverManifest(f.manifest,f.context),f.manifest);
 for(const change of [{url:'https://receiver.owner.workers.dev/callback?x=1'},{url:'https://receiver.owner.workers.dev:443/callback'},
  {url:'https://127.0.0.1/callback'},{url:'https://a.b.c.workers.dev/callback'},{url:'https://receiver.owner.workers.dev/other'},
  {project_id:'p_'+'e'.repeat(60)},{release_id:'other'},{issued_at_ms:now+1},{expires_at_ms:now+300001},{expires_at_ms:now},
  {signature:'0'.repeat(128)},{receiver_public_key:'e'.repeat(64)},{private_key:'not permitted'},{installation_sha256:'e'.repeat(64)}]){
   await assert.rejects(f.client.pairReceiver({...f.manifest,...change}),/invalid_receiver_manifest/);
 }
 assert.equal(f.calls.length,0);
});
test('pairing uses explicit scope and immutable idempotency; no automatic retries',async()=>{
 const f=fixture();await f.client.pairReceiver(f.manifest);assert.equal(f.calls.length,1);
 const {url,init}=f.calls[0];assert.equal(url,'https://api.runlater.io/v1/mcp/trials/receiver');
 assert.equal(init.headers['Idempotency-Key'],f.manifest.pairing_id);assert.equal(init.body,JSON.stringify(f.manifest));assert.equal(init.redirect,'manual');
 const old=fixture(['read']);await assert.rejects(old.client.pairReceiver(old.manifest),/insufficient_scope/);assert.equal(old.calls.length,0);
 let attempts=0;const uncertain=new AnonymousTrialClientV1({...f.options,fetchImpl:async()=>{attempts++;throw Error('PRIVATE_SENTINEL');}});
 await assert.rejects(uncertain.pairReceiver(f.manifest),e=>e.code==='transport_uncertain'&&!String(e).includes('PRIVATE_SENTINEL'));assert.equal(attempts,1);
});
test('capability responses cannot smuggle installation secrets or false readiness',async()=>{
 const f=fixture(),base={state:'awaiting_receiver',project_id:f.props.projectId,receiver_ready:false,endpoint_id:null};
 for(const change of [{installation:{callback_keys:'SECRET'}},{installation_sha256:'e'.repeat(64)},{endpoint_id:'arbitrary'},
  {state:'ready'},{receiver_ready:true},{project_id:'p_'+'e'.repeat(60)}]){
  const c=new AnonymousTrialClientV1({...f.options,fetchImpl:async()=>Response.json({...base,...change})});await assert.rejects(c.pairReceiver(f.manifest),/invalid_trial_response/);
 }
 const ready={state:'active',project_id:f.props.projectId,receiver_ready:true,endpoint_id:'receiver',expires_at_ms:f.props.descriptor.expires_at_ms,permissions:f.props.descriptor.permissions,attempt_units:100,client_operations_limit:1000};
 assert.deepEqual(await new AnonymousTrialClientV1({...f.options,fetchImpl:async()=>Response.json(ready)}).status(),ready);
});
test('pairing tool requires feature, confirmation and scope; positive result allowlist omits private material',async()=>{
 const f=fixture();let attempts=0;const client={pairReceiver:async()=>{attempts++;return {state:'awaiting_receiver',project_id:f.props.projectId,receiver_ready:false,endpoint_id:null,secret:'PRIVATE_SENTINEL'};}};
 const args={confirm:true,manifest:f.manifest};
 for(const options of [{},{receiverPairingEnabled:true},{receiverPairingEnabled:true,allowedScopes:['read']}]){
  assert.equal((await trialToolHandler({client,taskHandler:()=>{},...options})('pair_receiver',args,true)).isError,true);
 }
 assert.equal(attempts,0);const call=trialToolHandler({client,taskHandler:()=>{},receiverPairingEnabled:true,allowedScopes:['receiver_setup']});
 for(const bad of [{manifest:f.manifest},{...args,confirm:false},{...args,private_key:'SECRET'}])assert.equal((await call('pair_receiver',bad,true)).isError,true);
 assert.equal(attempts,0);const response=await call('pair_receiver',args,true);assert.equal(response.structuredContent.state,'awaiting_receiver');assert.ok(!JSON.stringify(response).includes('PRIVATE_SENTINEL'));assert.equal(attempts,1);
});
test('scheduling requires fresh readiness; disabling new pairing does not disable installed receivers',async()=>{
 const f=fixture();let ready=false,tasks=0;const client={status:async()=>({state:'active',project_id:f.props.projectId,receiver_ready:ready,...(ready?{endpoint_id:'receiver'}:{}),expires_at_ms:f.props.descriptor.expires_at_ms,permissions:['enqueue'],attempt_units:100,client_operations_limit:1000})};
 const call=trialToolHandler({client,taskHandler:async()=>{tasks++;return {ok:true};}});
 assert.equal((await call('schedule_task',{},true)).structuredContent.error.code,'receiver_setup_required');assert.equal(tasks,0);
 ready=true;assert.deepEqual(await call('schedule_task',{},true),{ok:true});assert.equal(tasks,1);
 client.status=async()=>{throw Error('SECRET');};const error=await call('schedule_task',{},true);assert.equal(error.structuredContent.error.code,'receiver_status_unavailable');assert.equal(tasks,1);assert.ok(!JSON.stringify(error).includes('SECRET'));
});
const request={responseType:'code',clientId:'https://client.example/metadata',redirectUri:'https://client.example/callback',scope:['cancel','enqueue','read','receiver_setup'],state:'exact-state',codeChallenge:'a'.repeat(43),codeChallengeMethod:'S256',resource:MCP_RESOURCE,issuer:MCP_RESOURCE};
test('new scope is opt-in and owner link only removes setup, preserving validated OAuth binding',()=>{
 assert.throws(()=>normalizedAuthRequest(request));assert.deepEqual(normalizedAuthRequest(request,{receiverPairingEnabled:true}).scope,request.scope);
 const url=new URL(ownerTaskAuthorizationUrl(request));assert.equal(url.origin,MCP_RESOURCE);assert.equal(url.pathname,'/authorize');
 assert.equal(url.searchParams.get('scope'),'cancel enqueue read');
 for(const [param,key]of [['client_id','clientId'],['redirect_uri','redirectUri'],['state','state'],['code_challenge','codeChallenge'],['code_challenge_method','codeChallengeMethod'],['resource','resource']])assert.equal(url.searchParams.get(param),request[key]);
 assert.equal([...url.searchParams].length,8);assert.equal(ownerTaskAuthorizationUrl({...request,scope:['receiver_setup']}),null);
 assert.throws(()=>ownerTaskAuthorizationUrl({...request,unknown:'injected'}));
});
test('pairing consent is explicit; owner form requires fresh task-only request',async()=>{
 let begins=0;const oauth={parseAuthRequest:async()=>request,describeConsent:async()=>({clientName:'Fixture',clientDomain:null,redirectIsLoopback:false}),beginConsent:async()=>{begins++;return {handle:'h'.repeat(43),headers:{}};}};
 const config={trialEnabled:true,receiverPairingEnabled:true,releaseId:'offline_receiver',gatewayPublicKey:'a'.repeat(64)};
 const response=await authorizeOwner(new Request(MCP_RESOURCE+'/authorize'),oauth,config);assert.equal(response.status,200);const html=await response.text();
 assert.match(html,/pair one fixed callback receiver/);assert.match(html,/Connect existing project with task permissions only/);assert.doesNotMatch(html,/Signed approval JSON|Public challenge<textarea/);assert.equal(begins,1);
 assert.equal((await authorizeOwner(new Request(MCP_RESOURCE+'/authorize'),oauth,{...config,receiverPairingEnabled:false})).status,400);assert.equal(begins,1);
});
