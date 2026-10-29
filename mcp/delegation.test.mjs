// Disposable offline identities only. These tests never enroll or contact a live service.
import test from 'node:test';
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,verify} from 'node:crypto';
import {signDelegation,verifyDelegation,delegationBytes,delegationPublicKey,encodeDelegation,decodeDelegation,DELEGATION_MAX_MS} from './delegation.mjs';
import {DelegatedPublicBetaClientV1} from './delegation-client.mjs';
import {PUBLIC_BETA_TERMS,PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
const NOW=1800000000000;
function fixture(permissions=['cancel','enqueue','read']) {
 const owner=generateKeyPairSync('ed25519'),gateway=generateKeyPairSync('ed25519');
 const publicKey=delegationPublicKey(owner.privateKey),gatewayPublicKey=delegationPublicKey(gateway.privateKey),releaseId='offline_mcp_delegation';
 const ticket=hash(JSON.stringify(['runlater.public-beta.registration.v1',releaseId,publicKey]));
 const receipt={ticket_id:ticket,project_id:'p_'+ticket.slice(0,60),public_key:publicKey,grant_id:'g_'+ticket.slice(0,60),enrolled_at_ms:NOW-1000,expires_at_ms:NOW-1000+604800000,attempt_units:100,permissions:[...PUBLIC_BETA_TERMS.permissions]};
 const input={privateKey:owner.privateKey,receipt,releaseId,gatewayPublicKey,permissions,delegationId:'ab'.repeat(32),issuedAtMs:NOW,expiresAtMs:NOW+DELEGATION_MAX_MS};
 const delegation=signDelegation(input);
 const calls=[];let now=NOW;
 const client=new DelegatedPublicBetaClientV1({privateKey:gateway.privateKey,delegation,releaseId,receipt,clock:()=>now,nonce:()=> 'cd'.repeat(32),fetchImpl:async(url,init)=>{calls.push({url,init});return Response.json({ok:true});}});
 return {owner,gateway,receipt,input,delegation,calls,client,options:{gatewayPublicKey,releaseId,now:NOW,receipt},expire:()=>{now=NOW+DELEGATION_MAX_MS;}};
}
test('owner consent binds exact project, gateway, resource, sorted task scopes and expiry',()=>{
 const f=fixture(); assert.deepEqual(verifyDelegation(f.delegation,f.options),f.delegation);
 assert.equal(verify(null,delegationBytes(f.delegation),f.owner.publicKey,Buffer.from(f.delegation.signature,'hex')),true);
 assert.deepEqual(decodeDelegation(encodeDelegation(f.delegation)),f.delegation);
 assert.equal(delegationBytes(f.delegation).toString().startsWith('RunLater MCP task delegation v1\n[1,"https://api.runlater.io","https://mcp.runlater.io",'),true);
 for(const change of [{project_id:'p_'+'0'.repeat(60)},{gateway_public_key:'01'.repeat(32)},{owner_public_key:'02'.repeat(32)},{resource:'https://evil.test'},{audience:'https://evil.test'},{release_id:'other'},{permissions:['read']},{delegation_id:'03'.repeat(32)},{issued_at_ms:NOW-1},{expires_at_ms:NOW+1000},{signature:'00'.repeat(64)},{extra:'no'}]) {
  assert.throws(()=>verifyDelegation({...f.delegation,...change},f.options),PublicBetaClientError);
 }
});
test('grant attenuation rejects malformed scope order, unknown privileges, stale/long grants and wrong receipts',()=>{
 const f=fixture();
 for(const permissions of [[],['enqueue','cancel'],['read','read'],['redrive'],['manage_destinations'],['read','enqueue','cancel']])assert.throws(()=>signDelegation({...f.input,permissions}),PublicBetaClientError);
 for(const expiresAtMs of [NOW,NOW-1,NOW+DELEGATION_MAX_MS+1,Number.MAX_SAFE_INTEGER+1])assert.throws(()=>signDelegation({...f.input,expiresAtMs}),PublicBetaClientError);
 assert.throws(()=>verifyDelegation(f.delegation,{...f.options,now:NOW-1}),/identity_expired/);
 assert.throws(()=>verifyDelegation(f.delegation,{...f.options,now:f.delegation.expires_at_ms}),/identity_expired/);
 for(const receipt of [{...f.receipt,expires_at_ms:NOW+100},{...f.receipt,public_key:'0'.repeat(64)},{...f.receipt,grant_id:'other'},{...f.receipt,permissions:['enqueue']},{...f.receipt,attempt_units:101}])assert.throws(()=>signDelegation({...f.input,receipt}),PublicBetaClientError);
 for(const value of ['',encodeDelegation(f.delegation)+'=','a'.repeat(4097),Buffer.from('{}').toString('base64url')])assert.throws(()=>decodeDelegation(value),PublicBetaClientError);
});
test('gateway calls exact fixed task API signed as delegated actor, never forwards MCP access tokens',async()=>{
 const f=fixture(),id='task_0000000000000001';
 await f.client.enqueue({endpoint_id:'owned',body:'{"synthetic":true}',operation_key:'stable',run_at_ms:0},'stable');
 await f.client.task(id);await f.client.cancel(id);
 assert.deepEqual(f.calls.map(c=>[c.url,c.init.method]),[['https://api.runlater.io/v1/tasks','POST'],['https://api.runlater.io/v1/tasks/'+id,'GET'],['https://api.runlater.io/v1/tasks/'+id+'/cancel','POST']]);
 for(const {url,init} of f.calls){
  const h=init.headers;assert.equal(h.Authorization,undefined);assert.equal(init.redirect,'manual');
  assert.deepEqual(decodeDelegation(h['RunLater-MCP-Delegation']),f.delegation);
  const wire='RunLater signed request v1\n'+JSON.stringify([1,'https://api.runlater.io',f.receipt.project_id,f.receipt.public_key,init.method,new URL(url).pathname,'',hash(init.body??''),h['Idempotency-Key']??'',NOW,NOW+60000,'cd'.repeat(32)]);
  assert.equal(verify(null,Buffer.from(wire),f.gateway.publicKey,Buffer.from(h['RunLater-Request-Signature'],'hex')),true);
  assert.equal(verify(null,Buffer.from(wire),f.owner.publicKey,Buffer.from(h['RunLater-Request-Signature'],'hex')),false);
 }
 assert.equal(f.calls[0].init.body,JSON.stringify({destination:'registered:owned',body:'{"synthetic":true}',operation_key:'stable',run_at_ms:0}));
 assert.equal(f.calls[1].init.body,undefined);assert.equal(f.calls[2].init.body,'{}');
});
test('expired or wrong-scope gateway calls emit no request; no mutable certificate references',async()=>{
 const f=fixture(['read']);f.delegation.permissions.push('enqueue');
 await assert.rejects(f.client.enqueue({endpoint_id:'owned',body:'{}',operation_key:'stable',run_at_ms:0},'stable'),/insufficient_scope/);
 assert.equal(f.calls.length,0);f.expire();await assert.rejects(f.client.task('task_0000000000000001'),/identity_expired/);assert.equal(f.calls.length,0);
 assert.equal(f.client.redrive,undefined);assert.equal(f.client.callbackKey,undefined);assert.equal(f.client.createDestination,undefined);
});
test('strict input rejects credential injection, arbitrary destinations and invalid operation keys',()=>{
 const f=fixture(),input={endpoint_id:'owned',body:'{}',operation_key:'stable',run_at_ms:0};
 for(const value of [{...input,project_id:'other'},{...input,endpoint_id:'https://evil.test'},{...input,body:'x'.repeat(1025)},{...input,operation_key:''},{...input,run_at_ms:-1},{...input,run_at_ms:f.receipt.expires_at_ms+1}])assert.throws(()=>f.client.enqueue(value,'stable'),/invalid_task/);
 assert.throws(()=>f.client.enqueue(input,''),/idempotency_key_required/);assert.throws(()=>f.client.task('../tasks'),/invalid_task/);assert.equal(f.calls.length,0);
});
test('bounded downstream failures do not expose payload/error text and never automatically retry',async()=>{
 const f=fixture();let calls=0;
 for(const response of [()=>Response.json({secret:'DO_NOT_ECHO'}, {status:403}),()=>new Response('DO_NOT_ECHO'),()=>new Response('x'.repeat(32769)),()=>{throw Error('DO_NOT_ECHO');},()=>new Response(null,{status:302,headers:{location:'https://evil.test'}})]){
  const client=new DelegatedPublicBetaClientV1({privateKey:f.gateway.privateKey,delegation:f.delegation,releaseId:f.options.releaseId,clock:()=>NOW,fetchImpl:async()=>{calls++;return response();}});
  await assert.rejects(client.task('task_0000000000000001'),e=>e instanceof PublicBetaClientError&&!String(e).includes('DO_NOT_ECHO'));
 }
 assert.equal(calls,5);
 let timeoutCalls=0;
 const client=new DelegatedPublicBetaClientV1({privateKey:f.gateway.privateKey,delegation:f.delegation,releaseId:f.options.releaseId,clock:()=>NOW,timeoutMs:10,fetchImpl:async()=>{timeoutCalls++;return new Promise(()=>{});}});
 await assert.rejects(client.task('task_0000000000000001'),/transport_uncertain/);assert.equal(timeoutCalls,1);
});

test('published synthetic vector preserves cross-language canonical encodings',()=>{
 const v=JSON.parse(fs.readFileSync(new URL('./delegation-vector.json',import.meta.url),'utf8'));
 assert.equal(delegationBytes(v.delegation).toString(),v.delegation_utf8);
 assert.equal(encodeDelegation(v.delegation),v.delegation_header);
 assert.deepEqual(verifyDelegation(v.delegation,{gatewayPublicKey:v.delegation.gateway_public_key,releaseId:v.delegation.release_id,now:v.now,receipt:v.receipt}),v.delegation);
 const noncanonical=Buffer.from(JSON.stringify({...v.delegation},Object.keys(v.delegation).reverse())).toString('base64url');
 assert.throws(()=>decodeDelegation(noncanonical),PublicBetaClientError);
 const duplicate=Buffer.from(JSON.stringify(v.delegation).replace('{','{\"version\":1,')).toString('base64url');
 assert.throws(()=>decodeDelegation(duplicate),PublicBetaClientError);
});

test('without a receipt, API remains authoritative for scheduling beyond access expiry',async()=>{
 const f=fixture();let called=false;
 const client=new DelegatedPublicBetaClientV1({privateKey:f.gateway.privateKey,delegation:f.delegation,releaseId:f.options.releaseId,clock:()=>NOW,fetchImpl:async()=>{called=true;return Response.json({ok:true});}});
 await client.enqueue({endpoint_id:'owned',body:'{}',operation_key:'stable',run_at_ms:f.delegation.expires_at_ms+1000},'stable');assert.equal(called,true);
});

test('uncertain delegated admission is never retried; explicit recovery preserves key and exact bytes',async()=>{
 const f=fixture(),calls=[];let nonce=0;
 const client=new DelegatedPublicBetaClientV1({privateKey:f.gateway.privateKey,delegation:f.delegation,releaseId:f.options.releaseId,clock:()=>NOW,
  nonce:()=>String(++nonce).padStart(64,'0'),fetchImpl:async(url,init)=>{calls.push({url,init});if(calls.length===1)throw Error('lost response');return Response.json({replayed:true,result:{id:'task_0000000000000001'}});}});
 const input={endpoint_id:'owned',body:'{"synthetic":true}',operation_key:'stable',run_at_ms:0};
 await assert.rejects(client.enqueue(input,'stable'),/transport_uncertain/);assert.equal(calls.length,1);
 const recovered=await client.enqueue(input,'stable');assert.equal(recovered.replayed,true);assert.equal(calls.length,2);
 assert.equal(calls[0].init.body,calls[1].init.body);assert.equal(calls[0].init.headers['Idempotency-Key'],calls[1].init.headers['Idempotency-Key']);
 assert.notEqual(calls[0].init.headers['RunLater-Nonce'],calls[1].init.headers['RunLater-Nonce']);
});

test('authoritative validation signs fixed read-only route for any supported attenuated scope',async()=>{
 for(const permission of ['enqueue','read','cancel']) {
  const f=fixture([permission]);let calls=0;
  const client=new DelegatedPublicBetaClientV1({privateKey:f.gateway.privateKey,delegation:f.delegation,releaseId:f.options.releaseId,clock:()=>NOW,nonce:()=> 'cd'.repeat(32),fetchImpl:async(url,init)=>{
   calls++;assert.equal(url,'https://api.runlater.io/v1/mcp/delegations/validate');assert.equal(init.method,'POST');assert.equal(init.body,'{}');assert.equal(init.redirect,'manual');
   const h=init.headers;assert.equal(h['Idempotency-Key'],undefined);assert.equal(h.Authorization,undefined);assert.deepEqual(decodeDelegation(h['RunLater-MCP-Delegation']),f.delegation);
   const wire='RunLater signed request v1\n'+JSON.stringify([1,'https://api.runlater.io',f.receipt.project_id,f.receipt.public_key,'POST','/v1/mcp/delegations/validate','',hash('{}'),'',NOW,NOW+60000,'cd'.repeat(32)]);
   assert.ok(verify(null,Buffer.from(wire),f.gateway.publicKey,Buffer.from(h['RunLater-Request-Signature'],'hex')));
   return Response.json({active:true,project_id:f.receipt.project_id,expires_at_ms:f.delegation.expires_at_ms,permissions:[permission]});
  }});
  assert.deepEqual(await client.validateDelegation(),{active:true,project_id:f.receipt.project_id,expires_at_ms:f.delegation.expires_at_ms,permissions:[permission]});assert.equal(calls,1);
 }
});
test('authoritative validation rejects inactive, mismatched, expanded, expired or malformed responses',async()=>{
 const f=fixture(['read']),valid={active:true,project_id:f.receipt.project_id,expires_at_ms:f.delegation.expires_at_ms,permissions:['read']};let calls=0;
 for(const response of [null,{}, {...valid,active:false},{...valid,project_id:'p_'+'0'.repeat(60)},{...valid,expires_at_ms:NOW},{...valid,expires_at_ms:f.delegation.expires_at_ms+1},{...valid,permissions:['enqueue','read']},{...valid,permissions:[]},{...valid,permissions:['read','read']},{...valid,extra:'sensitive_marker'}]) {
  const client=new DelegatedPublicBetaClientV1({privateKey:f.gateway.privateKey,delegation:f.delegation,releaseId:f.options.releaseId,clock:()=>NOW,fetchImpl:async()=>{calls++;return Response.json(response);}});
  await assert.rejects(client.validateDelegation(),e=>e instanceof PublicBetaClientError && e.code==='invalid_delegation_response' && !String(e).includes('sensitive_marker'));
 }
 assert.equal(calls,10);
});
test('authoritative validation fails closed without retries on upstream errors and response-time expiry',async()=>{
 const f=fixture();let calls=0;
 for(const reply of [()=>Response.json({secret:'sensitive_marker'},{status:403}),()=>{throw Error('sensitive_marker');},()=>new Response(null,{status:302,headers:{location:'https://evil.test'}})]) {
  const client=new DelegatedPublicBetaClientV1({privateKey:f.gateway.privateKey,delegation:f.delegation,releaseId:f.options.releaseId,clock:()=>NOW,fetchImpl:async()=>{calls++;return reply();}});
  await assert.rejects(client.validateDelegation(),e=>e instanceof PublicBetaClientError&&!String(e).includes('sensitive_marker'));
 }
 assert.equal(calls,3);
 let now=NOW;
 const expired=new DelegatedPublicBetaClientV1({privateKey:f.gateway.privateKey,delegation:f.delegation,releaseId:f.options.releaseId,clock:()=>now,fetchImpl:async()=>{now=f.delegation.expires_at_ms;return Response.json({active:true,project_id:f.receipt.project_id,expires_at_ms:f.delegation.expires_at_ms,permissions:f.delegation.permissions});}});
 await assert.rejects(expired.validateDelegation(),/identity_expired/);
});
