import test from 'node:test';
import assert from 'node:assert/strict';
import {createPrivateKey,createPublicKey,verify,createHash} from 'node:crypto';
import fs from 'node:fs';
import {revokeAllDelegations,parseRevokeArgs,runOwnerRevoke} from '../examples/mcp-revoke.mjs';
const v=JSON.parse(fs.readFileSync(new URL('./delegation-vector.json',import.meta.url),'utf8'));
// Public offline fixture seed: never enroll or deploy this key.
const privateKey=createPrivateKey({key:Buffer.from('302e020100300506032b657004220420'+'11'.repeat(32),'hex'),format:'der',type:'pkcs8'});
const opts={privateKey,receipt:v.receipt,releaseId:v.delegation.release_id,idempotencyKey:'revoke_stable',clock:()=>v.now,nonce:()=> 'ef'.repeat(32)};
test('owner revoke-all uses the fixed route and owner signature, not gateway/MCP authorization',async()=>{
 let count=0;const result=await revokeAllDelegations({...opts,fetchImpl:async(url,init)=>{
  count++;assert.equal(url,'https://api.runlater.io/v1/mcp/delegations/revoke');assert.equal(init.method,'POST');assert.equal(init.body,'{}');assert.equal(init.redirect,'manual');
  const h=init.headers;assert.equal(h.Authorization,undefined);assert.equal(h['RunLater-MCP-Delegation'],undefined);assert.equal(h['Idempotency-Key'],'revoke_stable');
  const wire='RunLater signed request v1\n'+JSON.stringify([1,'https://api.runlater.io',v.receipt.project_id,v.receipt.public_key,'POST','/v1/mcp/delegations/revoke','',createHash('sha256').update('{}').digest('hex'),'revoke_stable',v.now,v.now+60000,'ef'.repeat(32)]);
  assert.ok(verify(null,Buffer.from(wire),createPublicKey(privateKey),Buffer.from(h['RunLater-Request-Signature'],'hex')));
  return Response.json({revoked_before_ms:v.now,replayed:false});
 }});assert.deepEqual(result,{revoked_before_ms:v.now,replayed:false});assert.equal(count,1);
});
test('revocation dry run has zero file/network effects and stable key is mandatory',async()=>{
 let calls=0;const print=[];await runOwnerRevoke(['--key','/missing'],{print:s=>print.push(s),fetchImpl:async()=>{calls++;}});assert.equal(calls,0);assert.match(print[0],/Dry run/);
 assert.throws(()=>parseRevokeArgs(['--revoke-all']));assert.throws(()=>parseRevokeArgs(['--unknown']));
 await assert.rejects(revokeAllDelegations({...opts,idempotencyKey:'',fetchImpl:async()=>{calls++;}}),/idempotency_key_required/);assert.equal(calls,0);
});
test('failed/lost/malformed revocation has no retry and no raw response leakage',async()=>{
 let calls=0;for(const reply of [()=>{throw Error('secret_marker');},()=>Response.json({revoked_before_ms:v.now,replayed:false,secret:'secret_marker'}),()=>Response.json({secret:'secret_marker'},{status:403}),()=>new Response('secret_marker'),()=>new Response('x'.repeat(4097))]){
  await assert.rejects(revokeAllDelegations({...opts,fetchImpl:async()=>{calls++;return reply();}}),e=>!String(e).includes('secret_marker'));
 }assert.equal(calls,5);
});
