import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {createOwnerApproval,reviewChallenge,parseApprovalArgs,runOwnerApproval} from '../examples/mcp-authorize.mjs';
import {delegationPublicKey} from './delegation.mjs';
import {verifyOwnerApproval} from './oauth-consent.mjs';
import {PUBLIC_BETA_TERMS} from '../examples/public-beta-client.v1.mjs';
const hash=s=>createHash('sha256').update(s).digest('hex');
function fixture(){
 const key=generateKeyPairSync('ed25519').privateKey,gateway=generateKeyPairSync('ed25519').privateKey;
 const now=Date.now(),publicKey=delegationPublicKey(key),gatewayPublicKey=delegationPublicKey(gateway),releaseId='offline_mcp_delegation';
 const ticket=hash(JSON.stringify(['runlater.public-beta.registration.v1',releaseId,publicKey]));
 const receipt={ticket_id:ticket,project_id:'p_'+ticket.slice(0,60),public_key:publicKey,grant_id:'g_'+ticket.slice(0,60),enrolled_at_ms:now-1000,expires_at_ms:now-1000+604800000,attempt_units:100,permissions:[...PUBLIC_BETA_TERMS.permissions]};
 const challenge={version:1,origin:'https://mcp.runlater.io',handle:'opaque_browser_bound_handle',request:{responseType:'code',clientId:'registered-test-client',redirectUri:'https://client.example/callback',scope:['enqueue','read'],state:'client_state',codeChallenge:'a'.repeat(43),codeChallengeMethod:'S256',resource:'https://mcp.runlater.io',issuer:'https://mcp.runlater.io'},release_id:releaseId,gateway_public_key:gatewayPublicKey};
 return {privateKey:key,receipt,challenge,releaseId,gatewayPublicKey,now};
}
test('offline owner approval binds OAuth client, callback, state, PKCE, resource, handle and cert',()=>{
 const f=fixture(),approval=createOwnerApproval(f);assert.equal(verifyOwnerApproval(approval,f.challenge,{...f,now:f.now}).project_id,f.receipt.project_id);
 for(const request of [{...f.challenge.request,clientId:'other'},{...f.challenge.request,redirectUri:'https://other.example/callback'},{...f.challenge.request,state:'other'},{...f.challenge.request,codeChallenge:'b'.repeat(43)},{...f.challenge.request,scope:['read']},{...f.challenge.request,resource:'https://evil.test'}])assert.throws(()=>verifyOwnerApproval(approval,{...f.challenge,request},f));
 assert.throws(()=>verifyOwnerApproval(approval,{...f.challenge,handle:'another_browser_bound_handle'},f));
 assert.throws(()=>reviewChallenge(f.challenge,{...f,gatewayPublicKey:'00'.repeat(32)}));
 assert.throws(()=>reviewChallenge(f.challenge,{...f,releaseId:'other'}));
 assert.equal(JSON.stringify(approval).includes('PRIVATE KEY'),false);
});
test('CLI requires explicit approve, rejects unknown/duplicate options, never signs during review',()=>{
 const f=fixture(),root=fs.mkdtempSync(path.join(os.tmpdir(),'mcp-approval-'));
 try{
  const challenge=path.join(root,'challenge.json');fs.writeFileSync(challenge,JSON.stringify(f.challenge),{mode:0o600});
  const argv=['--challenge',challenge,'--release-id',f.releaseId,'--gateway-public-key',f.gatewayPublicKey];
  const messages=[];runOwnerApproval([...argv,'--key','/does/not/exist'],{print:s=>messages.push(s)});
  assert.match(messages.at(-1),/Review only/);assert.deepEqual(fs.readdirSync(root),['challenge.json']);
  for(const extra of [['--approve'],['--bad'],['--challenge',challenge],['--approve','--approve']])assert.throws(()=>parseApprovalArgs([...argv,...extra]));
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});
test('approved CLI writes exclusive 0600 output, rejects unsafe files, and prints no signatures or key',()=>{
 const f=fixture(),root=fs.mkdtempSync(path.join(os.tmpdir(),'mcp-approval-'));
 try{
  const names=Object.fromEntries(['challenge','key','receipt','out'].map(k=>[k,path.join(root,k)]));
  fs.writeFileSync(names.challenge,JSON.stringify(f.challenge),{mode:0o600});fs.writeFileSync(names.key,f.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600});fs.writeFileSync(names.receipt,JSON.stringify(f.receipt),{mode:0o600});
  const argv=['--challenge',names.challenge,'--release-id',f.releaseId,'--gateway-public-key',f.gatewayPublicKey,'--key',names.key,'--receipt',names.receipt,'--out',names.out,'--approve'];
  const messages=[];runOwnerApproval(argv,{print:s=>messages.push(s)});
  const approval=JSON.parse(fs.readFileSync(names.out,'utf8'));assert.equal(fs.statSync(names.out).mode&0o777,0o600);
  verifyOwnerApproval(approval,f.challenge,{...f,now:Date.now()});
  assert.ok(!messages.join().includes(approval.consent_signature));assert.ok(!messages.join().includes(approval.delegation.signature));assert.ok(!messages.join().includes('PRIVATE KEY'));
  assert.throws(()=>runOwnerApproval(argv,{print:()=>{}}));
  fs.unlinkSync(names.out);fs.chmodSync(names.key,0o644);assert.throws(()=>runOwnerApproval(argv,{print:()=>{}}));assert.equal(fs.existsSync(names.out),false);
 }finally{fs.rmSync(root,{recursive:true,force:true});}
});


test('standalone help prints safe usage without reading files or signing', () => {
 const output=[]; runOwnerApproval(['--help'],{print:s=>output.push(s)});
 assert.match(output.join(' '), /Review:/); assert.match(output.join(' '), /never sends HTTP/);
});
