// Actual loopback TLS/HTTP integration with ephemeral local certificates. No external traffic.
// TEST ONLY: translate selected public IP to loopback and report a synthetic public peer.
// This proves TLS name/CA gating and Node HTTP behavior, NOT provider public-IP enforcement.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import https from 'node:https';
import tls from 'node:tls';
import {createNativeTransport} from './native-transport.mjs';
import {createNativeEgress} from './index.mjs';
test('native TLS validates original hostname and CA before sending private headers/body',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-egress-tls-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const key=path.join(dir,'key.pem'),cert=path.join(dir,'cert.pem');
 // Test-only fixture input lets minimal runtime images omit the OpenSSL CLI.
 // Copy into our owned temporary directory; never chmod/delete the mounted source.
 const fixtureDir=process.env.RUNLATER_NATIVE_TLS_FIXTURE_DIR;
 if(fixtureDir){
  assert.ok(path.isAbsolute(fixtureDir),'TLS fixture directory must be absolute');
  fs.copyFileSync(path.join(fixtureDir,'key.pem'),key,fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(path.join(fixtureDir,'cert.pem'),cert,fs.constants.COPYFILE_EXCL);
 }else{
  const generated=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=example.com','-addext','subjectAltName=DNS:example.com'],{stdio:'ignore'});assert.equal(generated.status,0);
 }
 fs.chmodSync(key,0o600);const ca=fs.readFileSync(cert);let requests=0;
 const server=https.createServer({key:fs.readFileSync(key),cert:ca},(req,res)=>{
  requests++;assert.equal(req.headers.host,'example.com');assert.equal(req.headers.authorization,'PRIVATE_AUTH');let body='';req.on('data',c=>body+=c);req.on('end',()=>{assert.equal(body,'{}');res.writeHead(204);res.end();});
 });server.on('tlsClientError',()=>{});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
 const port=server.address().port;
 const transport=({trust=true}={})=>createNativeTransport({connect:options=>{
  assert.equal(options.host,'1.1.1.1');assert.equal(options.port,443);assert.equal(options.rejectUnauthorized,true);
  const socket=tls.connect({...options,host:'127.0.0.1',port,...(trust?{ca}:{})});
  Object.defineProperty(socket,'remoteAddress',{get:()=> '1.1.1.1'});Object.defineProperty(socket,'remotePort',{get:()=>443});return socket;
 }});
 const resolverFactory=()=>({resolveCname:async()=>[],resolve4:async()=>['1.1.1.1'],resolve6:async()=>[],cancel(){}});
 const input={url:'https://example.com/hook?PRIVATE_URL',body:'{}',contentType:'application/json',operationKey:'stable',privateHeaders:{Authorization:'PRIVATE_AUTH'}};
 const good=await createNativeEgress({enabled:true,resolverFactory,transport:transport()}).deliver(input);assert.equal(good.http_status,204);assert.equal(requests,1);
 const wrong=await createNativeEgress({enabled:true,resolverFactory,transport:transport()}).deliver({...input,url:'https://attacker.example/hook'});assert.equal(wrong.ok,false);assert.equal(wrong.request_may_have_been_sent,false);assert.equal(requests,1);
 const untrusted=await createNativeEgress({enabled:true,resolverFactory,transport:transport({trust:false})}).deliver(input);assert.equal(untrusted.ok,false);assert.equal(untrusted.request_may_have_been_sent,false);assert.equal(requests,1);
 for(const result of [good,wrong,untrusted])assert.doesNotMatch(JSON.stringify(result),/PRIVATE|certificate|example/);
});
