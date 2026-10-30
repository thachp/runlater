// Synthetic offline input, signing and official SDK tests. No public calls or projects.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,verify} from 'node:crypto';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {SSEClientTransport} from '@modelcontextprotocol/sdk/client/sse.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {httpTaskInput} from './http-task.mjs';
import {httpToolHandler} from './http-tools.mjs';
import {createTrialAuthority} from './oauth-trial.mjs';
import {AnonymousTrialClientV1} from './trial-client.mjs';
import {PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
import {MCP_RESOURCE,normalizedAuthRequest,ownerTaskAuthorizationUrl} from './oauth-consent.mjs';
import {authorizeOwner} from './oauth-app.mjs';
import {createHostedProtocol,MCP_ORIGIN} from './hosted-protocol.mjs';
const now=1800000000000, hash=x=>createHash('sha256').update(x).digest('hex');
const input={url:'https://customer.example/event?type=reminder',payload:{message:'hello'},run_at_ms:now+1000,operation_key:'stable-op'};
const args={...input,idempotency_key:'stable-admission'};
const task={task_accepted:true,replayed:false,result:{id:'task_0000000000000001',status:'scheduled',due_ms:input.run_at_ms,attempts:[]}};
function fixture(scopes=['cancel','http_schedule','read']) {
 const {props}=createTrialAuthority({releaseId:'offline_http',clientId:'fixture',scopes,now});
 const gateway=generateKeyPairSync('ed25519'),calls=[];
 const options={privateKey:gateway.privateKey,descriptor:props.descriptor,capability:props.capability,releaseId:'offline_http',clock:()=>now,nonce:()=> 'c'.repeat(64),fetchImpl:async(url,init)=>{calls.push({url,init});return Response.json(task);}};
 return {props,gateway,calls,options,client:new AnonymousTrialClientV1(options)};
}
test('HTTP inputs are exact bounded canonical JSON and HTTPS, not private auth or receiver configuration',()=>{
 assert.deepEqual(httpTaskInput(input),input);const clone=httpTaskInput(input);assert.notEqual(clone.payload,input.payload);
 const urls=['http://customer.example/','https://127.0.0.1/','https://[::1]/','https://localhost/','https://service.internal/','https://a.test/',
  'https://user:pass@customer.example/','https://customer.example:443/','https://customer.example/#fragment','https://customer.example/#','https://customer.example/%0Aheader',
  'https://CUSTOMER.example/','https://customer.example','https://customer.example./','https://customer.example:8443/','https://a..example/'];
 for(const url of urls) assert.throws(()=>httpTaskInput({...input,url}),/invalid_http_task/,url);
 for(const change of [{headers:{Authorization:'SECRET'}},{auth:'SECRET'},{callback_url:'https://callback.example/'},{endpoint_id:'receiver'},
  {payload:'x'.repeat(1023)},{payload:NaN},{payload:undefined},{payload:new Date()},{payload:{x:()=>0}},
  {run_at_ms:-1},{run_at_ms:now+2000},{operation_key:'spaces forbidden'}])
  assert.throws(()=>httpTaskInput({...input,...change},{expiresAt:now+1000}),/invalid_http_task/);
 const cyclic={};cyclic.x=cyclic;assert.throws(()=>httpTaskInput({...input,payload:cyclic}),/invalid_http_task/);
 assert.deepEqual(httpTaskInput({...input,payload:null}).payload,null);
});
test('dedicated scope signs original HTTP path/body with stable idempotency, no receiver lookup or bearer forwarding',async()=>{
 const f=fixture();await f.client.scheduleHttp(input,args.idempotency_key);assert.equal(f.calls.length,1);
 const {url,init}=f.calls[0],h=init.headers,d=f.props.descriptor;
 assert.equal(url,'https://api.runlater.io/v1/http/tasks');assert.equal(init.body,JSON.stringify(input));assert.equal(init.redirect,'manual');
 assert.equal(h.Authorization,undefined);assert.equal(h['Idempotency-Key'],args.idempotency_key);
 const wire='RunLater anonymous trial request v1\n'+JSON.stringify([1,'https://api.runlater.io',d.release_id,f.props.projectId,
  d.bootstrap_id,d.capability_hash,hash(JSON.stringify(d)),'POST','/v1/http/tasks','',hash(init.body),args.idempotency_key,now,now+60000,'c'.repeat(64)]);
 assert.ok(verify(null,Buffer.from(wire),f.gateway.publicKey,Buffer.from(h['RunLater-Request-Signature'],'hex')));
 const old=fixture(['cancel','enqueue','read']);await assert.rejects(old.client.scheduleHttp(input,args.idempotency_key),/insufficient_scope/);assert.equal(old.calls.length,0);
 assert.throws(()=>f.client.scheduleHttp(input,''),/idempotency_key_required/);
});
test('only exact API no-admission evidence is certain; malformed/error/timeout is redacted and never retried',async()=>{
 const f=fixture();const replies=[{body:{error:{code:'general_https_unavailable'},task_accepted:false},certain:true},
  {body:{error:{code:'general_https_unavailable'},task_accepted:true}},
  {body:{error:{code:'general_https_unavailable',detail:'SECRET'}},task_accepted:false},
  {body:{error:{code:'other'},task_accepted:false}},{body:'SECRET'},{body:'x'.repeat(1100)}];
 for(const entry of replies){let count=0;const client=new AnonymousTrialClientV1({...f.options,fetchImpl:async()=>{count++;return Response.json(entry.body,{status:503});}});
  const call=httpToolHandler({client,enabled:true,allowedScopes:['http_schedule'],next:()=>{throw Error('unreachable');}});
  const result=await call('schedule_http_request',args,true);assert.equal(count,1);
  assert.equal(result.structuredContent.task_acceptance,entry.certain?'not_attempted':'unknown');assert.ok(!JSON.stringify(result).includes('SECRET'));
 }
 let count=0;const lost=new AnonymousTrialClientV1({...f.options,fetchImpl:async()=>{count++;throw Error('SECRET');}});
 await assert.rejects(lost.scheduleHttp(input,args.idempotency_key),e=>e.code==='transport_uncertain'&&!String(e).includes('SECRET'));assert.equal(count,1);
 const slow=new AnonymousTrialClientV1({...f.options,timeoutMs:10,fetchImpl:async()=>new Response(new ReadableStream({start(){}}),{status:503})});
 await assert.rejects(slow.scheduleHttp(input,args.idempotency_key),e=>e.code==='transport_uncertain');
});
test('tool is separate opt-in, does not require a receiver and allowlists returned admission data',async()=>{
 let calls=0;const client={scheduleHttp:async()=>{calls++;return {...task,url:input.url,secret:'SECRET',result:{...task.result,payload:'SECRET',destination:input.url}};},status:()=>{throw Error('receiver lookup forbidden');}};
 for(const options of [{},{enabled:true},{enabled:true,allowedScopes:['enqueue']}]){
  const r=await httpToolHandler({client,next:()=>{},...options})('schedule_http_request',args,true);assert.equal(r.isError,true);
 }assert.equal(calls,0);
 const call=httpToolHandler({client,next:()=>{},enabled:true,allowedScopes:['http_schedule','read']});
 assert.equal((await call('schedule_http_request',{...args,headers:{}},true)).structuredContent.task_acceptance,'not_attempted');assert.equal(calls,0);
 const r=await call('schedule_http_request',args,true);assert.equal(r.structuredContent.receiver_required,false);assert.equal(r.structuredContent.task_accepted,true);assert.equal(calls,1);
 assert.ok(!JSON.stringify(r).includes('SECRET'));assert.ok(!JSON.stringify(r).includes(input.url));
});
const auth={responseType:'code',clientId:'https://client.example/metadata',redirectUri:'https://client.example/callback',scope:['cancel','http_schedule','read'],state:'state',codeChallenge:'a'.repeat(43),codeChallengeMethod:'S256',resource:MCP_RESOURCE,issuer:MCP_RESOURCE};
test('general HTTP consent is separately enabled and no owner grant can silently gain trial HTTP authority',async()=>{
 assert.throws(()=>normalizedAuthRequest({...auth,redirectUri:auth.redirectUri+'#'},{generalHttpEnabled:true}));
 assert.throws(()=>normalizedAuthRequest(auth));assert.throws(()=>normalizedAuthRequest(auth,{receiverPairingEnabled:true}));
 assert.deepEqual(normalizedAuthRequest(auth,{generalHttpEnabled:true}).scope,auth.scope);
 const owner=new URL(ownerTaskAuthorizationUrl(auth));assert.equal(owner.searchParams.get('scope'),'cancel read');assert.equal(owner.searchParams.get('state'),auth.state);
 assert.equal(ownerTaskAuthorizationUrl({...auth,scope:['http_schedule']}),null);
 let begins=0;const oauth={parseAuthRequest:async()=>auth,describeConsent:async()=>({clientName:'Fixture',clientDomain:null,redirectIsLoopback:false}),beginConsent:async()=>{begins++;return {handle:'h'.repeat(43),headers:{}};}};
 const config={trialEnabled:true,generalHttpEnabled:true,releaseId:'offline_http',gatewayPublicKey:'a'.repeat(64)};
 const r=await authorizeOwner(new Request(MCP_RESOURCE+'/authorize'),oauth,config),html=await r.text();assert.equal(r.status,200);assert.match(html,/public HTTPS/);assert.match(html,/does not require a RunLater receiver/);assert.doesNotMatch(html,/Signed approval JSON|Public challenge<textarea/);assert.equal(begins,1);
 assert.equal((await authorizeOwner(new Request(MCP_RESOURCE+'/authorize'),oauth,{...config,generalHttpEnabled:false})).status,400);assert.equal(begins,1);
});
for(const lane of ['sse','mcp'])test(`official SDK ${lane}: general scheduling has dedicated authority, no discovery allocation or receiver dependency`,async t=>{
 const f=fixture(),p={kind:'trial',trial:{descriptor:f.props.descriptor,capability:f.props.capability},scopes:['cancel','http_schedule','read'],tokenHash:'a'.repeat(64),expiresAt:now+60000};let calls=0;
 const server=createHostedProtocol({setup:'# Source-only general HTTPS',generalHttpEnabled:true,clock:()=>now,makeClient:()=>({scheduleHttp:async()=>{calls++;return task;},status:()=>{throw Error('receiver dependency');}})});t.after(()=>server.close());
 const client=new Client({name:'offline-general-http',version:'1'});t.after(()=>client.close());
 const localFetch=(url,init)=>server.handle(new Request(url,init),p);
 await client.connect(lane==='sse'?new SSEClientTransport(new URL(MCP_ORIGIN+'/sse'),{fetch:localFetch}):new StreamableHTTPClientTransport(new URL(MCP_ORIGIN+'/mcp'),{fetch:localFetch}));
 assert.ok((await client.listTools()).tools.some(t=>t.name==='schedule_http_request'));const service=JSON.parse((await client.readResource({uri:'runlater://service'})).contents[0].text);assert.match(service.onboarding,/No special receiver/);assert.equal(calls,0);
 const r=await client.callTool({name:'schedule_http_request',arguments:args});assert.equal(r.structuredContent.receiver_required,false);assert.equal(calls,1);
 const reduced={...p,scopes:['read']};const denied=await server.handle(new Request(MCP_ORIGIN+'/mcp',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:9,method:'tools/call',params:{name:'schedule_http_request',arguments:args}})}),reduced);
 assert.equal(denied.status,403);assert.match(denied.headers.get('www-authenticate'),/scope="http_schedule"/);assert.equal(calls,1);
});
