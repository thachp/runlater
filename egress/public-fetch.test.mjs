import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {sha256} from './controller/envelope.mjs';
import {createDispatcher} from './controller/dispatch.mjs';
import {createPublicFetch,destination,enabled,TRANSPORT} from './public-fetch/transport.mjs';
const revision='c'.repeat(64);
async function envelope(url='https://example.com/hook',now=Date.now()){
 const request={url,body:'{}',contentType:'application/json',operationKey:'stable'};
 return {version:1,adapter_revision:revision,release_id:'beta_test',project_id:'p_'+'a'.repeat(60),task_id:'task_'+'b'.repeat(16),fence:1,attempt_started_at_ms:now,deadline_ms:now+29000,target_sha256:await sha256(JSON.stringify({version:1,url,method:'POST',content_type:'application/json'})),request};
}
function storage(){const values=new Map();let chain=Promise.resolve();return {values,async get(k){return values.get(k);},async put(k,v){values.set(k,structuredClone(v));},transaction(fn){const result=chain.then(()=>fn(this));chain=result.catch(()=>{});return result;}};}
const approved={EGRESS_TRANSPORT:TRANSPORT,EGRESS_ENABLED:'operator-approved',EGRESS_REVIEW_REVISION:revision};
test('selection, revision and enablement are all explicit; sender defaults off',async()=>{
 assert.equal(enabled(approved),true);
 for(const change of [{EGRESS_TRANSPORT:undefined},{EGRESS_TRANSPORT:'native'},{EGRESS_ENABLED:'true'},{EGRESS_REVIEW_REVISION:'UNVERIFIED'},{EGRESS_REVIEW_REVISION:'0'.repeat(64)}])assert.equal(enabled({...approved,...change}),false);
 let calls=0;const send=createPublicFetch({fetchImpl:()=>calls++});assert.equal((await send(await envelope())).request_may_have_been_sent,false);assert.equal(calls,0);
});
test('canonical DNS HTTPS only, no IP literals or authority tricks',()=>{
 for(const url of ['http://example.com/','https://127.0.0.1/','https://2130706433/','https://0x7f000001/','https://[::1]/','https://[::ffff:127.0.0.1]/','https://a.local/','https://a.internal/','https://localhost/','https://a.test/','https://EXAMPLE.com/','https://example.com:443/','https://u:p@example.com/','https://example.com/#','https://example.com/\\x','https://example.com/%0d','https://example.com./'])assert.throws(()=>destination(url),url);
 assert.equal(destination('https://hooks.example.com/a?q=1').hostname,'hooks.example.com');
});
test('one fresh narrow POST, no cf settings or credentials, bounded summary only',async()=>{
 let calls=0;const send=createPublicFetch({approved:true,revision,fetchImpl:async r=>{
  calls++;assert.equal(r.url,'https://example.com/hook');assert.equal(r.method,'POST');assert.equal(r.redirect,'manual');assert.equal(r.cf,undefined);
  assert.deepEqual([...r.headers],[['content-type','application/json'],['idempotency-key','stable'],['user-agent','RunLater-Delivery/1']]);assert.equal(await r.text(),'{}');return new Response('PRIVATE');
 }});
 const result=await send(await envelope());assert.equal(calls,1);assert.deepEqual(result,{ok:true,http_status:200,outcome:'http_response',response_bytes:7,request_may_have_been_sent:true,automatic_retry:false});assert.ok(!JSON.stringify(result).includes('PRIVATE'));
});
test('extra fields, revision, payload and target mutations never invoke Fetch',async()=>{
 let calls=0;const send=createPublicFetch({approved:true,revision,fetchImpl:()=>calls++});
 for(const mutate of [e=>e.request.cf={resolveOverride:'internal'},e=>e.request.headers={Cookie:'PRIVATE'},e=>e.request.body='"'+'x'.repeat(1024)+'"',e=>e.request.contentType='text/plain',e=>e.request.url+='changed',e=>e.adapter_revision='d'.repeat(64)]){
  const e=await envelope();mutate(e);assert.equal((await send(e)).request_may_have_been_sent,false);
 }
 assert.equal(calls,0);
});
test('all redirects are summarized and cancelled, never followed or reflected',async()=>{
 for(const status of [300,301,302,303,304,307,308,399]){
  let calls=0,cancels=0;const send=createPublicFetch({approved:true,revision,fetchImpl:async()=>{calls++;return {status,headers:new Headers({Location:'https://127.0.0.1/PRIVATE'}),body:new ReadableStream({cancel(){cancels++;}})};}});
  const r=await send(await envelope());assert.equal(r.outcome,'redirect_rejected');assert.equal(r.response_bytes,0);assert.equal(calls,1);assert.equal(cancels,1);assert.ok(!JSON.stringify(r).includes('PRIVATE'));
 }
});
test('response status/header/byte/chunk bounds cancel and report possible effect',async()=>{
 for(const kind of ['status','headers','bytes','chunks']){
  let cancels=0;const send=createPublicFetch({approved:true,revision,fetchImpl:async()=>({status:kind==='status'?101:200,headers:new Headers(kind==='headers'?{'X-Huge':'x'.repeat(8193)}:{}),body:new ReadableStream({pull(c){if(kind==='bytes')c.enqueue(new Uint8Array(16385));else if(kind==='chunks')c.enqueue(new Uint8Array());},cancel(){cancels++;}})})});
  const r=await send(await envelope());assert.equal(r.ok,false);assert.equal(r.request_may_have_been_sent,true);assert.equal(cancels,1);
 }
});
test('expired/preaborted attempts never Fetch; exception after invocation is possibly sent',async()=>{
 let calls=0;const send=createPublicFetch({approved:true,revision,fetchImpl:()=>{calls++;throw Error('PRIVATE');}});
 const abort=new AbortController();abort.abort();assert.equal((await send(await envelope(),{signal:abort.signal})).request_may_have_been_sent,false);
 assert.equal((await send(await envelope(undefined,Date.now()-30000))).request_may_have_been_sent,false);
 assert.equal((await send(await envelope())).request_may_have_been_sent,true);assert.equal(calls,1);
});
test('abort/reset after Fetch reserves receipt and suppresses redispatch, including expired replay',async()=>{
 const s=storage(),e=await envelope();let calls=0,entered;const started=new Promise(r=>entered=r);const abort=new AbortController();
 const make=()=>createDispatcher({storage:s,enabled:true,revision,send:createPublicFetch({approved:true,revision,fetchImpl:()=>{calls++;entered();return new Promise(()=>{});}})});
 const pending=make()(e,{signal:abort.signal});await started;abort.abort();assert.equal((await pending).error,'attempt_uncertain');assert.equal((await make()(e)).error,'attempt_uncertain');
 const replay=createDispatcher({storage:s,enabled:true,revision,now:()=>e.deadline_ms+1,send:()=>calls++});assert.equal((await replay(e)).error,'attempt_uncertain');assert.equal(calls,1);
});
test('stalled stream and late response are cancelled after abort without awaiting hostile cancel',async()=>{
 for(const late of [false,true]){
  let entered,resolveFetch,cancels=0;const started=new Promise(r=>entered=r);const abort=new AbortController();
  const response=new Response(new ReadableStream({pull(){return new Promise(()=>{});},cancel(){cancels++;return new Promise(()=>{});}}));
  const send=createPublicFetch({approved:true,revision,fetchImpl:()=>{entered();return late?new Promise(r=>resolveFetch=r):response;}});
  const pending=send(await envelope(),{signal:abort.signal});await started;await new Promise(r=>setImmediate(r));abort.abort();assert.equal((await pending).request_may_have_been_sent,true);
  if(late)resolveFetch(response);await new Promise(r=>setImmediate(r));assert.equal(cancels,1);
 }
});
test('absolute near deadline bounds unresponsive Fetch and does not retry',async()=>{
 let calls=0;const send=createPublicFetch({approved:true,revision,fetchImpl:()=>{calls++;return new Promise(()=>{});}});
 const r=await send(await envelope(undefined,Date.now()-28950));assert.equal(r.request_may_have_been_sent,true);assert.equal(calls,1);
});
// Offline Worker class shim only: these tests prove routing/wiring, not Cloudflare network policy.
async function worker(){
 const url=new URL('./public-fetch/worker.mjs',import.meta.url);
 let source=await readFile(url,'utf8');source=source.replace("import {DurableObject,WorkerEntrypoint} from 'cloudflare:workers';","class WorkerEntrypoint {constructor(ctx,env){this.ctx=ctx;this.env=env;}};class DurableObject extends WorkerEntrypoint {};");
 source=source.replace(/from '([^']+)'/g,(_,path)=>`from '${new URL(path,url).href}'`);
 return import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
}
test('private binding gates and singleton routing; default internet handler never dispatches',async()=>{
 const w=await worker();let calls=0;
 const env={...approved,PUBLIC_FETCH_RECEIPTS:{getByName(name){assert.equal(name,'runlater-public-fetch-v1');return {fetch(){calls++;return Response.json({ready:true});}};}}};
 const binding=new w.PublicFetchBinding({},env);
 for(const url of ['https://example.com/dispatch','https://egress.internal/dispatch?x','https://egress.internal/nope'])assert.equal((await binding.fetch(new Request(url,{method:'POST'}))).status,404);
 assert.equal((await w.default.fetch(new Request('https://egress.internal/dispatch',{method:'POST'}))).status,404);
 assert.equal((await binding.fetch(new Request('https://egress.internal/ready'))).status,200);assert.equal(calls,1);
 const off=new w.PublicFetchBinding({},{});assert.equal((await off.fetch(new Request('https://egress.internal/ready'))).status,503);
 const ctx={storage:storage()};const receipts=new w.PublicFetchReceipts(ctx,{});assert.equal((await (await receipts.fetch(new Request('https://egress.internal/ready'))).json()).ready,false);
 assert.equal((await receipts.fetch(new Request('https://egress.internal/dispatch',{method:'POST'}))).status,503);assert.equal(ctx.storage.values.size,0);
});
test('example remains private, default off, strict public routing, signal enabled, no native fallback',async()=>{
 const config=JSON.parse(await readFile(new URL('./public-fetch/wrangler.example.jsonc',import.meta.url),'utf8'));
 assert.deepEqual(config.compatibility_flags,['global_fetch_strictly_public','enable_request_signal']);assert.equal(config.vars.EGRESS_ENABLED,'false');assert.equal(config.vars.EGRESS_REVIEW_REVISION,'UNVERIFIED');assert.equal(config.workers_dev,false);assert.equal(config.preview_urls,false);assert.deepEqual(config.routes,[]);assert.equal(config.containers,undefined);assert.equal(config.services,undefined);
});
