import test from 'node:test';
import assert from 'node:assert/strict';
import {sha256,validateEnvelope,canonicalEnvelope} from './controller/envelope.mjs';
import {createDispatcher,RECEIPT_LIMIT} from './controller/dispatch.mjs';
import {createIngress} from './controller/listener.mjs';
const good={ok:true,http_status:204,outcome:'http_response',response_bytes:0,request_may_have_been_sent:true,automatic_retry:false};
async function envelope(now=Date.now()){
 const request={url:'https://example.com/hook?PRIVATE',body:'{}',contentType:'application/json',operationKey:'stable'};
 return {version:1,adapter_revision:'c'.repeat(64),release_id:'beta_test',project_id:'p_'+'a'.repeat(60),task_id:'task_'+'b'.repeat(16),fence:1,attempt_started_at_ms:now,deadline_ms:now+29000,target_sha256:await sha256(JSON.stringify({version:1,url:request.url,method:'POST',content_type:'application/json'})),request};
}
function storage(){const values=new Map();let chain=Promise.resolve();return {values,async get(k){return values.get(k);},async put(k,v){values.set(k,structuredClone(v));},transaction(fn){const result=chain.then(()=>fn(this));chain=result.catch(()=>{});return result;}};}
test('exact envelope validates digest and IDs; rejects authority/header expansion and lease changes',async()=>{
 const e=await envelope();assert.equal((await validateEnvelope(e)).hash,await sha256(canonicalEnvelope(e)));
 for(const mutation of [v=>v.request.privateHeaders={},v=>v.request.url+='changed',v=>v.fence=0,v=>v.deadline_ms++,v=>v.release_id='x'.repeat(33),v=>v.project_id='p_bad',v=>v.request.contentType='text/plain',v=>v.request.body='not JSON']){const bad=structuredClone(e);mutation(bad);await assert.rejects(validateEnvelope(bad));}
});
test('default-off dispatcher does not write state or send',async()=>{const s=storage();let sends=0;const d=createDispatcher({storage:s,send:()=>sends++});assert.equal((await d(await envelope())).error,'egress_disabled');assert.equal(s.values.size,0);assert.equal(sends,0);});
test('durable receipt precedes send; completed exact duplicate cached and mutation rejected',async()=>{
 const s=storage();let sends=0;const e=await envelope();const d=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,send:async()=>{sends++;assert.equal([...s.values.values()].find(x=>x?.state)?.state,'reserved');return good;}});
 assert.deepEqual(await d(e),good);assert.deepEqual(await d(e),good);assert.equal(sends,1);
 const changed=structuredClone(e);changed.request.body='{"different":1}';assert.equal((await d(changed)).error,'attempt_uncertain');assert.equal(sends,1);
});
test('concurrent and restarted reserved attempt cannot resend; capacity never evicts',async()=>{
 const s=storage();let sends=0,release;const pending=new Promise(r=>release=r);const e=await envelope();
 const d=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,send:async()=>{sends++;return pending;}});const first=d(e);
 while(sends===0)await new Promise(r=>setImmediate(r));assert.equal((await d(e)).error,'attempt_uncertain');
 const restarted=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,send:async()=>{sends++;return good;}});assert.equal((await restarted(e)).error,'attempt_uncertain');release(good);await first;assert.equal(sends,1);
 await s.put('receipt_count',RECEIPT_LIMIT);const fresh=await envelope();fresh.fence=2;assert.equal((await restarted(fresh)).error,'receipt_capacity');assert.equal(sends,1);
});
test('cold-start expired or aborted dispatch stays reserved/uncertain and no replay',async()=>{
 let now=100000;const e=await envelope(now),s=storage();let sends=0;
 const d=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,now:()=>now,send:async()=>{sends++;now=e.deadline_ms;return good;}});
 assert.equal((await d(e)).error,'attempt_uncertain');assert.equal(sends,1);now=e.attempt_started_at_ms+1;assert.equal((await d(e)).error,'attempt_uncertain');
 const controller=new AbortController();controller.abort();const fresh=await envelope(now);fresh.fence=2;assert.equal((await d(fresh,{signal:controller.signal})).error,'dispatch_rejected');assert.equal(sends,1);
});
test('native ingress accepts only narrow private envelope and forwards absolute deadline/cancellation',async()=>{
 let calls=0;const e=await envelope();const server=createIngress({enabled:true,revision:'c'.repeat(64),adapter:{async deliver(request,options){calls++;assert.equal(options.deadlineMs,e.deadline_ms);assert.equal(request.contentType,'application/json');assert.ok(options.signal instanceof AbortSignal);return good;}}});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const base='http://127.0.0.1:'+server.address().port;
 try{
  assert.equal((await fetch(base+'/wrong')).status,404);
  const send=v=>fetch(base+'/dispatch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(v)});
  const bad=structuredClone(e);bad.request.privateHeaders={Authorization:'PRIVATE'};assert.equal((await send(bad)).status,400);assert.equal(calls,0);
  assert.deepEqual(await (await send(e)).json(),good);assert.equal(calls,1);
 }finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});
test('stream reader bounds empty chunks and aborts stalled reads without awaiting cancellation',async()=>{
 const {readLimited}=await import('./controller/envelope.mjs');
 const empty=new ReadableStream({pull(c){c.enqueue(new Uint8Array());}});
 await assert.rejects(readLimited(empty,{maxBytes:10,maxChunks:4}));
 const controller=new AbortController();const stalled=new ReadableStream({pull(){return new Promise(()=>{});},cancel(){return new Promise(()=>{});}});
 const pending=readLimited(stalled,{signal:controller.signal,maxBytes:10});controller.abort();await assert.rejects(pending);
});
test('unresponsive send cannot hold dispatcher capacity past absolute lease',async()=>{
 const s=storage();const e=await envelope(Date.now()-28950);let calls=0;
 const d=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,send:()=>{calls++;return new Promise(()=>{});}});
 const result=await d(e);assert.equal(result.error,'attempt_uncertain');assert.equal(calls,1);
 const reserved=[...s.values.values()].find(v=>v?.state);assert.equal(reserved.state,'reserved');
});
test('expired native absolute lease never invokes DNS or opens a socket',async()=>{
 const {createNativeEgress}=await import('./index.mjs');let dns=0;
 const adapter=createNativeEgress({enabled:true,resolverFactory(){dns++;throw Error();}});
 const e=await envelope();const result=await adapter.deliver(e.request,{deadlineMs:Date.now()-1});assert.equal(result.request_may_have_been_sent,false);assert.equal(dns,0);
});

test('malformed attempted/retry fields after send stay uncertain and never cache unsent',async()=>{
 for(const bad of [{ok:false},{ok:false,error:'delivery_rejected_or_failed',request_may_have_been_sent:'false',automatic_retry:false},{...good,automatic_retry:true},{...good,unexpected:'PRIVATE'}]){
  const s=storage(),e=await envelope();let calls=0;const d=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,send:async()=>{calls++;return bad;}});
  assert.equal((await d(e)).error,'attempt_uncertain');assert.equal((await d(e)).error,'attempt_uncertain');assert.equal(calls,1);assert.equal([...s.values.values()].find(v=>v?.state).state,'reserved');
 }
});
test('durable global and hostname limits survive restart, reject clock regression, no rate-denied receipt',async()=>{
 let now=100000;const s=storage();let sends=0;
 const make=()=>createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,now:()=>now,send:async()=>{sends++;return good;}});
 let e=await envelope(now);assert.equal((await make()(e)).ok,true);
 now+=500;let next=await envelope(now);next.fence=2;assert.equal((await make()(next)).error,'rate_limited');assert.equal(await s.get('receipt_count'),1);
 now+=1000;next=await envelope(now);next.fence=3;assert.equal((await make()(next)).error,'rate_limited');
 now=99999;next=await envelope(now);next.fence=4;assert.equal((await make()(next)).error,'rate_limited');
 now=110000;next=await envelope(now);next.fence=5;assert.equal((await make()(next)).ok,true);assert.equal(sends,2);
});
test('hostname map cannot evict/reset and uncertain concurrent hostname remains blocked',async()=>{
 let now=100000;const s=storage();await s.put('host_count',1024);let sends=0;
 const d=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,now:()=>now,send:async()=>{sends++;throw Error();}});
 assert.equal((await d(await envelope(now))).error,'rate_limited');assert.equal(sends,0);assert.equal(await s.get('receipt_count'),undefined);
 await s.put('host_count',0);const e=await envelope(now);assert.equal((await d(e)).error,'attempt_uncertain');
 now+=11000;const next=await envelope(now);next.fence=2;assert.equal((await d(next)).error,'rate_limited');assert.equal(sends,1);
});

test('expired same-attempt replay reports cached or reserved truth without sending again',async()=>{
 let now=100000;const e=await envelope(now),s=storage();let calls=0;
 const d=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,now:()=>now,send:async()=>{calls++;return good;}});
 assert.equal((await d(e)).ok,true);now=e.deadline_ms+1;assert.deepEqual(await d(e),good);assert.equal(calls,1);
 const key=(await validateEnvelope(e,now,{historical:true})).key;await s.put('receipt:'+key,{hash:await sha256(canonicalEnvelope(e)),state:'reserved'});
 assert.equal((await d(e)).error,'attempt_uncertain');assert.equal(calls,1);
});

test('unknown future-start or non-integer-deadline envelopes never reserve or send',async()=>{
 const now=100000,s=storage();let sends=0;const d=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,now:()=>now,send:async()=>{sends++;return good;}});
 const future=await envelope(now+10000000);assert.equal((await d(future)).error,'dispatch_rejected');
 const malformed=await envelope(now);malformed.deadline_ms=String(malformed.deadline_ms);assert.equal((await d(malformed)).error,'attempt_uncertain');assert.equal(s.values.size,0);assert.equal(sends,0);
});

test('concurrent conflicting envelope after absent read is uncertain, never unsent',async()=>{
 const s=storage(),originalGet=s.get.bind(s);let reads=0,release;const gate=new Promise(r=>release=r);
 s.get=async key=>{if(key.startsWith('receipt:')&&reads<2){reads++;if(reads===2)release();await gate;return undefined;}return originalGet(key);};
 let calls=0;const d=createDispatcher({enabled:true,revision:'c'.repeat(64),storage:s,send:async()=>{calls++;return good;}});
 const first=await envelope(),other=structuredClone(first);other.request.body='{"different":true}';
 const results=await Promise.all([d(first),d(other)]);assert.equal(calls,1);assert.equal(results.filter(r=>r.ok).length,1);const rejected=results.find(r=>!r.ok);assert.equal(rejected.error,'attempt_uncertain');assert.equal(rejected.request_may_have_been_sent,true);
});
