// Offline only: the compiled Rust consumer's outbound fetch is wired directly to
// the real receiver in workerd. No DNS, TLS, provider resources or live secrets.
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import fs from 'node:fs';
import assert from 'node:assert/strict';
const run='review',host='runlater-staging-review-receiver.local.workers.dev';
const shared={STAGING_RUN_ID:run,STAGING_EXPIRES_MS:String(Date.now()+120000),STAGING_INGRESS:'a'.repeat(64),STAGING_CALLBACK_HMAC:'b'.repeat(64)};
for (const [mode,expected] of [['valid','verified_receipt'],['policy','policy_rejected'],['content_type',{receiver_status:415}],['signature',{receiver_status:401}],['body',{receiver_status:400}],['redirect','redirect_rejected'],['headers','response_headers_too_large'],['size','response_body_too_large'],['receipt','receipt_rejected'],['timeout','timeout']]) {
const mf=new Miniflare(convertV4MiniflareOptions({workers:[{
 name:'api',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',
 bindings:{...shared,LOCAL_FIXTURES:'true',API_KEY_HASHES:JSON.parse(fs.readFileSync('wrangler.jsonc')).vars.API_KEY_HASHES,STAGING_DELIVERY_ENABLED:mode==='policy'?'false':'true',STAGING_RECEIVER_HOST:host,STAGING_RECEIVER_URL:`https://${host}/callback`},
 durableObjects:{LEDGER:{className:'TaskLedger',useSQLite:true}},queueProducers:{READY:'wire-ready'},queueConsumers:{'wire-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:'receiver',
},{name:'receiver',modules:[{type:'ESModule',path:'staging/wire-receiver-test.mjs',contents:`
import {handle} from './receiver.mjs';
export default {async fetch(request,env){
 const mode=env.TEST_MODE;
 if(mode==='timeout')await new Promise(r=>setTimeout(r,3200));
 if(mode==='content_type'||mode==='signature'||mode==='body'){
  request=new Request(request);request.headers.set(mode==='content_type'?'Content-Type':'RunLater-Signature',mode==='content_type'?'text/plain':'0'.repeat(64));
  if(mode==='body'){const {createHmac}=await import('node:crypto');const body=JSON.stringify({run:'review',case:'wrong',synthetic:true});request=new Request(request,{body});request.headers.set('RunLater-Signature',createHmac('sha256',env.STAGING_CALLBACK_HMAC).update(request.headers.get('RunLater-Timestamp')+'.'+request.headers.get('RunLater-Task-Id')+'.'+request.headers.get('RunLater-Operation-Key')+'.'+body).digest('hex'));}
 }
 const response=await handle(request,env);
 if(response.status!==204)return response;
 if(mode==='redirect')return new Response(null,{status:302,headers:{Location:'https://never-follow.invalid/'}});
 if(mode==='headers')return new Response(null,{status:204,headers:{Padding:'x'.repeat(2049)}});
 if(mode==='size')return new Response('x'.repeat(1025),{status:200});
 if(mode==='receipt')return new Response(null,{status:204});
 return response;
}};`},{type:'ESModule',path:'staging/receiver.mjs'}],compatibilityDate:'2026-10-27',compatibilityFlags:['nodejs_compat'],bindings:{...shared,TEST_MODE:mode}}]}));
try{
 const headers={Authorization:'Bearer local-alpha','Content-Type':'application/json','X-RunLater-Staging-Gate':shared.STAGING_INGRESS,'Idempotency-Key':'wire'};
 const body={destination:'staging://receiver',body:JSON.stringify({run,case:'receiver',synthetic:true}),operation_key:`run_${run}_receiver`};
 const response=await mf.dispatchFetch('https://api.invalid/v1/tasks',{method:'POST',headers,body:JSON.stringify(body)});
 assert.equal(response.status,201);const task=await response.json();
 let view;for(let i=0;i<40;i++){view=await (await mf.dispatchFetch(`https://api.invalid/v1/tasks/${task.id}`,{headers})).json();if(['succeeded','failed'].includes(view.status)||(mode==='timeout'&&view.attempts[0]?.staging_diagnostic))break;await new Promise(r=>setTimeout(r,100));}
 if(mode!=='timeout')assert.equal(view.status,mode==='valid'?'succeeded':'failed',JSON.stringify({status:view.status,attempts:view.attempts}));
 assert.equal(view.attempts.length,1);assert.deepEqual(view.attempts[0].staging_diagnostic,expected);console.log('PASS offline wire:',mode,JSON.stringify(expected));
}finally{await mf.dispose();}

}
