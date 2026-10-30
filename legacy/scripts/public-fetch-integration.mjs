// OFFLINE workerd composition. outboundService replaces ALL network I/O with a fake.
// This is not provider DNS, SSRF, TLS, cancellation or rebinding proof.
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {sha256} from '../egress/controller/envelope.mjs';
const root=await mkdtemp(join(tmpdir(),'runlater-public-fetch-'));
const revision='c'.repeat(64),observed=[];
const script=(await build({entryPoints:['egress/public-fetch/worker.mjs'],bundle:true,platform:'neutral',format:'esm',external:['cloudflare:*'],write:false})).outputFiles[0].text;
const config=JSON.parse(await readFile('egress/public-fetch/wrangler.example.jsonc','utf8'));
const options=enabled=>convertV4MiniflareOptions({resourcePersistencePath:root,workers:[
 {name:'caller',modules:true,script:`export default {fetch(r,e){return e.EGRESS.fetch(r);}}`,compatibilityDate:config.compatibility_date,serviceBindings:{EGRESS:{name:'candidate',entrypoint:'PublicFetchBinding'}},outboundService:()=>{throw Error('caller fallback');}},
 {name:'candidate',modules:true,script,compatibilityDate:config.compatibility_date,compatibilityFlags:config.compatibility_flags,
  bindings:{...config.vars,EGRESS_ENABLED:enabled?'operator-approved':'false',EGRESS_REVIEW_REVISION:revision},
  durableObjects:{PUBLIC_FETCH_RECEIPTS:{className:'PublicFetchReceipts',useSQLite:true}},
  outboundService:async r=>{observed.push({url:r.url,method:r.method,headers:[...r.headers],body:await r.text()});return new Response('PRIVATE_RESPONSE',{status:200});}}
]});
let mf;
async function envelope(){const now=Date.now(),request={url:'https://example.com/hook?PRIVATE',body:'{}',contentType:'application/json',operationKey:'stable'};return {version:1,adapter_revision:revision,release_id:'test',project_id:'p_'+'a'.repeat(60),task_id:'task_'+'b'.repeat(16),fence:1,attempt_started_at_ms:now,deadline_ms:now+29000,target_sha256:await sha256(JSON.stringify({version:1,url:request.url,method:'POST',content_type:'application/json'})),request};}
const dispatch=e=>mf.dispatchFetch('https://egress.internal/dispatch',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer INCOMING_PRIVATE',Cookie:'INCOMING_PRIVATE'},body:JSON.stringify(e)});
try{
 mf=new Miniflare(options(false));await mf.ready;assert.equal((await dispatch(await envelope())).status,503);assert.equal(observed.length,0);await mf.dispose();
 mf=new Miniflare(options(true));await mf.ready;
 assert.equal((await (await mf.dispatchFetch('https://egress.internal/ready')).json()).ready,true);
 const worker=await mf.getWorker('candidate');assert.equal((await worker.fetch('https://egress.internal/ready')).status,404);
 const e=await envelope();const result=await (await dispatch(e)).json();assert.equal(result.ok,true);assert.equal(result.response_bytes,16);assert.equal(observed.length,1);
 const sent=observed[0];assert.equal(JSON.stringify(sent).includes('INCOMING_PRIVATE'),false);
 // workerd adds routing headers itself; they are not inherited from the caller.
 assert.deepEqual(sent.headers.filter(([k])=>['cf-worker','content-length','host'].includes(k)),[['cf-worker','candidate.example.com'],['content-length','2'],['host','example.com']]);
 assert.deepEqual({...sent,headers:sent.headers.filter(([k])=>!['cf-worker','content-length','host'].includes(k))},{url:e.request.url,method:'POST',headers:[['content-type','application/json'],['idempotency-key','stable'],['user-agent','RunLater-Delivery/1']],body:'{}'});
 assert.deepEqual(await (await dispatch(e)).json(),result);assert.equal(observed.length,1);
 const changed=structuredClone(e);changed.request.body='{"changed":true}';assert.equal((await (await dispatch(changed)).json()).error,'attempt_uncertain');assert.equal(observed.length,1);
 await mf.dispose();mf=new Miniflare(options(true));await mf.ready;
 assert.deepEqual(await (await dispatch(e)).json(),result);assert.equal(observed.length,1);
 console.log(JSON.stringify({status:'passed',actual_worker_named_binding_and_sqlite_receipts:true,default_off:true,restart_replay_no_redispatch:true,incoming_credentials_omitted:true,network:'offline fake outboundService',provider_proof:false,live_resources:0}));
}finally{await mf?.dispose();await rm(root,{recursive:true,force:true});}
