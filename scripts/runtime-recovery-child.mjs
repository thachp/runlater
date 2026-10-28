// Private subprocess harness, not a Worker route. Only parent IPC can select faults.
import fs from 'node:fs';import path from 'node:path';import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
const store=path.resolve(process.argv[2]),mode=process.argv[3]??'enabled';
if(!process.send||!path.basename(path.dirname(store)).startsWith('runlater-runtime-recovery-')||fs.readFileSync(path.join(path.dirname(store),'.owner'),'utf8')!=='runlater-runtime-recovery-test')throw Error('Owned disposable test store and parent IPC required');
const pending=new Map();let pointId=0;
const control=async request=>{const {point,metadata}=await request.json();const id=++pointId;return new Promise(resolve=>{pending.set(id,resolve);process.send({kind:'point',id,point,metadata});});};
const bindings=JSON.parse(fs.readFileSync(new URL('../wrangler.jsonc',import.meta.url))).vars;
const mf=new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:store,workers:[{name:'recovery-api',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',bindings:{...bindings,TEST_RUNTIME_ENABLED:mode==='disabled'?'false':'true'},serviceBindings:mode==='unbound'?{}:{TEST_CONTROL:control},durableObjects:{LEDGER:{className:'TaskLedger',useSQLite:true}},queueProducers:{READY:'recovery-ready'},queueConsumers:{'recovery-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:'deny-egress'},{name:'deny-egress',modules:true,compatibilityDate:'2026-10-27',script:'export default {fetch(){return new Response(null,{status:403})}}'}]}));
process.on('message',async m=>{
 try{
  if(m.kind==='point-result'){const resolve=pending.get(m.id);pending.delete(m.id);resolve?.(new Response(null,{status:m.action==='fail'?500:204}));return;}
  if(m.kind==='guard'){const r=await mf.dispatchFetch('https://test-artifact.invalid/health');await r.text();process.send({kind:'reply',id:m.id,result:{status:r.status}});}
  if(m.kind==='publish'){const queue=await mf.getQueueProducer('READY','recovery-api');for(let i=0;i<m.copies;i++)await queue.send(m.reference);process.send({kind:'reply',id:m.id,result:{published:m.copies}});}
  if(m.kind==='finish'){const ns=await mf.getDurableObjectNamespace('LEDGER','recovery-api');const r=await ns.get(ns.idFromName('alpha')).fetch('http://ledger.invalid/finish',{method:'POST',headers:{'x-tenant':'alpha','Content-Type':'application/json'},body:JSON.stringify(m.value)});await r.text();process.send({kind:'reply',id:m.id,result:{status:r.status}});}
  if(m.kind==='stop'){for(const resolve of pending.values())resolve(new Response(null,{status:204}));pending.clear();await mf.dispose();process.exit(0);}
 }catch{process.send({kind:'reply',id:m.id,error:'Local harness command failed'});}
});
const url=await mf.ready;process.send({kind:'ready',url:String(url)});
