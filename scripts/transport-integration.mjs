// Actual local workerd/SQLite/Queue retries and dead-letter forwarding with test-only injected exceptions.
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';import {spawnSync} from 'node:child_process';import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-transport-'));fs.writeFileSync(path.join(root,'.owner'),'transport-test');
const bindings={...JSON.parse(fs.readFileSync('wrangler.jsonc')).vars,READY_QUEUE_NAME:'transport-ready',TRANSPORT_DLQ_NAME:'transport-dead',TEST_RUNTIME_ENABLED:'true'};
const faults=new Map(),finished=new Map();let mf,calls=0;
const control=async req=>{const {point,metadata}=await req.json(),id=metadata?.id,mode=faults.get(id);if(point==='after_finish'){finished.set(id,(finished.get(id)??0)+1);if(mode==='after')return new Response(null,{status:500});}if(point==='before_claim'&&(mode==='before'||mode==='after'&&finished.has(id)))return new Response(null,{status:500});return new Response(null,{status:204});};
function start(){return new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'transport-api',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',bindings,serviceBindings:{TEST_CONTROL:control},durableObjects:{LEDGER:{className:'TaskLedger',useSQLite:true}},queueProducers:{READY:'transport-ready'},queueConsumers:{'transport-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1,deadLetterQueue:'transport-dead'},'transport-dead':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:'deny-egress'},{name:'deny-egress',modules:true,compatibilityDate:'2026-10-27',script:'export default {fetch(){return new Response(null,{status:403})}}'}]}));}
async function api(route,{method='GET',body,key,token='local-alpha',status=200}={}){assert.ok(++calls<=150);const r=await mf.dispatchFetch('http://127.0.0.1:8787'+route,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',...(key?{'Idempotency-Key':key}:{})},body:body===undefined?undefined:JSON.stringify(body)});assert.equal(r.status,status,route);const text=await r.text();try{return JSON.parse(text)}catch{return text}}
async function wait(fn){for(let i=0;i<50;i++){const result=await fn();if(result)return result;await new Promise(r=>setTimeout(r,100));}throw Error('Bounded local Queue wait expired');}
const ref=t=>({tenant:'alpha',id:t.id,generation:t.generation});
async function send(value){const q=await mf.getQueueProducer('READY','transport-api');await q.send(value);}
function snapshot(){const r=spawnSync('python3',['-c',`import pathlib,sqlite3,hashlib,sys
out=[]
for p in sorted(pathlib.Path(sys.argv[1]).rglob('*.sqlite')):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 if c.execute("SELECT count(*) FROM sqlite_master WHERE name='ledger'").fetchone()[0]:out.append(c.execute('SELECT * FROM ledger').fetchall())
assert out
print(hashlib.sha256(repr(out).encode()).hexdigest())`,root],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);return r.stdout.trim();}
try{
 mf=start();
 const input={destination:'fixture://success',body:'private_transport_payload',operation_key:'private_transport_operation',run_at_ms:Date.now()+60000};
 const a=await api('/v1/tasks',{method:'POST',body:input,key:'before',status:201});faults.set(a.id,'before');await send(ref(a));
 const observation=await wait(async()=>{const list=await api('/v1/queue/dead-letters');return list.records.find(r=>r.reference.task_id===a.id&&r.transport_observed)});
 assert.equal(observation.current_classification,'waiting');assert.equal((await api('/v1/tasks/'+a.id)).attempts.length,0);
 const rid=observation.record_id;await api('/v1/queue/dead-letters/'+rid+'/reconcile',{method:'POST',body:{}});
 assert.equal((await api('/v1/tasks/'+a.id)).input.run_at_ms,input.run_at_ms,'Recovery must preserve schedule');
 // A due task: exhaust transport before claim, then remove fault and allow authoritative outbox recovery.
 const b=await api('/v1/tasks',{method:'POST',body:{...input,run_at_ms:0},key:'due',status:201});faults.set(b.id,'before');await send(ref(b));
 const bRecord=await wait(async()=>{const list=await api('/v1/queue/dead-letters');return list.records.find(r=>r.reference.task_id===b.id&&r.transport_observed)});assert.equal((await api('/v1/tasks/'+b.id)).attempts.length,0);
 faults.delete(b.id);await api('/v1/queue/dead-letters/'+bRecord.record_id+'/reconcile',{method:'POST',body:{}});
 const recovered=await wait(async()=>{const t=await api('/v1/tasks/'+b.id);return t.status==='succeeded'&&t});assert.equal(recovered.attempts.length,1);assert.equal(recovered.generation,b.generation);
 const c=await api('/v1/tasks',{method:'POST',body:{...input,run_at_ms:0},key:'after',status:201});faults.set(c.id,'after');await send(ref(c));
 const cRecord=await wait(async()=>{const list=await api('/v1/queue/dead-letters');return list.records.find(r=>r.reference.task_id===c.id&&r.transport_observed)});assert.equal(cRecord.current_classification,'succeeded');
 const receipt=await api('/v1/queue/dead-letters/'+cRecord.record_id+'/reconcile',{method:'POST',body:{}});assert.equal(receipt.dead_letter.reconciliation.action,'no_recovery');assert.equal((await api('/v1/tasks/'+c.id)).attempts.length,1);assert.equal(finished.get(c.id),1);
 await send({tenant:'alpha',id:'bad',generation:0});await send({...ref(c),tenant:'bad tenant'});await send({...ref(c),extra:'malformed'});
 await send({...ref(c),tenant:'beta'});await new Promise(r=>setTimeout(r,500));const beta=(await api('/v1/queue/dead-letters',{token:'local-beta'})).records;assert.ok(beta.every(r=>r.current_classification==='missing'&&r.current_status===null));await api('/v1/tasks/'+c.id,{token:'local-beta',status:404});
 await api('/v1/queue/dead-letters/'+cRecord.record_id,{token:'local-beta',status:404});
 const id='transport_config',token=`rl_local.alpha.${id}.public_local_transport_secret`;
 await api('/v1/keys',{method:'POST',body:{key_id:id,token_sha256:createHash('sha256').update(token).digest('hex'),permissions:['configure'],expires_at_ms:Date.now()+3600000},status:201});
 await api('/v1/queue/dead-letters',{token,status:403});const scoped=await api('/v1/queue/dead-letters/'+cRecord.record_id+'/reconcile',{method:'POST',body:{},token});assert.deepEqual(Object.keys(scoped.dead_letter),['record_id']);
 const readId='transport_reader',readToken=`rl_local.alpha.${readId}.public_local_transport_reader`;
 await api('/v1/keys',{method:'POST',body:{key_id:readId,token_sha256:createHash('sha256').update(readToken).digest('hex'),permissions:['read'],expires_at_ms:Date.now()+3600000},status:201});
 await api('/v1/queue/dead-letters',{token:readToken});await api('/v1/queue/dead-letters',{method:'POST',body:{task_id:c.id,generation:c.generation},token:readToken,status:403});await api('/v1/queue/dead-letters/'+cRecord.record_id+'/reconcile',{method:'POST',body:{},token:readToken,status:403});
 const ns=await mf.getDurableObjectNamespace('LEDGER','transport-api');const rejected=await ns.get(ns.idFromName('alpha')).fetch('http://ledger.invalid/dead-letter',{method:'POST',headers:{'x-tenant':'alpha','Content-Type':'application/json'},body:JSON.stringify({...ref(c),tenant:'beta'})});assert.equal(rejected.status,400);await rejected.text();
 await api('/v1/queue/dead-letters',{method:'POST',body:{task_id:c.id,generation:c.generation,tenant:'beta'},status:400});await api('/v1/queue/dead-letters/'+cRecord.record_id+'/reconcile',{method:'POST',body:{now_ms:9999999999999},status:400});
 await api('/v1/tasks/'+a.id+'/cancel',{method:'POST'});faults.clear();await new Promise(r=>setTimeout(r,1500));const before=snapshot();await api('/v1/queue/dead-letters');const diagnostic=await api('/v1/queue/dead-letters/'+cRecord.record_id);assert.equal(snapshot(),before,'GET mutated SQLite ledger');for(const hidden of [input.body,input.operation_key,input.destination,token])assert.ok(!JSON.stringify(diagnostic).includes(hidden));
 await mf.dispose();mf=start();const replay=await api('/v1/queue/dead-letters/'+cRecord.record_id+'/reconcile',{method:'POST',body:{}});assert.equal(replay.replayed,true);assert.deepEqual(replay.dead_letter.reconciliation,receipt.dead_letter.reconciliation);assert.equal((await api('/v1/tasks/'+c.id)).attempts.length,1);
 console.log(`PASS: actual local Queue exhaustion/forwarding before claim and after durable result, outbox recovery, schedule/terminal preservation, malformed/tenant/permission/redaction/pure-query checks, clean SQLite/workerd restart and receipt replay; ${calls} bounded HTTP calls. Faults are private test-build exceptions, not cloud outages.`);
}finally{if(mf)await mf.dispose();if(fs.readFileSync(path.join(root,'.owner'),'utf8')==='transport-test')fs.rmSync(root,{recursive:true});}
