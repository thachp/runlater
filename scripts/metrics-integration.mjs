// Compiled local DO command/query and clean-restart proof; no live resources/consumer callbacks.
import {spawnSync} from 'node:child_process';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-metrics-'));fs.writeFileSync(path.join(root,'.owner'),'metrics-local-test');
const bindings=JSON.parse(fs.readFileSync('wrangler.jsonc')).vars;bindings.READY_QUEUE_NAME='metrics-ready';let mf,calls=0;
function start(){return new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'metrics-api',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',bindings,durableObjects:{LEDGER:{className:'TaskLedger',useSQLite:true}},queueProducers:{READY:'metrics-ready'},outboundService:'deny-egress'},{name:'deny-egress',modules:true,compatibilityDate:'2026-10-27',script:'export default {fetch(){return new Response(null,{status:403})}}'}]}));}
async function api(route,{method='GET',body,key,token='local-alpha',status=200}={}){assert.ok(++calls<=80);const r=await mf.dispatchFetch('http://127.0.0.1:8787'+route,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',...(key?{'Idempotency-Key':key}:{})},body:body===undefined?undefined:JSON.stringify(body)});assert.equal(r.status,status);const text=await r.text();try{return JSON.parse(text)}catch{return text}}
async function internal(route,value,status){assert.ok(++calls<=80);const ns=await mf.getDurableObjectNamespace('LEDGER','metrics-api');const r=await ns.get(ns.idFromName('alpha')).fetch('http://ledger.invalid/'+route,{method:'POST',headers:{'x-tenant':'alpha','Content-Type':'application/json'},body:JSON.stringify(value)});assert.equal(r.status,status);const text=await r.text();try{return JSON.parse(text)}catch{return text}}
function sqliteSnapshot(){const p=spawnSync('python3',['-c',`
import pathlib,sqlite3,hashlib,sys
out=[]
for p in sorted(pathlib.Path(sys.argv[1]).rglob('*.sqlite')):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 tables=c.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
 if not any(name=='ledger' for name,sql in tables):continue
 rows=[]
 for name,sql in tables:
  if name.startswith('sqlite_'):continue
  rows.append((name,sql,sorted(repr(r) for r in c.execute('SELECT * FROM "'+name.replace('"','""')+'"'))))
 out.append((str(p),rows))
assert out,'No local TaskLedger SQL found'
print(hashlib.sha256(repr(out).encode()).hexdigest())
`,root],{encoding:'utf8'});assert.equal(p.status,0,p.stderr);return p.stdout.trim();}
try{
 mf=start();
 const input={destination:'fixture://success',body:'private_local_metrics_payload',operation_key:'private_metrics_operation'};
 const limits=await api('/v1/queue');await api('/v1/queue',{method:'PUT',body:{...limits,max_active_tasks:2,max_concurrent:1}});
 const a=await api('/v1/tasks',{method:'POST',body:input,key:'a',status:201}),b=await api('/v1/tasks',{method:'POST',body:input,key:'b',status:201});
 await api('/v1/tasks',{method:'POST',body:input,key:'denied',status:429});
 const ref=t=>({tenant:'alpha',id:t.id,generation:t.generation});const first=await internal('claim',ref(a),200);await internal('claim',ref(a),200);await internal('claim',ref(b),429);
 await internal('finish',{id:a.id,fence:first.fence,status:204},200);await internal('finish',{id:a.id,fence:first.fence,status:503},409);
 const v=await api('/v1/queue/metrics');const counts=v.totals.counts;assert.equal(counts.admission_active_tasks_denied,1);assert.equal(counts.claim_references,3);assert.equal(counts.claim_ignored,1);assert.equal(counts.claim_concurrency_denied,1);assert.equal(counts.stale_results_ignored,1);assert.equal(counts.attempt_started,1);assert.equal(v.totals.attempt_completed,1);assert.equal(v.totals.attempt_error_ratio,0);
 assert.equal((await api('/v1/tasks')).tasks.length,2);assert.equal((await api('/v1/tasks',{method:'POST',body:input,key:'a'})).id,a.id);
 const beta=await api('/v1/queue/metrics',{token:'local-beta'});assert.ok(Object.values(beta.totals.counts).every(n=>n===0));
 const id='metrics_writer',token=`rl_local.alpha.${id}.public_local_metrics_fixture_secret`;
 await api('/v1/keys',{method:'POST',body:{key_id:id,token_sha256:createHash('sha256').update(token).digest('hex'),permissions:['enqueue'],expires_at_ms:Date.now()+3600000},status:201});
 await api('/v1/queue/metrics',{token,status:403});
 const future=await api('/v1/queue/metrics?now_ms=9999999999999');assert.ok(Math.abs(future.sampled_at_ms-Date.now())<5000);
 for(const hidden of [input.body,input.operation_key,'fixture://success',token])assert.ok(!JSON.stringify(future).includes(hidden));
 await api('/v1/tasks/'+b.id+'/cancel',{method:'POST'});await new Promise(r=>setTimeout(r,2200));const sqlBefore=sqliteSnapshot();for(let i=0;i<3;i++)await api('/v1/queue/metrics');await api('/v1/queue/metrics',{token,status:403});assert.equal(sqliteSnapshot(),sqlBefore,'Metric reads changed SQLite/schema/alarm metadata');
 const totals=future.totals;await mf.dispose();mf=start();assert.deepEqual((await api('/v1/queue/metrics')).totals,totals,'Counters survive clean workerd/SQLite restart');
 console.log('PASS local SQLite/runtime: quota/claim/duplicate/stale-result semantics, read scope, tenant isolation, server sampling, redaction, SQL/alarm query immutability and clean restart persistence');
}finally{await mf?.dispose();assert.equal(fs.readFileSync(path.join(root,'.owner'),'utf8'),'metrics-local-test');fs.rmSync(root,{recursive:true});}
