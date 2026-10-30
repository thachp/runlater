// Compiled local Worker/SQLite/alarm/Queue proof. No provider resources or external callbacks.
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';import {spawnSync} from 'node:child_process';import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-pause-'));fs.writeFileSync(path.join(root,'.owner'),'pause-local-test');
const bindings={...JSON.parse(fs.readFileSync('wrangler.jsonc')).vars,READY_QUEUE_NAME:'pause-ready',TEST_RUNTIME_ENABLED:'true'};
const events=[],holdClaims=new Set(),holdCallbacks=new Set(),holdPublishes=new Set(),held=[];let mf,calls=0;
const control=async req=>{const event=await req.json();events.push(event);if(event.point==='before_claim'&&holdClaims.has(event.metadata.id)||event.point==='callback_complete'&&holdCallbacks.has(event.metadata.id)||event.point==='before_publish'&&holdPublishes.has(event.metadata.id))return new Promise(resolve=>held.push({event,resolve}));return new Response(null,{status:204});};
function release(id){holdClaims.delete(id);holdCallbacks.delete(id);holdPublishes.delete(id);for(let i=held.length-1;i>=0;i--)if(held[i].event.metadata.id===id){held[i].resolve(new Response(null,{status:204}));held.splice(i,1);}}
function start(){return new Miniflare(convertV4MiniflareOptions({resourcePersistencePath:root,workers:[{name:'pause-api',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',bindings,serviceBindings:{TEST_CONTROL:control},durableObjects:{LEDGER:{className:'TaskLedger',useSQLite:true}},queueProducers:{READY:'pause-ready'},queueConsumers:{'pause-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:'deny-egress'},{name:'deny-egress',modules:true,compatibilityDate:'2026-10-27',script:'export default {fetch(){return new Response(null,{status:403})}}'}]}));}
async function api(route,{method='GET',body,key,token='local-alpha',status=200}={}){assert.ok(++calls<=150);const r=await mf.dispatchFetch('http://127.0.0.1:8787'+route,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',...(key?{'Idempotency-Key':key}:{})},body:body===undefined?undefined:JSON.stringify(body)});assert.equal(r.status,status,route);const text=await r.text();try{return JSON.parse(text)}catch{return text}}
async function toggle(paused){return api('/v1/queue',{method:'PUT',body:{...await api('/v1/queue'),paused}});}
async function wait(fn){for(let i=0;i<50;i++){const result=await fn();if(result)return result;await new Promise(r=>setTimeout(r,100));}throw Error('Bounded local pause wait expired');}
async function send(t){const q=await mf.getQueueProducer('READY','pause-api');await q.send({tenant:'alpha',id:t.id,generation:t.generation});}
const point=(name,id)=>events.filter(e=>e.point===name&&e.metadata?.id===id);
function sql(mode,id=''){const result=spawnSync('python3',['-c',`import pathlib,sqlite3,hashlib,json,sys,time
root=pathlib.Path(sys.argv[1]);assert root.name.startswith('runlater-pause-') and (root/'.owner').read_text()=='pause-local-test'
rows=[];edited=0
for p in sorted(root.rglob('*.sqlite')):
 c=sqlite3.connect(p) if sys.argv[2]=='seed-aged' else sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 tables=c.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
 if not any(name=='ledger' for name,sql in tables):continue
 if sys.argv[2]=='seed-aged':
  data=json.loads(c.execute('SELECT data FROM ledger WHERE id=1').fetchone()[0]);task=data['ledger']['tasks'].get(sys.argv[3])
  if task is not None:
   assert data['tenant']=='alpha' and data['ledger']['limits']['paused'] and not task['attempts']
   task['initial_due_ms']=task['due_ms']=int(time.time()*1000)-86401000
   c.execute('UPDATE ledger SET data=? WHERE id=1',(json.dumps(data),));c.commit();edited+=1
 else:
  for name,ddl in tables:
   if not name.startswith('sqlite_'):rows.append((str(p),name,ddl,sorted(repr(r) for r in c.execute('SELECT * FROM "'+name.replace('"','""')+'"'))))
if sys.argv[2]=='seed-aged':assert edited==1;print('owned aged snapshot seeded')
else:assert rows;print(hashlib.sha256(repr(rows).encode()).hexdigest())`,root,mode,id],{encoding:'utf8'});assert.equal(result.status,0,result.stderr);return result.stdout.trim();}
try{
 mf=start();await toggle(true);
 const input={destination:'fixture://success',body:'private_pause_payload',operation_key:'private_pause_operation',run_at_ms:0};
 const a=await api('/v1/tasks',{method:'POST',body:input,key:'a',status:201}),b=await api('/v1/tasks',{method:'POST',body:input,key:'cancel',status:201});await api('/v1/tasks/'+b.id+'/cancel',{method:'POST'});
 await send(a);await wait(()=>point('before_claim',a.id).length);await new Promise(r=>setTimeout(r,2400));assert.equal((await api('/v1/tasks/'+a.id)).attempts.length,0);assert.equal(events.filter(e=>e.point==='before_publish').length,0);
 const pumps=events.filter(e=>e.point==='before_rearm'&&e.metadata.preserve_earlier===false);assert.ok(pumps.length<=1,'Paused alarm kept looping');assert.ok(pumps.length>=1,'Expected watchdog normalization alarm');assert.ok(pumps.every(e=>e.metadata.paused&&e.metadata.planned_wake_ms>Date.now()+3600000),'Paused wake should target age/retention, not ready polling');
 const before=sql('snapshot');await api('/v1/queue');const health=await api('/v1/queue/health');await api('/v1/queue/metrics');assert.equal(health.paused,true);assert.equal(sql('snapshot'),before,'Pure paused queries changed SQL/schema/alarm state');
 await mf.dispose();mf=start();assert.equal((await api('/v1/queue')).paused,true);await send(a);await new Promise(r=>setTimeout(r,200));assert.equal((await api('/v1/tasks/'+a.id)).attempts.length,0);assert.equal((await api('/v1/queue',{token:'local-beta'})).paused,false);
 const reader='pause_reader',token=`rl_local.alpha.${reader}.public_local_pause_reader`;
 await api('/v1/keys',{method:'POST',body:{key_id:reader,token_sha256:createHash('sha256').update(token).digest('hex'),permissions:['read'],expires_at_ms:Date.now()+3600000},status:201});await api('/v1/queue',{method:'PUT',body:{...await api('/v1/queue'),paused:false},token,status:403});
 await toggle(false);const recovered=await wait(async()=>{const t=await api('/v1/tasks/'+a.id);return t.status==='succeeded'&&t});assert.equal(recovered.attempts.length,1);assert.equal(recovered.generation,a.generation);assert.equal((await api('/v1/tasks/'+b.id)).status,'cancelled');
 // Pause wins while a real queued reference is stopped immediately before its private claim call.
 const c=await api('/v1/tasks',{method:'POST',body:input,key:'race',status:201});holdClaims.add(c.id);await send(c);await wait(()=>held.some(h=>h.event.point==='before_claim'&&h.event.metadata.id===c.id));await toggle(true);release(c.id);await new Promise(r=>setTimeout(r,250));assert.equal((await api('/v1/tasks/'+c.id)).attempts.length,0);await api('/v1/tasks/'+c.id+'/cancel',{method:'POST'});
 // A pump already awaiting publication may finish after pause, but that reference cannot claim.
 await toggle(false);const p=await api('/v1/tasks',{method:'POST',body:input,key:'publication_race',status:201});holdPublishes.add(p.id);await wait(()=>held.some(h=>h.event.point==='before_publish'&&h.event.metadata.id===p.id));await toggle(true);release(p.id);await wait(()=>point('before_claim',p.id).length);await new Promise(r=>setTimeout(r,200));assert.equal((await api('/v1/tasks/'+p.id)).attempts.length,0);await api('/v1/tasks/'+p.id+'/cancel',{method:'POST'});
 // Claim wins: callback fixture has completed but its result is held outside the DO during pause.
 await toggle(false);const d=await api('/v1/tasks',{method:'POST',body:input,key:'inflight',status:201});holdCallbacks.add(d.id);await send(d);await wait(()=>held.some(h=>h.event.point==='callback_complete'&&h.event.metadata.id===d.id));const running=await api('/v1/tasks/'+d.id);assert.equal(running.status,'running');await toggle(true);release(d.id);const done=await wait(async()=>{const t=await api('/v1/tasks/'+d.id);return t.status==='succeeded'&&t});assert.equal(done.fence,running.fence);assert.equal(done.attempts.length,1);
 // A due retry stays quiet during pause, then resumes with its original attempt/generation history.
 await toggle(false);const e=await api('/v1/tasks',{method:'POST',body:{...input,destination:'fixture://retry'},key:'retry',status:201});holdCallbacks.add(e.id);await send(e);await wait(()=>held.some(h=>h.event.point==='callback_complete'&&h.event.metadata.id===e.id));await toggle(true);release(e.id);const retry=await wait(async()=>{const t=await api('/v1/tasks/'+e.id);return t.status==='retry_wait'&&t});const eventStart=events.length;await new Promise(r=>setTimeout(r,Math.max(0,retry.due_ms-Date.now())+500));assert.equal((await api('/v1/tasks/'+e.id)).attempts.length,1);assert.equal(events.slice(eventStart).filter(e=>e.point==='before_publish').length,0);assert.ok(events.slice(eventStart).filter(e=>e.point==='before_rearm'&&e.metadata.preserve_earlier===false).length<=1);
 await toggle(false);const retried=await wait(async()=>{const t=await api('/v1/tasks/'+e.id);return t.status==='failed'&&t});assert.equal(retried.attempts.length,2);assert.equal(retried.generation,retry.generation);await send(e);await new Promise(r=>setTimeout(r,200));assert.equal(point('callback_complete',e.id).length,2);
 // Seed ONLY an owned stopped SQLite fixture to represent one day elapsed; real wall clock is unchanged.
 await toggle(true);const old=await api('/v1/tasks',{method:'POST',body:input,key:'aged',status:201});await mf.dispose();sql('seed-aged',old.id);mf=start();const expired=await wait(async()=>{const t=await api('/v1/tasks/'+old.id);return t.status==='failed'&&t});assert.equal(expired.attempts.length,0);assert.ok(Math.abs(expired.terminal_ms-Date.now())<5000);await toggle(false);assert.equal((await api('/v1/tasks/'+old.id)).status,'failed');assert.equal((await api('/v1/tasks/'+c.id)).status,'cancelled');
 console.log(`PASS: compiled local pause/restart, queued-reference race, in-flight finish, retry due while paused, resume, cancellation, tenant/read permission and SQL/alarm query purity; bounded paused pumps/publications; seeded aged-snapshot expiry via actual alarm. ${calls} bounded HTTP calls. Age fixture is simulated elapsed time, not a day-long or cloud test.`);
}finally{for(const h of held)h.resolve(new Response(null,{status:204}));if(mf)await mf.dispose();assert.equal(fs.readFileSync(path.join(root,'.owner'),'utf8'),'pause-local-test');fs.rmSync(root,{recursive:true});}
