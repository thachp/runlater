import assert from 'node:assert/strict';
const base='http://127.0.0.1:8787';const prefix='admission-'+Date.now();
async function request(path,{tenant='alpha',method='GET',body,key,expected=200,extra={}}={}){let r=await fetch(base+path,{method,headers:{Authorization:'Bearer local-'+tenant,'Content-Type':'application/json',...extra,...(key?{'Idempotency-Key':key}:{})},body:body===undefined?undefined:JSON.stringify(body)});let raw=await r.text();assert.equal(r.status,expected,raw);let data;try{data=JSON.parse(raw)}catch{data=raw}return {r,data}}
// Earlier fixture suites may leave a short retry in progress. Wait without mutating their work.
for(let attempt=0;attempt<100;attempt++){let after='',active=false;do{const list=(await request('/v1/tasks'+(after?'?after='+encodeURIComponent(after):''))).data;active ||= list.tasks.some(t=>!['succeeded','failed','cancelled'].includes(t.status));after=list.next_after;}while(after);if(!active)break;if(attempt===99)throw Error('admission suite requires an idle local alpha fixture tenant');await new Promise(r=>setTimeout(r,200));}
const saved=(await request('/v1/queue')).data;const created=[];
try{
 const limits={...saved,max_active_tasks:1,max_concurrent:1,dispatch_per_second:1,dispatch_burst:1};
 assert.deepEqual((await request('/v1/queue',{method:'PUT',body:limits})).data,limits);
 assert.deepEqual((await request('/v1/queue')).data,limits);
 const input={destination:'fixture://success',body:'local-admission-alpha-'+prefix,operation_key:prefix+'_alpha',run_at_ms:Date.now()+60000};
 const first=(await request('/v1/tasks',{method:'POST',body:input,key:prefix,expected:201})).data;created.push(['alpha',first.id]);
 assert.equal((await request('/v1/tasks',{method:'POST',body:input,key:prefix})).data.id,first.id);
 const limited=await request('/v1/tasks',{method:'POST',body:input,key:prefix+'-second',expected:429});assert.equal(limited.data.reason,'active_tasks');assert.ok(limited.data.retry_after_ms>0);assert.equal(limited.r.headers.get('Retry-After'),'1');
 const betaInput={...input,body:'local-admission-beta-'+prefix,operation_key:prefix+'_beta'};
 const other=(await request('/v1/tasks',{tenant:'beta',method:'POST',body:betaInput,key:prefix,expected:201})).data;created.push(['beta',other.id]);
 if(process.env.RUNLATER_REQUIRE_COINCIDENT_IDS==='1'){assert.equal(first.id,'task_0000000000000001');assert.equal(other.id,first.id,'fresh tenants must exercise coincident tenant-local task IDs');}
 // Compare each forged-header read with the actual authenticated tenant's owned result.
 // Distinct tenant markers make coincident task IDs unambiguous on a fresh store.
 const alphaOwned=(await request('/v1/tasks/'+first.id)).data;
 const alphaForged=(await request('/v1/tasks/'+first.id,{extra:{'x-tenant':'beta'}})).data;
 assert.deepEqual(alphaOwned.input,input);assert.deepEqual(alphaForged.input,alphaOwned.input);assert.equal(alphaForged.id,first.id);
 const betaOwned=(await request('/v1/tasks/'+other.id,{tenant:'beta'})).data;
 const betaForged=(await request('/v1/tasks/'+other.id,{tenant:'beta',extra:{'x-tenant':'alpha'}})).data;
 assert.deepEqual(betaOwned.input,betaInput);assert.deepEqual(betaForged.input,betaOwned.input);assert.equal(betaForged.id,other.id);
 assert.notEqual(alphaForged.input.operation_key,betaForged.input.operation_key);assert.notEqual(alphaForged.input.body,betaForged.input.body);
 if(first.id===other.id){console.log('PASS: coincident tenant-local task IDs return distinct tenant-owned markers despite forged tenant headers');}
 await request('/v1/tasks/'+first.id+'/cancel',{method:'POST'});
 const next=(await request('/v1/tasks',{method:'POST',body:input,key:prefix+'-second',expected:201})).data;created.push(['alpha',next.id]);
 await request('/v1/queue',{method:'PUT',body:{...limits,max_concurrent:0},expected:400});assert.deepEqual((await request('/v1/queue')).data,limits);
 await request('/v1/queue',{method:'PUT',body:{...limits,unexpected:true},expected:400});
 await request('/v1/tasks',{method:'POST',body:input,key:prefix+'-mime',extra:{'Content-Type':'text/plain'},expected:415});
 await request('/v1/tasks-unknown',{method:'POST',body:{},expected:404});
 await request('/v1/tasks/not-valid/cancel',{method:'POST',expected:404});
 // Exercise durable dispatch pacing as well as admission limits through the actual Queue consumer.
 await request('/v1/tasks/'+next.id+'/cancel',{method:'POST'});
 await request('/v1/queue',{method:'PUT',body:{...limits,max_active_tasks:10}});
 const paced=[];for(let n=0;n<3;n++){const task=(await request('/v1/tasks',{method:'POST',body:{...input,run_at_ms:0},key:prefix+'-paced-'+n,expected:201})).data;paced.push(task.id);created.push(['alpha',task.id]);}
 const timings=[];for(const id of paced){let done;for(let i=0;i<80;i++){const task=(await request('/v1/tasks/'+id)).data;if(task.status==='succeeded'){done=task;break}await new Promise(r=>setTimeout(r,200));}assert.ok(done,'rate-gated task stranded');assert.equal(done.attempts.length,1);timings.push(done.attempts[0].started_ms);}
 timings.sort((a,b)=>a-b);assert.ok(timings[1]-timings[0]>=1000);assert.ok(timings[2]-timings[1]>=1000);
 console.log('PASS: CQRS queue configuration, bounded validation, structured admission 429/Retry-After, replay under capacity, cancellation release, tenant/noisy-neighbor isolation, actual Queue rate pacing without extra attempts, MIME/path rejection');
}finally{for(const [tenant,id] of created)await request('/v1/tasks/'+id+'/cancel',{tenant,method:'POST'});await request('/v1/queue',{method:'PUT',body:saved});}
