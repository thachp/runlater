// Local fixture-only HTTP coverage. Run against the local emulator on loopback.
import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
const base='http://127.0.0.1:8787',prefix='ops'+Date.now();
async function call(path,{method='GET',body,key,token='local-alpha',expected=200}={}){const r=await fetch(base+path,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',...(key?{'Idempotency-Key':key}:{})},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(5000)});const text=await r.text();assert.equal(r.status,expected,text);try{return JSON.parse(text)}catch{return text}}
async function issue(name,permissions){const id=prefix+name,token=`rl_local.alpha.${id}.public_local_operations_fixture`;await call('/v1/keys',{method:'POST',expected:201,body:{key_id:id,token_sha256:createHash('sha256').update(token).digest('hex'),permissions,not_before_ms:0,expires_at_ms:Date.now()+3600000}});return {id,token};}
const reader=await issue('reader',['read']),config=await issue('config',['configure']),writer=await issue('writer',['enqueue']);
const input={destination:'fixture://success',body:'NEVER_IN_DIAGNOSTICS_'+prefix,operation_key:prefix,run_at_ms:Date.now()+7*86400000};
const task=await call('/v1/tasks',{method:'POST',key:prefix,body:input,expected:201});
const beta=await call('/v1/tasks',{method:'POST',key:prefix+'beta',body:{...input,run_at_ms:Date.now()+8*86400000},token:'local-beta',expected:201});
const a=await call('/v1/tasks/'+task.id+'/inspection',{token:reader.token});assert.equal(a.id,task.id);assert.ok(!('input'in a));
for(const path of ['/v1/queue/health','/v1/queue/audit','/v1/tasks/'+task.id+'/inspection']){const result=await call(path,{token:reader.token});for(const forbidden of [input.body,input.operation_key,'fixture://success',reader.token])assert.ok(!JSON.stringify(result).includes(forbidden));await call(path,{token:writer.token,expected:403});await call(path,{token:config.token,expected:403});}
const before=await call('/v1/queue/health',{token:'local-beta'});assert.equal(before.retained_tasks,1);assert.equal(before.counts_by_state.scheduled,1);assert.equal(before.eligible_backlog,0);
await call('/v1/queue/maintenance',{method:'POST',body:{},token:reader.token,expected:403});
await call('/v1/queue/maintenance',{method:'POST',body:{now_ms:Date.now()+40*86400000},token:config.token,expected:400});
await call('/v1/queue/maintenance?now_ms=9999999999999',{method:'POST',body:{},token:config.token,expected:400});
const first=await call('/v1/queue/maintenance',{method:'POST',body:{},token:config.token});assert.equal(first.tasks_removed,0);assert.equal((await call('/v1/queue/maintenance',{method:'POST',body:{},token:config.token})).tasks_removed,0);
assert.equal((await call('/v1/tasks/'+task.id+'/inspection',{token:reader.token})).status,'scheduled');
assert.equal((await call('/v1/tasks/'+beta.id+'/inspection',{token:'local-beta'})).due_ms,beta.due_ms);
for(const key of [reader,config,writer])await call('/v1/keys/'+key.id+'/revoke',{method:'POST'});
await call('/v1/tasks/'+task.id+'/cancel',{method:'POST'});await call('/v1/tasks/'+beta.id+'/cancel',{method:'POST',token:'local-beta'});
console.log('PASS: operational routes enforce read/configure scopes, tenant-local health/inspection, redaction, server-time-only maintenance and active payload preservation');
