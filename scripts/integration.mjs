import assert from 'node:assert/strict';
const base='http://127.0.0.1:8787';
async function api(path,{method='GET',body,key,tenant='alpha',expect=200}={}){let r=await fetch(base+path,{method,headers:{Authorization:`Bearer local-${tenant}`,'Content-Type':'application/json',...(key?{'Idempotency-Key':key}:{})},body:body?JSON.stringify(body):undefined});assert.equal(r.status,expect,await r.clone().text());let text=await r.text();try{return JSON.parse(text)}catch{return text}}
const token=String(Date.now());
const input={destination:'fixture://success',body:'local fixture payload',operation_key:'integration_'+token};
const t=await api('/v1/tasks',{method:'POST',body:input,key:token,expect:201});
assert.equal((await api('/v1/tasks',{method:'POST',body:input,key:token})).id,t.id);
await api('/v1/tasks',{method:'POST',body:{...input,body:'changed'},key:token,expect:409});
await api('/v1/tasks/'+t.id,{tenant:'beta',expect:404});
for(const destination of ['https://example.com','http://127.0.0.1','https://169.254.169.254','https://[::1]'])await api('/v1/tasks',{method:'POST',body:{...input,destination},key:token+destination,expect:422});
async function settled(id,status){for(let i=0;i<60;i++){let t=await api('/v1/tasks/'+id);if(t.status===status)return t;await new Promise(r=>setTimeout(r,250));}throw Error(`task ${id} did not reach ${status}`);}
let done=await settled(t.id,'succeeded');assert.equal(done.attempts.length,1);
const retry=await api('/v1/tasks',{method:'POST',body:{...input,destination:'fixture://retry'},key:token+'r',expect:201});
// retry fixture returns 503 first and permanent 400 second.
assert.equal((await settled(retry.id,'failed')).attempts.length,2);
const redrive=await api('/v1/tasks/'+retry.id+'/redrive',{method:'POST',key:token+'d',expect:201});assert.equal(redrive.parent,retry.id);assert.equal(redrive.input.operation_key,input.operation_key);
assert.equal((await api('/v1/tasks/'+retry.id+'/redrive',{method:'POST',key:token+'d'})).id,redrive.id);
const scheduled=await api('/v1/tasks',{method:'POST',body:{...input,run_at_ms:Date.now()+60000},key:token+'s',expect:201});await api('/v1/tasks/'+scheduled.id+'/cancel',{method:'POST'});assert.equal((await api('/v1/tasks/'+scheduled.id)).status,'cancelled');
const list=await api('/v1/tasks');assert.ok(list.tasks.some(x=>x.id===t.id));
console.log('PASS: durable create/idempotency/conflict, tenant isolation, fail-closed destinations, alarm→Queue→signed fixture→result, retry, redrive operation identity, cancel, list');
const future=await api('/v1/tasks',{method:'POST',body:{...input,run_at_ms:Date.now()+1000},key:token+'future',expect:201});assert.equal(future.status,'scheduled');assert.equal(future.attempts.length,0);await settled(future.id,'succeeded');
const unauthorized=await fetch(base+'/v1/tasks');assert.equal(unauthorized.status,401);
console.log('PASS: future schedule through persisted alarm; missing authentication rejected');
