import assert from 'node:assert/strict';
const base='http://127.0.0.1:8787';const headers={Authorization:'Bearer local-alpha','Content-Type':'application/json'};const key='slow-'+Date.now();
async function submit(key,input){let r=await fetch(base+'/v1/tasks',{method:'POST',headers:{...headers,'Idempotency-Key':key},body:JSON.stringify(input)});assert.equal(r.status,201);return r.json()}
const earlier=await submit(key+'-earlier',{destination:'fixture://success',body:'earlier',operation_key:key,run_at_ms:Date.now()+500});
const bytes=new TextEncoder().encode(JSON.stringify({destination:'fixture://success',body:'slow request fixture',operation_key:key}));
const body=new ReadableStream({start(c){c.enqueue(bytes.slice(0,12));setTimeout(()=>{c.enqueue(bytes.slice(12));c.close()},1800)}});
const response=await fetch(base+'/v1/tasks',{method:'POST',duplex:'half',headers:{...headers,'Idempotency-Key':key},body});assert.equal(response.status,201);const later=await response.json();
for(const task of [earlier,later]){let done=false;for(let i=0;i<60;i++){const r=await fetch(base+'/v1/tasks/'+task.id,{headers});const t=await r.json();if(t.status==='succeeded'){done=true;break}await new Promise(r=>setTimeout(r,250))}assert.ok(done,'alarm dispatch did not recover for '+task.id)}
console.log('PASS: slow streamed request body overlaps earlier alarm; both tasks durably accepted and delivered locally');
