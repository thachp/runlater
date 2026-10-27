// Public, deterministic local fixture credentials only. Never use these tokens outside the emulator.
import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
const base='http://127.0.0.1:8787',prefix='key'+Date.now(),issued=[],tasks=[];
const hash=t=>createHash('sha256').update(t).digest('hex');
const token=id=>`rl_local.alpha.${id}.public_fixture_secret_for_tests`;
async function api(path,{credential='local-alpha',method='GET',body,expected=200,key}={}){const r=await fetch(base+path,{method,headers:{Authorization:'Bearer '+credential,'Content-Type':'application/json',...(key?{'Idempotency-Key':key}:{})},body:body===undefined?undefined:JSON.stringify(body)});const text=await r.text();assert.equal(r.status,expected,text);try{return JSON.parse(text)}catch{return text}}
async function issue(name,permissions,extra={}){const id=prefix+'_'+name;const spec={key_id:id,token_sha256:hash(token(id)),permissions,not_before_ms:0,expires_at_ms:Date.now()+3600000,...extra};const view=await api('/v1/keys',{method:'POST',body:spec,expected:201});issued.push(id);assert.equal(view.key_id,id);assert.ok(!JSON.stringify(view).includes(spec.token_sha256));return {id,spec,credential:token(id)}}
async function settled(id,status){for(let i=0;i<80;i++){const t=await api('/v1/tasks/'+id);if(t.status===status)return t;await new Promise(r=>setTimeout(r,200))}throw Error('local task did not settle: '+id)}
try{
 const reader=await issue('read',['read']),writer=await issue('enqueue',['enqueue']),cancel=await issue('cancel',['cancel']),redrive=await issue('redrive',['redrive']),configure=await issue('configure',['configure']),manager=await issue('manage',['manage_keys']);
 await api('/v1/tasks',{credential:reader.credential});await api('/v1/queue',{credential:reader.credential});
 const input={destination:'fixture://success',body:'public local scoped fixture',operation_key:prefix,run_at_ms:Date.now()+60000};
 await api('/v1/tasks',{credential:reader.credential,method:'POST',body:input,key:prefix+'denied',expected:403});
 const t=await api('/v1/tasks',{credential:writer.credential,method:'POST',body:input,key:prefix,expected:201});tasks.push(t.id);assert.ok(!("input" in t));assert.ok(!("attempts" in t));
 await api('/v1/tasks/'+t.id,{credential:writer.credential,expected:403});
 await api('/v1/tasks/'+t.id+'/cancel',{credential:reader.credential,method:'POST',expected:403});
 const cancelled=await api('/v1/tasks/'+t.id+'/cancel',{credential:cancel.credential,method:'POST'});assert.ok(!('input' in cancelled));assert.ok(!('attempts' in cancelled));
 const limits=await api('/v1/queue');await api('/v1/queue',{credential:reader.credential,method:'PUT',body:limits,expected:403});await api('/v1/queue',{credential:configure.credential,method:'PUT',body:limits});
 await api('/v1/keys',{credential:reader.credential,expected:403});await api('/v1/keys',{credential:manager.credential});
 await api('/v1/keys',{credential:manager.credential,method:'POST',body:{...reader.spec,key_id:prefix+'_escalate'},expected:403});
 await api('/v1/tasks',{credential:reader.credential.replace('.alpha.','.beta.'),expected:401});
 const failure=await api('/v1/tasks',{credential:writer.credential,method:'POST',key:prefix+'fail',body:{...input,destination:'fixture://fail',run_at_ms:0},expected:201});tasks.push(failure.id);await settled(failure.id,'failed');
 await api('/v1/tasks/'+failure.id+'/redrive',{credential:cancel.credential,method:'POST',key:prefix+'redrive',expected:403});
 const replay=await api('/v1/tasks/'+failure.id+'/redrive',{credential:redrive.credential,method:'POST',key:prefix+'redrive',expected:201});tasks.push(replay.id);
 await api('/v1/keys/'+reader.id+'/revoke',{method:'POST'});await api('/v1/tasks',{credential:reader.credential,expected:401});
 const revoked=await api('/v1/keys',{method:'POST',body:reader.spec});assert.ok(revoked.revoked_at_ms);await api('/v1/tasks',{credential:reader.credential,expected:401});
 const old=await issue('old',['read']);const newId=prefix+'_new';const cutoff=Date.now()+1200;const rotation={new_key:{...old.spec,key_id:newId,token_sha256:hash(token(newId))},revoke_old_at_ms:cutoff};
 const rotated=await api('/v1/keys/'+old.id+'/rotate',{method:'POST',body:rotation,expected:201});issued.push(newId);assert.equal(rotated.rotated_from,old.id);await api('/v1/tasks',{credential:old.credential});await api('/v1/tasks',{credential:token(newId)});
 await new Promise(r=>setTimeout(r,Math.max(0,cutoff-Date.now()+30)));await api('/v1/tasks',{credential:old.credential,expected:401});await api('/v1/tasks',{credential:token(newId)});
 assert.equal((await api('/v1/keys/'+old.id+'/rotate',{method:'POST',body:rotation})).key_id,newId);
 const publicData=JSON.stringify([await api('/v1/keys'),await api('/v1/keys/audit')]);for(const id of issued){assert.ok(!publicData.includes(token(id)));assert.ok(!publicData.includes(hash(token(id))))}assert.ok(!publicData.includes(hash('local-alpha')));assert.ok(!publicData.includes('token_sha256'));
 console.log('PASS: project-scoped verification, six separate permissions, no privilege escalation, cross-project denial, immediate revoke, replay without resurrection, atomic rotation/overlap/cutover, and redacted key/audit views');
}finally{for(const id of tasks)await api('/v1/tasks/'+id+'/cancel',{method:'POST'});for(const id of issued)await api('/v1/keys/'+id+'/revoke',{method:'POST'});}
