import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {CanonicalProjects} from './projects.mjs';
import {trialProjectId} from '../../mcp/trial-client.mjs';
function fixture(t){
 const db=new DatabaseSync(':memory:');t.after(()=>db.close());let now=1000,sequence=0,failProvision=false,failRevoke=false;
 const calls=[],projects=new Map();let alarm,alarms=0;
 const storage={sql:{exec(q,...args){if(!args.length&&q.includes(';')){db.exec(q);return {toArray:()=>[]};}
  const statement=db.prepare(q);return {toArray:()=>statement.all(...args)};}},sync:async()=>{},setAlarm:async value=>{alarm=value;alarms++;}};
 const clientFor=(authority,revoke)=>{
  const id=authority.descriptor.bootstrap_id;calls.push({id,revoke});
  return {async provision(){projects.set(id,projects.get(id)??{remaining:100,expires:authority.descriptor.expires_at_ms});
   if(failProvision){failProvision=false;throw Error('transport_uncertain');}return {state:'active',project_id:trialProjectId(authority.descriptor)};},
   async scheduleHttp(task,key){const project=projects.get(id);assert.equal(task.operation_key,'unchanged');assert.equal(key,'original-idempotency');
    if(project.remaining===0)throw Error('api_quota_exhausted');project.remaining--;return {accepted:true};},
   async task(task){return {task,project:id};},async cancel(task){return {task,project:id};},
   async revoke(){if(failRevoke)throw Error('api_unavailable');projects.get(id).revoked=true;return {revoked:true};}};
 };
 const make=()=>new CanonicalProjects({storage,clientFor,releaseId:'local-fixture',clock:()=>now,entropy:()=> (++sequence).toString(16).padStart(64,'0')});
 let store=make();
 return {get store(){return store;},calls,projects,get alarm(){return alarm;},get alarms(){return alarms;},set now(value){now=value;},set failProvision(v){failProvision=v;},set failRevoke(v){failRevoke=v;},restart(){store=make();}};
}
test('connection/status does not allocate; one host project persists without secret disclosure',async t=>{
 const f=fixture(t);assert.deepEqual(await f.store.execute('host-a','project_status',{}),{state:'unprovisioned',quota_authority:'runlater-api'});assert.equal(f.calls.length,0);
 const first=await f.store.execute('host-a','create_project',{});f.restart();
 assert.deepEqual(await f.store.execute('host-a','create_project',{}),first);assert.equal(f.projects.size,1);
 assert.equal(first.remaining_attempts,null);assert.equal(first.trial_attempt_allocation,100);
 assert.equal(JSON.stringify(first).includes('capability'),false);
});
test('host identity selects project; cleanup is bounded and completed tombstones never rearm',async t=>{
 const f=fixture(t);const a=await f.store.execute('host-a','create_project',{}),b=await f.store.execute('host-b','create_project',{});
 assert.notEqual(a.project_id,b.project_id);
 assert.notDeepEqual(await f.store.execute('host-a','read_task',{task_id:'same'}),await f.store.execute('host-b','read_task',{task_id:'same'}));
 f.failRevoke=true;await f.store.tombstone('host-a',{hostRevoked:true});await f.store.tombstone('host-b',{hostRevoked:true});
 const before=f.calls.length;await f.store.cleanup();assert.equal(f.calls.length-before,1);
 f.failRevoke=false;await f.store.cleanup();await f.store.cleanup();
 const alarms=f.alarms;await f.store.tombstone('host-a',{hostRevoked:true});await f.store.tombstone('host-b',{hostRevoked:true});await f.store.cleanup();assert.equal(f.alarms,alarms);
});
test('unknown provision outcome reconciles original identity, expiry and idempotency',async t=>{
 const f=fixture(t);f.failProvision=true;
 await assert.rejects(f.store.execute('host-a','create_project',{}),/transport_uncertain/);
 const pending=await f.store.execute('host-a','project_status',{});assert.equal(pending.state,'pending');f.restart();
 const active=await f.store.execute('host-a','create_project',{});assert.equal(active.project_id,pending.project_id);assert.equal(active.expires_at_ms,pending.expires_at_ms);
 assert.equal(f.projects.size,1);assert.equal(new Set(f.calls.map(c=>c.id)).size,1);
});
test('API is sole quota authority and operation/idempotency values survive dispatch',async t=>{
 const f=fixture(t);await f.store.execute('host-a','create_project',{});
 const args={task:{operation_key:'unchanged'},idempotency_key:'original-idempotency'};
 await f.store.execute('host-a','schedule_http',args);
 const api=[...f.projects.values()][0];assert.equal(api.remaining,99);api.remaining=0;f.restart();
 await assert.rejects(f.store.execute('host-a','schedule_http',args),/api_quota_exhausted/);
 await f.store.execute('host-a','create_project',{});assert.equal(api.remaining,0);
 await assert.rejects(f.store.execute('host-a','schedule_http',{...args,project_id:'another'}),/arguments_rejected/);
});
test('project and host tombstones survive unavailable cleanup and runtime restart',async t=>{
 const f=fixture(t);const original=await f.store.execute('host-a','create_project',{});f.failRevoke=true;
 await f.store.tombstone('host-a',{hostRevoked:true});assert.ok(f.alarm);f.restart();
 assert.equal((await f.store.execute('host-a','project_status',{})).state,'revoked');
 await assert.rejects(f.store.execute('host-a','create_project',{}),/host_revoked/);
 await assert.rejects(f.store.execute('host-a','read_task',{task_id:'task_a'}),/host_revoked/);
 f.failRevoke=false;await f.store.cleanup();assert.equal((await f.store.execute('host-a','project_status',{})).cleanup_pending,false);
 assert.equal((await f.store.execute('host-a','project_status',{})).project_id,original.project_id);
});
test('original expiry denies dispatch and does not mint a replacement trial',async t=>{
 const f=fixture(t),original=await f.store.execute('host-a','create_project',{});f.now=original.expires_at_ms;f.restart();
 await assert.rejects(f.store.execute('host-a','create_project',{}),/identity_expired/);
 await assert.rejects(f.store.execute('host-a','read_task',{task_id:'task_a'}),/identity_expired/);
 assert.equal(f.projects.size,1);await f.store.tombstone('host-a');assert.equal((await f.store.execute('host-a','project_status',{})).cleanup_pending,false);
});
