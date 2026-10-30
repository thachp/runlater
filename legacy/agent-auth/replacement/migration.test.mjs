import {test} from 'node:test';
import assert from 'node:assert/strict';
import {replacementPlan,verifyRetainedState} from './migration.mjs';
const inventory=()=>({version:1,release_id:'fixture',lifetime_projects_used:1,projects:[{project_id:'p_'+'a'.repeat(60),kind:'trial',issued_at_ms:1000,expires_at_ms:604801000,remaining_attempt_units:37,identity_state_sha256:'1'.repeat(64),task_state_sha256:'2'.repeat(64),quota_state_sha256:'3'.repeat(64),revocation_state_sha256:'4'.repeat(64)}],oauth_grants:[{grant_sha256:'5'.repeat(64),project_id:'p_'+'a'.repeat(60),expires_at_ms:604801000,revoked:true}]});
test('replacement plan preserves tasks, identity, quota and revocations without minting grants',()=>{
 const input=inventory(),before=structuredClone(input),plan=replacementPlan(input);
 assert.deepEqual(input,before);assert.equal(plan.new_project_allocations,0);assert.deepEqual(plan.new_capability_grants,[]);
 assert.equal(plan.oauth_grant_conversion,'unsupported_reconnect_and_prove_project_control');
 assert.equal(verifyRetainedState(plan,input).preserved,true);
});
test('cutover gate rejects changed expiry, quota, identity, tasks, revocations or grant state',()=>{
 const before=inventory(),plan=replacementPlan(before);
 for(const mutate of [x=>x.projects[0].remaining_attempt_units=100,x=>x.projects[0].task_state_sha256='a'.repeat(64),x=>x.projects[0].identity_state_sha256='a'.repeat(64),x=>x.projects[0].revocation_state_sha256='a'.repeat(64),x=>x.oauth_grants[0].revoked=false,x=>x.projects[0].expires_at_ms++]){
  const after=structuredClone(before);mutate(after);assert.throws(()=>verifyRetainedState(plan,after));
 }
});
test('reject hidden credential imports, omitted lifetime slots and invalid trial limits',()=>{
 for(const mutate of [x=>x.oauth_grants[0].access_token='secret',x=>x.projects=[],x=>x.projects[0].remaining_attempt_units=101,x=>x.projects[0].issued_at_ms++,x=>x.projects.push({...x.projects[0]})]){
  const input=inventory();mutate(input);assert.throws(()=>replacementPlan(input));
 }
});

test('cutover plan cannot be amended to mint grants or delete retained state',()=>{
 const input=inventory(),plan=replacementPlan(input);
 assert.throws(()=>verifyRetainedState({...plan,delete_legacy_state:true},input));
 assert.throws(()=>verifyRetainedState({...plan,new_capability_grants:['http_schedule']},input));
 const reordered={oauth_grants:input.oauth_grants,projects:input.projects,release_id:input.release_id,lifetime_projects_used:input.lifetime_projects_used,version:1};
 assert.equal(verifyRetainedState(plan,reordered).preserved,true);
});
