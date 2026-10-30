import {createHash} from 'node:crypto';
const canonical=value=>Array.isArray(value)?value.map(canonical):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])):value;
const sha=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const integer=value=>Number.isSafeInteger(value)&&value>=0;
const shape=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.split(',').sort().join();
const reject=()=>{throw Error('migration_inventory_rejected');};
// Pure migration gate: accepts only redacted state inventory, never bearer tokens,
// private keys, trial capabilities, session cookies or credential imports. Callers
// must obtain authoritative inventory separately under action-time authorization.
export function replacementPlan(inventory){
 if(!shape(inventory,'version,release_id,lifetime_projects_used,projects,oauth_grants')||inventory.version!==1||typeof inventory.release_id!=='string'||!/^[A-Za-z0-9_-]{1,32}$/.test(inventory.release_id)||!integer(inventory.lifetime_projects_used)||inventory.lifetime_projects_used>10||!Array.isArray(inventory.projects)||inventory.projects.length!==inventory.lifetime_projects_used||!Array.isArray(inventory.oauth_grants))reject();
 const projects=new Set();
 for(const p of inventory.projects){
  if(!shape(p,'project_id,kind,issued_at_ms,expires_at_ms,remaining_attempt_units,identity_state_sha256,task_state_sha256,quota_state_sha256,revocation_state_sha256')||!/^p_[a-f0-9]{60}$/.test(p.project_id)||projects.has(p.project_id)||!['trial','owner'].includes(p.kind)||![p.issued_at_ms,p.expires_at_ms,p.remaining_attempt_units].every(integer)||p.expires_at_ms<=p.issued_at_ms||![p.identity_state_sha256,p.task_state_sha256,p.quota_state_sha256,p.revocation_state_sha256].every(hex))reject();
  if(p.kind==='trial'&&(p.expires_at_ms!==p.issued_at_ms+604800000||p.remaining_attempt_units>100))reject();
  projects.add(p.project_id);
 }
 const grants=new Set();
 for(const g of inventory.oauth_grants){
  if(!shape(g,'grant_sha256,project_id,expires_at_ms,revoked')||!hex(g.grant_sha256)||grants.has(g.grant_sha256)||!projects.has(g.project_id)||!integer(g.expires_at_ms)||typeof g.revoked!=='boolean')reject();
  grants.add(g.grant_sha256);
 }
 const retained=structuredClone(inventory);
 retained.projects.sort((a,b)=>a.project_id.localeCompare(b.project_id));
 retained.oauth_grants.sort((a,b)=>a.grant_sha256.localeCompare(b.grant_sha256));
 return {version:1,source_inventory_sha256:sha(retained),retained,
  target_authentication:'better-auth-agent-auth',legacy_routes:'retire_at_explicit_cutover',
  oauth_grant_conversion:'unsupported_reconnect_and_prove_project_control',
  new_project_allocations:0,new_capability_grants:[],trial_budget_reset:false,
  task_rewrite:false,delete_legacy_state:false};
}
export function verifyRetainedState(plan,observed){
 const expected=replacementPlan(plan.retained),actual=replacementPlan(observed);
 if(sha(plan)!==sha(expected)||plan.source_inventory_sha256!==expected.source_inventory_sha256||expected.source_inventory_sha256!==actual.source_inventory_sha256)throw Error('retained_state_drift');
 return {preserved:true,source_inventory_sha256:actual.source_inventory_sha256};
}
