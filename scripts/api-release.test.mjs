import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {canonical,digest,validate,uploadedVersion,release,deployExisting} from './api-release.mjs';
function fixture(){
 const c={name:'runlater-public-api',main:'build/worker/shim.mjs',compatibility_date:'2026-10-27',compatibility_flags:['global_fetch_strictly_public'],workers_dev:false,preview_urls:false,limits:{cpu_ms:50},observability:{enabled:false},durable_objects:{bindings:[{name:'ADMISSION',class_name:'AdmissionRegistry'},{name:'PROJECTS',class_name:'InvitationProject'}]},queues:{producers:[{binding:'BETA_READY',queue:'runlater-public-ready'}]},ratelimits:[{name:'BETA_IP_RATE',namespace_id:'1001',simple:{limit:60,period:60}},{name:'BETA_REG_IP_RATE',namespace_id:'1002',simple:{limit:6,period:60}}],vars:{PUBLIC_BETA_ENABLED:'operator-approved',PUBLIC_BETA_PROFILE:JSON.stringify({release_id:'test',opens_at_ms:1000,closes_at_ms:2000,callback_end_sec:1000000}),BETA_REVOKED_PROJECTS:'[]',BETA_READY_QUEUE:'runlater-public-ready'}};
 return {c,a:{worker:c.name,account_id:'a'.repeat(32),config_sha256:digest(c),settings_sha256:'b'.repeat(64)},e:{RUNLATER_RELEASE_ENABLED:'true',GITHUB_REPOSITORY:'thachp/runlater',RELEASE_SHA:'c'.repeat(40)}};
}
test('canonical digest is key-order stable',()=>assert.equal(digest({b:2,a:1}),digest({a:1,b:2})));
test('valid existing-resource production config accepted',()=>{const {c,a,e}=fixture();validate(c,a,e)});
for(const [label,mutate] of Object.entries({fixture:c=>c.vars.LOCAL_FIXTURES='true',alpha:c=>c.name='runlater-alpha-api',root:c=>c.main='src/lib.rs',route:c=>c.routes=['api.runlater.io/*'],migration:c=>c.migrations=[{tag:'new'}],build:c=>c.build={command:'wrangler deploy'},consumer:c=>c.queues.consumers=[{queue:'other'}],preview:c=>c.preview_urls=true,cpu:c=>c.limits.cpu_ms=500,flags:c=>c.compatibility_flags=[],secret:c=>c.vars.BETA_CALLBACK_MASTER='test'}))test(`reject ${label} even with refreshed config approval`,()=>{const {c,a,e}=fixture();mutate(c);a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));});
test('reject disabled, wrong repository, missing approvals and drift',()=>{const {c,a,e}=fixture();for(const env of [{...e,RUNLATER_RELEASE_ENABLED:'false'},{...e,GITHUB_REPOSITORY:'other/repo'},{...e,RELEASE_SHA:'main'}])assert.throws(()=>validate(c,a,env));assert.throws(()=>validate(c,{},e));c.compatibility_date='2026-10-28';assert.throws(()=>validate(c,a,e));});
test('release fails before network when unset',async()=>await assert.rejects(release({})));
const record={type:'version-upload',worker_name:'runlater-public-api',version_id:'01234567-0123-0123-0123-0123456789ab'};
test('only exact upload result selects version',()=>{assert.equal(uploadedVersion(JSON.stringify(record)),record.version_id);for(const x of ['',JSON.stringify({...record,worker_name:'runlater-alpha-api'}),JSON.stringify({...record,preview_url:'https://test'}),JSON.stringify(record)+'\n'+JSON.stringify(record)])assert.throws(()=>uploadedVersion(x));});
test('workflow has CI gating, fixed target environment, no PR secrets or cancellation',()=>{const w=readFileSync('.github/workflows/release-api.yml','utf8');assert.match(w,/workflow_run:/);assert.match(w,/conclusion == 'success'/);assert.match(w,/event == 'push'/);assert.match(w,/environment: runlater-public-api/);assert.match(w,/cancel-in-progress: false/);assert.match(w,/persist-credentials: false/);assert.doesNotMatch(w,/pull_request_target|wrangler deploy|workflow_dispatch/);assert.equal(canonical({b:1,a:2}),'{"a":2,"b":1}');});

test('provider flow checks twice and promotes only exact returned version',async()=>{
 const settings={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]}, a={settings_sha256:digest(settings)}, events=[];
 const get=async path=>{events.push(path);return path==='/settings'?settings:{deployments:['old']}};
 const id=await deployExisting(a,get,async()=>{events.push('upload');return JSON.stringify(record)},async id=>events.push(id));
 assert.equal(id,record.version_id);assert.deepEqual(events,['/settings','/deployments','upload','/settings','/deployments',id]);
});
for(const failure of ['absent','secret','settings-drift','deployment-drift','uncertain-upload','uncertain-promote'])test(`no unsafe retry for ${failure}`,async()=>{
 const settings={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]}, a={settings_sha256:digest(settings)};let gets=0,uploads=0,promotes=0;
 const get=async path=>{gets++;if(failure==='absent')throw Error('404');if(path==='/settings')return failure==='secret'?{bindings:[]}:failure==='settings-drift'&&gets>2?{}:settings;return {deployments:failure==='deployment-drift'&&gets>2?['other']:['old']}};
 await assert.rejects(deployExisting(a,get,async()=>{uploads++;if(failure==='uncertain-upload')throw Error('timeout');return JSON.stringify(record)},async()=>{promotes++;if(failure==='uncertain-promote')throw Error('timeout')}));
 assert.ok(uploads<=1);assert.equal(promotes,failure==='uncertain-promote'?1:0);
});

test('main advancing during upload blocks promotion',async()=>{
 const s={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]};let checks=0,promoted=false;
 await assert.rejects(deployExisting({settings_sha256:digest(s)},async path=>path==='/settings'?s:{deployments:['old']},async()=>JSON.stringify(record),async()=>{promoted=true},async()=>++checks===1));
 assert.equal(promoted,false);assert.equal(checks,2);
});

test('repository automatic trigger cannot satisfy separate execution gate',()=>{
 const {c,a,e}=fixture();const repositoryOnly={...e,RUNLATER_AUTODEPLOY_ENABLED:'true'};delete repositoryOnly.RUNLATER_RELEASE_ENABLED;
 assert.throws(()=>validate(c,a,repositoryOnly));
 const w=readFileSync('.github/workflows/release-api.yml','utf8');
 assert.match(w,/vars\.RUNLATER_AUTODEPLOY_ENABLED == 'true'/);
 assert.match(w,/RUNLATER_RELEASE_ENABLED: \$\{\{ vars\.RUNLATER_RELEASE_ENABLED \}\}/);
 assert.doesNotMatch(w,/vars\.RUNLATER_RELEASE_ENABLED == 'true'/);
});
