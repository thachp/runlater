import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {spawnSync} from 'node:child_process';
const workerTag='d'.repeat(32);
import {canonical,digest,validate,uploadedVersion,release,deployExisting,verifyHealth,uploadArguments,runWrangler,checkSecretCollisions,settingsDigest} from './api-release.mjs';
function fixture(){
 const c={name:'runlater-public-api',main:'build/worker/shim.mjs',version_metadata:{binding:'RELEASE_VERSION'},compatibility_date:'2026-10-27',compatibility_flags:['global_fetch_strictly_public'],workers_dev:false,preview_urls:false,limits:{cpu_ms:50},observability:{enabled:false},durable_objects:{bindings:[{name:'ADMISSION',class_name:'AdmissionRegistry'},{name:'PROJECTS',class_name:'InvitationProject'}]},queues:{producers:[{binding:'BETA_READY',queue:'runlater-public-ready'}]},ratelimits:[{name:'BETA_IP_RATE',namespace_id:'1001',simple:{limit:60,period:60}},{name:'BETA_REG_IP_RATE',namespace_id:'1002',simple:{limit:6,period:60}}],vars:{PUBLIC_BETA_ENABLED:'operator-approved',PUBLIC_BETA_PROFILE:JSON.stringify({release_id:'test',opens_at_ms:1000,closes_at_ms:2000,callback_end_sec:1000000}),BETA_REVOKED_PROJECTS:'[]',BETA_READY_QUEUE:'runlater-public-ready'}};
 return {c,a:{worker:c.name,worker_tag:workerTag,settings_schema:'runtime-v1',account_id:'a'.repeat(32),config_sha256:digest(c),settings_sha256:'b'.repeat(64)},e:{RUNLATER_RELEASE_ENABLED:'true',GITHUB_REPOSITORY:'thachp/runlater',RELEASE_SHA:'c'.repeat(40)}};
}
test('canonical digest is key-order stable',()=>assert.equal(digest({b:2,a:1}),digest({a:1,b:2})));
test('valid existing-resource production config accepted',()=>{const {c,a,e}=fixture();validate(c,a,e)});
for(const [label,mutate] of Object.entries({fixture:c=>c.vars.LOCAL_FIXTURES='true',alpha:c=>c.name='runlater-alpha-api',root:c=>c.main='src/lib.rs',route:c=>c.routes=['api.runlater.io/*'],migration:c=>c.migrations=[{tag:'new'}],build:c=>c.build={command:'wrangler deploy'},consumer:c=>c.queues.consumers=[{queue:'other'}],preview:c=>c.preview_urls=true,cpu:c=>c.limits.cpu_ms=500,flags:c=>c.compatibility_flags=[],secret:c=>c.vars.BETA_CALLBACK_MASTER='test'}))test(`reject ${label} even with refreshed config approval`,()=>{const {c,a,e}=fixture();mutate(c);a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));});
test('reject disabled, wrong repository, missing approvals and drift',()=>{const {c,a,e}=fixture();for(const env of [{...e,RUNLATER_RELEASE_ENABLED:'false'},{...e,GITHUB_REPOSITORY:'other/repo'},{...e,RELEASE_SHA:'main'}])assert.throws(()=>validate(c,a,env));assert.throws(()=>validate(c,{},e));c.compatibility_date='2026-10-28';assert.throws(()=>validate(c,a,e));});
test('release fails before network when unset',async()=>await assert.rejects(release({})));
const record={worker_tag:workerTag,type:'version-upload',worker_name:'runlater-public-api',version_id:'01234567-0123-0123-0123-0123456789ab'};
test('only exact upload result selects version',()=>{assert.equal(uploadedVersion(JSON.stringify(record),workerTag),record.version_id);for(const x of ['',JSON.stringify({...record,worker_name:'runlater-alpha-api'}),JSON.stringify({...record,preview_url:'https://test'}),JSON.stringify(record)+'\n'+JSON.stringify(record)])assert.throws(()=>uploadedVersion(x,workerTag));});
test('workflow has CI gating, fixed target environment, no PR secrets or cancellation',()=>{const w=readFileSync('.github/workflows/release-api.yml','utf8');assert.match(w,/workflow_run:/);assert.match(w,/conclusion == 'success'/);assert.match(w,/event == 'push'/);assert.match(w,/environment: runlater-public-api/);assert.match(w,/cancel-in-progress: false/);assert.match(w,/persist-credentials: false/);assert.doesNotMatch(w,/pull_request_target|wrangler deploy|workflow_dispatch/);assert.equal(canonical({b:1,a:2}),'{"a":2,"b":1}');});

test('provider flow checks twice and promotes only exact returned version',async()=>{
 const settings={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]}, a={worker_tag:workerTag,settings_sha256:digest(settings)}, events=[];
 let promoted=false;const get=async path=>{events.push(path);return path==='/settings'?settings:path==='/secrets'?settings.bindings:promoted?{deployments:[{versions:[{version_id:record.version_id,percentage:100}]}]}:{deployments:['old']}};
 const id=await deployExisting(a,get,async()=>{events.push('upload');return JSON.stringify(record)},async id=>{events.push(id);promoted=true},undefined,undefined,undefined,fixture().c);
 assert.equal(id,record.version_id);assert.deepEqual(events,['/settings','/secrets','/deployments','upload','/settings','/secrets','/deployments',id,'/deployments']);
});
for(const failure of ['absent','secret','settings-drift','deployment-drift','uncertain-upload','uncertain-promote'])test(`no unsafe retry for ${failure}`,async()=>{
 const settings={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]}, a={worker_tag:workerTag,settings_sha256:digest(settings)};let uploads=0,promotes=0;const reads={};
 const get=async path=>{reads[path]=(reads[path]??0)+1;if(failure==='absent')throw Error('404');if(path==='/settings')return failure==='secret'?{bindings:[]}:failure==='settings-drift'&&reads[path]>1?{}:settings;if(path==='/secrets')return settings.bindings;return {deployments:failure==='deployment-drift'&&reads[path]>1?['other']:['old']}};
 await assert.rejects(deployExisting(a,get,async()=>{uploads++;if(failure==='uncertain-upload')throw Error('timeout');return JSON.stringify(record)},async()=>{promotes++;if(failure==='uncertain-promote')throw Error('timeout')},undefined,undefined,undefined,fixture().c));
 assert.ok(uploads<=1);assert.equal(promotes,failure==='uncertain-promote'?1:0);
});

test('main advancing during upload blocks promotion',async()=>{
 const s={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]};let checks=0,promoted=false;
 await assert.rejects(deployExisting({worker_tag:workerTag,settings_sha256:digest(s)},async path=>path==='/settings'?s:path==='/secrets'?s.bindings:{deployments:['old']},async()=>JSON.stringify(record),async()=>{promoted=true},async()=>++checks===1,undefined,undefined,fixture().c));
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

test('upload receipt survives later drift; wrong active version never succeeds',async()=>{
 const s={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]};const receipts=[];let promoted=false;
 await assert.rejects(deployExisting({worker_tag:workerTag,settings_sha256:digest(s)},async path=>path==='/settings'?s:path==='/secrets'?s.bindings:{deployments:[{versions:[{version_id:'old',percentage:100}]}]},async()=>JSON.stringify(record),async()=>{promoted=true},async()=>true,id=>receipts.push(id),undefined,fixture().c));
 assert.equal(promoted,true);assert.deepEqual(receipts,[record.version_id]);
});
test('public host must serve exact uploaded beta version, not alpha health',()=>{
 verifyHealth({mode:'public_free_beta',configured:true,version_id:record.version_id},record.version_id);
 for(const body of [{mode:'restricted_alpha',configured:true},{mode:'public_free_beta',configured:true,version_id:'old'},{mode:'public_free_beta',configured:false,version_id:record.version_id}])assert.throws(()=>verifyHealth(body,record.version_id));
});

const service=origin=>({id:'runlater-public-api',default_environment:{environment:'production',script:{id:'runlater-public-api',tag:workerTag,last_deployed_from:origin}}});
test('approved API origin avoids pinned Wrangler unconditional strict refusal',async()=>{
 const {a,e}=fixture(),args=uploadArguments('/tmp/profile.json',e.RELEASE_SHA,service('api'),a);
 assert.equal(args.includes('--strict'),false);
 const source=readFileSync('node_modules/wrangler/wrangler-dist/cli.js','utf8');
 const start=source.indexOf('function getDeployConfirmFunction(options) {'),end=source.indexOf('\nvar init_deploy_confirm',start);
 assert.ok(start>=0&&end>start,'pinned Wrangler confirmation seam changed');
 const sandbox={isNonInteractiveOrCI:()=>true,logger:{error:()=>{}},process:{exitCode:0},confirm:async()=>{throw Error('unexpected prompt');}};
 const confirm=vm.runInNewContext('('+source.slice(start,end)+')',sandbox);
 assert.equal(await confirm({strictMode:true})('Would you like to continue?'),false);
 sandbox.process.exitCode=0;
 assert.equal(await confirm({strictMode:args.includes('--strict')})('Would you like to continue?'),true);
 assert.equal(sandbox.process.exitCode,0);
});
test('non-API origins retain strict mode; foreign or incomplete Worker identity is refused',()=>{
 const {a,e}=fixture();
 for(const origin of ['wrangler','dash','unknown',undefined])assert.ok(uploadArguments('/tmp/profile.json',e.RELEASE_SHA,service(origin),a).includes('--strict'));
 for(const mutate of [s=>s.id='other',s=>s.default_environment.environment='staging',s=>s.default_environment.script.id='other',s=>s.default_environment.script.tag='e'.repeat(32),s=>delete s.default_environment.script]){
  const s=service('api');mutate(s);assert.throws(()=>uploadArguments('/tmp/profile.json',e.RELEASE_SHA,s,a));
 }
 assert.throws(()=>uploadArguments('/tmp/profile.json',e.RELEASE_SHA,{},a));
});
test('immutable Worker tag is mandatory in approval and upload receipts match it',()=>{
 const {c,a,e}=fixture();for(const tag of [undefined,'not-a-tag','e'.repeat(31)])assert.throws(()=>validate(c,{...a,worker_tag:tag},e));
 assert.equal(uploadedVersion(JSON.stringify(record),workerTag),record.version_id);
 assert.throws(()=>uploadedVersion(JSON.stringify(record)));
 assert.throws(()=>uploadedVersion(JSON.stringify({...record,worker_tag:'e'.repeat(32)}),workerTag));
});
test('fixed phase breadcrumbs locate failure without serializing provider errors',async()=>{
 const phases=[];
 await assert.rejects(deployExisting({},async()=>{throw Error('PRIVATE-SENTINEL');},async()=>{throw Error('unexpected upload');},async()=>{},async()=>true,()=>{},phase=>phases.push(phase),fixture().c));
 assert.deepEqual(phases,['source_preflight','settings_preflight']);
 assert.doesNotMatch(JSON.stringify(phases),/PRIVATE-SENTINEL/);
});
test('child failure reports numeric status only and preserves uncertainty without raw output',()=>{
 const statuses=[];
 assert.throws(()=>runWrangler(['versions','upload'],{},'/tmp/output',()=>{const e=Error('PRIVATE-SENTINEL');e.status=1;e.stdout='PRIVATE-SENTINEL';e.stderr='PRIVATE-SENTINEL';throw e;},x=>statuses.push(x)),/^Error: wrangler_child_failed$/);
 assert.deepEqual(statuses,[1]);
 assert.throws(()=>runWrangler([],{},'/tmp/output',()=>{throw {status:'PRIVATE-SENTINEL'};},x=>statuses.push(x)),/wrangler_child_failed/);
 assert.deepEqual(statuses,[1,'unknown']);
});
test('actual release entry does not print malformed private configuration',()=>{
 const child=spawnSync(process.execPath,['scripts/api-release.mjs'],{env:{RUNLATER_RELEASE_CONFIG:'PRIVATE-SENTINEL-not-json'},encoding:'utf8'});
 assert.equal(child.status,1);assert.doesNotMatch(child.stdout+child.stderr,/PRIVATE-SENTINEL/);assert.match(child.stderr,/Release stopped/);
});
test('a valid uploaded UUID is retained before tag or preview rejection without promotion',async()=>{
 const s={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]},a={worker_tag:workerTag,settings_sha256:digest(s)};
 for(const extra of [{worker_tag:'e'.repeat(32)},{preview_url:'https://unexpected.invalid'}]){
  const receipts=[];let promoted=false;
  await assert.rejects(deployExisting(a,async path=>path==='/settings'?s:path==='/secrets'?s.bindings:{deployments:['old']},async()=>JSON.stringify({...record,...extra}),async()=>{promoted=true;},async()=>true,id=>receipts.push(id),undefined,fixture().c));
  assert.deepEqual(receipts,[record.version_id]);assert.equal(promoted,false);
 }
});

test('remote secret collision is rejected before upload even with an approved matching baseline',async()=>{
 const {c,a}=fixture();
 const secrets=[{name:'BETA_CALLBACK_MASTER',type:'secret_text'},{name:'PUBLIC_BETA_PROFILE',type:'secret_text'}];
 const settings={bindings:secrets};a.settings_sha256=digest(settings);
 let uploads=0,promotes=0;
 const get=async path=>path==='/settings'?settings:path==='/secrets'?secrets:{deployments:[{versions:[{version_id:record.version_id,percentage:100}]}]};
 await assert.rejects(deployExisting(a,get,async()=>{uploads++;return JSON.stringify(record);},async()=>{promotes++;},async()=>true,()=>{},()=>{},c));
 assert.equal(uploads,0);assert.equal(promotes,0);
});

for(const name of ['BETA_READY_QUEUE','BETA_REVOKED_PROJECTS','PUBLIC_BETA_ENABLED','PUBLIC_BETA_PROFILE','ADMISSION','PROJECTS','BETA_READY','BETA_IP_RATE','BETA_REG_IP_RATE','RELEASE_VERSION'])test(`secret collision with ${name} blocks upload from either metadata source`,async()=>{
 for(const source of ['settings','secrets']){
  const {c,a}=fixture(),master={name:'BETA_CALLBACK_MASTER',type:'secret_text'},collision={name,type:'secrets_store_secret'};
  const settings={bindings:[master,...(source==='settings'?[collision]:[])]},secrets=[master,...(source==='secrets'?[collision]:[])];
  a.settings_sha256=digest(settings);let uploads=0,promotes=0;
  await assert.rejects(deployExisting(a,async path=>path==='/settings'?settings:path==='/secrets'?secrets:{deployments:['old']},async()=>{uploads++;return JSON.stringify(record);},async()=>{promotes++;},undefined,undefined,undefined,c));
  assert.equal(uploads,0);assert.equal(promotes,0);
 }
});
test('pinned Wrangler reports a real secret overwrite which non-strict confirmation accepts',async()=>{
 const {c}=fixture(),secrets=[{name:'PUBLIC_BETA_PROFILE',type:'secret_text'}];
 const source=readFileSync('node_modules/wrangler/wrangler-dist/cli.js','utf8');
 const start=source.indexOf('async function checkRemoteSecretsOverride('),end=source.indexOf('\nvar init_check_remote_secrets_override',start);
 assert.ok(start>=0&&end>start,'pinned secret check seam changed');
 const check=vm.runInNewContext('(()=>{'+source.slice(start,end)+';return checkRemoteSecretsOverride;})()',{fetchSecrets:async()=>secrets,isWorkerNotFoundError:()=>false});
 const conflict=await check(c,'runlater-public-api','a'.repeat(32));
 assert.equal(conflict.override,true);assert.match(conflict.deployErrorMessage,/replace/);
 const confirmStart=source.indexOf('function getDeployConfirmFunction(options) {'),confirmEnd=source.indexOf('\nvar init_deploy_confirm',confirmStart);
 const confirm=vm.runInNewContext('('+source.slice(confirmStart,confirmEnd)+')',{isNonInteractiveOrCI:()=>true,logger:{error:()=>{}},process:{exitCode:0},confirm:async()=>false});
 assert.equal(await confirm({strictMode:false})('Would you like to continue?'),true);
 assert.throws(()=>checkSecretCollisions(c,{bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]},secrets));
});
test('missing or malformed secret metadata fails closed',()=>{
 const {c}=fixture(),settings={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]};
 for(const secrets of [undefined,{},[{name:''}],[{name:42}]])assert.throws(()=>checkSecretCollisions(c,settings,secrets));
 assert.throws(()=>checkSecretCollisions(undefined,settings,[]));
 assert.throws(()=>checkSecretCollisions(c,{bindings:[{type:'secret_key'}]},[]));
});
test('secret-name drift after upload blocks promotion while retaining the version receipt',async()=>{
 const {c,a}=fixture(),master={name:'BETA_CALLBACK_MASTER',type:'secret_text'},settings={bindings:[master]};a.settings_sha256=digest(settings);
 for(const later of [[master,{name:'UNEXPECTED_SECRET'}],[],[master,{name:'PUBLIC_BETA_PROFILE'}]]){
  let secretReads=0,uploads=0,promotes=0;const receipts=[];
  const get=async path=>path==='/settings'?settings:path==='/secrets'?(++secretReads===1?[master]:later):{deployments:['old']};
  await assert.rejects(deployExisting(a,get,async()=>{uploads++;return JSON.stringify(record);},async()=>{promotes++;},undefined,id=>receipts.push(id),undefined,c));
  assert.equal(uploads,1);assert.equal(promotes,0);assert.deepEqual(receipts,[record.version_id]);
 }
});
test('unchanged secret-name sets tolerate provider list reordering',async()=>{
 const {c,a}=fixture(),master={name:'BETA_CALLBACK_MASTER',type:'secret_text'},extra={name:'UNUSED_SECRET'},settings={bindings:[master]};a.settings_sha256=digest(settings);
 let reads=0,promoted=false;
 const get=async path=>path==='/settings'?settings:path==='/secrets'?(++reads===1?[master,extra]:[extra,master]):{deployments:promoted?[{versions:[{version_id:record.version_id,percentage:100}]}]:['old']};
 assert.equal(await deployExisting(a,get,async()=>JSON.stringify(record),async()=>{promoted=true;},undefined,undefined,undefined,c),record.version_id);
 assert.equal(promoted,true);
});
test('master absent from fresh secret listing prevents any upload',async()=>{
 const {c,a}=fixture(),s={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]};a.settings_sha256=digest(s);let uploads=0;
 await assert.rejects(deployExisting(a,async path=>path==='/settings'?s:path==='/secrets'?[]:{deployments:['old']},async()=>{uploads++;return JSON.stringify(record);},async()=>{},undefined,undefined,undefined,c));
 assert.equal(uploads,0);
});
test('version identity labels in latest-uploaded settings do not reject an approved code-only candidate',async()=>{
 const {c,a}=fixture();const observed=JSON.parse(readFileSync('scripts/fixtures/release-version-settings.json'));
 const before=structuredClone(observed.staged);delete before.annotations;
 const after={...structuredClone(before),annotations:{'workers/message':'Reviewed main '+'e'.repeat(40),'workers/tag':'e'.repeat(12),'workers/triggered_by':'version_upload'}};
 a.settings_sha256=digest(before);let uploaded=false,promoted=false;
 const secrets=[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}];
 const get=async path=>path==='/settings'?(uploaded?after:before):path==='/secrets'?secrets:{deployments:promoted?[{versions:[{version_id:record.version_id,percentage:100}]}]:[{versions:[{version_id:'old',percentage:100}]}]};
 const id=await deployExisting(a,get,async()=>{uploaded=true;return JSON.stringify(record);},async()=>{promoted=true;},undefined,undefined,undefined,c);
 assert.equal(id,record.version_id);assert.equal(promoted,true);
});

test('observed staged settings have a stable golden fingerprint without mutating the snapshot',()=>{
 const f=JSON.parse(readFileSync('scripts/fixtures/release-version-settings.json')),original=structuredClone(f.staged);
 assert.equal(settingsDigest(f.staged),f.expected_staged_runtime_sha256);
 const relabelled=structuredClone(f.staged);relabelled.annotations={'workers/message':'Reviewed main '+'e'.repeat(40),'workers/tag':'e'.repeat(12),'workers/triggered_by':'version_upload'};
 assert.notEqual(digest(f.staged),digest(relabelled));assert.equal(settingsDigest(f.staged),settingsDigest(relabelled));
 assert.deepEqual(f.staged,original);
 // The explicitly reviewed first binding transition still needs a new baseline.
 assert.notEqual(settingsDigest(f.before),settingsDigest(f.staged));
});
for(const [name,mutate]of Object.entries({
 namespace:s=>s.bindings.find(b=>b.name==='ADMISSION').namespace_id='9'.repeat(32),
 queue:s=>s.bindings.find(b=>b.name==='BETA_READY').queue_name='foreign-queue',
 rate:s=>s.bindings.find(b=>b.name==='BETA_IP_RATE').simple.limit=600,
 profile:s=>s.bindings.find(b=>b.name==='PUBLIC_BETA_PROFILE').text='different-profile',
 secret_type:s=>s.bindings.find(b=>b.name==='BETA_CALLBACK_MASTER').type='plain_text',
 extra_binding:s=>s.bindings.push({name:'UNEXPECTED_BINDING',type:'secret_text'}),
 cpu:s=>s.limits.cpu_ms=500,
 flags:s=>s.compatibility_flags=[],
 date:s=>s.compatibility_date='2026-10-28',
 logpush:s=>s.logpush=true,
 tails:s=>s.tail_consumers=[{service:'unexpected'}],
 placement:s=>s.placement={mode:'smart'},
 usage:s=>s.usage_model='other',
 other_annotation:s=>s.annotations['workers/unknown-control']='unexpected',
 unknown_setting:s=>s.new_setting={enabled:true}
}))test(`stable fingerprint still blocks ${name} drift after upload`,async()=>{
 const {c,a}=fixture(),before=JSON.parse(readFileSync('scripts/fixtures/release-version-settings.json')).staged,after=structuredClone(before);
 mutate(after);a.settings_sha256=settingsDigest(before);
 assert.notEqual(settingsDigest(after),a.settings_sha256);
 const secrets=[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}];let uploaded=false,promotes=0;const receipts=[];
 const get=async path=>path==='/settings'?(uploaded?after:before):path==='/secrets'?secrets:{deployments:['old']};
 await assert.rejects(deployExisting(a,get,async()=>{uploaded=true;return JSON.stringify(record);},async()=>{promotes++;},undefined,id=>receipts.push(id),undefined,c));
 assert.equal(promotes,0);assert.deepEqual(receipts,[record.version_id]);
});
test('an untyped legacy approval is rejected before any credential use',async()=>{
 const {c,a,e}=fixture();const original=globalThis.fetch;let calls=0;
 globalThis.fetch=async()=>{calls++;throw Error('unexpected network');};
 try{
  for(const schema of [undefined,'raw-v1','runtime-v2']){
   const approval={...a,settings_schema:schema};assert.throws(()=>validate(c,approval,e));
   await assert.rejects(release({...e,RUNLATER_RELEASE_CONFIG:JSON.stringify(c),RUNLATER_RELEASE_APPROVAL:JSON.stringify(approval),GH_TOKEN:'public-fixture',CLOUDFLARE_API_TOKEN:'public-fixture'}));
  }
  assert.equal(calls,0);
 }finally{globalThis.fetch=original;}
});
test('non-map annotations fail closed; absent and empty label sets are equivalent',()=>{
 for(const annotations of ['invalid',[],123])assert.throws(()=>settingsDigest({annotations}));
 assert.equal(settingsDigest({bindings:[]}),settingsDigest({bindings:[],annotations:{}}));
 assert.equal(settingsDigest({bindings:[]}),settingsDigest({bindings:[],annotations:{'workers/tag':'any-label'}}));
});


test('optional MCP gateway trust requires exact reviewed config and public-key shape',()=>{
 const {c,a,e}=fixture(); c.vars.MCP_DELEGATION_GATEWAY_PUBLIC_KEY='a'.repeat(64);
 assert.throws(()=>validate(c,a,e)); // No implicit activation from an unreviewed profile.
 a.config_sha256=digest(c); assert.doesNotThrow(()=>validate(c,a,e));
 for(const invalid of ['', '0'.repeat(64), 'A'.repeat(64), 'private-key-material', 123]) {
  c.vars.MCP_DELEGATION_GATEWAY_PUBLIC_KEY=invalid; a.config_sha256=digest(c);
  assert.throws(()=>validate(c,a,e));
 }
});

test('anonymous trial activation requires exact reviewed profile and existing gateway trust',()=>{
 const {c,a,e}=fixture(); c.vars.MCP_ANONYMOUS_TRIAL_ENABLED='operator-approved';
 assert.throws(()=>validate(c,a,e));
 a.config_sha256=digest(c); assert.throws(()=>validate(c,a,e)); // No gateway proof.
 c.vars.MCP_DELEGATION_GATEWAY_PUBLIC_KEY='a'.repeat(64);
 assert.throws(()=>validate(c,a,e)); // Adding trust still requires a newly reviewed digest.
 a.config_sha256=digest(c); assert.doesNotThrow(()=>validate(c,a,e));
 for(const invalid of ['true','enabled','',true,123]) {
  c.vars.MCP_ANONYMOUS_TRIAL_ENABLED=invalid; a.config_sha256=digest(c);
  assert.throws(()=>validate(c,a,e));
 }
 c.vars.MCP_ANONYMOUS_TRIAL_ENABLED='disabled'; delete c.vars.MCP_DELEGATION_GATEWAY_PUBLIC_KEY;
 a.config_sha256=digest(c); assert.doesNotThrow(()=>validate(c,a,e));
});

test('receiver pairing remains optional, separately approved and trial-dependent',()=>{
 const {c,a,e}=fixture(); c.vars.MCP_RECEIVER_PAIRING_ENABLED='operator-approved';a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));
 c.vars.MCP_ANONYMOUS_TRIAL_ENABLED='operator-approved';c.vars.MCP_DELEGATION_GATEWAY_PUBLIC_KEY='a'.repeat(64);a.config_sha256=digest(c);validate(c,a,e);
 for(const invalid of ['true',true,'enabled','']){c.vars.MCP_RECEIVER_PAIRING_ENABLED=invalid;a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));}
 c.vars.MCP_RECEIVER_PAIRING_ENABLED='disabled';delete c.vars.MCP_ANONYMOUS_TRIAL_ENABLED;delete c.vars.MCP_DELEGATION_GATEWAY_PUBLIC_KEY;a.config_sha256=digest(c);validate(c,a,e);
 c.vars.MCP_RECEIVER_PAIRING_ENABLED='operator-approved';assert.throws(()=>validate(c,a,e));
});
test('general HTTPS requires exact private binding/revision, separate trial authority and refreshed approval',()=>{
 const {c,a,e}=fixture();c.vars.GENERAL_HTTPS_ENABLED='operator-approved';a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));
 c.vars.MCP_ANONYMOUS_TRIAL_ENABLED='operator-approved';c.vars.MCP_DELEGATION_GATEWAY_PUBLIC_KEY='a'.repeat(64);a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));
 c.services=[{binding:'GENERAL_HTTPS_EGRESS',service:'runlater-general-egress',entrypoint:'EgressBinding'}];c.vars.GENERAL_HTTPS_EGRESS_REVIEW_REVISION='b'.repeat(64);a.config_sha256=digest(c);validate(c,a,e);
 for(const invalid of ['true',true,'enabled','']){c.vars.GENERAL_HTTPS_ENABLED=invalid;a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));}
 c.vars.GENERAL_HTTPS_ENABLED='disabled';delete c.vars.MCP_ANONYMOUS_TRIAL_ENABLED;delete c.vars.MCP_DELEGATION_GATEWAY_PUBLIC_KEY;a.config_sha256=digest(c);validate(c,a,e);
 const valid=structuredClone(c);
 for(const services of [[],[...c.services,...c.services],[{...c.services[0],service:'other'}],[{...c.services[0],entrypoint:'default'}],[{...c.services[0],environment:'other'}],[{...c.services[0],binding:'OTHER'}]]){c.services=services;a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));}
 Object.assign(c,structuredClone(valid));
 for(const revision of ['0'.repeat(64),'A'.repeat(64),'short',true,undefined]){if(revision===undefined)delete c.vars.GENERAL_HTTPS_EGRESS_REVIEW_REVISION;else c.vars.GENERAL_HTTPS_EGRESS_REVIEW_REVISION=revision;a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));}
 Object.assign(c,structuredClone(valid));delete c.services;a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));
 delete c.vars.GENERAL_HTTPS_EGRESS_REVIEW_REVISION;a.config_sha256=digest(c);validate(c,a,e);
 c.vars.GENERAL_HTTPS_ENABLED='operator-approved';assert.throws(()=>validate(c,a,e));
});
test('private egress binding cannot collide with a provider secret',()=>{
 const c=fixture().c;c.services=[{binding:'GENERAL_HTTPS_EGRESS',service:'runlater-general-egress',entrypoint:'EgressBinding'}];
 assert.throws(()=>checkSecretCollisions(c,{bindings:[{name:'GENERAL_HTTPS_EGRESS',type:'secret_text'}]},[{name:'GENERAL_HTTPS_EGRESS',type:'secret_text'}]));
});

const nativeEgress={binding:'GENERAL_HTTPS_EGRESS',service:'runlater-general-egress',entrypoint:'EgressBinding'};
const workerEgress={binding:'GENERAL_HTTPS_EGRESS',service:'runlater-public-fetch-candidate',entrypoint:'PublicFetchBinding'};
function egressFixture(target=workerEgress){
 const f=fixture();f.c.services=[{...target}];f.c.vars.GENERAL_HTTPS_EGRESS_REVIEW_REVISION='b'.repeat(64);f.a.config_sha256=digest(f.c);return f;
}
test('reviewed Worker egress binding is an explicit optional alternative with admission still off',()=>{
 const {c,a,e}=egressFixture();assert.equal(c.vars.GENERAL_HTTPS_ENABLED,undefined);validate(c,a,e);
 c.vars.GENERAL_HTTPS_ENABLED='disabled';a.config_sha256=digest(c);validate(c,a,e);
});
test('Worker egress admission still requires trial authority, revision and the reviewed complete profile',()=>{
 const {c,a,e}=egressFixture();c.vars.GENERAL_HTTPS_ENABLED='operator-approved';a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));
 c.vars.MCP_ANONYMOUS_TRIAL_ENABLED='operator-approved';a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));
 c.vars.MCP_DELEGATION_GATEWAY_PUBLIC_KEY='a'.repeat(64);assert.throws(()=>validate(c,a,e));
 a.config_sha256=digest(c);validate(c,a,e);
 for(const revision of [undefined,'0'.repeat(64),'A'.repeat(64),'UNVERIFIED',true]){
  const changed=structuredClone(c);if(revision===undefined)delete changed.vars.GENERAL_HTTPS_EGRESS_REVIEW_REVISION;else changed.vars.GENERAL_HTTPS_EGRESS_REVIEW_REVISION=revision;
  assert.throws(()=>validate(changed,{...a,config_sha256:digest(changed)},e));
 }
});
test('native and Worker targets cannot be interchanged under an existing config approval',()=>{
 const {c,a,e}=egressFixture(nativeEgress);validate(c,a,e);c.services=[{...workerEgress}];assert.throws(()=>validate(c,a,e));
 a.config_sha256=digest(c);validate(c,a,e);c.services=[{...nativeEgress}];assert.throws(()=>validate(c,a,e));
});
test('Worker egress rejects aliases, crossed entrypoints, extra authority and fallback lists even after digest approval',()=>{
 const {c,a,e}=egressFixture();
 for(const services of [null,[],[workerEgress,nativeEgress],[workerEgress,workerEgress],
  [{...workerEgress,service:'runlater-general-egress'}],[{...workerEgress,entrypoint:'EgressBinding'}],
  [{...nativeEgress,entrypoint:'PublicFetchBinding'}],[{...workerEgress,entrypoint:'default'}],
  [{...workerEgress,service:'other-worker'}],[{...workerEgress,binding:'OTHER'}],
  [{...workerEgress,environment:'production'}],[{...workerEgress,namespace:'other'}],
  [{...workerEgress,service:'runlater-fetch-proof-20261029a'}]]){
  const changed={...c,services};assert.throws(()=>validate(changed,{...a,config_sha256:digest(changed)},e));
 }
 const changed=structuredClone(c);delete changed.services;assert.throws(()=>validate(changed,{...a,config_sha256:digest(changed)},e));
});
test('Worker profile cannot bypass approved settings drift or secret collision guards',async()=>{
 const {c,a,e}=egressFixture();validate(c,a,e);
 const master={name:'BETA_CALLBACK_MASTER',type:'secret_text'};
 const settings={bindings:[master,workerEgress]};let uploads=0,promotes=0;
 a.settings_sha256=settingsDigest({bindings:[master,nativeEgress]});
 await assert.rejects(deployExisting(a,async path=>path==='/settings'?settings:path==='/secrets'?[master]:{deployments:['old']},async()=>{uploads++;return JSON.stringify(record);},async()=>{promotes++;},undefined,undefined,undefined,c));
 assert.equal(uploads,0);assert.equal(promotes,0);
 for(const name of ['GENERAL_HTTPS_EGRESS','GENERAL_HTTPS_EGRESS_REVIEW_REVISION']){
  assert.throws(()=>checkSecretCollisions(c,{bindings:[master,{name,type:'secret_text'}]},[master]));
  assert.throws(()=>checkSecretCollisions(c,{bindings:[master]},[master,{name,type:'secret_text'}]));
 }
});
