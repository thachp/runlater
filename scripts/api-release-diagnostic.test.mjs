import {test} from 'node:test';import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';import {spawnSync} from 'node:child_process';
import vm from 'node:vm';
import {diagnose} from './api-release-diagnostic.mjs';import {digest} from './api-release.mjs';
function fixture(){
 const config={name:'runlater-public-api',main:'build/worker/shim.mjs',version_metadata:{binding:'RELEASE_VERSION'},compatibility_date:'2026-10-27',compatibility_flags:['global_fetch_strictly_public'],workers_dev:false,preview_urls:false,limits:{cpu_ms:50},observability:{enabled:false},durable_objects:{bindings:[{name:'ADMISSION',class_name:'AdmissionRegistry'},{name:'PROJECTS',class_name:'InvitationProject'}]},queues:{producers:[{binding:'BETA_READY',queue:'runlater-public-ready'}]},ratelimits:[{name:'BETA_IP_RATE',namespace_id:'1001',simple:{limit:60,period:60}},{name:'BETA_REG_IP_RATE',namespace_id:'1002',simple:{limit:6,period:60}}],vars:{PUBLIC_BETA_ENABLED:'operator-approved',PUBLIC_BETA_PROFILE:JSON.stringify({release_id:'test',opens_at_ms:1000,closes_at_ms:2000,callback_end_sec:1000000}),BETA_REVOKED_PROJECTS:'[]',BETA_READY_QUEUE:'runlater-public-ready'}};
 const settings={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]};
 const approval={worker:config.name,worker_tag:'d'.repeat(32),settings_schema:'runtime-v1',account_id:'a'.repeat(32),config_sha256:digest(config),settings_sha256:digest(settings)};
 const e={RUNLATER_RELEASE_CONFIG:JSON.stringify(config),RUNLATER_RELEASE_APPROVAL:JSON.stringify(approval),RUNLATER_RELEASE_ENABLED:'false',GITHUB_REPOSITORY:'thachp/runlater',GITHUB_SHA:'c'.repeat(40),GH_TOKEN:'public-gh-fixture-sentinel',CLOUDFLARE_API_TOKEN:'public-cf-fixture-sentinel'};
 return {e,config,approval,settings};
}
const json=(value,status=200)=>new Response(JSON.stringify(value),{status});
function responder(e,settings,calls=[]){return async(url,options)=>{
 calls.push({url,options});
 if(url.includes('api.github.com/'))return json({object:{sha:e.GITHUB_SHA}});
 if(url.endsWith('/settings'))return json({success:true,result:settings});
 if(url.endsWith('/deployments'))return json({success:true,result:{deployments:[{versions:[{percentage:100}]}]}});
 return json({success:true,result:[]});
};}
test('diagnostic works with releases disabled and performs ten fixed GETs only',async()=>{
 const {e,settings}=fixture(),calls=[];const r=await diagnose(e,responder(e,settings,calls));
 assert.equal(r.requests,10);assert.equal(r.settings_match_baseline,true);assert.equal(r.master_binding_present,true);assert.equal(r.main_matches_source,true);assert.equal(r.single_active_version,true);
 assert.equal(e.RUNLATER_RELEASE_ENABLED,'false');
 for(const c of calls){assert.equal(c.options.method,'GET');assert.equal(c.options.redirect,'error');assert.ok(c.options.signal instanceof AbortSignal);assert.equal(c.options.body,undefined);}
 assert.equal(calls[3].url,'https://api.cloudflare.com/client/v4/accounts/'+ 'a'.repeat(32)+'/queues?per_page=1');
 assert.doesNotMatch(JSON.stringify(r),/public-gh-fixture|public-cf-fixture|BETA_CALLBACK_MASTER/);
});
test('403 status and numeric codes distinguish token access without leaking provider text',async()=>{
 const {e}=fixture();const r=await diagnose(e,async()=>json({success:false,errors:[{code:9109,message:'SECRET-SENTINEL'}, {code:'SECRET-SENTINEL'}]},403));
 assert.equal(r.checks[1].http_status,403);assert.deepEqual(r.checks[1].error_codes,[9109]);assert.doesNotMatch(JSON.stringify(r),/SECRET-SENTINEL|public-cf-fixture/);
});
test('baseline and source mismatches are observations, never a write or a new baseline',async()=>{
 const {e}=fixture(),before=structuredClone(e),calls=[];
 const r=await diagnose(e,async(url,o)=>{calls.push(o.method);return url.includes('github')?json({object:{sha:'d'.repeat(40)}}):json({success:true,result:{bindings:[]}});});
 assert.equal(r.main_matches_source,false);assert.equal(r.settings_match_baseline,false);assert.equal(r.master_binding_present,false);assert.deepEqual(e,before);assert.deepEqual(calls,Array(10).fill('GET'));
});
test('invalid configuration or missing credentials makes no network requests',async()=>{
 const {e,config,approval}=fixture();let calls=0;
 for(const env of [{...e,GH_TOKEN:''},{...e,CLOUDFLARE_API_TOKEN:''},{...e,RUNLATER_RELEASE_CONFIG:'SECRET-SENTINEL'},{...e,GITHUB_REPOSITORY:'foreign/repo'},{...e,GITHUB_SHA:'main'},{...e,RUNLATER_RELEASE_APPROVAL:JSON.stringify({...approval,worker:'foreign-worker'})},{...e,RUNLATER_RELEASE_CONFIG:JSON.stringify({...config,preview_urls:true})}]){
  const r=await diagnose(env,async()=>{calls++;throw Error('should not run');});assert.deepEqual(r,{diagnostic:'configuration_invalid',requests:0});
 }assert.equal(calls,0);
});
test('malformed, oversized and network error bodies never escape redaction',async()=>{
 const {e}=fixture();for(const fetcher of [async()=>new Response('SECRET-SENTINEL'),async()=>new Response('SECRET-SENTINEL'.repeat(10000)),async()=>{throw Error('SECRET-SENTINEL');}]){
  const r=await diagnose(e,fetcher);assert.equal(r.requests,10);assert.doesNotMatch(JSON.stringify(r),/SECRET-SENTINEL/);assert.ok(r.checks.every(x=>['invalid_json','response_bound','request_failed'].includes(x.error)));
 }
});
test('deadline prevents further calls after first read consumes the foreground budget',async()=>{
 const {e}=fixture();let now=0,calls=0;const r=await diagnose(e,async()=>{calls++;now=40000;return json({object:{sha:e.GITHUB_SHA}});},()=>now);
 assert.equal(calls,1);assert.equal(r.requests,1);assert.ok(r.checks.slice(1).every(x=>x.error==='deadline'));
});
test('actual diagnostic entry redacts malformed private input',()=>{
 const {e}=fixture();const child=spawnSync(process.execPath,['scripts/api-release-diagnostic.mjs'],{env:{...e,RUNLATER_RELEASE_CONFIG:'PRIVATE-SENTINEL-not-json'},encoding:'utf8'});
 assert.equal(child.status,1);assert.doesNotMatch(child.stdout+child.stderr,/PRIVATE-SENTINEL/);assert.deepEqual(JSON.parse(child.stdout),{diagnostic:'configuration_invalid',requests:0});
});
test('manual diagnostic workflow is main-only, environment scoped and cannot deploy',()=>{
 const w=readFileSync('.github/workflows/diagnose-api-release.yml','utf8');assert.match(w,/workflow_dispatch:/);assert.match(w,/github.ref == 'refs\/heads\/main'/);assert.match(w,/environment: runlater-public-api/);assert.match(w,/timeout-minutes: 3/);assert.match(w,/persist-credentials: false/);assert.match(w,/permissions:\n  contents: read/);assert.doesNotMatch(w,/wrangler|api-release\.mjs|build-production|RUNLATER_RELEASE_ENABLED|workflow_run|pull_request/);
});

test('explicit Worker egress profile retains the disabled GET-only diagnostic and exact baseline check',async()=>{
 const {e,config,approval,settings}=fixture();
 config.services=[{binding:'GENERAL_HTTPS_EGRESS',service:'runlater-public-fetch-candidate',entrypoint:'PublicFetchBinding'}];
 config.vars.GENERAL_HTTPS_EGRESS_REVIEW_REVISION='b'.repeat(64);
 settings.bindings.push({name:'GENERAL_HTTPS_EGRESS',type:'service',service:'runlater-public-fetch-candidate',entrypoint:'PublicFetchBinding'});
 approval.config_sha256=digest(config);approval.settings_sha256=digest(settings);
 const env={...e,RUNLATER_RELEASE_CONFIG:JSON.stringify(config),RUNLATER_RELEASE_APPROVAL:JSON.stringify(approval)},calls=[];
 const result=await diagnose(env,responder(env,settings,calls));
 assert.equal(result.requests,10);assert.equal(result.settings_match_baseline,true);assert.equal(result.main_matches_source,true);
 assert.equal(env.RUNLATER_RELEASE_ENABLED,'false');assert.equal(config.vars.GENERAL_HTTPS_ENABLED,undefined);
 assert.ok(calls.every(({options})=>options.method==='GET'&&options.body===undefined));
});

test('dashboard reads exactly match the six paths in the locked Wrangler implementation',async()=>{
 const {e,settings}=fixture(),calls=[];const r=await diagnose(e,responder(e,settings,calls));
 const source=readFileSync('node_modules/wrangler/wrangler-dist/cli.js','utf8'),start=source.indexOf('async function fetchWorkerConfig('),end=source.indexOf('\nasync function downloadWorkerConfig(',start);assert.ok(start>=0&&end>start);
 const paths=[],fn=vm.runInNewContext('('+source.slice(start,end)+')',{fetchResult:async(_,path)=>{paths.push(path);return {};}});
 await fn({},'a'.repeat(32),'runlater-public-api','production');
 assert.equal(paths.length,6);assert.deepEqual(calls.slice(4).map(x=>x.url),paths.map(path=>'https://api.cloudflare.com/client/v4'+path));
 assert.deepEqual(r.checks.slice(4).map(x=>x.check),['dashboard_bindings','dashboard_routes','dashboard_domains','dashboard_subdomain','dashboard_environment','dashboard_schedules']);
 for(const c of calls.slice(4)){assert.equal(c.options.headers.Authorization,'Bearer '+e.CLOUDFLARE_API_TOKEN);assert.equal(c.options.headers.Accept,'application/json');assert.deepEqual(Object.keys(c.options.headers).sort(),['Accept','Authorization']);}
});
for(let failed=0;failed<6;failed++)test(`dashboard failure ${failed+1} is isolated and never retried`,async()=>{
 const {e,settings}=fixture(),calls=[],respond=responder(e,settings,calls);let dashboard=0;
 const r=await diagnose(e,async(url,o)=>{if(calls.length>=4&&dashboard++===failed){calls.push({url,options:o});return json({success:false,errors:[{code:9109,message:'SECRET-SENTINEL'}],result:{token:'SECRET-SENTINEL'}},403);}return respond(url,o);});
 assert.equal(r.requests,10);assert.equal(new Set(calls.map(x=>x.url)).size,10);const rows=r.checks.slice(4);assert.equal(rows[failed].http_status,403);assert.deepEqual(rows[failed].error_codes,[9109]);assert.ok(rows.every((row,i)=>i===failed||row.http_status===200));assert.doesNotMatch(JSON.stringify(r),/SECRET-SENTINEL|public-cf-fixture/);
});
test('all dashboard status codes remain attributable without reflecting bodies or headers',async()=>{
 const {e,settings}=fixture(),calls=[],respond=responder(e,settings,calls),statuses=[200,401,403,404,429,503];let n=0;
 const r=await diagnose(e,async(url,o)=>{if(calls.length<4)return respond(url,o);calls.push({url,options:o});const status=statuses[n++];return json({success:status===200,errors:[{code:9109,message:'SECRET-SENTINEL'}, {code:'SECRET-SENTINEL'}],result:{private:'SECRET-SENTINEL'}},status);});
 assert.deepEqual(r.checks.slice(4).map(x=>x.http_status),statuses);assert.equal(r.requests,10);assert.doesNotMatch(JSON.stringify(r),/SECRET-SENTINEL|public-cf-fixture|public-gh-fixture/);
});
test('budget exhausted after initial preflight skips every dashboard request',async()=>{
 const {e,settings}=fixture(),calls=[],respond=responder(e,settings,calls);let now=0;
 const r=await diagnose(e,async(url,o)=>{const response=await respond(url,o);if(calls.length===4)now=40000;return response;},()=>now);
 assert.equal(r.requests,4);assert.equal(calls.length,4);assert.ok(r.checks.slice(4).every(x=>x.error==='deadline'));assert.equal(r.checks.length,10);
});
test('secret binding names, private values and provider-selected destinations never enter output or requests',async()=>{
 const {e,settings}=fixture(),calls=[],respond=responder(e,settings,calls);const r=await diagnose(e,async(url,o)=>{if(calls.length<4)return respond(url,o);calls.push({url,options:o});return json({success:true,result:{name:'SECRET-SENTINEL',value:e.CLOUDFLARE_API_TOKEN,url:'https://SECRET-SENTINEL.invalid',next_page:'https://SECRET-SENTINEL.invalid'}});});
 assert.equal(r.requests,10);assert.ok(calls.slice(4).every(x=>x.url.startsWith('https://api.cloudflare.com/client/v4/accounts/'+ 'a'.repeat(32)+'/workers/')));assert.doesNotMatch(JSON.stringify(r),/SECRET-SENTINEL|public-cf-fixture|public-gh-fixture/);
});
