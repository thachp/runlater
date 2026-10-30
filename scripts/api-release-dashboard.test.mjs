import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,realpathSync} from 'node:fs';
import {Module} from 'node:module';
import {dirname} from 'node:path';
import {validate,digest,uploadArguments} from './api-release.mjs';

const domain={pattern:'api.runlater.io',zone_name:'runlater.io',custom_domain:true,enabled:true,previews_enabled:false};
const target={binding:'GENERAL_HTTPS_EGRESS',service:'runlater-public-fetch-candidate',entrypoint:'PublicFetchBinding',environment:'production'};
function fixture(){const c={name:'runlater-public-api',main:'build/worker/shim.mjs',compatibility_date:'2026-10-27',compatibility_flags:['global_fetch_strictly_public'],workers_dev:false,preview_urls:false,limits:{cpu_ms:50},observability:{enabled:false},durable_objects:{bindings:[{name:'ADMISSION',class_name:'AdmissionRegistry'},{name:'PROJECTS',class_name:'InvitationProject'}]},queues:{producers:[{binding:'BETA_READY',queue:'runlater-public-ready'}]},ratelimits:[{name:'BETA_IP_RATE',namespace_id:'1001',simple:{limit:60,period:60}},{name:'BETA_REG_IP_RATE',namespace_id:'1002',simple:{limit:6,period:60}}],version_metadata:{binding:'RELEASE_VERSION'},vars:{PUBLIC_BETA_ENABLED:'operator-approved',PUBLIC_BETA_PROFILE:JSON.stringify({release_id:'synthetic',opens_at_ms:1000,closes_at_ms:2000,callback_end_sec:1000000}),BETA_REVOKED_PROJECTS:'[]',BETA_READY_QUEUE:'runlater-public-ready',GENERAL_HTTPS_EGRESS_REVIEW_REVISION:'b'.repeat(64)},services:[{...target}],routes:[{...domain}]};return {c,a:{worker:c.name,worker_tag:'d'.repeat(32),account_id:'a'.repeat(32),settings_schema:'runtime-v1',settings_sha256:'b'.repeat(64),config_sha256:digest(c)},e:{RUNLATER_RELEASE_ENABLED:'true',GITHUB_REPOSITORY:'thachp/runlater',RELEASE_SHA:'c'.repeat(40)}};}
test('exact existing domain and production service environment require a refreshed approval',()=>{const {c,a,e}=fixture();assert.doesNotThrow(()=>validate(c,a,e));delete c.services[0].environment;assert.throws(()=>validate(c,a,e));a.config_sha256=digest(c);validate(c,a,e);});
for(const [name,mutate]of Object.entries({wildcard:c=>c.routes[0].pattern='*.runlater.io/*',other_host:c=>c.routes[0].pattern='other.runlater.io',zone:c=>c.routes[0].zone_name='other.io',zone_id:c=>c.routes[0].zone_id='a'.repeat(32),disabled:c=>c.routes[0].enabled=false,preview:c=>c.routes[0].previews_enabled=true,route:c=>c.routes[0].custom_domain=false,missing_field:c=>delete c.routes[0].enabled,extra_field:c=>c.routes[0].unexpected=true,extra_route:c=>c.routes.push({...domain}),empty_routes:c=>c.routes=[],nonarray:c=>c.routes=domain,foreign_environment:c=>c.services[0].environment='staging',null_environment:c=>c.services[0].environment=null,extra_service_field:c=>c.services[0].unexpected=true,extra_service:c=>c.services.push({...target})}))test(`dashboard description rejects ${name} with refreshed digest`,()=>{const {c,a,e}=fixture();mutate(c);a.config_sha256=digest(c);assert.throws(()=>validate(c,a,e));});
test('both existing explicit transports accept only production environment; legacy profiles still work',()=>{for(const service of [{...target},{...target,service:'runlater-general-egress',entrypoint:'EgressBinding'}])for(const explicit of [true,false]){const {c,a,e}=fixture();c.services=[service];if(!explicit)delete service.environment;delete c.routes;a.config_sha256=digest(c);validate(c,a,e);}});
test('dashboard origin retains strict upload mode and pinned Worker identity',()=>{const {a,e}=fixture();const service={id:a.worker,default_environment:{environment:'production',script:{id:a.worker,tag:a.worker_tag,last_deployed_from:'dash'}}};assert.ok(uploadArguments('/tmp/synthetic.json',e.RELEASE_SHA,service,a).includes('--strict'));service.default_environment.script.tag='e'.repeat(32);assert.throws(()=>uploadArguments('/tmp/synthetic.json',e.RELEASE_SHA,service,a));});

test('pinned Wrangler reproduces dashboard omissions and exact description clears diff offline',()=>{
 const path=realpathSync('node_modules/wrangler/wrangler-dist/cli.js'),source=readFileSync(path,'utf8'),m=new Module(path);m.filename=path;m.paths=Module._nodeModulePaths(dirname(path));
 // Import only; require.main is this test, so the CLI command entry never runs.
 // The appended accessors expose pure config functions without editing the installed bundle.
 const savedFetch=globalThis.fetch;let networkCalls=0;globalThis.fetch=()=>{networkCalls++;throw Error('offline fixture forbids network');};
 try{m._compile(source+'\ninit_config_diffs();exports.__offlineDiff=getRemoteConfigDiff;',path);
  const {c}=fixture(),local={...structuredClone(c),routes:undefined,services:c.services.map(({environment,...s})=>s)};
  const diff=m.exports.__offlineDiff(c,local);assert.equal(diff.nonDestructive,false);assert.deepEqual(diff.diff.routes__deleted,[domain]);assert.match(JSON.stringify(diff.diff.services),/environment__deleted/);
  const complete=m.exports.__offlineDiff(c,c);assert.equal(complete.nonDestructive,true);assert.equal(complete.diff,null);assert.equal(networkCalls,0);
 }finally{globalThis.fetch=savedFetch;}
});
