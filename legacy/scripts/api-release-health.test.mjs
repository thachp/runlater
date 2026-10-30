import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {HEALTH_URL,HEALTH_LIMITS,verifyPublicHealth,HealthVerificationError} from './api-release-health.mjs';
import {verifyPromotedVersion,digest} from './api-release.mjs';
const id='01234567-0123-0123-0123-0123456789ab',old='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const sentinel='PRIVATE-SENTINEL-MUST-NOT-LOG';
const healthy=(version_id=id,extra={})=>({mode:'public_free_beta',configured:true,version_id,...extra});
const response=(body=healthy(),status=200,headers={})=>new Response(typeof body==='string'?body:JSON.stringify(body),{status,headers});
class Clock {
  time=0; sequence=0; timers=new Map(); epoch=Date.UTC(2026,9,29,9);
  now=()=>this.time;
  wallNow=()=>this.epoch+this.time;
  setTimeout=(callback,delay)=>{const key=++this.sequence;this.timers.set(key,{at:this.time+delay,callback});return key;};
  clearTimeout=key=>this.timers.delete(key);
  async drive(promise) {
    let done=false,value,error;
    promise.then(v=>{done=true;value=v;},e=>{done=true;error=e;});
    for(let step=0;!done&&step<100;step++) {
      // Let all finite byte/chunk work settle before advancing virtual timers.
      for(let i=0;i<1000&&!done;i++)await Promise.resolve();
      if(done)break;
      const next=[...this.timers].sort((a,b)=>a[1].at-b[1].at)[0];
      assert.ok(next,'promise stalled without an owned timer');
      this.timers.delete(next[0]);this.time=next[1].at;next[1].callback();
    }
    assert.ok(done,'verifier did not terminate');
    assert.equal(this.timers.size,0,'owned timer leaked');
    if(error)throw error;
    return value;
  }
}
async function run(sequence,{clock=new Clock(),expected=id}={}) {
  const calls=[],events=[];
  const fetch=async(url,options)=>{
    calls.push({at:clock.now(),url,options});
    const value=sequence[Math.min(calls.length-1,sequence.length-1)];
    if(typeof value==='function')return value({clock,options});
    return value;
  };
  let result,error;
  try { result=await clock.drive(verifyPublicHealth(expected,{fetch,clock,onAttempt:e=>events.push(e)})); }
  catch(e) { error=e; }
  assert.doesNotMatch(JSON.stringify(events)+(error?.stack??''),new RegExp(sentinel));
  for(const {url,options} of calls) {
    assert.equal(url,HEALTH_URL);assert.equal(options.method,'GET');assert.equal(options.redirect,'manual');
    assert.deepEqual(Object.keys(options).sort(),['method','redirect','signal']);
    assert.ok(options.signal.aborted,'attempt transport not closed');
  }
  return {clock,calls,events,result,error};
}
function rejected(r,outcome) {assert.ok(r.error instanceof HealthVerificationError);assert.equal(r.error.outcome,outcome);assert.equal(r.result,undefined);}

test('exact immediate health succeeds on fixed public host with no credentials/overrides',async()=>{
  const r=await run([response()]);assert.deepEqual(r.result,{attempts:1});assert.equal(r.calls.length,1);
  assert.deepEqual(r.events,[{attempt:1,elapsed_ms:0,status:200,outcome:'verified',mode_match:true,configured:true,version_match:true}]);
});
test('healthy prior version is never accepted and may converge to the expected version',async()=>{
  const r=await run([response(healthy(old)),response()]);assert.deepEqual(r.result,{attempts:2});assert.deepEqual(r.calls.map(c=>c.at),[0,5000]);
  assert.equal(r.events[0].version_match,false);
});
test('persistent valid mismatch stops at the finite request cap',async()=>{
  const r=await run([()=>response(healthy(old))]);rejected(r,'version_mismatch');assert.equal(r.calls.length,12);assert.equal(r.clock.now(),55000);
});
for(const status of [500,502,503,504])test(`transient HTTP ${status} retries only a public read`,async()=>{
  const r=await run([response(sentinel,status),response()]);assert.deepEqual(r.result,{attempts:2});assert.equal(r.events[0].outcome,'http_5xx');
});
test('429 respects Retry-After 60 seconds rather than retrying early',async()=>{
  const r=await run([response(sentinel,429,{'Retry-After':'60'}),response()]);assert.deepEqual(r.calls.map(c=>c.at),[0,60000]);assert.deepEqual(r.result,{attempts:2});
});
test('Retry-After HTTP-date uses wall time for delay but monotonic total deadline',async()=>{
  const clock=new Clock(),date=new Date(clock.wallNow()+60000).toUTCString();
  const r=await run([response(sentinel,503,{'Retry-After':date}),response()],{clock});assert.deepEqual(r.calls.map(c=>c.at),[0,60000]);
});
for(const value of ['0','Thu, 29 Oct 2026 08:00:00 GMT'])test(`Retry-After ${value} still keeps minimum spacing`,async()=>{
  const r=await run([response(sentinel,429,{'Retry-After':value}),response()]);assert.deepEqual(r.calls.map(c=>c.at),[0,5000]);
});
for(const value of ['120','9999999999'])test(`excessive Retry-After ${value} stops rather than retrying early`,async()=>{
  const r=await run([response(sentinel,429,{'Retry-After':value})]);rejected(r,'retry_after_exceeds_deadline');assert.equal(r.calls.length,1);assert.equal(r.clock.now(),0);
});
for(const value of ['-1','1.5','Infinity',sentinel,'99999999999','Thu, 32 Oct 2026 09:00:00 GMT'])test(`invalid retry header is redacted and fails closed (${value===sentinel?'sentinel':value})`,async()=>{
  const r=await run([response(sentinel,429,{'Retry-After':value})]);rejected(r,'retry_after_invalid');assert.equal(r.calls.length,1);
});
test('second 60-second Retry-After cannot push polling beyond the overall budget',async()=>{
  const r=await run([()=>response(sentinel,429,{'Retry-After':'60'})]);rejected(r,'retry_after_exceeds_deadline');assert.equal(r.calls.length,2);assert.equal(r.clock.now(),60000);
});
for(const status of [301,302,307,308,400,401,403,404,501])test(`HTTP ${status} fails without following Location or printing body`,async()=>{
  const r=await run([response(sentinel,status,{Location:`https://invalid.example/${sentinel}`})]);rejected(r,status<400?'redirect':'http_status');assert.equal(r.calls.length,1);
});
test('opaque redirect/status zero is rejected',async()=>{const r=await run([Response.error()]);rejected(r,'http_status');assert.equal(r.calls.length,1);});
for(const [body,outcome] of [[healthy(id,{mode:sentinel}),'wrong_mode'],[healthy(id,{configured:false}),'not_configured'],[healthy(id,{configured:'true'}),'not_configured'],[healthy(sentinel),'invalid_version'],[healthy(null),'invalid_version'],[{mode:'public_free_beta',configured:true},'invalid_version'],['{'+sentinel,'invalid_json']])test(`invalid identity/body fails immediately: ${outcome}`,async()=>{
  const r=await run([response(body)]);rejected(r,outcome);assert.equal(r.calls.length,1);
});
test('invalid expected identity performs no request and does not expose input',async()=>{const r=await run([],{expected:sentinel});rejected(r,'invalid_expected_version');assert.equal(r.calls.length,0);});
function streamResponse(chunks,{cancel=()=>{},end=true}={}) {
  let n=0;
  return new Response(new ReadableStream({pull(controller){if(n<chunks.length)controller.enqueue(chunks[n++]);else if(end)controller.close();},cancel}));
}
test('exact 4096-byte valid body is accepted; 4097 rejected',async()=>{
  const data=JSON.stringify(healthy());
  assert.deepEqual((await run([response(data+' '.repeat(4096-data.length))])).result,{attempts:1});
  rejected(await run([response(data+' '.repeat(4097-data.length))]),'body_too_large');
});
test('valid UTF-8 character split across chunks is decoded once as a stream',async()=>{
  const bytes=new TextEncoder().encode(JSON.stringify(healthy(id,{note:'€'}))),position=bytes.indexOf(0xe2);
  const r=await run([streamResponse([bytes.slice(0,position+1),bytes.slice(position+1,position+2),bytes.slice(position+2)])]);assert.deepEqual(r.result,{attempts:1});
});
for(const bytes of [[0xff],[0xe2,0x82]])test(`invalid/truncated UTF-8 is not replacement-decoded (${bytes.length} bytes)`,async()=>{
  rejected(await run([streamResponse([new Uint8Array(bytes)])]),'invalid_utf8');
});
test('excessive empty chunks are bounded independently of bytes',async()=>{
  rejected(await run([streamResponse(Array.from({length:129},()=>new Uint8Array()))]),'too_many_chunks');
});
test('missing body is rejected',async()=>{rejected(await run([new Response(null)]),'invalid_body');});
test('locked body is rejected',async()=>{const body=response();body.body.getReader();rejected(await run([body]),'invalid_body');});
test('transport exception is redacted and may recover',async()=>{
  const r=await run([()=>{const e=Error(sentinel);e.name=sentinel;e.code=sentinel;throw e;},response()]);assert.deepEqual(r.result,{attempts:2});assert.equal(r.events[0].outcome,'transport_error');
});
test('headers-only fetch stall is aborted and bounded; no request after 120 seconds',async()=>{
  const r=await run([()=>new Promise(()=>{})]);rejected(r,'request_timeout');assert.equal(r.calls.length,12);assert.equal(r.clock.now(),115000);
});
test('stream stall and never-resolving cancellation cannot hang or mask timeout',async()=>{
  const r=await run([()=>streamResponse([],{end:false,cancel:()=>new Promise(()=>{})})]);rejected(r,'request_timeout');assert.equal(r.calls.length,12);assert.equal(r.clock.now(),115000);
});
for(const cancel of [()=>{throw Error(sentinel);},()=>Promise.reject(Error(sentinel)),()=>new Promise(()=>{})])test('non-200 cancellation failure never masks original classification',async()=>{
  const r=await run([{status:403,body:{cancel},headers:new Headers()}]);rejected(r,'http_status');assert.equal(r.calls.length,1);
});
test('success delivered after the monotonic deadline is refused',async()=>{
  const r=await run([({clock})=>{clock.time=HEALTH_LIMITS.totalMs;return response();}]);rejected(r,'deadline');
});
test('success delivered after a request deadline cannot beat a delayed timer callback',async()=>{
  const r=await run([({clock})=>{clock.time+=6000;return response();},response()]);
  assert.equal(r.events[0].outcome,'request_timeout');assert.deepEqual(r.result,{attempts:2});assert.deepEqual(r.calls.map(c=>c.at),[0,11000]);
});
test('final partial request is clamped to remaining overall time',async()=>{
  const r=await run([response(sentinel,429,{'Retry-After':'118'}),()=>new Promise(()=>{})]);rejected(r,'deadline');assert.equal(r.clock.now(),120000);assert.equal(r.calls.length,2);
});

test('final current-main and sole active 100% identity must still match after health',async()=>{
  const events=[],health=async expected=>{assert.equal(expected,id);events.push('health');};
  const current=async()=>{events.push('main');return true;};
  const get=async path=>{events.push(path);return {deployments:[{versions:[{version_id:id,percentage:100}]}]};};
  await verifyPromotedVersion(id,get,current,health);assert.deepEqual(events,['health','main','/deployments']);
  await assert.rejects(verifyPromotedVersion(id,get,async()=>false,health));
  for(const versions of [[],[{version_id:old,percentage:100}],[{version_id:id,percentage:99}],[{version_id:id,percentage:100},{version_id:old,percentage:0}]]) {
    await assert.rejects(verifyPromotedVersion(id,async()=>({deployments:[{versions}]}),current,health));
  }
});

test('real release entry retains receipt and uploads/promotes once on success or health failure',()=>{
  const releaseScript=resolve('scripts/api-release.mjs');
  for(const success of [true,false]) {
    const dir=mkdtempSync(join(tmpdir(),'release-health-entry-'));
    try {
      const config={name:'runlater-public-api',main:'build/worker/shim.mjs',version_metadata:{binding:'RELEASE_VERSION'},compatibility_date:'2026-10-27',compatibility_flags:['global_fetch_strictly_public'],workers_dev:false,preview_urls:false,limits:{cpu_ms:50},observability:{enabled:false},durable_objects:{bindings:[{name:'ADMISSION',class_name:'AdmissionRegistry'},{name:'PROJECTS',class_name:'InvitationProject'}]},queues:{producers:[{binding:'BETA_READY',queue:'runlater-public-ready'}]},ratelimits:[{name:'BETA_IP_RATE',namespace_id:'1001',simple:{limit:60,period:60}},{name:'BETA_REG_IP_RATE',namespace_id:'1002',simple:{limit:6,period:60}}],vars:{PUBLIC_BETA_ENABLED:'operator-approved',PUBLIC_BETA_PROFILE:JSON.stringify({release_id:'test',opens_at_ms:1000,closes_at_ms:2000,callback_end_sec:1000000}),BETA_REVOKED_PROJECTS:'[]',BETA_READY_QUEUE:'runlater-public-ready'}};
      const settings={bindings:[{name:'BETA_CALLBACK_MASTER',type:'secret_text'}]},tag='d'.repeat(32),sha='c'.repeat(40);
      const approval={worker:config.name,worker_tag:tag,settings_schema:'runtime-v1',account_id:'a'.repeat(32),config_sha256:digest(config),settings_sha256:digest(settings)};
      mkdirSync(join(dir,'node_modules/wrangler/bin'),{recursive:true});
      writeFileSync(join(dir,'node_modules/wrangler/bin/wrangler.js'),`const fs=require('node:fs');const mode=process.argv[3];fs.appendFileSync('calls',mode+'\\n');if(mode==='upload')fs.writeFileSync(process.env.WRANGLER_OUTPUT_FILE_PATH,JSON.stringify(${JSON.stringify({type:'version-upload',worker_name:config.name,worker_tag:tag,version_id:id})}));else if(mode==='deploy')fs.writeFileSync('promoted','yes');else process.exit(2);`);
      writeFileSync(join(dir,'preload.mjs'),`import {existsSync} from 'node:fs';globalThis.fetch=async(url,options)=>{let data;if(url==='${HEALTH_URL}'){if(options.method!=='GET'||options.redirect!=='manual'||options.headers)throw Error('bad health options');return Response.json(${JSON.stringify(success?healthy():healthy(id,{mode:sentinel}))});}if(url==='https://api.github.com/repos/thachp/runlater/git/ref/heads/main')return Response.json({object:{sha:'${sha}'}});if(!url.startsWith('https://api.cloudflare.com/client/v4/accounts/${approval.account_id}/workers/'))throw Error('unexpected network');if(url.endsWith('/settings'))data=${JSON.stringify(settings)};else if(url.endsWith('/secrets'))data=${JSON.stringify(settings.bindings)};else if(url.endsWith('/deployments'))data={deployments:[{versions:[{version_id:existsSync('promoted')?'${id}':'${old}',percentage:100}]}]};else data={id:'runlater-public-api',default_environment:{environment:'production',script:{id:'runlater-public-api',tag:'${tag}',last_deployed_from:'api'}}};return Response.json({success:true,result:data});};`);
      const child=spawnSync(process.execPath,['--import',join(dir,'preload.mjs'),releaseScript],{cwd:dir,env:{PATH:process.env.PATH,RUNLATER_RELEASE_ENABLED:'true',GITHUB_REPOSITORY:'thachp/runlater',RELEASE_SHA:sha,RUNLATER_RELEASE_CONFIG:JSON.stringify(config),RUNLATER_RELEASE_APPROVAL:JSON.stringify(approval),GH_TOKEN:'public-fixture',CLOUDFLARE_API_TOKEN:'public-fixture'},encoding:'utf8',timeout:10000});
      assert.equal(child.status,success?0:1,child.stdout+child.stderr);assert.deepEqual(readFileSync(join(dir,'calls'),'utf8').trim().split('\n'),['upload','deploy']);
      assert.match(child.stdout,new RegExp(`Uploaded Worker version ${id}`));assert.doesNotMatch(child.stdout+child.stderr,new RegExp(sentinel));
      if(success)assert.match(child.stdout,/public health returned 200/);else assert.match(child.stderr,/Promotion completed; public health or final identity not verified/);
    } finally {rmSync(dir,{recursive:true,force:true});}
  }
});
