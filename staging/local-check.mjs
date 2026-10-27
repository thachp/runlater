// LOCAL ONLY: public fixture gate. Refuses any network hostname other than loopback.
import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
const base=new URL(process.env.STAGING_LOCAL_URL??'http://127.0.0.1:8787');assert.equal(base.hostname,'127.0.0.1');
const gate='a'.repeat(64),run='review';let calls=0;
async function request(path,{method='GET',body,authorized=true,tenant='alpha',expected=200,key,host}={}){assert.ok(++calls<=100,'local request budget');const r=await fetch(new URL(path,base),{method,headers:{Authorization:`Bearer local-${tenant}`,'Content-Type':'application/json',...(authorized?{'X-RunLater-Staging-Gate':gate}:{}),...(key?{'Idempotency-Key':key}:{}),...(host?{Host:host}:{})},body:body===undefined?undefined:typeof body==='string'?body:JSON.stringify(body),signal:AbortSignal.timeout(5000)});const text=await r.text();assert.equal(r.status,expected,text);try{return JSON.parse(text)}catch{return text}}
for(const path of ['/health','/v1/tasks','/v1/keys','/unknown']){await request(path,{authorized:false,expected:403});await request(path,{authorized:false,method:'POST',body:'not-json',host:'version-preview.example',expected:403});}
const state=process.env.RUNLATER_STATE_DIR;assert.ok(state,'point at the fresh local store');const query=spawnSync('python3',['-c',`import sqlite3,pathlib,sys\ncount=0\nfor p in pathlib.Path(sys.argv[1]).rglob('*.sqlite'):\n c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)\n count+=c.execute("SELECT count(*) FROM sqlite_master WHERE name='ledger'").fetchone()[0]\nprint(count)`,state],{encoding:'utf8'});assert.equal(query.status,0,query.stderr);assert.equal(query.stdout.trim(),'0','denied requests touched task DO storage');
await request('/health');await request('/v1/keys',{expected:403});await request('/v1/tasks',{tenant:'beta',expected:403});await request('/v1/tasks',{method:'POST',body:'bad-json',expected:400});
const input=(destination,which,at=0)=>({destination,body:JSON.stringify({run,case:which,synthetic:true}),operation_key:`run_${run}_${which}`,run_at_ms:at});
const first=await request('/v1/tasks',{method:'POST',body:input('fixture://success','initial'),key:'initial',expected:201});
async function settled(id,status){for(let i=0;i<20;i++){const t=await request('/v1/tasks/'+id);if(t.status===status)return t;await new Promise(r=>setTimeout(r,250))}throw Error('local staged task did not settle')}
assert.equal((await settled(first.id,'succeeded')).attempts.length,1);
const disabled=await request('/v1/tasks',{method:'POST',body:input('staging://receiver','receiver'),key:'disabled',expected:201});const failed=await settled(disabled.id,'failed');assert.equal(failed.attempts[0].outcome,'http_400');
await request('/v1/tasks',{method:'POST',body:input('https://example.com','receiver'),key:'egress',expected:400});
const scheduled=[];for(let i=0;i<10;i++){const t=await request('/v1/tasks',{method:'POST',body:input('fixture://success','cancel',Date.now()+20000),key:'cap-'+i,expected:201});scheduled.push(t.id)}
await request('/v1/tasks',{method:'POST',body:input('fixture://success','initial'),key:'over-cap',expected:429});
for(const id of scheduled)await request('/v1/tasks/'+id+'/cancel',{method:'POST'});
console.log('PASS: staging-feature gate before malformed bodies/DO access on aliases, fixture credentials cannot bypass, disabled egress, actual local alarm/Queue state, synthetic-only admission and 12-task cap');
