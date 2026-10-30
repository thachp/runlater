import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import {createHash,randomUUID} from 'node:crypto';
const NOW = Date.now();
const AUD = 'https://fixture.invalid/agent/execute';
const output = await build({entryPoints:[fileURLToPath(new URL('./worker.mjs',import.meta.url))],bundle:true,write:false,format:'esm',platform:'neutral',external:['cloudflare:*']});
const script = output.outputFiles[0].text;
async function start(persist,enabled=true) {
 const options = convertV4MiniflareOptions({name:'runlater-local-fixture',modules:true,script,compatibilityDate:'2026-10-23',
  durableObjects:{LEDGER:{className:'FixtureCoordinator',useSQLite:true}},durableObjectsPersist:persist,
  bindings:{LOCAL_COORDINATOR_FIXTURE:enabled?'enabled':'disabled'},
  outboundService:()=>{throw Error('outbound_network_forbidden');}});
 options.resourcePersistencePath = persist;
 const mf = new Miniflare(options);
 const ns = await mf.getDurableObjectNamespace('LEDGER');
 const raw = ns.get(ns.idFromName('bounded-release-fixture'));
 const stub = new Proxy({}, {get:(_,method)=>async(...args)=>{
   const result=await raw.fixtureCall(method,args);
   if(!result.ok) throw new Error(result.error);
   return result.value;
 }});
 return {mf,stub};
}
async function fixture(t) {
 const dir=await mkdtemp(join(tmpdir(),'runlater-agent-ledger-'));
 let current=await start(dir);
 t.after(async()=>{await current.mf.dispose();await rm(dir,{recursive:true,force:true});});
 await current.stub.fixtureClock(NOW);
 const key=await generateKeyPair('EdDSA');
 const publicKey=await exportJWK(key.publicKey);
 const enrollment={entitlement:'entitlement-1',project:'fixture-project-1',issued:NOW,host:'host-1',publicKey};
 await current.stub.fixtureEnroll(enrollment);
 const command={capability:'fixture_debit',units:5};
 const token=(claims={},body=command,signingKey=key.privateKey)=>new SignJWT({sub:'host-1',capabilities:['fixture_debit'],htm:'POST',htu:AUD,
  ath:createHash('sha256').update(JSON.stringify(body)).digest('base64url'),...claims})
  .setProtectedHeader({alg:'EdDSA',typ:'agent+jwt'}).setAudience(AUD).setIssuedAt(Math.floor(NOW/1000)).setExpirationTime(Math.floor(NOW/1000)+60).setJti(randomUUID()).sign(signingKey);
 return {get stub(){return current.stub;},get mf(){return current.mf;},key,enrollment,command,token,
  async restart(){await current.mf.dispose();current=await start(dir);}};
}
test('workerd SQLite atomically consumes one replay and debits once across concurrent calls',async t=>{
 const f=await fixture(t), jwt=await f.token();
 const outcomes=await Promise.allSettled(Array.from({length:12},()=>f.stub.execute(jwt,f.command)));
 assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);
 assert.equal((await f.stub.fixtureInspect('entitlement-1')).remaining,95);
 assert.ok(outcomes.filter(x=>x.status==='rejected').every(x=>/replay_rejected/.test(x.reason.message)));
});
test('process restart retains replay, budget and original identity/expiry',async t=>{
 const f=await fixture(t),jwt=await f.token();
 await f.stub.execute(jwt,f.command);
 const before=await f.stub.fixtureInspect('entitlement-1');
 await f.restart();
 await assert.rejects(f.stub.execute(jwt,f.command),/replay_rejected/);
 const other=await generateKeyPair('EdDSA');
 await f.stub.fixtureEnroll({...f.enrollment,host:'host-2',publicKey:await exportJWK(other.publicKey)});
 assert.deepEqual(await f.stub.fixtureInspect('entitlement-1'),before);
 await assert.rejects(f.stub.fixtureEnroll({...f.enrollment,issued:NOW-1}),/identity_conflict/);
 await assert.rejects(f.stub.fixtureEnroll({...f.enrollment,project:'new-project'}),/identity_conflict/);
});
test('concurrent quota reservations never overspend; re-enrollment never refills',async t=>{
 const f=await fixture(t);
 const tokens=await Promise.all(Array.from({length:25},()=>f.token()));
 const outcomes=await Promise.allSettled(tokens.map(jwt=>f.stub.execute(jwt,f.command)));
 assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,20);
 assert.equal((await f.stub.fixtureEnroll(f.enrollment)).remaining,0);
});
test('revocation persists before cleanup and cleanup resumes after restart',async t=>{
 const f=await fixture(t);
 await f.stub.fixtureRevoke('entitlement-1');
 await f.restart();
 await assert.rejects(f.stub.execute(await f.token(),f.command),/authority_inactive/);
 await assert.rejects(f.stub.fixtureEnroll(f.enrollment),/authority_inactive/);
 assert.deepEqual(await f.stub.fixtureCleanupPending(),[{entitlement:'entitlement-1'}]);
 await f.stub.fixtureRevoke('entitlement-1');
 assert.equal((await f.stub.fixtureCleanupPending()).length,1);
 await f.stub.fixtureFinishCleanup('entitlement-1');
 await f.restart();
 assert.deepEqual(await f.stub.fixtureCleanupPending(),[]);
 assert.equal((await f.stub.fixtureInspect('entitlement-1')).revoked,1);
});
test('expiry and revoked projects retain lifetime capacity; clock never goes backward',async t=>{
 const f=await fixture(t);
 for(let n=2;n<=10;n++) await f.stub.fixtureEnroll({...f.enrollment,entitlement:`entitlement-${n}`,project:`fixture-project-${n}`,host:`host-${n}`});
 await f.stub.fixtureRevoke('entitlement-1');
 await assert.rejects(f.stub.fixtureEnroll({...f.enrollment,entitlement:'extra',project:'extra',host:'extra'}),/lifetime_project_cap/);
 await f.stub.fixtureClock(NOW+604800000);
 await assert.rejects(f.stub.fixtureEnroll({...f.enrollment,entitlement:'extra',project:'extra',host:'extra',issued:NOW+604800000}),/lifetime_project_cap/);
 await assert.rejects(f.stub.fixtureEnroll({...f.enrollment,entitlement:'entitlement-2',project:'fixture-project-2',host:'host-2'}),/authority_inactive/);
 await assert.rejects(f.stub.fixtureClock(NOW),/clock_reversal/);
});
test('invalid signatures/bindings/units fail without debit and HTTP ingress stays closed',async t=>{
 const f=await fixture(t);
 assert.equal((await f.mf.dispatchFetch('https://fixture.invalid/')).status,503);
 const wrong=await generateKeyPair('EdDSA');
 for(const jwt of [await f.token({},f.command,wrong.privateKey),await f.token({htu:AUD+'/other'}),await f.token({capabilities:['http_schedule']}),await f.token({ath:'wrong'})]) await assert.rejects(f.stub.execute(jwt,f.command));
 await assert.rejects(f.stub.execute(await f.token(),{capability:'fixture_debit',units:-5}),/invalid_command/);
 await assert.rejects(f.stub.execute(await f.token(),{capability:'http_schedule',units:5}),/invalid_command/);
 assert.equal((await f.stub.fixtureInspect('entitlement-1')).remaining,100);
});
test('missing fixture enable gate denies RPC state creation',async t=>{
 const dir=await mkdtemp(join(tmpdir(),'runlater-disabled-'));
 const f=await start(dir,false);
 t.after(async()=>{await f.mf.dispose();await rm(dir,{recursive:true,force:true});});
 await assert.rejects(f.stub.fixtureClock(NOW),/fixture_disabled/);
});
test('failed enrollment rolls back slot allocation and bounds host aliases',async t=>{
 const f=await fixture(t);
 await assert.rejects(f.stub.fixtureEnroll({...f.enrollment,entitlement:'conflicting',project:'new-project'}),/host_conflict/);
 assert.equal(await f.stub.fixtureInspect('conflicting'),null);
 for(let n=2;n<=4;n++) await f.stub.fixtureEnroll({...f.enrollment,host:`alias-${n}`});
 await assert.rejects(f.stub.fixtureEnroll({...f.enrollment,host:'alias-5'}),/host_cap/);
 assert.equal((await f.stub.fixtureInspect('entitlement-1')).remaining,100);
});
async function mint(key,host,command,now=NOW,changes={}) {
 return new SignJWT({sub:host,capabilities:['fixture_debit'],htm:'POST',htu:AUD,
  ath:createHash('sha256').update(JSON.stringify(command)).digest('base64url'),aud:AUD,
  iat:Math.floor(now/1000),exp:Math.floor(now/1000)+60,jti:randomUUID(),...changes})
  .setProtectedHeader({alg:'EdDSA',typ:'agent+jwt'}).sign(key);
}
test('expired ledger rejects fresh otherwise valid tokens without resetting budget',async t=>{
 const f=await fixture(t),later=NOW+604800000;
 await f.stub.fixtureClock(later);
 const token=await mint(f.key.privateKey,'host-1',f.command,later);
 await assert.rejects(f.stub.execute(token,f.command),/authority_inactive/);
 assert.equal((await f.stub.fixtureInspect('entitlement-1')).remaining,100);
});
test('malformed and overlong token lifetimes fail without replay or budget writes',async t=>{
 const f=await fixture(t),sec=Math.floor(NOW/1000);
 for(const changes of [{aud:'https://other.invalid'},{jti:undefined},{iat:'bad'},{exp:sec+1000},{iat:sec+120,exp:sec+180},{iat:sec-120,exp:sec-60}]) {
  await assert.rejects(f.stub.execute(await mint(f.key.privateKey,'host-1',f.command,NOW,changes),f.command));
 }
 assert.equal((await f.stub.fixtureInspect('entitlement-1')).remaining,100);
});
test('bounded replay partition fails closed then prunes only after tokens expire',async t=>{
 const f=await fixture(t),command={capability:'fixture_debit',units:1};
 for(let n=2;n<=6;n++) await f.stub.fixtureEnroll({...f.enrollment,entitlement:`entitlement-${n}`,project:`fixture-project-${n}`,host:`host-${n}`});
 const tokens=await Promise.all(Array.from({length:512},(_,i)=>mint(f.key.privateKey,`host-${Math.floor(i/100)+1}`,command)));
 for(const token of tokens) await f.stub.execute(token,command);
 assert.equal((await f.stub.fixtureInspect('entitlement-6')).remaining,88);
 await assert.rejects(f.stub.execute(await mint(f.key.privateKey,'host-6',command),command),/replay_capacity/);
 assert.equal((await f.stub.fixtureInspect('entitlement-6')).remaining,88);
 const later=NOW+91000;
 await f.stub.fixtureClock(later);
 await f.stub.execute(await mint(f.key.privateKey,'host-6',command,later),command);
 await assert.rejects(f.stub.execute(tokens[0],command));
 assert.equal((await f.stub.fixtureInspect('entitlement-6')).remaining,87);
});
