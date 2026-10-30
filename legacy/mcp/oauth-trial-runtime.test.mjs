import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {build} from 'esbuild';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {fileURLToPath} from 'node:url';
const origin='https://mcp.runlater.io', client='https://client.example.com/metadata';
test('anonymous seven-day OAuth: no allocation, atomic issuance, strict refresh replay and durable cleanup', {timeout:30000},async t=>{
  const root=fileURLToPath(new URL('../',import.meta.url));
  const script=(await build({stdin:{resolveDir:root,contents:`
    import {DurableObject} from 'cloudflare:workers';
    import {createRunLaterOAuth} from './mcp/oauth.mjs';
    export class Hub extends DurableObject {
      constructor(ctx,env){super(ctx,env);this.fail=false;this.apiDown=false;this.validations=0;this.revokes=0;
        const storage={get:(...a)=>ctx.storage.get(...a),put:(...a)=>ctx.storage.put(...a),delete:(...a)=>ctx.storage.delete(...a),list:(...a)=>ctx.storage.list(...a),
          transaction:fn=>ctx.storage.transaction(async tx=>{const result=await fn(tx);if(this.fail){this.fail=false;throw new Error('fixture_commit_failure');}return result;})};
        this.makeApp=()=>createRunLaterOAuth({env:{...env,MCP_ANONYMOUS_TRIAL_ENABLED:this.trialOff ? "disabled" : env.MCP_ANONYMOUS_TRIAL_ENABLED,MCP_RECEIVER_PAIRING_ENABLED:this.pairOff ? "disabled" : "operator-approved"},storage,validateDelegation:async()=>{throw new Error();},
          validateTrial:async t=>{this.validations++;return {state:'unprovisioned',expires_at_ms:t.descriptor.expires_at_ms};},
          revokeTrial:async()=>{if(this.apiDown)throw new Error('fixture_unavailable');if(this.falseRevoke)return {revoked:false};this.revokes++;return {revoked:true};},
          protectedHandler:{fetch:async(req,env,c)=>{this.capability=c.principal.trial.capability;return Response.json({kind:c.principal.kind,project:c.principal.trial.descriptor.bootstrap_id,expires:c.principal.trial.descriptor.expires_at_ms,scopes:c.principal.scopes});}}});this.app=this.makeApp();}
      async fetch(req){const path=new URL(req.url).pathname;
        if(path==='/_fixture/pair-off'){this.pairOff=true;this.app=this.makeApp();return new Response('ok');}
        if(path==='/_fixture/pair-on'){this.pairOff=false;this.app=this.makeApp();return new Response('ok');}
        if(path==='/_fixture/false-revoke'){this.falseRevoke=true;return new Response('ok');}
        if(path==='/_fixture/true-revoke'){this.falseRevoke=false;return new Response('ok');}
        if(path==='/_fixture/off'){this.trialOff=true;this.app=this.makeApp();return new Response('ok');}
        if(path==='/_fixture/on'){this.trialOff=false;this.app=this.makeApp();return new Response('ok');}
        if(path==='/_fixture/drain-failed'){this.apiDown=true;return Response.json(await this.app.drainRevocations());}
        if(path==='/_fixture/restart'){this.app=this.makeApp();return new Response('ok');}
        if(path==='/_fixture/secret-check'){const rows=await this.ctx.storage.list();return Response.json({taskCapabilityStored:JSON.stringify([...rows]).includes(this.capability)});}
        if(path==='/_fixture/seed-cleanups'){const rows=await this.ctx.storage.list({prefix:'oauth:family:'});const sample=JSON.parse(rows.values().next().value.value);for(let i=0;i<3;i++){const f={...sample,clientId:'cleanup-client',revoked:true,cleanupDone:false,cleanupAttempts:0,nextAttemptAtMs:0,revocationSecret:'b'.repeat(64)};await this.ctx.storage.put('oauth:family:cleanup'+i+':g',{value:JSON.stringify(f),expiration:Math.ceil(f.expiresAt/1000)});}return new Response('ok');}
        if(path==='/_fixture/fail'){this.fail=true;return new Response('ok');}
        if(path==='/_fixture/down'){this.apiDown=true;return new Response('ok');}
        if(path==='/_fixture/drain'){this.apiDown=false;const queue=await this.app.drainRevocations();return Response.json({revokes:this.revokes,...queue});}
        if(path==='/_fixture/expire-pending'){for(const [key,record] of await this.ctx.storage.list({prefix:'oauth:family:'})){if(!JSON.parse(record.value).issued){record.expiration=Math.floor(Date.now()/1000)-1;await this.ctx.storage.put(key,record);}}return new Response('ok');}
        if(path==='/_fixture/exhaust'){for(const [key,record] of await this.ctx.storage.list({prefix:'oauth:family:'})){const value=JSON.parse(record.value);if(!value.revoked){value.consumed=Array.from({length:192},(_,i)=>i.toString(16).padStart(64,'0'));record.value=JSON.stringify(value);await this.ctx.storage.put(key,record);}}return new Response('ok');}
        if(path==='/_fixture/elapsed'){for(const [key,record] of await this.ctx.storage.list({prefix:'oauth:family:'})){const value=JSON.parse(record.value);value.nextAttemptAtMs=0;record.value=JSON.stringify(value);await this.ctx.storage.put(key,record);}return new Response('ok');}
        if(path==='/_fixture/count'){return Response.json({validations:this.validations,revokes:this.revokes});}
        return this.app.fetch(req,this.env,this.ctx);}
    }
    export default {fetch(req,env){return env.HUB.get(env.HUB.idFromName('one')).fetch(req);}};`},bundle:true,platform:'neutral',mainFields:['module','main'],format:'esm',external:['cloudflare:*','node:*'],write:false,drop:['console']})).outputFiles[0].text;
  let unexpected=0;
  const mf=new Miniflare(convertV4MiniflareOptions({modules:true,script,compatibilityDate:'2026-10-28',compatibilityFlags:['nodejs_compat','global_fetch_strictly_public'],
    durableObjects:{HUB:{className:'Hub',useSQLite:true}},bindings:{MCP_OAUTH_ENABLED:'operator-approved',MCP_ANONYMOUS_TRIAL_ENABLED:'operator-approved',MCP_GATEWAY_PUBLIC_KEY:'a'.repeat(64),MCP_RELEASE_ID:'trial_fixture'},
    outboundService:async req=>{if([client,'https://other.example.com/metadata'].includes(req.url))return Response.json({client_id:req.url,client_name:'Fixture',redirect_uris:['https://client.example.com/callback'],token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],response_types:['code']});unexpected++;return new Response(null,{status:403});}}));
  t.after(()=>mf.dispose());
  const call=(path,init={})=>mf.dispatchFetch(origin+path,{...init,redirect:'manual'});
  const post=(body)=>call('/oauth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body).toString()});
  const access=token=>call('/mcp',{headers:{Authorization:'Bearer '+token}});
  async function consent(scope='cancel enqueue read'){const verifier='v'.repeat(64),challenge=createHash('sha256').update(verifier).digest('base64url');
    const params=new URLSearchParams({response_type:'code',client_id:client,redirect_uri:'https://client.example.com/callback',scope,state:'fixture',resource:origin,code_challenge:challenge,code_challenge_method:'S256'});
    const page=await call('/authorize?'+params);assert.equal(page.status,200);const html=await page.text();assert.match(html,/Start free agent project/);
    const handle=html.match(/name="handle" value="([^"]+)"/)[1],cookie=page.headers.get('set-cookie').split(';')[0];
    const missing=await call('/authorize',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Origin:origin},body:new URLSearchParams({handle,decision:'trial'}).toString()});assert.equal(missing.status,400);
    const approved=await call('/authorize',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Origin:origin,Cookie:cookie},body:new URLSearchParams({handle,decision:'trial'}).toString()});assert.equal(approved.status,302);
    return {grant_type:'authorization_code',client_id:client,code:new URL(approved.headers.get('location')).searchParams.get('code'),code_verifier:verifier,redirect_uri:'https://client.example.com/callback',resource:origin};}
  const form=await consent();assert.equal((await (await call('/_fixture/count')).json()).validations,0);
  await call('/_fixture/fail');assert.equal((await post(form)).status,503);
  const issued=await post(form);assert.equal(issued.status,200);const first=await issued.json();assert.ok(first.refresh_token);assert.equal(first.expires_in,3600);
  const identity=await (await access(first.access_token)).json();assert.equal(identity.kind,'trial');assert.ok(identity.expires>Date.now()+6*86400000);
  const refresh=token=>post({grant_type:'refresh_token',client_id:client,refresh_token:token,resource:origin});
  const wrong=await post({grant_type:'refresh_token',client_id:'https://other.example.com/metadata',refresh_token:first.refresh_token,resource:origin});assert.equal(wrong.status,400);assert.equal((await access(first.access_token)).status,200);
  await call('/_fixture/fail');assert.equal((await refresh(first.refresh_token)).status,503);
  const second=await (await refresh(first.refresh_token)).json();assert.ok(second.refresh_token);assert.notEqual(second.refresh_token,first.refresh_token);assert.equal((await access(first.access_token)).status,401);
  const thirdResponse=await refresh(second.refresh_token);assert.equal(thirdResponse.status,200);const third=await thirdResponse.json();
  assert.deepEqual(await (await access(third.access_token)).json(),identity);
  const invalidClient=await post({grant_type:'refresh_token',client_id:client,client_secret:'invalid-fixture',refresh_token:first.refresh_token,resource:origin});assert.equal(invalidClient.status,401);
  assert.equal((await access(third.access_token)).status,200);
  const unknown=third.refresh_token.split(':').slice(0,2).join(':')+':'+ 'x'.repeat(40);assert.equal((await refresh(unknown)).status,400);assert.equal((await access(third.access_token)).status,200);
  assert.equal((await (await call('/_fixture/secret-check')).json()).taskCapabilityStored,false);
  await call('/_fixture/down');assert.equal((await refresh(first.refresh_token)).status,400); // Older than provider previous token.
  assert.equal((await access(third.access_token)).status,401);assert.equal((await refresh(third.refresh_token)).status,400);
  assert.equal((await (await call('/_fixture/count')).json()).revokes,0);
  assert.equal((await (await call('/_fixture/drain')).json()).pending,true);
  await call('/_fixture/restart');assert.equal((await access(third.access_token)).status,401);
  await call('/_fixture/elapsed');
  assert.equal((await (await call('/_fixture/drain')).json()).revokes,1);
  assert.equal((await (await call('/_fixture/drain')).json()).revokes,1);const concurrentToken=await (await post(await consent())).json();
  const results=await Promise.all([refresh(concurrentToken.refresh_token),refresh(concurrentToken.refresh_token)]);
  assert.deepEqual(results.map(r=>r.status).sort(),[200,400]);
  const rotated=await results.find(r=>r.status===200).json();assert.equal((await access(rotated.access_token)).status,401);
  const exhausted=await (await post(await consent())).json();await call('/_fixture/exhaust');assert.equal((await refresh(exhausted.refresh_token)).status,400);assert.equal((await access(exhausted.access_token)).status,401);
  const beforeCleanup=(await (await call('/_fixture/count')).json()).revokes;await call('/_fixture/seed-cleanups');
  const bounded=await (await call('/_fixture/drain')).json();assert.equal(bounded.revokes,beforeCleanup+2);assert.equal(bounded.pending,true);
  const rest=await (await call('/_fixture/drain')).json();assert.equal(rest.revokes,beforeCleanup+3);assert.equal(rest.pending,false);
  const expiredFamilyForm=await consent();await call('/_fixture/expire-pending');assert.equal((await post(expiredFamilyForm)).status,503);
  const rollbackToken=await (await post(await consent())).json();
  await call('/_fixture/seed-cleanups');await call('/_fixture/off');
  assert.equal((await access(rollbackToken.access_token)).status,401);
  const deniedRefresh=await refresh(rollbackToken.refresh_token);assert.notEqual(deniedRefresh.status,200);
  const deniedBody=await deniedRefresh.json();assert.equal(deniedBody.access_token,undefined);assert.equal(deniedBody.refresh_token,undefined);
  const offFailure=await (await call('/_fixture/drain-failed')).json();assert.equal(offFailure.pending,true);
  // A second pass admits the third family; every failed attempt must then be backed off.
  const offBackoff=await (await call('/_fixture/drain-failed')).json();assert.ok(offBackoff.nextAttemptAtMs>Date.now()+25000);
  await call('/_fixture/restart');
  assert.ok((await (await call('/_fixture/drain-failed')).json()).nextAttemptAtMs>Date.now()+25000);
  await call('/_fixture/elapsed');const offClean=await (await call('/_fixture/drain')).json();assert.equal(offClean.pending,true);
  assert.equal((await (await call('/_fixture/drain')).json()).pending,false);
  await call('/_fixture/seed-cleanups');await call('/_fixture/false-revoke');
  const beforeFalse=(await (await call('/_fixture/count')).json()).revokes;
  await call('/_fixture/drain');const falseResult=await (await call('/_fixture/drain')).json();
  assert.equal(falseResult.revokes,beforeFalse);assert.equal(falseResult.pending,true);assert.ok(falseResult.nextAttemptAtMs>Date.now()+25000);
  await call('/_fixture/true-revoke');await call('/_fixture/elapsed');await call('/_fixture/drain');
  assert.equal((await (await call('/_fixture/drain')).json()).pending,false);
  // Newly consented setup scope is explicit; disabling pairing admission must not
  // change installed task authority or permit scope upgrade on old credentials.
  await call('/_fixture/on');
  const pairingIssued=await post(await consent('cancel enqueue read receiver_setup'));
  assert.equal(pairingIssued.status,200);const pairingTokens=await pairingIssued.json();
  assert.equal(pairingTokens.scope,'cancel enqueue read receiver_setup');
  const pairingIdentity=await (await access(pairingTokens.access_token)).json();assert.ok(pairingIdentity.scopes.includes('receiver_setup'));
  await call('/_fixture/pair-off');
  const metadata=await (await call('/.well-known/oauth-protected-resource')).json();assert.deepEqual(metadata.scopes_supported,['cancel','enqueue','read']);
  assert.equal((await access(pairingTokens.access_token)).status,200);
  const pairedRefresh=await refresh(pairingTokens.refresh_token);assert.equal(pairedRefresh.status,200);
  const pairedNext=await pairedRefresh.json();assert.deepEqual(await (await access(pairedNext.access_token)).json(),pairingIdentity);
  const blockedParams=new URLSearchParams({response_type:'code',client_id:client,redirect_uri:'https://client.example.com/callback',scope:'receiver_setup',state:'fixture',resource:origin,code_challenge:'a'.repeat(43),code_challenge_method:'S256'});
  assert.equal((await call('/authorize?'+blockedParams)).status,400);
  const taskOnly=await (await post(await consent())).json();
  const noUpgrade=await post({grant_type:'refresh_token',client_id:client,refresh_token:taskOnly.refresh_token,resource:origin,scope:'receiver_setup'});
  assert.notEqual(noUpgrade.status,200);assert.equal((await access(taskOnly.access_token)).status,200);
  await call('/_fixture/pair-on');
  assert.equal(unexpected,0);
});

test('disabled trial storage permits only monotonic cleanup on existing tombstones',async()=>{
  const {createOAuthStorage}=await import('./oauth-storage.mjs');
  const records=new Map(),storage={async get(k){return records.get(k);},async put(k,v){records.set(k,v);},async delete(k){records.delete(k);},async list({prefix='' }={}){return new Map([...records].filter(([k])=>k.startsWith(prefix)));}};
  const now=Date.now(),deadline=now+604800000;
  const family={clientId:'fixture-client',descriptor:{bootstrap_id:'a'.repeat(64)},expiresAt:deadline,consumed:['b'.repeat(64)],
    revoked:true,cleanupDone:false,cleanupAttempts:0,nextAttemptAtMs:0,revocationSecret:'c'.repeat(64)};
  const expiration=Math.floor(deadline/1000),key='family:fixture:grant';
  records.set('oauth:'+key,{value:JSON.stringify(family),expiration});
  const off=createOAuthStorage(storage,{trialEnabled:false}),write=f=>off.put(key,JSON.stringify(f),{expiration:Math.ceil(deadline/1000)});
  const admission={...family,cleanupAttempts:1,nextAttemptAtMs:now+30000};await write(admission);
  assert.equal(records.get('oauth:'+key).expiration,expiration);
  for(const changed of [{...admission,revoked:false},{...admission,clientId:'changed'},
    {...admission,descriptor:{bootstrap_id:'changed'}},{...admission,consumed:[]},{...admission,expiresAt:deadline+1},
    {...admission,revocationSecret:'d'.repeat(64)},{...admission,cleanupAttempts:0},{...admission,cleanupAttempts:33},
    {...admission,nextAttemptAtMs:0},{...admission,nextAttemptAtMs:deadline+1}])await assert.rejects(write(changed),/trial_storage_disabled/);
  await assert.rejects(off.put('family:new:grant',JSON.stringify(family),{expiration}),/capacity|disabled/);
  await assert.rejects(off.put('grant:new:grant',JSON.stringify({metadata:{authorityKind:'trial'}}),{expiration}),/trial_storage_disabled/);
  await assert.rejects(off.put('token:fixture:grant:new','{}',{expiration}),/trial_storage_disabled/);
  const done={...admission,cleanupDone:true};delete done.revocationSecret;await write(done);
  await assert.rejects(write({...done,cleanupDone:false}),/trial_storage_disabled/);
  records.set('oauth:family:unrevoked:grant',{value:JSON.stringify({...family,revoked:false}),expiration});
  await assert.rejects(off.put('family:unrevoked:grant',JSON.stringify(family),{expiration}),/trial_storage_disabled/);
});
