import test from 'node:test';
import assert from 'node:assert/strict';
import {createOAuthStorage} from './oauth-storage.mjs';
import {oauthTransaction} from './oauth-transaction.mjs';
import {createTrialAuthority,validateTrialAuthority,TRIAL_MS} from './oauth-trial.mjs';
function memory(){let data=new Map();return {async get(k){return structuredClone(data.get(k));},async put(k,v){data.set(k,structuredClone(v));},async delete(k){data.delete(k);},async list({prefix='' }={}){return new Map([...data].filter(([k])=>k.startsWith(prefix)).map(([k,v])=>[k,structuredClone(v)]));},async transaction(fn){const old=structuredClone(data);try{return await fn(this);}catch(e){data=old;throw e;}}};}
test('issuer transaction cannot overwrite a concurrent distinct-client commit; collisions fail closed',async()=>{
 const storage=memory();let release,started;const wait=new Promise(r=>release=r),seen=new Promise(r=>started=r);
 const a=oauthTransaction(storage,async kv=>{await kv.put('client:a','A');started();await wait;});
 await seen;await oauthTransaction(storage,kv=>kv.put('client:b','B'));release();await assert.rejects(a,/commit_conflict/);
 assert.equal(await storage.get('oauth:client:a'),undefined);assert.equal((await storage.get('oauth:client:b')).value,'B');
 await oauthTransaction(storage,kv=>kv.put('client:a','A'));assert.equal((await storage.get('oauth:client:a')).value,'A');
 await assert.rejects(oauthTransaction(storage,async kv=>{await kv.put('client:b','changed');throw new Error('fail');}));
 assert.equal((await storage.get('oauth:client:b')).value,'B');
});
test('trial tuple has independent capability/revoke secrets and immutable client/scope/expiry binding',()=>{
 const now=Date.now(),options={releaseId:'fixture',clientId:'https://client.example/metadata',scopes:['read'],now};
 const trial=createTrialAuthority(options);assert.notEqual(trial.props.capability,trial.revocationSecret);
 assert.equal(trial.props.descriptor.expires_at_ms,now+TRIAL_MS);
 validateTrialAuthority(trial.props,{...options});
 assert.throws(()=>validateTrialAuthority(trial.props,{...options,clientId:'https://other.example/metadata'}));
 assert.throws(()=>validateTrialAuthority(trial.props,{...options,now:now+TRIAL_MS}));
 const modified=structuredClone(trial.props);modified.descriptor.expires_at_ms++;assert.throws(()=>validateTrialAuthority(modified,options));
 assert.notEqual(createTrialAuthority(options).props.descriptor.bootstrap_id,trial.props.descriptor.bootstrap_id);
});

test('disabled trial preserves old storage budgets; enabled pending client quota reserves active partition',async()=>{
 const old=createOAuthStorage(memory());
 for(let i=0;i<384;i++)await old.put(`token:p${Math.floor(i/32)}:g:${i}`,'fixture');
 for(let i=0;i<64;i++)await old.put(`client:${i}`,'fixture');
 for(let i=0;i<64;i++)await old.put(`transaction:${i}`,'fixture');
 assert.equal((await old.list()).keys.length,512);
 const enabled=createOAuthStorage(memory(),{trialEnabled:true});
 for(let i=0;i<8;i++)await enabled.put(`family:p${i}:g`,JSON.stringify({clientId:'shared-client',provisioned:false}));
 await assert.rejects(enabled.put('family:p8:g',JSON.stringify({clientId:'shared-client',provisioned:false})),/client_pending_capacity/);
 await enabled.put('family:p8:g',JSON.stringify({clientId:'other-client',provisioned:false}));
 for(let i=0;i<10;i++)await enabled.put(`family:active${i}:g`,JSON.stringify({clientId:'shared-client',provisioned:true}));
 await assert.rejects(enabled.put('family:active10:g',JSON.stringify({clientId:'shared-client',provisioned:true})),/partition_capacity/);
});
