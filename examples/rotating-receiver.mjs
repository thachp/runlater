// Callback-v2 verifier/policy helpers and opt-in offline fixture receiver. No network.
import {createHmac,timingSafeEqual} from 'node:crypto';import {operationDedup} from './operation-dedup.mjs';
const materials=Object.freeze({fixture_a:'public-fixture-callback-a-not-production',fixture_b:'public-fixture-callback-b-not-production',fixture_c:'public-fixture-callback-c-not-production'});
const identifier=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(s),time=n=>Number.isSafeInteger(n)&&n>=0&&n<=253402300799;
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');
const stable=v=>JSON.stringify(v,(_,item)=>item&&typeof item==='object'&&!Array.isArray(item)?Object.fromEntries(Object.entries(item).sort(([a],[b])=>a.localeCompare(b))):item);
export function validatePolicy(p){
 if(!exact(p,['version','tenant','policy_id','revision','keys','rotations'])||p.version!=='v2'||!identifier(p.tenant)||!identifier(p.policy_id)||!Number.isSafeInteger(p.revision)||p.revision<1||!p.keys||typeof p.keys!=='object'||Array.isArray(p.keys)||!p.rotations||typeof p.rotations!=='object'||Array.isArray(p.rotations))return false;
 const keys=Object.entries(p.keys);if(keys.length<1||keys.length>16||Object.keys(p.rotations).length+1!==keys.length||p.revision!==keys.length+keys.filter(([,k])=>k?.revoked_at_sec!==null).length)return false;
 const revisions=new Set();
 for(const[id,k]of keys){if(!exact(k,['key_id','introduced_revision','active_from_sec','sign_until_sec','verify_until_sec','revoked_at_sec'])||!identifier(id)||id!==k.key_id||!Number.isSafeInteger(k.introduced_revision)||k.introduced_revision<1||k.introduced_revision>p.revision||revisions.has(k.introduced_revision)||!time(k.active_from_sec)||!time(k.sign_until_sec)||!time(k.verify_until_sec)||k.sign_until_sec<k.active_from_sec||k.verify_until_sec<k.sign_until_sec||k.verify_until_sec-k.sign_until_sec>300||(k.revoked_at_sec!==null&&!time(k.revoked_at_sec)))return false;revisions.add(k.introduced_revision);}
 if(keys.filter(([,k])=>k.introduced_revision===1).length!==1||keys.some(([id,k])=>k.introduced_revision!==1&&!Object.hasOwn(p.rotations,id)))return false;
 const active=keys.map(([,k])=>k).filter(k=>k.revoked_at_sec===null);for(let i=0;i<active.length;i++)for(const b of active.slice(i+1)){const a=active[i];if(a.active_from_sec<b.sign_until_sec&&b.active_from_sec<a.sign_until_sec)return false;}
 for(const[id,r]of Object.entries(p.rotations)){if(!exact(r,['source','cutover_sec','sign_until_sec'])||!Object.hasOwn(p.keys,id)||!Object.hasOwn(p.keys,r.source))return false;const newer=p.keys[id],old=p.keys[r.source];if(id===r.source||newer.introduced_revision<=old.introduced_revision||newer.active_from_sec!==r.cutover_sec||newer.sign_until_sec>r.sign_until_sec||old.sign_until_sec>r.cutover_sec||!time(r.sign_until_sec))return false;}
 return true;
}
export function fixtureV2Signature(policy,keyId,timestamp,task,operation,bytes){if(!Object.hasOwn(materials,keyId))return null;return createHmac('sha256',materials[keyId]).update(`runlater.v2.${policy}.${keyId}.${timestamp}.${task}.${operation}.`).update(bytes).digest('hex');}
export function verifyV2WithMaterial(policy,headers,body,nowSec,lookup){
 if(!validatePolicy(policy)||!time(nowSec))return false;let h,bytes;try{h=new Headers(headers);bytes=Buffer.from(body)}catch{return false}if(bytes.length>16384)return false;
 const version=h.get('RunLater-Signature-Version'),kid=h.get('RunLater-Key-Id'),scope=h.get('RunLater-Signing-Policy'),ts=h.get('RunLater-Timestamp')??'',task=h.get('RunLater-Task-Id')??'',operation=h.get('RunLater-Operation-Key')??'',sig=h.get('RunLater-Signature')??'';
 if(version!=='v2'||scope!==policy.policy_id||!kid||!Object.hasOwn(policy.keys,kid)||!/^\d{1,12}$/.test(ts)||String(Number(ts))!==ts||!time(Number(ts))||Math.abs(nowSec-Number(ts))>300||!task.startsWith(policy.tenant+':')||!/^task_[0-9a-f]{16}$/.test(task.slice(policy.tenant.length+1))||!/^[A-Za-z0-9_-]{1,128}$/.test(operation)||!/^[0-9a-f]{64}$/.test(sig))return false;
 const key=policy.keys[kid];if(key.revoked_at_sec!==null||nowSec<key.active_from_sec||nowSec>=key.verify_until_sec||Number(ts)<key.active_from_sec||Number(ts)>=key.sign_until_sec)return false;
 let material;try{material=lookup(kid)}catch{return false}if(!(material instanceof Uint8Array)||material.byteLength<32)return false;
 const expected=createHmac('sha256',material).update(`runlater.v2.${scope}.${kid}.${ts}.${task}.${operation}.`).update(bytes).digest();return timingSafeEqual(expected,Buffer.from(sig,'hex'));
}
export function verifyV2(policy,headers,body,nowSec){return verifyV2WithMaterial(policy,headers,body,nowSec,id=>Object.hasOwn(materials,id)?Buffer.from(materials[id]):null);}
export function advancePolicy(previous,next){
 if(!validatePolicy(previous)||!validatePolicy(next)||next.tenant!==previous.tenant||next.policy_id!==previous.policy_id||next.revision<previous.revision)throw Error('Invalid policy transition');
 if(next.revision===previous.revision){if(stable(next)!==stable(previous))throw Error('Policy revision conflict');return structuredClone(next);}
 for(const[id,old]of Object.entries(previous.keys)){const k=Object.hasOwn(next.keys,id)?next.keys[id]:null;if(!k||k.introduced_revision!==old.introduced_revision||k.active_from_sec!==old.active_from_sec||k.sign_until_sec>old.sign_until_sec||k.verify_until_sec>old.verify_until_sec||(old.revoked_at_sec!==null&&k.revoked_at_sec!==old.revoked_at_sec))throw Error('Key history cannot be reset or extended');}
 for(const[id,old]of Object.entries(previous.rotations))if(!Object.hasOwn(next.rotations,id)||stable(next.rotations[id])!==stable(old))throw Error('Rotation identity cannot change');
 return structuredClone(next);
}
export function createRotatingReceiver(initialPolicy){
 if(!validatePolicy(initialPolicy))throw Error('Invalid fixture signing policy');let policy=structuredClone(initialPolicy);const dedup=operationDedup();
 return {
  updatePolicy(next){policy=advancePolicy(policy,next);},
  receive({headers,body,nowSec=Math.floor(Date.now()/1000)}){if(!verifyV2(policy,headers,body,nowSec))return {status:401};const h=new Headers(headers);return dedup(policy.tenant,h.get('RunLater-Operation-Key'),Buffer.from(body));}
 };
}
