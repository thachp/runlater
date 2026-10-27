// Protocol demonstration only: no server, network, proxy, production secrets or durable dedup.
import {createHmac,createHash,timingSafeEqual} from 'node:crypto';
export const LOCAL_FIXTURE_KEY='public-local-fixture-signing-key-not-for-production';
export function fixtureSignature(timestamp,task,operation,body){return createHmac('sha256',LOCAL_FIXTURE_KEY).update(`${timestamp}.${task}.${operation}.`).update(body).digest('hex');}
export function createLocalReceiver(){
 const seen=new Map();
 return ({headers,body,nowMs=Date.now()})=>{
  const h=new Headers(headers),bytes=Buffer.from(body);
  if(bytes.length>16384)return {status:413};
  const task=h.get('RunLater-Task-Id')??'',op=h.get('RunLater-Operation-Key')??'',timestamp=h.get('RunLater-Timestamp')??'',signature=h.get('RunLater-Signature')??'';
  const tenant=task.split(':')[0];
  if(!/^[A-Za-z0-9_-]{1,64}:task_[0-9a-f]{16}$/.test(task)||!/^[A-Za-z0-9_-]{1,128}$/.test(op)||!/^\d{1,12}$/.test(timestamp)||String(Number(timestamp))!==timestamp||!Number.isSafeInteger(nowMs)||Math.abs(Math.floor(nowMs/1000)-Number(timestamp))>300||!/^[0-9a-f]{64}$/.test(signature))return {status:401};
  const expected=Buffer.from(fixtureSignature(timestamp,task,op,bytes),'hex');
  if(!timingSafeEqual(expected,Buffer.from(signature,'hex')))return {status:401};
  const key=tenant+':'+op,digest=createHash('sha256').update(bytes).digest('hex');
  if(seen.has(key))return seen.get(key)===digest?{status:204,duplicate:true}:{status:409};
  if(seen.size>=1024)return {status:503};
  seen.set(key,digest);return {status:204,duplicate:false};
 };
}
