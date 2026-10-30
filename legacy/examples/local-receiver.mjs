// Protocol demonstration only: no server, network, proxy, production secrets or durable dedup.
import {createHmac,timingSafeEqual} from 'node:crypto';
import {operationDedup} from './operation-dedup.mjs';
export const LOCAL_FIXTURE_KEY='public-local-fixture-signing-key-not-for-production';
export function fixtureSignature(timestamp,task,operation,body){return createHmac('sha256',LOCAL_FIXTURE_KEY).update(`${timestamp}.${task}.${operation}.`).update(body).digest('hex');}
export function createLocalReceiver(){
 const dedup=operationDedup();
 return ({headers,body,nowMs=Date.now()})=>{
  const h=new Headers(headers),bytes=Buffer.from(body);
  if(h.has('RunLater-Signature-Version')||h.has('RunLater-Key-Id')||h.has('RunLater-Signing-Policy'))return {status:401};
  if(bytes.length>16384)return {status:413};
  const task=h.get('RunLater-Task-Id')??'',op=h.get('RunLater-Operation-Key')??'',timestamp=h.get('RunLater-Timestamp')??'',signature=h.get('RunLater-Signature')??'';
  const tenant=task.split(':')[0];
  if(!/^[A-Za-z0-9_-]{1,64}:task_[0-9a-f]{16}$/.test(task)||!/^[A-Za-z0-9_-]{1,128}$/.test(op)||!/^\d{1,12}$/.test(timestamp)||String(Number(timestamp))!==timestamp||!Number.isSafeInteger(nowMs)||Math.abs(Math.floor(nowMs/1000)-Number(timestamp))>300||!/^[0-9a-f]{64}$/.test(signature))return {status:401};
  const expected=Buffer.from(fixtureSignature(timestamp,task,op,bytes),'hex');
  if(!timingSafeEqual(expected,Buffer.from(signature,'hex')))return {status:401};
  return dedup(tenant,op,bytes);
 };
}
