import {validateEnvelope,assertDeadline,boundedResult} from './envelope.mjs';
export const RECEIPT_LIMIT=10000;
export const HOST_LIMIT=1024;
const uncertain=()=>({ok:false,error:'attempt_uncertain',request_may_have_been_sent:true,automatic_retry:false});
// storage is the singleton Durable Object's transactional storage. No receipt deletion.
export function createDispatcher({storage,send,enabled=false,revision,now=Date.now}){
 let active=0;
 return async function dispatch(input,{signal}={}){
  if(enabled!==true)return {ok:false,error:'egress_disabled',request_may_have_been_sent:true,automatic_retry:false};
  if(active>=4)return {ok:false,error:'busy',request_may_have_been_sent:true,automatic_retry:false};
  active++;let claimed=false,absent=false,key,hash,timer,hostKey;
  const controller=new AbortController();const abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
  try{
   const checked=await validateEnvelope(input,now(),{historical:true});const e=checked.envelope;({key,hash}=checked);
   // Replays report persisted attempt truth even after expiry; this path never dispatches.
   const known=await storage.get('receipt:'+key);
   if(known){claimed=true;if(known.hash!==hash)return uncertain();return known.state==='completed'?boundedResult(known.result):uncertain();}
   absent=true;await validateEnvelope(e,now());
   if(e.adapter_revision!==revision)throw Error('revision_mismatch');
   const live=()=>{if(controller.signal.aborted)throw Error('cancelled');assertDeadline(e,now());};live();
   timer=setTimeout(abort,Math.max(0,e.deadline_ms-now()));
   const url=new URL(e.request.url);if(url.href!==e.request.url||url.protocol!=='https:'||url.hostname!==url.hostname.toLowerCase()||!url.hostname||url.username||url.password||url.port||url.hash||e.request.url.includes('#'))throw Error('invalid_target');
   hostKey='host:'+url.hostname;
   const decision=await storage.transaction(async tx=>{
    const prior=await tx.get('receipt:'+key);
    if(prior)return prior.hash===hash?{prior}:{conflict:true};
    const count=(await tx.get('receipt_count'))??0;
    if(!Number.isSafeInteger(count)||count<0||count>=RECEIPT_LIMIT)return {full:true};
    live();const timestamp=now();const globalLast=await tx.get('global_last_dispatch');
    const host=await tx.get(hostKey);const hostCount=(await tx.get('host_count'))??0;
    if((globalLast!==undefined&&(!Number.isSafeInteger(globalLast)||timestamp-globalLast<1000))
      ||(host&&(!Number.isSafeInteger(host.last)||!Number.isSafeInteger(host.activeUntil)||timestamp-host.last<10000||timestamp<host.activeUntil)))return {rate:true};
    if(!host&&(!Number.isSafeInteger(hostCount)||hostCount<0||hostCount>=HOST_LIMIT))return {rate:true};
    await tx.put('global_last_dispatch',timestamp);await tx.put(hostKey,{last:timestamp,activeUntil:e.deadline_ms,receipt:key});if(!host)await tx.put('host_count',hostCount+1);
    await tx.put('receipt:'+key,{hash,state:'reserved'});await tx.put('receipt_count',count+1);return {claimed:true};
   });
   if(decision.prior){claimed=true;return decision.prior.state==='completed'?boundedResult(decision.prior.result):uncertain();}
   if(decision.conflict)return uncertain();
   if(!decision.claimed)return {ok:false,error:decision.full?'receipt_capacity':decision.rate?'rate_limited':'attempt_conflict',request_may_have_been_sent:false,automatic_retry:false};
   claimed=true;live();
   // send must preserve this signal and absolute lease across cold start. No waitUntil/background work.
   let onAbort;const stopped=new Promise((_,reject)=>{onAbort=()=>reject(Error('cancelled'));controller.signal.addEventListener('abort',onAbort,{once:true});});
   let result;try{result=boundedResult(await Promise.race([send(e,{signal:controller.signal}),stopped]));}finally{controller.signal.removeEventListener('abort',onAbort);}live();
   await storage.transaction(async tx=>{await tx.put('receipt:'+key,{hash,state:'completed',result});const host=await tx.get(hostKey);if(host?.receipt===key)await tx.put(hostKey,{...host,activeUntil:0});});return result;
  }catch{return claimed||!absent?uncertain():{ok:false,error:'dispatch_rejected',request_may_have_been_sent:false,automatic_retry:false};}
  finally{clearTimeout(timer);controller.abort();signal?.removeEventListener('abort',abort);active--;}
 };
}
