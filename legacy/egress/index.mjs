// No listener, endpoint or deployment. Default-off native Node component, not a Worker Fetch shim.
import {Resolver} from 'node:dns/promises';
import {destinationURL,resolvePublic} from './address-policy.mjs';
import {createNativeTransport} from './native-transport.mjs';
export const LIMITS=Object.freeze({bodyBytes:1024,responseBytes:16384,headerBytes:8192,deadlineMs:5000,concurrency:4});
function validated(input){
 if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).some(k=>!['url','body','contentType','operationKey','privateHeaders'].includes(k)))throw Error('invalid_request');
 const target=destinationURL(input.url);
 if(typeof input.body!=='string'||Buffer.byteLength(input.body)>1024||!['application/json','text/plain; charset=utf-8'].includes(input.contentType)
  ||typeof input.operationKey!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(input.operationKey))throw Error('invalid_request');
 const headers={'Host':target.hostname,'Content-Type':input.contentType,'Content-Length':String(Buffer.byteLength(input.body)),
  'Idempotency-Key':input.operationKey,'Connection':'close','User-Agent':'RunLater-Delivery/1'};
 const privateHeaders=input.privateHeaders??{};
 if(!privateHeaders||typeof privateHeaders!=='object'||Array.isArray(privateHeaders)||Object.keys(privateHeaders).length>1)throw Error('invalid_request');
 for(const [name,value]of Object.entries(privateHeaders)){
  if(!['Authorization','X-API-Key'].includes(name)||typeof value!=='string'||value.length<1||value.length>2048||!/^[\x20-\x7e]+$/.test(value))throw Error('invalid_request');headers[name]=value;
 }
 return {...target,body:Buffer.from(input.body),headers};
}
// Dependencies are internal composition seams for offline tests, never accepted from network/input/env.
export function createNativeEgress({enabled=false,resolverFactory=()=>new Resolver({timeout:1000,tries:1}),transport=createNativeTransport(),monotonicNow=()=>performance.now()}={}){
 let active=0;
 return Object.freeze({async deliver(input,{signal,deadlineMs}={}){
  if(enabled!==true)return {ok:false,error:'egress_disabled',request_may_have_been_sent:false,automatic_retry:false};
  if(deadlineMs!==undefined&&(!Number.isSafeInteger(deadlineMs)||deadlineMs<=Date.now()))return {ok:false,error:'deadline_or_cancelled',request_may_have_been_sent:false,automatic_retry:false};
  if(signal!==undefined&&!(signal instanceof AbortSignal))return {ok:false,error:'invalid_request',request_may_have_been_sent:false,automatic_retry:false};
  if(/(?:http|https|tls|net|\*)/i.test(process.env.NODE_DEBUG??'') || !!process.env.NODE_DEBUG_NATIVE || !!process.env.SSLKEYLOGFILE
   ||/--tls-keylog(?:[=\s]|$)/.test([process.env.NODE_OPTIONS??'',...process.execArgv].join(' ')))return {ok:false,error:'unsafe_runtime_logging',request_may_have_been_sent:false,automatic_retry:false};
  if(active>=LIMITS.concurrency)return {ok:false,error:'busy',request_may_have_been_sent:false,automatic_retry:false};
  const budget=Math.min(LIMITS.deadlineMs,deadlineMs===undefined?LIMITS.deadlineMs:deadlineMs-Date.now());
  const expires=monotonicNow()+budget;
  active++;let resolver,timer,attempted=false;const controller=new AbortController();
  const assertLive=()=>{if(controller.signal.aborted||monotonicNow()>=expires||(deadlineMs!==undefined&&Date.now()>=deadlineMs)){controller.abort();throw Error('deadline_or_cancelled');}};
  const abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)controller.abort();
  try{
   assertLive();const request=validated(input);resolver=resolverFactory();
   const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();try{resolver.cancel();}catch{}reject(Error('deadline_or_cancelled'));},Math.max(0,budget));});
   const cancellation=new Promise((_,reject)=>{if(controller.signal.aborted)reject(Error());else controller.signal.addEventListener('abort',()=>reject(Error()),{once:true});});
   const operation=(async()=>{
    assertLive();const addresses=await resolvePublic(request.hostname,resolver,controller.signal);assertLive();
    // Exactly one address/attempt. No fallback DNS lookup or alternate-address retry.
    return transport({...request,...addresses[0],signal:controller.signal,beforeConnect:assertLive,onAttempt:()=>{assertLive();attempted=true;}});
   })();
   const result=await Promise.race([operation,deadline,cancellation]);
   if(!result||!Number.isInteger(result.http_status)||result.http_status<200||result.http_status>599
    ||!['http_response','redirect_rejected'].includes(result.outcome)||!Number.isSafeInteger(result.response_bytes)||result.response_bytes<0||result.response_bytes>16384)throw Error();
   return {ok:true,http_status:result.http_status,outcome:result.outcome,response_bytes:result.response_bytes,request_may_have_been_sent:attempted,automatic_retry:false};
  }catch{return {ok:false,error:controller.signal.aborted?'deadline_or_cancelled':'delivery_rejected_or_failed',request_may_have_been_sent:attempted,automatic_retry:false};}
  finally{clearTimeout(timer);controller.abort();try{resolver?.cancel();}catch{}signal?.removeEventListener('abort',abort);active--;}
 }});
}
