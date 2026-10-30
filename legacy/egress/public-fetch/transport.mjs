// Worker global Fetch only: provider public-network boundary, NOT observed peer pinning.
import {assertDeadline,validateEnvelope,readLimited} from '../controller/envelope.mjs';
export const TRANSPORT='worker-public-fetch-v1';
export const LIMITS=Object.freeze({deadlineMs:5000,headerBytes:8192,responseBytes:16384,responseChunks:128});
export const enabled=env=>env.EGRESS_TRANSPORT===TRANSPORT&&env.EGRESS_ENABLED==='operator-approved'
 &&typeof env.EGRESS_REVIEW_REVISION==='string'&&/^[0-9a-f]{64}$/.test(env.EGRESS_REVIEW_REVISION)&&env.EGRESS_REVIEW_REVISION!=='0'.repeat(64);
export function destination(raw){
 if(typeof raw!=='string'||raw.length>2048||raw.includes('#')||!/^https:\/\/[\x21-\x7e]+$/.test(raw)||raw.includes('\\')||/%(?:0[0-9a-f]|1[0-9a-f]|7f)/i.test(raw))throw Error('invalid_target');
 const u=new URL(raw),h=u.hostname;
 if(u.href!==raw||u.protocol!=='https:'||u.username||u.password||u.port||u.hash||h.length>253
  ||/^[0-9.]+$/.test(h)||h.split('.').length<2||!h.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))
  ||/(?:^|\.)(?:localhost|local|internal|home|onion|arpa|invalid|test)$/.test(h))throw Error('invalid_target');
 return u;
}
// fetchImpl is a source-only offline test seam; never derived from input or environment.
export function createPublicFetch({approved=false,revision,fetchImpl=request=>globalThis.fetch(request)}={}){
 return async function send(input,{signal}={}){
  let attempted=false,response,timer,onAbort;
  const controller=new AbortController();
  const abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
  const live=e=>{if(controller.signal.aborted)throw Error('cancelled');assertDeadline(e);};
  try{
   if(approved!==true)throw Error('disabled');
   const {envelope:e}=await validateEnvelope(input);if(e.adapter_revision!==revision)throw Error('revision');
   destination(e.request.url);live(e);
   timer=setTimeout(abort,Math.min(LIMITS.deadlineMs,e.deadline_ms-Date.now()));
   const stopped=new Promise((_,reject)=>{onAbort=()=>reject(Error('cancelled'));controller.signal.addEventListener('abort',onAbort,{once:true});});
   // Fresh request: no incoming credentials, arbitrary headers, cf overrides or custom TLS trust.
   const request=new Request(e.request.url,{method:'POST',redirect:'manual',signal:controller.signal,
    headers:{'Content-Type':'application/json','Idempotency-Key':e.request.operationKey,'User-Agent':'RunLater-Delivery/1'},body:e.request.body});
   live(e);attempted=true;
   // One application invocation. Fetch's underlying DNS/TCP behavior is provider-controlled.
   const operation=(async()=>{
    response=await fetchImpl(request);
    // Also clean up a late response if cancellation won the race.
    if(controller.signal.aborted){void response.body?.cancel().catch(()=>{});throw Error('cancelled');}
    live(e);
    let headers=0;for(const [k,v]of response.headers){headers+=new TextEncoder().encode(k+v).length;if(headers>LIMITS.headerBytes)throw Error('headers');}
    if(!Number.isInteger(response.status)||response.status<200||response.status>599)throw Error('status');
    const redirect=response.status>=300&&response.status<400;
    const bytes=redirect||!response.body?0:(await readLimited(response.body,{signal:controller.signal,maxBytes:LIMITS.responseBytes,maxChunks:LIMITS.responseChunks})).length;
    live(e);return {ok:true,http_status:response.status,outcome:redirect?'redirect_rejected':'http_response',response_bytes:bytes,request_may_have_been_sent:true,automatic_retry:false};
   })();
   return await Promise.race([operation,stopped]);
  }catch{return {ok:false,error:'delivery_rejected_or_failed',request_may_have_been_sent:attempted,automatic_retry:false};}
  finally{
   clearTimeout(timer);controller.abort();signal?.removeEventListener('abort',abort);controller.signal.removeEventListener('abort',onAbort);
   // Do not await a hostile stream's cancellation promise or reflect any response bytes.
   if(response?.body&&!response.body.locked)void response.body.cancel().catch(()=>{});
  }
 };
}
