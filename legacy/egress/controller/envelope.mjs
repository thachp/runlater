// Portable exact internal envelope. This does not authenticate a public caller.
const encoder=new TextEncoder();
export const MAX_ENVELOPE_BYTES=8192;
export const MAX_LEASE_MS=29000;
export function exactKeys(value,keys){return value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));}
export async function sha256(value){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value)))].map(x=>x.toString(16).padStart(2,'0')).join('');}
export function canonicalEnvelope(e){return JSON.stringify([e.version,e.adapter_revision,e.release_id,e.project_id,e.task_id,e.fence,e.attempt_started_at_ms,e.deadline_ms,e.target_sha256,[e.request.url,e.request.body,e.request.contentType,e.request.operationKey]]);}
export function assertDeadline(e,now=Date.now()){if(!Number.isSafeInteger(e.deadline_ms)||now>=e.deadline_ms)throw Error('expired');}
export async function validateEnvelope(e,now=Date.now(),{historical=false}={}){
 if(!exactKeys(e,['version','adapter_revision','release_id','project_id','task_id','fence','attempt_started_at_ms','deadline_ms','target_sha256','request'])||e.version!==1)throw Error('invalid_envelope');
 if(typeof e.adapter_revision!=='string'||!/^[0-9a-f]{64}$/.test(e.adapter_revision)||e.adapter_revision==='0'.repeat(64))throw Error('invalid_envelope');
 if(typeof e.release_id!=='string'||!/^[A-Za-z0-9_-]{1,32}$/.test(e.release_id)||typeof e.project_id!=='string'||!/^p_[0-9a-f]{60}$/.test(e.project_id)||typeof e.task_id!=='string'||!/^task_[0-9a-f]{16}$/.test(e.task_id))throw Error('invalid_envelope');
 if(!Number.isSafeInteger(e.deadline_ms)||!Number.isSafeInteger(e.fence)||e.fence<1||!Number.isSafeInteger(e.attempt_started_at_ms)||e.attempt_started_at_ms<0||(!historical&&e.attempt_started_at_ms>now)||e.deadline_ms-e.attempt_started_at_ms!==MAX_LEASE_MS)throw Error('invalid_envelope');
 if(!historical)assertDeadline(e,now);
 const r=e.request;
 if(!exactKeys(r,['url','body','contentType','operationKey'])||typeof r.url!=='string'||encoder.encode(r.url).length>2048||typeof r.body!=='string'||encoder.encode(r.body).length>1024||r.contentType!=='application/json'||typeof r.operationKey!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(r.operationKey))throw Error('invalid_envelope');
 try{JSON.parse(r.body);}catch{throw Error('invalid_envelope');}
 if(typeof e.target_sha256!=='string'||!/^[0-9a-f]{64}$/.test(e.target_sha256)||await sha256(JSON.stringify({version:1,url:r.url,method:'POST',content_type:'application/json'}))!==e.target_sha256)throw Error('invalid_envelope');
 // Digest is not network proof. Each adapter validates URL syntax; native pins an observed
 // public peer, while the separate Worker artifact relies on provider public-Fetch routing.
 const canonical=canonicalEnvelope(e);if(encoder.encode(canonical).length>MAX_ENVELOPE_BYTES)throw Error('invalid_envelope');
 return {envelope:JSON.parse(JSON.stringify(e)),hash:await sha256(canonical),key:await sha256(JSON.stringify([e.release_id,e.project_id,e.task_id,e.fence]))};
}
export async function readLimited(stream,{signal,maxBytes,maxChunks=128}){
 if(!stream||signal?.aborted)throw Error('invalid_stream');
 const reader=stream.getReader();let size=0,count=0;const chunks=[];let onAbort;
 const aborted=new Promise((_,reject)=>{onAbort=()=>reject(Error('cancelled'));signal?.addEventListener('abort',onAbort,{once:true});});
 try{
  for(;;){if(signal?.aborted)throw Error('cancelled');const {done,value}=await Promise.race([reader.read(),aborted]);if(done)break;
   if(++count>maxChunks||!(value instanceof Uint8Array)||(size+=value.byteLength)>maxBytes)throw Error('invalid_stream');chunks.push(value);
  }
  const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.byteLength;}return bytes;
 }finally{signal?.removeEventListener('abort',onAbort);void reader.cancel().catch(()=>{});}
}
export async function boundedJson(request){
 if(request.headers.get('content-type')!=='application/json')throw Error('invalid_request');
 return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await readLimited(request.body,{signal:request.signal,maxBytes:MAX_ENVELOPE_BYTES})));
}
export function boundedResult(value){
 if(!value||typeof value!=='object')throw Error('invalid_result');
 if(typeof value.request_may_have_been_sent!=='boolean'||value.automatic_retry!==false)throw Error('invalid_result');
 const base={request_may_have_been_sent:value.request_may_have_been_sent,automatic_retry:false};
 if(value.ok===true&&exactKeys(value,['ok','http_status','outcome','response_bytes','request_may_have_been_sent','automatic_retry'])&&Number.isInteger(value.http_status)&&value.http_status>=200&&value.http_status<=599&&['http_response','redirect_rejected'].includes(value.outcome)&&Number.isSafeInteger(value.response_bytes)&&value.response_bytes>=0&&value.response_bytes<=16384)return {ok:true,http_status:value.http_status,outcome:value.outcome,response_bytes:value.response_bytes,...base};
 if(value.ok===false&&exactKeys(value,['ok','error','request_may_have_been_sent','automatic_retry'])&&typeof value.error==='string'&&['egress_disabled','invalid_request','unsafe_runtime_logging','busy','deadline_or_cancelled','delivery_rejected_or_failed','dispatch_rejected','rate_limited'].includes(value.error))return {ok:false,error:'delivery_rejected_or_failed',...base};
 throw Error('invalid_result');
}
