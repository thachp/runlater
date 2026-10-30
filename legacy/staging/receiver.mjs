// Dedicated synthetic receiver: no fetch/proxy path, no durable state, no user destinations.
const enc=new TextEncoder();
export function equalSecret(expected,supplied,cryptoApi=crypto){if(typeof cryptoApi?.subtle?.timingSafeEqual!=='function')return false;if(!/^[0-9a-f]{64}$/.test(expected??'')||!/^[0-9a-f]{64}$/.test(supplied??''))return false;return cryptoApi.subtle.timingSafeEqual(enc.encode(expected),enc.encode(supplied));}
export async function handle(request,env,cryptoApi=crypto){
 const now=Date.now();
 // First boundary on every route/hostname, before URL/body parsing or signature work.
 if(!equalSecret(env.STAGING_INGRESS,request.headers.get('X-RunLater-Staging-Gate'),cryptoApi)||!Number.isSafeInteger(Number(env.STAGING_EXPIRES_MS))||(now>=Number(env.STAGING_EXPIRES_MS)||Number(env.STAGING_EXPIRES_MS)-now>900000))return new Response('Staging gate denied',{status:403});
 const url=new URL(request.url);if(url.pathname!=='/callback'||url.search||request.method!=='POST')return new Response('Not found',{status:404});
 if(!/^[0-9a-f]{64}$/.test(env.STAGING_CALLBACK_HMAC??'')||!/^[-a-z0-9]{1,24}$/.test(env.STAGING_RUN_ID??''))return new Response('Receiver disabled',{status:503});
 let headerBytes=0;for(const[k,v]of request.headers)headerBytes+=k.length+v.length;if(headerBytes>2048)return new Response('Headers too large',{status:431});
 if(request.headers.get('Content-Type')!=='application/json')return new Response('Expected JSON',{status:415});
 const task=request.headers.get('RunLater-Task-Id')??'',operation=request.headers.get('RunLater-Operation-Key')??'',timestamp=request.headers.get('RunLater-Timestamp')??'',signature=request.headers.get('RunLater-Signature')??'';
 if(!/^alpha:task_[0-9a-f]{16}$/.test(task)||!/^\d{9,12}$/.test(timestamp)||String(Number(timestamp))!==timestamp||Math.abs(Math.floor(now/1000)-Number(timestamp))>30||!/^[0-9a-f]{64}$/.test(signature))return new Response('Invalid signature',{status:401});
 const reader=request.body?.getReader();if(!reader)return new Response('Missing body',{status:400});let timer;
 try{
  const read=async()=>{const chunks=[];let size=0;for(;;){const{done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>256){await reader.cancel();throw 413}chunks.push(value)}const bytes=new Uint8Array(size);let at=0;for(const chunk of chunks){bytes.set(chunk,at);at+=chunk.byteLength}return bytes;};
  const bytes=await Promise.race([read(),new Promise((_,reject)=>{timer=setTimeout(()=>{void reader.cancel().catch(()=>{});reject(408)},1000)})]);
  const prefix=enc.encode(`${timestamp}.${task}.${operation}.`),signed=new Uint8Array(prefix.length+bytes.length);signed.set(prefix);signed.set(bytes,prefix.length);
  const key=await cryptoApi.subtle.importKey('raw',enc.encode(env.STAGING_CALLBACK_HMAC),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
  const sig=Uint8Array.from(signature.match(/../g),s=>parseInt(s,16));if(!await cryptoApi.subtle.verify('HMAC',key,sig,signed))return new Response('Invalid signature',{status:401});
  let body;try{body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes))}catch{return new Response('Synthetic body required',{status:400})}
  if(!body||Object.keys(body).sort().join(',')!=='case,run,synthetic'||body.synthetic!==true||body.run!==env.STAGING_RUN_ID||!['initial','scheduled','receiver','retry','cancel'].includes(body.case)||operation!==`run_${body.run}_${body.case}`)return new Response('Synthetic body required',{status:400});
  const receiptPrefix=enc.encode(`${timestamp}.receipt:${task}.${operation}.`),receiptBytes=new Uint8Array(receiptPrefix.length+bytes.length);receiptBytes.set(receiptPrefix);receiptBytes.set(bytes,receiptPrefix.length);const receipt=Array.from(new Uint8Array(await cryptoApi.subtle.sign('HMAC',key,receiptBytes)),v=>v.toString(16).padStart(2,'0')).join('');
  // Evidence is a domain-separated authenticated receipt, never echoed payload or credentials.
  return new Response(null,{status:204,headers:{'RunLater-Receipt':receipt,'Cache-Control':'no-store'}});
 }catch(code){return new Response('Synthetic request rejected',{status:[408,413].includes(code)?code:400})}finally{clearTimeout(timer);reader.releaseLock()}
}
export default {fetch(request,env){return handle(request,env)}};
