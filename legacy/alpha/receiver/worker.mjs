// Synthetic side-effect-free alpha receiver. No proxying, customer action, logging or public secrets.
const URL='https://receiver-alpha.runlater.io/callback';
const names=['RunLater-Signature-Version','RunLater-Key-Id','RunLater-Signing-Policy','RunLater-Timestamp','RunLater-Task-Id','RunLater-Operation-Key','RunLater-Signature'];
const response=(status,code)=>Response.json({code},{status,headers:{'Cache-Control':'no-store'}});
export default {async fetch(request,env){
 if(request.url!==URL||request.method!=='POST')return response(404,'route_unavailable');
 if(request.headers.get('Content-Type')!=='application/json')return response(415,'json_required');
 if(!env.IDENTITIES||!env.ALPHA_CALLBACK_KEYS)return response(503,'receiver_unconfigured');
 const h=request.headers,kid=h.get('RunLater-Key-Id'),task=h.get('RunLater-Task-Id')??'',ts=h.get('RunLater-Timestamp')??'',signature=h.get('RunLater-Signature')??'',scope=h.get('RunLater-Signing-Policy')??'',operation=h.get('RunLater-Operation-Key')??'';
 if(h.get('RunLater-Signature-Version')!=='v2'||!/^[A-Za-z0-9_-]{1,64}$/.test(kid??'')||!/^[A-Za-z0-9_-]{1,64}:task_[0-9a-f]{16}$/.test(task)||!/^[A-Za-z0-9_-]{1,64}$/.test(scope)||!/^[A-Za-z0-9_-]{1,128}$/.test(operation)||!/^\d{1,12}$/.test(ts)||String(Number(ts))!==ts||Math.abs(Math.floor(Date.now()/1000)-Number(ts))>300||!/^[0-9a-f]{64}$/.test(signature))return response(403,'callback_forbidden');
 let keys;try{if(env.ALPHA_CALLBACK_KEYS.length>4096)throw Error();keys=JSON.parse(env.ALPHA_CALLBACK_KEYS);}catch{return response(503,'receiver_unconfigured');}
 const secret=Object.hasOwn(keys,kid)?keys[kid]:null;if(typeof secret!=='string'||!/^[0-9a-f]{64}$/.test(secret)||kid.startsWith('fixture'))return response(403,'callback_forbidden');
 let body;const reader=request.body?.getReader();if(!reader)return response(400,'body_required');
 let timer;try{body=await Promise.race([(async()=>{let n=0,parts=[],chunks=0;while(true){const {done,value}=await reader.read();if(done)break;if((n+=value.length)>1024||++chunks>32)throw Error();parts.push(value);}const result=new Uint8Array(n);let offset=0;for(const p of parts){result.set(p,offset);offset+=p.length;}return result;})(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error()),3000);})]);}catch{reader.cancel().catch(()=>{});return response(413,'body_limit');}finally{clearTimeout(timer);}
 const bytes=hex=>Uint8Array.from(hex.match(/../g).map(b=>parseInt(b,16)));
 const key=await crypto.subtle.importKey('raw',bytes(secret),{name:'HMAC',hash:'SHA-256'},false,['verify']);
 const prefix=new TextEncoder().encode(`runlater.v2.${scope}.${kid}.${ts}.${task}.${operation}.`),wire=new Uint8Array(prefix.length+body.length);wire.set(prefix);wire.set(body,prefix.length);
 if(!await crypto.subtle.verify('HMAC',key,bytes(signature),wire))return response(403,'callback_forbidden');
 const project=task.split(':')[0],stub=env.IDENTITIES.get(env.IDENTITIES.idFromName(project));
 const verify=await stub.fetch('https://identity/verify-callback',{method:'POST',headers:{'x-project':project},body:JSON.stringify({headers:names.map(name=>[name,h.get(name)]),body_hex:Array.from(body,b=>b.toString(16).padStart(2,'0')).join('')})});
 if(verify.status!==200)return response(403,'callback_policy_rejected');
 const verification=await verify.json();
 let input;try{input=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body));}catch{return response(400,'invalid_synthetic_body');}
 if(input?.synthetic!==true)return response(400,'synthetic_required');
 if(input.mode==='retry'&&verification.attempt===1)return response(503,'synthetic_retry');
 if(input.mode==='failure')return response(400,'synthetic_failure');
 if(input.mode==='redirect')return new Response(null,{status:302,headers:{Location:'https://receiver-alpha.runlater.io/rejected'}});
 if(input.mode==='oversize')return new Response('x'.repeat(1025));
 if(input.mode==='headers')return new Response(null,{status:204,headers:{'x-large':'x'.repeat(2049)}});
 if(input.mode==='timeout')await new Promise(r=>setTimeout(r,3200));
 return new Response(null,{status:204});
}};
