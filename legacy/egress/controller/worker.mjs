// Source candidate only. Dedicated named binding; default internet entrypoint never dispatches.
import {DurableObject,WorkerEntrypoint} from 'cloudflare:workers';
import {boundedJson,assertDeadline,readLimited} from './envelope.mjs';
import {createDispatcher} from './dispatch.mjs';
const revisionValid=r=>typeof r==='string'&&/^[0-9a-f]{64}$/.test(r)&&r!=='0'.repeat(64);
const enabled=env=>env.EGRESS_ENABLED==='operator-approved'&&revisionValid(env.EGRESS_REVIEW_REVISION);
const reply=(value,status=200)=>Response.json(value,{status,headers:{'Cache-Control':'no-store'}});
export default {fetch(){return new Response('Not found',{status:404});}};
export class EgressBinding extends WorkerEntrypoint{
 async fetch(request){
  const u=new URL(request.url);
  if(u.origin!=='https://egress.internal'||u.search||u.hash)return new Response('Not found',{status:404});
  if(request.method==='GET'&&u.pathname==='/ready')return this.env.EGRESS_CONTAINER.getByName('runlater-egress-v1').fetch(request);
  if(request.method!=='POST'||u.pathname!=='/dispatch'||!enabled(this.env))return reply({error:'egress_disabled'},503);
  // Only deployers can create the named service binding. There is no network bearer secret.
  return this.env.EGRESS_CONTAINER.getByName('runlater-egress-v1').fetch(request);
 }
}
export class EgressContainer extends DurableObject{
 constructor(ctx,env){super(ctx,env);this.dispatch=createDispatcher({storage:ctx.storage,enabled:enabled(env),revision:env.EGRESS_REVIEW_REVISION,send:(e,o)=>this.send(e,o)});}
 async fetch(request){
  if(request.method==='GET'&&new URL(request.url).pathname==='/ready'){
   const n=(await this.ctx.storage.get('receipt_count'))??0;
   const capacity=Number.isSafeInteger(n)&&n>=0&&n<=10000?10000-n:0;
   return reply({ready:enabled(this.env)&&capacity>0,protocol:1,revision:enabled(this.env)?this.env.EGRESS_REVIEW_REVISION:null,capacity_remaining:capacity});
  }
  if(request.method!=='POST'||new URL(request.url).pathname!=='/dispatch')return new Response('Not found',{status:404});
  const timeout=AbortSignal.timeout(2000);const signal=AbortSignal.any([request.signal,timeout]);
  try{
   const input=await boundedJson(new Request(request,{signal}));
   return reply(await this.dispatch(input,{signal:request.signal}));
  }catch{return reply({error:'dispatch_rejected'},400);}
 }
 async send(e,{signal}){
  const live=()=>{if(signal.aborted)throw Error('cancelled');assertDeadline(e);};live();
  const container=this.ctx.container;if(!container)throw Error('container_unavailable');
  if(!container.running)container.start({enableInternet:true,env:{RUNLATER_NATIVE_EGRESS_ENABLED:'true',EGRESS_REVIEW_REVISION:this.env.EGRESS_REVIEW_REVISION}});
  await container.setInactivityTimeout(30000);live();
  const port=container.getTcpPort(8080);
  // Only read-only health probes repeat; the dispatch below occurs exactly once.
  let ready=false;
  for(let i=0;i<50;i++){
   live();try{
    const probeSignal=AbortSignal.any([signal,AbortSignal.timeout(200)]);
    const r=await port.fetch('http://container/ready',{signal:probeSignal});
    const text=new TextDecoder().decode(await readLimited(r.body,{signal:probeSignal,maxBytes:256,maxChunks:8}));if(r.status===200&&JSON.parse(text).ready===true&&JSON.parse(text).revision===e.adapter_revision){ready=true;break;}
   }catch{live();}
   await new Promise((resolve,reject)=>{const abort=()=>{clearTimeout(t);reject(Error('cancelled'));};const t=setTimeout(()=>{signal.removeEventListener('abort',abort);resolve();},100);signal.addEventListener('abort',abort,{once:true});});
  }
  if(!ready)throw Error('startup_failed');live();
  const response=await port.fetch('http://container/dispatch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(e),signal});
  if(response.status!==200)throw Error('dispatch_failed');
  const bytes=await readLimited(response.body,{signal,maxBytes:1024,maxChunks:32});
  live();return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }
}
