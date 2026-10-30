// Source candidate only. No public dispatch endpoint; private named binding + singleton receipts.
import {DurableObject,WorkerEntrypoint} from 'cloudflare:workers';
import {boundedJson} from '../controller/envelope.mjs';
import {createDispatcher,RECEIPT_LIMIT} from '../controller/dispatch.mjs';
import {createPublicFetch,enabled} from './transport.mjs';
const reply=(value,status=200)=>Response.json(value,{status,headers:{'Cache-Control':'no-store'}});
export default {fetch(){return new Response('Not found',{status:404});}};
export class PublicFetchBinding extends WorkerEntrypoint{
 async fetch(request){
  const u=new URL(request.url);
  if(u.origin!=='https://egress.internal'||u.search||u.hash||!((request.method==='GET'&&u.pathname==='/ready')||(request.method==='POST'&&u.pathname==='/dispatch')))return new Response('Not found',{status:404});
  if(!enabled(this.env))return reply({error:'egress_disabled'},503);
  return this.env.PUBLIC_FETCH_RECEIPTS.getByName('runlater-public-fetch-v1').fetch(request);
 }
}
export class PublicFetchReceipts extends DurableObject{
 constructor(ctx,env){
  super(ctx,env);
  this.dispatch=createDispatcher({storage:ctx.storage,enabled:enabled(env),revision:env.EGRESS_REVIEW_REVISION,
   send:createPublicFetch({approved:enabled(env),revision:env.EGRESS_REVIEW_REVISION})});
 }
 async fetch(request){
  const u=new URL(request.url);
  if(u.origin!=='https://egress.internal'||u.search||u.hash)return new Response('Not found',{status:404});
  if(request.method==='GET'&&u.pathname==='/ready'){
   const n=(await this.ctx.storage.get('receipt_count'))??0;
   const capacity=Number.isSafeInteger(n)&&n>=0&&n<=RECEIPT_LIMIT?RECEIPT_LIMIT-n:0;
   return reply({ready:enabled(this.env)&&capacity>0,protocol:1,revision:enabled(this.env)?this.env.EGRESS_REVIEW_REVISION:null,capacity_remaining:capacity});
  }
  if(request.method!=='POST'||u.pathname!=='/dispatch')return new Response('Not found',{status:404});
  if(!enabled(this.env))return reply({error:'egress_disabled'},503);
  try{
   const signal=AbortSignal.any([request.signal,AbortSignal.timeout(2000)]);
   const input=await boundedJson(new Request(request,{signal}));
   return reply(await this.dispatch(input,{signal:request.signal}));
  }catch{return reply({error:'dispatch_rejected'},400);}
 }
}
