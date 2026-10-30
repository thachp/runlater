// Native Container ingress only. Never expose this port directly to a public network.
import http from 'node:http';
import {createNativeEgress} from '../index.mjs';
import {validateEnvelope,MAX_ENVELOPE_BYTES} from './envelope.mjs';
export function createIngress({adapter=createNativeEgress({enabled:false}),enabled=false,revision}={}){
 const server=http.createServer({maxHeaderSize:4096,requestTimeout:2000,headersTimeout:2000,keepAliveTimeout:1},async(req,res)=>{
  const respond=(status,value)=>{if(!res.destroyed){res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store','Connection':'close'});res.end(JSON.stringify(value));}};
  if(req.method==='GET'&&req.url==='/ready')return respond(200,{ready:enabled===true,protocol:1,revision});
  if(!enabled||req.method!=='POST'||req.url!=='/dispatch'||req.headers['content-type']!=='application/json')return respond(404,{error:'not_found'});
  const controller=new AbortController();const abort=()=>controller.abort();req.once('aborted',abort);res.once('close',abort);
  const readTimer=setTimeout(()=>{abort();req.destroy();},2000);let size=0,handed=false;const chunks=[];
  try{
   for await(const chunk of req){size+=chunk.length;if(size>MAX_ENVELOPE_BYTES)throw Error();chunks.push(chunk);}
   clearTimeout(readTimer);
   const parsed=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)));
   const {envelope}=await validateEnvelope(parsed);if(controller.signal.aborted||envelope.adapter_revision!==revision)throw Error();
   handed=true;const result=await adapter.deliver(envelope.request,{signal:controller.signal,deadlineMs:envelope.deadline_ms});respond(200,result);
  }catch{respond(400,{ok:false,error:'dispatch_rejected',request_may_have_been_sent:handed,automatic_retry:false});}
  finally{clearTimeout(readTimer);controller.abort();req.removeListener('aborted',abort);res.removeListener('close',abort);}
 });
 server.maxConnections=4;server.on('clientError',(_error,socket)=>socket.destroy());return server;
}
