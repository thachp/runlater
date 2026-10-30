// Native Node only. Internal transport: caller must use address-policy + immutable request validation.
import https from 'node:https';
import tls from 'node:tls';
import {sameAddress,publicAddress} from './address-policy.mjs';
export function createNativeTransport({connect=tls.connect,request=https.request,Agent=https.Agent}={}){
 return ({hostname,address,family,path,body,headers,signal,onAttempt,beforeConnect=()=>{}})=>new Promise((resolve,reject)=>{
  let socket,req,res,done=false,handed=false,connections=0;
  const agent=new Agent({keepAlive:false,maxSockets:1,maxTotalSockets:1,maxCachedSessions:0});
  const finish=(error,value)=>{if(done)return;done=true;signal?.removeEventListener('abort',abort);req?.destroy();res?.destroy();socket?.destroy();agent.destroy();error?reject(Error(error)):resolve(value);};
  const abort=()=>finish('deadline_or_cancelled');
  if(signal?.aborted)return finish('deadline_or_cancelled');signal?.addEventListener('abort',abort,{once:true});
  if(!publicAddress(address))return finish('peer_rejected');
  agent.createConnection=(_options,callback)=>{
   if(++connections!==1){callback(Error('reconnect_rejected'));finish('reconnect_rejected');return undefined;}
   let callbackUsed=false;const completeConnection=(error,value)=>{if(callbackUsed)return;callbackUsed=true;callback(error,value);};
   try{
    beforeConnect();socket=connect({host:address,port:443,family,servername:hostname,rejectUnauthorized:true,minVersion:'TLSv1.2',ALPNProtocols:['http/1.1'],
     checkServerIdentity:(_name,cert)=>tls.checkServerIdentity(hostname,cert)});
    socket.once('error',()=>{if(!handed)completeConnection(Error('tls_rejected'));finish('transport_failed');});
    socket.once('secureConnect',()=>{
     if(done){socket.destroy();return;}
     try{
      if(!socket.authorized||!sameAddress(socket.remoteAddress,address)||!publicAddress(socket.remoteAddress)
       ||socket.remotePort!==443||!['',false,'http/1.1'].includes(socket.alpnProtocol)
       ||tls.checkServerIdentity(hostname,socket.getPeerCertificate()))throw Error();
      socket.disableRenegotiation();handed=true;onAttempt();completeConnection(null,socket);
     }catch{completeConnection(Error('tls_or_peer_rejected'));finish('tls_or_peer_rejected');}
    });
   }catch{completeConnection(Error('transport_failed'));finish('transport_failed');}
   return undefined; // Never give HTTP an unverified socket.
  };
  try{
   req=request({protocol:'https:',hostname,port:443,path,method:'POST',agent,headers,
    maxHeaderSize:8192,insecureHTTPParser:false,joinDuplicateHeaders:false},response=>{
    res=response;let size=0,chunks=0;
    if(!Number.isInteger(res.statusCode)||res.statusCode<200||res.statusCode>599)return finish('invalid_response');
    if(res.rawHeaders.length>128||res.rawHeaders.reduce((n,x)=>n+Buffer.byteLength(x),0)>8192)return finish('response_too_large');
    if(res.statusCode>=300&&res.statusCode<400)return finish(null,{http_status:res.statusCode,outcome:'redirect_rejected',response_bytes:0});
    res.on('data',chunk=>{size+=chunk.length;chunks++;if(size>16384||chunks>128)finish('response_too_large');});
    res.once('end',()=>{if(!res.complete)return finish('incomplete_response');finish(null,{http_status:res.statusCode,outcome:'http_response',response_bytes:size});});
    res.once('aborted',()=>finish('incomplete_response'));res.once('error',()=>finish('transport_failed'));
   });
   req.once('error',()=>finish('transport_failed'));
   req.once('upgrade',()=>finish('upgrade_rejected'));
   req.on('information',()=>finish('informational_response_rejected'));
   req.end(body);
  }catch{finish('transport_failed');}
 });
}
