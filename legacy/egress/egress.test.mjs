import test from 'node:test';
import assert from 'node:assert/strict';
import {Duplex} from 'node:stream';
import {publicAddress,sameAddress,destinationURL,resolvePublic} from './address-policy.mjs';
import {createNativeEgress} from './index.mjs';
import {createNativeTransport} from './native-transport.mjs';
const input={url:'https://example.com/hook?cap=PRIVATE_URL',body:'{"test":true}',contentType:'application/json',operationKey:'stable'};
const noData=()=>Promise.reject(Object.assign(Error('PRIVATE_DNS_ERROR'),{code:'ENODATA'}));
const resolver=(answers={})=>({resolveCname:async name=>answers[name]?.cname??[],resolve4:async name=>answers[name]?.a??['93.184.216.34'],resolve6:async name=>answers[name]?.aaaa??[],cancel(){}});
test('all special-use and alternate address forms fail closed',()=>{
 for(const address of ['0.0.0.0','10.0.0.1','100.64.1.1','127.0.0.1','169.254.169.254','172.16.0.1','192.0.0.9','192.0.2.1','192.31.196.1','192.52.193.1','192.88.99.1','192.168.0.1','192.175.48.1','198.18.0.1','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255','::','::1','::ffff:127.0.0.1','::ffff:808:808','64:ff9b::808:808','100::1','2001::1','2001:db8::1','2002:808:808::1','2620:4f:8000::1','3fff::1','fc00::1','fe80::1','ff02::1','2606:4700::1111%eth0','0177.0.0.1','2130706433','garbage'])assert.equal(publicAddress(address),false,address);
 for(const address of ['1.1.1.1','8.8.8.8','93.184.216.34','2606:4700:4700::1111','2001:4860:4860::8888'])assert.equal(publicAddress(address),true,address);
 assert.equal(sameAddress('2606:4700::1','2606:4700:0:0:0:0:0:1'),true);
});
test('canonical HTTPS URL accepts capability query privately, rejects ambiguous authorities/ports/encodings',()=>{
 assert.deepEqual(destinationURL(input.url),{hostname:'example.com',path:'/hook?cap=PRIVATE_URL'});
 assert.deepEqual(destinationURL('https://example.com/?'),{hostname:'example.com',path:'/?'});
 for(const url of ['http://example.com/hook','https://example.com:443/hook','https://example.com:444/hook','https://user:pass@example.com/hook','https://example.com/hook#x','https://example.com/#','https://127.0.0.1/hook','https://[::1]/hook','https://2130706433/hook','https://EXAMPLE.com/hook','https://example.com./hook','https://metadata.internal/hook','https://example.com/../hook','https://example.com/%0d%0aHost:evil','https://example.com/hello world','https://example.com\\@evil.com/hook','https://%65xample.com/hook','https://example.com','https://example.com/'+ 'a'.repeat(2048)])assert.throws(()=>destinationURL(url));
});
test('DNS validates every answer and CNAME hop with finite depth/count',async()=>{
 const good=resolver({'example.com':{cname:['alias.example.com'],a:['93.184.216.34'],aaaa:[]},'alias.example.com':{a:['1.1.1.1'],aaaa:['2606:4700::1111']}});
 assert.equal((await resolvePublic('example.com',good)).length,3);
 for(const bad of [resolver({'example.com':{a:['1.1.1.1','127.0.0.1']}}),resolver({'example.com':{cname:['other.example.com']},'other.example.com':{aaaa:['::1']}}),resolver({'example.com':{cname:['example.com']}}),resolver({'example.com':{cname:['one.example.com','two.example.com']}}),resolver({'example.com':{a:Array(17).fill('1.1.1.1')}}),resolver({'example.com':{cname:['metadata.internal']}}),{resolveCname:noData,resolve4:noData,resolve6:noData}])await assert.rejects(resolvePublic('example.com',bad));
 let n=0;await assert.rejects(resolvePublic('example.com',{resolveCname:async()=>['hop'+(++n)+'.example.com'],resolve4:async()=>['1.1.1.1'],resolve6:async()=>[]}));assert.equal(n,8);
});
test('default-off, immutable request validation and private headers cannot invoke transport',async()=>{
 let calls=0;const transport=async()=>{calls++;throw Error();};assert.equal((await createNativeEgress({transport}).deliver(input)).error,'egress_disabled');
 const e=createNativeEgress({enabled:true,resolverFactory:()=>resolver(),transport});
 for(const change of [{body:'x'.repeat(1025)},{contentType:'text/html'},{operationKey:'bad\r\nkey'},{headers:{Host:'evil'}},{privateHeaders:{Host:'evil'}},{privateHeaders:{Authorization:'x\r\nSecret'}},{privateHeaders:{Authorization:'secret','X-API-Key':'other'}}])assert.equal((await e.deliver({...input,...change})).ok,false);
 assert.equal(calls,0);
});
test('one public pin, no fallback/retry, no raw body/header/URL/error reflection',async()=>{
 let calls=0;const e=createNativeEgress({enabled:true,resolverFactory:()=>resolver({'example.com':{a:['1.1.1.1','8.8.8.8']}}),transport:async r=>{
  calls++;assert.equal(r.address,'1.1.1.1');assert.equal(r.hostname,'example.com');assert.equal(r.headers.Authorization,'PRIVATE_AUTH');assert.equal(r.headers.Host,'example.com');r.onAttempt();throw Error('PRIVATE_URL PRIVATE_AUTH PRIVATE_BODY');}});
 const result=await e.deliver({...input,privateHeaders:{Authorization:'PRIVATE_AUTH'}});assert.equal(result.request_may_have_been_sent,true);assert.equal(calls,1);assert.doesNotMatch(JSON.stringify(result),/PRIVATE/);
});
test('redacted bounded result only and redirect classification without follow-up',async()=>{
 let calls=0;const e=createNativeEgress({enabled:true,resolverFactory:()=>resolver(),transport:async r=>{calls++;r.onAttempt();return {http_status:302,outcome:'redirect_rejected',response_bytes:0,location:'PRIVATE_URL',body:'PRIVATE_BODY'};}});
 assert.deepEqual(await e.deliver(input),{ok:true,http_status:302,outcome:'redirect_rejected',response_bytes:0,request_may_have_been_sent:true,automatic_retry:false});assert.equal(calls,1);
});
test('cancellation while DNS stalls never sends; concurrency is bounded',async()=>{
 let sends=0,cancels=0;const e=createNativeEgress({enabled:true,resolverFactory:()=>({resolveCname:()=>new Promise(()=>{}),resolve4:()=>new Promise(()=>{}),resolve6:()=>new Promise(()=>{}),cancel(){cancels++;}}),transport:async()=>{sends++;}});
 const controllers=Array.from({length:4},()=>new AbortController());const pending=controllers.map(c=>e.deliver(input,{signal:c.signal}));
 assert.equal((await e.deliver(input)).error,'busy');controllers.forEach(c=>c.abort());const results=await Promise.all(pending);assert.ok(results.every(r=>r.error==='deadline_or_cancelled'&&!r.request_may_have_been_sent));assert.equal(sends,0);assert.equal(cancels,4);
});
class FakeTls extends Duplex{
 constructor({peer='1.1.1.1',authorized=true,cert='example.com',response='HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n'}={}){super();this.remoteAddress=peer;this.remotePort=443;this.authorized=authorized;this.alpnProtocol='http/1.1';this.cert=cert;this.response=response;this.bytes=[];this.encrypted=true;this.onceResponse=false;}
 _read(){} _write(chunk,_encoding,cb){this.bytes.push(Buffer.from(chunk));cb();if(!this.onceResponse){this.onceResponse=true;queueMicrotask(()=>{this.push(this.response);this.push(null);});}}
 getPeerCertificate(){return {subjectaltname:'DNS:'+this.cert};}disableRenegotiation(){}setTimeout(){return this;}setNoDelay(){return this;}setKeepAlive(){return this;}
}
const requestArgs=()=>({hostname:'example.com',address:'1.1.1.1',family:4,path:'/hook?private',body:Buffer.from('{}'),headers:{Host:'example.com','Content-Length':'2','Content-Type':'application/json',Authorization:'PRIVATE_AUTH'},signal:new AbortController().signal,onAttempt(){}});
test('real Node HTTP parser receives socket only after TLS+hostname+peer checks; no pre-validation credential bytes',async()=>{
 for(const failure of [{peer:'8.8.8.8'},{peer:'127.0.0.1'},{authorized:false},{cert:'attacker.example'}]){
  let socket;const transport=createNativeTransport({connect:options=>{assert.equal(options.host,'1.1.1.1');assert.equal(options.servername,'example.com');assert.equal(options.rejectUnauthorized,true);socket=new FakeTls(failure);queueMicrotask(()=>socket.emit('secureConnect'));return socket;}});
  await assert.rejects(transport(requestArgs()));assert.equal(Buffer.concat(socket.bytes).length,0);
 }
 let socket;const transport=createNativeTransport({connect:()=>{socket=new FakeTls();queueMicrotask(()=>socket.emit('secureConnect'));return socket;}});
 const result=await transport(requestArgs());assert.equal(result.http_status,204);assert.match(Buffer.concat(socket.bytes).toString(),/Host: example.com/);
});
test('native parser rejects redirect follow-up, malformed/truncated/oversize responses',async()=>{
 const responses=[['HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/PRIVATE\r\nContent-Length: 0\r\n\r\n','redirect_rejected'],['HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n'+'x'.repeat(20000),null],['HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nx',null],['HTTP/1.1 200 OK\r\nX-Large: '+'x'.repeat(9000)+'\r\n\r\n',null]];
 for(const [response,outcome]of responses){let connections=0;const transport=createNativeTransport({connect:()=>{connections++;const s=new FakeTls({response});queueMicrotask(()=>s.emit('secureConnect'));return s;}});if(outcome)assert.equal((await transport(requestArgs())).outcome,outcome);else await assert.rejects(transport(requestArgs()));assert.equal(connections,1);}
});
test('deadline cancels stalled DNS and never emits HTTP',async()=>{
 let sends=0,cancelled=0;const started=Date.now();
 const e=createNativeEgress({enabled:true,resolverFactory:()=>({resolveCname:()=>new Promise(()=>{}),resolve4:()=>new Promise(()=>{}),resolve6:()=>new Promise(()=>{}),cancel(){cancelled++;}}),transport:async()=>{sends++;}});
 const r=await e.deliver(input);assert.equal(r.error,'deadline_or_cancelled');assert.equal(r.request_may_have_been_sent,false);assert.equal(sends,0);assert.equal(cancelled,2);assert.ok(Date.now()-started>=4900&&Date.now()-started<7000);
});
test('TLS-stage cancellation destroys socket before any HTTP bytes, and invalid signal does not consume capacity',async()=>{
 const controller=new AbortController();let socket;
 const transport=createNativeTransport({connect:()=>{socket=new FakeTls();return socket;}});
 const p=transport({...requestArgs(),signal:controller.signal});controller.abort();await assert.rejects(p);assert.equal(socket.destroyed,true);assert.equal(socket.bytes.length,0);
 const e=createNativeEgress({enabled:true,resolverFactory:()=>resolver(),transport:async()=>({http_status:204,outcome:'http_response',response_bytes:0})});
 for(let i=0;i<5;i++)assert.equal((await e.deliver(input,{signal:{}})).error,'invalid_request');assert.equal((await e.deliver(input)).ok,true);
});
test('known native HTTP debug/keylog configuration fails before secret-bearing work',async()=>{
 const old=process.env.NODE_DEBUG;try{process.env.NODE_DEBUG='http';const r=await createNativeEgress({enabled:true}).deliver(input);assert.equal(r.error,'unsafe_runtime_logging');}finally{if(old===undefined)delete process.env.NODE_DEBUG;else process.env.NODE_DEBUG=old;}
});

test('late TLS handoff checks monotonic budget even before timer callback runs',async()=>{
 let now=0,socket;
 const transport=createNativeTransport({connect:()=>{socket=new FakeTls({peer:'93.184.216.34'});queueMicrotask(()=>{now=5001;socket.emit('secureConnect');});return socket;}});
 const e=createNativeEgress({enabled:true,resolverFactory:()=>resolver(),transport,monotonicNow:()=>now});
 const r=await e.deliver(input);assert.equal(r.error,'deadline_or_cancelled');assert.equal(r.request_may_have_been_sent,false);assert.equal(socket.bytes.length,0);assert.equal(socket.destroyed,true);
});
