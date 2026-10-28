// Local emulator client only. No provider account or production credential needed.
export class RunLaterError extends Error {
 constructor(status,retryAfterSeconds=null){super(`RunLater local API returned HTTP ${status}`);this.name='RunLaterError';this.status=status;this.retryAfterSeconds=retryAfterSeconds;}
}
export class LocalRunLater {
 constructor({base='http://127.0.0.1:8787',token='local-alpha',fetchImpl=fetch}={}){
  const u=new URL(base);if(u.protocol!=='http:'||u.hostname!=='127.0.0.1'||u.username||u.password||u.pathname!=='/'||u.search||u.hash)throw new Error('Use the loopback local emulator only');
  this.base=u.origin;this.token=token;this.fetchImpl=fetchImpl;
 }
 async request(path,{method='GET',body,idempotencyKey}={}){
  if(!path.startsWith('/v1/')||path.startsWith('//')||path.includes('#'))throw new Error('Expected local API path');
  let r;try{r=await this.fetchImpl(this.base+path,{method,redirect:'manual',signal:AbortSignal.timeout(5000),headers:{Authorization:`Bearer ${this.token}`,...(body===undefined?{}:{'Content-Type':'application/json'}),...(idempotencyKey===undefined?{}:{'Idempotency-Key':idempotencyKey})},body:body===undefined?undefined:JSON.stringify(body)});}catch{throw new Error('Local API request failed');}
  let size=0,text='';const decoder=new TextDecoder();const reader=r.body?.getReader();
  try{if(reader)for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>1048576){await reader.cancel();throw new Error('Local API response exceeds example client bound');}text+=decoder.decode(value,{stream:true});}text+=decoder.decode();}finally{reader?.releaseLock();}
  if(!r.ok){const raw=r.headers.get('Retry-After');throw new RunLaterError(r.status,raw&&/^\d{1,9}$/.test(raw)?Number(raw):null);}
  try{return {status:r.status,data:JSON.parse(text)};}catch{throw new Error('Local API returned invalid JSON');}
 }
 enqueue(input,idempotencyKey){return this.request('/v1/tasks',{method:'POST',body:input,idempotencyKey});}
 task(id){return this.request('/v1/tasks/'+taskId(id));}
 inspection(id){return this.request('/v1/tasks/'+taskId(id)+'/inspection');}
 attempts(id){return this.request('/v1/tasks/'+taskId(id)+'/attempts');}
 list(after=''){return this.request('/v1/tasks'+(after?'?after='+encodeURIComponent(taskId(after)):''));}
 cancel(id){return this.request('/v1/tasks/'+taskId(id)+'/cancel',{method:'POST'});}
 redrive(id,idempotencyKey){return this.request('/v1/tasks/'+taskId(id)+'/redrive',{method:'POST',idempotencyKey});}
 metrics(){return this.request('/v1/queue/metrics');}
 health(){return this.request('/v1/queue/health');}
 audit(){return this.request('/v1/queue/audit');}
 limits(){return this.request('/v1/queue');}
 configure(body){return this.request('/v1/queue',{method:'PUT',body});}
 maintain(){return this.request('/v1/queue/maintenance',{method:'POST',body:{}});}
}
function taskId(id){if(!/^task_[0-9a-f]{16}$/.test(id))throw new Error('Invalid local task ID');return id;}
