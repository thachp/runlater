// Task-only downstream signer plus read-only authoritative delegation validation. MCP OAuth access tokens never enter this client.
import {createHash,createPrivateKey,randomBytes,sign} from 'node:crypto';
import {PublicBetaClientError} from '../examples/public-beta-client.v1.mjs';
import {API_ORIGIN,delegationPublicKey,verifyDelegation,encodeDelegation} from './delegation.mjs';
const hash = value => createHash('sha256').update(value).digest('hex');
const integer = n => Number.isSafeInteger(n) && n >= 0;
const identifier = n => typeof n === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(n);
const commandKey = n => typeof n === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(n);
const exact = (v,fields) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join() === [...fields].sort().join();
function check(ok,code='invalid_context') {if (!ok) throw new PublicBetaClientError(code);}
function taskId(id) {check(typeof id === 'string' && /^task_[a-f0-9]{16}$/.test(id),'invalid_task'); return id;}
export class DelegatedPublicBetaClientV1 {
  #key; #delegation; #receipt; #release; #fetch; #clock; #nonce; #timeout;
  constructor({privateKey,delegation,releaseId,fetchImpl,receipt,clock=Date.now,nonce=()=>randomBytes(32).toString('hex'),timeoutMs=5000}={}) {
    check(typeof fetchImpl === 'function','explicit_transport_required');
    check(typeof clock === 'function' && typeof nonce === 'function' && Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 5000);
    const gatewayPublicKey=delegationPublicKey(privateKey);
    this.#key=privateKey?.type === 'private' ? privateKey : createPrivateKey(privateKey);
    this.#delegation=verifyDelegation(delegation,{gatewayPublicKey,releaseId,now:clock(),receipt});
    this.#release=releaseId; this.#receipt=receipt && structuredClone(receipt); this.#fetch=fetchImpl; this.#clock=clock; this.#nonce=nonce; this.#timeout=timeoutMs;
  }
  get project() {return this.#delegation.project_id;}
  async #request(path,{method='POST',body,idempotencyKey='',permission}) {
    const now=this.#clock();
    const c=verifyDelegation(this.#delegation,{gatewayPublicKey:delegationPublicKey(this.#key),releaseId:this.#release,now,receipt:this.#receipt});
    check((permission === null && path === '/v1/mcp/delegations/validate' && method === 'POST'
      && exact(body,[]) && idempotencyKey === '') || c.permissions.includes(permission),'insufficient_scope');
    check(integer(now) && now <= Number.MAX_SAFE_INTEGER-60000);
    const nonce=this.#nonce(); check(typeof nonce === 'string' && /^[a-f0-9]{64}$/.test(nonce));
    const bytes=body === undefined ? '' : JSON.stringify(body); check(Buffer.byteLength(bytes)<=2048,'request_too_large');
    const expires=Math.min(now+60000,c.expires_at_ms);
    const wire='RunLater signed request v1\n'+JSON.stringify([1,API_ORIGIN,c.project_id,c.owner_public_key,method,path,'',hash(bytes),idempotencyKey,now,expires,nonce]);
    const headers={'RunLater-Project-Id':c.project_id,'RunLater-Public-Key':c.owner_public_key,'RunLater-Nonce':nonce,
      'RunLater-Issued-At':String(now),'RunLater-Expires-At':String(expires),'RunLater-Request-Signature':sign(null,Buffer.from(wire),this.#key).toString('hex'),
      'RunLater-MCP-Delegation':encodeDelegation(c)};
    if(body!==undefined) headers['Content-Type']='application/json';
    if(idempotencyKey) headers['Idempotency-Key']=idempotencyKey;
    const controller=new AbortController(); let reader,timer;
    const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new PublicBetaClientError('transport_uncertain'));},this.#timeout);});
    try {return await Promise.race([deadline,(async()=>{
      const response=await this.#fetch(API_ORIGIN+path,{method,headers,body:bytes||undefined,redirect:'manual',signal:controller.signal});
      check(!(response.status>=300&&response.status<400),'redirect_rejected');
      if(!response.ok) throw new PublicBetaClientError('http_error',response.status);
      reader=response.body?.getReader(); let size=0,chunks=0; const parts=[];
      if(reader) for(;;) {const {done,value}=await reader.read();if(done)break;size+=value.byteLength;chunks++;check(size<=32768&&chunks<=32,'response_too_large');parts.push(Buffer.from(value));}
      try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts)));}catch{throw new PublicBetaClientError('invalid_response');}
    })()]);}catch(e){throw e instanceof PublicBetaClientError?e:new PublicBetaClientError('transport_uncertain');}
    finally{clearTimeout(timer);controller.abort();if(reader){void reader.cancel().catch(()=>{});try{reader.releaseLock();}catch{}}}
  }
  async validateDelegation() {
    const result=await this.#request('/v1/mcp/delegations/validate',{body:{},permission:null});
    const now=this.#clock();
    const c=verifyDelegation(this.#delegation,{gatewayPublicKey:delegationPublicKey(this.#key),releaseId:this.#release,now,receipt:this.#receipt});
    check(exact(result,['active','project_id','expires_at_ms','permissions']) && result.active === true
      && result.project_id === c.project_id && integer(result.expires_at_ms) && result.expires_at_ms > now
      && result.expires_at_ms <= c.expires_at_ms && Array.isArray(result.permissions)
      && JSON.stringify(result.permissions) === JSON.stringify(c.permissions),'invalid_delegation_response');
    return {active:true,project_id:result.project_id,expires_at_ms:result.expires_at_ms,permissions:[...result.permissions]};
  }
  enqueue(input,idempotencyKey) {
    check(exact(input,['endpoint_id','body','operation_key','run_at_ms'])&&identifier(input.endpoint_id)&&typeof input.body==='string'
      &&Buffer.byteLength(input.body)<=1024&&commandKey(input.operation_key)&&integer(input.run_at_ms)
      &&input.run_at_ms<=(this.#receipt?.expires_at_ms??Number.MAX_SAFE_INTEGER),'invalid_task');
    check(commandKey(idempotencyKey),'idempotency_key_required');
    return this.#request('/v1/tasks',{body:{destination:'registered:'+input.endpoint_id,body:input.body,operation_key:input.operation_key,run_at_ms:input.run_at_ms},idempotencyKey,permission:'enqueue'});
  }
  task(id){return this.#request('/v1/tasks/'+taskId(id),{method:'GET',permission:'read'});}
  cancel(id){return this.#request('/v1/tasks/'+taskId(id)+'/cancel',{body:{},permission:'cancel'});}
}
