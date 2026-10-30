// Operator-approved hosted alpha only. No credential generation, payment, arbitrary URL or auto-task loop.
import {createHash,createPrivateKey,createPublicKey,randomBytes,sign} from 'node:crypto';
import fs from 'node:fs';import {fileURLToPath} from 'node:url';
const ORIGIN='https://api.runlater.io',taskId=id=>{if(!/^task_[a-f0-9]{16}$/.test(id))throw Error('Invalid task ID');return id;};
const stableKey=key=>{if(!/^[A-Za-z0-9_-]{1,128}$/.test(key))throw Error('Use a stable1–128-character alphanumeric, underscore or hyphen key');return key;};
export class AlphaRunLater {
 constructor({project,privateKey,fetchImpl=fetch,clock=Date.now,nonce=()=>randomBytes(32).toString('hex')}={}){
  if(!/^[A-Za-z0-9_-]{1,64}$/.test(project??''))throw Error('An approved project ID is required');
  this.key=typeof privateKey==='string'||Buffer.isBuffer(privateKey)?createPrivateKey(privateKey):privateKey;
  if(this.key?.asymmetricKeyType!=='ed25519'||this.key.type!=='private')throw Error('An Ed25519 private key is required');
  this.project=project;this.publicKey=createPublicKey(this.key).export({type:'spki',format:'der'}).subarray(-32).toString('hex');this.fetch=fetchImpl;this.clock=clock;this.nonce=nonce;
 }
 async request(path,{method='GET',body,idempotencyKey='',signed=true}={}){
  if(!/^\/(?:health|v1\/identity\/(?:challenges|enroll|me)|v1\/tasks(?:\/task_[a-f0-9]{16}(?:\/(?:cancel|redrive))?)?)$/.test(path))throw Error('Unsupported alpha route');
  const bytes=body===undefined?'':JSON.stringify(body),headers=body===undefined?{}:{'Content-Type':'application/json'};
  if(Buffer.byteLength(bytes)>2048)throw Error('Alpha request body exceeds2048bytes');
  if(signed){const at=this.clock(),nonce=this.nonce();if(!Number.isSafeInteger(at)||at<0||!/^[a-f0-9]{64}$/.test(nonce))throw Error('Invalid signing clock/nonce');
   const canonical='RunLater signed request v1\n'+JSON.stringify([1,ORIGIN,this.project,this.publicKey,method,path,'',createHash('sha256').update(bytes).digest('hex'),idempotencyKey,at,at+60000,nonce]);
   Object.assign(headers,{'RunLater-Project-Id':this.project,'RunLater-Public-Key':this.publicKey,'RunLater-Nonce':nonce,'RunLater-Issued-At':String(at),'RunLater-Expires-At':String(at+60000),'RunLater-Request-Signature':sign(null,Buffer.from(canonical),this.key).toString('hex')});
  }
  if(idempotencyKey)headers['Idempotency-Key']=idempotencyKey;
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),5000);let response;
  try{response=await this.fetch(ORIGIN+path,{method,headers,body:bytes||undefined,redirect:'manual',signal:controller.signal});if(!response.ok)throw Error('Alpha API returned HTTP '+response.status);let all=new Uint8Array(),chunks=0;const reader=response.body?.getReader();if(reader)while(true){const {done,value}=await reader.read();if(done)break;if(all.length+value.length>32768||++chunks>32){controller.abort();throw Error('Alpha response exceeds example bounds');}const next=new Uint8Array(all.length+value.length);next.set(all);next.set(value,all.length);all=next;}return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(all));}
  catch(e){if(response&&!response.ok)throw Error('Alpha API returned HTTP '+response.status+'; check current approval, expiry, scope and grant.');throw Error('Alpha request failed or response exceeded example bounds; no automatic retry.');}
  finally{clearTimeout(timer);controller.abort();}
 }
 async enroll(){
  const received=await this.request('/v1/identity/challenges',{method:'POST',body:{project_id:this.project,public_key:this.publicKey},signed:false}),c=received.challenge,now=this.clock();
  if(!c||c.version!==1||c.origin!==ORIGIN||c.purpose!=='operator_alpha_enrollment'||c.project_id!==this.project||c.public_key!==this.publicKey||!/^[a-f0-9]{64}$/.test(c.nonce??'')||!/^[a-f0-9]{64}$/.test(received.challenge_id??'')||!/^[a-f0-9]{64}$/.test(c.policy_hash??'')||!Number.isSafeInteger(c.policy_revision)||c.policy_revision<1||!Number.isSafeInteger(c.issued_at_ms)||!Number.isSafeInteger(c.expires_at_ms)||c.issued_at_ms>now||c.expires_at_ms<=now||c.expires_at_ms-c.issued_at_ms>300000||!Number.isSafeInteger(c.identity_expires_at_ms)||c.identity_expires_at_ms<=now||!Array.isArray(c.permissions)||!c.permissions.length||new Set(c.permissions).size!==c.permissions.length||c.permissions.some(p=>!['enqueue','read','cancel','redrive'].includes(p)))throw Error('Unexpected enrollment context; proof not signed');
  const proof='RunLater enrollment proof v1\n'+JSON.stringify([c.version,c.origin,c.purpose,c.project_id,c.public_key,c.nonce,c.issued_at_ms,c.expires_at_ms,c.policy_revision,c.policy_hash,c.permissions,c.identity_expires_at_ms]);
  if(received.canonical_utf8!==proof)throw Error('Unexpected enrollment bytes; proof not signed');
  return this.request('/v1/identity/enroll',{method:'POST',body:{project_id:this.project,challenge_id:received.challenge_id,signature:sign(null,Buffer.from(proof),this.key).toString('hex')},signed:false});
 }
 enqueueSynthetic(key,runAt){stableKey(key);if(!Number.isSafeInteger(runAt)||runAt<0)throw Error('Use an explicit nonnegative UTC millisecond schedule');return this.request('/v1/tasks',{method:'POST',idempotencyKey:key,body:{destination:'registered:receiver_a',body:JSON.stringify({synthetic:true,mode:'success'}),operation_key:key,run_at_ms:runAt}});}
 task(id){return this.request('/v1/tasks/'+taskId(id));}
 cancel(id){return this.request('/v1/tasks/'+taskId(id)+'/cancel',{method:'POST',body:{}});}
}
export function loadOperatorKey(file){
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);if(!s.isFile()||s.size>4096||(s.mode&0o077)!==0||(process.getuid&&s.uid!==process.getuid()))throw Error('Use an owner-only private key file');return fs.readFileSync(fd,'utf8');}finally{fs.closeSync(fd);}
}
export async function checkAvailability(fetchImpl=fetch){
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),5000);
 try{const r=await fetchImpl(ORIGIN+'/health',{redirect:'manual',signal:controller.signal});if(!r.ok)throw Error('Health unavailable');const reader=r.body?.getReader();let size=0,chunks=0,text='';const decoder=new TextDecoder('utf-8',{fatal:true});if(reader)while(true){const {done,value}=await reader.read();if(done)break;if((size+=value.length)>8192||++chunks>32)throw Error('Health response exceeds bounds');text+=decoder.decode(value,{stream:true});}text+=decoder.decode();const v=JSON.parse(text);return {mode:v.mode,task_api:v.task_api,outbound:v.outbound};}finally{clearTimeout(timer);controller.abort();}
}
async function main(){
 const [mode,a,b,...extra]=process.argv.slice(2);if(extra.length)throw Error('Unexpected arguments');
 if(mode==='--check'&&a===undefined){console.log(JSON.stringify(await checkAvailability()));return;}
 if(!['--enroll','--send-synthetic','--status','--cancel'].includes(mode)||mode==='--enroll'&&a!==undefined||['--status','--cancel'].includes(mode)&&(b!==undefined||!a)||mode==='--send-synthetic'&&(a===undefined||b===undefined))throw Error('Usage: --check | --enroll | --send-synthetic STABLE_KEY UTC_MS | --status TASK_ID | --cancel TASK_ID');
 const client=new AlphaRunLater({project:process.env.RUNLATER_PROJECT_ID,privateKey:loadOperatorKey(process.env.RUNLATER_KEY_FILE)});
 if(mode==='--enroll'){await client.enroll();console.log(JSON.stringify({enrolled:true,note:'Scope, grant and expiry remain operator-controlled.'}));}
 if(mode==='--send-synthetic'){if(!/^(0|[1-9][0-9]*)$/.test(b))throw Error('Use canonical UTC milliseconds');const v=await client.enqueueSynthetic(a,Number(b));console.log(JSON.stringify({task_id:v.result?.id,status:v.result?.status,replayed:v.replayed}));}
 if(mode==='--status'){const v=await client.task(a);console.log(JSON.stringify({task_id:v.result?.id,status:v.result?.status,attempt_count:v.result?.attempts?.length}));}
 if(mode==='--cancel'){const v=await client.cancel(a);console.log(JSON.stringify({task_id:v.result?.id,status:v.result?.status}));}
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1])main().catch(()=>{console.error('RunLater alpha command failed. Check arguments, owner-only approved key, current scopes/expiry/grant and API availability. No automatic retry or purchase was performed.');process.exitCode=1;});
