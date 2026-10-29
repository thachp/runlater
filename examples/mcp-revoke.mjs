// Explicit owner-only revoke-all command. Never called as an MCP tool or automatically.
import {createHash,createPrivateKey,randomBytes,sign} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {PublicBetaClientV1,PublicBetaClientError,readOwnerText,loadOwnerKey} from './public-beta-client.v1.mjs';
const ORIGIN='https://api.runlater.io',PATH='/v1/mcp/delegations/revoke';
const hash=value=>createHash('sha256').update(value).digest('hex');
const integer=n=>Number.isSafeInteger(n)&&n>=0;
function check(ok,code='invalid_revoke_request'){if(!ok)throw new PublicBetaClientError(code);}
export async function revokeAllDelegations({privateKey,receipt,releaseId,idempotencyKey,fetchImpl,clock=Date.now,nonce=()=>randomBytes(32).toString('hex'),timeoutMs=5000}){
 check(typeof fetchImpl==='function','explicit_transport_required');
 check(typeof clock==='function'&&typeof nonce==='function'&&Number.isInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=5000);
 check(typeof idempotencyKey==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(idempotencyKey),'idempotency_key_required');
 // Reuse original key/receipt/release binding validation without making a request.
 const client=new PublicBetaClientV1({privateKey,receipt,releaseId,fetchImpl,clock});
 const at=clock(),n=nonce();check(integer(at)&&at<=Number.MAX_SAFE_INTEGER-60000&&typeof n==='string'&&/^[a-f0-9]{64}$/.test(n));
 check(receipt.expires_at_ms>at,'identity_expired');
 const expires=Math.min(at+60000,receipt.expires_at_ms),body='{}';
 const wire='RunLater signed request v1\n'+JSON.stringify([1,ORIGIN,client.project,client.publicKey,'POST',PATH,'',hash(body),idempotencyKey,at,expires,n]);
 const key=privateKey?.type==='private'?privateKey:createPrivateKey(privateKey);
 const headers={'Content-Type':'application/json','Idempotency-Key':idempotencyKey,'RunLater-Project-Id':client.project,'RunLater-Public-Key':client.publicKey,
  'RunLater-Nonce':n,'RunLater-Issued-At':String(at),'RunLater-Expires-At':String(expires),'RunLater-Request-Signature':sign(null,Buffer.from(wire),key).toString('hex')};
 const controller=new AbortController();let timer,reader;
 const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new PublicBetaClientError('transport_uncertain'));},timeoutMs);});
 try{return await Promise.race([timeout,(async()=>{
  const response=await fetchImpl(ORIGIN+PATH,{method:'POST',headers,body,redirect:'manual',signal:controller.signal});
  check(!(response.status>=300&&response.status<400),'redirect_rejected');if(!response.ok)throw new PublicBetaClientError('http_error',response.status);
  reader=response.body?.getReader();let size=0,chunks=0;const parts=[];
  if(reader)for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;chunks++;check(size<=4096&&chunks<=16,'response_too_large');parts.push(Buffer.from(value));}
  let value;try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(parts)));}catch{throw new PublicBetaClientError('invalid_response');}
  check(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()==='replayed,revoked_before_ms'
    &&integer(value.revoked_before_ms)&&typeof value.replayed==='boolean','invalid_response');
  return {revoked_before_ms:value.revoked_before_ms,replayed:value.replayed};
 })()]);}catch(e){throw e instanceof PublicBetaClientError?e:new PublicBetaClientError('transport_uncertain');}
 finally{clearTimeout(timer);controller.abort();if(reader){void reader.cancel().catch(()=>{});try{reader.releaseLock();}catch{}}}
}
export function parseRevokeArgs(argv){
 const allowed=new Set(['--revoke-all','--key','--receipt','--release-id','--idempotency-key']),options={};
 for(let i=0;i<argv.length;i++){const name=argv[i];check(allowed.has(name)&&!Object.hasOwn(options,name));if(name==='--revoke-all'){options[name]=true;continue;}const value=argv[++i];check(typeof value==='string'&&value.length>0&&!value.startsWith('--'));options[name]=value;}
 if(options['--revoke-all'])check(['--key','--receipt','--release-id','--idempotency-key'].every(n=>options[n]));return options;
}
export async function runOwnerRevoke(argv,{print=s=>console.log(s),fetchImpl=fetch}={}){
 const options=parseRevokeArgs(argv);
 if(!options['--revoke-all']){print('Dry run: no files read, signatures made or HTTP sent. --revoke-all --key FILE --receipt FILE --release-id ID --idempotency-key STABLE_KEY revokes existing MCP delegations for this owner project. It does not cancel already accepted tasks.');return;}
 const result=await revokeAllDelegations({privateKey:loadOwnerKey(options['--key']),receipt:JSON.parse(readOwnerText(options['--receipt'])),releaseId:options['--release-id'],idempotencyKey:options['--idempotency-key'],fetchImpl});
 print(JSON.stringify({...result,note:'Delegations issued at or before this cutoff are revoked. Existing tasks are not cancelled. New approval must be explicitly signed after the cutoff.'}));
}
if(process.argv[1]&&pathToFileURL(process.argv[1]).href===import.meta.url)runOwnerRevoke(process.argv.slice(2)).catch(()=>{
 console.error('RunLater MCP revoke command failed or its outcome is uncertain. Keep the original idempotency key; do not automatically retry or assume revocation. No credentials or response bodies are printed.');process.exitCode=1;
});
