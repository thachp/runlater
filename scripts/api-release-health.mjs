// Public, read-only verification. No provider credentials or mutation callbacks.
export const HEALTH_URL = 'https://api.runlater.io/health';
export const HEALTH_LIMITS = Object.freeze({totalMs:120000, requestMs:5000, attempts:12, spacingMs:5000, bytes:4096, chunks:128});
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const RETRY_STATUSES = new Set([500,502,503,504]);
const realClock = {now:()=>performance.now(), wallNow:()=>Date.now(), setTimeout, clearTimeout};
const result = (outcome,retry=false,extra={}) => ({outcome,retry,status:null,mode_match:false,configured:false,version_match:false,...extra});
export class HealthVerificationError extends Error {
  constructor(outcome) { super('promotion_completed_public_health_unverified'); this.name='HealthVerificationError'; this.outcome=outcome; }
}

function retryDelay(value,wallNow) {
  if(value===null)return 0;
  if(typeof value!=='string'||value.length>128)return null;
  if(/^\d{1,10}$/.test(value))return Number(value)*1000;
  // Only the standard IMF-fixdate form, not Date.parse's permissive shorthand.
  if(!/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value))return null;
  const date=Date.parse(value);
  if(!Number.isFinite(date)||new Date(date).toUTCString()!==value)return null;
  return Math.max(0,date-wallNow());
}

function cancel(body) {
  // Abort owns transport cleanup. A broken cancel promise cannot extend a bound
  // or replace the primary result; rejected cancellation is always consumed.
  try { Promise.resolve(body?.cancel()).catch(()=>{}); } catch {}
}

async function attempt(id,fetchImpl,clock,deadline) {
  const controller=new AbortController();
  let response,reader,timer,expired=false,status=null;
  const requestDeadline=Math.min(deadline,clock.now()+HEALTH_LIMITS.requestMs);
  const finish = () => { controller.abort(); cancel(reader??response?.body); };
  const timeout=new Promise(resolve=>{
    timer=clock.setTimeout(()=>{expired=true;finish();resolve(result('request_timeout',true,{status}));},requestDeadline-clock.now());
  });
  const work=(async()=>{
    try {
      response=await fetchImpl(HEALTH_URL,{method:'GET',redirect:'manual',signal:controller.signal});
      if(expired)return result('request_timeout',true);
      status=Number.isInteger(response.status)&&response.status>=100&&response.status<=599?response.status:null;
      const base={status};
      if(status>=300&&status<=399)return result('redirect',false,base);
      if(status===429||RETRY_STATUSES.has(status)) {
        const delay=retryDelay(response.headers.get('retry-after'),clock.wallNow);
        if(delay===null)return result('retry_after_invalid',false,base);
        return result(status===429?'http_429':'http_5xx',true,{...base,retry_after_ms:delay});
      }
      if(status!==200)return result('http_status',false,base);
      if(!response.body||response.body.locked)return result('invalid_body',false,base);
      reader=response.body.getReader();
      const decoder=new TextDecoder('utf-8',{fatal:true});
      let text='',bytes=0,chunks=0;
      for(;;) {
        const {done,value}=await reader.read();
        if(expired)return result('request_timeout',true,base);
        if(done)break;
        if(!(value instanceof Uint8Array))return result('invalid_body',false,base);
        bytes+=value.byteLength;chunks++;
        if(bytes>HEALTH_LIMITS.bytes)return result('body_too_large',false,base);
        if(chunks>HEALTH_LIMITS.chunks)return result('too_many_chunks',false,base);
        try { text+=decoder.decode(value,{stream:true}); } catch { return result('invalid_utf8',false,base); }
      }
      try { text+=decoder.decode(); } catch { return result('invalid_utf8',false,base); }
      let body;
      try { body=JSON.parse(text); } catch { return result('invalid_json',false,base); }
      const matches={...base,mode_match:body?.mode==='public_free_beta',configured:body?.configured===true,version_match:body?.version_id===id};
      if(!matches.mode_match)return result('wrong_mode',false,matches);
      if(!matches.configured)return result('not_configured',false,matches);
      if(typeof body.version_id!=='string'||!UUID.test(body.version_id))return result('invalid_version',false,matches);
      return result(matches.version_match?'verified':'version_mismatch',!matches.version_match,matches);
    } catch { return result(expired?'request_timeout':'transport_error',true,{status}); }
    finally { finish(); }
  })();
  try {
    const observed=await Promise.race([work,timeout]);
    return clock.now()>=requestDeadline?result('request_timeout',true,{status}):observed;
  }
  finally { clock.clearTimeout(timer); finish(); }
}

export async function verifyPublicHealth(id,{fetch:fetchImpl=globalThis.fetch,clock=realClock,onAttempt=()=>{}}={}) {
  if(typeof id!=='string'||!UUID.test(id))throw new HealthVerificationError('invalid_expected_version');
  const start=clock.now(),deadline=start+HEALTH_LIMITS.totalMs;
  let last='deadline';
  for(let number=1;number<=HEALTH_LIMITS.attempts&&clock.now()<deadline;number++) {
    const observed=await attempt(id,fetchImpl,clock,deadline);
    if(clock.now()>=deadline)observed.outcome='deadline';
    const diagnostic={attempt:number,elapsed_ms:Math.max(0,Math.floor(clock.now()-start)),status:observed.status,outcome:observed.outcome,mode_match:observed.mode_match,configured:observed.configured,version_match:observed.version_match};
    if(observed.retry_after_ms!==undefined)diagnostic.retry_after_ms=observed.retry_after_ms;
    onAttempt(diagnostic);
    last=observed.outcome;
    if(last==='verified')return {attempts:number};
    if(last==='deadline'||!observed.retry)throw new HealthVerificationError(last);
    if(number===HEALTH_LIMITS.attempts)break;
    const delay=Math.max(HEALTH_LIMITS.spacingMs,observed.retry_after_ms??0);
    if(delay>=deadline-clock.now())throw new HealthVerificationError('retry_after_exceeds_deadline');
    await new Promise(resolve=>clock.setTimeout(resolve,delay));
  }
  throw new HealthVerificationError(clock.now()>=deadline?'deadline':last);
}
