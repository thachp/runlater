import {createHash} from 'node:crypto';
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
export function canonical(v) { return JSON.stringify(Array.isArray(v) ? v.map(x=>JSON.parse(canonical(x))) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k=>[k,JSON.parse(canonical(v[k]))])) : v); }
export const digest = v => createHash('sha256').update(canonical(v)).digest('hex');
function guard(ok) { if (!ok) throw new Error('release guard rejected configuration or provider state'); }
export function validate(c,a,e) {
  guard(e.RUNLATER_RELEASE_ENABLED === 'true' && e.GITHUB_REPOSITORY === 'thachp/runlater' && /^[a-f0-9]{40}$/.test(e.RELEASE_SHA ?? ''));
  guard(a.worker === 'runlater-public-api' && /^[a-f0-9]{32}$/.test(a.account_id ?? '') && /^[a-f0-9]{64}$/.test(a.settings_sha256 ?? '') && digest(c) === a.config_sha256);
  guard(Object.keys(c).every(k=>['name','main','compatibility_date','compatibility_flags','workers_dev','preview_urls','limits','observability','durable_objects','queues','ratelimits','vars','version_metadata'].includes(k)));
  guard(c.name === a.worker && c.main === 'build/worker/shim.mjs' && c.workers_dev === false && c.preview_urls === false && canonical(c.limits) === '{"cpu_ms":50}' && canonical(c.observability) === '{"enabled":false}');
  guard(canonical(c.compatibility_flags) === '["global_fetch_strictly_public"]' && /^\d{4}-\d{2}-\d{2}$/.test(c.compatibility_date ?? ''));
  guard(canonical(c.durable_objects) === canonical({bindings:[{name:'ADMISSION',class_name:'AdmissionRegistry'},{name:'PROJECTS',class_name:'InvitationProject'}]}));
  guard(canonical(c.version_metadata) === '{"binding":"RELEASE_VERSION"}');
  guard(canonical(c.queues) === canonical({producers:[{binding:'BETA_READY',queue:'runlater-public-ready'}]}));
  guard(c.vars?.PUBLIC_BETA_ENABLED === 'operator-approved' && c.vars?.BETA_READY_QUEUE === 'runlater-public-ready');
  guard(Object.keys(c.vars).sort().join(',') === 'BETA_READY_QUEUE,BETA_REVOKED_PROJECTS,PUBLIC_BETA_ENABLED,PUBLIC_BETA_PROFILE');
  const p = JSON.parse(c.vars.PUBLIC_BETA_PROFILE);
  guard(p.release_id && Number.isSafeInteger(p.opens_at_ms) && Number.isSafeInteger(p.closes_at_ms) && p.closes_at_ms>p.opens_at_ms && p.closes_at_ms-p.opens_at_ms<=604800000 && Number.isSafeInteger(p.callback_end_sec) && p.callback_end_sec>=Math.floor((p.closes_at_ms+691200000)/1000)+300);
  guard(Array.isArray(JSON.parse(c.vars.BETA_REVOKED_PROJECTS)));
  guard(canonical(c.ratelimits) === canonical([{name:'BETA_IP_RATE',namespace_id:'1001',simple:{limit:60,period:60}},{name:'BETA_REG_IP_RATE',namespace_id:'1002',simple:{limit:6,period:60}}]));
}
export function uploadedVersion(lines) {
  const records=lines.trim().split('\n').map(l=>JSON.parse(l)).filter(r=>r.type==='version-upload');
  guard(records.length===1 && records[0].worker_name==='runlater-public-api' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(records[0].version_id??'') && !records[0].preview_url && !records[0].preview_alias_url);
  return records[0].version_id;
}
export async function deployExisting(a,get,upload,promote,stillCurrent=async()=>true,onUploaded=()=>{}) {
  guard(await stillCurrent());
  const s=await get('/settings');
  guard(digest(s)===a.settings_sha256 && s.bindings?.some(b=>b.name==='BETA_CALLBACK_MASTER' && b.type==='secret_text'));
  const before=digest(await get('/deployments'));
  const id=uploadedVersion(await upload());
  onUploaded(id);
  guard(digest(await get('/settings'))===a.settings_sha256 && digest(await get('/deployments'))===before);
  guard(await stillCurrent());
  await promote(id);
  const active=await get('/deployments');
  const versions=active?.deployments?.[0]?.versions;
  guard(Array.isArray(versions) && versions.length===1 && versions[0].version_id===id && versions[0].percentage===100);
  return id;
}
export function verifyHealth(body,id) {
  guard(body?.mode==='public_free_beta' && body.configured===true && body.version_id===id);
}
export async function release(e=process.env) {
  const c=JSON.parse(e.RUNLATER_RELEASE_CONFIG??'{}'), a=JSON.parse(e.RUNLATER_RELEASE_APPROVAL??'{}'); validate(c,a,e);
  guard(e.CLOUDFLARE_API_TOKEN && (!e.CLOUDFLARE_ACCOUNT_ID || e.CLOUDFLARE_ACCOUNT_ID===a.account_id));
  const stillCurrent=async()=>{
    guard(e.GH_TOKEN);
    const r=await fetch('https://api.github.com/repos/thachp/runlater/git/ref/heads/main',{headers:{Authorization:`Bearer ${e.GH_TOKEN}`,Accept:'application/vnd.github+json'},signal:AbortSignal.timeout(15000),redirect:'error'});
    guard(r.ok);return (await r.json()).object?.sha===e.RELEASE_SHA;
  };
  const get=async suffix=>{
    const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${a.account_id}/workers/scripts/${a.worker}${suffix}`,{headers:{Authorization:`Bearer ${e.CLOUDFLARE_API_TOKEN}`},signal:AbortSignal.timeout(15000),redirect:'error'});
    guard(r.ok);const b=await r.json();guard(b.success);return b.result;
  };
  const dir=await mkdtemp(join(tmpdir(),'runlater-release-')), file=join(process.cwd(),'.runlater-release.generated.json'), out=join(dir,'upload.jsonl');
  const run=args=>execFileSync('node',['node_modules/wrangler/bin/wrangler.js',...args],{timeout:120000,stdio:'pipe',env:{...e,CLOUDFLARE_ACCOUNT_ID:a.account_id,WRANGLER_SEND_METRICS:'false',WRANGLER_OUTPUT_FILE_PATH:out}});
  let owned=false;
  try {
    await writeFile(file,JSON.stringify(c),{mode:0o600,flag:'wx'});owned=true;
    const id=await deployExisting(a,get,async()=>{
      run(['versions','upload','--config',file,'--strict','--tag',e.RELEASE_SHA.slice(0,12),'--message',`Reviewed main ${e.RELEASE_SHA}`]);
      return readFile(out,'utf8');
    },async id=>run(['versions','deploy',`${id}@100%`,'--config',file,'--yes','--message',`Reviewed main ${e.RELEASE_SHA}`]),stillCurrent,id=>console.log(`Uploaded Worker version ${id} for ${e.RELEASE_SHA}; retain this receipt even if later checks fail.`));
    const health=await fetch('https://api.runlater.io/health',{signal:AbortSignal.timeout(5000),redirect:'error'});
    guard(health.status===200);
    const reader=health.body.getReader();let body='',size=0;
    try { for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;guard(size<=4096);body+=new TextDecoder().decode(value);} }
    finally {await reader.cancel();}
    verifyHealth(JSON.parse(body),id);
    console.log(`Released ${e.RELEASE_SHA} as ${id}; public health returned 200. No task traffic generated.`);
  } finally { if(owned)await rm(file,{force:true});await rm(dir,{recursive:true,force:true}); }
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href)release().catch(()=>{console.error('Release stopped. Reconcile Cloudflare versions/deployments before retry. No automatic rollback or provisioning.');process.exitCode=1;});
