import {createHash} from 'node:crypto';
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
export function canonical(v) { return JSON.stringify(Array.isArray(v) ? v.map(x=>JSON.parse(canonical(x))) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k=>[k,JSON.parse(canonical(v[k]))])) : v); }
export const digest = v => createHash('sha256').update(canonical(v)).digest('hex');
function guard(ok) { if (!ok) throw new Error('release guard rejected configuration or provider state'); }
export function settingsDigest(settings) {
  guard(settings&&typeof settings==='object'&&!Array.isArray(settings));
  const value=structuredClone(settings),annotations=value.annotations??{};
  guard(typeof annotations==='object'&&!Array.isArray(annotations));
  // These observed version-identity labels vary on every upload. Code identity
  // is bound separately by current main, the upload receipt and active version.
  for(const key of ['workers/message','workers/tag','workers/triggered_by'])delete annotations[key];
  if(Object.keys(annotations).length)value.annotations=annotations;else delete value.annotations;
  return digest(value);
}
export function validate(c,a,e) {
  guard(e.RUNLATER_RELEASE_ENABLED === 'true' && e.GITHUB_REPOSITORY === 'thachp/runlater' && /^[a-f0-9]{40}$/.test(e.RELEASE_SHA ?? ''));
  guard(a.worker === 'runlater-public-api' && /^[a-f0-9]{32}$/.test(a.account_id ?? '') && /^[a-f0-9]{32}$/.test(a.worker_tag ?? '') && a.settings_schema==='runtime-v1' && /^[a-f0-9]{64}$/.test(a.settings_sha256 ?? '') && digest(c) === a.config_sha256);
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
export function uploadedVersion(lines,expectedTag,onReceipt=()=>{}) {
  const records=lines.trim().split('\n').map(l=>JSON.parse(l)).filter(r=>r.type==='version-upload');
  guard(records.length===1 && records[0].worker_name==='runlater-public-api' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(records[0].version_id??''));
  onReceipt(records[0].version_id);
  guard(!records[0].preview_url&&!records[0].preview_alias_url&&/^[a-f0-9]{32}$/.test(expectedTag??'')&&records[0].worker_tag===expectedTag);
  return records[0].version_id;
}
export function uploadArguments(file,sha,service,a) {
  const env=service?.default_environment,script=env?.script;
  guard(a.worker==='runlater-public-api'&&/^[a-f0-9]{32}$/.test(a.worker_tag??'')&&service?.id===a.worker&&env?.environment==='production'&&script?.id===a.worker&&script?.tag===a.worker_tag);
  // Wrangler strict mode always refuses an API-origin Worker, even without drift.
  // Only this authenticated, pinned identity can acknowledge that generic warning.
  // deployExisting's approved settings/deployment fingerprints still gate promotion.
  return ['versions','upload','--config',file,...(script.last_deployed_from==='api'?[]:['--strict']),'--tag',sha.slice(0,12),'--message',`Reviewed main ${sha}`];
}
export function runWrangler(args,e,out,exec=execFileSync,onFailure=()=>{}) {
  try{return exec('node',['node_modules/wrangler/bin/wrangler.js',...args],{timeout:120000,stdio:'pipe',env:{...e,WRANGLER_SEND_METRICS:'false',WRANGLER_OUTPUT_FILE_PATH:out}});}
  catch(error){onFailure(Number.isInteger(error?.status)&&error.status>=0&&error.status<=255?error.status:'unknown');throw new Error('wrangler_child_failed');}
}
export function checkSecretCollisions(config,settings,secrets) {
  guard(config&&typeof config==='object'&&Array.isArray(settings?.bindings)&&Array.isArray(secrets));
  const localNames=new Set([
    ...Object.keys(config.vars??{}),
    ...(config.durable_objects?.bindings??[]).map(b=>b.name),
    ...(config.queues?.producers??[]).map(b=>b.binding),
    ...(config.ratelimits??[]).map(b=>b.name),
    config.version_metadata?.binding
  ].filter(name=>name!==undefined));
  guard(localNames.size>0&&[...localNames].every(name=>typeof name==='string'&&name.length>0));
  const names=bindings=>{
    const result=new Set();
    for(const binding of bindings){
      guard(typeof binding?.name==='string'&&binding.name.length>0);
      guard(!localNames.has(binding.name));
      result.add(binding.name);
    }
    return [...result].sort();
  };
  return {listed:names(secrets),metadata:names(settings.bindings.filter(b=>typeof b.type==='string'&&b.type.includes('secret')))};
}
export async function deployExisting(a,get,upload,promote,stillCurrent=async()=>true,onUploaded=()=>{},onStage=()=>{},config) {
  onStage('source_preflight');
  guard(await stillCurrent());
  onStage('settings_preflight');
  const s=await get('/settings');
  guard(settingsDigest(s)===a.settings_sha256 && s.bindings?.some(b=>b.name==='BETA_CALLBACK_MASTER' && b.type==='secret_text'));
  onStage('secret_preflight');
  const secrets=await get('/secrets');
  guard(Array.isArray(secrets)&&secrets.some(b=>b?.name==='BETA_CALLBACK_MASTER'));
  const secretNames=checkSecretCollisions(config,s,secrets);
  onStage('deployment_preflight');
  const before=digest(await get('/deployments'));
  onStage('version_upload');
  const id=uploadedVersion(await upload(),a.worker_tag,onUploaded);
  onStage('settings_post_upload');
  const afterSettings=await get('/settings');
  guard(settingsDigest(afterSettings)===a.settings_sha256);
  onStage('secret_post_upload');
  guard(digest(checkSecretCollisions(config,afterSettings,await get('/secrets')))===digest(secretNames));
  onStage('deployment_post_upload');
  guard(digest(await get('/deployments'))===before);
  onStage('source_post_upload');
  guard(await stillCurrent());
  onStage('version_promote');
  await promote(id);
  onStage('deployment_verify');
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
    console.log(`GitHub read HTTP status: ${r.status}`);
    guard(r.ok);return (await r.json()).object?.sha===e.RELEASE_SHA;
  };
  const providerRead=async path=>{
    const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${a.account_id}${path}`,{headers:{Authorization:`Bearer ${e.CLOUDFLARE_API_TOKEN}`},signal:AbortSignal.timeout(15000),redirect:'error'});
    console.log(`Provider read HTTP status: ${r.status}`);
    guard(r.ok);const b=await r.json();guard(b.success);return b.result;
  };
  const get=suffix=>providerRead(`/workers/scripts/${a.worker}${suffix}`);
  const dir=await mkdtemp(join(tmpdir(),'runlater-release-')), file=join(process.cwd(),'.runlater-release.generated.json'), out=join(dir,'upload.jsonl');
  const run=args=>runWrangler(args,{...e,CLOUDFLARE_ACCOUNT_ID:a.account_id},out,execFileSync,status=>console.error(`Wrangler child exit status: ${status}`));
  let owned=false;
  try {
    await writeFile(file,JSON.stringify(c),{mode:0o600,flag:'wx'});owned=true;
    const id=await deployExisting(a,get,async()=>{
      console.log('Release phase: service_identity');
      const service=await providerRead(`/workers/services/${a.worker}`);
      const args=uploadArguments(file,e.RELEASE_SHA,service,a);
      console.log('Release phase: upload_cli');
      run(args);
      return readFile(out,'utf8');
    },async id=>run(['versions','deploy',`${id}@100%`,'--config',file,'--yes','--message',`Reviewed main ${e.RELEASE_SHA}`]),stillCurrent,id=>console.log(`Uploaded Worker version ${id} for ${e.RELEASE_SHA}; retain this receipt even if later checks fail.`),stage=>console.log(`Release phase: ${stage}`),c);
    console.log('Release phase: health_verify');
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
