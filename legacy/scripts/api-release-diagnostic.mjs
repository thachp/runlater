// Bounded GET-only preflight. Never uploads, promotes, changes settings, or prints provider bodies.
import {validate, settingsDigest} from './api-release.mjs';
import {pathToFileURL} from 'node:url';

// Exactly the metadata reads in locked Wrangler's dashboard-origin pre-upload
// check. A label identifies a fixed path; no provider URL or body is reflected.
const DASHBOARD_READS=[
  ['dashboard_bindings','/workers/services/runlater-public-api/environments/production/bindings'],
  ['dashboard_routes','/workers/services/runlater-public-api/environments/production/routes?show_zonename=true'],
  ['dashboard_domains','/workers/domains/records?page=0&per_page=5&service=runlater-public-api&environment=production'],
  ['dashboard_subdomain','/workers/services/runlater-public-api/environments/production/subdomain'],
  ['dashboard_environment','/workers/services/runlater-public-api/environments/production'],
  ['dashboard_schedules','/workers/scripts/runlater-public-api/schedules']
];

export async function diagnose(e=process.env, fetchImpl=globalThis.fetch, clock=Date.now) {
  let config, approval;const mode=e.RUNLATER_DIAGNOSTIC_MODE??'metadata';
  try {
    if(!['metadata','token_identity'].includes(mode))throw Error();
    config=JSON.parse(e.RUNLATER_RELEASE_CONFIG??'{}');
    approval=JSON.parse(e.RUNLATER_RELEASE_APPROVAL??'{}');
    // Reuse pure target validation while releases stay disabled. This function has no writer.
    validate(config,approval,{...e,RUNLATER_RELEASE_ENABLED:'true',RELEASE_SHA:e.GITHUB_SHA});
    if((mode==='metadata'&&!e.GH_TOKEN) || !e.CLOUDFLARE_API_TOKEN) throw Error();
  } catch { return {diagnostic:'configuration_invalid',requests:0}; }
  const deadline=clock()+(mode==='token_identity'?8000:35000), report={diagnostic:mode==='token_identity'?'token_identity':'read_only',requests:0,checks:[]};
  async function read(check,url,token) {
    const row={check}; report.checks.push(row);
    const remaining=Math.min(8000,deadline-clock());
    if(remaining<=0){row.error='deadline';return null;}
    try {
      report.requests++;
      const response=await fetchImpl(url,{method:'GET',redirect:'error',signal:AbortSignal.timeout(remaining),headers:{Authorization:`Bearer ${token}`,Accept:'application/json'}});
      row.http_status=response.status;
      const reader=response.body?.getReader();
      if(!reader){row.error='missing_body';return null;}
      let size=0,chunks=0,body='';const decoder=new TextDecoder();
      try {
        for(;;){const {done,value}=await reader.read();if(done)break;
          size+=value.length;chunks++;
          if(size>65536 || chunks>64){row.error='response_bound';return null;}
          body+=decoder.decode(value,{stream:true});
        }
        body+=decoder.decode();
      }finally{await reader.cancel();}
      let data;try{data=JSON.parse(body);}catch{row.error='invalid_json';return null;}
      if(typeof data.success==='boolean')row.api_success=data.success;
      if(Array.isArray(data.errors))row.error_codes=data.errors.slice(0,5).map(x=>x?.code).filter(Number.isSafeInteger);
      if(!response.ok || data.success===false)return null;
      return data;
    }catch{row.error='request_failed';return null;}
  }
  if(mode==='token_identity'){
    const data=await read('ci_token_verify','https://api.cloudflare.com/client/v4/user/tokens/verify',e.CLOUDFLARE_API_TOKEN);
    const value=data?.result;
    if(data?.success===true&&typeof value?.id==='string'&&/^[a-f0-9]{32}$/.test(value.id)&&value.id!==e.CLOUDFLARE_API_TOKEN&&['active','disabled','expired'].includes(value.status)){
      report.token_id=value.id;report.token_status=value.status;
    }else if(data)report.checks[0].error='token_metadata_invalid';
    return report;
  }
  const github=await read('github_main','https://api.github.com/repos/thachp/runlater/git/ref/heads/main',e.GH_TOKEN);
  if(github)report.main_matches_source=github.object?.sha===e.GITHUB_SHA;
  const base=`https://api.cloudflare.com/client/v4/accounts/${approval.account_id}`;
  const settings=await read('worker_settings',`${base}/workers/scripts/runlater-public-api/settings`,e.CLOUDFLARE_API_TOKEN);
  if(settings?.result){report.settings_match_baseline=settingsDigest(settings.result)===approval.settings_sha256;report.master_binding_present=!!settings.result.bindings?.some(b=>b.name==='BETA_CALLBACK_MASTER'&&b.type==='secret_text');}
  const deployments=await read('worker_deployments',`${base}/workers/scripts/runlater-public-api/deployments`,e.CLOUDFLARE_API_TOKEN);
  if(deployments?.result)report.single_active_version=deployments.result.deployments?.[0]?.versions?.length===1&&deployments.result.deployments[0].versions[0].percentage===100;
  await read('queues_read',`${base}/queues?per_page=1`,e.CLOUDFLARE_API_TOKEN);
  for(const [check,path] of DASHBOARD_READS)await read(check,base+path,e.CLOUDFLARE_API_TOKEN);
  return report;
}
export function diagnosticSucceeded(report){
  if(!Array.isArray(report?.checks)||report.checks.some(x=>x.error||!Number.isInteger(x.http_status)||x.http_status<200||x.http_status>=300||x.api_success===false))return false;
  if(report.diagnostic==='token_identity')return report.requests===1&&report.checks.length===1&&report.checks[0].check==='ci_token_verify'&&/^[a-f0-9]{32}$/.test(report.token_id??'')&&report.token_status==='active';
  return report.diagnostic==='read_only'&&report.main_matches_source===true&&report.settings_match_baseline===true&&report.master_binding_present===true&&report.single_active_version===true;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  diagnose().then(report=>{
    console.log(JSON.stringify(report));
    if(!diagnosticSucceeded(report))process.exitCode=1;
  }).catch(()=>{console.error('read_only_diagnostic_failed');process.exitCode=1;});
}
