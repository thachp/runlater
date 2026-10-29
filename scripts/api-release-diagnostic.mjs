// Bounded GET-only preflight. Never uploads, promotes, changes settings, or prints provider bodies.
import {validate, digest} from './api-release.mjs';
import {pathToFileURL} from 'node:url';

export async function diagnose(e=process.env, fetchImpl=globalThis.fetch, clock=Date.now) {
  let config, approval;
  try {
    config=JSON.parse(e.RUNLATER_RELEASE_CONFIG??'{}');
    approval=JSON.parse(e.RUNLATER_RELEASE_APPROVAL??'{}');
    // Reuse pure target validation while releases stay disabled. This function has no writer.
    validate(config,approval,{...e,RUNLATER_RELEASE_ENABLED:'true',RELEASE_SHA:e.GITHUB_SHA});
    if(!e.GH_TOKEN || !e.CLOUDFLARE_API_TOKEN) throw Error();
  } catch { return {diagnostic:'configuration_invalid',requests:0}; }
  const deadline=clock()+35000, report={diagnostic:'read_only',requests:0,checks:[]};
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
  const github=await read('github_main','https://api.github.com/repos/thachp/runlater/git/ref/heads/main',e.GH_TOKEN);
  if(github)report.main_matches_source=github.object?.sha===e.GITHUB_SHA;
  const base=`https://api.cloudflare.com/client/v4/accounts/${approval.account_id}`;
  const settings=await read('worker_settings',`${base}/workers/scripts/runlater-public-api/settings`,e.CLOUDFLARE_API_TOKEN);
  if(settings?.result){report.settings_match_baseline=digest(settings.result)===approval.settings_sha256;report.master_binding_present=!!settings.result.bindings?.some(b=>b.name==='BETA_CALLBACK_MASTER'&&b.type==='secret_text');}
  const deployments=await read('worker_deployments',`${base}/workers/scripts/runlater-public-api/deployments`,e.CLOUDFLARE_API_TOKEN);
  if(deployments?.result)report.single_active_version=deployments.result.deployments?.[0]?.versions?.length===1&&deployments.result.deployments[0].versions[0].percentage===100;
  await read('queues_read',`${base}/queues?per_page=1`,e.CLOUDFLARE_API_TOKEN);
  return report;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  diagnose().then(report=>{
    console.log(JSON.stringify(report));
    if(report.diagnostic!=='read_only'||report.main_matches_source!==true||report.settings_match_baseline!==true||report.master_binding_present!==true||report.single_active_version!==true||report.checks.some(x=>x.error||x.http_status<200||x.http_status>=300||x.api_success===false))process.exitCode=1;
  }).catch(()=>{console.error('read_only_diagnostic_failed');process.exitCode=1;});
}
