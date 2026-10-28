// Source-only static artifact builder. It never contacts hosts, registers tools or deploys resources.
import fs from 'node:fs';import path from 'node:path';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';
const repo=fileURLToPath(new URL('../',import.meta.url));
export const readJson=p=>JSON.parse(fs.readFileSync(path.join(repo,p),'utf8'));
const object=properties=>({type:'object',additionalProperties:false,properties,required:Object.keys(properties)});
const opaque=max=>({type:'string',minLength:1,maxLength:max});
export function tools(spec,bytes){
 const operation=(route,method)=>spec.paths[route][method];
 const names=[['schedule_task','/v1/tasks','post','schedule'],['task_status','/v1/tasks/{id}','get','read'],['cancel_task','/v1/tasks/{id}/cancel','post','cancel']];
 const local=names.map(([name,route,method,effect])=>{const op=operation(route,method),id=op.parameters.find(p=>p.name==='id'),key=op.parameters.find(p=>p.name==='Idempotency-Key');return {name,description:'Local synthetic fixture only; hosted execution is unavailable.',effect,hosted_enabled:false,local_enabled:true,input_stability:'derived_from_canonical_local_openapi',binding:{method:method.toUpperCase(),path:route,operation_id:op.operationId,required_permission:op['x-required-permission']},input_schema:object(id?{task_id:id.schema}:{idempotency_key:key.schema,task:spec.components.schemas.Create}),credential_transport:'authorization_header_managed_by_authorized_client_not_tool_arguments'};});
 const proposals=[['registration_challenge',27,'registration',object({public_key:opaque(2048)})],['complete_registration',27,'registration',object({challenge_id:opaque(128),proof:opaque(4096)})],['inspect_entitlements',30,'read',object({})],['request_credit_quote',29,'read',object({requested_units:{type:'integer',minimum:1,maximum:9007199254740991}})],['initiate_credit_purchase',30,'potential_spend',object({quote_id:opaque(128),idempotency_key:opaque(128)})]];
 return {$schema:'https://docs.runlater.io/agent/tools.v1.schema.json',version:'1.0.0',format_owner:'RunLater',protocol_status:'custom_data_not_tool_registration_or_authorization',canonical_contract:{url:'https://docs.runlater.io/openapi.json',version:spec.info.version,sha256:createHash('sha256').update(bytes).digest('hex')},automatic_execution:false,hosted_enabled:false,tools:[...local,...proposals.map(([name,issue,effect,input_schema])=>({name,description:'Disabled illustrative proposal. Key/proof formats, commercial terms and REST binding remain unresolved; this is not an implemented input contract.',effect,hosted_enabled:false,local_enabled:false,input_stability:'illustrative_nonbinding_proposal',binding:null,tracking_issue:issue,input_schema,credential_transport:'authorization_header_managed_by_authorized_client_not_tool_arguments',purchase_authority:'separate_wallet_delegation_required_before_any_future_spend'}))]};
}
export function buildDiscovery(output=path.join(repo,'build/discovery')){
 const marker=path.join(output,'.runlater-discovery-output');if(fs.existsSync(output)&&(!fs.existsSync(marker)||fs.readFileSync(marker,'utf8')!=='runlater-source-artifacts-v1'))throw Error('Refuse to overwrite a directory not owned by this artifact builder');
 fs.mkdirSync(output,{recursive:true});fs.writeFileSync(marker,'runlater-source-artifacts-v1');
 for(const role of ['landing','docs']){fs.rmSync(path.join(output,role),{recursive:true,force:true});fs.cpSync(path.join(repo,'web',role),path.join(output,role),{recursive:true});}
 const copy=(src,dest)=>{const target=path.join(output,dest);fs.mkdirSync(path.dirname(target),{recursive:true});fs.copyFileSync(path.join(repo,src),target);};
 copy('discovery/service.v1.json','landing/runlater-service.v1.json');copy('discovery/pricing-status.v1.json','landing/pricing-status.v1.json');copy('discovery/llms.txt','landing/llms.txt');copy('discovery/llms.txt','docs/llms.txt');
 for(const name of ['service.v1.schema.json','tools.v1.schema.json','pricing-status.v1.schema.json'])copy('discovery/'+name,'docs/agent/'+name);
 copy('docs/AGENT-QUICKSTART.md','docs/agent/quickstart.md');copy('docs/openapi.json','docs/openapi.json');
 const bytes=fs.readFileSync(path.join(repo,'docs/openapi.json'));const bundle=tools(JSON.parse(bytes),bytes);fs.writeFileSync(path.join(output,'docs/agent/tools.v1.json'),JSON.stringify(bundle,null,2)+'\n');return {output,bundle};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){const {output}=buildDiscovery();console.log('Built source-only discovery artifacts: '+output+' (no deployment or network calls)');}
