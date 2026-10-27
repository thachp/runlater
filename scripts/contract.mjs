// Executable OpenAPI parity against fresh local workerd; no provider resources or callbacks.
import {request as httpRequest} from 'node:http';import fs from 'node:fs';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
import {LocalRunLater,RunLaterError} from '../examples/local-client.mjs';
const spec=JSON.parse(fs.readFileSync(new URL('../docs/openapi.json',import.meta.url)));
const ajv=new Ajv2020({strict:true,allErrors:true,allowUnionTypes:true});
ajv.addFormat('int64',{type:'number',validate:value=>Number.isInteger(value)&&Math.abs(value)<=2**63});
ajv.addKeyword({keyword:'x-max-utf8-bytes',type:'string',schemaType:'number',validate:(limit,value)=>Buffer.byteLength(value,'utf8')<=limit});
const compile=schema=>ajv.compile(JSON.parse(JSON.stringify({$defs:spec.components.schemas,...schema}).replaceAll('#/components/schemas/','#/$defs/')));
const operations=new Map();
for(const [path,methods]of Object.entries(spec.paths))for(const [method,op]of Object.entries(methods)){
 assert.ok(!operations.has(op.operationId),'Duplicate operation ID');
 const requestSchema=op.requestBody?.content?.['application/json']?.schema;
 const responses=new Map();for(const [status,rawResponse]of Object.entries(op.responses)){const response=rawResponse.$ref?spec.components.responses[rawResponse.$ref.split('/').pop()]:rawResponse;for(const [type,media]of Object.entries(response.content??{}))responses.set(status+':'+type,compile(media.schema));}
 operations.set(op.operationId,{...op,path,method,validateRequest:requestSchema&&compile(requestSchema),validators:responses});
}
const bindings=JSON.parse(fs.readFileSync(new URL('../wrangler.jsonc',import.meta.url))).vars;
const mf=new Miniflare(convertV4MiniflareOptions({workers:[{name:'contract-api',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',bindings,durableObjects:{LEDGER:{className:'TaskLedger',useSQLite:true}},queueProducers:{READY:'contract-ready'},queueConsumers:{'contract-ready':{maxBatchSize:1,maxBatchTimeout:0,maxRetries:1}},outboundService:'deny-egress'},{name:'contract-disabled',modules:[{type:'ESModule',path:'build/index.js'},{type:'CompiledWasm',path:'build/index_bg.wasm'}],compatibilityDate:'2026-10-27',bindings:{...bindings,LOCAL_FIXTURES:'false'},outboundService:'deny-egress'},{name:'deny-egress',modules:true,compatibilityDate:'2026-10-27',script:'export default {fetch(){return new Response(null,{status:403})}}'}]}));
const covered=new Set();let calls=0;
const dispatch=(...args)=>{assert.ok(++calls<=200,'Finite contract HTTP call budget');return mf.dispatchFetch(...args);};
async function probe(id,{path,body,status=200,token='local-alpha',key,invalid=false,raw,contentType='application/json'}={}){
 const op=operations.get(id);assert.ok(op,id);path??=op.path;
 if(!invalid){if(op.validateRequest)assert.ok(op.validateRequest(body),`Request schema: ${id} ${ajv.errorsText(op.validateRequest.errors)}`);for(const p of op.parameters??[])if(p.in==='header'&&p.name==='Idempotency-Key')assert.ok(compile(p.schema)(key),'Idempotency header schema');}
 const response=await dispatch('http://127.0.0.1:8787'+path,{method:op.method.toUpperCase(),headers:{...(token?{Authorization:'Bearer '+token}:{}),...(key===undefined?{}:{'Idempotency-Key':key}),...(body===undefined&&raw===undefined?{}:{'Content-Type':contentType})},body:raw??(body===undefined?undefined:JSON.stringify(body))});
 assert.equal(response.status,status,`${id} expected status; response contents omitted`);const declared=op.responses[String(status)];assert.ok(declared,`Undocumented status ${id} ${status}`);
 const type=response.headers.get('Content-Type')?.split(';')[0];const validate=op.validators.get(String(status)+':'+type);assert.ok(validate,`Undocumented media type ${id} ${status} ${type}`);
 const text=await response.text(),value=type==='application/json'?JSON.parse(text):text;
 assert.ok(validate(value),`Response schema ${id} ${status}: ${ajv.errorsText(validate.errors)}`);
 if(status===429){assert.match(response.headers.get('Retry-After')??'',/^\d+$/);assert.ok(Number(response.headers.get('Retry-After'))>=1);}
 covered.add(id);return value;
}
const client=new LocalRunLater({fetchImpl:dispatch});
try{
 await probe('getRuntimeHealth',{token:''});
 // Audit every shared POST/PUT media/envelope exit, including keys and maintenance.
 for(const [id,op]of operations){
  if(!['post','put'].includes(op.method))continue;
  const path=op.path.replace('{id}','task_0000000000000001').replace('{key_id}','contract_probe');
  await probe(id,{path,raw:'{}',contentType:'text/plain',status:415,invalid:true});
  await probe(id,{path,raw:'x'.repeat(25000),status:413,invalid:true});
 }
 // GET bodies are legal incoming HTTP but forbidden by fetch clients. Use bounded
 // raw loopback HTTP to exercise the same envelope reader, without changing method.
 const local=new URL(await mf.ready);assert.equal(local.hostname,'127.0.0.1');
 async function rawGet(id,status,body,contentType='application/json'){
  const op=operations.get(id),path=op.path.replace('{id}','task_0000000000000001');
  assert.ok(++calls<=200,'Finite contract HTTP call budget');
  const result=await new Promise((resolve,reject)=>{
   const req=httpRequest(new URL(path,local),{method:'GET',headers:{Authorization:'Bearer local-alpha','Content-Type':contentType,'Content-Length':Buffer.byteLength(body)}},response=>{
    let text='';response.on('data',chunk=>{text+=chunk;if(Buffer.byteLength(text)>262144)req.destroy(new Error('Bounded middleware response exceeded'));});response.on('end',()=>resolve({status:response.statusCode,type:response.headers['content-type']?.split(';')[0],text}));response.on('error',reject);
   });req.on('error',reject);req.setTimeout(5000,()=>req.destroy(new Error('Local middleware timeout')));req.end(body);
  });
  assert.equal(result.status,status,`Raw GET envelope ${id}`);const validate=op.validators.get(status+':'+result.type);assert.ok(validate,`Undocumented raw GET status/media ${id}`);assert.ok(validate(result.type==='application/json'?JSON.parse(result.text):result.text),`Raw GET schema ${id}`);
 }
 for(const [id,op]of operations){if(op.method!=='get'||id==='getRuntimeHealth')continue;await rawGet(id,400,'not-json');await rawGet(id,413,'x'.repeat(25000));}
 await rawGet('getDefaultQueueLimits',200,'{}','text/plain'); // GET has no 415 media gate.
 // Disabled prototype gate precedes auth/body/media on every tenant operation.
 const disabled=await mf.getWorker('contract-disabled');
 for(const [id,op]of operations){
  if(id==='getRuntimeHealth')continue;
  assert.ok(++calls<=200,'Finite contract HTTP call budget');
  const path=op.path.replace('{id}','task_0000000000000001').replace('{key_id}','contract_probe');
  const response=await disabled.fetch('http://127.0.0.1:8787'+path,{method:op.method.toUpperCase()});
  assert.equal(response.status,503,`Prototype gate ${id}`);
  const type=response.headers.get('Content-Type')?.split(';')[0],validate=op.validators.get('503:'+type);
  assert.ok(validate,`Undocumented prototype media ${id}`);assert.ok(validate(await response.text()),`Prototype body schema ${id}`);
 }

 const input={destination:'fixture://success',body:'contract fixture',operation_key:'contract_operation',run_at_ms:Date.now()+60000};
 const t=await probe('createTask',{body:input,key:'enqueue',status:201});
 assert.equal((await probe('createTask',{body:input,key:'enqueue'})).id,t.id);
 await probe('createTask',{body:{...input,body:'changed'},key:'enqueue',status:409});
 await probe('createTask',{body:{...input,destination:'https://never-call.invalid'},key:'disabled',status:422,invalid:true});
 await probe('createTask',{body:{...input,extra:true},key:'bad',status:400,invalid:true});
 await probe('createTask',{body:input,status:400,invalid:true});
 await probe('createTask',{body:input,key:'unauthorized',token:'',status:401});
 await probe('createTask',{raw:'{}',contentType:'text/plain',status:415,invalid:true});
 await probe('createTask',{raw:'x'.repeat(25000),status:413,invalid:true});
 await probe('createTask',{body:{...input,body:'é'.repeat(8193)},key:'utf8',status:400,invalid:true});
 assert.equal(compile(spec.components.schemas.Create)({...input,body:'é'.repeat(8193)}),false,'Schema must enforce UTF-8 byte bound');
 for(const id of ['getTask','getAttempts','inspectTask'])await probe(id,{path:operations.get(id).path.replace('{id}',t.id)});
 await probe('listTasks');await probe('getTask',{path:'/v1/tasks/'+t.id,token:'local-beta',status:404});
 await probe('cancelTask',{path:`/v1/tasks/${t.id}/cancel`});
 const limits=await probe('getDefaultQueueLimits');await probe('configureDefaultQueueLimits',{body:limits});
 await probe('configureDefaultQueueLimits',{body:{...limits,max_concurrent:0},status:400,invalid:true});
 await probe('getQueueHealth');await probe('getQueueAudit');await probe('maintainRetention',{body:{}});
 await probe('maintainRetention',{body:{now_ms:9999999999999},status:400,invalid:true});
 const tokenFor=id=>`rl_local.alpha.${id}.public_contract_fixture_secret`;
 const keySpec=id=>({key_id:id,token_sha256:createHash('sha256').update(tokenFor(id)).digest('hex'),permissions:['enqueue','enqueue'],expires_at_ms:Date.now()+3600000});
 const writer=keySpec('contract_writer');await probe('issueLocalProjectKey',{body:writer,status:201});
 const receipt=await probe('createTask',{body:input,key:'scoped',token:tokenFor(writer.key_id),status:201});assert.ok(!('input'in receipt));
 await probe('getQueueHealth',{token:tokenFor(writer.key_id),status:403});
 await probe('listProjectKeys');await probe('getKeyAudit');
 const rotate={new_key:{...keySpec('contract_rotated'),permissions:['read']},revoke_old_at_ms:Date.now()+60000};
 await probe('rotateLocalProjectKey',{path:`/v1/keys/${writer.key_id}/rotate`,body:rotate,status:201});await probe('rotateLocalProjectKey',{path:`/v1/keys/${writer.key_id}/rotate`,body:rotate});
 await probe('revokeProjectKey',{path:`/v1/keys/${writer.key_id}/revoke`});await probe('createTask',{body:input,key:'revoked',token:tokenFor(writer.key_id),status:401});
 const f=await probe('createTask',{body:{...input,destination:'fixture://fail',run_at_ms:0},key:'fail',status:201});
 let failed;for(let i=0;i<40;i++){failed=await probe('getTask',{path:`/v1/tasks/${f.id}`});if(failed.status==='failed')break;await new Promise(r=>setTimeout(r,100));}assert.equal(failed.status,'failed');
 const redriven=await probe('redriveTask',{path:`/v1/tasks/${f.id}/redrive`,key:'redrive',status:201});assert.equal(redriven.input.operation_key,input.operation_key);assert.equal((await probe('redriveTask',{path:`/v1/tasks/${f.id}/redrive`,key:'redrive'})).id,redriven.id);
 await probe('configureDefaultQueueLimits',{body:{...limits,max_active_tasks:1}});
 const rejected=await probe('createTask',{body:input,key:'limited',status:429});assert.equal(rejected.reason,'active_tasks');
 await assert.rejects(client.enqueue(input,'client_limited'),e=>e instanceof RunLaterError&&e.status===429&&e.retryAfterSeconds>=1&&!e.message.includes(input.body));
 await probe('configureDefaultQueueLimits',{body:limits});
 const sample=await client.enqueue(input,'client_example');assert.equal((await client.enqueue(input,'client_example')).data.id,sample.data.id);await client.cancel(sample.data.id);await client.configure(limits);await client.redrive(f.id,'client_redrive');
 assert.equal((await client.task(t.id)).data.status,'cancelled');assert.equal((await client.inspection(t.id)).data.id,t.id);await client.attempts(t.id);await client.list();await client.health();await client.audit();await client.limits();await client.maintain();
 assert.deepEqual([...covered].sort(),[...operations.keys()].sort(),'Every documented operation must execute');
 console.log(`PASS: ${covered.size} OpenAPI operations, full/scoped receipts, DTO/media/error/idempotency/auth/retention/rate parity and local client; ${calls} bounded HTTP calls`);
}finally{await mf.dispose();}
