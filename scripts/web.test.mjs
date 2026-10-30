import {spawnSync} from 'node:child_process';
import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import Ajv2020 from 'ajv/dist/2020.js';import {buildDiscovery,readJson} from './discovery.mjs';
const ajv=new Ajv2020({strict:true,allErrors:true});ajv.addKeyword({keyword:'x-max-utf8-bytes',type:'string',schemaType:'number',validate:(n,s)=>Buffer.byteLength(s)<=n});
test('published hosted contract and operation body schemas match restricted alpha boundaries',()=>{const a=readJson('discovery/alpha.v1.json'),validate=ajv.compile(readJson('discovery/alpha.v1.schema.json'));assert.ok(validate(a),ajv.errorsText(validate.errors));const create=ajv.compile(a.definitions.Create);assert.ok(create({destination:'registered:receiver_a',body:'{"synthetic":true}',operation_key:'stable',run_at_ms:0}));assert.equal(create({destination:'https://attacker.example',body:'{}',operation_key:'stable',run_at_ms:0}),false);assert.equal(create({destination:'registered:receiver_a',body:'é'.repeat(600),operation_key:'stable',run_at_ms:0}),false);assert.equal(a.authentication.maximum_signature_ms,60000);assert.deepEqual(a.authority,{automatic_execution:false,payment_authority:false,self_service_registration:false});const routes=new Set(a.routes.map(x=>x.method+' '+x.path));assert.equal(routes.size,8);const local=readJson('docs/openapi.json');assert.deepEqual(Object.keys(a.definitions.Create.properties).sort(),Object.keys(local.components.schemas.Create.properties).sort());assert.ok(a.routes.filter(r=>r.required_permission).every(r=>r.authentication==='signed'));assert.equal(a.routes.find(r=>r.name==='schedule_task').idempotency_key_required,true);assert.equal(a.routes.find(r=>r.name==='cancel_task').idempotency_key_required,false);});
test('public assets include defensive headers,404s,shared resources and no deployment config or credentials',()=>{const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-web-'));try{const {output}=buildDiscovery(path.join(tmp,'out'));for(const role of ['landing','docs']){const root=path.join(output,role),headers=fs.readFileSync(path.join(root,'_headers'),'utf8');assert.match(headers,/default-src 'none'/);assert.match(headers,/connect-src 'none'/);assert.match(headers,/X-Content-Type-Options: nosniff/);assert.match(headers,/frame-ancestors 'none'/);for(const n of ['site.css','site.mjs','icon.svg','404.html','robots.txt'])assert.ok(fs.existsSync(path.join(root,n)));assert.equal(fs.existsSync(path.join(root,'wrangler.jsonc')),false);assert.equal(fs.existsSync(path.join(root,'worker.mjs')),false);for(const n of ['index.html','404.html']){const html=fs.readFileSync(path.join(root,n),'utf8');assert.match(html,/<html lang="en">/);assert.match(html,/name="viewport"/);assert.match(html,/Skip to content/);assert.doesNotMatch(html,/<script[^>]*>[^<]+|style="|BEGIN PRIVATE KEY|ALPHA_CALLBACK_KEYS/);for(const m of html.matchAll(/(?:src|href)="(\/[^"#]+)"/g)){const file=m[1].split('#')[0];assert.ok(fs.existsSync(path.join(root,file)),'missing asset '+file);}}}}finally{fs.rmSync(tmp,{recursive:true,force:true});}});
test('static and redirect deploy configurations cannot acquire API secrets or database bindings',()=>{for(const [role,name]of [['landing','runlater-web-landing'],['docs','runlater-web-docs'],['redirect','runlater-web-www']]){const c=JSON.parse(fs.readFileSync('web/'+role+'/wrangler.jsonc'));assert.equal(c.name,name);assert.equal(c.workers_dev,false);assert.equal(c.preview_urls,false);assert.equal(c.observability.enabled,false);for(const forbidden of ['durable_objects','queues','kv_namespaces','d1_databases','services','vars','secrets_store_secrets'])assert.equal(c[forbidden],undefined);if(role==='docs'){assert.equal(c.main,undefined);assert.equal(c.assets.not_found_handling,'404-page');}else if(role==='landing'){assert.equal(c.main,'worker.mjs');assert.equal(c.assets.binding,'ASSETS');assert.equal(c.assets.run_worker_first,true);assert.equal(c.assets.not_found_handling,'404-page');assert.equal(c.limits.cpu_ms,10);}else assert.equal(c.limits.cpu_ms,10);}});
test('published beta descriptor and release metadata agree with actual client receiver policy and bounded terms',async()=>{const d=readJson('discovery/service.v1.json'),release=readJson('discovery/public-beta-release.v1.json'),contract=readJson('contracts/public-beta-v1.json'),{receiverSetup}=await import('../examples/public-beta-client.v1.mjs'),{createHash}=await import('node:crypto');assert.equal(d.descriptor_version,'1.4.0');assert.equal(d.readiness.public_task_api,'public_free_beta');assert.equal(d.capabilities.public_self_service,'available_limited_cohort');assert.equal(d.capabilities.arbitrary_https_delivery,'public_https_post_json_limited_beta');assert.equal(contract.availability,'deployed_public_free_beta');assert.equal(release.api_origin,'https://api.runlater.io');assert.match(release.release_id,/^beta_[a-f0-9]{12}$/);const{signature_window_sec,...key}=release.callback_v2_key_metadata;assert.equal(key.active_from_sec,Math.floor(release.registration_opens_at_ms/1000));assert.equal(key.verify_until_sec-key.sign_until_sec,300);assert.equal(signature_window_sec,300);assert.ok(key.sign_until_sec*1000>=release.registration_closes_at_ms+8*86400000);assert.equal(release.trial.attempt_units,100);assert.equal(release.trial.lifetime_task_limit,16);assert.equal(release.payments_enabled,false);const material=createHash('sha256').update('PUBLIC_OFFLINE_FIXTURE').digest('hex'),project='public_fixture';const result=receiverSetup({receipt:{project_id:project},callbackKey:{version:'v2',project_id:project,policy_id:'public_beta_'+release.release_id,key_id:'beta_v1',key_hex:material,signature_window_sec},callbackPolicy:{version:'v2',tenant:project,policy_id:'public_beta_'+release.release_id,revision:1,keys:{beta_v1:key},rotations:{}},url:'https://owned.fixture.workers.dev/callback'});assert.equal(result.RECEIVER_PROJECT_ID,project);for(const flag of Object.values(d.authority).filter(x=>typeof x==='boolean'))assert.equal(flag,false);});

test('source and hosted quickstarts create private keys exclusively in ignored owner state',()=>{
  for(const file of ['docs/AGENT-QUICKSTART.md','web/docs/index.html']){
    const text=fs.readFileSync(file,'utf8');
    assert.match(text,/chmod 700 private/);
    assert.match(text,/refuses to replace an existing key/);
    const command=text.match(/node --input-type=module -e '([^']+)'/)[1];
    const root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-owner-key-'));
    try{
      fs.mkdirSync(path.join(root,'private'),{mode:0o700});
      const run=()=>spawnSync(process.execPath,['--input-type=module','-e',command],{cwd:root,encoding:'utf8'});
      assert.equal(run().status,0);
      const key=path.join(root,'private/bot.pem'),original=fs.readFileSync(key);
      assert.equal(fs.statSync(key).mode&0o777,0o600);
      assert.notEqual(run().status,0);
      assert.deepEqual(fs.readFileSync(key),original);
    }finally{fs.rmSync(root,{recursive:true,force:true});}
  }
  for(const file of ['bot.pem','receipt.json','receiver-bindings.json','proof.json']){
    const r=spawnSync('git',['check-ignore','--no-index','private/'+file],{encoding:'utf8'});
    assert.equal(r.status,0,file+' must be ignored');
  }
});

test('published client module tree resolves all transitive dependencies from built output',async()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-hosted-client-'));
  try{
    const {output}=buildDiscovery(path.join(root,'out'));
    const module=path.join(output,'docs/agent/public-beta-client.v1.mjs');
    const result=spawnSync(process.execPath,['--input-type=module','-e',`await import(${JSON.stringify('file://'+module)});`],{cwd:root,encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    assert.ok(fs.existsSync(path.join(output,'docs/agent/operation-dedup.mjs')));
  }finally{fs.rmSync(root,{recursive:true,force:true});}
});

test('general HTTPS guide matches MCP schema and keeps Connect primary with bounded activation claims',async()=>{
 const {HTTP_SCHEDULE_TOOL}=await import('../mcp/http-tools.mjs');
 const html=fs.readFileSync('web/docs/index.html','utf8');
 const sample=JSON.parse(html.match(/id="http-code">([\s\S]*?)<\/code>/)[1]);
 const validate=ajv.compile(HTTP_SCHEDULE_TOOL.inputSchema);
 assert.ok(validate(sample),ajv.errorsText(validate.errors));
 assert.deepEqual(Object.keys(sample).sort(),['idempotency_key','operation_key','payload','run_at_ms','url']);
 assert.match(html,/POST \/v1\/http\/tasks/);
 assert.match(html,/Public HTTPS and no-account Connect are enabled/);
 assert.match(html,/Idempotency-Key/);
 assert.match(fs.readFileSync('web/landing/index.html','utf8'),/https:\/\/docs.runlater.io\/#connect/);
 const guide=fs.readFileSync('docs/GENERAL-HTTPS-DESTINATIONS.md','utf8');
 assert.match(guide,/at least once at task level/);
 assert.match(guide,/does not observe or pin the connected peer IP/);
});
