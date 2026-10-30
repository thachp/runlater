// OFFLINE composition: actual OAuth/MCP and SDK transports -> compiled Rust -> private controller
// -> native Node TLS -> ordinary HTTPS fixture. Synthetic public-IP mapping is NOT provider proof.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash, generateKeyPairSync, randomBytes} from 'node:crypto';
import {build} from 'esbuild';
import {createOrdinaryHttpsFixture} from './general-http-fixture.mjs';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {SSEClientTransport} from '@modelcontextprotocol/sdk/client/sse.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import {bundleMcp} from './build-mcp.mjs';
import {delegationPublicKey} from '../mcp/delegation.mjs';
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'runlater-general-http-composition-'));
const apiOrigin = 'https://api.runlater.io', mcpOrigin = 'https://mcp.runlater.io';
const clientId = 'https://client.example.com/metadata', callback = 'https://client.example.com/callback';
const gateway = generateKeyPairSync('ed25519'), gatewayKey = delegationPublicKey(gateway.privateKey);
const releaseId = 'local_general_composition', begin = Date.now() - 1000;
const apiCalls = [], secrets = new Set(), unexpected = []; let mcpCalls = 0, lostProvision = false, lostAdmission = false, api, hosted, ordinary;
const revision = 'c'.repeat(64), outputs = [], nativeEnvelopes = []; let loseNativeOnce = true, safeHostAfter = 0;
function snapshots() {
  const value = spawnSync('python3', ['-c', `import pathlib,sqlite3,json,sys
out=[]
for p in pathlib.Path(sys.argv[1]).rglob('*.sqlite'):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 if c.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='invitation_snapshot'").fetchone()[0]:
  for row in c.execute('SELECT data FROM invitation_snapshot'):out.append(json.loads(row[0])['data'])
print(json.dumps(out,sort_keys=True))`, root], {encoding: 'utf8'});
  assert.equal(value.status, 0, value.stderr); return JSON.parse(value.stdout);
}
const grants = () => Object.values(snapshots().find(value => value.trials)?.trials || {});
async function bridge(request) {
  if (request.url === clientId) return Response.json({client_id: clientId, client_name: 'Offline trial composition', redirect_uris: [callback],
    token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code']});
  const url = new URL(request.url);
  if (url.origin !== apiOrigin || url.search || !(/^\/v1\/mcp\/trials\/(provision|status|validate|revoke)$/.test(url.pathname) || url.pathname === '/v1/beta' || url.pathname === '/v1/http/tasks' || /^\/v1\/tasks(?:\/task_[a-f0-9]{16}(?:\/cancel)?)?$/.test(url.pathname))) {
    unexpected.push('unexpected_egress'); return new Response(null, {status: 403});
  }
  assert.equal(request.headers.has('authorization'), false); assert.ok(apiCalls.length < 400);
  apiCalls.push(url.pathname);
  for (const name of ['RunLater-Trial-Capability', 'RunLater-Trial-Revocation']) if (request.headers.has(name)) secrets.add(request.headers.get(name));
  const headers = new Headers(request.headers); headers.set('CF-Connecting-IP', `192.0.2.${1 + Math.floor(apiCalls.length / 20)}`);
  const response = await api.dispatchFetch(request.url, {method: request.method, headers, body: request.method === 'GET' ? undefined : await request.text(), redirect: 'manual'});
  if (lostAdmission && url.pathname === '/v1/http/tasks' && response.status === 201) {lostAdmission = false; throw new Error('simulated_committed_admission_loss');}
  if (lostProvision && url.pathname.endsWith('/provision')) {lostProvision = false; throw new Error('simulated_committed_response_loss');}
  return response;
}
async function call(route, init = {}) {
  assert.ok(++mcpCalls < 400);
  const headers = new Headers(init.headers); headers.set('CF-Connecting-IP', `198.51.100.${1 + Math.floor(mcpCalls / 20)}`);
  return hosted.dispatchFetch(mcpOrigin + route, {...init, headers, redirect: 'manual'});
}
const tokenRequest = value => call('/oauth/token', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded'}, body: new URLSearchParams(value).toString()});
async function authorize(scope = 'cancel http_schedule read') {
  const verifier = randomBytes(48).toString('base64url'), challenge = createHash('sha256').update(verifier).digest('base64url');
  const query = new URLSearchParams({response_type: 'code', client_id: clientId, redirect_uri: callback, scope,
    state: 'offline', resource: mcpOrigin, code_challenge: challenge, code_challenge_method: 'S256'});
  const before = snapshots(), page = await call('/authorize?' + query); assert.equal(page.status, 200);
  const html = await page.text(); assert.match(html, /Start free agent project/); if (scope.includes('http_schedule')) assert.match(html, /HTTPS|HTTP/);
  const handle = html.match(/name="handle" value="([^"]+)"/)[1];
  const consent = await call('/authorize', {method: 'POST', headers: {'Content-Type': 'application/x-www-form-urlencoded',
    Origin: mcpOrigin, Cookie: page.headers.get('set-cookie').split(';')[0]}, body: new URLSearchParams({handle, decision: 'trial'}).toString()});
  assert.equal(consent.status, 302); assert.deepEqual(snapshots(), before);
  const response = await tokenRequest({grant_type: 'authorization_code', client_id: clientId, redirect_uri: callback,
    code: new URL(consent.headers.get('location')).searchParams.get('code'), code_verifier: verifier, resource: mcpOrigin});
  assert.equal(response.status, 200); const token = await response.json(); assert.ok(token.refresh_token); assert.equal(token.expires_in, 3600);
  assert.deepEqual(snapshots(), before); return token;
}
function sdkFor(kind, token) {
  const client = new Client({name: 'actual-trial-composition', version: '1'});
  const localFetch = (url, init = {}) => {const u = new URL(url); assert.equal(u.origin, mcpOrigin);
    const headers = new Headers(init.headers); headers.set('Authorization', 'Bearer ' + token.access_token);
    return call(u.pathname + u.search, {...init, headers});};
  const transport = kind === 'sse' ? new SSEClientTransport(new URL(mcpOrigin + '/sse'), {fetch: localFetch})
    : new StreamableHTTPClientTransport(new URL(mcpOrigin + '/mcp'), {fetch: localFetch});
  return {client, transport};
}
try {
  ordinary = await createOrdinaryHttpsFixture({revision});
  const controller = (await build({stdin: {resolveDir: process.cwd(), contents: `
    import worker,{EgressBinding,EgressContainer as Base} from './egress/controller/worker.mjs';
    export default worker;export {EgressBinding};
    export class EgressContainer extends Base {
      async send(envelope,{signal}) {
        const response=await this.env.NATIVE_FIXTURE.fetch('https://native-fixture.internal/dispatch',{
          method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(envelope),signal});
        if(response.status!==200)throw Error('private_transport_uncertain');
        return response.json();
      }
    }`}, bundle:true, platform:'neutral', mainFields:['module','main'], format:'esm', external:['cloudflare:*','node:*'], write:false})).outputFiles[0].text;
  const apiOptions = {resourcePersistencePath: root, workers: [{name: 'trial-api',
    modules: [{type: 'ESModule', path: 'build/index.js'}, {type: 'CompiledWasm', path: 'build/index_bg.wasm'}],
    compatibilityDate: '2026-10-27', compatibilityFlags: ['global_fetch_strictly_public'],
    serviceBindings: {GENERAL_HTTPS_EGRESS: {name: 'general-controller', entrypoint: 'EgressBinding'}},
    bindings: {GENERAL_HTTPS_ENABLED: 'operator-approved', GENERAL_HTTPS_EGRESS_REVIEW_REVISION: revision, PUBLIC_BETA_ENABLED: 'operator-approved', MCP_ANONYMOUS_TRIAL_ENABLED: 'operator-approved', MCP_DELEGATION_GATEWAY_PUBLIC_KEY: gatewayKey,
      BETA_CALLBACK_MASTER: randomBytes(32).toString('hex'), BETA_READY_QUEUE: 'runlater-public-ready',
      PUBLIC_BETA_PROFILE: JSON.stringify({release_id: releaseId, opens_at_ms: begin, closes_at_ms: begin + 604800000,
        callback_end_sec: Math.ceil((begin + 15 * 86400000) / 1000) + 301, self_host: 'runlater-public-api.operator.workers.dev'})},
    ratelimits: {BETA_IP_RATE: {namespace_id: '1001', simple: {limit: 60, period: 60}}, BETA_REG_IP_RATE: {namespace_id: '1002', simple: {limit: 6, period: 60}}},
    durableObjects: {ADMISSION: {className: 'AdmissionRegistry', useSQLite: true}, PROJECTS: {className: 'InvitationProject', useSQLite: true}},
    queueProducers: {BETA_READY: 'runlater-public-ready'}, queueConsumers: {'runlater-public-ready': {maxBatchSize: 1, maxBatchTimeout: 0, maxRetries: 1}},
    outboundService: () => {unexpected.push('api_fetch_fallback'); return new Response(null, {status: 403});}},
    {name:'general-controller',modules:true,script:controller,compatibilityDate:'2026-10-29',
      bindings:{EGRESS_ENABLED:'operator-approved',EGRESS_REVIEW_REVISION:revision},
      durableObjects:{EGRESS_CONTAINER:{className:'EgressContainer',useSQLite:true}},
      serviceBindings:{NATIVE_FIXTURE:async request=>{
        assert.equal(request.url,'https://native-fixture.internal/dispatch');assert.ok(nativeEnvelopes.length<30);
        const envelope=await request.json();assert.equal(envelope.adapter_revision,revision);nativeEnvelopes.push(envelope);safeHostAfter=envelope.attempt_started_at_ms+10500;
        const response=await ordinary.nativeRequest('/dispatch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(envelope),signal:request.signal});
        // Simulate a committed ordinary HTTP effect whose private-controller response is lost.
        if(loseNativeOnce&&envelope.request.operationKey==='uncertain_sse'){loseNativeOnce=false;safeHostAfter=envelope.deadline_ms+250;return new Response(null,{status:503});}
        return response;
      }},outboundService:()=>{unexpected.push('controller_fetch_fallback');return new Response(null,{status:403});}}]};
  for(const scenario of ['api_kill','missing_binding','revision_mismatch','public_entrypoint','controller_kill']){
    const worker={...apiOptions.workers[0],bindings:{...apiOptions.workers[0].bindings},serviceBindings:{...apiOptions.workers[0].serviceBindings}};
    const control={...apiOptions.workers[1],bindings:{...apiOptions.workers[1].bindings}};
    if(scenario==='api_kill')worker.bindings.GENERAL_HTTPS_ENABLED='disabled';
    if(scenario==='missing_binding')delete worker.serviceBindings.GENERAL_HTTPS_EGRESS;
    if(scenario==='revision_mismatch')worker.bindings.GENERAL_HTTPS_EGRESS_REVIEW_REVISION='d'.repeat(64);
    if(scenario==='public_entrypoint')worker.serviceBindings.GENERAL_HTTPS_EGRESS={name:'general-controller'};
    if(scenario==='controller_kill')control.bindings.EGRESS_ENABLED='disabled';
    const guard=new Miniflare(convertV4MiniflareOptions({...apiOptions,resourcePersistencePath:path.join(root,'guard-'+scenario),workers:[worker,control]}));
    try{await guard.ready;const before=snapshots();const r=await guard.dispatchFetch(apiOrigin+'/v1/http/tasks',{method:'POST',headers:{'Content-Type':'application/json','CF-Connecting-IP':'192.0.2.90'},body:JSON.stringify({url:ordinary.url('/ok'),payload:{guard:true},run_at_ms:Date.now()+60000,operation_key:'guard'})});
      assert.equal(r.status,503,scenario);assert.deepEqual(await r.json(),{error:{code:'general_https_unavailable'},task_accepted:false});assert.deepEqual(snapshots(),before,scenario+' allocated API state');
      assert.equal(nativeEnvelopes.length,0);assert.equal(ordinary.requests.length,0);
    }finally{await guard.dispose();}
  }
  api = new Miniflare(convertV4MiniflareOptions(apiOptions));
  hosted = new Miniflare(convertV4MiniflareOptions({modules: true, script: await bundleMcp(), compatibilityDate: '2026-10-29',
    compatibilityFlags: ['global_fetch_strictly_public'], durableObjects: {MCP_HUB: {className: 'McpHub', useSQLite: true}},
    ratelimits: {MCP_IP_RATE: {namespace_id: '2101', simple: {limit: 60, period: 60}}, MCP_AUTH_RATE: {namespace_id: '2102', simple: {limit: 6, period: 60}}},
    bindings: {GENERAL_HTTPS_ENABLED:'operator-approved', MCP_ENABLED: 'operator-approved', MCP_OAUTH_ENABLED: 'operator-approved', MCP_ANONYMOUS_TRIAL_ENABLED: 'operator-approved',
      MCP_GATEWAY_PUBLIC_KEY: gatewayKey, MCP_GATEWAY_PRIVATE_KEY: gateway.privateKey.export({format: 'pem', type: 'pkcs8'}), MCP_RELEASE_ID: releaseId}, outboundService: bridge}));
  await Promise.all([api.ready, hosted.ready]);
  // Actual unchanged public controller entrypoint remains closed. Only the named service binding dispatches.
  const publicController = await api.getWorker('general-controller');
  assert.equal((await publicController.fetch('https://egress.internal/ready')).status,404);
  assert.equal((await publicController.fetch('https://egress.internal/dispatch',{method:'POST',body:'{}'})).status,404);
  const tools=async(client,name,args={})=>{const value=await client.callTool({name,arguments:args});outputs.push(JSON.stringify(value));return value.structuredContent;};
  const denied=(client,name,args)=>assert.rejects(()=>tools(client,name,args),error=>error.code===403||/403|insufficient_scope/.test(String(error)));
  const old=await authorize('cancel enqueue read'),oldSdk=sdkFor('mcp',old),oldBefore=snapshots();
  try{await oldSdk.client.connect(oldSdk.transport);await denied(oldSdk.client,'schedule_http_request',{});assert.deepEqual(snapshots(),oldBefore);await tools(oldSdk.client,'revoke_trial',{confirm:true});}
  finally{await oldSdk.client.close();}
  let acceptedTasks=0;
  for (const kind of ['sse', 'mcp']) {
    const token=await authorize(),{client,transport}=sdkFor(kind,token),before=snapshots();
    try{
      await client.connect(transport);assert.ok((await client.listTools()).tools.some(t=>t.name==='schedule_http_request'));
      await client.listResources();await client.readResource({uri:'runlater://service'});await client.readResource({uri:'runlater://setup'});
      await tools(client,'service_status');assert.equal((await tools(client,'trial_status')).state,'unprovisioned');assert.deepEqual(snapshots(),before);
      lostProvision=true;assert.equal((await tools(client,'provision_trial',{accept_finite_trial:true})).provisioning,'unknown');
      const committed=snapshots(),provision=await tools(client,'provision_trial',{accept_finite_trial:true});assert.deepEqual(snapshots(),committed);
      assert.equal(provision.receiver_ready,false,'ordinary HTTPS must not create a registered receiver');
      // Real-time pacing preserves the unchanged global and same-host controller limits.
      await new Promise(resolve=>setTimeout(resolve,Math.max(0,safeHostAfter-Date.now())));
      const input={url:ordinary.url('/ok?PRIVATE_URL_SENTINEL='+kind),payload:{event:'synthetic',private_payload:'PRIVATE_PAYLOAD_SENTINEL'},
        run_at_ms:Date.now()+1500,operation_key:'ordinary_'+kind,idempotency_key:'ordinary_'+kind};
      lostAdmission=true;assert.equal((await tools(client,'schedule_http_request',input)).task_acceptance,'unknown');
      const scheduled=await tools(client,'schedule_http_request',input);assert.equal(scheduled.ok,true);assert.equal(scheduled.replayed,true);
      assert.equal(scheduled.receiver_required,false);assert.equal(scheduled.completion_notification_configured,false);acceptedTasks++;
      const replay=await tools(client,'schedule_http_request',input);assert.equal(replay.task_id,scheduled.task_id);assert.equal(replay.replayed,true);
      const deadline=Date.now()+15000;let delivered;
      do{delivered=await tools(client,'task_status',{task_id:scheduled.task_id});if(delivered.status==='succeeded')break;await new Promise(r=>setTimeout(r,250));}while(Date.now()<deadline);
      assert.equal(delivered.status,'succeeded');assert.equal(delivered.delivery_confirmed,true);assert.match(delivered.delivery_meaning,/not downstream business completion/);
      const observed=ordinary.requests.filter(r=>r.operation===input.operation_key);assert.equal(observed.length,1);assert.deepEqual(JSON.parse(observed[0].body),input.payload);
      const future=await tools(client,'schedule_http_request',{...input,operation_key:'cancel_'+kind,idempotency_key:'cancel_'+kind,run_at_ms:Date.now()+60000});
      assert.equal(future.ok,true);acceptedTasks++;assert.equal((await tools(client,'cancel_task',{task_id:future.task_id})).status,'cancelled');
      if(kind==='sse'){
        await new Promise(resolve=>setTimeout(resolve,Math.max(0,safeHostAfter-Date.now())));
        const uncertain=await tools(client,'schedule_http_request',{...input,operation_key:'uncertain_sse',idempotency_key:'uncertain_sse',run_at_ms:Date.now()+500});assert.equal(uncertain.ok,true);acceptedTasks++;
        let state;const end=Date.now()+15000;
        do{state=await tools(client,'task_status',{task_id:uncertain.task_id});if(state.status==='retry_wait')break;await new Promise(r=>setTimeout(r,100));}while(Date.now()<end);
        assert.equal(state.status,'retry_wait');assert.equal(ordinary.requests.filter(r=>r.operation==='uncertain_sse').length,1);
        assert.equal((await tools(client,'cancel_task',{task_id:uncertain.task_id})).status,'cancelled');
        const receipt=(await api.getDurableObjectNamespace('EGRESS_CONTAINER','general-controller')).getByName('runlater-egress-v1');
        // Replay identical private envelope through the real controller: reserved uncertain receipt never sends again.
        const e=nativeEnvelopes.find(e=>e.request.operationKey==='uncertain_sse');assert.ok(e);
        const count=ordinary.requests.length;const r=await receipt.fetch('https://egress.internal/dispatch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(e)});
        assert.equal(r.status,200);assert.equal((await r.json()).request_may_have_been_sent,true);assert.equal(ordinary.requests.length,count);
        // Same shared lifetime task ledger and five-unit reservation budget; cancellation does not reset task count.
        for(let i=3;i<16;i++){
          const t=await tools(client,'schedule_http_request',{...input,operation_key:'bounded_'+i,idempotency_key:'bounded_'+i,run_at_ms:Date.now()+120000});
          assert.equal(t.ok,true);acceptedTasks++;assert.equal((await tools(client,'cancel_task',{task_id:t.task_id})).status,'cancelled');
        }
        assert.equal((await tools(client,'schedule_http_request',{...input,operation_key:'overflow',idempotency_key:'overflow',run_at_ms:Date.now()+120000})).ok,false);
        const stored=snapshots().find(value=>value.project?.funding?.project_id===provision.project_id)?.project;assert.ok(stored);
        assert.equal(Object.keys(stored.ledger.tasks).length,16);
        const reservations=Object.values(stored.funding.reservations);assert.equal(reservations.length,16);
        assert.ok(reservations.every(r=>r.allocated_units===5));assert.equal(new Set(reservations.map(r=>r.grant_id)).size,1);
        const funding=Object.values(stored.funding.grants);assert.equal(funding.length,1);assert.equal(funding[0].spec.total_attempt_units,100);
      }
      const refreshed=await tokenRequest({grant_type:'refresh_token',client_id:clientId,refresh_token:token.refresh_token,resource:mcpOrigin,scope:'read'});
      assert.equal(refreshed.status,200);const next=await refreshed.json();assert.equal(next.scope,'read');
      assert.equal((await call('/mcp',{headers:{Authorization:'Bearer '+token.access_token}})).status,401);
      const newer=sdkFor(kind,next);
      try{await newer.client.connect(newer.transport);const status=await tools(newer.client,'trial_status');assert.equal(status.project_id,provision.project_id);assert.equal(status.expires_at_ms,provision.expires_at_ms);
        assert.deepEqual(status.permissions,['read']);await denied(newer.client,'schedule_http_request',input);await denied(newer.client,'cancel_task',{task_id:future.task_id});
        assert.equal((await tools(newer.client,'task_status',{task_id:scheduled.task_id})).status,'succeeded');
        assert.equal((await tools(newer.client,'revoke_trial',{confirm:true})).api_revoked,true);
      }finally{await newer.client.close();}
      assert.equal((await call('/mcp',{headers:{Authorization:'Bearer '+next.access_token}})).status,401);
    }finally{await client.close();}
  }
  assert.equal(acceptedTasks,18);assert.equal(grants().length,2);assert.ok(grants().every(g=>g.revoked_at_ms!==null));
  assert.deepEqual(ordinary.failures,[]);assert.deepEqual(unexpected,[]);assert.equal(ordinary.requests.length,3);
  const text=outputs.join('\n');for(const secret of [...secrets,'PRIVATE_URL_SENTINEL','PRIVATE_PAYLOAD_SENTINEL','PRIVATE_RESPONSE_SENTINEL','PRIVATE_HEADER_SENTINEL'])assert.equal(text.includes(secret),false);
  console.log(JSON.stringify({status:'passed',mcp_calls:mcpCalls,api_calls:apiCalls.length,private_attempts:nativeEnvelopes.length,
    sdk_transports:['legacy_SSE','Streamable_HTTP'],zero_implicit_allocation:true,receiver_or_hmac_required:false,
    explicit_http_scope:true,kill_missing_binding_revision_guards:true,immutable_admission_replay:true,read_cancel:true,refresh_downscope:true,revocation:true,
    shared_lifetime_task_limit:true,private_uncertain_receipt_no_resend:true,local_tasks:acceptedTasks,
    ...ordinary.report(),live_resources:0}));
}finally{await hosted?.dispose();await api?.dispose();await ordinary?.close();fs.rmSync(root,{recursive:true,force:true});}
