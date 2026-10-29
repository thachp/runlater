// Real local subprocess SIGKILL tests plus separately labelled injected exceptions.
// No live Cloudflare, callback network, credentials, or existing local stores.
import {spawn} from 'node:child_process';import {EventEmitter} from 'node:events';
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import assert from 'node:assert/strict';import {fileURLToPath} from 'node:url';
const repo=fileURLToPath(new URL('../',import.meta.url)),root=fs.mkdtempSync(path.join(os.tmpdir(),'runlater-runtime-recovery-'));
fs.writeFileSync(path.join(root,'.owner'),'runlater-runtime-recovery-test');
const children=new Set();let started=0,calls=0,cleaning;
function recordChildren(){fs.writeFileSync(path.join(root,'children.json'),JSON.stringify([...children].map(child=>({pid:child.pid,process_group:child.pid,spawned_at_ms:child.spawnedAtMs}))));}
async function cleanup(){
 if(cleaning)return cleaning;
 cleaning=(async()=>{
  const owned=[...children];
  for(const child of owned)if(child.pid>0){try{process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}}
  await Promise.race([Promise.all(owned.filter(child=>children.has(child)).map(child=>new Promise(resolve=>child.once('close',resolve)))),timeout(10000,'Owned subprocess cleanup deadline: '+root)]);
  assert.equal(children.size,0,'Owned subprocess still running: '+root);
  assert.equal(fs.readFileSync(path.join(root,'.owner'),'utf8'),'runlater-runtime-recovery-test');fs.rmSync(root,{recursive:true});
 })();return cleaning;
}
for(const [signal,code]of [['SIGINT',130],['SIGTERM',143]])process.once(signal,()=>{void cleanup().then(()=>process.exit(code),()=>{console.error('Owned local test cleanup failed: '+root);process.exit(1);});});
const timeout=(ms,message)=>new Promise((_,reject)=>{const t=setTimeout(()=>reject(Error(message)),ms);t.unref();});
async function start(scenario,{holds=[],fail=()=>false,mode='enabled'}={}){
 assert.ok(!cleaning,'Local harness is stopping');
 assert.ok(++started<=14,'Subprocess budget');
 const child=spawn(process.execPath,['scripts/runtime-recovery-child.mjs',path.join(root,scenario),mode],{cwd:repo,detached:true,stdio:['ignore','pipe','pipe','ipc']});child.spawnedAtMs=Date.now();children.add(child);recordChildren();
 const bus=new EventEmitter(),events=[],held=new Map(),hold=new Set(holds);let log='',rpcId=0;
 for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{log=(log+chunk).slice(-16000);});
 child.on('error',()=>{events.push({kind:'spawn_error'});bus.emit('update');});
 child.on('close',(code,signal)=>{children.delete(child);recordChildren();events.push({kind:'closed',code,signal});bus.emit('update');});
 child.on('message',m=>{
  events.push(m);bus.emit('update');
  if(m.kind==='point'){
   if(fail(m,events)){child.send({kind:'point-result',id:m.id,action:'fail'});}
   else if(hold.has(m.point)){held.set(m.id,m);}
   else child.send({kind:'point-result',id:m.id,action:'continue'});
  }
 });
 async function wait(predicate,ms=12000){const get=()=>events.find(predicate);if(get())return get();return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{bus.off('update',check);reject(Error('Local runtime boundary deadline; '+log));},ms);function check(){const value=get();if(value){clearTimeout(timer);bus.off('update',check);resolve(value);}else if(!children.has(child)){clearTimeout(timer);bus.off('update',check);reject(Error('Local runtime exited early; '+log));}}bus.on('update',check);});}
 const ready=await wait(m=>m.kind==='ready');const url=new URL(ready.url);assert.equal(url.hostname,'127.0.0.1');
 const instance={child,events,wait,
  async api(route,{method='GET',body,key,expected=200}={}){assert.ok(++calls<=240,'HTTP budget');const r=await fetch(new URL(route,url),{method,headers:{Authorization:'Bearer local-alpha','Content-Type':'application/json',...(key?{'Idempotency-Key':key}:{})},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(8000)});assert.equal(r.status,expected,'Local API status (body omitted)');const text=await r.text();return r.headers.get('Content-Type')?.startsWith('application/json')?JSON.parse(text):text;},
  point(name,n=1){return wait(m=>m.kind==='point'&&m.point===name&&events.filter(e=>e.kind==='point'&&e.point===name).indexOf(m)===n-1,45000);},
  release(name){hold.delete(name);for(const [id,m]of held)if(m.point===name){held.delete(id);child.send({kind:'point-result',id,action:'continue'});}},
  async rpc(kind,data){const id=++rpcId;child.send({kind,id,...data});const r=await wait(m=>m.kind==='reply'&&m.id===id);assert.ok(!r.error,r.error);return r.result;},
  async kill(){assert.ok(children.has(child)&&child.pid>0);process.kill(-child.pid,'SIGKILL');await wait(m=>m.kind==='closed');},
  async stop(){if(children.has(child)){child.send({kind:'stop'});await wait(m=>m.kind==='closed');}},
 };
 return instance;
}
const input={destination:'fixture://success',body:'local recovery fixture',operation_key:'stable_recovery_operation'};
async function settle(instance,id){for(let i=0;i<80;i++){const t=await instance.api('/v1/tasks/'+id);if(t.status==='succeeded')return t;await new Promise(r=>setTimeout(r,100));}throw Error('Local task did not recover');}
async function replayIgnored(instance,reference){
 const before=(await instance.api('/v1/queue/metrics')).totals.counts.claim_ignored;
 assert.equal((await instance.rpc('publish',{reference,copies:3})).published,3);
 for(let i=0;i<80;i++){const after=(await instance.api('/v1/queue/metrics')).totals.counts.claim_ignored;if(after>=before+3)return;await new Promise(r=>setTimeout(r,100));}
 throw Error('Replayed references did not reach the authoritative claim guard');
}
try{
 // 1. Actual process-group death after SQLite commit; no completed enqueue response.
 let a=await start('accept',{holds:['accepted_commit','before_publish']});
 assert.equal((await a.rpc('guard',{})).status,403,'Test artifact rejects non-loopback ingress');
 const pending=a.api('/v1/tasks',{method:'POST',body:input,key:'accept',expected:201}).catch(()=>null);
 const accepted=await a.point('accepted_commit');assert.equal(a.events.filter(e=>e.point==='after_publish').length,0);assert.equal(a.events.filter(e=>e.point==='callback_complete').length,0);
 await a.kill();await pending;
 a=await start('accept');const recovered=await settle(a,accepted.metadata.id);
 assert.equal(recovered.attempts.length,1);assert.equal((await a.api('/v1/tasks',{method:'POST',body:input,key:'accept'})).id,recovered.id);await a.stop();
 console.log('PASS actual SIGKILL: durable acceptance survives restart before publish; unknown response replays same task');
 // 2. Exception AFTER successful local Queue send + explicit duplicate Queue references.
 let failedPublish=false;
 const b=await start('publish',{holds:['before_claim'],fail:m=>m.point==='after_publish'&&!failedPublish&&(failedPublish=true)});
 const created=await b.api('/v1/tasks',{method:'POST',body:input,key:'publish',expected:201});
 const sent=await b.point('after_publish');await b.rpc('publish',{reference:sent.metadata,copies:3});
 b.release('before_claim');const delivered=await settle(b,created.id);await new Promise(r=>setTimeout(r,400));
 assert.equal(delivered.attempts.length,1);assert.equal(b.events.filter(e=>e.point==='callback_complete').length,1);assert.ok(b.events.filter(e=>e.point==='before_claim').length>=2);await b.stop();
 console.log('PASS injected post-send exception + real duplicate Queue references: one leased fixture attempt');
 // Actual process death AFTER durable claim, BEFORE the fixture is invoked.
 let claimedRuntime=await start('claim',{holds:['after_claim']});
 const claimTask=await claimedRuntime.api('/v1/tasks',{method:'POST',body:input,key:'claim',expected:201});
 const claimPoint=await claimedRuntime.point('after_claim');assert.equal(claimPoint.metadata.id,claimTask.id);
 const leased=await claimedRuntime.api('/v1/tasks/'+claimTask.id);assert.equal(leased.status,'running');assert.equal(leased.attempts.length,1);assert.equal(leased.attempts[0].outcome,null);assert.equal(leased.fence,claimPoint.metadata.fence);
 assert.equal(claimedRuntime.events.filter(e=>e.point==='callback_complete').length,0);
 await claimedRuntime.kill();claimedRuntime=await start('claim',{holds:['after_claim']});
 assert.deepEqual(await claimedRuntime.api('/v1/tasks/'+claimTask.id),leased,'Claim survives same-store restart unchanged before lease expiry');
 const reclaimed=await claimedRuntime.point('after_claim');assert.ok(Date.now()>=leased.lease_until);assert.ok(reclaimed.metadata.fence>claimPoint.metadata.fence);assert.ok(reclaimed.metadata.generation>claimPoint.metadata.generation);
 const recoveredClaim=await claimedRuntime.api('/v1/tasks/'+claimTask.id);assert.equal(recoveredClaim.attempts.length,2);assert.equal(recoveredClaim.attempts[0].outcome,'lease_expired_unknown');assert.equal(recoveredClaim.attempts[1].outcome,null);assert.ok(recoveredClaim.attempts[1].started_ms>=leased.lease_until,'Persisted retry must not start before the old lease deadline');assert.equal(recoveredClaim.input.operation_key,input.operation_key);
 assert.equal((await claimedRuntime.rpc('finish',{value:{id:claimTask.id,fence:claimPoint.metadata.fence,status:204}})).status,409);
 assert.equal(claimedRuntime.events.filter(e=>e.point==='callback_complete').length,0);
 claimedRuntime.release('after_claim');const claimFinal=await settle(claimedRuntime,claimTask.id);assert.equal(claimFinal.attempts.length,2);assert.equal(claimFinal.attempts[1].outcome,'http_204');assert.equal(claimedRuntime.events.filter(e=>e.point==='callback_complete').length,1);await claimedRuntime.stop();
 console.log('PASS actual SIGKILL after claim/before fixture: durable unknown attempt, real lease recovery, old fence rejected, one fixture invocation');
 // Cancel durably while the pre-fixture boundary is held, then kill before it can run.
 let cancelledRuntime=await start('claim-cancel',{holds:['after_claim']});
 const cancelTask=await cancelledRuntime.api('/v1/tasks',{method:'POST',body:input,key:'claim-cancel',expected:201});
 const cancelClaim=await cancelledRuntime.point('after_claim');const cancelSent=await cancelledRuntime.point('after_publish');
 await cancelledRuntime.api('/v1/tasks/'+cancelTask.id+'/cancel',{method:'POST'});
 const cancelling=await cancelledRuntime.api('/v1/tasks/'+cancelTask.id);assert.equal(cancelling.status,'running');assert.equal(cancelling.cancel_requested,true);
 assert.equal(cancelledRuntime.events.filter(e=>e.point==='callback_complete').length,0);
 await cancelledRuntime.kill();cancelledRuntime=await start('claim-cancel');
 let cancelled;
 for(let i=0;i<80;i++){cancelled=await cancelledRuntime.api('/v1/tasks/'+cancelTask.id);if(cancelled.status==='cancelled')break;assert.equal(cancelled.cancel_requested,true);await new Promise(r=>setTimeout(r,500));}
 assert.equal(cancelled.status,'cancelled');assert.ok(Date.now()>=cancelling.lease_until);assert.equal(cancelled.attempts.length,1);assert.equal(cancelled.attempts[0].outcome,'lease_expired_unknown');assert.ok(cancelled.attempts[0].finished_ms>=cancelling.lease_until,'Persisted cancellation settlement must not precede lease expiry');assert.equal(cancelled.lease_until,null);
 assert.equal((await cancelledRuntime.rpc('finish',{value:{id:cancelTask.id,fence:cancelClaim.metadata.fence,status:204}})).status,409);
 await replayIgnored(cancelledRuntime,cancelSent.metadata);
 assert.deepEqual(await cancelledRuntime.api('/v1/tasks/'+cancelTask.id),cancelled);assert.equal(cancelledRuntime.events.filter(e=>e.point==='after_claim').length,0);assert.equal(cancelledRuntime.events.filter(e=>e.point==='callback_complete').length,0);await cancelledRuntime.stop();
 console.log('PASS actual SIGKILL after persisted cancellation/before fixture: lease settles cancelled; replay never claims or invokes fixture');
 // 3. Actual process death AFTER fixture completion, BEFORE authoritative finish.
 let c=await start('callback',{holds:['callback_complete']});const first=await c.api('/v1/tasks',{method:'POST',body:input,key:'callback',expected:201});
 const effect=await c.point('callback_complete');assert.equal(effect.metadata.status,204);const running=await c.api('/v1/tasks/'+first.id);assert.equal(running.status,'running');assert.equal(running.attempts[0].outcome,null);
 await c.kill();c=await start('callback',{holds:['callback_complete']});
 const replay=await c.point('callback_complete');assert.ok(Date.now()>=running.lease_until,'Real wall-clock lease deadline must pass');assert.ok(replay.metadata.fence>effect.metadata.fence);
 const stale=await c.rpc('finish',{value:{id:first.id,fence:effect.metadata.fence,status:204}});assert.equal(stale.status,409);
 c.release('callback_complete');const final=await settle(c,first.id);assert.equal(final.attempts.length,2);assert.equal(final.attempts[0].outcome,'lease_expired_unknown');assert.equal(final.input.operation_key,input.operation_key);await c.stop();
 console.log('PASS actual SIGKILL + real lease deadline: fixture may repeat, old result fenced, business identity preserved');
 // 4. Actual process death AFTER durable finish, BEFORE Queue acknowledgement.
 let ack=await start('ack',{holds:['after_finish']});
 const ackTask=await ack.api('/v1/tasks',{method:'POST',body:input,key:'ack',expected:201});
 const committed=await ack.point('after_finish');assert.equal(committed.metadata.id,ackTask.id);assert.equal(committed.metadata.status,200);
 const sentAck=await ack.point('after_publish');
 const beforeKill=await ack.api('/v1/tasks/'+ackTask.id);assert.equal(beforeKill.status,'succeeded');assert.equal(beforeKill.attempts.length,1);assert.equal(beforeKill.attempts[0].outcome,'http_204');
 await ack.kill();ack=await start('ack');
 // Explicitly replay even if the emulator does not retain its in-flight Queue message.
 await replayIgnored(ack,sentAck.metadata);
 assert.deepEqual(await ack.api('/v1/tasks/'+ackTask.id),beforeKill,'Committed task/attempt survives process death and duplicate replay unchanged');
 assert.equal(ack.events.filter(e=>e.point==='callback_complete').length,0,'Terminal replay must not invoke the fixture');
 assert.equal((await ack.api('/v1/tasks',{method:'POST',body:input,key:'ack'})).id,ackTask.id);await ack.stop();
 console.log('PASS actual SIGKILL after finish/before ack: committed success survives restart; at least three replay deliveries ignored without another fixture call');
 // 5. Exception before final pump re-arm, while the earlier durable watchdog exists.
 let failedRearm=false;
 const d=await start('rearm',{holds:['before_claim'],fail:m=>m.point==='before_rearm'&&m.metadata.preserve_earlier===false&&!failedRearm&&(failedRearm=true)});
 const waiting=await d.api('/v1/tasks',{method:'POST',body:input,key:'rearm',expected:201});await d.point('after_publish',2);assert.ok(failedRearm);
 d.release('before_claim');assert.equal((await settle(d,waiting.id)).attempts.length,1);await d.stop();
 console.log('PASS injected final pump re-arm exception: alarm republishes, retained work completes');
 for(const mode of ['disabled','unbound']){const guard=await start('guard-'+mode,{mode});await guard.api('/health',{expected:403});await guard.api('/v1/tasks',{method:'POST',body:'bad-json',expected:403});assert.equal(guard.events.filter(e=>e.kind==='point').length,0);await guard.stop();}
 console.log('PASS test artifact guards: wrong host, disabled mode and missing private binding reject before body/DO work');
 console.log(JSON.stringify({scenarios:8,actual_process_group_kills:5,subprocesses:started,http_calls:calls,live_resources:0,external_callbacks:0}));
}finally{await cleanup();}
