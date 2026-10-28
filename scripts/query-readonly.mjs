// Run against an idle local emulator. Inspects only local fixture DO databases, using read-only SQLite.
import {spawnSync} from 'node:child_process';import assert from 'node:assert/strict';
const base='http://127.0.0.1:8787';const headers={Authorization:'Bearer local-alpha','Content-Type':'application/json'};
const key='readonly-'+Date.now();const created=await fetch(base+'/v1/tasks',{method:'POST',headers:{...headers,'Idempotency-Key':key},body:JSON.stringify({destination:'fixture://success',body:'local-readonly-fixture',operation_key:key,run_at_ms:Date.now()+7*86400000})});assert.equal(created.status,201);const task=await created.json();
await new Promise(r=>setTimeout(r,2200)); // allow the acceptance watchdog to settle to the future due time
function snapshot(){const p=spawnSync('python3',['-c',`
import pathlib,sqlite3,hashlib,json,os
out=[]
ledger_seen=False
root=pathlib.Path(os.environ.get('RUNLATER_STATE_DIR','.wrangler/state'))/'v3'/'do'
for p in sorted(root.rglob('*.sqlite')):
 c=sqlite3.connect(p.absolute().as_uri()+'?mode=ro',uri=True)
 tables=c.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
 rows=[]
 for name,sql in tables:
  if name.startswith('sqlite_'):continue
  if name=='ledger':ledger_seen=True
  rows.append((name,sql,sorted(repr(r) for r in c.execute('SELECT * FROM "'+name.replace('"','""')+'"'))))
 out.append((str(p),rows))
assert ledger_seen,'No fixture ledger found; set RUNLATER_STATE_DIR to the emulator persistence directory'
print(hashlib.sha256(repr(out).encode()).hexdigest())
`],{encoding:'utf8'});assert.equal(p.status,0,p.stderr);return p.stdout.trim()}
const before=snapshot();for(const path of ['/v1/keys','/v1/keys/audit','/v1/queue','/v1/queue/health','/v1/queue/metrics','/v1/queue/audit','/v1/tasks','/v1/tasks/'+task.id,'/v1/tasks/'+task.id+'/attempts','/v1/tasks/'+task.id+'/inspection','/v1/tasks/missing']){const r=await fetch(base+path,{headers});assert.ok([200,404].includes(r.status));await r.text();}
const after=snapshot();assert.equal(after,before,'HTTP queries changed durable SQL schema, ledger or alarm metadata');
await fetch(base+'/v1/tasks/'+task.id+'/cancel',{method:'POST',headers});console.log('PASS: actual HTTP GET list/task/attempts/not-found leave durable SQL schema, ledger and alarm metadata unchanged');
