import {test} from 'node:test'; import assert from 'node:assert/strict'; import worker from './worker.mjs';
test('canonical redirect preserves encoded path and query over HTTPS',()=>{const r=worker.fetch(new Request('http://www.runlater.io/a%2Fb?q=x%20y&next=2'));assert.equal(r.status,308);assert.equal(r.headers.get('Location'),'https://runlater.io/a%2Fb?q=x%20y&next=2');});
test('unknown host is rejected',()=>assert.equal(worker.fetch(new Request('https://attacker.example/')).status,404));
