import fs from 'node:fs';
import assert from 'node:assert/strict';
const wasm = fs.readFileSync(new URL('../build/index_bg.wasm', import.meta.url));
for (const marker of ['TEST_DESTINATION_CONTROL', 'TEST_APPROVED_HOSTS', 'destination_fixture', 'complete_at_ms', 'DestinationFixture']) {
  assert.equal(wasm.includes(Buffer.from(marker)), false, `Normal artifact retains destination fixture: ${marker}`);
}
console.log('PASS: normal Wasm has no destination fixture routes, binding or clock controls');
