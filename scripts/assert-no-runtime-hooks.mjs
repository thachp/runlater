// This is an additive artifact tripwire, not a substitute for cfg/feature review.
import fs from 'node:fs';import assert from 'node:assert/strict';
const wasm=fs.readFileSync(new URL('../build/index_bg.wasm',import.meta.url));
for(const marker of ['TEST_INVITATION_CONTROL','invitation_fixture_loopback_only','Injected invitation fixture interruption','TEST_CONTROL','accepted_commit','before_publish','after_publish','before_claim','after_claim','callback_complete','after_finish','before_rearm','Injected local runtime failure'])assert.equal(wasm.includes(Buffer.from(marker)),false,`Default artifact retains test marker: ${marker}`);
console.log('PASS: normal Wasm artifact has no runtime-fault binding/point markers');
