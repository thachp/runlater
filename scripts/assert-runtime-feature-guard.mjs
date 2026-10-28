import {execFileSync,spawnSync} from 'node:child_process';import assert from 'node:assert/strict';
const rustc=execFileSync('rustup',['which','rustc','--toolchain','1.92.0'],{encoding:'utf8'}).trim();
const result=spawnSync('rustup',['run','1.92.0','cargo','check','--locked','--target','wasm32-unknown-unknown','--features','staging,runtime-tests'],{encoding:'utf8',env:{...process.env,RUSTC:rustc}});
assert.notEqual(result.status,0,'Staging and runtime-test features must not compile together');
assert.ok(result.stderr.includes('runtime-tests must never be combined with the staging build'),result.stderr);
console.log('PASS: staging + runtime-tests combination rejected at compile time');
