import {execFileSync, spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
const rustc = execFileSync('rustup', ['which', 'rustc', '--toolchain', '1.92.0'], {encoding: 'utf8'}).trim();
for (const feature of ['production', 'staging', 'runtime-tests', 'funding-tests']) {
  const r = spawnSync('rustup', ['run', '1.92.0', 'cargo', 'check', '--locked', '--target', 'wasm32-unknown-unknown', '--features', `destination-tests,${feature}`], {encoding: 'utf8', env: {...process.env, RUSTC: rustc}});
  assert.notEqual(r.status, 0, `Fixture compiled with ${feature}`);
  assert.ok(r.stderr.includes('destination-tests must be built in isolation'), r.stderr);
}
console.log('PASS: destination fixture cannot compile with production, staging, runtime-tests or funding-tests');
