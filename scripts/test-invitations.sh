#!/bin/sh
set -eu
restore_default() {
 ./scripts/build.sh
 node scripts/assert-no-runtime-hooks.mjs
 node -e 'const fs=require("node:fs"),assert=require("node:assert/strict");for(const m of ["TEST_INVITATION_CONTROL","invitation_fixture_loopback_only","Injected invitation fixture interruption"])assert.equal(fs.readFileSync("build/index_bg.wasm").includes(Buffer.from(m)),false);'
}
trap restore_default EXIT
TASK_RUST_BIN="$(dirname "$(rustup which rustc --toolchain 1.92.0)")"
export PATH="$TASK_RUST_BIN:$HOME/.cargo/bin:$PATH"
export RUSTC="$(rustup which rustc --toolchain 1.92.0)"
node - <<'JS'
const {spawnSync}=require('node:child_process'),assert=require('node:assert/strict');for(const other of ['production','staging','runtime-tests','funding-tests']){const r=spawnSync('cargo',['check','--locked','--features','invitation-tests,'+other],{encoding:'utf8'});assert.notEqual(r.status,0);assert.match(r.stderr,/invitation-tests must never be combined/);}console.log('PASS invitation feature separation');
JS
./scripts/build-invitation-tests.sh
node scripts/invitation-runtime.mjs
