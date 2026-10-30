#!/bin/sh
set -eu
restore_default() {
  ./scripts/build.sh
  node scripts/assert-no-runtime-hooks.mjs
  node -e 'const fs=require("node:fs"),assert=require("node:assert/strict");assert.equal(fs.readFileSync("build/index_bg.wasm").includes(Buffer.from("TEST_FUNDING_CONTROL")),false);'
}
trap restore_default EXIT
TASK_RUST_BIN="$(dirname "$(rustup which rustc --toolchain 1.92.0)")"
export PATH="$TASK_RUST_BIN:$HOME/.cargo/bin:$PATH"
export RUSTC="$(rustup which rustc --toolchain 1.92.0)"
node - <<'JS'
const {spawnSync}=require('node:child_process'),assert=require('node:assert/strict');for(const other of ['production','staging','runtime-tests']){const r=spawnSync('cargo',['check','--locked','--features','funding-tests,'+other],{encoding:'utf8'});assert.notEqual(r.status,0);assert.match(r.stderr,/must never be combined/);}console.log('PASS: funding fixtures cannot combine with production/staging/runtime-test builds');
JS
./scripts/build-funding-tests.sh
node scripts/funding-integration.mjs
./scripts/build-production.sh
node scripts/production-funding-gate.mjs
node scripts/production-identity.mjs
node scripts/signed-requests.mjs
