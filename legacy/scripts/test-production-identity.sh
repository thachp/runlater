#!/bin/sh
set -eu
restore_default() {
  ./scripts/build.sh
  node scripts/assert-no-runtime-hooks.mjs
  node -e 'const fs=require("node:fs"),assert=require("node:assert/strict");assert.equal(fs.readFileSync("build/index_bg.wasm").includes(Buffer.from("operator_alpha_enrollment")),false,"Default artifact retains production enrollment runtime");'
}
trap restore_default EXIT
TASK_RUST_BIN="$(dirname "$(rustup which rustc --toolchain 1.92.0)")"
export PATH="$TASK_RUST_BIN:$HOME/.cargo/bin:$PATH"
export RUSTC="$(rustup which rustc --toolchain 1.92.0)"
node - <<'JS'
const {spawnSync}=require('node:child_process'),assert=require('node:assert/strict');for(const other of ['staging','runtime-tests']){const r=spawnSync('cargo',['check','--locked','--features','production,'+other],{encoding:'utf8'});assert.notEqual(r.status,0);assert.match(r.stderr,/production must never be combined/);}console.log('PASS: production rejects staging/runtime-test feature combinations');
JS
./scripts/build-production.sh
node scripts/production-identity.mjs
