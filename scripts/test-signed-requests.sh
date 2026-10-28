#!/bin/sh
set -eu
restore_default() {
  ./scripts/build.sh
  node scripts/assert-no-runtime-hooks.mjs
  node -e 'const fs=require("node:fs"),assert=require("node:assert/strict");for(const marker of ["operator_alpha_enrollment","RunLater signed request v1"]){assert.equal(fs.readFileSync("build/index_bg.wasm").includes(Buffer.from(marker)),false,"Default artifact retains production request runtime");}'
}
trap restore_default EXIT
./scripts/build-production.sh
node scripts/production-identity.mjs
node scripts/signed-requests.mjs
