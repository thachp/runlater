#!/bin/sh
set -eu
# Restore a normal artifact even if a local fault test fails.
restore_default() {
  ./scripts/build.sh
  node scripts/assert-no-runtime-hooks.mjs
}
trap restore_default EXIT
node scripts/assert-runtime-feature-guard.mjs
./scripts/build-runtime-tests.sh
node scripts/runtime-recovery.mjs
