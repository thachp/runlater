#!/bin/sh
set -eu
restore_default() {
  ./scripts/build.sh
  node scripts/assert-no-runtime-hooks.mjs
}
trap restore_default EXIT
node scripts/assert-runtime-feature-guard.mjs
./scripts/build-runtime-tests.sh
node scripts/pause-integration.mjs
