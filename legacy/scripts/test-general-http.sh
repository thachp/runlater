#!/bin/sh
set -eu
restore_default() { ./scripts/build.sh; node scripts/assert-no-runtime-hooks.mjs; node scripts/assert-no-destination-hooks.mjs; }
trap restore_default EXIT
./scripts/build-production.sh
node scripts/assert-no-runtime-hooks.mjs
node scripts/assert-no-destination-hooks.mjs
node scripts/general-http-integration.mjs

node scripts/general-http-composition.mjs
