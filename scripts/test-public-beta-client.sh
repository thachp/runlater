#!/bin/sh
set -eu
restore_default(){ ./scripts/build.sh; node scripts/assert-no-runtime-hooks.mjs; }
trap restore_default EXIT
./scripts/build-production.sh
node scripts/assert-no-destination-hooks.mjs
node scripts/public-beta-client-local.mjs
