#!/bin/sh
set -eu
restore_default() { ./scripts/build.sh; node scripts/assert-no-runtime-hooks.mjs; }
trap restore_default EXIT
./scripts/build-production.sh
node scripts/invitation-production.mjs
