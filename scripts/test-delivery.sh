#!/bin/sh
set -eu
restore_default(){ ./scripts/build.sh; node scripts/assert-no-runtime-hooks.mjs; }
trap restore_default EXIT
./scripts/build-production.sh
node scripts/assert-no-destination-hooks.mjs
node --test alpha/receiver/worker.test.mjs alpha/config.test.mjs
node scripts/delivery-integration.mjs
node scripts/invitation-delivery.mjs
node scripts/production-identity.mjs
node scripts/signed-requests.mjs
node scripts/production-funding-gate.mjs
