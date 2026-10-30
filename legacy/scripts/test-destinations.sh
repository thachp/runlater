#!/bin/sh
set -eu
TASK_RUST_BIN="$(dirname "$(rustup which rustc --toolchain 1.92.0)")"
export PATH="$TASK_RUST_BIN:$HOME/.cargo/bin:$PATH"
export RUSTC="$(rustup which rustc --toolchain 1.92.0)"
restore_default(){ ./scripts/build.sh; node scripts/assert-no-runtime-hooks.mjs; node scripts/assert-no-destination-hooks.mjs; }
trap restore_default EXIT
rustup run 1.92.0 worker-build --release --features destination-tests
node scripts/destinations-integration.mjs
node scripts/destination-feature-guard.mjs
