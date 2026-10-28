#!/bin/sh
set -eu
TASK_RUST_BIN="$(dirname "$(rustup which rustc --toolchain 1.92.0)")"
export PATH="$TASK_RUST_BIN:$HOME/.cargo/bin:$PATH"
export RUSTC="$(rustup which rustc --toolchain 1.92.0)"
exec rustup run 1.92.0 worker-build --release --features funding-tests
