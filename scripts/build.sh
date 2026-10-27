#!/bin/sh
set -eu
TASK_RUST_BIN="$(dirname "$(rustup which rustc --toolchain stable)")"
export PATH="$TASK_RUST_BIN:$HOME/.cargo/bin:$PATH"
export RUSTC="$(rustup which rustc --toolchain stable)"
exec rustup run stable worker-build --release
