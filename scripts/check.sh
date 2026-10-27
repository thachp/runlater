#!/bin/sh
set -eu
TASK_RUST_BIN="$(dirname "$(rustup which rustc --toolchain stable)")"
export PATH="$TASK_RUST_BIN:$HOME/.cargo/bin:$PATH"
export RUSTDOC="$(rustup which rustdoc --toolchain stable)"
export RUSTC="$(rustup which rustc --toolchain stable)"
rustup run stable cargo fmt -- --check
rustup run stable cargo test --locked
rustup run stable cargo check --locked --target wasm32-unknown-unknown
node --test web/redirect/worker.test.mjs
