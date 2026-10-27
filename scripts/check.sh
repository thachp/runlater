#!/bin/sh
set -eu
TASK_RUST_BIN="$(dirname "$(rustup which rustc --toolchain 1.92.0)")"
export PATH="$TASK_RUST_BIN:$HOME/.cargo/bin:$PATH"
export RUSTDOC="$(rustup which rustdoc --toolchain 1.92.0)"
export RUSTC="$(rustup which rustc --toolchain 1.92.0)"
rustup run 1.92.0 cargo fmt -- --check
rustup run 1.92.0 cargo test --locked
rustup run 1.92.0 cargo check --locked --target wasm32-unknown-unknown
node --test web/redirect/worker.test.mjs
