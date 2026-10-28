#[cfg(all(feature = "runtime-tests", feature = "staging"))]
compile_error!("runtime-tests must never be combined with the staging build");
pub mod core;
#[cfg(target_arch = "wasm32")]
mod runtime;
pub mod security;

pub mod application;

pub mod limits;

pub mod auth;

pub mod staging;

pub mod operations;

pub mod callback;
