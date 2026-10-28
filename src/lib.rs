#[cfg(all(
    feature = "production",
    any(feature = "staging", feature = "runtime-tests")
))]
compile_error!("production must never be combined with staging or runtime-tests");
#[cfg(all(feature = "runtime-tests", feature = "staging"))]
compile_error!("runtime-tests must never be combined with the staging build");
pub mod core;
pub mod identity;
#[cfg(all(target_arch = "wasm32", feature = "production"))]
mod production_runtime;
#[cfg(all(target_arch = "wasm32", not(feature = "production")))]
mod runtime;
pub mod security;

pub mod application;

pub mod limits;

pub mod auth;

pub mod staging;

pub mod operations;

pub mod callback;

pub mod metrics;

pub mod transport;

pub mod signed;
