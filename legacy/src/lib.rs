#[cfg(all(
    feature = "invitation-tests",
    any(
        feature = "destination-tests",
        feature = "production",
        feature = "funding-tests",
        feature = "staging",
        feature = "runtime-tests"
    )
))]
compile_error!("invitation-tests must never be combined with production, funding-tests, staging, runtime-tests or destination-tests");
#[cfg(all(
    target_arch = "wasm32",
    any(feature = "invitation-tests", feature = "production")
))]
mod invitation_runtime;
#[cfg(all(
    feature = "funding-tests",
    any(feature = "staging", feature = "runtime-tests")
))]
compile_error!("funding-tests must never be combined with staging or runtime-tests");
#[cfg(all(
    feature = "production",
    any(
        feature = "staging",
        feature = "runtime-tests",
        feature = "funding-tests"
    )
))]
compile_error!("production must never be combined with staging, runtime-tests or funding-tests");
#[cfg(all(feature = "runtime-tests", feature = "staging"))]
compile_error!("runtime-tests must never be combined with the staging build");
pub mod core;
pub mod identity;
#[cfg(all(
    target_arch = "wasm32",
    any(feature = "production", feature = "funding-tests")
))]
mod production_runtime;
pub mod publication;
#[cfg(all(
    target_arch = "wasm32",
    not(any(
        feature = "production",
        feature = "funding-tests",
        feature = "invitation-tests",
        feature = "destination-tests"
    ))
))]
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

pub mod funding;

pub mod funded_tasks;

pub mod delivery;

pub mod invitation;
pub mod invitation_delivery;
pub mod public_beta;

#[cfg(all(
    feature = "destination-tests",
    any(
        feature = "production",
        feature = "staging",
        feature = "runtime-tests",
        feature = "funding-tests",
        feature = "invitation-tests"
    )
))]
compile_error!("destination-tests must be built in isolation");

#[cfg(all(target_arch = "wasm32", feature = "destination-tests"))]
mod destination_runtime;
pub mod destinations;
#[cfg(all(
    target_arch = "wasm32",
    any(
        feature = "production",
        feature = "destination-tests",
        feature = "invitation-tests"
    )
))]
mod safe_egress;

pub mod mcp_delegation;

pub mod anonymous_trial;

pub mod receiver_pairing;

pub mod general_http;

pub mod general_http_attempt;
