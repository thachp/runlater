//! Pure task domain: lifecycle, retry policy, limits and validation.
//!
//! No Cloudflare dependencies, so everything here is tested natively with `cargo test`.
//! Ported from `legacy/src` in phase 2; see `docs/spec/ARCHITECTURE.md`.
