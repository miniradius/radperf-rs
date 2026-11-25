//! `radperf-rs` - a Rust RADIUS performance-testing client.
//!
//! See `NOTICE.md` for the provenance statement: this crate is an independent
//! reimplementation based on public RFCs and observed behaviour, and contains
//! no code or text from the C implementation of RadPerf.

#![forbid(unsafe_code)]

pub mod accounting;
pub mod cli;
pub mod client;
pub mod crypto;
pub mod dict;
pub mod input;
pub mod output;
pub mod packet;
pub mod request;
pub mod rng;
pub mod signals;
pub mod stats;
pub mod value;

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
