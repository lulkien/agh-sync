pub mod client;
pub mod config;
pub mod metrics;
pub mod model;
pub mod sync;

/// AdGuardHome Sync version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
