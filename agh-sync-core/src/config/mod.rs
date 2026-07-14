//! Configuration types and loading.
//!
//! Supports layered configuration via:
//! 1. Default values
//! 2. YAML file
//! 3. Environment variables
//! 4. CLI flags

mod loader;
mod types;

pub use loader::{CliOverrides, load_config};
pub use types::*;
