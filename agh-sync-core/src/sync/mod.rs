//! Sync engine — fetch from origin, reconcile, push to replicas.

mod actions;
mod orchestrator;

pub use orchestrator::sync;
