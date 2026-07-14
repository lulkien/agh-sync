//! REST API client for AdGuardHome instances.

mod reqwest_client;

pub use reqwest_client::{Client, ClientError};
