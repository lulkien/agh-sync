//! API model types for AdGuardHome REST API.

use serde::{Deserialize, Serialize};

/// Server status response from /control/status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatus {
    pub version: String,
    pub running: bool,
    pub protection_enabled: bool,
    pub dns_addresses: Vec<String>,
    pub dns_port: u16,
    pub http_port: u16,
    pub language: String,
}

/// DNS rewrite entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RewriteEntry {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub answer: String,
    #[serde(default)]
    pub enabled: bool,
}

/// DNS rewrite settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteSettings {
    pub enabled: bool,
}

/// DNS rewrite update payload (target + new data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewriteUpdate {
    pub target: RewriteEntry,
    pub update: RewriteEntry,
}

/// Filter status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterStatus {
    pub enabled: Option<bool>,
    pub interval: Option<i32>,
    pub filters: Option<Vec<Filter>>,
    pub whitelist_filters: Option<Vec<Filter>>,
    pub user_rules: Option<Vec<String>>,
}

/// A single filter entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Filter {
    pub url: String,
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub id: i64,
}

/// Client settings (API model, not the HTTP client).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSettings {
    pub name: String,
    #[serde(default)]
    pub ids: Vec<String>,
    #[serde(default)]
    pub use_global_settings: bool,
    #[serde(default)]
    pub use_global_blocked_services: bool,
    #[serde(default)]
    pub filtering_enabled: Option<bool>,
    #[serde(default)]
    pub parental_enabled: Option<bool>,
    #[serde(default)]
    pub safebrowsing_enabled: Option<bool>,
    #[serde(default)]
    pub safesearch_enabled: Option<bool>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Client list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Clients {
    pub clients: Vec<ClientSettings>,
}

/// Blocked services schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedServicesSchedule {
    #[serde(default)]
    pub schedule: Schedule,
    #[serde(default)]
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Schedule {
    #[serde(default)]
    pub time_zone: String,
    #[serde(default)]
    pub days: Vec<String>,
    #[serde(default)]
    pub start: String,
    #[serde(default)]
    pub end: String,
}

/// Query log config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogConfig {
    pub enabled: Option<bool>,
    pub interval: Option<f64>,
    pub anonymize_client_ip: Option<bool>,
    #[serde(default)]
    pub ignored: Vec<String>,
}

/// Stats config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsConfig {
    pub interval: Option<i32>,
}

/// DNS access list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessList {
    #[serde(default)]
    pub allowed_clients: Vec<String>,
    #[serde(default)]
    pub disallowed_clients: Vec<String>,
    #[serde(default)]
    pub blocked_hosts: Vec<String>,
}

/// DNS config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub upstream_dns: Vec<String>,
    #[serde(default)]
    pub upstream_dns_file: Option<String>,
    #[serde(default)]
    pub bootstrap_dns: Vec<String>,
    #[serde(default)]
    pub protection_enabled: Option<bool>,
    #[serde(default)]
    pub ratelimit: Option<i32>,
    #[serde(default)]
    pub blocking_mode: Option<String>,
    #[serde(default)]
    pub blocking_ipv4: Option<String>,
    #[serde(default)]
    pub blocking_ipv6: Option<String>,
    #[serde(default)]
    pub edns_cs_enabled: Option<bool>,
    #[serde(default)]
    pub dnssec_enabled: Option<bool>,
    #[serde(default)]
    pub disable_ipv6: Option<bool>,
    #[serde(default)]
    pub cache_size: Option<i32>,
    #[serde(default)]
    pub cache_ttl_min: Option<i32>,
    #[serde(default)]
    pub cache_ttl_max: Option<i32>,
}

/// DHCP server status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpStatus {
    pub enabled: Option<bool>,
    pub interface_name: Option<String>,
    pub v4: Option<DhcpConfigV4>,
    pub v6: Option<DhcpConfigV6>,
    pub static_leases: Option<Vec<DhcpStaticLease>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfigV4 {
    pub gateway_ip: Option<String>,
    pub subnet_mask: Option<String>,
    pub range_start: Option<String>,
    pub range_end: Option<String>,
    pub lease_duration: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfigV6 {
    pub range_start: Option<String>,
    pub lease_duration: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DhcpStaticLease {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
}

/// TLS config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: Option<bool>,
    pub server_name: Option<String>,
    pub force_https: Option<bool>,
    pub port_https: Option<u16>,
    pub port_dns_over_tls: Option<u16>,
    pub port_dns_over_quic: Option<u16>,
    pub certificate_chain: Option<String>,
    pub private_key: Option<String>,
}

/// Safe search config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeSearchConfig {
    pub enabled: Option<bool>,
    pub bing: Option<bool>,
    pub google: Option<bool>,
    pub youtube: Option<bool>,
    pub pixabay: Option<bool>,
    pub duckduckgo: Option<bool>,
    pub yandex: Option<bool>,
}

/// Profile info (for theme sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileInfo {
    pub name: Option<String>,
    pub language: Option<String>,
    pub theme: Option<String>,
}

/// Stats response from /control/stats.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Stats {
    pub avg_processing_time: Option<f64>,
    pub num_dns_queries: Option<i32>,
    pub num_blocked_filtering: Option<i32>,
    pub num_replaced_parental: Option<i32>,
    pub num_replaced_safebrowsing: Option<i32>,
    pub num_replaced_safesearch: Option<i32>,
    pub top_queried_domains: Option<Vec<serde_json::Value>>,
    pub top_blocked_domains: Option<Vec<serde_json::Value>>,
    pub top_clients: Option<Vec<serde_json::Value>>,
}

/// Query log response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLog {
    pub data: Option<Vec<serde_json::Value>>,
}
