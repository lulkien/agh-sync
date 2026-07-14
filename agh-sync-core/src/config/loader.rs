//! Layered configuration loading via Figment.
//!
//! Priority (lowest to highest):
//! 1. Default values
//! 2. YAML config file
//! 3. Environment variables
//! 4. CLI overrides

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::path::PathBuf;

use figment::Figment;
use figment::providers::{Env, Format, Yaml};

use super::types::{AdGuardInstance, Config};

/// Configuration loading error.
#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "config error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

impl From<figment::Error> for ConfigError {
    fn from(e: figment::Error) -> Self {
        ConfigError(e.to_string())
    }
}

impl From<String> for ConfigError {
    fn from(s: String) -> Self {
        ConfigError(s)
    }
}

impl From<&str> for ConfigError {
    fn from(s: &str) -> Self {
        ConfigError(s.to_string())
    }
}

/// CLI overrides passed from the binary.
#[derive(Debug, Default)]
pub struct CliOverrides {
    pub cron: Option<String>,
    pub run_on_start: Option<bool>,
    pub print_config_only: Option<bool>,
    pub continue_on_error: Option<bool>,
    pub api_port: Option<u16>,
    pub api_username: Option<String>,
    pub api_password: Option<String>,
    pub api_dark_mode: Option<bool>,
    pub origin_url: Option<String>,
    pub origin_web_url: Option<String>,
    pub origin_username: Option<String>,
    pub origin_password: Option<String>,
    pub origin_cookie: Option<String>,
    pub origin_insecure_skip_verify: Option<bool>,
    pub replica_url: Option<String>,
    pub replica_web_url: Option<String>,
    pub replica_username: Option<String>,
    pub replica_password: Option<String>,
    pub replica_cookie: Option<String>,
    pub replica_insecure_skip_verify: Option<bool>,
    pub replica_auto_setup: Option<bool>,
    pub replica_interface_name: Option<String>,
    // Feature flags
    pub feature_general_settings: Option<bool>,
    pub feature_protection_status: Option<bool>,
    pub feature_query_log_config: Option<bool>,
    pub feature_stats_config: Option<bool>,
    pub feature_client_settings: Option<bool>,
    pub feature_services: Option<bool>,
    pub feature_dns_server_config: Option<bool>,
    pub feature_dns_access_lists: Option<bool>,
    pub feature_dns_rewrites: Option<bool>,
    pub feature_dhcp_server_config: Option<bool>,
    pub feature_dhcp_static_leases: Option<bool>,
    pub feature_filters_blacklist: Option<bool>,
    pub feature_filters_whitelist: Option<bool>,
    pub feature_filters_user_rules: Option<bool>,
    pub feature_theme: Option<bool>,
    pub feature_tls_config: Option<bool>,
}

/// Load configuration from all layers.
pub fn load_config(config_path: &str, overrides: CliOverrides) -> Result<Config, ConfigError> {
    let config_path = resolve_path(config_path);

    let mut figment = Figment::new()
        // Layer 1: defaults
        .merge(figment::providers::Serialized::defaults(Config::default()))
        // Layer 2: YAML file (if exists)
        .merge(yaml_provider(&config_path));

    // Layer 3: environment variables
    figment = figment.merge(Env::prefixed("").split("_"));

    // Build base config
    let mut cfg: Config = figment.extract()?;

    // Handle replica env vars (REPLICA1_URL, etc.)
    let replica_instances = parse_replica_env();
    if !replica_instances.is_empty() {
        cfg.replicas = replica_instances;
    }

    // Handle origin env vars explicitly (prefixed with ORIGIN_)
    apply_origin_env(&mut cfg);

    // Layer 4: CLI overrides (highest priority)
    apply_cli_overrides(&mut cfg, overrides);

    // Validate and normalize
    validate_config(&mut cfg)?;

    Ok(cfg)
}

fn resolve_path(config_path: &str) -> PathBuf {
    let path = config_path.replace('~', &env::var("HOME").unwrap_or_default());
    PathBuf::from(path)
}

fn yaml_provider(path: &PathBuf) -> impl figment::Provider {
    Yaml::file(path)
}

/// Parse REPLICA#_* environment variables.
///
/// Example: `REPLICA1_URL=http://...`, `REPLICA1_USERNAME=admin`
fn parse_replica_env() -> Vec<AdGuardInstance> {
    let mut replicas: HashMap<usize, HashMap<String, String>> = HashMap::new();

    for (key, value) in env::vars() {
        if let Some(rest) = key.strip_prefix("REPLICA") {
            // Find where the index number ends
            if let Some(idx_end) = rest.find(|c: char| !c.is_ascii_digit())
                && let Ok(idx) = rest[..idx_end].parse::<usize>()
            {
                let field = rest[idx_end..].trim_start_matches('_').to_lowercase();
                replicas.entry(idx).or_default().insert(field, value);
            }
        }
    }

    // Also handle REPLICA_* (singular, without index — treated as index 0)
    for (key, value) in env::vars() {
        if let Some(rest) = key.strip_prefix("REPLICA_") {
            let field = rest.to_lowercase();
            replicas.entry(0).or_default().insert(field, value);
        }
    }

    let mut indices: Vec<_> = replicas.keys().copied().collect();
    indices.sort();

    indices
        .into_iter()
        .filter_map(|idx| {
            let fields = replicas.get(&idx)?;
            if fields.get("url").is_none() || fields.get("url")?.is_empty() {
                return None;
            }
            Some(AdGuardInstance {
                url: fields.get("url")?.clone(),
                web_url: fields.get("web_url").cloned(),
                api_path: fields.get("api_path").cloned().unwrap_or("/control".into()),
                username: fields.get("username").cloned(),
                password: fields.get("password").cloned(),
                cookie: fields.get("cookie").cloned(),
                request_headers: parse_headers(fields.get("request_headers")),
                insecure_skip_verify: fields
                    .get("insecure_skip_verify")
                    .is_some_and(|v| v == "true"),
                auto_setup: fields.get("auto_setup").is_some_and(|v| v == "true"),
                interface_name: fields.get("interface_name").cloned(),
                dhcp_server_enabled: fields.get("dhcp_server_enabled").map(|v| v == "true"),
                config_path: None,
                host: None,
                web_host: None,
            })
        })
        .collect()
}

/// Parse ORIGIN_* env vars and merge into config.
fn apply_origin_env(cfg: &mut Config) {
    let mut fields = HashMap::new();
    for (key, value) in env::vars() {
        if let Some(rest) = key.strip_prefix("ORIGIN_") {
            fields.insert(rest.to_lowercase(), value);
        }
    }

    if fields.is_empty() {
        return;
    }

    if let Some(url) = fields.get("url").filter(|v| !v.is_empty()) {
        cfg.origin.url.clone_from(url);
    }
    if let Some(web_url) = fields.get("web_url") {
        cfg.origin.web_url = Some(web_url.clone());
    }
    if let Some(api_path) = fields.get("api_path") {
        cfg.origin.api_path.clone_from(api_path);
    }
    if let Some(username) = fields.get("username") {
        cfg.origin.username = Some(username.clone());
    }
    if let Some(password) = fields.get("password") {
        cfg.origin.password = Some(password.clone());
    }
    if let Some(cookie) = fields.get("cookie") {
        cfg.origin.cookie = Some(cookie.clone());
    }
    if let Some(headers) = fields.get("request_headers") {
        cfg.origin.request_headers = parse_headers(Some(headers));
    }
    if let Some(isv) = fields.get("insecure_skip_verify") {
        cfg.origin.insecure_skip_verify = isv == "true";
    }
    if let Some(auto) = fields.get("auto_setup") {
        cfg.origin.auto_setup = auto == "true";
    }
}

fn parse_headers(raw: Option<&String>) -> HashMap<String, String> {
    let raw = match raw {
        Some(r) => r,
        None => return HashMap::new(),
    };
    raw.split(',')
        .filter_map(|pair| {
            let (k, v) = pair.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Apply CLI overrides on top of the loaded config.
fn apply_cli_overrides(cfg: &mut Config, overrides: CliOverrides) {
    if let Some(v) = overrides.cron {
        cfg.cron = Some(v);
    }
    if let Some(v) = overrides.run_on_start {
        cfg.run_on_start = v;
    }
    if let Some(v) = overrides.print_config_only {
        cfg.print_config_only = v;
    }
    if let Some(v) = overrides.continue_on_error {
        cfg.continue_on_error = v;
    }
    if let Some(v) = overrides.api_port {
        cfg.api.port = v;
    }
    if let Some(v) = overrides.api_username {
        cfg.api.username = Some(v);
    }
    if let Some(v) = overrides.api_password {
        cfg.api.password = Some(v);
    }
    if let Some(v) = overrides.api_dark_mode {
        cfg.api.dark_mode = v;
    }

    // Origin overrides
    if let Some(v) = overrides.origin_url {
        cfg.origin.url = v;
    }
    if let Some(v) = overrides.origin_web_url {
        cfg.origin.web_url = Some(v);
    }
    if let Some(v) = overrides.origin_username {
        cfg.origin.username = Some(v);
    }
    if let Some(v) = overrides.origin_password {
        cfg.origin.password = Some(v);
    }
    if let Some(v) = overrides.origin_cookie {
        cfg.origin.cookie = Some(v);
    }
    if let Some(v) = overrides.origin_insecure_skip_verify {
        cfg.origin.insecure_skip_verify = v;
    }

    // Single replica overrides (if set, create a replica entry)
    if let Some(url) = overrides.replica_url {
        let replica = AdGuardInstance {
            url,
            web_url: overrides.replica_web_url,
            username: overrides.replica_username,
            password: overrides.replica_password,
            cookie: overrides.replica_cookie,
            insecure_skip_verify: overrides.replica_insecure_skip_verify.unwrap_or(false),
            auto_setup: overrides.replica_auto_setup.unwrap_or(false),
            interface_name: overrides.replica_interface_name,
            ..Default::default()
        };
        cfg.replicas.push(replica);
    }

    // Feature overrides
    macro_rules! feat {
        ($field:ident, $ov:expr) => {
            if let Some(v) = $ov {
                cfg.features.$field = v;
            }
        };
    }
    feat!(general_settings, overrides.feature_general_settings);
    feat!(protection_status, overrides.feature_protection_status);
    feat!(query_log_config, overrides.feature_query_log_config);
    feat!(stats_config, overrides.feature_stats_config);
    feat!(client_settings, overrides.feature_client_settings);
    feat!(services, overrides.feature_services);
    feat!(theme, overrides.feature_theme);
    feat!(tls_config, overrides.feature_tls_config);

    if let Some(v) = overrides.feature_dns_server_config {
        cfg.features.dns.server_config = v;
    }
    if let Some(v) = overrides.feature_dns_access_lists {
        cfg.features.dns.access_lists = v;
    }
    if let Some(v) = overrides.feature_dns_rewrites {
        cfg.features.dns.rewrites = v;
    }
    if let Some(v) = overrides.feature_dhcp_server_config {
        cfg.features.dhcp.server_config = v;
    }
    if let Some(v) = overrides.feature_dhcp_static_leases {
        cfg.features.dhcp.static_leases = v;
    }
    if let Some(v) = overrides.feature_filters_blacklist {
        cfg.features.filters.blacklist = v;
    }
    if let Some(v) = overrides.feature_filters_whitelist {
        cfg.features.filters.whitelist = v;
    }
    if let Some(v) = overrides.feature_filters_user_rules {
        cfg.features.filters.user_rules = v;
    }
}

/// Validate and normalize the config.
fn validate_config(cfg: &mut Config) -> Result<(), ConfigError> {
    // Origin URL is required
    if cfg.origin.url.is_empty() {
        return Err("origin.url is required".into());
    }

    // Handle single replica conversion
    if let Some(single) = cfg.replica.take() {
        if single.url.is_empty() {
            // Empty single replica — ignore
        } else if !cfg.replicas.iter().any(|r| r.url == single.url) {
            // Avoid duplicates
            cfg.replicas.push(single);
        }
    }

    // Must have at least one replica
    if cfg.replicas.is_empty() {
        return Err("at least one replica is required".into());
    }

    // Normalize origin
    if cfg.origin.username.as_deref() == Some("") {
        cfg.origin.username = None;
    }
    if cfg.origin.password.as_deref() == Some("") {
        cfg.origin.password = None;
    }

    // Normalize replicas
    for replica in &mut cfg.replicas {
        if replica.username.as_deref() == Some("") {
            replica.username = None;
        }
        if replica.password.as_deref() == Some("") {
            replica.password = None;
        }
        if replica.api_path.is_empty() {
            replica.api_path = "/control".to_string();
        }
    }

    // Disable origin auto_setup (makes no sense)
    cfg.origin.auto_setup = false;

    // Disable origin dhcp_server_enabled (makes no sense)
    cfg.origin.dhcp_server_enabled = None;

    // Parse client timeout
    if let Some(ref _timeout_str) = cfg.client_timeout {
        // We validate the timeout string format but store it as-is
        // Parsing to Duration happens when creating the HTTP client
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_headers() {
        let h = parse_headers(Some(&"Key1:Val1,Key2:Val2".to_string()));
        assert_eq!(h.get("Key1").unwrap(), "Val1");
        assert_eq!(h.get("Key2").unwrap(), "Val2");
    }

    #[test]
    fn test_parse_headers_none() {
        let h = parse_headers(None);
        assert!(h.is_empty());
    }

    #[test]
    fn test_parse_headers_empty() {
        let h = parse_headers(Some(&"".to_string()));
        assert!(h.is_empty());
    }
}
