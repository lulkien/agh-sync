//! Configuration types.

use serde::{Deserialize, Serialize};

/// Top-level application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Cron expression for daemon mode.
    #[serde(default)]
    pub cron: Option<String>,

    /// Run sync on startup.
    #[serde(default = "default_true")]
    pub run_on_start: bool,

    /// Print config only and exit.
    #[serde(default)]
    pub print_config_only: bool,

    /// Continue on errors.
    #[serde(default)]
    pub continue_on_error: bool,

    /// HTTP client timeout string (e.g. "30s").
    #[serde(default)]
    pub client_timeout: Option<String>,

    /// Origin AdGuardHome instance.
    pub origin: AdGuardInstance,

    /// Single replica (mutually exclusive with `replicas`).
    #[serde(default)]
    pub replica: Option<AdGuardInstance>,

    /// Multiple replicas (mutually exclusive with `replica`).
    #[serde(default)]
    pub replicas: Vec<AdGuardInstance>,

    /// API server configuration.
    #[serde(default)]
    pub api: ApiConfig,

    /// Feature flags.
    #[serde(default = "Features::all_enabled")]
    pub features: Features,
}

/// An AdGuardHome instance (origin or replica).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdGuardInstance {
    /// URL of the AdGuardHome instance.
    pub url: String,

    /// Web URL (for dashboard links). Defaults to `url`.
    #[serde(default)]
    pub web_url: Option<String>,

    /// API path. Defaults to "/control".
    #[serde(default = "default_api_path")]
    pub api_path: String,

    /// Username for authentication.
    #[serde(default)]
    pub username: Option<String>,

    /// Password for authentication.
    #[serde(default)]
    pub password: Option<String>,

    /// Cookie for authentication (alternative to username/password).
    #[serde(default)]
    pub cookie: Option<String>,

    /// Custom request headers.
    #[serde(default)]
    pub request_headers: std::collections::HashMap<String, String>,

    /// Skip TLS verification.
    #[serde(default)]
    pub insecure_skip_verify: bool,

    /// Auto-setup uninitialized instances.
    #[serde(default)]
    pub auto_setup: bool,

    /// Network interface name override.
    #[serde(default)]
    pub interface_name: Option<String>,

    /// Enable DHCP server on replica.
    #[serde(default)]
    pub dhcp_server_enabled: Option<bool>,

    /// Path to AdGuardHome config file to watch for changes (origin only).
    #[serde(default)]
    pub config_path: Option<String>,

    // Computed fields (not serialized).
    #[serde(skip)]
    pub host: Option<String>,

    #[serde(skip)]
    pub web_host: Option<String>,
}

/// API server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    /// Port (0 = disabled).
    #[serde(default = "default_api_port")]
    pub port: u16,

    /// API username for basic auth.
    #[serde(default)]
    pub username: Option<String>,

    /// API password for basic auth.
    #[serde(default)]
    pub password: Option<String>,

    /// Dark mode for the web dashboard.
    #[serde(default)]
    pub dark_mode: bool,

    /// Metrics configuration.
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// TLS configuration.
    #[serde(default)]
    pub tls: TlsConfig,
}

/// Metrics scraping configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics.
    #[serde(default)]
    pub enabled: bool,

    /// Scrape interval in seconds.
    #[serde(default = "default_scrape_interval")]
    pub scrape_interval: u64,

    /// Query log limit for metrics.
    #[serde(default = "default_query_log_limit")]
    pub query_log_limit: u32,
}

/// TLS configuration for the API server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate directory.
    #[serde(default)]
    pub cert_dir: Option<String>,

    /// Certificate file name.
    #[serde(default)]
    pub cert_name: Option<String>,

    /// Key file name.
    #[serde(default)]
    pub key_name: Option<String>,
}

/// Feature flags controlling which settings are synced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Features {
    /// General settings (profile, protection, parental, safesearch, safebrowsing).
    #[serde(default = "default_true")]
    pub general_settings: bool,

    /// Protection status sync (disabled if general_settings is disabled).
    #[serde(default = "default_true")]
    pub protection_status: bool,

    /// Query log configuration.
    #[serde(default = "default_true")]
    pub query_log_config: bool,

    /// Stats configuration.
    #[serde(default = "default_true")]
    pub stats_config: bool,

    /// Client settings.
    #[serde(default = "default_true")]
    pub client_settings: bool,

    /// Blocked services schedule.
    #[serde(default = "default_true")]
    pub services: bool,

    /// DNS sub-features.
    #[serde(default)]
    pub dns: DnsFeatures,

    /// DHCP sub-features.
    #[serde(default)]
    pub dhcp: DhcpFeatures,

    /// Filters sub-features.
    #[serde(default = "FiltersFeatures::all_enabled")]
    pub filters: FiltersFeatures,

    /// Web UI theme sync.
    #[serde(default)]
    pub theme: bool,

    /// TLS config sync.
    #[serde(default)]
    pub tls_config: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFeatures {
    #[serde(default = "default_true")]
    pub access_lists: bool,
    #[serde(default = "default_true")]
    pub server_config: bool,
    #[serde(default = "default_true")]
    pub rewrites: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpFeatures {
    #[serde(default = "default_true")]
    pub server_config: bool,
    #[serde(default = "default_true")]
    pub static_leases: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiltersFeatures {
    #[serde(default = "default_true")]
    pub blacklist: bool,
    #[serde(default = "default_true")]
    pub whitelist: bool,
    #[serde(default = "default_true")]
    pub user_rules: bool,
}

// ── Default functions ──

const fn default_true() -> bool {
    true
}

fn default_api_path() -> String {
    "/control".to_string()
}

fn default_api_port() -> u16 {
    8080
}

const fn default_scrape_interval() -> u64 {
    30
}

const fn default_query_log_limit() -> u32 {
    10_000
}

// ── Default impls ──

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            port: default_api_port(),
            username: None,
            password: None,
            dark_mode: false,
            metrics: MetricsConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scrape_interval: default_scrape_interval(),
            query_log_limit: default_query_log_limit(),
        }
    }
}

impl Default for DnsFeatures {
    fn default() -> Self {
        Self {
            access_lists: true,
            server_config: true,
            rewrites: true,
        }
    }
}

impl Default for DhcpFeatures {
    fn default() -> Self {
        Self {
            server_config: true,
            static_leases: true,
        }
    }
}

impl FiltersFeatures {
    fn all_enabled() -> Self {
        Self {
            blacklist: true,
            whitelist: true,
            user_rules: true,
        }
    }
}

impl Features {
    fn all_enabled() -> Self {
        Self {
            general_settings: true,
            protection_status: true,
            query_log_config: true,
            stats_config: true,
            client_settings: true,
            services: true,
            dns: DnsFeatures::default(),
            dhcp: DhcpFeatures::default(),
            filters: FiltersFeatures::all_enabled(),
            theme: false,
            tls_config: false,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cron: None,
            run_on_start: true,
            print_config_only: false,
            continue_on_error: false,
            client_timeout: None,
            origin: AdGuardInstance::default(),
            replica: None,
            replicas: Vec::new(),
            api: ApiConfig::default(),
            features: Features::all_enabled(),
        }
    }
}

impl Default for AdGuardInstance {
    fn default() -> Self {
        Self {
            url: String::new(),
            web_url: None,
            api_path: default_api_path(),
            username: None,
            password: None,
            cookie: None,
            request_headers: std::collections::HashMap::new(),
            insecure_skip_verify: false,
            auto_setup: false,
            interface_name: None,
            dhcp_server_enabled: None,
            config_path: None,
            host: None,
            web_host: None,
        }
    }
}

impl Config {
    /// Initialize computed fields (parse URLs, set host/web_host).
    pub fn init(&mut self) -> Result<(), String> {
        self.origin.init()?;
        for replica in &mut self.replicas {
            replica.init()?;
        }
        Ok(())
    }

    /// Get unique replicas (deduplicated by URL + API path).
    pub fn unique_replicas(&self) -> Vec<&AdGuardInstance> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for r in &self.replicas {
            let key = format!("{}#{}", r.url, r.api_path);
            if seen.insert(key) {
                result.push(r);
            }
        }
        result
    }

    /// Print the current config (with masked secrets) as YAML.
    pub fn print_config(&self) -> String {
        let mut masked = self.clone();
        masked.origin.mask();
        for r in &mut masked.replicas {
            r.mask();
        }
        masked.api.mask();
        serde_yaml::to_string(&masked).unwrap_or_else(|e| format!("error: {e}"))
    }
}

impl AdGuardInstance {
    /// Initialize computed fields from URL.
    pub fn init(&mut self) -> Result<(), String> {
        let parsed =
            url::Url::parse(&self.url).map_err(|e| format!("invalid URL '{}': {e}", self.url))?;
        self.host = Some(parsed.host_str().unwrap_or("").to_string());
        if let Some(port) = parsed.port() {
            self.host = Some(format!("{}:{port}", self.host.as_ref().unwrap()));
        }

        if let Some(ref web_url) = self.web_url {
            let w = url::Url::parse(web_url)
                .map_err(|e| format!("invalid web URL '{web_url}': {e}"))?;
            self.web_host = Some(w.host_str().unwrap_or("").to_string());
            if let Some(port) = w.port() {
                self.web_host = Some(format!("{}:{port}", self.web_host.as_ref().unwrap()));
            }
        } else {
            self.web_host.clone_from(&self.host);
            self.web_url = Some(self.url.clone());
        }

        Ok(())
    }

    /// Mask sensitive fields.
    pub fn mask(&mut self) {
        self.username = self.username.as_ref().map(|s| mask_str(s));
        self.password = self.password.as_ref().map(|s| mask_str(s));
    }
}

impl ApiConfig {
    /// Mask sensitive fields.
    pub fn mask(&mut self) {
        self.username = self.username.as_ref().map(|s| mask_str(s));
        self.password = self.password.as_ref().map(|s| mask_str(s));
    }
}

/// Mask a string: keep first and last char, replace middle with asterisks.
fn mask_str(s: &str) -> String {
    if s.len() < 3 {
        return "*".repeat(s.len());
    }
    let mask = "*".repeat(s.len() - 2);
    format!("{}{}{}", &s[..1], mask, &s[s.len() - 1..])
}
