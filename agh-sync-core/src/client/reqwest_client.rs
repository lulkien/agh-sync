//! Reqwest-based REST client for AdGuardHome API.
//!
//! Implements the `Client` trait with all ~30 AGH API methods.

use crate::config::AdGuardInstance;
use crate::model::{
    AccessList, BlockedServicesSchedule, ClientSettings, Clients, DhcpStaticLease, DhcpStatus,
    DnsConfig, Filter, FilterStatus, ProfileInfo, QueryLog, QueryLogConfig, RewriteEntry,
    RewriteSettings, RewriteUpdate, SafeSearchConfig, ServerStatus, Stats, StatsConfig, TlsConfig,
};
use reqwest::{Client as HttpClient, StatusCode, Url};
use std::sync::Arc;
use std::time::Duration;
// logging removed

/// Client for interacting with an AdGuardHome instance's REST API.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    http: HttpClient,
    base_url: Url,
    host: String,
}

/// Error from the AdGuardHome API.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("API error: {status}: {body}")]
    Api { status: StatusCode, body: String },

    #[error("setup needed")]
    SetupNeeded,

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

impl Client {
    /// Create a new client for the given AdGuardHome instance.
    pub fn new(inst: &AdGuardInstance, timeout: Option<Duration>) -> Result<Self, ClientError> {
        let api_url = format!(
            "{}/{}/",
            inst.url.trim_end_matches('/'),
            inst.api_path.trim_matches('/')
        );

        let base_url = Url::parse(&api_url)
            .map_err(|e| ClientError::InvalidUrl(format!("invalid API URL '{api_url}': {e}")))?;

        let mut builder = HttpClient::builder()
            .danger_accept_invalid_certs(inst.insecure_skip_verify)
            .no_proxy();

        if let Some(t) = timeout {
            builder = builder.timeout(t);
        }

        // Set custom headers
        let mut headers = reqwest::header::HeaderMap::new();
        for (k, v) in &inst.request_headers {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                headers.insert(name, value);
            }
        }

        // Auth: cookie takes priority, then basic auth
        if let Some(ref cookie) = inst.cookie {
            if let Some((name, value)) = cookie.split_once('=') {
                headers.insert(
                    reqwest::header::COOKIE,
                    reqwest::header::HeaderValue::from_str(&format!("{name}={value}"))
                        .unwrap_or(reqwest::header::HeaderValue::from_static("")),
                );
            }
        } else if let (Some(user), Some(pass)) = (&inst.username, &inst.password) {
            use base64::{Engine, engine::general_purpose::STANDARD};
            let auth = STANDARD.encode(format!("{user}:{pass}"));
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Basic {auth}"))
                    .unwrap_or(reqwest::header::HeaderValue::from_static("")),
            );
        }

        builder = builder.default_headers(headers);

        let http = builder.build()?;
        let host = inst
            .host
            .clone()
            .unwrap_or_else(|| base_url.host_str().unwrap_or("unknown").to_string());

        Ok(Client {
            inner: Arc::new(Inner {
                http,
                base_url,
                host,
            }),
        })
    }

    pub fn host(&self) -> &str {
        &self.inner.host
    }

    // ── GET helpers ──

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let url = self.inner.base_url.join(path)?;
        let resp = self.inner.http.get(url).send().await?;

        if resp.status() == StatusCode::OK {
            Ok(resp.json().await?)
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(ClientError::Api { status, body })
        }
    }

    /// GET that can return 200 (ok) or specific codes meaning "not set up".
    async fn get_optional<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, ClientError> {
        let url = self.inner.base_url.join(path)?;
        let resp = self.inner.http.get(url).send().await?;

        match resp.status() {
            StatusCode::OK => Ok(resp.json().await?),
            s => {
                let body = resp.text().await.unwrap_or_default();
                // AGH returns this body when setup is needed
                if body.contains("install/configure") {
                    return Err(ClientError::SetupNeeded);
                }
                Err(ClientError::Api { status: s, body })
            }
        }
    }

    // ── POST helpers ──

    async fn post(&self, path: &str, body: &impl serde::Serialize) -> Result<(), ClientError> {
        let url = self.inner.base_url.join(path)?;
        let resp = self.inner.http.post(url).json(body).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            Err(ClientError::Api {
                status,
                body: body_text,
            })
        }
    }

    /// POST with no body.
    async fn post_empty(&self, path: &str) -> Result<(), ClientError> {
        let url = self.inner.base_url.join(path)?;
        let resp = self.inner.http.post(url).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            Err(ClientError::Api {
                status,
                body: body_text,
            })
        }
    }

    // ── PUT helpers ──

    async fn put(&self, path: &str, body: &impl serde::Serialize) -> Result<(), ClientError> {
        let url = self.inner.base_url.join(path)?;
        let resp = self.inner.http.put(url).json(body).send().await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body_text = resp.text().await.unwrap_or_default();
            Err(ClientError::Api {
                status,
                body: body_text,
            })
        }
    }

    // ── API Methods ──

    /// Get server status.
    pub async fn status(&self) -> Result<ServerStatus, ClientError> {
        let url = self.inner.base_url.join("status")?;
        let resp = self.inner.http.get(url).send().await?;

        match resp.status() {
            StatusCode::OK => {
                let body = resp.text().await.unwrap_or_default();
                // Check if this is actually the setup page
                if body.contains("install/configure") {
                    return Err(ClientError::SetupNeeded);
                }
                serde_json::from_str(&body).map_err(|e| ClientError::Api {
                    status: StatusCode::OK,
                    body: format!("JSON parse error: {e}"),
                })
            }
            s => {
                let body = resp.text().await.unwrap_or_default();
                if body.contains("install/configure") {
                    return Err(ClientError::SetupNeeded);
                }
                Err(ClientError::Api { status: s, body })
            }
        }
    }

    /// Get statistics.
    pub async fn stats(&self) -> Result<Stats, ClientError> {
        self.get("stats").await
    }

    /// Get query log (limited).
    pub async fn query_log(&self, limit: u32) -> Result<QueryLog, ClientError> {
        let path = format!("querylog?limit={limit}&response_status=\"all\"");
        self.get(&path).await
    }

    /// Toggle protection.
    pub async fn toggle_protection(&self, enable: bool) -> Result<(), ClientError> {
        self.post(
            "dns_config",
            &serde_json::json!({"protection_enabled": enable}),
        )
        .await
    }

    // ── Rewrites ──

    pub async fn rewrite_entries(&self) -> Result<Vec<RewriteEntry>, ClientError> {
        self.get("rewrite/list").await
    }

    pub async fn add_rewrite_entries(&self, entries: &[RewriteEntry]) -> Result<(), ClientError> {
        for e in entries {
            self.post("rewrite/add", e).await?;
        }
        Ok(())
    }

    pub async fn delete_rewrite_entries(
        &self,
        entries: &[RewriteEntry],
    ) -> Result<(), ClientError> {
        for e in entries {
            self.post("rewrite/delete", e).await?;
        }
        Ok(())
    }

    pub async fn update_rewrite_entries(
        &self,
        entries: &[RewriteUpdate],
    ) -> Result<(), ClientError> {
        for e in entries {
            self.put("rewrite/update", e).await?;
        }
        Ok(())
    }

    pub async fn rewrite_settings(&self) -> Result<RewriteSettings, ClientError> {
        self.get("rewrite/settings").await
    }

    pub async fn set_rewrite_settings(
        &self,
        settings: &RewriteSettings,
    ) -> Result<(), ClientError> {
        self.put("rewrite/settings/update", settings).await
    }

    // ── Filtering ──

    pub async fn filtering(&self) -> Result<FilterStatus, ClientError> {
        self.get("filtering/status").await
    }

    pub async fn toggle_filtering(&self, enabled: bool, interval: i32) -> Result<(), ClientError> {
        self.post(
            "filtering/config",
            &serde_json::json!({
                "enabled": enabled,
                "interval": interval
            }),
        )
        .await
    }

    pub async fn add_filter(&self, whitelist: bool, filter: &Filter) -> Result<(), ClientError> {
        self.post(
            "filtering/add_url",
            &serde_json::json!({
                "name": filter.name,
                "url": filter.url,
                "whitelist": whitelist
            }),
        )
        .await
    }

    pub async fn delete_filter(&self, whitelist: bool, filter: &Filter) -> Result<(), ClientError> {
        self.post(
            "filtering/remove_url",
            &serde_json::json!({
                "url": filter.url,
                "whitelist": whitelist
            }),
        )
        .await
    }

    pub async fn update_filter(&self, whitelist: bool, filter: &Filter) -> Result<(), ClientError> {
        self.post(
            "filtering/set_url",
            &serde_json::json!({
                "whitelist": whitelist,
                "url": filter.url,
                "data": {
                    "name": filter.name,
                    "url": filter.url,
                    "enabled": filter.enabled
                }
            }),
        )
        .await
    }

    pub async fn refresh_filters(&self, whitelist: bool) -> Result<(), ClientError> {
        self.post(
            "filtering/refresh",
            &serde_json::json!({"whitelist": whitelist}),
        )
        .await
    }

    pub async fn set_custom_rules(&self, rules: &[String]) -> Result<(), ClientError> {
        self.post("filtering/set_rules", &serde_json::json!({"rules": rules}))
            .await
    }

    // ── Safe browsing / parental ──

    async fn toggle_status(&self, mode: &str) -> Result<bool, ClientError> {
        let v: serde_json::Value = self.get(&format!("{mode}/status")).await?;
        Ok(v.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false))
    }

    async fn toggle_bool(&self, mode: &str, enable: bool) -> Result<(), ClientError> {
        let action = if enable { "enable" } else { "disable" };
        self.post_empty(&format!("{mode}/{action}")).await
    }

    pub async fn safe_browsing(&self) -> Result<bool, ClientError> {
        self.toggle_status("safebrowsing").await
    }

    pub async fn toggle_safe_browsing(&self, enable: bool) -> Result<(), ClientError> {
        self.toggle_bool("safebrowsing", enable).await
    }

    pub async fn parental(&self) -> Result<bool, ClientError> {
        self.toggle_status("parental").await
    }

    pub async fn toggle_parental(&self, enable: bool) -> Result<(), ClientError> {
        self.toggle_bool("parental", enable).await
    }

    // ── Safe search ──

    pub async fn safe_search_config(&self) -> Result<SafeSearchConfig, ClientError> {
        self.get("safesearch/status").await
    }

    pub async fn set_safe_search_config(
        &self,
        config: &SafeSearchConfig,
    ) -> Result<(), ClientError> {
        self.put("safesearch/settings", config).await
    }

    // ── Profile ──

    pub async fn profile_info(&self) -> Result<ProfileInfo, ClientError> {
        let v: serde_json::Value = self.get_optional("profile").await?;
        Ok(ProfileInfo {
            name: v.get("name").and_then(|n| n.as_str()).map(String::from),
            language: v.get("language").and_then(|l| l.as_str()).map(String::from),
            theme: v.get("theme").and_then(|t| t.as_str()).map(String::from),
        })
    }

    pub async fn set_profile_info(&self, profile: &ProfileInfo) -> Result<(), ClientError> {
        self.put("profile/update", profile).await
    }

    // ── Blocked services ──

    pub async fn blocked_services_schedule(&self) -> Result<BlockedServicesSchedule, ClientError> {
        self.get("blocked_services/get").await
    }

    pub async fn set_blocked_services_schedule(
        &self,
        schedule: &BlockedServicesSchedule,
    ) -> Result<(), ClientError> {
        self.put("blocked_services/update", schedule).await
    }

    // ── Clients ──

    pub async fn clients(&self) -> Result<Clients, ClientError> {
        self.get("clients").await
    }

    pub async fn add_client(&self, c: &ClientSettings) -> Result<(), ClientError> {
        self.post("clients/add", c).await
    }

    pub async fn update_client(&self, c: &ClientSettings) -> Result<(), ClientError> {
        self.post(
            "clients/update",
            &serde_json::json!({
                "name": c.name,
                "data": c
            }),
        )
        .await
    }

    pub async fn delete_client(&self, c: &ClientSettings) -> Result<(), ClientError> {
        self.post("clients/delete", c).await
    }

    // ── Query log config ──

    pub async fn query_log_config(&self) -> Result<QueryLogConfig, ClientError> {
        self.get("querylog/config").await
    }

    pub async fn set_query_log_config(&self, config: &QueryLogConfig) -> Result<(), ClientError> {
        self.put("querylog/config/update", config).await
    }

    // ── Stats config ──

    pub async fn stats_config(&self) -> Result<StatsConfig, ClientError> {
        self.get("stats/config").await
    }

    pub async fn set_stats_config(&self, config: &StatsConfig) -> Result<(), ClientError> {
        self.put("stats/config/update", config).await
    }

    // ── Setup ──

    pub async fn setup(&self) -> Result<(), ClientError> {
        let body = serde_json::json!({
            "web": {
                "ip": "0.0.0.0",
                "port": 3000,
                "status": "",
                "can_autofix": false
            },
            "dns": {
                "ip": "0.0.0.0",
                "port": 53,
                "status": "",
                "can_autofix": false
            }
        });
        self.post("install/configure", &body).await
    }

    // ── Access list ──

    pub async fn access_list(&self) -> Result<AccessList, ClientError> {
        self.get("access/list").await
    }

    pub async fn set_access_list(&self, list: &AccessList) -> Result<(), ClientError> {
        self.post("access/set", list).await
    }

    // ── DNS config ──

    pub async fn dns_config(&self) -> Result<DnsConfig, ClientError> {
        self.get("dns_info").await
    }

    pub async fn set_dns_config(&self, config: &DnsConfig) -> Result<(), ClientError> {
        self.post("dns_config", config).await
    }

    // ── DHCP ──

    pub async fn dhcp_config(&self) -> Result<DhcpStatus, ClientError> {
        self.get("dhcp/status").await
    }

    pub async fn set_dhcp_config(&self, config: &DhcpStatus) -> Result<(), ClientError> {
        self.post("dhcp/set_config", config).await
    }

    pub async fn add_dhcp_static_lease(&self, lease: &DhcpStaticLease) -> Result<(), ClientError> {
        self.post("dhcp/add_static_lease", lease).await
    }

    pub async fn delete_dhcp_static_lease(
        &self,
        lease: &DhcpStaticLease,
    ) -> Result<(), ClientError> {
        self.post("dhcp/remove_static_lease", lease).await
    }

    // ── TLS ──

    pub async fn tls_config(&self) -> Result<TlsConfig, ClientError> {
        self.get("tls/status").await
    }

    pub async fn set_tls_config(&self, config: &TlsConfig) -> Result<(), ClientError> {
        self.put("tls/configure", config).await
    }
}
