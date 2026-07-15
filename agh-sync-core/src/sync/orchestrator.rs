//! Sync orchestrator — fetch from origin, reconcile, push to replicas.

use std::time::Instant;

use anyhow::{Context, bail};
use log::{error, info};

use crate::client::Client;
use crate::config::{AdGuardInstance, Config};
use crate::model::{
    AccessList, BlockedServicesSchedule, Clients, DhcpStatus, DnsConfig, FilterStatus,
    GeneralSettings, RewriteEntry, RewriteSettings, ServerStatus, TlsConfig,
};

use super::actions;

/// All data fetched from the origin instance.
pub(crate) struct OriginData {
    pub general: GeneralSettings,
    #[allow(dead_code)]
    pub status: ServerStatus,
    pub rewrite_settings: RewriteSettings,
    pub rewrite_entries: Vec<RewriteEntry>,
    pub blocked_services_schedule: BlockedServicesSchedule,
    pub filters: FilterStatus,
    pub clients: Clients,
    pub access_list: AccessList,
    pub dns_config: DnsConfig,
    pub dhcp_server_config: Option<DhcpStatus>,
    pub tls_config: Option<TlsConfig>,
}

/// Context passed to each sync action.
pub(crate) struct ActionContext<'a> {
    pub features: &'a crate::config::Features,
    #[allow(dead_code)]
    pub continue_on_error: bool,
    pub replica: &'a AdGuardInstance,
}

/// Run a full sync from origin to all replicas.
pub async fn sync(cfg: &Config) -> anyhow::Result<()> {
    if cfg.origin.url.is_empty() {
        bail!("origin URL is required");
    }

    let replicas = cfg.unique_replicas();
    if replicas.is_empty() {
        bail!("no replicas configured");
    }

    info!(
        "AdGuardHome sync v{} on {}/{}",
        crate::VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    let timeout = humantime::parse_duration(cfg.client_timeout.as_deref().unwrap_or("30s")).ok();

    let origin_client = Client::new(&cfg.origin, timeout).context("creating origin client")?;

    let origin_data = fetch_origin_data(&origin_client, &cfg.features).await?;

    for replica in &replicas {
        if let Err(e) = sync_to_replica(cfg, replica, &origin_data, timeout).await {
            error!("Failed to sync to {}: {e:#}", replica.url);
            if !cfg.continue_on_error {
                return Err(e);
            }
        }
    }

    Ok(())
}

async fn fetch_origin_data(
    client: &Client,
    features: &crate::config::Features,
) -> anyhow::Result<OriginData> {
    let host = client.host();

    let status = client
        .status()
        .await
        .context(format!("getting origin status from {host}"))?;

    info!("Connected to origin (version {})", status.version);

    let profile_info = client.profile_info().await.ok();

    let parental = client.parental().await.context("getting parental status")?;

    let safe_search = client
        .safe_search_config()
        .await
        .context("getting safe search config")?;

    let safe_browsing = client
        .safe_browsing()
        .await
        .context("getting safe browsing status")?;

    let query_log_config = client
        .query_log_config()
        .await
        .context("getting query log config")?;

    let stats_config = client
        .stats_config()
        .await
        .context("getting stats config")?;

    let general = GeneralSettings {
        profile_info,
        protection_enabled: status.protection_enabled,
        parental,
        safebrowsing: safe_browsing,
        safe_search,
        query_log: query_log_config,
        stats: stats_config,
    };

    let rewrite_settings = client
        .rewrite_settings()
        .await
        .context("getting rewrite settings")?;

    let rewrite_entries = client
        .rewrite_entries()
        .await
        .context("getting rewrite entries")?;

    let blocked_services_schedule = client
        .blocked_services_schedule()
        .await
        .context("getting blocked services schedule")?;

    let filters = client.filtering().await.context("getting filters")?;

    let clients = client.clients().await.context("getting clients")?;

    let access_list = client.access_list().await.context("getting access list")?;

    let dns_config = client.dns_config().await.context("getting DNS config")?;

    let dhcp_server_config = if features.dhcp.server_config || features.dhcp.static_leases {
        Some(client.dhcp_config().await.context("getting DHCP config")?)
    } else {
        None
    };

    let tls_config = if features.tls_config {
        Some(client.tls_config().await.context("getting TLS config")?)
    } else {
        None
    };

    Ok(OriginData {
        general,
        status,
        rewrite_settings,
        rewrite_entries,
        blocked_services_schedule,
        filters,
        clients,
        access_list,
        dns_config,
        dhcp_server_config,
        tls_config,
    })
}

async fn sync_to_replica(
    cfg: &Config,
    replica: &AdGuardInstance,
    origin: &OriginData,
    timeout: Option<std::time::Duration>,
) -> anyhow::Result<()> {
    let replica_client = Client::new(replica, timeout).context("creating replica client")?;

    info!("Start sync to {}", replica_client.host());
    let start = Instant::now();

    let replica_status = match replica_client.status().await {
        Ok(s) => s,
        Err(crate::client::ClientError::SetupNeeded) if replica.auto_setup => {
            replica_client.setup().await.context("setting up replica")?;
            replica_client
                .status()
                .await
                .context("getting replica status after setup")?
        }
        Err(e) => return Err(e).context("getting replica status"),
    };

    info!("Connected to replica (version {})", replica_status.version);

    let ctx = ActionContext {
        features: &cfg.features,
        continue_on_error: cfg.continue_on_error,
        replica,
    };

    let actions = actions::build_actions(cfg);
    let mut with_error = false;

    for (name, action_fn) in &actions {
        if let Err(e) = action_fn(&replica_client, origin, &ctx).await {
            error!("Error syncing {name}: {e:#}");
            with_error = true;
            if !cfg.continue_on_error {
                let elapsed = start.elapsed().as_secs_f64();
                info!("Sync done ({elapsed}s) — errors");
                return Err(e);
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    if with_error {
        error!("Sync done ({elapsed}s)");
    } else {
        info!("Sync done ({elapsed}s)");
    }

    Ok(())
}

#[allow(dead_code)]
pub fn last_24_hours() -> Vec<String> {
    use chrono::{Duration, Utc};
    let now = Utc::now();
    (0..24)
        .rev()
        .map(|i| {
            let t = now - Duration::hours(i);
            t.format("%d %b %H:%M").to_string()
        })
        .collect()
}
