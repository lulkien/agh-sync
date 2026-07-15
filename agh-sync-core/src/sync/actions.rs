//! Per-feature sync actions — async fn, each reconciles one feature.

use anyhow::Context;

use crate::client::Client;
use crate::config::Config;
use crate::model::merge;
use crate::model::{
    AccessList, BlockedServicesSchedule, DhcpStatus, DnsConfig, Filter, QueryLogConfig,
    SafeSearchConfig, TlsConfig,
};

use super::orchestrator::{ActionContext, OriginData};

type SyncFn = Box<
    dyn for<'a> Fn(
            &'a Client,
            &'a OriginData,
            &'a ActionContext<'a>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send + 'a>,
        > + Send
        + Sync,
>;

pub(crate) fn build_actions(cfg: &Config) -> Vec<(&'static str, SyncFn)> {
    let mut actions: Vec<(&str, SyncFn)> = Vec::new();

    macro_rules! push {
        ($name:expr, $fn:ident) => {
            actions.push(($name, Box::new(|c, o, x| Box::pin($fn(c, o, x)))));
        };
    }

    if cfg.features.general_settings {
        push!("profile info", sync_profile_info);
        if cfg.features.protection_status {
            push!("protection", sync_protection);
        }
        push!("parental", sync_parental);
        push!("safe search", sync_safe_search);
        push!("safe browsing", sync_safe_browsing);
    }
    if cfg.features.dns.server_config {
        push!("DNS server config", sync_dns_server_config);
    }
    if cfg.features.query_log_config {
        push!("query log config", sync_query_log_config);
    }
    if cfg.features.stats_config {
        push!("stats config", sync_stats_config);
    }
    if cfg.features.dns.rewrites {
        push!("DNS rewrite settings", sync_rewrite_settings);
        push!("DNS rewrite entries", sync_rewrite_entries);
    }
    if cfg.features.filters.blacklist
        || cfg.features.filters.whitelist
        || cfg.features.filters.user_rules
    {
        push!("filters", sync_filters);
    }
    if cfg.features.services {
        push!("blocked services", sync_blocked_services);
    }
    if cfg.features.client_settings {
        push!("client settings", sync_client_settings);
    }
    if cfg.features.dns.access_lists {
        push!("DNS access lists", sync_dns_access_lists);
    }
    if cfg.features.dhcp.server_config {
        push!("DHCP server config", sync_dhcp_server_config);
    }
    if cfg.features.dhcp.static_leases {
        push!("DHCP static leases", sync_dhcp_static_leases);
    }
    if cfg.features.tls_config {
        push!("TLS config", sync_tls_config);
    }

    actions
}

// ── Individual action functions ──

async fn sync_profile_info(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let origin = match &o.general.profile_info {
        Some(p) => p,
        None => return Ok(()),
    };
    let replica = c.profile_info().await.ok();
    if replica.as_ref().and_then(|p| p.theme.as_deref()) != origin.theme.as_deref() {
        c.set_profile_info(origin).await.context("profile info")?;
    }
    Ok(())
}

async fn sync_protection(c: &Client, o: &OriginData, _x: &ActionContext<'_>) -> anyhow::Result<()> {
    let rs = c.status().await.context("protection status")?;
    log::debug!(
        "protection: origin={} replica={}",
        o.general.protection_enabled,
        rs.protection_enabled
    );
    if o.general.protection_enabled != rs.protection_enabled {
        c.toggle_protection(o.general.protection_enabled)
            .await
            .context("toggle protection")?;
    }
    Ok(())
}

async fn sync_parental(c: &Client, o: &OriginData, _x: &ActionContext<'_>) -> anyhow::Result<()> {
    let rp = c.parental().await.context("parental")?;
    log::debug!("parental: origin={} replica={}", o.general.parental, rp);
    if o.general.parental != rp {
        c.toggle_parental(o.general.parental)
            .await
            .context("toggle parental")?;
    }
    Ok(())
}

async fn sync_safe_search(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let rss = c.safe_search_config().await.context("safe search")?;
    if !safe_search_eq(&o.general.safe_search, &rss) {
        c.set_safe_search_config(&o.general.safe_search)
            .await
            .context("set safe search")?;
    }
    Ok(())
}

fn safe_search_eq(a: &SafeSearchConfig, b: &SafeSearchConfig) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

async fn sync_safe_browsing(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let rsb = c.safe_browsing().await.context("safe browsing")?;
    log::debug!(
        "safe_browsing: origin={} replica={}",
        o.general.safebrowsing,
        rsb
    );
    if o.general.safebrowsing != rsb {
        c.toggle_safe_browsing(o.general.safebrowsing)
            .await
            .context("toggle safe browsing")?;
    }
    Ok(())
}

async fn sync_dns_server_config(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let rd = c.dns_config().await.context("DNS config")?;
    log::debug!("dns config: origin={:?} replica={:?}", o.dns_config, rd);
    if !dns_config_eq(&o.dns_config, &rd) {
        let mut desired = o.dns_config.clone();
        desired.protection_enabled = None;
        c.set_dns_config(&desired).await.context("set DNS config")?;
    }
    Ok(())
}

fn dns_config_eq(a: &DnsConfig, b: &DnsConfig) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

async fn sync_query_log_config(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let rql = c.query_log_config().await.context("query log config")?;
    log::debug!(
        "query_log_config: origin={:?} replica={:?}",
        o.general.query_log,
        rql
    );
    if !query_log_config_eq(&o.general.query_log, &rql) {
        c.set_query_log_config(&o.general.query_log)
            .await
            .context("set query log config")?;
    }
    Ok(())
}

fn query_log_config_eq(a: &QueryLogConfig, b: &QueryLogConfig) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

async fn sync_stats_config(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let rs = c.stats_config().await.context("stats config")?;
    log::debug!(
        "stats_config: origin={:?} replica={:?}",
        o.general.stats.interval,
        rs.interval
    );
    if o.general.stats.interval != rs.interval {
        c.set_stats_config(&o.general.stats)
            .await
            .context("set stats config")?;
    }
    Ok(())
}

async fn sync_rewrite_settings(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let rr = c.rewrite_settings().await.context("rewrite settings")?;
    log::debug!(
        "rewrite_settings: origin={} replica={}",
        o.rewrite_settings.enabled,
        rr.enabled
    );
    if o.rewrite_settings.enabled != rr.enabled {
        c.set_rewrite_settings(&o.rewrite_settings)
            .await
            .context("set rewrite settings")?;
    }
    Ok(())
}

async fn sync_rewrite_entries(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let re = c.rewrite_entries().await.context("rewrite entries")?;
    log::debug!(
        "rewrite entries: origin={} replica={}",
        o.rewrite_entries.len(),
        re.len()
    );
    let (adds, removes, _, _) = merge::merge_rewrite_entries(&re, &o.rewrite_entries);
    c.delete_rewrite_entries(&removes)
        .await
        .context("delete rewrites")?;
    c.add_rewrite_entries(&adds).await.context("add rewrites")?;
    Ok(())
}

async fn sync_filters(c: &Client, o: &OriginData, ctx: &ActionContext<'_>) -> anyhow::Result<()> {
    let rf = c.filtering().await.context("filters")?;
    if ctx.features.filters.blacklist {
        sync_filter_list(c, false, o.filters.filters.as_ref(), rf.filters.as_ref()).await?;
    }
    if ctx.features.filters.whitelist {
        sync_filter_list(
            c,
            true,
            o.filters.whitelist_filters.as_ref(),
            rf.whitelist_filters.as_ref(),
        )
        .await?;
    }
    if ctx.features.filters.user_rules {
        let or = o.filters.user_rules.as_deref().unwrap_or(&[]);
        let rr = rf.user_rules.as_deref().unwrap_or(&[]);
        if or != rr {
            c.set_custom_rules(or).await.context("set custom rules")?;
        }
    }
    if let (Some(en), Some(iv)) = (o.filters.enabled, o.filters.interval)
        && (rf.enabled != Some(en) || rf.interval != Some(iv))
    {
        c.toggle_filtering(en, iv)
            .await
            .context("toggle filtering")?;
    }
    Ok(())
}

async fn sync_filter_list(
    c: &Client,
    wl: bool,
    origin: Option<&Vec<Filter>>,
    replica: Option<&Vec<Filter>>,
) -> anyhow::Result<()> {
    let (adds, _, deletes) = merge::merge_filters(replica, origin);
    log::debug!(
        "filters (wl={wl}): add={} delete={}",
        adds.len(),
        deletes.len()
    );
    for f in &deletes {
        c.delete_filter(wl, f).await?;
    }
    for f in &adds {
        c.add_filter(wl, f).await?;
    }
    if !adds.is_empty() || !deletes.is_empty() {
        c.refresh_filters(wl).await?;
    }
    Ok(())
}

async fn sync_blocked_services(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let rb = c
        .blocked_services_schedule()
        .await
        .context("blocked services")?;
    log::debug!(
        "blocked services: origin={:?} replica={:?}",
        o.blocked_services_schedule.services,
        rb.services
    );
    if !blocked_services_eq(&o.blocked_services_schedule, &rb) {
        c.set_blocked_services_schedule(&o.blocked_services_schedule)
            .await
            .context("set blocked services")?;
    }
    Ok(())
}

fn blocked_services_eq(a: &BlockedServicesSchedule, b: &BlockedServicesSchedule) -> bool {
    a.services == b.services
        && a.schedule.time_zone == b.schedule.time_zone
        && a.schedule.days == b.schedule.days
        && a.schedule.start == b.schedule.start
        && a.schedule.end == b.schedule.end
}

async fn sync_client_settings(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let rc = c.clients().await.context("clients")?;
    let (adds, updates, deletes) = merge::merge_clients(&rc.clients, &o.clients.clients);
    log::debug!(
        "clients: origin={} replica={} add={} update={} delete={}",
        o.clients.clients.len(),
        rc.clients.len(),
        adds.len(),
        updates.len(),
        deletes.len()
    );
    for cl in &deletes {
        c.delete_client(cl).await?;
    }
    for cl in &adds {
        c.add_client(cl).await?;
    }
    for cl in &updates {
        c.update_client(cl).await?;
    }
    Ok(())
}

async fn sync_dns_access_lists(
    c: &Client,
    o: &OriginData,
    _x: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let ra = c.access_list().await.context("access list")?;
    log::debug!(
        "access_list: origin_allowed={:?} replica_allowed={:?}",
        o.access_list.allowed_clients,
        ra.allowed_clients
    );
    if !access_list_eq(&o.access_list, &ra) {
        c.set_access_list(&o.access_list)
            .await
            .context("set access list")?;
    }
    Ok(())
}

fn access_list_eq(a: &AccessList, b: &AccessList) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

async fn sync_dhcp_server_config(
    c: &Client,
    o: &OriginData,
    ctx: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let od = match &o.dhcp_server_config {
        Some(d) if d.has_config() => d,
        _ => return Ok(()),
    };
    let rd = c.dhcp_config().await.context("DHCP config")?;
    let mut desired = od.clone();
    if let Some(ref iface) = ctx.replica.interface_name {
        desired.interface_name = Some(iface.clone());
    }
    if let Some(en) = ctx.replica.dhcp_server_enabled {
        desired.enabled = Some(en);
    }
    log::debug!(
        "dhcp_config: origin_enabled={:?} replica_enabled={:?}",
        desired.enabled,
        rd.enabled
    );
    if !dhcp_config_eq(&desired, &rd) {
        c.set_dhcp_config(&desired)
            .await
            .context("set DHCP config")?;
    }
    Ok(())
}

fn dhcp_config_eq(a: &DhcpStatus, b: &DhcpStatus) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

async fn sync_dhcp_static_leases(
    c: &Client,
    o: &OriginData,
    _ctx: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let od = match &o.dhcp_server_config {
        Some(d) => d,
        _ => return Ok(()),
    };
    let rd = c.dhcp_config().await.context("DHCP static leases")?;
    let (adds, removes) =
        merge::merge_dhcp_leases(rd.static_leases.as_ref(), od.static_leases.as_ref());
    for l in &removes {
        c.delete_dhcp_static_lease(l).await?;
    }
    for l in &adds {
        c.add_dhcp_static_lease(l).await?;
    }
    Ok(())
}

async fn sync_tls_config(
    c: &Client,
    o: &OriginData,
    _ctx: &ActionContext<'_>,
) -> anyhow::Result<()> {
    let ot = match &o.tls_config {
        Some(t) => t,
        _ => return Ok(()),
    };
    let rt = c.tls_config().await.context("TLS config")?;
    log::debug!("tls_config: origin={:?} replica={:?}", ot, rt);
    if !tls_config_eq(ot, &rt) {
        c.set_tls_config(ot).await.context("set TLS config")?;
    }
    Ok(())
}

fn tls_config_eq(a: &TlsConfig, b: &TlsConfig) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

// ── DhcpStatus helpers ──

impl DhcpStatus {
    fn has_config(&self) -> bool {
        dhcp_v4_valid(self.v4.as_ref()) || dhcp_v6_valid(self.v6.as_ref())
    }
}

fn dhcp_v4_valid(v: Option<&crate::model::DhcpConfigV4>) -> bool {
    v.is_some_and(|v| {
        v.gateway_ip.as_deref().is_some_and(|s| !s.is_empty())
            && v.subnet_mask.as_deref().is_some_and(|s| !s.is_empty())
            && v.range_start.as_deref().is_some_and(|s| !s.is_empty())
            && v.range_end.as_deref().is_some_and(|s| !s.is_empty())
    })
}

fn dhcp_v6_valid(v: Option<&crate::model::DhcpConfigV6>) -> bool {
    v.is_some_and(|v| v.range_start.as_deref().is_some_and(|s| !s.is_empty()))
}
