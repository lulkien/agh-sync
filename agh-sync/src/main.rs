//! agh-sync — synchronize AdGuardHome config to replica instances.
//!
//! Usage:
//!   agh-sync run                                    # single sync
//!   agh-sync run --cron "0 */2 * * *"               # daemon mode
//!   agh-sync run --print-config-only                # debug config

use anyhow::Result;
use clap::Parser;
use log::info;

use agh_sync_core::config::{self, CliOverrides};

#[derive(Parser)]
#[command(name = "agh-sync", version = agh_sync_core::VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Start synchronization from origin to replica(s).
    Run {
        /// Path to YAML config file
        #[arg(short, long, default_value = "~/.adguardhome-sync.yaml")]
        config: String,

        /// Cron expression for daemon mode (e.g. "0 */2 * * *")
        #[arg(long)]
        cron: Option<String>,

        /// Run sync immediately on startup (cron/daemon mode only)
        #[arg(long, default_value = "true")]
        run_on_start: bool,

        /// Print merged config and exit
        #[arg(long)]
        print_config_only: bool,

        /// Keep syncing to remaining replicas on error
        #[arg(long)]
        continue_on_error: bool,

        // ── Origin overrides ──
        #[arg(long, env = "ORIGIN_URL")]
        origin_url: Option<String>,
        #[arg(long, env = "ORIGIN_USERNAME")]
        origin_username: Option<String>,
        #[arg(long, env = "ORIGIN_PASSWORD")]
        origin_password: Option<String>,
        #[arg(long)]
        origin_cookie: Option<String>,
        #[arg(long)]
        origin_insecure_skip_verify: Option<bool>,

        // ── Single replica override ──
        #[arg(long, env = "REPLICA_URL")]
        replica_url: Option<String>,
        #[arg(long)]
        replica_username: Option<String>,
        #[arg(long)]
        replica_password: Option<String>,

        // ── Feature flags ──
        #[arg(long, default_value = "true")]
        feature_general_settings: bool,
        #[arg(long, default_value = "true")]
        feature_filters: bool,
        #[arg(long, default_value = "true")]
        feature_rewrites: bool,
        #[arg(long, default_value = "true")]
        feature_services: bool,
        #[arg(long, default_value = "true")]
        feature_clients: bool,
        #[arg(long, default_value = "true")]
        feature_dns: bool,
        #[arg(long, default_value = "true")]
        feature_dhcp: bool,
        #[arg(long)]
        feature_theme: bool,
        #[arg(long)]
        feature_tls: bool,
    },
}

fn setup_logger() -> Result<()> {
    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Info)
        .level_for("agh_sync", log::LevelFilter::Debug)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger()?;

    let cli = Cli::parse();
    let Commands::Run {
        config,
        cron,
        run_on_start,
        print_config_only,
        continue_on_error,
        origin_url,
        origin_username,
        origin_password,
        origin_cookie,
        origin_insecure_skip_verify,
        replica_url,
        replica_username,
        replica_password,
        feature_general_settings,
        feature_filters,
        feature_rewrites,
        feature_services,
        feature_clients,
        feature_dns,
        feature_dhcp,
        feature_theme,
        feature_tls,
    } = cli.command;

    let overrides = CliOverrides {
        cron: cron.clone(),
        run_on_start: Some(run_on_start),
        print_config_only: Some(print_config_only),
        continue_on_error: Some(continue_on_error),
        origin_url,
        origin_username,
        origin_password,
        origin_cookie,
        origin_insecure_skip_verify,
        replica_url,
        replica_username,
        replica_password,
        // Expand feature flags into granular overrides
        feature_general_settings: Some(feature_general_settings),
        feature_protection_status: Some(feature_general_settings),
        feature_query_log_config: Some(feature_general_settings),
        feature_stats_config: Some(feature_general_settings),
        feature_client_settings: Some(feature_clients),
        feature_services: Some(feature_services),
        feature_dns_server_config: Some(feature_dns),
        feature_dns_access_lists: Some(feature_dns),
        feature_dns_rewrites: Some(feature_rewrites),
        feature_dhcp_server_config: Some(feature_dhcp),
        feature_dhcp_static_leases: Some(feature_dhcp),
        feature_filters_blacklist: Some(feature_filters),
        feature_filters_whitelist: Some(feature_filters),
        feature_filters_user_rules: Some(feature_filters),
        feature_theme: Some(feature_theme),
        feature_tls_config: Some(feature_tls),
        // Unused overrides
        api_port: None,
        api_username: None,
        api_password: None,
        api_dark_mode: None,
        origin_web_url: None,
        replica_web_url: None,
        replica_cookie: None,
        replica_insecure_skip_verify: None,
        replica_auto_setup: None,
        replica_interface_name: None,
    };

    // Load config
    let mut cfg = config::load_config(&config, overrides)?;
    cfg.init().map_err(|e| anyhow::anyhow!("{e}"))?;

    if cfg.print_config_only {
        println!("{}", cfg.print_config());
        return Ok(());
    }

    info!("agh-sync v{}", agh_sync_core::VERSION);

    if let Some(cron_expr) = cron {
        // ── Daemon mode ──
        info!("cron: {cron_expr}");

        if run_on_start {
            info!("running sync on startup");
            if let Err(e) = agh_sync_core::sync::sync(&cfg).await {
                log::error!("startup sync failed: {e:#}");
            }
        }

        use tokio_cron_scheduler::{Job, JobScheduler};
        let sched = JobScheduler::new().await?;
        let cfg = std::sync::Arc::new(cfg);

        let job = Job::new_async(&cron_expr, {
            let cfg = cfg.clone();
            move |_uuid, _lock| {
                let cfg = cfg.clone();
                Box::pin(async move {
                    info!("cron sync triggered");
                    if let Err(e) = agh_sync_core::sync::sync(&cfg).await {
                        log::error!("cron sync failed: {e:#}");
                    }
                })
            }
        })?;

        sched.add(job).await?;
        sched.start().await?;

        info!("daemon running, press Ctrl+C to stop");
        tokio::signal::ctrl_c().await?;
        info!("shutting down");
    } else {
        // ── Single run ──
        agh_sync_core::sync::sync(&cfg).await?;
        info!("sync complete");
    }

    Ok(())
}
