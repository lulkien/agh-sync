//! agh-sync — synchronize AdGuardHome config to replica instances.
//!
//! Usage:
//!   agh-sync run                      # single sync
//!   agh-sync run --watch              # daemon, sync on config change
//!   agh-sync run --print-config-only  # debug config

use anyhow::Result;
use clap::Parser;
use log::info;

use agh_sync_core::config::{self, CliOverrides};
use notify::Watcher;

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

        /// Watch config file and sync on changes (daemon mode)
        #[arg(long)]
        watch: bool,

        /// Run sync immediately on startup (watch mode only)
        #[arg(long, default_value = "true")]
        run_on_start: bool,

        /// Print merged config and exit
        #[arg(long)]
        print_config_only: bool,

        /// Verbose logging (show diff details)
        #[arg(long)]
        verbose: bool,

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

fn setup_logger(verbose: bool) -> Result<()> {
    let level = if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(level)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let Commands::Run {
        config,
        watch,
        run_on_start,
        print_config_only,
        verbose,
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

    setup_logger(verbose)?;

    let overrides = CliOverrides {
        cron: None,
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

    if watch {
        // ── Watch daemon ──
        let watch_path = match &cfg.origin.config_path {
            Some(p) => {
                let expanded = p.replace('~', &std::env::var("HOME").unwrap_or_default());
                info!("watching AdGuardHome config: {expanded}");
                expanded
            }
            None => {
                anyhow::bail!("--watch requires origin.configPath to be set in the config file");
            }
        };

        if run_on_start {
            info!("running sync on startup");
            if let Err(e) = agh_sync_core::sync::sync(&cfg).await {
                log::error!("startup sync failed: {e:#}");
            }
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let file_name = std::path::Path::new(&watch_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let dir_path = std::path::Path::new(&watch_path)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let mut watcher =
            notify::recommended_watcher(move |event: Result<notify::Event, notify::Error>| {
                if let Ok(event) = event {
                    let matches = event.paths.iter().any(|p| {
                        p.file_name()
                            .map(|n| n == file_name.as_str())
                            .unwrap_or(false)
                    });
                    if matches && (event.kind.is_modify() || event.kind.is_create()) {
                        let _ = tx.blocking_send(());
                    }
                }
            })?;

        watcher.watch(&dir_path, notify::RecursiveMode::NonRecursive)?;

        info!("daemon running, watching {watch_path}. Press Ctrl+C to stop");

        let debounce = std::time::Duration::from_secs(cfg.debounce_seconds);
        let mut timer: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
        let mut last_event = tokio::time::Instant::now();
        let dedup_window = std::time::Duration::from_millis(500);

        loop {
            let signal = tokio::signal::ctrl_c();
            tokio::pin!(signal);

            if let Some(ref mut t) = timer {
                tokio::select! {
                    _ = &mut signal => { info!("shutting down"); break; }
                    () = t.as_mut() => {
                        timer = None;
                        info!("quiet period elapsed, syncing");
                        let mut sync_cfg = match config::load_config(&config, CliOverrides::default()) {
                            Ok(c) => c,
                            Err(e) => { log::error!("config reload failed: {e}"); continue; }
                        };
                        if let Err(e) = sync_cfg.init() { log::error!("config init failed: {e}"); continue; }
                        if let Err(e) = agh_sync_core::sync::sync(&sync_cfg).await {
                            log::error!("sync failed: {e:#}");
                        }
                    }
                    Some(()) = rx.recv() => {
                        let now = tokio::time::Instant::now();
                        if now - last_event >= dedup_window {
                            t.as_mut().reset(now + debounce);
                            info!("config changed, sync in {}s", debounce.as_secs());
                        }
                        last_event = now;
                    }
                }
            } else {
                tokio::select! {
                    _ = &mut signal => { info!("shutting down"); break; }
                    Some(()) = rx.recv() => {
                        let now = tokio::time::Instant::now();
                        if now - last_event >= dedup_window {
                            timer = Some(Box::pin(tokio::time::sleep_until(now + debounce)));
                            info!("config changed, sync in {}s", debounce.as_secs());
                        }
                        last_event = now;
                    }
                }
            }
        }
    } else {
        // ── Single run ──
        agh_sync_core::sync::sync(&cfg).await?;
        info!("sync complete");
    }

    Ok(())
}
