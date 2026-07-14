use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod server;
mod templates;

/// Synchronize AdGuardHome config to replica instances.
#[derive(Parser)]
#[command(name = "agh-sync", version = agh_sync_core::VERSION)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a synchronization from origin to replica(s).
    Run {
        /// Path to YAML config file
        #[arg(short, long, default_value = "~/.adguardhome-sync.yaml")]
        config: String,

        /// Cron expression for daemon mode
        #[arg(long)]
        cron: Option<String>,

        /// Run sync on startup
        #[arg(long, default_value = "true")]
        run_on_start: bool,

        /// Print config and exit
        #[arg(long)]
        print_config_only: bool,

        /// Continue on errors
        #[arg(long)]
        continue_on_error: bool,

        /// API port (0 = disabled)
        #[arg(long, default_value = "8080")]
        api_port: u16,

        /// API username
        #[arg(long)]
        api_username: Option<String>,

        /// API password
        #[arg(long)]
        api_password: Option<String>,

        /// API dark mode
        #[arg(long)]
        api_dark_mode: bool,

        // Origin flags
        #[arg(long, env = "ORIGIN_URL")]
        origin_url: Option<String>,
        #[arg(long, env = "ORIGIN_USERNAME")]
        origin_username: Option<String>,
        #[arg(long, env = "ORIGIN_PASSWORD")]
        origin_password: Option<String>,

        // Feature flags
        #[arg(long, default_value = "true")]
        feature_general_settings: bool,
        #[arg(long, default_value = "true")]
        feature_protection_status: bool,
        #[arg(long, default_value = "true")]
        feature_query_log_config: bool,
        #[arg(long, default_value = "true")]
        feature_stats_config: bool,
        #[arg(long, default_value = "true")]
        feature_client_settings: bool,
        #[arg(long, default_value = "true")]
        feature_services: bool,
        #[arg(long, default_value = "true")]
        feature_dns_server_config: bool,
        #[arg(long, default_value = "true")]
        feature_dns_access_lists: bool,
        #[arg(long, default_value = "true")]
        feature_dns_rewrites: bool,
        #[arg(long, default_value = "true")]
        feature_dhcp_server_config: bool,
        #[arg(long, default_value = "true")]
        feature_dhcp_static_leases: bool,
        #[arg(long, default_value = "true")]
        feature_filters_blacklist: bool,
        #[arg(long, default_value = "true")]
        feature_filters_whitelist: bool,
        #[arg(long, default_value = "true")]
        feature_filters_user_rules: bool,
        #[arg(long)]
        feature_theme: bool,
        #[arg(long)]
        feature_tls_config: bool,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            config,
            cron,
            run_on_start,
            print_config_only,
            continue_on_error,
            api_port,
            api_username,
            api_password,
            api_dark_mode,
            origin_url,
            origin_username,
            origin_password,
            feature_general_settings,
            feature_protection_status,
            feature_query_log_config,
            feature_stats_config,
            feature_client_settings,
            feature_services,
            feature_dns_server_config,
            feature_dns_access_lists,
            feature_dns_rewrites,
            feature_dhcp_server_config,
            feature_dhcp_static_leases,
            feature_filters_blacklist,
            feature_filters_whitelist,
            feature_filters_user_rules,
            feature_theme,
            feature_tls_config,
        } => {
            info!("agh-sync v{} starting", agh_sync_core::VERSION);

            // TODO: Load and merge config from file + env + flags
            // TODO: Run sync or start daemon

            let _ = (
                config,
                cron,
                run_on_start,
                print_config_only,
                continue_on_error,
                api_port,
                api_username,
                api_password,
                api_dark_mode,
                origin_url,
                origin_username,
                origin_password,
                feature_general_settings,
                feature_protection_status,
                feature_query_log_config,
                feature_stats_config,
                feature_client_settings,
                feature_services,
                feature_dns_server_config,
                feature_dns_access_lists,
                feature_dns_rewrites,
                feature_dhcp_server_config,
                feature_dhcp_static_leases,
                feature_filters_blacklist,
                feature_filters_whitelist,
                feature_filters_user_rules,
                feature_theme,
                feature_tls_config,
            );
            info!(
                "agh-sync v{} exiting (not yet implemented)",
                agh_sync_core::VERSION
            );
        }
    }
}
