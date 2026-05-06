use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use std::time::Duration;
use kernelradar_core::config::Config;
use kernelradar_detectors::{
    allowlist::SharedAllowlist,
    baseline::{
        in_learning, init_with_config as init_baseline, reset_global as baseline_reset,
        save as baseline_save, snapshot as baseline_snapshot, spawn_periodic_save,
        BaselineConfig,
    },
    bpf_loader::BpfLoaderDetector,
    container::ContainerDetector,
    cred::CredDetector,
    dedup::{init as init_rate_limit, RateLimitConfig},
    fim::FimDetector,
    injection::InjectionDetector,
    kmod::KmodDetector,
    metrics::{
        cumulative_anomalies, cumulative_bursts, cumulative_totals, spawn_hourly_summary,
    },
    network::NetworkDetector,
    output::{detect_systemd_environment, set_output_format, OutputFormat},
    privesc::PrivEscDetector,
};

const DEFAULT_ALLOW: &str = "runc,containerd,dockerd,podman,crio,\
modprobe,kmod,insmod,\
bpftrace,falco,kernelradar,\
sshd,su,sudo,login,polkitd,dbus-daemon,cron,crond,systemd,\
AdGuardHome,systemd-resolved,chronyd,ntpd,timesyncd,\
apt,apt-get,dpkg,unattended-upgr,\
exim4,postfix,sendmail,\
gdb,lldb,strace,ltrace,perf,rr";

const DETECTOR_NAMES: &[&str] = &[
    "privesc", "bpf-loader", "container", "kmod",
    "fim", "network", "injection", "cred",
];

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliFormat { Auto, Plain, Json, Journald }

#[derive(Parser)]
#[command(name = "kernelradar")]
#[command(about = "Behavioral anomaly detection for the Linux kernel")]
#[command(version)]
struct Cli {
    /// Path to TOML config (optional; CLI flags override)
    #[arg(long, default_value = "/etc/kernelradar/config.toml", global = true)]
    config: String,

    #[arg(long, value_enum, default_value = "auto", global = true)]
    format: CliFormat,

    /// Backwards-compat: equivalent to --format=json
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all detectors concurrently (with SIGHUP-driven config reload)
    Daemon {
        #[arg(long, default_value = "crates/kernelradar-bpf/.output")]
        bpf_dir: String,
        /// Default allowlist (used if config doesn't specify per-detector)
        #[arg(long, default_value = DEFAULT_ALLOW)]
        allow: String,
    },

    /// Run a single detector
    Detect {
        detector: String,
        #[arg(long, default_value = "crates/kernelradar-bpf/.output")]
        bpf_dir: String,
        #[arg(long, default_value = DEFAULT_ALLOW)]
        allow: String,
    },

    /// Show detector status and cumulative alert counters
    Status,

    /// Config file management
    #[command(subcommand)]
    ConfigCmd(ConfigSub),

    /// Adaptive baseline management (T-4)
    #[command(subcommand)]
    Baseline(BaselineSub),
}

#[derive(Subcommand)]
enum BaselineSub {
    /// Print the learned baseline as JSON
    Show,
    /// Reset the baseline (delete persistent file + zero in-memory)
    Reset,
    /// Quick status: are we still learning, how many pairs known, etc.
    Status,
}

#[derive(Subcommand)]
enum ConfigSub {
    /// Validate a config file (checks schema, regex compilation)
    Validate {
        /// Path to config to validate (default: --config)
        #[arg(long)]
        path: Option<String>,
    },
    /// Print the resolved effective config (with defaults filled in)
    Show {
        #[arg(long)]
        path: Option<String>,
    },
    /// Print an example TOML to stdout
    Example,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Load config (best-effort) ────────────────────────────────────
    let cfg = Config::from_path(&cli.config).unwrap_or_default();

    // ── Resolve output format ────────────────────────────────────────
    let format = match cli.format {
        CliFormat::Auto => {
            if cli.json {
                OutputFormat::Json
            } else {
                match cfg.global.output_format.as_str() {
                    "plain"    => OutputFormat::Plain,
                    "json"     => OutputFormat::Json,
                    "journald" => OutputFormat::Journald,
                    _ => if detect_systemd_environment() {
                        OutputFormat::Journald
                    } else {
                        OutputFormat::Plain
                    },
                }
            }
        }
        CliFormat::Plain    => OutputFormat::Plain,
        CliFormat::Json     => OutputFormat::Json,
        CliFormat::Journald => OutputFormat::Journald,
    };
    set_output_format(format);

    // ── Init tracing ─────────────────────────────────────────────────
    let env_filter_str = if cfg.global.log_level == "info" || cfg.global.log_level.is_empty() {
        "kernelradar=info,kernelradar.alert=info,kernelradar.summary=info".to_string()
    } else {
        cfg.global.log_level.clone()
    };
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(env_filter_str));

    match format {
        OutputFormat::Journald => {
            let layer = tracing_journald::layer()
                .map_err(|e| anyhow::anyhow!("journald layer: {e}"))?;
            tracing_subscriber::registry()
                .with(env_filter).with(layer).init();
        }
        OutputFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        OutputFormat::Plain => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    }

    // Initialise rate limiter from config
    let rl_cfg = &cfg.ratelimit;
    init_rate_limit(RateLimitConfig {
        window:           Duration::from_secs(rl_cfg.window_secs),
        window_max:       rl_cfg.window_max,
        burst_threshold:  rl_cfg.burst_threshold,
        burst_window:     Duration::from_secs(rl_cfg.burst_window_secs),
        backoff_initial:  Duration::from_secs(rl_cfg.backoff_initial_secs),
        backoff_max:      Duration::from_secs(rl_cfg.backoff_max_secs),
    });

    // Initialise baseline (T-4) — load from disk if present
    if cfg.baseline.enabled {
        init_baseline(BaselineConfig {
            learning_secs:      cfg.baseline.learning_secs,
            score_threshold:    cfg.baseline.score_threshold,
            alpha:              cfg.baseline.alpha,
            save_path:          cfg.baseline.save_path.clone(),
            save_interval_secs: cfg.baseline.save_interval_secs,
        });
    }

    if matches!(cli.command, Commands::Daemon { .. }) {
        spawn_hourly_summary();
        if cfg.baseline.enabled {
            spawn_periodic_save();
        }
    }

    match cli.command {
        Commands::Daemon { bpf_dir, allow } => {
            run_daemon(&bpf_dir, &allow, &cli.config, &cfg).await?;
        }
        Commands::Detect { detector, bpf_dir, allow } => {
            let fallback = parse_allow(&allow);
            let al = SharedAllowlist::new(cfg.allowlist_for(&detector, &fallback));
            run_single_detector(&detector, &bpf_dir, al).await?;
        }
        Commands::Status => {
            print_status();
        }
        Commands::ConfigCmd(ConfigSub::Validate { path }) => {
            let p = path.as_deref().unwrap_or(&cli.config);
            let c = Config::from_path(p)?;
            let issues = c.validate();
            if issues.is_empty() {
                println!("✓ {p}: valid");
            } else {
                eprintln!("✗ {p}: {} issue(s):", issues.len());
                for i in issues { eprintln!("  • {i}"); }
                std::process::exit(1);
            }
        }
        Commands::ConfigCmd(ConfigSub::Show { path }) => {
            let p = path.as_deref().unwrap_or(&cli.config);
            let c = Config::from_path(p).unwrap_or_default();
            println!("{}", toml::to_string_pretty(&c).unwrap_or_default());
        }
        Commands::ConfigCmd(ConfigSub::Example) => {
            print!("{}", EXAMPLE_CONFIG);
        }
        Commands::Baseline(BaselineSub::Show) => {
            let snap = baseline_snapshot();
            println!("{}", serde_json::to_string_pretty(&snap)?);
        }
        Commands::Baseline(BaselineSub::Reset) => {
            baseline_reset();
            // Also delete persistent file so a daemon restart doesn't reload it
            let path = cfg.baseline.save_path.clone();
            let _ = std::fs::remove_file(&path);
            println!("baseline reset; removed {}", path);
        }
        Commands::Baseline(BaselineSub::Status) => {
            let snap = baseline_snapshot();
            println!("Baseline:");
            println!("  started:        {}", snap.started);
            println!("  in_learning:    {}", in_learning());
            println!("  learning_secs:  {}", snap.config.learning_secs);
            println!("  threshold:      {} σ", snap.config.score_threshold);
            println!("  alpha:          {}", snap.config.alpha);
            println!("  save_path:      {}", snap.config.save_path);
            println!("  pairs_observed: {}", snap.pairs.len());
            let total: u64 = snap.pairs.values().map(|p| p.total).sum();
            println!("  total_events:   {}", total);
        }
    }

    Ok(())
}

async fn run_single_detector(name: &str, bpf_dir: &str, al: SharedAllowlist) -> Result<()> {
    match name {
        "privesc"     => PrivEscDetector::new(&format!("{bpf_dir}/privesc.bpf.o"),    al).run().await,
        "bpf-loader"  => BpfLoaderDetector::new(&format!("{bpf_dir}/bpf_loader.bpf.o"), al).run().await,
        "container"   => ContainerDetector::new(&format!("{bpf_dir}/container.bpf.o"), al).run().await,
        "kmod"        => KmodDetector::new(&format!("{bpf_dir}/kmod.bpf.o"),         al).run().await,
        "fim"         => FimDetector::new(&format!("{bpf_dir}/fim.bpf.o"),          al).run().await,
        "network"     => NetworkDetector::new(&format!("{bpf_dir}/network.bpf.o"),    al).run().await,
        "injection"   => InjectionDetector::new(&format!("{bpf_dir}/injection.bpf.o"), al).run().await,
        "cred"        => CredDetector::new(&format!("{bpf_dir}/cred.bpf.o"),         al).run().await,
        other         => {
            eprintln!("Unknown detector: {other}");
            eprintln!("Available: {}", DETECTOR_NAMES.join(" | "));
            std::process::exit(1);
        }
    }
}

fn print_status() {
    println!("kernelradar {}", env!("CARGO_PKG_VERSION"));
    println!("Detectors:");
    for (i, n) in DETECTOR_NAMES.iter().enumerate() {
        println!("  [{}] {:12} ✅", i + 1, n);
    }
    let totals = cumulative_totals();
    if !totals.is_empty() {
        println!("\nCumulative alerts (this process):");
        for ((det, sev), n) in totals {
            println!("  {det}/{sev}: {n}");
        }
    }
    let bursts = cumulative_bursts();
    if !bursts.is_empty() {
        println!("\nBursts detected (this process):");
        for (det, n) in bursts {
            println!("  {det}: {n}");
        }
    }
    let anomalies = cumulative_anomalies();
    if !anomalies.is_empty() {
        println!("\nAnomalies detected (this process):");
        for (det, n) in anomalies {
            println!("  {det}: {n}");
        }
    }
}

fn parse_allow(s: &str) -> Vec<String> {
    s.split(',').map(|e| e.trim().to_string()).collect()
}

async fn run_daemon(
    bpf_dir:    &str,
    cli_allow:  &str,
    config_path: &str,
    cfg:        &Config,
) -> Result<()> {
    let fallback = parse_allow(cli_allow);

    // Per-detector SharedAllowlist
    let mut shared: std::collections::BTreeMap<&'static str, SharedAllowlist>
        = std::collections::BTreeMap::new();
    for &name in DETECTOR_NAMES {
        let lst = cfg.allowlist_for(name, &fallback);
        shared.insert(name, SharedAllowlist::new(lst));
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = config_path,
        detectors = DETECTOR_NAMES.len(),
        "kernelradar daemon starting"
    );

    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let dir = bpf_dir.to_string();

    macro_rules! spawn_detector {
        ($name:expr, $obj:expr, $det:ident) => {
            if cfg.detector_enabled($name) {
                let obj  = format!("{dir}/{}", $obj);
                let al   = shared.get($name).cloned().unwrap();
                handles.push(tokio::spawn(async move {
                    if let Err(e) = $det::new(&obj, al).run().await {
                        tracing::error!("{}: {e}", $name);
                    }
                }));
            } else {
                tracing::info!(detector = $name, "disabled in config");
            }
        };
    }

    spawn_detector!("privesc",    "privesc.bpf.o",    PrivEscDetector);
    spawn_detector!("bpf-loader", "bpf_loader.bpf.o", BpfLoaderDetector);
    spawn_detector!("container",  "container.bpf.o",  ContainerDetector);
    spawn_detector!("kmod",       "kmod.bpf.o",       KmodDetector);
    spawn_detector!("fim",        "fim.bpf.o",        FimDetector);
    spawn_detector!("network",    "network.bpf.o",    NetworkDetector);
    spawn_detector!("injection",  "injection.bpf.o",  InjectionDetector);
    spawn_detector!("cred",       "cred.bpf.o",       CredDetector);

    // SIGHUP handler — re-load config and update allowlists in place
    spawn_sighup_handler(config_path.to_string(), shared, fallback);

    // Wait for any detector to finish (Ctrl+C propagates inside detector loops)
    if !handles.is_empty() {
        let (_, _, _) = futures_select(handles).await;
    }
    tracing::info!("kernelradar daemon stopped");
    Ok(())
}

fn spawn_sighup_handler(
    config_path: String,
    shared: std::collections::BTreeMap<&'static str, SharedAllowlist>,
    fallback: Vec<String>,
) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        tokio::spawn(async move {
            let mut sig = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("cannot install SIGHUP handler: {e}");
                    return;
                }
            };
            loop {
                if sig.recv().await.is_none() { break; }
                tracing::info!(config = %config_path, "SIGHUP received — reloading config");
                match Config::from_path(&config_path) {
                    Ok(new_cfg) => {
                        let issues = new_cfg.validate();
                        if !issues.is_empty() {
                            for i in issues {
                                tracing::error!("config issue: {i}");
                            }
                            tracing::warn!("reload aborted — fix config first");
                            continue;
                        }
                        for (name, sl) in &shared {
                            let lst = new_cfg.allowlist_for(name, &fallback);
                            sl.replace(lst);
                        }
                        tracing::info!("config reload complete");
                    }
                    Err(e) => tracing::error!("reload failed: {e}"),
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = (config_path, shared, fallback);
    }
}

/// Minimal "wait for any of a Vec of JoinHandles to finish".
async fn futures_select(mut handles: Vec<tokio::task::JoinHandle<()>>)
    -> (Vec<tokio::task::JoinHandle<()>>, (), ())
{
    if handles.is_empty() {
        return (handles, (), ());
    }
    let mut iter = handles.drain(..);
    let first = iter.next().unwrap();
    let _ = first.await;
    (Vec::new(), (), ())
}

const EXAMPLE_CONFIG: &str = r#"# /etc/kernelradar/config.toml — example

[global]
log_level     = "info"
output_format = "auto"   # auto | plain | json | journald

[ratelimit]
# Sliding window: max emissions per (detector, comm, event_type) per window
window_secs = 60
window_max  = 10
# Burst detection: same key fires this many times in burst_window → BURST alert
burst_threshold   = 100
burst_window_secs = 1
# Exponential backoff after window cap exceeded (seconds; doubles per recurrence)
backoff_initial_secs = 60
backoff_max_secs     = 3600

[baseline]
# Adaptive anomaly scoring: learn normal rates per (detector, comm, hour-of-day),
# then emit synthetic ANOMALY alerts when activity deviates by ≥ score_threshold σ.
enabled            = true
learning_secs      = 86400   # 24 hours warm-up before scoring
score_threshold    = 3.0     # 3-sigma threshold
alpha              = 0.10    # EWMA smoothing factor (smaller = more inertia)
save_path          = "/var/lib/kernelradar/baseline.json"
save_interval_secs = 300     # save every 5 minutes

# Allowlist entries:
#   "exact"        — match comm or basename(exe)
#   "/regex.*/"    — Rust regex against comm/exe
#
# Detector-specific allowlists override the global default.

[detectors.privesc]
enabled   = true
allowlist = [
    "sshd", "su", "sudo", "login",
    "polkitd", "dbus-daemon", "cron", "crond", "systemd",
    "exim4", "postfix",
]

[detectors.bpf-loader]
enabled   = true
allowlist = ["bpftrace", "falco", "kernelradar"]

[detectors.container]
enabled   = true
allowlist = ["runc", "containerd", "dockerd", "podman", "crio"]

[detectors.kmod]
enabled   = true
allowlist = ["modprobe", "kmod", "insmod"]

[detectors.fim]
enabled = true

[detectors.network]
enabled   = true
allowlist = [
    "AdGuardHome", "systemd-resolved", "chronyd", "ntpd", "timesyncd",
    "apt", "apt-get", "dpkg", "unattended-upgr",
]

[detectors.injection]
enabled   = true
allowlist = ["gdb", "lldb", "strace", "ltrace", "perf", "rr"]

[detectors.cred]
enabled = true
"#;
