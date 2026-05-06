use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use kernelradar_detectors::{
    bpf_loader::BpfLoaderDetector,
    container::ContainerDetector,
    cred::CredDetector,
    fim::FimDetector,
    injection::InjectionDetector,
    kmod::KmodDetector,
    metrics::{cumulative_totals, spawn_hourly_summary},
    network::NetworkDetector,
    output::{detect_systemd_environment, set_output_format, OutputFormat},
    privesc::PrivEscDetector,
};

// DEFAULT_ALLOW covers (groups separated):
//   - Container runtimes
//   - Module management
//   - BPF tooling
//   - Legitimate setuid users (sshd privsep, sudo/su/login, PAM)
//   - Network-noisy legitimate processes (DNS, NTP, package managers)
//   - Mail / system daemons
//   - Debugging tools (gdb, strace, etc.)
const DEFAULT_ALLOW: &str = "runc,containerd,dockerd,podman,crio,\
modprobe,kmod,insmod,\
bpftrace,falco,kernelradar,\
sshd,su,sudo,login,polkitd,dbus-daemon,cron,crond,systemd,\
AdGuardHome,systemd-resolved,chronyd,ntpd,timesyncd,\
apt,apt-get,dpkg,unattended-upgr,\
exim4,postfix,sendmail,\
gdb,lldb,strace,ltrace,perf,rr";

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliFormat { Auto, Plain, Json, Journald }

#[derive(Parser)]
#[command(name = "kernelradar")]
#[command(about = "Behavioral anomaly detection for the Linux kernel")]
#[command(version)]
struct Cli {
    #[arg(long, default_value = "/etc/kernelradar/config.toml")]
    config: String,

    /// Output format. `auto` picks `journald` under systemd, otherwise `plain`.
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
    /// Run all detectors concurrently
    Daemon {
        #[arg(long, default_value = "crates/kernelradar-bpf/.output")]
        bpf_dir: String,
        #[arg(long, default_value = DEFAULT_ALLOW)]
        allow: String,
    },

    /// Run a single detector
    Detect {
        /// privesc | bpf-loader | container | kmod | fim | network | injection | cred
        detector: String,
        #[arg(long, default_value = "crates/kernelradar-bpf/.output")]
        bpf_dir: String,
        #[arg(long, default_value = DEFAULT_ALLOW)]
        allow: String,
    },

    /// Show detector status and cumulative alert counters
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ── Resolve output format ────────────────────────────────────────
    let format = match cli.format {
        CliFormat::Auto => {
            if cli.json {
                OutputFormat::Json
            } else if detect_systemd_environment() {
                OutputFormat::Journald
            } else {
                OutputFormat::Plain
            }
        }
        CliFormat::Plain    => OutputFormat::Plain,
        CliFormat::Json     => OutputFormat::Json,
        CliFormat::Journald => OutputFormat::Journald,
    };
    set_output_format(format);

    // ── Initialise tracing subscriber ────────────────────────────────
    // EnvFilter honours RUST_LOG (T-1.6: per-target levels), with
    // sensible defaults if RUST_LOG is unset.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("kernelradar=info,kernelradar.alert=info,kernelradar.summary=info"));

    match format {
        OutputFormat::Journald => {
            // Structured fields → systemd journal as DETECTOR=, PID=, ...
            let layer = tracing_journald::layer()
                .map_err(|e| anyhow::anyhow!("journald layer: {e}"))?;
            tracing_subscriber::registry()
                .with(env_filter)
                .with(layer)
                .init();
        }
        OutputFormat::Json => {
            // JSON formatter writes to stdout — alerts go via emit_json
            // (println), and any tracing events also as JSON.
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

    // Hourly metric summary (T-1.7) — runs in background for daemon
    if matches!(cli.command, Commands::Daemon { .. }) {
        spawn_hourly_summary();
    }

    match cli.command {
        Commands::Daemon { bpf_dir, allow } => {
            run_daemon(&bpf_dir, &allow).await?;
        }
        Commands::Detect { detector, bpf_dir, allow } => {
            let al = parse_allow(&allow);
            match detector.as_str() {
                "privesc" => {
                    PrivEscDetector::new(&format!("{bpf_dir}/privesc.bpf.o"), al)
                        .run().await?;
                }
                "bpf-loader" => {
                    BpfLoaderDetector::new(&format!("{bpf_dir}/bpf_loader.bpf.o"), al)
                        .run().await?;
                }
                "container" => {
                    ContainerDetector::new(&format!("{bpf_dir}/container.bpf.o"), al)
                        .run().await?;
                }
                "kmod" => {
                    KmodDetector::new(&format!("{bpf_dir}/kmod.bpf.o"), al)
                        .run().await?;
                }
                "fim" => {
                    FimDetector::new(&format!("{bpf_dir}/fim.bpf.o"), al)
                        .run().await?;
                }
                "network" => {
                    NetworkDetector::new(&format!("{bpf_dir}/network.bpf.o"), al)
                        .run().await?;
                }
                "injection" => {
                    InjectionDetector::new(&format!("{bpf_dir}/injection.bpf.o"), al)
                        .run().await?;
                }
                "cred" => {
                    CredDetector::new(&format!("{bpf_dir}/cred.bpf.o"), al)
                        .run().await?;
                }
                other => {
                    eprintln!("Unknown detector: {other}");
                    eprintln!("Available: privesc | bpf-loader | container | kmod \
                               | fim | network | injection | cred");
                    std::process::exit(1);
                }
            }
        }
        Commands::Status => {
            println!("kernelradar {}", env!("CARGO_PKG_VERSION"));
            println!("Detectors:");
            println!("  [1] privesc     ✅");
            println!("  [2] bpf-loader  ✅");
            println!("  [3] container   ✅");
            println!("  [4] kmod        ✅");
            println!("  [5] fim         ✅");
            println!("  [6] network     ✅");
            println!("  [7] injection   ✅");
            println!("  [8] cred        ✅");
            let totals = cumulative_totals();
            if !totals.is_empty() {
                println!("\nCumulative alerts (this process):");
                for ((det, sev), n) in totals {
                    println!("  {det}/{sev}: {n}");
                }
            }
        }
    }

    Ok(())
}

fn parse_allow(s: &str) -> Vec<String> {
    s.split(',').map(|e| e.trim().to_string()).collect()
}

async fn run_daemon(bpf_dir: &str, allow: &str) -> Result<()> {
    let al = parse_allow(allow);
    tracing::info!(version = env!("CARGO_PKG_VERSION"),
                   detectors = 8,
                   "kernelradar daemon starting");

    let d1 = { let (o, a) = (format!("{bpf_dir}/privesc.bpf.o"), al.clone());
        tokio::spawn(async move {
            if let Err(e) = PrivEscDetector::new(&o, a).run().await {
                tracing::error!("privesc: {e}");
            }
        })
    };
    let d2 = { let (o, a) = (format!("{bpf_dir}/bpf_loader.bpf.o"), al.clone());
        tokio::spawn(async move {
            if let Err(e) = BpfLoaderDetector::new(&o, a).run().await {
                tracing::error!("bpf-loader: {e}");
            }
        })
    };
    let d3 = { let (o, a) = (format!("{bpf_dir}/container.bpf.o"), al.clone());
        tokio::spawn(async move {
            if let Err(e) = ContainerDetector::new(&o, a).run().await {
                tracing::error!("container: {e}");
            }
        })
    };
    let d4 = { let (o, a) = (format!("{bpf_dir}/kmod.bpf.o"), al.clone());
        tokio::spawn(async move {
            if let Err(e) = KmodDetector::new(&o, a).run().await {
                tracing::error!("kmod: {e}");
            }
        })
    };
    let d5 = { let (o, a) = (format!("{bpf_dir}/fim.bpf.o"), al.clone());
        tokio::spawn(async move {
            if let Err(e) = FimDetector::new(&o, a).run().await {
                tracing::error!("fim: {e}");
            }
        })
    };
    let d6 = { let (o, a) = (format!("{bpf_dir}/network.bpf.o"), al.clone());
        tokio::spawn(async move {
            if let Err(e) = NetworkDetector::new(&o, a).run().await {
                tracing::error!("network: {e}");
            }
        })
    };
    let d7 = { let (o, a) = (format!("{bpf_dir}/injection.bpf.o"), al.clone());
        tokio::spawn(async move {
            if let Err(e) = InjectionDetector::new(&o, a).run().await {
                tracing::error!("injection: {e}");
            }
        })
    };
    let d8 = { let (o, a) = (format!("{bpf_dir}/cred.bpf.o"), al.clone());
        tokio::spawn(async move {
            if let Err(e) = CredDetector::new(&o, a).run().await {
                tracing::error!("cred: {e}");
            }
        })
    };

    tokio::select! {
        _ = d1 => {}  _ = d2 => {}  _ = d3 => {}  _ = d4 => {}
        _ = d5 => {}  _ = d6 => {}  _ = d7 => {}  _ = d8 => {}
    }

    tracing::info!("kernelradar daemon stopped");
    Ok(())
}
