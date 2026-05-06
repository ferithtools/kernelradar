use anyhow::Result;
use clap::{Parser, Subcommand};
use kernelradar_detectors::bpf_loader::BpfLoaderDetector;
use kernelradar_detectors::privesc::PrivEscDetector;

#[derive(Parser)]
#[command(name = "kernelradar")]
#[command(about = "Behavioral anomaly detection for the Linux kernel")]
#[command(version)]
struct Cli {
    #[arg(long, default_value = "/etc/kernelradar/config.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all enabled detectors as a daemon
    Daemon,

    /// Run a single detector, print events to stdout
    Detect {
        /// Detector name: privesc | bpf-loader
        detector: String,

        /// Directory containing compiled BPF .o files
        #[arg(long, default_value = "crates/kernelradar-bpf/.output")]
        bpf_dir: String,

        /// Comma-separated allowlist for bpf-loader (process names)
        #[arg(long, default_value = "bpftrace,falco,kernelradar")]
        allow: String,
    },

    /// Show detector status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("kernelradar=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon => {
            eprintln!("Daemon mode — Phase 2.");
        }

        Commands::Detect { detector, bpf_dir, allow } => {
            match detector.as_str() {
                "privesc" => {
                    let obj = format!("{}/privesc.bpf.o", bpf_dir);
                    PrivEscDetector::new(&obj).run().await?;
                }
                "bpf-loader" => {
                    let obj = format!("{}/bpf_loader.bpf.o", bpf_dir);
                    let allowlist = allow
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                    BpfLoaderDetector::new(&obj, allowlist).run().await?;
                }
                other => {
                    eprintln!("Unknown detector: {other}");
                    eprintln!("Available: privesc | bpf-loader");
                    std::process::exit(1);
                }
            }
        }

        Commands::Status => {
            println!("kernelradar {}", env!("CARGO_PKG_VERSION"));
            println!("Detectors:");
            println!("  [1] privesc     ✅ ready");
            println!("  [2] bpf-loader  ✅ ready");
            println!("  [3] container   — Phase 2");
            println!("  [4] kmod        — Phase 2");
        }
    }

    Ok(())
}
