use anyhow::Result;
use clap::{Parser, Subcommand};
use kernelradar_detectors::privesc::PrivEscDetector;

#[derive(Parser)]
#[command(name = "kernelradar")]
#[command(about = "Behavioral anomaly detection for the Linux kernel")]
#[command(version)]
struct Cli {
    /// Path to config file
    #[arg(long, default_value = "/etc/kernelradar/config.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run all enabled detectors as a daemon
    Daemon,

    /// Run a single detector and print events to stdout
    Detect {
        /// Detector: privesc | bpf-loader | container | kmod
        detector: String,

        /// Path to compiled BPF object directory
        #[arg(long, default_value = "crates/kernelradar-bpf/.output")]
        bpf_dir: String,
    },

    /// Print loaded config and detector status
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
            tracing::info!("daemon mode — Phase 2");
            eprintln!("Daemon not yet implemented (Phase 2).");
        }

        Commands::Detect { detector, bpf_dir } => {
            match detector.as_str() {
                "privesc" => {
                    let obj = format!("{}/privesc.bpf.o", bpf_dir);
                    PrivEscDetector::new(&obj).run().await?;
                }
                other => {
                    eprintln!("Unknown detector: {other}");
                    eprintln!("Available: privesc");
                    std::process::exit(1);
                }
            }
        }

        Commands::Status => {
            println!("kernelradar {}", env!("CARGO_PKG_VERSION"));
            println!("Config: {}", cli.config);
            println!("Detectors:");
            println!("  [1] privesc     ✅ implemented");
            println!("  [2] bpf-loader  — Phase 1 step 2");
            println!("  [3] container   — Phase 2");
            println!("  [4] kmod        — Phase 2");
        }
    }

    Ok(())
}
