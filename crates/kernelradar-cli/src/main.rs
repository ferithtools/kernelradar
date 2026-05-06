use anyhow::Result;
use clap::{Parser, Subcommand};

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
        /// Detector name: privesc | bpf-loader | container | kmod
        detector: String,
    },

    /// Print loaded config and detector status
    Status,

    /// Run a self-test: generates a synthetic detectable event
    Test {
        /// Detector to test
        detector: String,
    },
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
            tracing::info!("kernelradar daemon starting");
            // TODO: Phase 1 — load BPF programs, start event loop
            eprintln!("Daemon not yet implemented. Phase 1 in progress.");
        }

        Commands::Detect { detector } => {
            tracing::info!(%detector, "starting single-detector mode");
            eprintln!("Single detector mode: {} — Phase 1 in progress.", detector);
        }

        Commands::Status => {
            println!("kernelradar {}", env!("CARGO_PKG_VERSION"));
            println!("Config: {}", cli.config);
            println!("Detectors:");
            println!("  [1] privesc     — planned");
            println!("  [2] bpf-loader  — planned");
            println!("  [3] container   — planned");
            println!("  [4] kmod        — planned");
        }

        Commands::Test { detector } => {
            eprintln!("Test mode: {} — Phase 1 in progress.", detector);
        }
    }

    Ok(())
}
