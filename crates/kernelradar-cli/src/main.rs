use anyhow::Result;
use clap::{Parser, Subcommand};
use kernelradar_detectors::{
    bpf_loader::BpfLoaderDetector,
    container::ContainerDetector,
    kmod::KmodDetector,
    privesc::PrivEscDetector,
};

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
    /// Run all detectors concurrently (daemon mode)
    Daemon {
        #[arg(long, default_value = "crates/kernelradar-bpf/.output")]
        bpf_dir: String,
        #[arg(long, default_value = "bpftrace,falco,kernelradar,modprobe,kmod,insmod")]
        allow: String,
    },

    /// Run a single detector
    Detect {
        /// privesc | bpf-loader | container | kmod
        detector: String,
        #[arg(long, default_value = "crates/kernelradar-bpf/.output")]
        bpf_dir: String,
        #[arg(long, default_value = "bpftrace,falco,kernelradar,modprobe,kmod,insmod")]
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
        Commands::Daemon { bpf_dir, allow } => {
            run_daemon(&bpf_dir, &allow).await?;
        }

        Commands::Detect { detector, bpf_dir, allow } => {
            let allowlist = parse_allow(&allow);
            match detector.as_str() {
                "privesc" => {
                    PrivEscDetector::new(
                        &format!("{bpf_dir}/privesc.bpf.o")
                    ).run().await?;
                }
                "bpf-loader" => {
                    BpfLoaderDetector::new(
                        &format!("{bpf_dir}/bpf_loader.bpf.o"),
                        allowlist,
                    ).run().await?;
                }
                "container" => {
                    ContainerDetector::new(
                        &format!("{bpf_dir}/container.bpf.o"),
                        allowlist,
                    ).run().await?;
                }
                "kmod" => {
                    KmodDetector::new(
                        &format!("{bpf_dir}/kmod.bpf.o"),
                        allowlist,
                    ).run().await?;
                }
                other => {
                    eprintln!("Unknown detector: {other}");
                    eprintln!("Available: privesc | bpf-loader | container | kmod");
                    std::process::exit(1);
                }
            }
        }

        Commands::Status => {
            println!("kernelradar {}", env!("CARGO_PKG_VERSION"));
            println!("Detectors:");
            println!("  [1] privesc     ✅ Phase 1");
            println!("  [2] bpf-loader  ✅ Phase 1");
            println!("  [3] container   ✅ Phase 2");
            println!("  [4] kmod        ✅ Phase 2");
        }
    }

    Ok(())
}

fn parse_allow(allow: &str) -> Vec<String> {
    allow.split(',').map(|s| s.trim().to_string()).collect()
}

async fn run_daemon(bpf_dir: &str, allow: &str) -> Result<()> {
    let allowlist = parse_allow(allow);
    println!("kernelradar daemon starting — all 4 detectors");
    println!("BPF dir:   {bpf_dir}");
    println!("Allowlist: {allow}");
    println!("Press Ctrl+C to stop all.\n");

    // Spawn all 4 detectors as independent tokio tasks.
    // Each task owns its Ebpf instance; all auto-unload on drop.
    let d1 = {
        let obj = format!("{bpf_dir}/privesc.bpf.o");
        tokio::spawn(async move {
            if let Err(e) = PrivEscDetector::new(&obj).run().await {
                tracing::error!("privesc: {e}");
            }
        })
    };

    let d2 = {
        let obj = format!("{bpf_dir}/bpf_loader.bpf.o");
        let al  = allowlist.clone();
        tokio::spawn(async move {
            if let Err(e) = BpfLoaderDetector::new(&obj, al).run().await {
                tracing::error!("bpf-loader: {e}");
            }
        })
    };

    let d3 = {
        let obj = format!("{bpf_dir}/container.bpf.o");
        let al  = allowlist.clone();
        tokio::spawn(async move {
            if let Err(e) = ContainerDetector::new(&obj, al).run().await {
                tracing::error!("container: {e}");
            }
        })
    };

    let d4 = {
        let obj = format!("{bpf_dir}/kmod.bpf.o");
        let al  = allowlist.clone();
        tokio::spawn(async move {
            if let Err(e) = KmodDetector::new(&obj, al).run().await {
                tracing::error!("kmod: {e}");
            }
        })
    };

    // Wait for any task to finish (Ctrl+C propagates via signal::ctrl_c
    // inside each detector's run loop)
    tokio::select! {
        _ = d1 => {}
        _ = d2 => {}
        _ = d3 => {}
        _ = d4 => {}
    }

    println!("\nkernelradar daemon stopped.");
    Ok(())
}
