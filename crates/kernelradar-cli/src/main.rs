use anyhow::Result;
use clap::{Parser, Subcommand};
use kernelradar_detectors::{
    bpf_loader::BpfLoaderDetector,
    container::ContainerDetector,
    fim::FimDetector,
    kmod::KmodDetector,
    network::NetworkDetector,
    privesc::PrivEscDetector,
};

// Default allowlist covers:
//   - container runtimes (runc, containerd, dockerd...)
//   - module management (modprobe, kmod, insmod)
//   - BPF tooling (bpftrace, falco, kernelradar)
//   - legitimate setuid users (sshd does privsep, su/sudo/login/polkitd
//     transition uid by design; PAM/systemd often need root credentials)
// DEFAULT_ALLOW covers (groups separated):
//   - Container runtimes: runc, containerd, dockerd, podman, crio
//   - Module management: modprobe, kmod, insmod
//   - BPF tooling: bpftrace, falco, kernelradar
//   - Legitimate setuid users (sshd privsep, sudo/su/login, PAM)
//   - Network-noisy legitimate processes (DNS, NTP, package managers)
//   - Mail / system daemons
const DEFAULT_ALLOW: &str = "runc,containerd,dockerd,podman,crio,\
modprobe,kmod,insmod,\
bpftrace,falco,kernelradar,\
sshd,su,sudo,login,polkitd,dbus-daemon,cron,crond,systemd,\
AdGuardHome,systemd-resolved,chronyd,ntpd,timesyncd,\
apt,apt-get,dpkg,unattended-upgr,\
exim4,postfix,sendmail";

#[derive(Parser)]
#[command(name = "kernelradar")]
#[command(about = "Behavioral anomaly detection for the Linux kernel")]
#[command(version)]
struct Cli {
    #[arg(long, default_value = "/etc/kernelradar/config.toml")]
    config: String,

    /// Output alerts as JSON (one object per line)
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
        /// privesc | bpf-loader | container | kmod
        detector: String,
        #[arg(long, default_value = "crates/kernelradar-bpf/.output")]
        bpf_dir: String,
        #[arg(long, default_value = DEFAULT_ALLOW)]
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
    let json = cli.json;

    match cli.command {
        Commands::Daemon { bpf_dir, allow } => {
            run_daemon(&bpf_dir, &allow, json).await?;
        }
        Commands::Detect { detector, bpf_dir, allow } => {
            let al = parse_allow(&allow);
            match detector.as_str() {
                "privesc" => {
                    let mut d = PrivEscDetector::new(
                        &format!("{bpf_dir}/privesc.bpf.o"), al);
                    d.json = json;
                    d.run().await?;
                }
                "bpf-loader" => {
                    let mut d = BpfLoaderDetector::new(
                        &format!("{bpf_dir}/bpf_loader.bpf.o"), al);
                    d.json = json;
                    d.run().await?;
                }
                "container" => {
                    let mut d = ContainerDetector::new(
                        &format!("{bpf_dir}/container.bpf.o"), al);
                    d.json = json;
                    d.run().await?;
                }
                "kmod" => {
                    let mut d = KmodDetector::new(
                        &format!("{bpf_dir}/kmod.bpf.o"), al);
                    d.json = json;
                    d.run().await?;
                }
                "fim" => {
                    let mut d = FimDetector::new(
                        &format!("{bpf_dir}/fim.bpf.o"), al);
                    d.json = json;
                    d.run().await?;
                }
                "network" => {
                    let mut d = NetworkDetector::new(
                        &format!("{bpf_dir}/network.bpf.o"), al);
                    d.json = json;
                    d.run().await?;
                }
                other => {
                    eprintln!("Unknown detector: {other}");
                    eprintln!("Available: privesc | bpf-loader | container | kmod | fim | network");
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
        }
    }
    Ok(())
}

fn parse_allow(s: &str) -> Vec<String> {
    s.split(',').map(|e| e.trim().to_string()).collect()
}

async fn run_daemon(bpf_dir: &str, allow: &str, json: bool) -> Result<()> {
    let al = parse_allow(allow);
    if !json {
        println!("kernelradar {}", env!("CARGO_PKG_VERSION"));
        println!("daemon mode — 6 detectors active");
        println!("Allowlist: {allow}");
        println!("Press Ctrl+C to stop.\n");
    }

    let d1 = { let (o, a) = (format!("{bpf_dir}/privesc.bpf.o"), al.clone());
        tokio::spawn(async move {
            let mut d = PrivEscDetector::new(&o, a); d.json = json;
            if let Err(e) = d.run().await { tracing::error!("privesc: {e}"); }
        })
    };
    let d2 = { let (o, a) = (format!("{bpf_dir}/bpf_loader.bpf.o"), al.clone());
        tokio::spawn(async move {
            let mut d = BpfLoaderDetector::new(&o, a); d.json = json;
            if let Err(e) = d.run().await { tracing::error!("bpf-loader: {e}"); }
        })
    };
    let d3 = { let (o, a) = (format!("{bpf_dir}/container.bpf.o"), al.clone());
        tokio::spawn(async move {
            let mut d = ContainerDetector::new(&o, a); d.json = json;
            if let Err(e) = d.run().await { tracing::error!("container: {e}"); }
        })
    };
    let d4 = { let (o, a) = (format!("{bpf_dir}/kmod.bpf.o"), al.clone());
        tokio::spawn(async move {
            let mut d = KmodDetector::new(&o, a); d.json = json;
            if let Err(e) = d.run().await { tracing::error!("kmod: {e}"); }
        })
    };
    let d5 = { let (o, a) = (format!("{bpf_dir}/fim.bpf.o"), al.clone());
        tokio::spawn(async move {
            let mut d = FimDetector::new(&o, a); d.json = json;
            if let Err(e) = d.run().await { tracing::error!("fim: {e}"); }
        })
    };
    let d6 = { let (o, a) = (format!("{bpf_dir}/network.bpf.o"), al.clone());
        tokio::spawn(async move {
            let mut d = NetworkDetector::new(&o, a); d.json = json;
            if let Err(e) = d.run().await { tracing::error!("network: {e}"); }
        })
    };

    tokio::select! {
        _ = d1 => {}  _ = d2 => {}  _ = d3 => {}
        _ = d4 => {}  _ = d5 => {}  _ = d6 => {}
    }
    println!("\nkernelradar stopped.");
    Ok(())
}
