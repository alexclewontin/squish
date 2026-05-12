use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use qssh::bootstrap::{BootstrapConfig, run};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "qssh-bootstrap",
    about = "Bootstrap a remote host to run qsshd via an existing SSH connection"
)]
struct Cli {
    /// Remote host to bootstrap, optionally with user: [user@]host
    target: String,

    /// SSH port used for the initial bootstrap connection
    #[arg(long, default_value = "22")]
    ssh_port: u16,

    /// QUIC port qsshd will listen on after setup
    #[arg(long, default_value = "2222")]
    qsshd_port: u16,

    /// Override the SSH login user (default: current user)
    #[arg(short = 'u', long)]
    user: Option<String>,

    /// squishd release version to install (e.g. "0.1.0"). Defaults to the latest release.
    #[arg(long, value_name = "VERSION")]
    squishd_version: Option<String>,

    /// Path to the local ML-DSA-65 identity file (will be created if absent)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Parse user@host from target string.
    let (ssh_user, host) = if let Some((u, h)) = cli.target.split_once('@') {
        (Some(u.to_string()), h.to_string())
    } else {
        (cli.user.clone(), cli.target.clone())
    };
    let ssh_user = ssh_user.or(cli.user);

    // Resolve identity and known_hosts paths.
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let config_dir = PathBuf::from(&home).join(".config").join("qssh");

    let identity_path = cli
        .identity
        .unwrap_or_else(|| config_dir.join("id_ml_dsa_65"));

    let known_hosts_path = config_dir.join("known_hosts");

    let cfg = BootstrapConfig {
        host,
        ssh_port: cli.ssh_port,
        qsshd_port: cli.qsshd_port,
        ssh_user,
        squishd_version: cli.squishd_version,
        identity_path,
        known_hosts_path,
    };

    run(&cfg).context("bootstrap failed")
}
