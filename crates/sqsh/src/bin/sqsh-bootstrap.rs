use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use sqsh::bootstrap::{BootstrapConfig, run};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "sqsh-bootstrap",
    about = "Bootstrap a remote host to run sqshd via an existing SSH connection"
)]
struct Cli {
    /// Remote host to bootstrap, optionally with user: [user@]host
    target: String,

    /// SSH port used for the initial bootstrap connection
    #[arg(long, default_value = "22")]
    ssh_port: u16,

    /// QUIC port sqshd will listen on after setup
    #[arg(long, default_value = "2222")]
    sqshd_port: u16,

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
    let cfg = build_config(cli, std::env::var("HOME").ok().as_deref());

    run(&cfg).context("bootstrap failed")
}

fn build_config(cli: Cli, home: Option<&str>) -> BootstrapConfig {
    // Parse user@host from target string.
    let (ssh_user, host) = if let Some((u, h)) = cli.target.split_once('@') {
        (Some(u.to_string()), h.to_string())
    } else {
        (cli.user.clone(), cli.target.clone())
    };
    let ssh_user = ssh_user.or(cli.user);

    // Resolve identity and known_hosts paths.
    let home = home.unwrap_or("/tmp");
    let config_dir = PathBuf::from(home).join(".config").join("sqsh");

    let identity_path = cli
        .identity
        .unwrap_or_else(|| config_dir.join("id_ml_dsa_65"));

    let known_hosts_path = config_dir.join("known_hosts");

    BootstrapConfig {
        host,
        ssh_port: cli.ssh_port,
        sqshd_port: cli.sqshd_port,
        ssh_user,
        squishd_version: cli.squishd_version,
        identity_path,
        known_hosts_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_user_takes_precedence_over_user_flag() {
        let cli = Cli::try_parse_from([
            "sqsh-bootstrap",
            "embedded@example.com",
            "--ssh-port",
            "2200",
            "--sqshd-port",
            "3300",
            "-u",
            "flag-user",
        ])
        .unwrap();

        let cfg = build_config(cli, Some("/home/tester"));

        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.ssh_user.as_deref(), Some("embedded"));
        assert_eq!(cfg.ssh_port, 2200);
        assert_eq!(cfg.sqshd_port, 3300);
    }

    #[test]
    fn user_flag_is_used_when_target_has_no_user() {
        let cli = Cli::try_parse_from(["sqsh-bootstrap", "example.com", "-u", "deploy"]).unwrap();

        let cfg = build_config(cli, Some("/home/tester"));

        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.ssh_user.as_deref(), Some("deploy"));
    }

    #[test]
    fn default_paths_are_resolved_under_home() {
        let cli = Cli::try_parse_from(["sqsh-bootstrap", "example.com"]).unwrap();

        let cfg = build_config(cli, Some("/srv/home/alice"));

        assert_eq!(
            cfg.identity_path,
            PathBuf::from("/srv/home/alice/.config/sqsh/id_ml_dsa_65")
        );
        assert_eq!(
            cfg.known_hosts_path,
            PathBuf::from("/srv/home/alice/.config/sqsh/known_hosts")
        );
    }

    #[test]
    fn explicit_identity_and_version_are_preserved() {
        let cli = Cli::try_parse_from([
            "sqsh-bootstrap",
            "example.com",
            "--squishd-version",
            "0.1.0",
            "-i",
            "/tmp/id_ml_dsa_65",
        ])
        .unwrap();

        let cfg = build_config(cli, Some("/ignored"));

        assert_eq!(cfg.squishd_version.as_deref(), Some("0.1.0"));
        assert_eq!(cfg.identity_path, PathBuf::from("/tmp/id_ml_dsa_65"));
    }
}
