pub mod detect;
pub mod keys;
pub mod service;
pub mod ssh;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use self::detect::OsKind;
use self::service::QSSHD_INSTALL_PATH;
use self::ssh::SshRunner;

const GITHUB_REPO: &str = "alexclewontin/squish";
const QSSHD_CONFIG_PATH: &str = "/etc/qssh/qsshd.toml";

pub struct BootstrapConfig {
    /// Remote host to bootstrap.
    pub host: String,
    /// SSH port to use for the bootstrap connection (not the qsshd port).
    pub ssh_port: u16,
    /// Remote qsshd port that will be configured.
    pub qsshd_port: u16,
    /// SSH user for the bootstrap connection.
    pub ssh_user: Option<String>,
    /// squishd release version to install (e.g. "0.1.0"). None = latest release.
    pub squishd_version: Option<String>,
    /// Local client identity file (ML-DSA-65 seed).
    pub identity_path: PathBuf,
    /// Local known_hosts file to pin the fingerprint into.
    pub known_hosts_path: PathBuf,
}

/// Run the full bootstrap sequence against a remote host.
///
/// Steps:
///   1. Detect remote OS and architecture.
///   2. Download and install qsshd from GitHub Releases if not already present.
///   3. Write server config and authorized_keys.
///   4. Install and start the system service.
///   5. Emit cert fingerprint and pin it in the local known_hosts.
pub fn run(cfg: &BootstrapConfig) -> Result<()> {
    let runner = SshRunner {
        user: cfg.ssh_user.clone(),
        host: cfg.host.clone(),
        ssh_port: cfg.ssh_port,
    };

    // 1. Detect OS and architecture.
    let os = detect::detect_os(&runner).context("detecting remote OS")?;
    let arch = detect::remote_arch(&runner).context("detecting remote arch")?;
    let target = detect::release_target(os, &arch).context("mapping to release target")?;
    let os_label = match os {
        OsKind::Linux => "Linux",
        OsKind::MacOs => "macOS",
    };
    eprintln!("[bootstrap] remote OS: {os_label} ({arch})");

    // 2. Ensure qsshd is installed.
    let installed = detect::is_qsshd_installed(&runner).context("checking qsshd install status")?;

    if !installed {
        // The version flows into a shell command on the remote host; reject
        // anything that isn't a plain semver-ish token so we can't be a
        // shell-injection vector.
        if let Some(v) = cfg.squishd_version.as_deref() {
            validate_version(v)?;
        }
        let url = release_asset_url(cfg.squishd_version.as_deref(), target);
        eprintln!("[bootstrap] downloading qsshd from {url}…");
        let fetch = fetch_command(os, &url);
        runner
            .run(&format!("{fetch} | tar xzf - -C /tmp qsshd"))
            .context("downloading and extracting qsshd")?;
        runner
            .sudo(&format!("install -m 755 /tmp/qsshd {QSSHD_INSTALL_PATH}"))
            .context("installing qsshd binary")?;
    } else {
        eprintln!("[bootstrap] qsshd already installed, skipping download");
    }

    // 3. Write server config.
    eprintln!("[bootstrap] writing server config…");
    let config_content = build_server_config(cfg.qsshd_port);
    runner
        .sudo("mkdir -p /etc/qssh && chmod 755 /etc/qssh")
        .context("creating /etc/qssh")?;

    // Write to /tmp first, then sudo-move into place.
    runner
        .write_file("/tmp/qsshd.toml", &config_content)
        .context("writing qsshd.toml to /tmp")?;
    runner
        .sudo(&format!(
            "install -m 644 /tmp/qsshd.toml {QSSHD_CONFIG_PATH}"
        ))
        .context("installing qsshd.toml")?;

    // 4. Add client public key to the SSH user's ~/.squish/authorized_keys.
    //    No sudo needed — the SSH connection is already authenticated as the
    //    user, and the file lives in their own home directory.
    eprintln!("[bootstrap] configuring ~/.squish/authorized_keys…");
    let pubkey =
        keys::ensure_client_keypair(&cfg.identity_path).context("ensuring client key pair")?;
    let ak_line = keys::format_authorized_key(&pubkey, "");
    runner
        .run(&format!(
            "sh -c 'mkdir -p \"$HOME/.squish\" && chmod 700 \"$HOME/.squish\" && \
             grep -qF \"{ak_line}\" \"$HOME/.squish/authorized_keys\" 2>/dev/null || \
             {{ echo \"{ak_line}\" >> \"$HOME/.squish/authorized_keys\" && \
                chmod 600 \"$HOME/.squish/authorized_keys\"; }}'"
        ))
        .context("installing authorized_keys")?;

    // 5. Install and start service.
    let already_running = detect::is_qsshd_running(&runner).unwrap_or(false);
    if !already_running {
        eprintln!("[bootstrap] installing and starting qsshd service…");
        service::install_and_start(&runner, os).context("installing qsshd service")?;
    } else {
        eprintln!("[bootstrap] qsshd already running, reloading config…");
        reload_service(&runner, os).context("reloading qsshd")?;
    }

    // 6. Capture fingerprint and pin in known_hosts.
    eprintln!("[bootstrap] capturing server certificate fingerprint…");
    let fingerprint =
        service::fetch_fingerprint(&runner).context("fetching server cert fingerprint")?;
    let fingerprint = fingerprint.trim().to_string();

    let host_port = format!("{}:{}", cfg.host, cfg.qsshd_port);
    let mut kh = crate::known_hosts::KnownHosts::load(&cfg.known_hosts_path)
        .context("loading known_hosts")?;
    kh.pin(&host_port, &fingerprint)
        .context("pinning server fingerprint")?;

    eprintln!("[bootstrap] done!");
    eprintln!("  server: {host_port}");
    eprintln!("  fingerprint: {fingerprint}");

    Ok(())
}

/// Reject version strings that contain anything outside `[0-9A-Za-z.+-]`. The
/// value is interpolated into a remote shell command and must not be able to
/// terminate a URL or introduce metacharacters.
fn validate_version(v: &str) -> Result<()> {
    if v.is_empty() {
        bail!("version string is empty");
    }
    if !v.starts_with(|c: char| c.is_ascii_digit()) {
        bail!("version '{v}' must start with a digit");
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
    {
        bail!("version '{v}' contains disallowed characters (only [0-9A-Za-z.+-] allowed)");
    }
    Ok(())
}

/// Construct the GitHub Releases download URL for the squish tarball.
fn release_asset_url(version: Option<&str>, target: &str) -> String {
    let asset = format!("squish-{target}.tar.gz");
    match version {
        Some(v) => format!("https://github.com/{GITHUB_REPO}/releases/download/v{v}/{asset}"),
        None => format!("https://github.com/{GITHUB_REPO}/releases/latest/download/{asset}"),
    }
}

/// Return the fetch-to-stdout command appropriate for the remote OS.
fn fetch_command(os: OsKind, url: &str) -> String {
    match os {
        OsKind::Linux => format!("wget -qO- {url}"),
        OsKind::MacOs => format!("curl -fsSL {url}"),
    }
}

fn build_server_config(port: u16) -> String {
    format!(
        r#"bind_addr = "0.0.0.0"
port = {port}
host_key = "/etc/qssh/host.key"
host_cert = "/etc/qssh/host.cert"
"#
    )
}

fn reload_service(runner: &SshRunner, os: OsKind) -> Result<()> {
    match os {
        OsKind::Linux => runner.sudo("systemctl restart qsshd"),
        OsKind::MacOs => runner.sudo(
            "launchctl unload /Library/LaunchDaemons/com.qssh.qsshd.plist 2>/dev/null; \
                 launchctl load -w /Library/LaunchDaemons/com.qssh.qsshd.plist",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_version_accepts_semver() {
        validate_version("0.1.0").unwrap();
        validate_version("1.2.3").unwrap();
        validate_version("1.2.3-beta.1").unwrap();
        validate_version("0.1.0+build42").unwrap();
    }

    #[test]
    fn validate_version_rejects_shell_metacharacters() {
        for bad in [
            "",
            "0.1.0; rm -rf /",
            "0.1.0 | sh",
            "0.1.0`whoami`",
            "0.1.0$(whoami)",
            "0.1.0/../etc/passwd",
            "0.1.0 ",
            "v0.1.0", // must start with digit
        ] {
            assert!(validate_version(bad).is_err(), "should reject: {bad:?}");
        }
    }
}
