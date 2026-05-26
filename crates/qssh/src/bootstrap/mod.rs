pub mod detect;
pub mod keys;
pub mod service;
pub mod ssh;

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use minisign_verify::{PublicKey, Signature};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use self::detect::OsKind;
use self::service::QSSHD_INSTALL_PATH;
use self::ssh::SshRunner;

const GITHUB_REPO: &str = "alexclewontin/squish";
const QSSHD_CONFIG_PATH: &str = "/etc/qssh/qsshd.toml";
const RELEASE_CHECKSUMS_NAME: &str = "SHA256SUMS";
const RELEASE_CHECKSUMS_SIG_NAME: &str = "SHA256SUMS.minisig";
const RELEASE_SIGNING_PUBLIC_KEY: &str = "RWRbIET4r585mncP/VNFFujSlXXfvb+SzyZQrfnbBMYC89BK6Lj9Oyxt";

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

struct VerifiedRelease {
    _staging: TempDir,
    qsshd_binary: PathBuf,
}

/// Run the full bootstrap sequence against a remote host.
///
/// Steps:
///   1. Detect remote OS and architecture.
///   2. Download the matching release locally, verify its signed checksums, and upload `qsshd`.
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
        if let Some(v) = cfg.squishd_version.as_deref() {
            validate_version(v)?;
        }
        let asset_name = release_archive_name(target);
        let url = release_asset_url(cfg.squishd_version.as_deref(), &asset_name);
        eprintln!("[bootstrap] downloading and verifying {asset_name} from {url}…");
        let verified = download_and_verify_qsshd_release(cfg.squishd_version.as_deref(), target)
            .context("downloading and verifying qsshd release artifacts")?;
        eprintln!("[bootstrap] uploading verified qsshd…");
        runner
            .upload(&verified.qsshd_binary, "/tmp/qsshd")
            .context("uploading verified qsshd binary")?;
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
        .sudo("mkdir -p /etc/qssh && chmod 700 /etc/qssh")
        .context("creating /etc/qssh")?;
    runner
        .write_file("/tmp/qsshd.toml", &config_content)
        .context("writing qsshd.toml to /tmp")?;
    runner
        .sudo(&format!(
            "install -m 644 /tmp/qsshd.toml {QSSHD_CONFIG_PATH}"
        ))
        .context("installing qsshd.toml")?;

    // 4. Add client public key to the SSH user's ~/.squish/authorized_keys.
    eprintln!("[bootstrap] configuring ~/.squish/authorized_keys…");
    let pubkey =
        keys::ensure_client_keypair(&cfg.identity_path).context("ensuring client key pair")?;
    let ak_line = keys::format_authorized_key(&pubkey, "");
    runner
        .install_authorized_key(&ak_line)
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
/// value is interpolated into a GitHub release URL and must not be able to
/// terminate a path segment or introduce shell metacharacters.
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

fn release_archive_name(target: &str) -> String {
    format!("squish-{target}.tar.gz")
}

/// Construct the GitHub Releases download URL for a release asset.
fn release_asset_url(version: Option<&str>, asset: &str) -> String {
    match version {
        Some(v) => format!("https://github.com/{GITHUB_REPO}/releases/download/v{v}/{asset}"),
        None => format!("https://github.com/{GITHUB_REPO}/releases/latest/download/{asset}"),
    }
}

fn download_and_verify_qsshd_release(
    version: Option<&str>,
    target: &str,
) -> Result<VerifiedRelease> {
    let staging = TempDir::new().context("creating bootstrap staging directory")?;
    let asset_name = release_archive_name(target);
    let archive_path = staging.path().join(&asset_name);
    let checksums_path = staging.path().join(RELEASE_CHECKSUMS_NAME);
    let signature_path = staging.path().join(RELEASE_CHECKSUMS_SIG_NAME);

    download_to_path(&release_asset_url(version, &asset_name), &archive_path)?;
    download_to_path(
        &release_asset_url(version, RELEASE_CHECKSUMS_NAME),
        &checksums_path,
    )?;
    download_to_path(
        &release_asset_url(version, RELEASE_CHECKSUMS_SIG_NAME),
        &signature_path,
    )?;

    verify_release_artifact(&archive_path, &checksums_path, &signature_path, &asset_name)?;
    let qsshd_binary = extract_qsshd_binary(&archive_path, staging.path())?;

    Ok(VerifiedRelease {
        _staging: staging,
        qsshd_binary,
    })
}

fn download_to_path(url: &str, destination: &Path) -> Result<()> {
    let status = if command_on_path("curl") {
        Command::new("curl")
            .args(["-fsSL", "-o"])
            .arg(destination)
            .arg(url)
            .status()
            .with_context(|| format!("spawning curl for {url}"))?
    } else if command_on_path("wget") {
        Command::new("wget")
            .arg("-qO")
            .arg(destination)
            .arg(url)
            .status()
            .with_context(|| format!("spawning wget for {url}"))?
    } else {
        bail!("neither curl nor wget is available locally to download release artifacts");
    };

    if !status.success() {
        bail!("failed to download {url}");
    }
    Ok(())
}

fn command_on_path(name: &str) -> bool {
    let Some(path_var) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path_var).any(|dir| dir.join(name).is_file())
}

fn verify_release_artifact(
    archive_path: &Path,
    checksums_path: &Path,
    signature_path: &Path,
    asset_name: &str,
) -> Result<()> {
    let checksums = fs::read_to_string(checksums_path)
        .with_context(|| format!("reading {}", checksums_path.display()))?;
    let signature_text = fs::read_to_string(signature_path)
        .with_context(|| format!("reading {}", signature_path.display()))?;
    verify_signed_checksum_manifest(&checksums, &signature_text)?;

    let expected = checksum_for_asset(&checksums, asset_name)?;
    let actual = sha256_file_hex(archive_path)?;
    if actual != expected {
        bail!("release checksum mismatch for {asset_name}: expected {expected}, got {actual}");
    }
    Ok(())
}

fn verify_signed_checksum_manifest(checksums: &str, signature_text: &str) -> Result<()> {
    let public_key = PublicKey::from_base64(RELEASE_SIGNING_PUBLIC_KEY)
        .map_err(|e| anyhow::anyhow!("invalid embedded release signing key: {e}"))?;
    let signature = Signature::decode(signature_text)
        .map_err(|e| anyhow::anyhow!("invalid release signature: {e}"))?;
    public_key
        .verify(checksums.as_bytes(), &signature, false)
        .map_err(|e| anyhow::anyhow!("release signature verification failed: {e}"))
}

fn checksum_for_asset(checksums: &str, asset_name: &str) -> Result<String> {
    let mut found = None;
    for line in checksums.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(checksum) = parts.next() else {
            continue;
        };
        let Some(asset) = parts.next() else {
            continue;
        };
        let asset = asset
            .strip_prefix("./")
            .unwrap_or(asset)
            .strip_prefix('*')
            .unwrap_or(asset);
        if asset != asset_name {
            continue;
        }
        if !checksum.chars().all(|c| c.is_ascii_hexdigit()) || checksum.len() != 64 {
            bail!("invalid SHA-256 entry for {asset_name} in {RELEASE_CHECKSUMS_NAME}");
        }
        if found.replace(checksum.to_ascii_lowercase()).is_some() {
            bail!("duplicate checksum entry for {asset_name} in {RELEASE_CHECKSUMS_NAME}");
        }
    }

    found.ok_or_else(|| anyhow::anyhow!("missing checksum entry for {asset_name}"))
}

fn sha256_file_hex(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn extract_qsshd_binary(archive_path: &Path, output_dir: &Path) -> Result<PathBuf> {
    let status = Command::new("tar")
        .arg("xzf")
        .arg(archive_path)
        .arg("-C")
        .arg(output_dir)
        .arg("qsshd")
        .status()
        .with_context(|| format!("spawning tar to extract {}", archive_path.display()))?;
    if !status.success() {
        bail!("failed to extract qsshd from {}", archive_path.display());
    }

    let qsshd_path = output_dir.join("qsshd");
    if !qsshd_path.is_file() {
        bail!("archive {} did not contain qsshd", archive_path.display());
    }
    Ok(qsshd_path)
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

    const FIXTURE_ARCHIVE_NAME: &str = "squish-x86_64-unknown-linux-gnu.tar.gz";
    const FIXTURE_ARCHIVE_BYTES: &[u8] = b"fixture archive bytes\n";
    const FIXTURE_CHECKSUMS: &str = "56041e4ee0a24a42dac2f5d1774519dd4548a2fbba2c9b72d75a21b47fb1d9bc  squish-x86_64-unknown-linux-gnu.tar.gz\n";
    const FIXTURE_SIGNATURE: &str = "untrusted comment: fixture signature\nRURbIET4r585mhw711R86MdZIf5C+nexdZNOuzf9jaJusPou0TD+H/acPWv20gGatKE8IGQWZSrNYrsWq9psj/7oibvCmK3N8gA=\ntrusted comment: trusted checksum fixture\nmKTejnBtUe4nT3zvZZC0YxXkubHUnN3Wazx7zFUqOTnB8mNgUDwO13csNY01L1Rz5hoL6OfOuc135gCyvCK6Ag==\n";

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
            "v0.1.0",
        ] {
            assert!(validate_version(bad).is_err(), "should reject: {bad:?}");
        }
    }

    #[test]
    fn release_asset_url_builds_versioned_and_latest_paths() {
        assert_eq!(
            release_asset_url(Some("0.1.0"), "asset.tar.gz"),
            "https://github.com/alexclewontin/squish/releases/download/v0.1.0/asset.tar.gz"
        );
        assert_eq!(
            release_asset_url(None, "asset.tar.gz"),
            "https://github.com/alexclewontin/squish/releases/latest/download/asset.tar.gz"
        );
    }

    #[test]
    fn checksum_for_asset_finds_exact_match() {
        let checksum = checksum_for_asset(FIXTURE_CHECKSUMS, FIXTURE_ARCHIVE_NAME).unwrap();
        assert_eq!(
            checksum,
            "56041e4ee0a24a42dac2f5d1774519dd4548a2fbba2c9b72d75a21b47fb1d9bc"
        );
    }

    #[test]
    fn verify_release_artifact_accepts_signed_matching_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(FIXTURE_ARCHIVE_NAME);
        let checksums = dir.path().join(RELEASE_CHECKSUMS_NAME);
        let signature = dir.path().join(RELEASE_CHECKSUMS_SIG_NAME);
        fs::write(&archive, FIXTURE_ARCHIVE_BYTES).unwrap();
        fs::write(&checksums, FIXTURE_CHECKSUMS).unwrap();
        fs::write(&signature, FIXTURE_SIGNATURE).unwrap();

        verify_release_artifact(&archive, &checksums, &signature, FIXTURE_ARCHIVE_NAME).unwrap();
    }

    #[test]
    fn verify_release_artifact_rejects_checksum_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join(FIXTURE_ARCHIVE_NAME);
        let checksums = dir.path().join(RELEASE_CHECKSUMS_NAME);
        let signature = dir.path().join(RELEASE_CHECKSUMS_SIG_NAME);
        fs::write(&archive, b"tampered archive bytes\n").unwrap();
        fs::write(&checksums, FIXTURE_CHECKSUMS).unwrap();
        fs::write(&signature, FIXTURE_SIGNATURE).unwrap();

        let err = verify_release_artifact(&archive, &checksums, &signature, FIXTURE_ARCHIVE_NAME)
            .unwrap_err()
            .to_string();
        assert!(err.contains("release checksum mismatch"));
    }
}
