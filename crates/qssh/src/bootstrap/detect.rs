use anyhow::{bail, Result};

use super::ssh::SshRunner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsKind {
    Linux,
    MacOs,
}

/// Detect the remote OS.
pub fn detect_os(runner: &SshRunner) -> Result<OsKind> {
    let uname = runner.run("uname -s")?;
    match uname.as_str() {
        "Linux" => Ok(OsKind::Linux),
        "Darwin" => Ok(OsKind::MacOs),
        other => bail!("unsupported remote OS: {other}"),
    }
}

/// Check whether qsshd is already installed at the expected path.
pub fn is_qsshd_installed(runner: &SshRunner) -> Result<bool> {
    let result = runner.run("command -v qsshd || test -f /usr/local/bin/qsshd && echo yes || echo no");
    match result {
        Ok(s) if s.contains("yes") || s.ends_with("qsshd") => Ok(true),
        Ok(_) => Ok(false),
        Err(_) => Ok(false),
    }
}

/// Check whether the qsshd process is currently running.
pub fn is_qsshd_running(runner: &SshRunner) -> Result<bool> {
    let result = runner.run("pgrep -x qsshd > /dev/null 2>&1 && echo running || echo stopped");
    match result {
        Ok(s) => Ok(s.trim() == "running"),
        Err(_) => Ok(false),
    }
}

/// Return the remote CPU architecture for selecting the right binary.
pub fn remote_arch(runner: &SshRunner) -> Result<String> {
    runner.run("uname -m")
}

/// Map `(os, uname -m output)` to the Rust target triple used in release asset names.
pub fn release_target(os: OsKind, arch: &str) -> Result<&'static str> {
    match (os, arch) {
        (OsKind::Linux, "x86_64") => Ok("x86_64-unknown-linux-gnu"),
        (OsKind::Linux, "aarch64") => Ok("aarch64-unknown-linux-gnu"),
        // macOS reports "arm64" for Apple Silicon
        (OsKind::MacOs, "arm64") | (OsKind::MacOs, "aarch64") => Ok("aarch64-apple-darwin"),
        (OsKind::MacOs, "x86_64") => Ok("x86_64-apple-darwin"),
        (os, arch) => anyhow::bail!("no release asset for {os:?} {arch}"),
    }
}
